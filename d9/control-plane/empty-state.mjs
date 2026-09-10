import fs from 'node:fs'
import { createHash } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'
import { canonicalSha256, canonicalize, sha256Bytes, sha256File } from './canonical.mjs'

export class EmptyStateError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'EmptyStateError'
    this.code = code
  }
}

function reject(code, message) {
  throw new EmptyStateError(code, message)
}

function digest(value) {
  return sha256Bytes(Buffer.from(canonicalize(value), 'utf8'))
}

function descriptorSha256(descriptor, size) {
  const hash = createHash('sha256')
  const chunk = Buffer.allocUnsafe(64 * 1024)
  let position = 0
  while (position < size) {
    const bytesRead = fs.readSync(descriptor, chunk, 0, Math.min(chunk.length, size - position), position)
    if (bytesRead === 0) reject('DATABASE_PATH_CHANGED', 'Canonical database ended while hashing its held descriptor')
    hash.update(chunk.subarray(0, bytesRead))
    position += bytesRead
  }
  return hash.digest('hex')
}

function sameFileIdentity(left, right) {
  return ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every((field) => left[field] === right[field])
}

function sqliteDigestValue(value) {
  if (value === null || typeof value === 'string') return value
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value
  if (value instanceof Uint8Array) return { blob_hex: Buffer.from(value).toString('hex') }
  reject('STATE_PROJECTION_INVALID', `Unsupported SQLite value in state projection: ${typeof value}`)
}

function assertSafeIdentifier(identifier) {
  if (!/^[a-z][a-z0-9_]*$/.test(identifier)) {
    reject('STATE_PROJECTION_INVALID', `Unsafe SQLite projection identifier: ${identifier}`)
  }
}

function schemaProjection(database, digestProfiles, projectionCode) {
  const projection = digestProfiles.sqlite_projections.schema_inventories.find(
    (candidate) => candidate.projection_code === projectionCode,
  )
  if (!projection) reject('STATE_PROJECTION_INVALID', `Missing schema projection: ${projectionCode}`)
  return database.prepare(projection.select_sql).all().map((row) =>
    Object.fromEntries(Object.entries(row).map(([key, value]) => [key, sqliteDigestValue(value)])),
  )
}

function tableProjection(database, digestProfiles, tableCode) {
  assertSafeIdentifier(tableCode)
  const projection = digestProfiles.sqlite_projections.table_rows.projections.find(
    (candidate) => candidate.table_code === tableCode,
  )
  if (!projection) reject('STATE_PROJECTION_INVALID', `Missing row projection: ${tableCode}`)
  const actualColumns = database.prepare(`PRAGMA table_info("${tableCode}")`).all().map(({ name }) => name)
  if (canonicalize(actualColumns) !== canonicalize(projection.columns)) {
    reject('STATE_SCHEMA_MISMATCH', `${tableCode} columns differ from the frozen projection`)
  }
  if (canonicalize(projection.columns) !== canonicalize(projection.ordering_columns)) {
    reject('STATE_PROJECTION_INVALID', `${tableCode} uses an unsupported ordering projection`)
  }
  for (const column of projection.columns) assertSafeIdentifier(column)
  const select = projection.columns.map((column) => `"${column}"`).join(',')
  const order = projection.ordering_columns.map((column) => `"${column}" COLLATE BINARY ASC`).join(',')
  const rows = database.prepare(`SELECT ${select} FROM "${tableCode}" ORDER BY ${order}`).all()
  return rows.map((row) =>
    Object.fromEntries(projection.columns.map((column) => [column, sqliteDigestValue(row[column])])),
  )
}

function assertMigrationState(database, runtimeProfile) {
  const expected = runtimeProfile.migration_hashes
  const applied = database.prepare(`
    SELECT m.name, c.sha256
      FROM schema_migrations m
      JOIN migration_checksums c ON c.name = m.name
     ORDER BY m.name COLLATE BINARY ASC
  `).all()
  const projected = applied.map(({ name, sha256 }) => ({ migration_name: name, sha256 }))
  if (canonicalize(projected) !== canonicalize(expected)) {
    reject('MIGRATION_STATE_MISMATCH', 'The database migration ledger differs from the verified runtime profile')
  }
}

function assertProhibitedSurfaces(projectRoot, runtimeProfile, digestProfiles) {
  const contract = digestProfiles.sqlite_projections.prohibited_surfaces
  const expectedItemsDigest = digest(contract.items)
  if (expectedItemsDigest !== runtimeProfile.database_contract.prohibited_surfaces_sha256) {
    reject('PROHIBITED_SURFACE_MISMATCH', 'The runtime profile does not pin the frozen prohibited-surface inventory')
  }
  for (const item of contract.items) {
    const candidate = path.resolve(projectRoot, item.path)
    const relative = path.relative(projectRoot, candidate)
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      reject('PROHIBITED_SURFACE_MISMATCH', `Surface escapes project root: ${item.path}`)
    }
    const stat = fs.lstatSync(candidate)
    if (!stat.isFile() || stat.isSymbolicLink()) {
      reject('PROHIBITED_SURFACE_MISMATCH', `Surface is not a regular non-symlink file: ${item.path}`)
    }
    if (sha256File(candidate) !== item.exact_content_sha256) {
      reject('PROHIBITED_SURFACE_MISMATCH', `Protected application surface changed: ${item.path}`)
    }
  }
}

function assertDeclaredRows(database, digestProfiles, declaredRows, expectedEmpty) {
  for (const declared of declaredRows) {
    const rows = tableProjection(database, digestProfiles, declared.table_code)
    if (rows.length !== declared.row_count || digest(rows) !== declared.rows_sha256) {
      reject('STATE_ROW_MISMATCH', `${declared.table_code} differs from the declared logical state`)
    }
    if (expectedEmpty && declared.row_count !== 0) {
      reject('ATLAS_NOT_EMPTY', `${declared.table_code} is not declared empty`)
    }
  }
}

function assertExactRowInventories(payload, digestProfiles) {
  const allTableCodes = digestProfiles.sqlite_projections.table_rows.projections.map(({ table_code: tableCode }) => tableCode)
  const expectedLegacy = allTableCodes.filter((tableCode) => !tableCode.startsWith('atlas_')).sort()
  const expectedAtlas = allTableCodes.filter((tableCode) => tableCode.startsWith('atlas_')).sort()
  const actualLegacy = payload.legacy_rows.map(({ table_code: tableCode }) => tableCode)
  const actualAtlas = payload.atlas_tables.map(({ table_code: tableCode }) => tableCode)
  if (canonicalize(actualLegacy) !== canonicalize(expectedLegacy) || canonicalize(actualAtlas) !== canonicalize(expectedAtlas)) {
    reject('EXPECTED_STATE_MISMATCH', 'Expected state does not contain the exact frozen row-projection inventories')
  }
}

/**
 * Read-only D9.1 verifier for the pre-bootstrap canonical state. It pins one
 * regular-file identity with O_NOFOLLOW and keeps that descriptor open while
 * SQLite reads through /proc/self/fd. The supplied path is configuration, not a
 * later authorization fact, and is rechecked against the held inode on exit.
 */
export function verifyEmptyCanonicalState({
  databasePath,
  projectRoot,
  runtimeProfile,
  digestProfiles,
  expectedStateSeal,
}) {
  let descriptor
  let database
  try {
    const pathStat = fs.lstatSync(databasePath, { bigint: true })
    if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
      reject('DATABASE_PATH_INVALID', 'Canonical database must be a regular non-symlink file')
    }
    descriptor = fs.openSync(
      databasePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | (fs.constants.O_CLOEXEC ?? 0),
    )
    const heldBefore = fs.fstatSync(descriptor, { bigint: true })
    if (!heldBefore.isFile() || !sameFileIdentity(pathStat, heldBefore) || heldBefore.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      reject('DATABASE_PATH_CHANGED', 'Canonical database identity changed while acquiring its descriptor')
    }
    const heldSize = Number(heldBefore.size)
    const beforeFileSha256 = descriptorSha256(descriptor, heldSize)
    database = new DatabaseSync(`/proc/self/fd/${descriptor}`, { readOnly: true })
    database.exec('PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON; PRAGMA query_only = ON')
    if (database.prepare('PRAGMA foreign_keys').get().foreign_keys !== 1) {
      reject('PLATFORM_CONTROL_UNAVAILABLE', 'SQLite foreign-key enforcement is unavailable')
    }
    if (database.prepare('PRAGMA recursive_triggers').get().recursive_triggers !== 1) {
      reject('PLATFORM_CONTROL_UNAVAILABLE', 'SQLite recursive triggers are unavailable')
    }
    if (database.prepare('PRAGMA query_only').get().query_only !== 1) {
      reject('PLATFORM_CONTROL_UNAVAILABLE', 'SQLite query-only mode is unavailable')
    }
    if (database.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok') {
      reject('DATABASE_INTEGRITY_FAILED', 'SQLite integrity_check failed')
    }
    if (database.prepare('PRAGMA foreign_key_check').all().length !== 0) {
      reject('DATABASE_FOREIGN_KEY_FAILED', 'SQLite foreign_key_check found violations')
    }

    assertMigrationState(database, runtimeProfile)
    assertProhibitedSurfaces(projectRoot, runtimeProfile, digestProfiles)

    const completeSchema = schemaProjection(database, digestProfiles, 'complete_schema')
    const legacySchema = schemaProjection(database, digestProfiles, 'legacy_schema')
    const inventory = schemaProjection(database, digestProfiles, 'exact_object_inventory')
    const observedSchema = {
      complete_schema_sha256: digest(completeSchema),
      legacy_schema_sha256: digest(legacySchema),
      exact_object_inventory_sha256: digest(inventory),
    }
    for (const [field, observed] of Object.entries(observedSchema)) {
      if (runtimeProfile.database_contract[field] !== observed) {
        reject('STATE_SCHEMA_MISMATCH', `${field} differs from the verified runtime profile`)
      }
    }

    const payload = expectedStateSeal.state_payload
    if (canonicalSha256(expectedStateSeal, { excludedTopLevelField: 'record_digest_sha256' }) !== expectedStateSeal.record_digest_sha256 ||
        digest(payload) !== expectedStateSeal.logical_state_sha256) {
      reject('EXPECTED_STATE_MISMATCH', 'Expected logical-state seal or payload digest is invalid')
    }
    if (payload.receipt_head !== null || payload.principal_roster.length !== 0) {
      reject('EXPECTED_STATE_NOT_EMPTY', 'Expected logical-state seal is not the empty state')
    }
    assertExactRowInventories(payload, digestProfiles)
    if (payload.runtime_profile_record_digest_sha256 !== runtimeProfile.record_digest_sha256 ||
        payload.contract_catalog_sha256 !== runtimeProfile.contract_catalog_sha256 ||
        payload.complete_schema_sha256 !== observedSchema.complete_schema_sha256 ||
        payload.legacy_schema_sha256 !== observedSchema.legacy_schema_sha256 ||
        payload.prohibited_surfaces_sha256 !== runtimeProfile.database_contract.prohibited_surfaces_sha256 ||
        canonicalize(payload.migration_hashes) !== canonicalize(runtimeProfile.migration_hashes)) {
      reject('EXPECTED_STATE_MISMATCH', 'Expected empty state does not bind the verified runtime/database contract')
    }
    const emptySetSha256 = digest([])
    if (payload.principal_roster_sha256 !== emptySetSha256 ||
        payload.receipt_dependency_graph_sha256 !== emptySetSha256 ||
        payload.prior_logical_state_sha256 !== null) {
      reject('EXPECTED_STATE_MISMATCH', 'Expected state is not the unique empty-lineage projection')
    }

    const atlasNames = database.prepare(`
      SELECT name FROM sqlite_schema
       WHERE type = 'table' AND substr(name, 1, 6) = 'atlas_'
       ORDER BY name COLLATE BINARY ASC
    `).all().map(({ name }) => name)
    const declaredAtlasNames = payload.atlas_tables.map(({ table_code }) => table_code).sort()
    if (canonicalize(atlasNames) !== canonicalize(declaredAtlasNames)) {
      reject('ATLAS_INVENTORY_MISMATCH', 'Atlas table inventory differs from the empty logical-state seal')
    }
    assertDeclaredRows(database, digestProfiles, payload.legacy_rows, false)
    assertDeclaredRows(database, digestProfiles, payload.atlas_tables, true)
    if (database.prepare('SELECT count(*) AS count FROM atlas_evidence_bundle_receipts').get().count !== 0) {
      reject('ATLAS_NOT_EMPTY', 'Receipt ledger is not empty')
    }

    const heldAfter = fs.fstatSync(descriptor, { bigint: true })
    let pathAfter
    try {
      pathAfter = fs.lstatSync(databasePath, { bigint: true })
    } catch {
      reject('DATABASE_PATH_CHANGED', 'Canonical database path disappeared during verification')
    }
    if (!sameFileIdentity(heldBefore, heldAfter) || !sameFileIdentity(heldAfter, pathAfter)) {
      reject('DATABASE_PATH_CHANGED', 'Canonical database identity changed during verification')
    }
    const afterFileSha256 = descriptorSha256(descriptor, heldSize)
    if (beforeFileSha256 !== afterFileSha256) {
      reject('READ_ONLY_VERIFICATION_MUTATED_STATE', 'Read-only empty-state verification changed the database file')
    }
    return Object.freeze({
      atlasTableCount: atlasNames.length,
      databaseFileSha256: beforeFileSha256,
      ...observedSchema,
      logicalStateSha256: expectedStateSeal.logical_state_sha256,
    })
  } finally {
    database?.close()
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}
