import fs from 'node:fs'
import path from 'node:path'
import { canonicalize, sha256Bytes, sha256File } from '../control-plane/canonical.mjs'
import { assertSyntheticD92RuntimeContext } from './runtime.mjs'
import { failD92 } from './errors.mjs'

const NON_EVIDENCE_ATLAS_TABLES = Object.freeze([
  'atlas_jurisdiction_versions',
  'atlas_jurisdictions',
  'atlas_languages',
])

function digest(value) {
  return sha256Bytes(Buffer.from(canonicalize(value), 'utf8'))
}

function sqliteValue(value) {
  if (value === null || typeof value === 'string') return value
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value
  if (value instanceof Uint8Array) return { blob_hex: Buffer.from(value).toString('hex') }
  failD92('STATE_PROJECTION_INVALID', `unsupported SQLite value: ${typeof value}`)
}

function safeIdentifier(value) {
  if (!/^[a-z][a-z0-9_]*$/u.test(value)) failD92('STATE_PROJECTION_INVALID', `unsafe projection identifier: ${value}`)
  return value
}

export function projectFrozenTableRows(database, profiles, tableCode, { throughBundleSequence = null } = {}) {
  safeIdentifier(tableCode)
  const projection = profiles.sqlite_projections.table_rows.projections.find((row) => row.table_code === tableCode)
  if (!projection) failD92('STATE_PROJECTION_INVALID', `missing frozen row projection: ${tableCode}`)
  const columns = database.prepare(`PRAGMA table_info("${tableCode}")`).all().map((row) => row.name)
  if (canonicalize(columns) !== canonicalize(projection.columns)
    || canonicalize(projection.columns) !== canonicalize(projection.ordering_columns)) {
    failD92('STATE_SCHEMA_MISMATCH', `${tableCode} columns or ordering differ from the frozen projection`)
  }
  for (const column of projection.columns) safeIdentifier(column)
  const select = projection.columns.map((column) => `"${column}"`).join(',')
  const order = projection.ordering_columns.map((column) => `"${column}" COLLATE BINARY ASC`).join(',')
  let predicate = ''
  const parameters = []
  if (throughBundleSequence !== null) {
    if (!Number.isSafeInteger(throughBundleSequence) || throughBundleSequence < 0) failD92('STATE_PROJECTION_INVALID', 'bundle-sequence projection bound is invalid')
    if (tableCode === 'atlas_evidence_bundle_receipts') {
      predicate = ' WHERE bundle_sequence <= ?'
      parameters.push(throughBundleSequence)
    } else if (tableCode.startsWith('atlas_') && !NON_EVIDENCE_ATLAS_TABLES.includes(tableCode) && tableCode !== 'atlas_principals') {
      predicate = ' WHERE evidence_bundle_receipt_id IN (SELECT id FROM atlas_evidence_bundle_receipts WHERE bundle_sequence <= ?)'
      parameters.push(throughBundleSequence)
    }
  }
  return database.prepare(`SELECT ${select} FROM "${tableCode}"${predicate} ORDER BY ${order}`).all(...parameters).map((row) =>
    Object.fromEntries(projection.columns.map((column) => [column, sqliteValue(row[column])])),
  )
}

function schemaRows(database, profiles, code) {
  const projection = profiles.sqlite_projections.schema_inventories.find((row) => row.projection_code === code)
  if (!projection) failD92('STATE_PROJECTION_INVALID', `missing frozen schema projection: ${code}`)
  return database.prepare(projection.select_sql).all().map((row) =>
    Object.fromEntries(Object.entries(row).map(([key, value]) => [key, sqliteValue(value)])),
  )
}

function verifyMigrations(database, runtime) {
  const applied = database.prepare(`SELECT name AS migration_name FROM schema_migrations
    ORDER BY name COLLATE BINARY ASC`).all().map((row) => row.migration_name)
  const checksums = database.prepare(`SELECT name AS migration_name,sha256 FROM migration_checksums
    ORDER BY name COLLATE BINARY ASC`).all().map((row) => ({ ...row }))
  const expectedNames = runtime.migration_hashes.map((row) => row.migration_name)
  if (canonicalize(applied) !== canonicalize(expectedNames)
    || canonicalize(checksums) !== canonicalize(runtime.migration_hashes)) {
    failD92('MIGRATION_STATE_MISMATCH', 'migration and checksum ledgers differ from the exact verified D9.0.1 inventory')
  }
  return checksums
}

function verifyProhibitedSurfaces(context) {
  const contract = context.contractSet.digestProfiles.sqlite_projections.prohibited_surfaces
  if (digest(contract.items) !== context.verifiedGeneration.runtimeProfile.database_contract.prohibited_surfaces_sha256) {
    failD92('PROHIBITED_SURFACE_MISMATCH', 'frozen prohibited-surface inventory digest differs')
  }
  for (const item of contract.items) {
    const target = path.resolve(context.projectRoot, item.path)
    const relative = path.relative(context.projectRoot, target)
    if (relative.startsWith('..') || path.isAbsolute(relative)) failD92('PROHIBITED_SURFACE_MISMATCH', 'prohibited-surface path escapes the project root')
    const stat = fs.lstatSync(target, { bigint: true })
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || sha256File(target) !== item.exact_content_sha256) {
      failD92('PROHIBITED_SURFACE_MISMATCH', `protected application surface changed: ${item.path}`)
    }
  }
  return context.verifiedGeneration.runtimeProfile.database_contract.prohibited_surfaces_sha256
}

export function verifyFrozenDatabaseBoundary({ database, runtimeContext }) {
  const context = assertSyntheticD92RuntimeContext(runtimeContext)
  const runtime = context.verifiedGeneration.runtimeProfile
  const profiles = context.contractSet.digestProfiles
  const schemaDigests = {
    complete_schema_sha256: digest(schemaRows(database, profiles, 'complete_schema')),
    legacy_schema_sha256: digest(schemaRows(database, profiles, 'legacy_schema')),
    exact_object_inventory_sha256: digest(schemaRows(database, profiles, 'exact_object_inventory')),
  }
  for (const [field, actual] of Object.entries(schemaDigests)) {
    if (actual !== runtime.database_contract[field]) failD92('STATE_SCHEMA_MISMATCH', `${field} differs from the frozen runtime contract`)
  }
  const migrations = verifyMigrations(database, runtime)
  const expectedLegacy = new Map(context.baselineStateSeal.state_payload.legacy_rows.map((row) => [row.table_code, row]))
  const actualLegacy = {}
  for (const [tableCode, expected] of expectedLegacy) {
    const rows = projectFrozenTableRows(database, profiles, tableCode)
    const observed = { row_count: rows.length, rows_sha256: digest(rows) }
    if (observed.row_count !== expected.row_count || observed.rows_sha256 !== expected.rows_sha256) {
      failD92('LEGACY_STATE_MISMATCH', `${tableCode} differs from the frozen pre-D9 baseline`)
    }
    actualLegacy[tableCode] = observed
  }
  for (const tableCode of NON_EVIDENCE_ATLAS_TABLES) {
    if (projectFrozenTableRows(database, profiles, tableCode).length !== 0) failD92('FORBIDDEN_ATLAS_STATE', `${tableCode} is outside the D9.2 write boundary`)
  }
  const prohibitedSurfacesSha256 = verifyProhibitedSurfaces(context)
  return Object.freeze({
    ...schemaDigests,
    migrationCount: migrations.length,
    legacyTableCount: expectedLegacy.size,
    nonEvidenceAtlasTableCount: NON_EVIDENCE_ATLAS_TABLES.length,
    prohibitedSurfacesSha256,
    boundarySha256: digest({ actualLegacy, migrations, prohibitedSurfacesSha256, schemaDigests }),
  })
}
