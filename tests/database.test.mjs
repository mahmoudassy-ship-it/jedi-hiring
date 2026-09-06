import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import { spawnSync } from 'node:child_process'
import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { createRepository } from '../backend/src/database.mjs'
import { applyMigrations, FROZEN_CHECKSUMS } from '../data/lib/migrations.mjs'
import { createTestDatabase } from './helpers.mjs'

const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const migrationsDirectory = path.join(projectDirectory, 'data', 'migrations')
const frozenMigrations = ['001_schema.sql', '002_reference_data.sql', '003_seed_eu_core.sql']
const tranche1aMigration = '004_tranche_1a_foundations.sql'
const tranche2aMigration = '005_tranche_2a_source_quarantine.sql'
const tranche2aMigrationSha256 = '1f83b484ca998be3bf5756492d4dffd958e2a6b37dbcc837e399226fdf41026b'
const migrationNamesThrough005 = [...frozenMigrations, tranche1aMigration, tranche2aMigration]
const tranche1aProposalPath = path.join(projectDirectory, 'docs', 'schema', 'tranche-1-foundations.proposed.sql')
const tranche2aProposalPath = path.join(projectDirectory, 'docs', 'schema', 'tranche-2a-source-quarantine.proposed.sql')
const tranche1aTables = ['atlas_principals', 'atlas_languages', 'atlas_jurisdictions', 'atlas_jurisdiction_versions']
const frozenMigrationHashesThrough004 = Object.freeze({
  ...FROZEN_CHECKSUMS,
  [tranche1aMigration]: '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
})
const tranche2aObjects = Object.freeze({
  table: [
    'atlas_artifact_custody_events',
    'atlas_artifacts',
    'atlas_evidence_bundle_receipts',
    'atlas_processing_outputs',
    'atlas_processing_runs',
    'atlas_retrieval_events',
    'atlas_retrieval_locations',
    'atlas_retrieval_redirects',
    'atlas_unverified_candidate_occurrences',
  ],
  index: [
    'atlas_artifact_custody_events_code_uidx',
    'atlas_artifact_custody_events_leaf_idx',
    'atlas_artifact_custody_events_one_root_uidx',
    'atlas_artifact_custody_events_predecessor_uidx',
    'atlas_artifacts_code_uidx',
    'atlas_artifacts_identity_uidx',
    'atlas_candidate_occurrences_leaf_idx',
    'atlas_candidate_occurrences_one_root_uidx',
    'atlas_candidate_occurrences_predecessor_uidx',
    'atlas_candidate_occurrences_record_code_uidx',
    'atlas_candidate_occurrences_run_output_idx',
    'atlas_evidence_bundle_receipts_code_uidx',
    'atlas_evidence_bundle_receipts_digest_uidx',
    'atlas_evidence_bundle_receipts_path_uidx',
    'atlas_evidence_bundle_receipts_sequence_uidx',
    'atlas_processing_outputs_code_uidx',
    'atlas_processing_outputs_id_run_uidx',
    'atlas_processing_outputs_run_ordinal_uidx',
    'atlas_processing_runs_code_uidx',
    'atlas_processing_runs_input_time_idx',
    'atlas_processing_runs_receipt_ordinal_uidx',
    'atlas_retrieval_events_code_uidx',
    'atlas_retrieval_events_location_time_idx',
    'atlas_retrieval_locations_code_uidx',
    'atlas_retrieval_locations_url_uidx',
    'atlas_retrieval_redirects_code_uidx',
    'atlas_retrieval_redirects_event_ordinal_uidx',
  ],
  trigger: [
    'atlas_artifact_custody_events_immutable_delete',
    'atlas_artifact_custody_events_immutable_update',
    'atlas_artifact_custody_events_validate_insert',
    'atlas_artifacts_immutable_delete',
    'atlas_artifacts_immutable_update',
    'atlas_artifacts_validate_insert',
    'atlas_candidate_occurrences_immutable_delete',
    'atlas_candidate_occurrences_immutable_update',
    'atlas_candidate_occurrences_validate_insert',
    'atlas_evidence_bundle_receipts_immutable_delete',
    'atlas_evidence_bundle_receipts_immutable_update',
    'atlas_evidence_bundle_receipts_validate_insert',
    'atlas_processing_outputs_immutable_delete',
    'atlas_processing_outputs_immutable_update',
    'atlas_processing_outputs_validate_insert',
    'atlas_processing_runs_immutable_delete',
    'atlas_processing_runs_immutable_update',
    'atlas_processing_runs_validate_insert',
    'atlas_retrieval_events_immutable_delete',
    'atlas_retrieval_events_immutable_update',
    'atlas_retrieval_events_validate_insert',
    'atlas_retrieval_locations_immutable_delete',
    'atlas_retrieval_locations_immutable_update',
    'atlas_retrieval_locations_validate_insert',
    'atlas_retrieval_redirects_immutable_delete',
    'atlas_retrieval_redirects_immutable_update',
    'atlas_retrieval_redirects_validate_insert',
  ],
})
const legacyTables = [
  'jurisdictions', 'legal_instruments', 'requirements', 'hiring_stages', 'legal_lenses', 'actors',
  'requirement_hiring_stages', 'requirement_legal_lenses', 'requirement_actors',
  'requirement_relations', 'country_overlays', 'source_checks', 'requirement_search',
]

function temporaryDirectory(prefix = 'jedi-hiring-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix))
}

function copyMigrations(names = fs.readdirSync(migrationsDirectory)) {
  const directory = temporaryDirectory('jedi-migrations-')
  for (const file of names) {
    fs.copyFileSync(path.join(migrationsDirectory, file), path.join(directory, file))
  }
  return directory
}

function createFrozenTranche1aDatabase() {
  const directory = temporaryDirectory('jedi-frozen-tranche-1a-')
  const databasePath = path.join(directory, 'tranche-1a.sqlite')
  const baselineMigrations = copyMigrations([...frozenMigrations, tranche1aMigration])
  try {
    assert.deepEqual(
      applyMigrations({ databasePath, migrationsDirectory: baselineMigrations }).appliedNow,
      [...frozenMigrations, tranche1aMigration],
    )
  } finally {
    fs.rmSync(baselineMigrations, { recursive: true, force: true })
  }
  return { databasePath, remove: () => fs.rmSync(directory, { recursive: true, force: true }) }
}

function createFrozenLegacyDatabase() {
  const directory = temporaryDirectory('jedi-frozen-v1-')
  const databasePath = path.join(directory, 'legacy.sqlite')
  const database = new DatabaseSync(databasePath)
  database.exec('PRAGMA foreign_keys = ON; CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)')
  for (const [index, name] of frozenMigrations.entries()) {
    database.exec(fs.readFileSync(path.join(migrationsDirectory, name), 'utf8'))
    database.prepare('INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)')
      .run(name, `2026-01-0${index + 1}T00:00:00.000Z`)
  }
  database.close()
  return { databasePath, remove: () => fs.rmSync(directory, { recursive: true, force: true }) }
}

function tableDigests(databasePath) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    return Object.fromEntries(legacyTables.map((table) => {
      const columns = database.prepare(`PRAGMA table_info(${table})`).all().map(({ name }) => name)
      const order = columns.map((name) => `"${name}"`).join(', ')
      const rows = database.prepare(`SELECT * FROM "${table}" ORDER BY ${order}`).all().map((row) => ({ ...row }))
      return [table, crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex')]
    }))
  } finally { database.close() }
}

function schemaDefinitions(databasePath) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    return database.prepare(`SELECT type, name, tbl_name, sql
      FROM sqlite_schema
      ORDER BY type, name, tbl_name`).all().map((row) => ({ ...row }))
  } finally { database.close() }
}

function assertPriorSchemaDefinitionsUnchanged(before, after) {
  const key = (row) => `${row.type}\0${row.name}\0${row.tbl_name}`
  const afterByKey = new Map(after.map((row) => [key(row), row]))
  for (const expected of before) {
    const actual = afterByKey.get(key(expected))
    assert.ok(actual, `pre-005 schema object was deleted: ${expected.type} ${expected.name}`)
    assert.equal(actual.sql, expected.sql, `pre-005 schema object was modified: ${expected.type} ${expected.name}`)
  }
}

function schemaDefinitionDelta(before, after) {
  const key = (row) => `${row.type}\0${row.name}\0${row.tbl_name}`
  const beforeKeys = new Set(before.map(key))
  const delta = after.filter((row) => !beforeKeys.has(key(row)))
  return Object.fromEntries(['table', 'index', 'trigger', 'view'].map((type) => [
    type,
    delta.filter((row) => row.type === type).map((row) => row.name).toSorted(),
  ]))
}

function migrationLedgerSnapshot(databasePath) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    return {
      migrations: database.prepare('SELECT name, applied_at FROM schema_migrations ORDER BY name').all().map((row) => ({ ...row })),
      checksums: database.prepare('SELECT name, sha256, recorded_at FROM migration_checksums ORDER BY name').all().map((row) => ({ ...row })),
    }
  } finally { database.close() }
}

function fileSha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex')
}

test('fresh installation applies every discovered migration and reruns as a no-op', () => {
  const fixture = createTestDatabase()
  try {
    assert.deepEqual(fixture.appliedNow, migrationNamesThrough005)
    assert.equal(fixture.total, 5)
    assert.deepEqual(applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory }).appliedNow, [])
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    assert.deepEqual(
      database.prepare('SELECT name FROM schema_migrations ORDER BY name').all().map(({ name }) => name),
      migrationNamesThrough005,
    )
    const receipt = database.prepare(`SELECT migration.sha256, migration.recorded_at, ledger.applied_at
      FROM migration_checksums migration
      JOIN schema_migrations ledger ON ledger.name = migration.name
      WHERE migration.name = ?`).get(tranche2aMigration)
    assert.equal(receipt.sha256, tranche2aMigrationSha256)
    assert.equal(receipt.recorded_at, receipt.applied_at)
    for (const table of tranche2aObjects.table) assert.equal(database.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0)
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
    assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
    database.close()
  } finally { fixture.remove() }
})

test('production Tranche 1A matches its proposal and remains empty, strict, and adversarially validated', () => {
  assert.equal(
    fs.readFileSync(path.join(migrationsDirectory, tranche1aMigration), 'utf8'),
    fs.readFileSync(tranche1aProposalPath, 'utf8'),
  )
  const fixture = createTestDatabase()
  try {
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    const placeholders = tranche1aTables.map(() => '?').join(',')
    const objects = database.prepare(`SELECT type, name, sql FROM sqlite_master
      WHERE tbl_name IN (${placeholders}) AND name NOT LIKE 'sqlite_autoindex_%'
      ORDER BY type, name`).all(...tranche1aTables)
    assert.equal(objects.filter(({ type }) => type === 'table').length, 4)
    assert.equal(objects.filter(({ type }) => type === 'index').length, 3)
    assert.equal(objects.filter(({ type }) => type === 'trigger').length, 17)
    for (const table of tranche1aTables) {
      assert.equal(database.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0)
      assert.match(objects.find((object) => object.type === 'table' && object.name === table).sql, /\) STRICT$/)
    }
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
    assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
    database.close()

    const validation = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', 'docs/schema/validate-tranche-1a.mjs'], {
      cwd: projectDirectory,
      encoding: 'utf8',
    })
    assert.equal(validation.status, 0, validation.stderr)
    const result = JSON.parse(validation.stdout)
    assert.equal(result.proposal_migration_byte_equality, 'passed')
    assert.equal(result.bootstrap_exclusion, 'passed')
    assert.equal(result.record_time_causality, 'passed')
    assert.equal(result.withdrawal_reinstatement, 'passed')
    assert.equal(result.recursive_triggers_off_replace_protection, 'passed')
    assert.equal(result.broken_004_rollback, 'passed')
  } finally { fixture.remove() }
})

test('production Tranche 2A matches its approved proposal and remains empty, strict, and adversarially validated', () => {
  for (const [name, expected] of Object.entries(frozenMigrationHashesThrough004)) {
    assert.equal(fileSha256(path.join(migrationsDirectory, name)), expected, `${name} changed after being frozen`)
  }
  const productionSql = fs.readFileSync(path.join(migrationsDirectory, tranche2aMigration))
  assert.deepEqual(productionSql, fs.readFileSync(tranche2aProposalPath), 'migration 005 is not byte-identical to the approved DDL')
  assert.equal(crypto.createHash('sha256').update(productionSql).digest('hex'), tranche2aMigrationSha256)
  const fixture = createTestDatabase()
  try {
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    const placeholders = tranche2aObjects.table.map(() => '?').join(',')
    const objects = database.prepare(`SELECT type, name, tbl_name, sql FROM sqlite_master
      WHERE tbl_name IN (${placeholders}) AND name NOT LIKE 'sqlite_autoindex_%'
      ORDER BY type, name`).all(...tranche2aObjects.table).map((row) => ({ ...row }))
    for (const type of ['table', 'index', 'trigger']) {
      assert.deepEqual(
        objects.filter((object) => object.type === type).map((object) => object.name),
        tranche2aObjects[type],
        `Tranche 2A ${type} inventory drift`,
      )
    }
    for (const table of tranche2aObjects.table) {
      assert.equal(database.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0)
      assert.equal(database.prepare('PRAGMA table_list').all().find(({ name }) => name === table)?.strict, 1)
    }
    const checksum = database.prepare('SELECT sha256 FROM migration_checksums WHERE name = ?').get(tranche2aMigration)
    assert.equal(checksum?.sha256, tranche2aMigrationSha256)
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
    assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
    database.close()

    const validation = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', 'docs/schema/validate-tranche-2a.mjs'], {
      cwd: projectDirectory,
      encoding: 'utf8',
    })
    assert.equal(validation.status, 0, validation.stderr)
    const result = JSON.parse(validation.stdout)
    assert.equal(result.production_migration_byte_equality, 'passed')
    assert.equal(result.fresh_install, 'passed')
    assert.equal(result.upgrade_from_004, 'passed')
    assert.equal(result.no_op_migration_rerun, 'passed')
    assert.equal(result.migrations_001_004_unchanged, 'passed')
    assert.equal(result.legacy_digests_preserved, 13)
    assert.equal(result.legacy_schema_definitions_preserved, 'passed')
    assert.equal(result.complete_retrieval_outcome_null_matrix, 'passed')
    assert.equal(result.sequence_bounded_candidate_history, 'passed')
    assert.equal(result.exact_index_collation_direction_and_key_participation, 'passed')
    assert.equal(result.integrity_check, 'ok')
    assert.equal(result.foreign_key_check, 'clean')
    assert.deepEqual(result.objects, {
      tables: tranche2aObjects.table,
      indexes: tranche2aObjects.index,
      triggers: tranche2aObjects.trigger,
    })
  } finally { fixture.remove() }
})

test('database frozen at migration 004 upgrades by exactly 005 without changing prior rows or schema definitions', () => {
  const fixture = createFrozenTranche1aDatabase()
  try {
    const beforeDigests = tableDigests(fixture.databasePath)
    const beforeSchema = schemaDefinitions(fixture.databasePath)
    const result = applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory })
    assert.deepEqual(result.appliedNow, [tranche2aMigration])
    assert.deepEqual(tableDigests(fixture.databasePath), beforeDigests)
    const afterSchema = schemaDefinitions(fixture.databasePath)
    assertPriorSchemaDefinitionsUnchanged(beforeSchema, afterSchema)
    assert.deepEqual(schemaDefinitionDelta(beforeSchema, afterSchema), {
      table: tranche2aObjects.table,
      index: tranche2aObjects.index,
      trigger: tranche2aObjects.trigger,
      view: [],
    })
    assert.deepEqual(applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory }).appliedNow, [])

    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    const receipt = database.prepare(`SELECT migration.sha256, migration.recorded_at, ledger.applied_at
      FROM migration_checksums migration
      JOIN schema_migrations ledger ON ledger.name = migration.name
      WHERE migration.name = ?`).get(tranche2aMigration)
    assert.equal(receipt.sha256, tranche2aMigrationSha256)
    assert.equal(receipt.recorded_at, receipt.applied_at)
    for (const table of tranche2aObjects.table) assert.equal(database.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0)
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
    assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
    database.close()
  } finally { fixture.remove() }
})

test('independent frozen 001-003 database bootstraps exact checksums without changing legacy content', () => {
  const fixture = createFrozenLegacyDatabase()
  try {
    const before = tableDigests(fixture.databasePath)
    assert.deepEqual(
      applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory }).appliedNow,
      [tranche1aMigration, tranche2aMigration],
    )
    assert.deepEqual(tableDigests(fixture.databasePath), before)
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    const checksums = Object.fromEntries(database.prepare('SELECT name, sha256 FROM migration_checksums ORDER BY name').all().map((row) => [row.name, row.sha256]))
    assert.deepEqual(Object.fromEntries(frozenMigrations.map((name) => [name, checksums[name]])), FROZEN_CHECKSUMS)
    assert.equal(checksums[tranche1aMigration], fileSha256(path.join(migrationsDirectory, tranche1aMigration)))
    assert.equal(checksums[tranche2aMigration], fileSha256(path.join(migrationsDirectory, tranche2aMigration)))
    database.close()
  } finally { fixture.remove() }
})

test('repository search and taxonomy filters return source-backed requirements', () => {
  const fixture = createTestDatabase(); const repository = createRepository(fixture.databasePath)
  try {
    const result = repository.listRequirements({ q: 'automated decisions', lens: 'ai-automation' })
    assert.equal(result.total, 2)
    assert.deepEqual(result.items.map((item) => item.slug), [
      'gdpr-solely-automated-decisions',
      'platform-work-algorithmic-management',
    ])
    assert.ok(result.items.every((item) => item.official_url.startsWith('https://eur-lex.europa.eu/')))
    const detail = repository.getRequirement('ai-employment-high-risk-regime')
    assert.equal(detail.status, 'upcoming')
    assert.equal(detail.effective_from, '2027-12-02')
    assert.deepEqual(detail.relations.map((relation) => relation.slug), [
      'gdpr-recruitment-principles',
      'platform-work-algorithmic-management',
      'worker-information-consultation',
      'employment-protected-grounds-discrimination',
      'gdpr-solely-automated-decisions',
      'gdpr-dpia-recruitment-profiling',
      'ai-act-prohibited-hiring-practices',
    ])
  } finally { repository.close(); fixture.remove() }
})

test('legacy checksum bootstrap is atomic and recovers after injected failure', () => {
  const fixture = createFrozenLegacyDatabase()
  try {
    assert.throws(() => applyMigrations({
      databasePath: fixture.databasePath,
      migrationsDirectory,
      onChecksumBootstrapRow: ({ index }) => { if (index === 0) throw new Error('injected bootstrap failure') },
    }), /injected bootstrap failure/)
    let database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    assert.equal(database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'migration_checksums'").get().n, 0)
    database.close()

    assert.deepEqual(
      applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory }).appliedNow,
      [tranche1aMigration, tranche2aMigration],
    )
    database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    const checksums = Object.fromEntries(database.prepare('SELECT name, sha256 FROM migration_checksums ORDER BY name').all().map((row) => [row.name, row.sha256]))
    assert.deepEqual(Object.fromEntries(frozenMigrations.map((name) => [name, checksums[name]])), FROZEN_CHECKSUMS)
    assert.equal(checksums[tranche1aMigration], fileSha256(path.join(migrationsDirectory, tranche1aMigration)))
    assert.equal(checksums[tranche2aMigration], fileSha256(path.join(migrationsDirectory, tranche2aMigration)))
    database.close()
  } finally { fixture.remove() }
})

test('pre-existing incomplete checksum ledger fails closed before mutation', () => {
  const fixture = createFrozenLegacyDatabase()
  try {
    const database = new DatabaseSync(fixture.databasePath)
    database.exec(`CREATE TABLE migration_checksums (
      name TEXT PRIMARY KEY REFERENCES schema_migrations(name) ON DELETE CASCADE,
      sha256 TEXT NOT NULL CHECK (length(sha256) = 64), recorded_at TEXT NOT NULL
    )`)
    database.prepare('INSERT INTO migration_checksums VALUES (?, ?, ?)')
      .run('001_schema.sql', FROZEN_CHECKSUMS['001_schema.sql'], '2026-01-04T00:00:00.000Z')
    database.close()
    assert.throws(() => applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory }), /Checksum missing/)
    const check = new DatabaseSync(fixture.databasePath, { readOnly: true })
    assert.equal(check.prepare('SELECT COUNT(*) AS n FROM migration_checksums').get().n, 1)
    assert.equal(check.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'rollback_probe'").get().n, 0)
    check.close()
  } finally { fixture.remove() }
})

test('failed migration after Tranche 2A rolls back its DDL and ledger records', () => {
  const fixture = createTestDatabase(); const directory = copyMigrations()
  try {
    fs.writeFileSync(path.join(directory, '006_failure.sql'), 'CREATE TABLE rollback_probe (id INTEGER PRIMARY KEY);\nINVALID SQL;')
    assert.throws(() => applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory: directory }), /Migration 006_failure.sql failed/)
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    assert.equal(database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'rollback_probe'").get().n, 0)
    assert.equal(database.prepare("SELECT COUNT(*) AS n FROM schema_migrations WHERE name = '006_failure.sql'").get().n, 0)
    assert.equal(database.prepare("SELECT COUNT(*) AS n FROM migration_checksums WHERE name = '006_failure.sql'").get().n, 0)
    database.close()
  } finally { fs.rmSync(directory, { recursive: true, force: true }); fixture.remove() }
})

test('a deliberately broken migration 005 rolls back all Tranche 2A DDL and ledger records', () => {
  const fixture = createFrozenTranche1aDatabase()
  const directory = copyMigrations([...frozenMigrations, tranche1aMigration])
  try {
    const beforeDigests = tableDigests(fixture.databasePath)
    const beforeSchema = schemaDefinitions(fixture.databasePath)
    const beforeLedgers = migrationLedgerSnapshot(fixture.databasePath)
    const brokenSql = `${fs.readFileSync(path.join(migrationsDirectory, tranche2aMigration), 'utf8')}\nCREATE TRIGGER rollback_probe BEFORE INSERT ON migration_checksums\nWHEN NEW.name = '${tranche2aMigration}'\nBEGIN\n  SELECT RAISE(ABORT, 'deliberate migration 005 checksum failure');\nEND;\n`
    fs.writeFileSync(path.join(directory, tranche2aMigration), brokenSql)
    assert.throws(
      () => applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory: directory }),
      /Migration 005_tranche_2a_source_quarantine\.sql failed/,
    )

    assert.deepEqual(tableDigests(fixture.databasePath), beforeDigests)
    assert.deepEqual(schemaDefinitions(fixture.databasePath), beforeSchema)
    assert.deepEqual(migrationLedgerSnapshot(fixture.databasePath), beforeLedgers)
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    for (const table of tranche2aObjects.table) {
      assert.equal(database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name = ?").get(table).n, 0)
    }
    assert.equal(database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'rollback_probe'").get().n, 0)
    assert.equal(database.prepare('SELECT COUNT(*) AS n FROM schema_migrations WHERE name = ?').get(tranche2aMigration).n, 0)
    assert.equal(database.prepare('SELECT COUNT(*) AS n FROM migration_checksums WHERE name = ?').get(tranche2aMigration).n, 0)
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
    assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
    database.close()
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
    fixture.remove()
  }
})

test('modified or missing applied migration files are rejected', () => {
  const fixture = createTestDatabase(); const modified = copyMigrations(); const missing = copyMigrations()
  try {
    fs.appendFileSync(path.join(modified, '001_schema.sql'), '\n-- tampered')
    fs.rmSync(path.join(missing, '002_reference_data.sql'))
    assert.throws(() => applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory: modified }), /checksum mismatch/)
    assert.throws(() => applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory: missing }), /file is missing/)
  } finally { fs.rmSync(modified, { recursive: true, force: true }); fs.rmSync(missing, { recursive: true, force: true }); fixture.remove() }
})

test('invalid names, duplicate identifiers, and invalid file ordering are rejected', () => {
  const invalid = copyMigrations(); const duplicate = copyMigrations(); const ordering = copyMigrations()
  const databasePath = path.join(temporaryDirectory(), 'test.sqlite')
  try {
    fs.writeFileSync(path.join(invalid, 'bad.sql'), 'SELECT 1;')
    fs.writeFileSync(path.join(duplicate, '003_duplicate.sql'), 'SELECT 1;')
    fs.writeFileSync(path.join(ordering, '1000_thousand.sql'), 'SELECT 1;')
    fs.writeFileSync(path.join(ordering, '999_nine.sql'), 'SELECT 1;')
    assert.throws(() => applyMigrations({ databasePath, migrationsDirectory: invalid }), /Invalid migration filename/)
    assert.throws(() => applyMigrations({ databasePath, migrationsDirectory: duplicate }), /Duplicate migration identifier/)
    assert.throws(() => applyMigrations({ databasePath, migrationsDirectory: ordering }), /Invalid migration ordering/)
  } finally {
    for (const directory of [invalid, duplicate, ordering, path.dirname(databasePath)]) fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('applied history gaps are rejected before checksum bootstrap', () => {
  const fixture = createFrozenLegacyDatabase()
  try {
    const database = new DatabaseSync(fixture.databasePath)
    database.prepare('DELETE FROM schema_migrations WHERE name = ?').run('002_reference_data.sql')
    database.close()
    assert.throws(() => applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory }), /history has a gap/)
    const check = new DatabaseSync(fixture.databasePath, { readOnly: true })
    assert.equal(check.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'migration_checksums'").get().n, 0)
    check.close()
  } finally { fixture.remove() }
})
