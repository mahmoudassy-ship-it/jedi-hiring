import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { applyMigrations } from '../../data/lib/migrations.mjs'

const schemaDirectory = path.dirname(fileURLToPath(import.meta.url))
const projectDirectory = path.resolve(schemaDirectory, '../..')
const productionMigrationsDirectory = path.join(projectDirectory, 'data/migrations')
const proposalPath = path.join(schemaDirectory, 'tranche-1-foundations.proposed.sql')
const frozenNames = ['001_schema.sql', '002_reference_data.sql', '003_seed_eu_core.sql']
const legacyTables = [
  'jurisdictions', 'legal_instruments', 'requirements', 'hiring_stages', 'legal_lenses', 'actors',
  'requirement_hiring_stages', 'requirement_legal_lenses', 'requirement_actors',
  'requirement_relations', 'country_overlays', 'source_checks', 'requirement_search',
]
const expectedAtlasObjects = {
  index: [
    'atlas_jurisdiction_external_identifiers_as_of_idx',
    'atlas_jurisdiction_external_identifiers_lookup_idx',
    'atlas_jurisdiction_status_events_as_of_idx',
    'atlas_jurisdiction_versions_as_of_idx',
    'atlas_principal_status_events_as_of_idx',
  ],
  table: [
    'atlas_jurisdiction_external_identifiers',
    'atlas_jurisdiction_status_events',
    'atlas_jurisdiction_versions',
    'atlas_jurisdictions',
    'atlas_languages',
    'atlas_principal_status_events',
    'atlas_principals',
  ],
  trigger: [
    'atlas_jurisdiction_external_identifiers_immutable_delete',
    'atlas_jurisdiction_external_identifiers_immutable_update',
    'atlas_jurisdiction_external_identifiers_validate_successor',
    'atlas_jurisdiction_status_events_append_only_delete',
    'atlas_jurisdiction_status_events_append_only_update',
    'atlas_jurisdiction_status_events_prevent_replacement_cycles',
    'atlas_jurisdiction_versions_immutable_delete',
    'atlas_jurisdiction_versions_immutable_update',
    'atlas_jurisdiction_versions_validate_successor',
    'atlas_jurisdictions_immutable_delete',
    'atlas_jurisdictions_immutable_update',
    'atlas_languages_immutable_delete',
    'atlas_languages_immutable_update',
    'atlas_principal_status_events_append_only_delete',
    'atlas_principal_status_events_append_only_update',
    'atlas_principal_status_events_prevent_replacement_cycles',
    'atlas_principals_immutable_delete',
    'atlas_principals_immutable_update',
  ],
}

function makeDirectory(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix))
}

function makeTemporaryMigrations({ includeFailure = false } = {}) {
  const directory = makeDirectory('jedi-tranche-1a-migrations-')
  for (const name of frozenNames) fs.copyFileSync(path.join(productionMigrationsDirectory, name), path.join(directory, name))
  fs.copyFileSync(proposalPath, path.join(directory, '004_tranche_1a_foundations.sql'))
  if (includeFailure) {
    fs.writeFileSync(path.join(directory, '005_deliberate_failure.sql'), 'CREATE TABLE rollback_probe (id INTEGER PRIMARY KEY);\nINVALID SQL;\n')
  }
  return directory
}

function createFrozenDatabase() {
  const directory = makeDirectory('jedi-tranche-1a-frozen-')
  const databasePath = path.join(directory, 'frozen.sqlite')
  const database = new DatabaseSync(databasePath)
  database.exec('PRAGMA foreign_keys = ON; CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)')
  for (const [index, name] of frozenNames.entries()) {
    database.exec(fs.readFileSync(path.join(productionMigrationsDirectory, name), 'utf8'))
    database.prepare('INSERT INTO schema_migrations VALUES (?, ?)').run(name, `2026-01-0${index + 1}T00:00:00.000Z`)
  }
  database.close()
  return { databasePath, directory }
}

function digestTable(database, table) {
  const columns = database.prepare(`PRAGMA table_info(${table})`).all().map(({ name }) => name)
  const ordering = columns.map((name) => `"${name}"`).join(', ')
  const rows = database.prepare(`SELECT * FROM "${table}" ORDER BY ${ordering}`).all().map((row) => ({ ...row }))
  return crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex')
}

function legacyDigests(databasePath) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try { return Object.fromEntries(legacyTables.map((table) => [table, digestTable(database, table)])) }
  finally { database.close() }
}

function validateDatabase(databasePath) {
  const database = new DatabaseSync(databasePath)
  try {
    const objects = Object.fromEntries(['table', 'index', 'trigger'].map((type) => [
      type,
      database.prepare("SELECT name FROM sqlite_master WHERE type = ? AND name LIKE 'atlas_%' ORDER BY name").all(type).map(({ name }) => name),
    ]))
    assert.deepEqual(objects, expectedAtlasObjects)
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
    assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])

    const timestamp = '2026-09-02T12:00:00.000Z'
    const reject = (sql, values, pattern) => assert.throws(() => database.prepare(sql).run(...values), pattern)
    reject('INSERT INTO atlas_principals (principal_code, principal_kind_code, display_name, created_at) VALUES (?, ?, ?, ?)', ['bad-date', 'human', 'Bad date', '2026-09-02T25:00:00.000Z'], /CHECK/)
    database.prepare('INSERT INTO atlas_principals (principal_code, principal_kind_code, display_name, created_at) VALUES (?, ?, ?, ?)').run('person.one', 'human', 'Person One', timestamp)
    reject('UPDATE atlas_principals SET principal_kind_code = ? WHERE principal_code = ?', ['service', 'person.one'], /immutable/)
    reject('INSERT INTO atlas_principal_status_events (principal_id, status_code, effective_on, recorded_at, reason) VALUES (1, ?, ?, ?, ?)', ['active', '2026-02-30', timestamp, 'invalid'], /CHECK/)
    database.prepare('INSERT INTO atlas_principal_status_events (principal_id, status_code, effective_on, recorded_at, reason) VALUES (1, ?, ?, ?, ?)').run('active', '2026-09-02', timestamp, 'created')
    reject('DELETE FROM atlas_principal_status_events WHERE id = 1', [], /append-only/)

    database.prepare('INSERT INTO atlas_languages (language_code, display_name, created_at) VALUES (?, ?, ?)').run('en', 'English', timestamp)
    database.prepare('INSERT INTO atlas_jurisdictions (jurisdiction_code, jurisdiction_kind_code, created_at) VALUES (?, ?, ?)').run('example', 'state', timestamp)
    reject('UPDATE atlas_jurisdictions SET jurisdiction_kind_code = ? WHERE jurisdiction_code = ?', ['regional', 'example'], /immutable/)
    reject('INSERT INTO atlas_jurisdiction_versions (jurisdiction_id, language_id, name, effective_from, recorded_at, content_sha256) VALUES (1, 1, ?, ?, ?, ?)', ['Invalid hash', '2026-09-02', timestamp, 'ABC'], /CHECK/)
    const firstVersion = database.prepare('INSERT INTO atlas_jurisdiction_versions (jurisdiction_id, language_id, name, effective_from, recorded_at, content_sha256) VALUES (1, 1, ?, ?, ?, ?) RETURNING id').get('Example', '2026-09-02', timestamp, 'a'.repeat(64)).id
    const successor = database.prepare('INSERT INTO atlas_jurisdiction_versions (jurisdiction_id, language_id, name, effective_from, recorded_at, content_sha256, supersedes_jurisdiction_version_id) VALUES (1, 1, ?, ?, ?, ?, ?) RETURNING id').get('Corrected example', '2026-01-01', '2026-09-03T12:00:00.000Z', 'b'.repeat(64), firstVersion).id
    assert.ok(successor > firstVersion)
    reject('UPDATE atlas_jurisdiction_versions SET name = ? WHERE id = ?', ['Mutation', successor], /immutable/)
    return objects
  } finally { database.close() }
}

const proposal = fs.readFileSync(proposalPath, 'utf8')
assert.doesNotMatch(proposal, /^\s*(BEGIN(?:\s+(?:IMMEDIATE|DEFERRED|EXCLUSIVE))?|COMMIT|ROLLBACK)\s*;/im)

const cleanup = []
try {
  const freshDirectory = makeDirectory('jedi-tranche-1a-fresh-')
  const freshDatabase = path.join(freshDirectory, 'fresh.sqlite')
  const migrationsDirectory = makeTemporaryMigrations()
  cleanup.push(freshDirectory, migrationsDirectory)
  const freshResult = applyMigrations({ databasePath: freshDatabase, migrationsDirectory })
  assert.equal(freshResult.appliedNow.at(-1), '004_tranche_1a_foundations.sql')
  const objects = validateDatabase(freshDatabase)

  const frozen = createFrozenDatabase()
  const frozenMigrations = makeTemporaryMigrations()
  cleanup.push(frozen.directory, frozenMigrations)
  const before = legacyDigests(frozen.databasePath)
  assert.deepEqual(applyMigrations({ databasePath: frozen.databasePath, migrationsDirectory: frozenMigrations }).appliedNow, ['004_tranche_1a_foundations.sql'])
  assert.deepEqual(legacyDigests(frozen.databasePath), before)

  const failureDirectory = makeTemporaryMigrations({ includeFailure: true })
  const failureDatabaseDirectory = makeDirectory('jedi-tranche-1a-rollback-')
  const failureDatabase = path.join(failureDatabaseDirectory, 'rollback.sqlite')
  cleanup.push(failureDirectory, failureDatabaseDirectory)
  assert.throws(() => applyMigrations({ databasePath: failureDatabase, migrationsDirectory: failureDirectory }), /Migration 005_deliberate_failure.sql failed/)
  const rollbackDatabase = new DatabaseSync(failureDatabase, { readOnly: true })
  assert.equal(rollbackDatabase.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE name = 'rollback_probe'").get().count, 0)
  assert.equal(rollbackDatabase.prepare("SELECT COUNT(*) AS count FROM schema_migrations WHERE name = '005_deliberate_failure.sql'").get().count, 0)
  rollbackDatabase.close()

  console.log(JSON.stringify({
    fresh_install: 'passed',
    frozen_upgrade: 'passed',
    migration_runner: 'applyMigrations',
    legacy_row_digests_preserved: legacyTables.length,
    integrity_check: 'ok',
    foreign_key_check: 'clean',
    rejection_checks: 'passed',
    rollback_check: 'passed',
    object_counts: Object.fromEntries(Object.entries(objects).map(([type, names]) => [type, names.length])),
  }, null, 2))
} finally {
  for (const directory of cleanup) fs.rmSync(directory, { recursive: true, force: true })
}
