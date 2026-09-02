import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
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
const legacyTables = [
  'jurisdictions', 'legal_instruments', 'requirements', 'hiring_stages', 'legal_lenses', 'actors',
  'requirement_hiring_stages', 'requirement_legal_lenses', 'requirement_actors',
  'requirement_relations', 'country_overlays', 'source_checks', 'requirement_search',
]

function temporaryDirectory(prefix = 'jedi-hiring-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix))
}

function copyMigrations() {
  const directory = temporaryDirectory('jedi-migrations-')
  for (const file of fs.readdirSync(migrationsDirectory)) {
    fs.copyFileSync(path.join(migrationsDirectory, file), path.join(directory, file))
  }
  return directory
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

test('fresh installation applies every discovered migration and reruns as a no-op', () => {
  const fixture = createTestDatabase()
  try {
    const migrationCount = fs.readdirSync(migrationsDirectory).filter((name) => name.endsWith('.sql')).length
    assert.equal(fixture.appliedNow.length, migrationCount)
    assert.deepEqual(applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory }).appliedNow, [])
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
    assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
    database.close()
  } finally { fixture.remove() }
})

test('independent frozen 001-003 database bootstraps exact checksums without changing legacy content', () => {
  const fixture = createFrozenLegacyDatabase()
  try {
    const before = tableDigests(fixture.databasePath)
    assert.deepEqual(applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory }).appliedNow, [])
    assert.deepEqual(tableDigests(fixture.databasePath), before)
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    const checksums = Object.fromEntries(database.prepare('SELECT name, sha256 FROM migration_checksums ORDER BY name').all().map((row) => [row.name, row.sha256]))
    assert.deepEqual(checksums, FROZEN_CHECKSUMS)
    database.close()
  } finally { fixture.remove() }
})

test('repository search and taxonomy filters return source-backed requirements', () => {
  const fixture = createTestDatabase(); const repository = createRepository(fixture.databasePath)
  try {
    const result = repository.listRequirements({ q: 'automated decisions', lens: 'ai-automation' })
    assert.ok(result.items.some((item) => item.slug === 'gdpr-solely-automated-decisions'))
    assert.ok(result.items.every((item) => item.official_url.startsWith('https://eur-lex.europa.eu/')))
  } finally { repository.close(); fixture.remove() }
})

test('failed migration rolls back its DDL and ledger records', () => {
  const fixture = createTestDatabase(); const directory = copyMigrations()
  try {
    fs.writeFileSync(path.join(directory, '004_failure.sql'), 'CREATE TABLE rollback_probe (id INTEGER PRIMARY KEY);\nINVALID SQL;')
    assert.throws(() => applyMigrations({ databasePath: fixture.databasePath, migrationsDirectory: directory }), /Migration 004_failure.sql failed/)
    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    assert.equal(database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'rollback_probe'").get().n, 0)
    assert.equal(database.prepare("SELECT COUNT(*) AS n FROM schema_migrations WHERE name = '004_failure.sql'").get().n, 0)
    assert.equal(database.prepare("SELECT COUNT(*) AS n FROM migration_checksums WHERE name = '004_failure.sql'").get().n, 0)
    database.close()
  } finally { fs.rmSync(directory, { recursive: true, force: true }); fixture.remove() }
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
