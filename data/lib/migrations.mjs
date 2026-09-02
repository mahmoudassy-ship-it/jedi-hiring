import crypto from 'node:crypto'
import fs from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'

const FROZEN_CHECKSUMS = Object.freeze({
  '001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  '002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  '003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
})

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex')
}

function readMigrations(directory) {
  const names = fs.readdirSync(directory).filter((name) => name.endsWith('.sql')).sort()
  const identifiers = new Set()
  let previousIdentifier = -1

  return names.map((name) => {
    const match = name.match(/^(\d{3,})_[a-z0-9][a-z0-9_]*\.sql$/)
    if (!match) throw new Error(`Invalid migration filename: ${name}`)
    const identifier = Number(match[1])
    if (identifiers.has(identifier)) throw new Error(`Duplicate migration identifier: ${match[1]}`)
    if (identifier <= previousIdentifier) throw new Error(`Invalid migration ordering: ${name}`)
    identifiers.add(identifier)
    previousIdentifier = identifier
    const sql = fs.readFileSync(path.join(directory, name), 'utf8')
    return { identifier, name, sha256: sha256(sql), sql }
  })
}

function tableExists(database, name) {
  return Boolean(database.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name))
}

function inspectExistingDatabase(databasePath, migrations) {
  if (!fs.existsSync(databasePath)) return { applied: [], needsLedger: true, needsChecksumBootstrap: false }

  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    if (!tableExists(database, 'schema_migrations')) {
      const userTable = database.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' LIMIT 1").get()
      if (userTable) throw new Error('Existing database has no schema_migrations ledger')
      return { applied: [], needsLedger: true, needsChecksumBootstrap: false }
    }

    const applied = database.prepare('SELECT name, applied_at FROM schema_migrations ORDER BY name').all()
    const expectedPrefix = migrations.slice(0, applied.length).map(({ name }) => name)
    const actualNames = applied.map(({ name }) => name)
    if (actualNames.some((name, index) => name !== expectedPrefix[index])) {
      const missing = expectedPrefix.find((name) => !actualNames.includes(name))
      if (missing) throw new Error(`Applied migration history has a gap: ${missing}`)
      const absentFile = actualNames.find((name) => !migrations.some((migration) => migration.name === name))
      if (absentFile) throw new Error(`Applied migration file is missing: ${absentFile}`)
      throw new Error('Applied migrations do not form an ordered prefix')
    }

    const hasChecksums = tableExists(database, 'migration_checksums')
    const recorded = hasChecksums
      ? new Map(database.prepare('SELECT name, sha256 FROM migration_checksums').all().map((row) => [row.name, row.sha256]))
      : new Map()
    if (recorded.size > applied.length) throw new Error('Checksum ledger contains unapplied migrations')

    for (const { name } of applied) {
      const migration = migrations.find((candidate) => candidate.name === name)
      if (!migration) throw new Error(`Applied migration file is missing: ${name}`)
      const expected = recorded.get(name) || FROZEN_CHECKSUMS[name]
      if (!expected) throw new Error(`No trusted checksum available for applied migration: ${name}`)
      if (migration.sha256 !== expected) throw new Error(`Migration checksum mismatch: ${name}`)
      if (hasChecksums && !recorded.has(name)) throw new Error(`Checksum missing for applied migration: ${name}`)
    }

    return { applied, needsLedger: false, needsChecksumBootstrap: !hasChecksums && applied.length > 0 }
  } finally {
    database.close()
  }
}

export function applyMigrations({ databasePath, migrationsDirectory }) {
  const migrations = readMigrations(migrationsDirectory)
  const preflight = inspectExistingDatabase(databasePath, migrations)
  fs.mkdirSync(path.dirname(databasePath), { recursive: true })
  const database = new DatabaseSync(databasePath)
  const appliedNow = []

  try {
    database.exec('PRAGMA foreign_keys = ON')
    if (preflight.needsLedger) {
      database.exec('CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)')
    }
    database.exec(`CREATE TABLE IF NOT EXISTS migration_checksums (
      name TEXT PRIMARY KEY REFERENCES schema_migrations(name) ON DELETE CASCADE,
      sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
      recorded_at TEXT NOT NULL
    )`)

    if (preflight.needsChecksumBootstrap) {
      database.exec('BEGIN IMMEDIATE')
      try {
        const insert = database.prepare('INSERT INTO migration_checksums (name, sha256, recorded_at) VALUES (?, ?, ?)')
        for (const { name } of preflight.applied) insert.run(name, FROZEN_CHECKSUMS[name], new Date().toISOString())
        database.exec('COMMIT')
      } catch (error) {
        database.exec('ROLLBACK')
        throw error
      }
    }

    database.exec('PRAGMA journal_mode = WAL')
    const appliedNames = new Set(preflight.applied.map(({ name }) => name))
    for (const migration of migrations) {
      if (appliedNames.has(migration.name)) continue
      database.exec('BEGIN IMMEDIATE')
      try {
        database.exec(migration.sql)
        const now = new Date().toISOString()
        database.prepare('INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)').run(migration.name, now)
        database.prepare('INSERT INTO migration_checksums (name, sha256, recorded_at) VALUES (?, ?, ?)').run(migration.name, migration.sha256, now)
        database.exec('COMMIT')
        appliedNow.push(migration.name)
      } catch (error) {
        database.exec('ROLLBACK')
        throw new Error(`Migration ${migration.name} failed`, { cause: error })
      }
    }
    return { appliedNow, total: migrations.length }
  } finally {
    database.close()
  }
}

export { FROZEN_CHECKSUMS }
