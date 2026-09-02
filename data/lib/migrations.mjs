import fs from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'

export function applyMigrations({ databasePath, migrationsDirectory }) {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true })
  const database = new DatabaseSync(databasePath)
  const appliedNow = []

  try {
    database.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL
      );
    `)

    const applied = new Set(
      database.prepare('SELECT name FROM schema_migrations').all().map(({ name }) => name),
    )
    const migrations = fs.readdirSync(migrationsDirectory)
      .filter((file) => file.endsWith('.sql'))
      .sort()

    for (const migration of migrations) {
      if (applied.has(migration)) continue

      const sql = fs.readFileSync(path.join(migrationsDirectory, migration), 'utf8')
      database.exec('BEGIN IMMEDIATE')
      try {
        database.exec(sql)
        database.prepare('INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)')
          .run(migration, new Date().toISOString())
        database.exec('COMMIT')
        appliedNow.push(migration)
      } catch (error) {
        database.exec('ROLLBACK')
        throw new Error(`Migration ${migration} failed`, { cause: error })
      }
    }

    return { appliedNow, total: migrations.length }
  } finally {
    database.close()
  }
}
