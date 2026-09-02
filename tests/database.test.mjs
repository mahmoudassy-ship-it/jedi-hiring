import assert from 'node:assert/strict'
import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { createRepository } from '../backend/src/database.mjs'
import { applyMigrations } from '../data/lib/migrations.mjs'
import { createTestDatabase } from './helpers.mjs'

const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

test('migrations create an idempotent, valid seed database', () => {
  const fixture = createTestDatabase()
  try {
    assert.equal(fixture.appliedNow.length, 3)
    const secondRun = applyMigrations({
      databasePath: fixture.databasePath,
      migrationsDirectory: path.join(projectDirectory, 'data', 'migrations'),
    })
    assert.deepEqual(secondRun.appliedNow, [])

    const database = new DatabaseSync(fixture.databasePath, { readOnly: true })
    try {
      assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
      assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
      assert.equal(database.prepare('SELECT COUNT(*) AS count FROM requirements').get().count, 20)
      assert.equal(database.prepare('SELECT COUNT(*) AS count FROM legal_instruments').get().count, 12)
    } finally {
      database.close()
    }
  } finally {
    fixture.remove()
  }
})

test('repository search and taxonomy filters return source-backed requirements', () => {
  const fixture = createTestDatabase()
  const repository = createRepository(fixture.databasePath)
  try {
    const result = repository.listRequirements({ q: 'automated decisions', lens: 'ai-automation' })
    assert.ok(result.total >= 1)
    assert.ok(result.items.every((item) => item.official_url.startsWith('https://eur-lex.europa.eu/')))
    assert.ok(result.items.some((item) => item.slug === 'gdpr-solely-automated-decisions'))

    const detail = repository.getRequirement('ai-employment-high-risk-regime')
    assert.equal(detail.status, 'upcoming')
    assert.equal(detail.effective_from, '2027-12-02')
    assert.ok(detail.relations.length >= 3)
  } finally {
    repository.close()
    fixture.remove()
  }
})
