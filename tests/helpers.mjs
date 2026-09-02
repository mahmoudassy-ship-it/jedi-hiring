import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { applyMigrations } from '../data/lib/migrations.mjs'

const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const migrationsDirectory = path.join(projectDirectory, 'data', 'migrations')

export function createTestDatabase() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-hiring-test-'))
  const databasePath = path.join(directory, 'test.sqlite')
  const result = applyMigrations({ databasePath, migrationsDirectory })
  return {
    ...result,
    databasePath,
    remove: () => fs.rmSync(directory, { recursive: true, force: true }),
  }
}
