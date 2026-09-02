import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { applyMigrations } from '../lib/migrations.mjs'

const dataDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const databasePath = path.resolve(process.env.DATABASE_PATH || path.join(dataDirectory, 'jedi-hiring.sqlite'))
const migrationsDirectory = path.join(dataDirectory, 'migrations')

const { appliedNow, total } = applyMigrations({ databasePath, migrationsDirectory })

if (appliedNow.length === 0) {
  console.log(`Database is current (${total} migrations): ${databasePath}`)
} else {
  console.log(`Applied ${appliedNow.length} migration(s): ${appliedNow.join(', ')}`)
  console.log(`Database: ${databasePath}`)
}
