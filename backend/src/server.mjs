import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApplication } from './app.mjs'

const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const databasePath = path.resolve(projectDirectory, process.env.DATABASE_PATH || 'data/jedi-hiring.sqlite')
const frontendDirectory = path.join(projectDirectory, 'frontend', 'dist')
const port = Number(process.env.PORT || 3100)
const host = process.env.HOST || '127.0.0.1'

const application = createApplication({ databasePath, frontendDirectory })

application.server.listen(port, host, () => {
  console.log(`JEDI Hiring Legal Atlas listening on http://${host}:${port}`)
})

let stopping = false
async function stop() {
  if (stopping) return
  stopping = true
  await application.close()
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, async () => {
    await stop()
    process.exit(0)
  })
}
