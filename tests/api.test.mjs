import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { createApplication } from '../backend/src/app.mjs'
import { createTestDatabase } from './helpers.mjs'

test('HTTP API serves overview, filtered lists, and requirement detail', async () => {
  const fixture = createTestDatabase()
  const emptyFrontend = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-hiring-frontend-'))
  const application = createApplication({
    databasePath: fixture.databasePath,
    frontendDirectory: emptyFrontend,
  })

  try {
    await new Promise((resolve) => application.server.listen(0, '127.0.0.1', resolve))
    const address = application.server.address()
    const origin = `http://127.0.0.1:${address.port}`

    const [overviewResponse, rulesResponse, detailResponse] = await Promise.all([
      fetch(`${origin}/api/overview`),
      fetch(`${origin}/api/requirements?lens=ai-automation&status=upcoming`),
      fetch(`${origin}/api/requirements/ai-employment-high-risk-regime`),
    ])

    assert.equal(overviewResponse.status, 200)
    assert.deepEqual(await overviewResponse.json(), {
      requirements: 20,
      official_sources: 12,
      jurisdictions: 1,
      last_verified_on: '2026-09-02',
    })

    assert.equal(rulesResponse.status, 200)
    const rules = await rulesResponse.json()
    assert.ok(rules.total >= 1)
    assert.ok(rules.items.every((item) => item.status === 'upcoming'))

    assert.equal(detailResponse.status, 200)
    const detail = await detailResponse.json()
    assert.equal(detail.source_locator, 'Article 6; Annex III point 4(a); deployer duties in Article 26')
    assert.ok(detail.hiring_stages.includes('Screening & assessment'))

    const methodResponse = await fetch(`${origin}/api/requirements`, { method: 'POST' })
    assert.equal(methodResponse.status, 405)
  } finally {
    await application.close()
    fs.rmSync(emptyFrontend, { recursive: true, force: true })
    fixture.remove()
  }
})
