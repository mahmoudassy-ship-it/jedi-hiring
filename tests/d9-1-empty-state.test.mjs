import assert from 'node:assert/strict'
import fs from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { canonicalSha256, readStrictJson, sha256File } from '../d9/control-plane/canonical.mjs'
import { verifyEmptyCanonicalState } from '../d9/control-plane/empty-state.mjs'
import { createTestDatabase } from './helpers.mjs'

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const contractRoot = path.join(projectRoot, 'docs', 'schema', 'd9-0')

function fixture(fixtureCode) {
  const registry = readStrictJson(path.join(contractRoot, 'fixtures', 'valid-contracts-v1.json'))
  return registry.fixtures.find((candidate) => candidate.fixture_code === fixtureCode).value
}

function verificationInput(databasePath) {
  return {
    databasePath,
    projectRoot,
    runtimeProfile: fixture('runtime_profile'),
    digestProfiles: readStrictJson(path.join(contractRoot, 'digest-profiles-v1.json')),
    expectedStateSeal: fixture('logical_state_empty'),
  }
}

test('empty-state verifier proves the exact migration-005 state without effects', () => {
  const database = createTestDatabase()
  try {
    const before = sha256File(database.databasePath)
    const result = verifyEmptyCanonicalState(verificationInput(database.databasePath))
    assert.equal(result.atlasTableCount, 13)
    assert.equal(result.databaseFileSha256, before)
    assert.equal(sha256File(database.databasePath), before)
    assert.equal(result.logicalStateSha256, fixture('logical_state_empty').logical_state_sha256)
  } finally {
    database.remove()
  }
})

test('empty-state verifier fails closed for partial bootstrap state', () => {
  const database = createTestDatabase()
  try {
    const writer = new DatabaseSync(database.databasePath)
    try {
      writer.exec('PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON')
      writer.prepare(`
        INSERT INTO atlas_principals(id, principal_code, principal_kind_code, created_by_principal_id, created_at)
        VALUES (1, 'system.bootstrap', 'service', 1, '2030-01-01T00:00:00.000Z')
      `).run()
    } finally {
      writer.close()
    }
    assert.throws(
      () => verifyEmptyCanonicalState(verificationInput(database.databasePath)),
      /atlas_principals differs from the declared logical state/,
    )
  } finally {
    database.remove()
  }
})

test('empty-state verifier detects migration-ledger substitution', () => {
  const database = createTestDatabase()
  try {
    const writer = new DatabaseSync(database.databasePath)
    try {
      writer.exec('PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON')
      writer.prepare("UPDATE migration_checksums SET sha256 = ? WHERE name = '005_tranche_2a_source_quarantine.sql'").run('0'.repeat(64))
    } finally {
      writer.close()
    }
    assert.throws(
      () => verifyEmptyCanonicalState(verificationInput(database.databasePath)),
      /migration ledger differs/,
    )
  } finally {
    database.remove()
  }
})

test('empty-state verifier rejects a substituted state seal or runtime binding', () => {
  const database = createTestDatabase()
  try {
    const substitutedSeal = fixture('logical_state_empty')
    substitutedSeal.logical_state_sha256 = '0'.repeat(64)
    assert.throws(
      () => verifyEmptyCanonicalState({
        ...verificationInput(database.databasePath),
        expectedStateSeal: substitutedSeal,
      }),
      /logical-state seal or payload digest is invalid/,
    )

    const substitutedRuntime = verificationInput(database.databasePath)
    substitutedRuntime.runtimeProfile = {
      ...substitutedRuntime.runtimeProfile,
      record_digest_sha256: '0'.repeat(64),
    }
    assert.throws(
      () => verifyEmptyCanonicalState(substitutedRuntime),
      /does not bind the verified runtime\/database contract/,
    )

    const incompleteInventory = fixture('logical_state_empty')
    incompleteInventory.state_payload.legacy_rows.pop()
    incompleteInventory.logical_state_sha256 = canonicalSha256(incompleteInventory.state_payload)
    incompleteInventory.record_digest_sha256 = canonicalSha256(incompleteInventory, {
      excludedTopLevelField: 'record_digest_sha256',
    })
    assert.throws(
      () => verifyEmptyCanonicalState({
        ...verificationInput(database.databasePath),
        expectedStateSeal: incompleteInventory,
      }),
      /exact frozen row-projection inventories/,
    )
  } finally {
    database.remove()
  }
})

test('empty-state verifier refuses a symlink database path', () => {
  const database = createTestDatabase()
  const linkPath = path.join(path.dirname(database.databasePath), 'linked.sqlite')
  try {
    fs.symlinkSync(database.databasePath, linkPath)
    assert.throws(
      () => verifyEmptyCanonicalState(verificationInput(linkPath)),
      /regular non-symlink file/,
    )
  } finally {
    database.remove()
  }
})

test('empty-state verifier keeps one descriptor-bound inode and rejects pathname replacement', () => {
  const database = createTestDatabase()
  const displacedPath = `${database.databasePath}.displaced`
  const originalLstat = fs.lstatSync
  let databaseLstatCount = 0
  try {
    fs.lstatSync = function instrumentedLstat(candidate, options) {
      if (candidate === database.databasePath) {
        databaseLstatCount += 1
        if (databaseLstatCount === 2) {
          fs.renameSync(database.databasePath, displacedPath)
          fs.copyFileSync(displacedPath, database.databasePath)
        }
      }
      return originalLstat.call(fs, candidate, options)
    }
    assert.throws(
      () => verifyEmptyCanonicalState(verificationInput(database.databasePath)),
      (error) => error.code === 'DATABASE_PATH_CHANGED',
    )
  } finally {
    fs.lstatSync = originalLstat
    database.remove()
  }
})
