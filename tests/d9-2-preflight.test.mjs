import assert from 'node:assert/strict'
import fs from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import {
  assertPreflightResult,
  preflightEvidenceBundle,
} from '../d9/data-plane/preflight.mjs'
import { createTestDatabase } from './helpers.mjs'
import { createSyntheticRuntimeFixture, runtimeFor } from './d9-2-support/fixture.mjs'

const goldenVectors = JSON.parse(fs.readFileSync(
  new URL('../docs/schema/d9-0/fixtures/golden-vectors-v1.json', import.meta.url),
  'utf8',
))
function manifestFixture() {
  return structuredClone(goldenVectors.complete_manifest_vector.value)
}

function runtimeFixture(runtimeContext, manifest, options = {}) {
  return runtimeFor(runtimeContext, manifest, options)
}

function resign(manifest) {
  manifest.bundle_digest_sha256 = canonicalSha256(manifest, {
    excludedTopLevelField: 'bundle_digest_sha256',
  })
  return manifest
}

function databaseFixture(t) {
  const fixture = createTestDatabase()
  const database = new DatabaseSync(fixture.databasePath)
  database.exec('PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON')
  t.after(() => {
    database.close()
    fixture.remove()
  })
  return { database, runtimeContext: createSyntheticRuntimeFixture(t) }
}

function atlasRowCount(database) {
  return database.prepare(`
    SELECT SUM(row_count) AS row_count
    FROM (
      SELECT COUNT(*) AS row_count FROM atlas_principals
      UNION ALL SELECT COUNT(*) FROM atlas_languages
      UNION ALL SELECT COUNT(*) FROM atlas_jurisdictions
      UNION ALL SELECT COUNT(*) FROM atlas_jurisdiction_versions
      UNION ALL SELECT COUNT(*) FROM atlas_evidence_bundle_receipts
      UNION ALL SELECT COUNT(*) FROM atlas_retrieval_locations
      UNION ALL SELECT COUNT(*) FROM atlas_artifacts
      UNION ALL SELECT COUNT(*) FROM atlas_retrieval_events
      UNION ALL SELECT COUNT(*) FROM atlas_retrieval_redirects
      UNION ALL SELECT COUNT(*) FROM atlas_artifact_custody_events
      UNION ALL SELECT COUNT(*) FROM atlas_processing_runs
      UNION ALL SELECT COUNT(*) FROM atlas_processing_outputs
      UNION ALL SELECT COUNT(*) FROM atlas_unverified_candidate_occurrences
    )
  `).get().row_count
}

function assertCode(code) {
  return (error) => {
    assert.equal(error.code, code)
    return true
  }
}

test('preflights the frozen bootstrap bundle without entering a transaction or changing Atlas state', (t) => {
  const { database, runtimeContext } = databaseFixture(t)
  const manifest = manifestFixture()
  const runtime = runtimeFixture(runtimeContext, manifest)
  const before = atlasRowCount(database)

  const result = preflightEvidenceBundle({ database, manifest, runtime })
  const metadata = assertPreflightResult(result)

  assert.deepEqual(result, {
    preflightVersion: '1.0.0',
    mode: 'insert',
    bundleId: manifest.bundle_id,
    bundleSequence: manifest.bundle_sequence,
    bundleDigestSha256: manifest.bundle_digest_sha256,
    usedDependencyBundleIds: [],
  })
  assert.equal(Object.isFrozen(result), true)
  assert.equal(Object.isFrozen(metadata), true)
  assert.deepEqual(metadata.manifest, manifest)
  assert.deepEqual(metadata.runtime, runtime)
  assert.notEqual(metadata.manifest, manifest)
  assert.notEqual(metadata.runtime, runtime)
  assert.equal(database.isTransaction, false)
  assert.equal(atlasRowCount(database), before)
  assert.throws(() => assertPreflightResult({ ...result }), assertCode('UNVERIFIED_PREFLIGHT_RESULT'))

  manifest.bundle_id = 'mutated.after.preflight'
  assert.throws(() => { runtime.importerVersion = 'mutated' }, TypeError)
  assert.equal(metadata.manifest.bundle_id, 'synthetic.bootstrap-bundle')
  assert.equal(metadata.runtime.importerVersion, '1.0.0')
})

test('fails before mutation for authenticated-runtime mismatch and active SQL transaction', (t) => {
  const { database, runtimeContext } = databaseFixture(t)
  const before = atlasRowCount(database)

  const spoofed = manifestFixture()
  spoofed.expected_importer_principal_code = 'synthetic.spoofed-importer'
  resign(spoofed)
  assert.throws(
    () => preflightEvidenceBundle({
      database,
      manifest: spoofed,
      runtime: runtimeFixture(runtimeContext, spoofed),
    }),
    assertCode('ATTRIBUTION_MISMATCH'),
  )
  assert.equal(atlasRowCount(database), before)

  const matchingButUntrustedRuntime = {
    authenticatedSubmitterPrincipalCode: 'synthetic.human',
    authenticatedImporterPrincipalCode: 'synthetic.importer',
    authenticatedCollectorPrincipalCode: 'synthetic.collector',
    importerSoftwareCode: 'synthetic-importer',
    importerVersion: '1.0.0',
    manifestByteLength: 1,
    policy: runtimeContext.verifiedGeneration.runtimeProfile,
  }
  assert.throws(
    () => preflightEvidenceBundle({ database, manifest: manifestFixture(), runtime: matchingButUntrustedRuntime }),
    assertCode('RUNTIME_BINDING_MISSING'),
  )

  database.exec('BEGIN')
  try {
    assert.throws(
      () => preflightEvidenceBundle({ database, manifest: manifestFixture(), runtime: runtimeFixture(runtimeContext, manifestFixture()) }),
      assertCode('PREFLIGHT_TRANSACTION_ACTIVE'),
    )
  } finally {
    database.exec('ROLLBACK')
  }
  assert.equal(atlasRowCount(database), before)
})

test('enforces the frozen pilot zero-processing boundary and bootstrap actor separation', (t) => {
  const { database, runtimeContext } = databaseFixture(t)
  const processingManifest = manifestFixture()
  processingManifest.processing_runs.push({ outputs: [] })
  resign(processingManifest)
  assert.throws(
    () => preflightEvidenceBundle({ database, manifest: processingManifest, runtime: runtimeFixture(runtimeContext, processingManifest) }),
    assertCode('PILOT_SHAPE_MISMATCH'),
  )

  const actorManifest = manifestFixture()
  actorManifest.principal_bootstrap.principals = actorManifest.principal_bootstrap.principals.filter(
    ({ runtime_role_code: role }) => role !== 'collector',
  )
  resign(actorManifest)
  assert.throws(
    () => preflightEvidenceBundle({ database, manifest: actorManifest, runtime: runtimeFixture(runtimeContext, actorManifest, { componentTestOnly: true }) }),
    assertCode('INVALID_BOOTSTRAP'),
  )
})

test('rejects digest drift, forbidden credential material, and noncausal bootstrap creation', (t) => {
  const { database, runtimeContext } = databaseFixture(t)
  const digestDrift = manifestFixture()
  digestDrift.bundle_created_at = '2030-01-01T00:07:00.000Z'
  assert.throws(
    () => preflightEvidenceBundle({ database, manifest: digestDrift, runtime: runtimeFixture(runtimeContext, digestDrift) }),
    assertCode('DIGEST_MISMATCH'),
  )

  const secret = manifestFixture()
  secret.api_key = 'synthetic-secret'
  resign(secret)
  assert.throws(
    () => preflightEvidenceBundle({ database, manifest: secret, runtime: runtimeFixture(runtimeContext, secret) }),
    assertCode('FORBIDDEN_MATERIAL'),
  )

  const noncausal = manifestFixture()
  noncausal.principal_bootstrap.principals[0].created_at = '2030-01-01T00:05:09.000Z'
  resign(noncausal)
  assert.throws(
    () => preflightEvidenceBundle({ database, manifest: noncausal, runtime: runtimeFixture(runtimeContext, noncausal) }),
    assertCode('INVALID_BOOTSTRAP'),
  )
})
