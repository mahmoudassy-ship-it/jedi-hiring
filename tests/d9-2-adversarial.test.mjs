import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import { createTestDatabase } from './helpers.mjs'
import { compileReviewedManifestReader, openApprovedEvidenceManifest } from '../d9/data-plane/manifest.mjs'
import { preflightEvidenceBundle } from '../d9/data-plane/preflight.mjs'
import { buildImportPlan, serializeImportPlan } from '../d9/data-plane/plan.mjs'
import { applyImportPlanToCandidate, createSyntheticWriterFault } from '../d9/data-plane/writer.mjs'
import { cloneDisposableCandidate, openSyntheticReadOnlyDatabaseDescriptor } from '../d9/data-plane/candidate.mjs'
import { logicalStateDigest, snapshotDatabase, verifyPersistedBundleProjection } from '../d9/data-plane/projection.mjs'
import { verifyOrPlanAcceptedBundle } from '../d9/data-plane/coordinator.mjs'
import { createReviewedEvidenceFixture, materializeProcessingComponentBundle, runtimeFor } from './d9-2-support/fixture.mjs'

function sourceFor(t, databasePath) {
  const descriptor = fs.openSync(databasePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  const source = openSyntheticReadOnlyDatabaseDescriptor(descriptor)
  t.after(() => { source.close(); fs.closeSync(descriptor) })
  return source
}

function cloneValue(value) {
  return structuredClone(value)
}

async function acceptedBootstrap(t, fixture, reader) {
  const base = createTestDatabase()
  t.after(base.remove)
  const source = sourceFor(t, base.databasePath)
  const result = await verifyOrPlanAcceptedBundle({ source, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: fixture.bootstrap.manifest_path, reader, byteAdapter: fixture.byteAdapter, runtimeContext: fixture.runtimeContext })
  t.after(() => result.candidate.dispose())
  return result.candidate
}

test('all nine plan tables roll back after a late writer fault and the deterministic plan is byte-stable', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = compileReviewedManifestReader()
  t.after(() => reader.dispose())
  const bootstrap = await acceptedBootstrap(t, fixture, reader)
  const manifest = materializeProcessingComponentBundle(fixture)
  const opened = openApprovedEvidenceManifest({ reader, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: manifest.manifest_path })
  const source = sourceFor(t, bootstrap.candidateDatabasePath)
  const runtime = runtimeFor(fixture.runtimeContext, opened.manifest, { componentTestOnly: true })
  const first = buildImportPlan(preflightEvidenceBundle({ database: source.database, manifest: opened.manifest, runtime }))
  const second = buildImportPlan(preflightEvidenceBundle({ database: source.database, manifest: opened.manifest, runtime }))
  assert.equal(first.plan_digest_sha256, second.plan_digest_sha256)
  assert.deepEqual(serializeImportPlan(first), serializeImportPlan(second))
  for (const [table, rows] of Object.entries(first.rows)) assert.ok(rows.length > 0, `${table} must be represented in the rollback fixture`)

  const candidate = await cloneDisposableCandidate({ source })
  t.after(() => candidate.dispose())
  const beforeDb = new DatabaseSync(candidate.candidateDatabasePath, { readOnly: true })
  const beforeDigest = logicalStateDigest(beforeDb)
  const beforeSnapshot = snapshotDatabase(beforeDb)
  beforeDb.close()
  for (const [faultCode, errorCode] of [
    ['after_all_rows', 'WRITER_SYNTHETIC_FAULT'],
    ['integrity_corruption', 'WRITER_INTEGRITY_FAILED'],
    ['projection_extra_row', 'PROJECTION_MISMATCH'],
  ]) {
    assert.throws(
      () => applyImportPlanToCandidate({ candidate, plan: first, syntheticFault: createSyntheticWriterFault(faultCode) }),
      (error) => error.code === errorCode,
    )
    const afterDb = new DatabaseSync(candidate.candidateDatabasePath, { readOnly: true })
    assert.equal(logicalStateDigest(afterDb), beforeDigest)
    assert.deepEqual(snapshotDatabase(afterDb), beforeSnapshot)
    afterDb.close()
  }
})

test('projection verifier detects drift in every persisted evidence table', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = compileReviewedManifestReader()
  t.after(() => reader.dispose())
  const bootstrap = await acceptedBootstrap(t, fixture, reader)
  const manifest = materializeProcessingComponentBundle(fixture)
  const opened = openApprovedEvidenceManifest({ reader, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: manifest.manifest_path })
  const source = sourceFor(t, bootstrap.candidateDatabasePath)
  const plan = buildImportPlan(preflightEvidenceBundle({ database: source.database, manifest: opened.manifest, runtime: runtimeFor(fixture.runtimeContext, opened.manifest, { componentTestOnly: true }) }))
  const candidate = await cloneDisposableCandidate({ source })
  t.after(() => candidate.dispose())
  applyImportPlanToCandidate({ candidate, plan })

  const mutations = [
    ['atlas_evidence_bundle_receipts', 'atlas_evidence_bundle_receipts_immutable_update', "UPDATE atlas_evidence_bundle_receipts SET importer_version='drift' WHERE bundle_code='synthetic.bundle-002'"],
    ['atlas_retrieval_locations', 'atlas_retrieval_locations_immutable_update', "UPDATE atlas_retrieval_locations SET location_url='https://example.invalid/drift' WHERE evidence_bundle_receipt_id=(SELECT id FROM atlas_evidence_bundle_receipts WHERE bundle_code='synthetic.bundle-002') LIMIT 1"],
    ['atlas_artifacts', 'atlas_artifacts_immutable_update', "UPDATE atlas_artifacts SET recorded_at='2030-01-01T00:06:29.000Z' WHERE evidence_bundle_receipt_id=(SELECT id FROM atlas_evidence_bundle_receipts WHERE bundle_code='synthetic.bundle-002') LIMIT 1"],
    ['atlas_retrieval_events', 'atlas_retrieval_events_immutable_update', "UPDATE atlas_retrieval_events SET collector_version='drift' WHERE retrieval_event_code='synthetic.bundle-002.retrieval-001'"],
    ['atlas_retrieval_redirects', 'atlas_retrieval_redirects_immutable_update', "UPDATE atlas_retrieval_redirects SET http_status_code=301 WHERE redirect_code='synthetic.bundle-002.redirect-001'"],
    ['atlas_artifact_custody_events', 'atlas_artifact_custody_events_immutable_update', "UPDATE atlas_artifact_custody_events SET reason='drift' WHERE custody_event_code='synthetic.bundle-002.custody-derived'"],
    ['atlas_processing_runs', 'atlas_processing_runs_immutable_update', "UPDATE atlas_processing_runs SET processor_version='drift' WHERE processing_run_code='synthetic.bundle-002.run-parser'"],
    ['atlas_processing_outputs', 'atlas_processing_outputs_immutable_update', "UPDATE atlas_processing_outputs SET detected_media_type='application/octet-stream' WHERE processing_output_code='synthetic.bundle-002.output-text'"],
    ['atlas_unverified_candidate_occurrences', 'atlas_candidate_occurrences_immutable_update', "UPDATE atlas_unverified_candidate_occurrences SET reason='drift' WHERE candidate_record_code='synthetic.bundle-002.candidate-title'"],
  ]
  for (const [table, trigger, sql] of mutations) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `jedi-d9-2-${table}-`))
    const mutatedPath = path.join(root, 'mutation.sqlite')
    fs.copyFileSync(candidate.candidateDatabasePath, mutatedPath)
    const database = new DatabaseSync(mutatedPath)
    database.exec(`DROP TRIGGER ${trigger}`)
    database.exec(sql)
    assert.throws(() => verifyPersistedBundleProjection({ database, manifest: opened.manifest }), (error) => error.code === 'PROJECTION_MISMATCH')
    database.close()
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic mutation matrix rejects before any transaction begins', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = compileReviewedManifestReader()
  t.after(() => reader.dispose())
  const bootstrap = await acceptedBootstrap(t, fixture, reader)
  const source = sourceFor(t, bootstrap.candidateDatabasePath)
  const base = fixture.document
  const cases = [
    ['dependency digest', (value) => { value.required_bundles[0].bundle_digest_sha256 = 'f'.repeat(64) }],
    ['location chronology', (value) => { value.retrieval_locations[0].recorded_at = '2030-01-01T00:05:15.000Z' }],
    ['artifact identity', (value) => { value.artifacts[0].sha256 = 'e'.repeat(64) }],
    ['partial HTTP response', (value) => { value.retrieval_events[0].http_status_code = 206 }],
    ['custody reference', (value) => { value.custody_events[0].backend_reference = 'objects/sha256/00/drift' }],
  ]
  for (const [label, mutate] of cases) {
    const manifest = cloneValue(base)
    mutate(manifest)
    manifest.bundle_digest_sha256 = canonicalSha256ForManifest(manifest)
    assert.equal(source.database.isTransaction, false)
    assert.throws(() => preflightEvidenceBundle({ database: source.database, manifest, runtime: runtimeFor(fixture.runtimeContext, manifest, { componentTestOnly: true }) }), undefined, label)
    assert.equal(source.database.isTransaction, false)
  }
})

function canonicalSha256ForManifest(manifest) {
  return canonicalSha256(manifest, { excludedTopLevelField: 'bundle_digest_sha256' })
}

test('replay identity drift fails closed without touching the accepted database', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = compileReviewedManifestReader()
  t.after(() => reader.dispose())
  const bootstrap = await acceptedBootstrap(t, fixture, reader)
  const source = sourceFor(t, bootstrap.candidateDatabasePath)
  const before = logicalStateDigest(source.database)
  const replay = structuredClone(fixture.bootstrap)
  replay.bundle_created_at = '2030-01-01T00:06:01.000Z'
  replay.bundle_digest_sha256 = canonicalSha256ForManifest(replay)
  const replayPath = path.join(fixture.root, replay.manifest_path)
  fs.writeFileSync(replayPath, `${JSON.stringify(replay, null, 2)}\n`)
  await assert.rejects(
    verifyOrPlanAcceptedBundle({ source, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: replay.manifest_path, reader, byteAdapter: fixture.byteAdapter, runtimeContext: fixture.runtimeContext }),
    (error) => error.code === 'ACCEPTED_REPLAY_DRIFT',
  )
  assert.equal(logicalStateDigest(source.database), before)
})
