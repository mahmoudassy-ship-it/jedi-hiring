import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import { createTestDatabase } from './helpers.mjs'
import { validateApprovedRecord } from '../d9/control-plane/contracts.mjs'
import { compileReviewedManifestReader, openApprovedEvidenceManifest } from '../d9/data-plane/manifest.mjs'
import { preflightEvidenceBundle } from '../d9/data-plane/preflight.mjs'
import { buildImportPlan } from '../d9/data-plane/plan.mjs'
import { applyImportPlanToCandidate, createSyntheticWriterFault } from '../d9/data-plane/writer.mjs'
import { cloneDisposableCandidate, openSyntheticReadOnlyDatabaseDescriptor } from '../d9/data-plane/candidate.mjs'
import { verifyPersistedBundleProjection, logicalStateDigest } from '../d9/data-plane/projection.mjs'
import { reconstructSyntheticAcceptedSet, verifyOrPlanAcceptedBundle } from '../d9/data-plane/coordinator.mjs'
import { verifyAcceptedCandidate } from '../d9/data-plane/verifier.mjs'
import { createReviewedEvidenceFixture, createSyntheticRuntimeFixture, materializeProcessingComponentBundle, runtimeFor } from './d9-2-support/fixture.mjs'
import { fixture as d91Fixture } from './d9-1-support/runtime-fixture.mjs'

function sourceFor(t, databasePath) {
  const descriptor = fs.openSync(databasePath, fs.constants.O_RDONLY | fs.constants.O_CLOEXEC | fs.constants.O_NOFOLLOW)
  const source = openSyntheticReadOnlyDatabaseDescriptor(descriptor)
  t.after(() => { source.close(); fs.closeSync(descriptor) })
  return source
}

function readerFor(t) {
  const reader = compileReviewedManifestReader()
  t.after(() => reader.dispose())
  return reader
}

async function bootstrapCandidate(t, fixture, reader) {
  const base = createTestDatabase()
  t.after(base.remove)
  const source = sourceFor(t, base.databasePath)
  const result = await verifyOrPlanAcceptedBundle({
    source,
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.bootstrap.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  })
  assert.equal(result.outcome, 'candidate_verified')
  t.after(() => result.candidate.dispose())
  return { base, result }
}

test('bootstrap candidate is verified independently and exact accepted replay is a read-only no-op', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const { base, result } = await bootstrapCandidate(t, fixture, reader)
  assert.equal(result.verification.candidate.acceptedBundleCount, 1)
  assert.equal(result.verification.syntheticPostCopyGeneration.logicalStateSha256, result.verification.candidate.logicalStateSha256)
  assert.equal(result.verification.candidate.logicalStateProjection.throughBundleSequence, 1)
  assert.equal(result.verification.candidate.logicalStateProjection.priorLogicalStateSha256, fixture.runtimeContext.baselineStateSeal.logical_state_sha256)
  assert.equal(result.verification.candidate.logicalStateProjection.statePayload.receipt_head.bundle_id, fixture.bootstrap.bundle_id)
  const expectedBootstrapState = d91Fixture('logical_state_bootstrap').state_payload
  expectedBootstrapState.runtime_profile_record_digest_sha256 = fixture.runtimeContext.verifiedGeneration.runtimeProfile.record_digest_sha256
  expectedBootstrapState.prior_logical_state_sha256 = fixture.runtimeContext.baselineStateSeal.logical_state_sha256
  assert.deepEqual(result.verification.candidate.logicalStateProjection.statePayload, expectedBootstrapState)
  assert.equal(result.verification.candidate.logicalStateSha256, canonicalSha256(expectedBootstrapState))

  const projectedSeal = {
    format: 'jedi-atlas-logical-state-seal',
    format_version: '1.0.0',
    record_kind_code: 'logical_state_seal',
    record_code: 'synthetic.d9-2-projected-state',
    state_payload: result.verification.candidate.logicalStateProjection.statePayload,
    logical_state_sha256: result.verification.candidate.logicalStateSha256,
    produced_by_binding_code: 'binding.verifier',
    produced_at: '2030-01-01T00:09:00.000Z',
    record_digest_sha256: '0'.repeat(64),
  }
  projectedSeal.record_digest_sha256 = canonicalSha256(projectedSeal, { excludedTopLevelField: 'record_digest_sha256' })
  assert.doesNotThrow(() => validateApprovedRecord({
    contractSet: fixture.runtimeContext.contractSet,
    schemaFile: 'logical-state-seal-v1.schema.json',
    record: projectedSeal,
  }))

  const baseDb = new DatabaseSync(base.databasePath, { readOnly: true })
  assert.equal(baseDb.prepare('SELECT count(*) AS count FROM atlas_principals').get().count, 0)
  assert.equal(baseDb.prepare('SELECT count(*) AS count FROM atlas_evidence_bundle_receipts').get().count, 0)
  baseDb.close()

  const acceptedSource = sourceFor(t, result.candidate.candidateDatabasePath)
  const before = logicalStateDigest(acceptedSource.database)
  const noOp = await verifyOrPlanAcceptedBundle({
    source: acceptedSource,
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.bootstrap.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  })
  assert.equal(noOp.outcome, 'no_op_verified')
  assert.equal(noOp.verification.acceptedBundleCount, 1)
  assert.equal(logicalStateDigest(acceptedSource.database), before)
})

test('document candidate preserves the exact evidence projection and accepted replay verifies custody bytes', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const bootstrap = await bootstrapCandidate(t, fixture, reader)
  const bootstrapSource = sourceFor(t, bootstrap.result.candidate.candidateDatabasePath)
  const document = await verifyOrPlanAcceptedBundle({
    source: bootstrapSource,
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.document.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  })
  t.after(() => document.candidate.dispose())
  assert.equal(document.outcome, 'candidate_verified')
  assert.equal(document.verification.candidate.acceptedBundleCount, 2)
  assert.equal(document.verification.candidate.custodyObjectsChecked, 1)
  assert.equal(document.verification.candidate.logicalStateProjection.throughBundleSequence, 2)
  assert.equal(
    document.verification.candidate.logicalStateProjection.priorLogicalStateSha256,
    bootstrap.result.verification.candidate.logicalStateSha256,
  )
  const expectedDocumentState = d91Fixture('logical_state_document_002').state_payload
  expectedDocumentState.runtime_profile_record_digest_sha256 = fixture.runtimeContext.verifiedGeneration.runtimeProfile.record_digest_sha256
  expectedDocumentState.prior_logical_state_sha256 = bootstrap.result.verification.candidate.logicalStateSha256
  assert.deepEqual(document.verification.candidate.logicalStateProjection.statePayload, expectedDocumentState)
  assert.equal(document.verification.candidate.logicalStateSha256, canonicalSha256(expectedDocumentState))

  const database = new DatabaseSync(document.candidate.candidateDatabasePath, { readOnly: true })
  const evidence = database.prepare(`SELECT r.bundle_code,l.location_url,e.started_at,e.completed_at,e.captured_at,
      e.collector_version,a.sha256,a.byte_length,c.custody_class_code,c.reason
    FROM atlas_evidence_bundle_receipts r
    JOIN atlas_retrieval_locations l ON l.evidence_bundle_receipt_id=r.id
    JOIN atlas_retrieval_events e ON e.evidence_bundle_receipt_id=r.id
    JOIN atlas_artifacts a ON a.id=e.artifact_id
    JOIN atlas_artifact_custody_events c ON c.artifact_id=a.id
    WHERE r.bundle_code=?`).get(fixture.document.bundle_id)
  assert.deepEqual({ ...evidence }, {
    bundle_code: fixture.document.bundle_id,
    location_url: fixture.document.retrieval_locations[0].url,
    started_at: fixture.document.retrieval_events[0].started_at,
    completed_at: fixture.document.retrieval_events[0].completed_at,
    captured_at: fixture.document.retrieval_events[0].captured_at,
    collector_version: fixture.document.retrieval_events[0].collector_version,
    sha256: fixture.document.artifacts[0].sha256,
    byte_length: fixture.document.artifacts[0].byte_length,
    custody_class_code: 'restricted_store',
    reason: fixture.document.custody_events[0].reason,
  })
  database.close()

  const acceptedSource = sourceFor(t, document.candidate.candidateDatabasePath)
  const before = logicalStateDigest(acceptedSource.database)
  const noOp = await verifyOrPlanAcceptedBundle({
    source: acceptedSource,
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.document.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  })
  assert.equal(noOp.outcome, 'no_op_verified')
  assert.equal(noOp.verification.acceptedBundleCount, 2)
  assert.equal(noOp.verification.custodyObjectsChecked, 1)
  assert.equal(logicalStateDigest(acceptedSource.database), before)
})

test('bootstrap no-op remains receipt-prefix bounded after a document bundle exists', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const bootstrap = await bootstrapCandidate(t, fixture, reader)
  const document = await verifyOrPlanAcceptedBundle({
    source: sourceFor(t, bootstrap.result.candidate.candidateDatabasePath),
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.document.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  })
  t.after(() => document.candidate.dispose())
  fs.unlinkSync(path.join(fixture.root, fixture.document.artifacts[0].staged_path))
  const acceptedSource = sourceFor(t, document.candidate.candidateDatabasePath)
  const bootstrapReplay = await verifyOrPlanAcceptedBundle({
    source: acceptedSource,
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.bootstrap.manifest_path,
    reader,
    byteAdapter: undefined,
    runtimeContext: fixture.runtimeContext,
  })
  assert.equal(bootstrapReplay.outcome, 'no_op_verified')
  assert.equal(bootstrapReplay.verification.acceptedBundleCount, 1)
  assert.equal(bootstrapReplay.verification.custodyObjectsChecked, 0)
  await assert.rejects(reconstructSyntheticAcceptedSet({
    expectedVerification: bootstrapReplay.verification,
    manifestRelativePaths: [fixture.bootstrap.manifest_path],
    reader,
    reviewedRootDescriptor: fixture.descriptor,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  }), (error) => error.code === 'RECONSTRUCTION_INPUT_INVALID')
  await assert.rejects(verifyOrPlanAcceptedBundle({
    source: acceptedSource,
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.document.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  }), (error) => error.code === 'BYTE_OPEN_FAILED')
})

test('no-op verification fails closed on persisted projection drift and unavailable retained bytes', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const bootstrap = await bootstrapCandidate(t, fixture, reader)
  const bootstrapSource = sourceFor(t, bootstrap.result.candidate.candidateDatabasePath)
  const document = await verifyOrPlanAcceptedBundle({ source: bootstrapSource, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: fixture.document.manifest_path, reader, byteAdapter: fixture.byteAdapter, runtimeContext: fixture.runtimeContext })
  t.after(() => document.candidate.dispose())

  const mutationRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-projection-mutation-'))
  t.after(() => fs.rmSync(mutationRoot, { recursive: true, force: true }))
  const mutatedPath = path.join(mutationRoot, 'mutated.sqlite')
  fs.copyFileSync(document.candidate.candidateDatabasePath, mutatedPath)
  const mutationDb = new DatabaseSync(mutatedPath)
  mutationDb.exec('PRAGMA foreign_keys=ON; DROP TRIGGER atlas_retrieval_events_immutable_update')
  mutationDb.prepare('UPDATE atlas_retrieval_events SET response_etag=?').run('"drifted"')
  mutationDb.close()
  const mutatedSource = sourceFor(t, mutatedPath)
  await assert.rejects(
    verifyOrPlanAcceptedBundle({ source: mutatedSource, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: fixture.document.manifest_path, reader, byteAdapter: fixture.byteAdapter, runtimeContext: fixture.runtimeContext }),
    (error) => error.code === 'STATE_SCHEMA_MISMATCH',
  )

  const artifactPath = path.join(fixture.root, fixture.document.artifacts[0].staged_path)
  const originalBytes = fs.readFileSync(artifactPath)
  const changedBytes = Buffer.from(originalBytes)
  changedBytes[0] ^= 0xff
  fs.writeFileSync(artifactPath, changedBytes)
  const acceptedSource = sourceFor(t, document.candidate.candidateDatabasePath)
  await assert.rejects(
    verifyOrPlanAcceptedBundle({ source: acceptedSource, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: fixture.document.manifest_path, reader, byteAdapter: fixture.byteAdapter, runtimeContext: fixture.runtimeContext }),
    (error) => error.code === 'ARTIFACT_INTEGRITY_MISMATCH',
  )
  fs.writeFileSync(artifactPath, originalBytes)
  fs.unlinkSync(artifactPath)
  await assert.rejects(
    verifyOrPlanAcceptedBundle({ source: acceptedSource, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: fixture.document.manifest_path, reader, byteAdapter: fixture.byteAdapter, runtimeContext: fixture.runtimeContext }),
    (error) => error.code === 'BYTE_OPEN_FAILED',
  )
})

test('fixed writer rolls back every inserted table and bootstrap principal on an injected late failure', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const base = createTestDatabase()
  t.after(base.remove)
  const source = sourceFor(t, base.databasePath)
  const preflight = preflightEvidenceBundle({ database: source.database, manifest: fixture.bootstrap, runtime: runtimeFor(fixture.runtimeContext, fixture.bootstrap) })
  const plan = buildImportPlan(preflight)
  const candidate = await cloneDisposableCandidate({ source })
  t.after(() => candidate.dispose())
  const beforeDb = new DatabaseSync(candidate.candidateDatabasePath, { readOnly: true })
  const before = logicalStateDigest(beforeDb)
  beforeDb.close()
  assert.throws(
    () => applyImportPlanToCandidate({ candidate, plan, syntheticFault: createSyntheticWriterFault() }),
    (error) => error.code === 'WRITER_SYNTHETIC_FAULT',
  )
  const afterDb = new DatabaseSync(candidate.candidateDatabasePath, { readOnly: true })
  assert.equal(logicalStateDigest(afterDb), before)
  assert.equal(afterDb.prepare('SELECT count(*) AS count FROM atlas_principals').get().count, 0)
  assert.equal(afterDb.prepare('SELECT count(*) AS count FROM atlas_evidence_bundle_receipts').get().count, 0)
  afterDb.close()
})

test('typed component projection preserves parser version, lineage, candidate value, locator and limitation reason while pilot gate rejects it', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const bootstrap = await bootstrapCandidate(t, fixture, reader)
  const manifest = materializeProcessingComponentBundle(fixture)

  const opened = openApprovedEvidenceManifest({ reader, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: manifest.manifest_path })
  const source = sourceFor(t, bootstrap.result.candidate.candidateDatabasePath)
  assert.throws(() => preflightEvidenceBundle({ database: source.database, manifest: opened.manifest, runtime: runtimeFor(fixture.runtimeContext, opened.manifest) }), (error) => error.code === 'PILOT_SHAPE_MISMATCH')
  const componentRuntime = runtimeFor(fixture.runtimeContext, opened.manifest, { componentTestOnly: true })
  const preflight = preflightEvidenceBundle({ database: source.database, manifest: opened.manifest, runtime: componentRuntime })
  const plan = buildImportPlan(preflight)
  const candidate = await cloneDisposableCandidate({ source })
  t.after(() => candidate.dispose())
  applyImportPlanToCandidate({ candidate, plan })
  const database = new DatabaseSync(candidate.candidateDatabasePath, { readOnly: true })
  verifyPersistedBundleProjection({ database, manifest: opened.manifest })
  const persisted = database.prepare(`SELECT r.processor_version,o.output_kind_code,c.observed_value,c.locator_kind_code,c.locator_value,c.reason
    FROM atlas_processing_runs r JOIN atlas_processing_outputs o ON o.processing_run_id=r.id
    JOIN atlas_unverified_candidate_occurrences c ON c.processing_output_id=o.id
    WHERE r.processing_run_code=?`).get('synthetic.bundle-002.run-parser')
  assert.deepEqual({ ...persisted }, { processor_version: '9.2.0-test', output_kind_code: 'extracted_text', observed_value: 'synthetic', locator_kind_code: 'text_span', locator_value: 'text bytes 0..9', reason: 'Unverified synthetic candidate; not a legal conclusion.' })
  database.close()
})

test('from-zero synthetic reconstruction reproduces the accepted data projection while bytes are available', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const bootstrap = await bootstrapCandidate(t, fixture, reader)
  const bootstrapSource = sourceFor(t, bootstrap.result.candidate.candidateDatabasePath)
  const document = await verifyOrPlanAcceptedBundle({ source: bootstrapSource, reviewedRootDescriptor: fixture.descriptor, manifestRelativePath: fixture.document.manifest_path, reader, byteAdapter: fixture.byteAdapter, runtimeContext: fixture.runtimeContext })
  t.after(() => document.candidate.dispose())
  const result = await reconstructSyntheticAcceptedSet({
    expectedVerification: document.verification.candidate,
    manifestRelativePaths: [fixture.bootstrap.manifest_path, fixture.document.manifest_path],
    reader,
    reviewedRootDescriptor: fixture.descriptor,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  })
  assert.equal(result.outcome, 'reconstruction_verified')
  assert.equal(result.acceptedBundleCount, 2)
  assert.equal(result.reconstructableStateSha256, document.verification.candidate.reconstructableStateSha256)

  await assert.rejects(reconstructSyntheticAcceptedSet({
    expectedVerification: { reconstructableStateSha256: document.verification.candidate.reconstructableStateSha256 },
    manifestRelativePaths: [fixture.bootstrap.manifest_path, fixture.document.manifest_path],
    reader,
    reviewedRootDescriptor: fixture.descriptor,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  }), (error) => error.code === 'RECONSTRUCTION_INPUT_INVALID')

  const maliciousRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-malicious-migrations-'))
  t.after(() => fs.rmSync(maliciousRoot, { recursive: true, force: true }))
  const maliciousMigrations = path.join(maliciousRoot, 'data/migrations')
  fs.mkdirSync(maliciousMigrations, { recursive: true })
  for (const name of fs.readdirSync(path.resolve('data/migrations'))) {
    fs.copyFileSync(path.resolve('data/migrations', name), path.join(maliciousMigrations, name))
  }
  const escapedMarker = path.join(maliciousRoot, 'escaped.sqlite').replaceAll("'", "''")
  fs.writeFileSync(path.join(maliciousMigrations, '001_schema.sql'), `ATTACH DATABASE '${escapedMarker}' AS escaped; CREATE TABLE escaped.probe(id INTEGER);\n`)
  const maliciousRuntime = createSyntheticRuntimeFixture(t, { runtimeProjectRoot: maliciousRoot })
  await assert.rejects(reconstructSyntheticAcceptedSet({
    expectedVerification: document.verification.candidate,
    manifestRelativePaths: [fixture.bootstrap.manifest_path, fixture.document.manifest_path],
    reader,
    reviewedRootDescriptor: fixture.descriptor,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: maliciousRuntime,
  }), (error) => error.code === 'RECONSTRUCTION_MIGRATIONS_INVALID')
  assert.equal(fs.existsSync(path.join(maliciousRoot, 'escaped.sqlite')), false)
})

test('writer rejects unbranded plans and symlink database targets before mutation', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const base = createTestDatabase()
  t.after(base.remove)
  const source = sourceFor(t, base.databasePath)
  const plan = buildImportPlan(preflightEvidenceBundle({ database: source.database, manifest: fixture.bootstrap, runtime: runtimeFor(fixture.runtimeContext, fixture.bootstrap) }))
  assert.throws(() => applyImportPlanToCandidate({ candidate: { candidateDatabasePath: base.databasePath }, plan }), (error) => error.code === 'CANDIDATE_UNTRUSTED')
  const candidate = await cloneDisposableCandidate({ source })
  t.after(() => candidate.dispose())
  assert.throws(() => applyImportPlanToCandidate({ candidate, plan: structuredClone(plan) }), (error) => error.code === 'IMPORT_PLAN_UNTRUSTED')
  const displaced = path.join(candidate.root, 'candidate-displaced.sqlite')
  fs.renameSync(candidate.candidateDatabasePath, displaced)
  fs.symlinkSync(displaced, candidate.candidateDatabasePath)
  assert.throws(() => applyImportPlanToCandidate({ candidate, plan }), (error) => error.code === 'CANDIDATE_CHANGED')
})

test('independent verification rejects a candidate path swapped after writing', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const base = createTestDatabase()
  t.after(base.remove)
  const source = sourceFor(t, base.databasePath)
  const plan = buildImportPlan(preflightEvidenceBundle({ database: source.database, manifest: fixture.bootstrap, runtime: runtimeFor(fixture.runtimeContext, fixture.bootstrap) }))
  const candidate = await cloneDisposableCandidate({ source })
  t.after(() => candidate.dispose())
  applyImportPlanToCandidate({ candidate, plan })
  const displaced = path.join(candidate.root, 'written-candidate.sqlite')
  fs.renameSync(candidate.candidateDatabasePath, displaced)
  fs.symlinkSync(displaced, candidate.candidateDatabasePath)
  assert.throws(() => verifyAcceptedCandidate({
    candidate,
    reviewedRootDescriptor: fixture.descriptor,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  }), (error) => error.code === 'CANDIDATE_CHANGED')
})
