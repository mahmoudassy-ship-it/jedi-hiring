import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import { loadApprovedContractSet } from '../d9/control-plane/contracts.mjs'
import { createSyntheticReadOnlyByteAdapter, verifyStagedManifestArtifacts } from '../d9/data-plane/bytes.mjs'
import {
  cloneDisposableCandidate,
  openSyntheticReadOnlyDatabaseDescriptor,
} from '../d9/data-plane/candidate.mjs'
import { verifyOrPlanAcceptedBundle } from '../d9/data-plane/coordinator.mjs'
import { compileReviewedManifestReader, openApprovedEvidenceManifest } from '../d9/data-plane/manifest.mjs'
import { buildImportPlan } from '../d9/data-plane/plan.mjs'
import { preflightEvidenceBundle } from '../d9/data-plane/preflight.mjs'
import { createSyntheticD92RuntimeContext } from '../d9/data-plane/runtime.mjs'
import { applyImportPlanToCandidate } from '../d9/data-plane/writer.mjs'
import { createTestDatabase } from './helpers.mjs'
import { createGenerationFixture, fixture as d91Fixture, reseal, verifyFixture } from './d9-1-support/runtime-fixture.mjs'
import { createReviewedEvidenceFixture, runtimeFor } from './d9-2-support/fixture.mjs'

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

function resignManifest(manifest) {
  manifest.bundle_digest_sha256 = canonicalSha256(manifest, { excludedTopLevelField: 'bundle_digest_sha256' })
  return manifest
}

function writeManifest(root, manifest) {
  fs.writeFileSync(path.join(root, manifest.manifest_path), `${JSON.stringify(manifest, null, 2)}\n`)
}

async function acceptedBootstrap(t, fixture, reader) {
  const base = createTestDatabase()
  t.after(base.remove)
  const result = await verifyOrPlanAcceptedBundle({
    source: sourceFor(t, base.databasePath),
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.bootstrap.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  })
  t.after(() => result.candidate.dispose())
  return result.candidate
}

test('runtime context rejects duplicate or incomplete self-sealed baseline inventories', (t) => {
  const contractSet = loadApprovedContractSet()
  const generation = verifyFixture(contractSet, createGenerationFixture(t))
  const makeSeal = () => {
    const seal = d91Fixture('logical_state_empty')
    seal.state_payload.runtime_profile_record_digest_sha256 = generation.runtimeProfile.record_digest_sha256
    return seal
  }
  const attempt = (mutate) => {
    const seal = makeSeal()
    mutate(seal.state_payload, seal)
    seal.logical_state_sha256 = canonicalSha256(seal.state_payload)
    seal.record_digest_sha256 = canonicalSha256(seal, { excludedTopLevelField: 'record_digest_sha256' })
    assert.throws(() => createSyntheticD92RuntimeContext({
      baselineStateSeal: seal,
      contractSet,
      projectRoot: path.resolve('.'),
      verifiedGeneration: generation,
    }), (error) => error.code === 'RUNTIME_BASELINE_MISMATCH')
  }
  attempt((payload) => { payload.legacy_rows = payload.legacy_rows.map(() => structuredClone(payload.legacy_rows[0])) })
  attempt((payload) => { payload.legacy_rows[0].rows_sha256 = 'e'.repeat(64) })
  attempt((payload) => { payload.legacy_rows[0].row_count += 1 })
  attempt((payload) => { payload.atlas_tables[0].rows_sha256 = 'f'.repeat(64) })
  attempt((payload) => { payload.principal_roster_sha256 = 'f'.repeat(64) })
  attempt((_payload, seal) => { seal.produced_at = '2030-01-01T00:02:01.000Z' })
})

test('baseline seal resolves to the selected independent verifier at production time', (t) => {
  const contractSet = loadApprovedContractSet()
  for (const mutate of [
    (binding) => { binding.binding_code = 'binding.alternate-verifier' },
    (binding) => { binding.valid_from = '2030-01-01T00:05:00.000Z' },
  ]) {
    const generationFixture = createGenerationFixture(t)
    mutate(generationFixture.identity.bindings.find((binding) => binding.runtime_role_code === 'independent_verifier'))
    reseal(generationFixture.identity)
    generationFixture.selection.identity_bindings_record_digest_sha256 = generationFixture.identity.record_digest_sha256
    const generation = verifyFixture(contractSet, generationFixture)
    const seal = d91Fixture('logical_state_empty')
    seal.state_payload.runtime_profile_record_digest_sha256 = generation.runtimeProfile.record_digest_sha256
    seal.logical_state_sha256 = canonicalSha256(seal.state_payload)
    seal.record_digest_sha256 = canonicalSha256(seal, { excludedTopLevelField: 'record_digest_sha256' })
    assert.throws(() => createSyntheticD92RuntimeContext({
      baselineStateSeal: seal,
      contractSet,
      projectRoot: path.resolve('.'),
      verifiedGeneration: generation,
    }), (error) => error.code === 'RUNTIME_BASELINE_MISMATCH')
  }
})

test('byte adapter pins descriptor bindings against caller mutation and descriptor reuse', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-byte-binding-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const originalRoot = path.join(root, 'original')
  const substituteRoot = path.join(root, 'substitute')
  fs.mkdirSync(originalRoot)
  fs.mkdirSync(substituteRoot)
  const relativePath = 'object.bin'
  const expectedBytes = Buffer.from('synthetic substitute bytes', 'utf8')
  fs.writeFileSync(path.join(substituteRoot, relativePath), expectedBytes)
  const originalDescriptor = fs.openSync(originalRoot, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
  const substituteDescriptor = fs.openSync(substituteRoot, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
  const bindings = new Map([['pilot_local_cas_v1', originalDescriptor]])
  const adapter = createSyntheticReadOnlyByteAdapter({
    stagingRootDescriptor: originalDescriptor,
    backendRootDescriptors: bindings,
  })
  t.after(() => adapter.dispose())
  bindings.set('pilot_local_cas_v1', substituteDescriptor)
  fs.closeSync(originalDescriptor)
  fs.closeSync(substituteDescriptor)
  const artifact = {
    record_code: 'artifact.synthetic-binding',
    sha256: crypto.createHash('sha256').update(expectedBytes).digest('hex'),
    byte_length: expectedBytes.length,
  }
  assert.throws(() => adapter.readCustody({
    artifact,
    backendCode: 'pilot_local_cas_v1',
    backendReference: relativePath,
  }), (error) => error.code === 'BYTE_OPEN_FAILED')

  const fifoRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-byte-fifo-'))
  t.after(() => fs.rmSync(fifoRoot, { recursive: true, force: true }))
  assert.equal(fs.existsSync(path.join(fifoRoot, 'pipe')), false)
  const fifoDescriptor = fs.openSync(fifoRoot, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
  assert.equal(spawnSync('/usr/bin/mkfifo', [path.join(fifoRoot, 'pipe')]).status, 0)
  const fifoAdapter = createSyntheticReadOnlyByteAdapter({ stagingRootDescriptor: fifoDescriptor, backendRootDescriptors: new Map() })
  t.after(() => { fifoAdapter.dispose(); fs.closeSync(fifoDescriptor) })
  const startedAt = Date.now()
  assert.throws(() => fifoAdapter.readStaged({ staged_path: 'pipe', byte_length: 0 }), (error) => error.code === 'BYTE_OPEN_FAILED')
  assert.ok(Date.now() - startedAt < 2_000, 'artifact FIFO rejection must not wait for a writer')
})

test('accepted manifests are bound to the verified bootstrap roster and custody backend', async (t) => {
  const bootstrapFixture = createReviewedEvidenceFixture(t)
  const bootstrapReader = readerFor(t)
  const changedBootstrap = structuredClone(bootstrapFixture.bootstrap)
  changedBootstrap.principal_bootstrap.principals[1].principal_code = 'synthetic.unbound-collector'
  resignManifest(changedBootstrap)
  writeManifest(bootstrapFixture.root, changedBootstrap)
  const base = createTestDatabase()
  t.after(base.remove)
  await assert.rejects(verifyOrPlanAcceptedBundle({
    source: sourceFor(t, base.databasePath),
    reviewedRootDescriptor: bootstrapFixture.descriptor,
    manifestRelativePath: changedBootstrap.manifest_path,
    reader: bootstrapReader,
    byteAdapter: bootstrapFixture.byteAdapter,
    runtimeContext: bootstrapFixture.runtimeContext,
  }), (error) => error.code === 'RUNTIME_PROFILE_MISMATCH')

  const documentFixture = createReviewedEvidenceFixture(t)
  const documentReader = readerFor(t)
  const bootstrap = await acceptedBootstrap(t, documentFixture, documentReader)
  const mutations = [
    (manifest) => { manifest.custody_events[0].backend_code = 'unapproved_backend' },
    (manifest) => {
      manifest.retrieval_locations.push({
        record_code: `location.${'1'.repeat(64)}`,
        url: 'https://unused.invalid/document',
        recorded_by_principal_code: 'synthetic.human',
        recorded_at: '2030-01-01T00:05:13.000Z',
      })
    },
    (manifest) => {
      manifest.retrieval_events[0].request_headers.accept_encoding = 'gzip'
      manifest.retrieval_events[0].response_metadata.content_encoding = 'gzip'
    },
  ]
  for (const mutate of mutations) {
    const changedDocument = structuredClone(documentFixture.document)
    mutate(changedDocument)
    resignManifest(changedDocument)
    writeManifest(documentFixture.root, changedDocument)
    await assert.rejects(verifyOrPlanAcceptedBundle({
      source: sourceFor(t, bootstrap.candidateDatabasePath),
      reviewedRootDescriptor: documentFixture.descriptor,
      manifestRelativePath: changedDocument.manifest_path,
      reader: documentReader,
      byteAdapter: documentFixture.byteAdapter,
      runtimeContext: documentFixture.runtimeContext,
    }), (error) => error.code === 'RUNTIME_PROFILE_MISMATCH')
  }
})

test('frozen-state verification rejects legacy drift and writes outside the evidence boundary', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const bootstrap = await acceptedBootstrap(t, fixture, reader)
  const cases = [
    ["UPDATE requirements SET title=title || ' drift' WHERE id=1", 'LEGACY_STATE_MISMATCH'],
    ["INSERT INTO atlas_languages(language_code,recorded_by_principal_id,recorded_at) VALUES('en',2,'2030-01-01T00:05:20.000Z')", 'FORBIDDEN_ATLAS_STATE'],
    ["INSERT INTO schema_migrations(name,applied_at) VALUES('999_unapproved.sql','2030-01-01T00:00:00.000Z')", 'MIGRATION_STATE_MISMATCH'],
    ["DELETE FROM migration_checksums WHERE name='005_tranche_2a_source_quarantine.sql'", 'MIGRATION_STATE_MISMATCH'],
  ]
  for (const [sql, code] of cases) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-boundary-mutation-'))
    t.after(() => fs.rmSync(root, { recursive: true, force: true }))
    const databasePath = path.join(root, 'mutated.sqlite')
    fs.copyFileSync(bootstrap.candidateDatabasePath, databasePath)
    const database = new DatabaseSync(databasePath)
    database.exec('PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON')
    database.exec(sql)
    database.close()
    await assert.rejects(verifyOrPlanAcceptedBundle({
      source: sourceFor(t, databasePath),
      reviewedRootDescriptor: fixture.descriptor,
      manifestRelativePath: fixture.bootstrap.manifest_path,
      reader,
      byteAdapter: fixture.byteAdapter,
      runtimeContext: fixture.runtimeContext,
    }), (error) => error.code === code)
  }
})

test('frozen-state verification rejects protected application-surface drift', async (t) => {
  const protectedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-protected-surfaces-'))
  t.after(() => fs.rmSync(protectedRoot, { recursive: true, force: true }))
  const contractSet = loadApprovedContractSet()
  const items = contractSet.digestProfiles.sqlite_projections.prohibited_surfaces.items
  for (const item of items) {
    const target = path.join(protectedRoot, item.path)
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.copyFileSync(path.resolve(item.path), target)
  }
  const fixture = createReviewedEvidenceFixture(t, { runtimeProjectRoot: protectedRoot })
  const reader = readerFor(t)
  fs.appendFileSync(path.join(protectedRoot, items[0].path), '\nsynthetic drift\n')
  const base = createTestDatabase()
  t.after(base.remove)
  await assert.rejects(verifyOrPlanAcceptedBundle({
    source: sourceFor(t, base.databasePath),
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.bootstrap.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  }), (error) => error.code === 'PROHIBITED_SURFACE_MISMATCH')
})

test('writer rejects no-op plans, hard-linked sources, and hard-linked candidates', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const bootstrap = await acceptedBootstrap(t, fixture, reader)
  const acceptedSource = sourceFor(t, bootstrap.candidateDatabasePath)
  const opened = openApprovedEvidenceManifest({
    reader,
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.bootstrap.manifest_path,
  })
  const noOp = preflightEvidenceBundle({ database: acceptedSource.database, manifest: opened.manifest, runtime: runtimeFor(fixture.runtimeContext, opened.manifest) })
  assert.equal(noOp.mode, 'no_op')
  assert.throws(() => buildImportPlan(noOp), (error) => error.code === 'IMPORT_PLAN_MODE_INVALID')

  const hardlinkRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-hardlink-'))
  t.after(() => fs.rmSync(hardlinkRoot, { recursive: true, force: true }))
  const sourceLink = path.join(hardlinkRoot, 'source-link.sqlite')
  fs.linkSync(bootstrap.candidateDatabasePath, sourceLink)
  const descriptor = fs.openSync(bootstrap.candidateDatabasePath, fs.constants.O_RDONLY)
  try {
    assert.throws(() => openSyntheticReadOnlyDatabaseDescriptor(descriptor), (error) => error.code === 'DATABASE_DESCRIPTOR_INVALID')
  } finally { fs.closeSync(descriptor) }
  fs.unlinkSync(sourceLink)

  const base = createTestDatabase()
  t.after(base.remove)
  const freshSource = sourceFor(t, base.databasePath)
  const plan = buildImportPlan(preflightEvidenceBundle({ database: freshSource.database, manifest: fixture.bootstrap, runtime: runtimeFor(fixture.runtimeContext, fixture.bootstrap) }))
  const candidate = await cloneDisposableCandidate({ source: freshSource })
  t.after(() => candidate.dispose())
  const candidateLink = path.join(candidate.root, 'candidate-hardlink.sqlite')
  fs.linkSync(candidate.candidateDatabasePath, candidateLink)
  assert.throws(() => applyImportPlanToCandidate({ candidate, plan }), (error) => error.code === 'CANDIDATE_CHANGED')
})

test('every retained or derived byte occurrence is verified, including references to existing artifacts', async (t) => {
  const fixture = createReviewedEvidenceFixture(t)
  const reader = readerFor(t)
  const bootstrap = await acceptedBootstrap(t, fixture, reader)
  const document = await verifyOrPlanAcceptedBundle({
    source: sourceFor(t, bootstrap.candidateDatabasePath),
    reviewedRootDescriptor: fixture.descriptor,
    manifestRelativePath: fixture.document.manifest_path,
    reader,
    byteAdapter: fixture.byteAdapter,
    runtimeContext: fixture.runtimeContext,
  })
  t.after(() => document.candidate.dispose())
  const database = new DatabaseSync(document.candidate.candidateDatabasePath, { readOnly: true })
  t.after(() => database.close())
  const artifact = fixture.document.artifacts[0]
  const wrongPath = 'objects/sha256/00/wrong-occurrence'
  const wrongTarget = path.join(fixture.root, wrongPath)
  fs.mkdirSync(path.dirname(wrongTarget), { recursive: true })
  fs.writeFileSync(wrongTarget, Buffer.alloc(artifact.byte_length, 0x78))

  assert.throws(() => verifyStagedManifestArtifacts({
    database,
    byteAdapter: fixture.byteAdapter,
    manifest: {
      artifacts: [],
      retrieval_events: [{ outcome_code: 'retrieved_retained', artifact_code: artifact.record_code, artifact_staged_path: wrongPath }],
      processing_runs: [],
      candidate_occurrences: [],
    },
  }), (error) => error.code === 'ARTIFACT_INTEGRITY_MISMATCH')

  assert.throws(() => verifyStagedManifestArtifacts({
    database,
    byteAdapter: fixture.byteAdapter,
    manifest: {
      artifacts: [],
      retrieval_events: [],
      processing_runs: [{ outputs: [{ record_code: 'synthetic.output-repeat', artifact_code: artifact.record_code, staged_path: wrongPath }] }],
      candidate_occurrences: [],
    },
  }), (error) => error.code === 'ARTIFACT_INTEGRITY_MISMATCH')

  fs.linkSync(path.join(fixture.root, artifact.staged_path), path.join(fixture.root, 'artifact-hardlink'))
  assert.throws(() => verifyStagedManifestArtifacts({
    database,
    byteAdapter: fixture.byteAdapter,
    manifest: { artifacts: [artifact], retrieval_events: [], processing_runs: [], candidate_occurrences: [] },
  }), (error) => error.code === 'BYTE_OPEN_FAILED')
})

test('text-span bounds use valid UTF-8 Unicode scalar values', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-unicode-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const descriptor = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
  const adapter = createSyntheticReadOnlyByteAdapter({ stagingRootDescriptor: descriptor, backendRootDescriptors: new Map() })
  t.after(() => { adapter.dispose(); fs.closeSync(descriptor) })
  const database = new DatabaseSync(':memory:')
  database.exec('CREATE TABLE atlas_artifacts(artifact_code TEXT,byte_layer_code TEXT,sha256 TEXT,byte_length INTEGER); CREATE TABLE atlas_processing_outputs(processing_output_code TEXT,artifact_id INTEGER); CREATE TABLE atlas_artifact_custody_events(id INTEGER,artifact_id INTEGER,predecessor_custody_event_id INTEGER,event_kind_code TEXT,backend_code TEXT,backend_reference TEXT)')
  t.after(() => database.close())
  const bytes = Buffer.from('😀x', 'utf8')
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex')
  const relativePath = `objects/${sha256}`
  fs.mkdirSync(path.dirname(path.join(root, relativePath)), { recursive: true })
  fs.writeFileSync(path.join(root, relativePath), bytes)
  const artifact = { record_code: 'artifact.unicode', byte_layer_code: 'derived_output', sha256, byte_length: bytes.length, staged_path: relativePath }
  const manifest = {
    artifacts: [artifact],
    retrieval_events: [],
    processing_runs: [{ outputs: [{ record_code: 'output.unicode', artifact_code: artifact.record_code, staged_path: relativePath }] }],
    candidate_occurrences: [{ processing_output_code: 'output.unicode', locator_kind_code: 'text_span', span_end: 2 }],
  }
  assert.doesNotThrow(() => verifyStagedManifestArtifacts({ database, byteAdapter: adapter, manifest }))
  manifest.candidate_occurrences[0].span_end = 3
  assert.throws(() => verifyStagedManifestArtifacts({ database, byteAdapter: adapter, manifest }), (error) => error.code === 'CANDIDATE_SPAN_INVALID')
  fs.writeFileSync(path.join(root, relativePath), Buffer.from([0xc3, 0x28, 0x78, 0x78, 0x78]))
  artifact.sha256 = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, relativePath))).digest('hex')
  assert.throws(() => verifyStagedManifestArtifacts({ database, byteAdapter: adapter, manifest }), (error) => error.code === 'CANDIDATE_TEXT_INVALID')
})
