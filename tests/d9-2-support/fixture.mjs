import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { canonicalSha256, canonicalize } from '../../d9/control-plane/canonical.mjs'
import { loadApprovedContractSet } from '../../d9/control-plane/contracts.mjs'
import { createSyntheticReadOnlyByteAdapter } from '../../d9/data-plane/bytes.mjs'
import { createD92PreflightRuntime, createSyntheticD92RuntimeContext } from '../../d9/data-plane/runtime.mjs'
import { createGenerationFixture, fixture as d91Fixture, verifyFixture } from '../d9-1-support/runtime-fixture.mjs'

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const goldenPath = path.join(projectRoot, 'docs/schema/d9-0/fixtures/golden-vectors-v1.json')
const syntheticObjectPath = path.join(projectRoot, 'docs/schema/d9-0/fixtures/objects/sha256/c7/c76da313046a10971896c921d6bfaf00383159f10e5f1fa6d11f86f6276fc173')

export function goldenBundles() {
  const golden = JSON.parse(fs.readFileSync(goldenPath, 'utf8'))
  return {
    bootstrap: structuredClone(golden.complete_manifest_vector.value),
    document: structuredClone(golden.complete_document_manifest_vector.value),
  }
}

function writeFile(root, relativePath, bytes) {
  const target = path.join(root, relativePath)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, bytes)
}

export function createReviewedEvidenceFixture(t, { runtimeProjectRoot = projectRoot } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-reviewed-'))
  const { bootstrap, document } = goldenBundles()
  writeFile(root, bootstrap.manifest_path, `${JSON.stringify(bootstrap, null, 2)}\n`)
  writeFile(root, document.manifest_path, `${JSON.stringify(document, null, 2)}\n`)
  for (const artifact of document.artifacts) writeFile(root, artifact.staged_path, fs.readFileSync(syntheticObjectPath))
  const descriptor = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  const byteAdapter = createSyntheticReadOnlyByteAdapter({
    stagingRootDescriptor: descriptor,
    backendRootDescriptors: new Map([['pilot_local_cas_v1', descriptor]]),
  })
  const runtimeContext = createSyntheticRuntimeFixture(t, { runtimeProjectRoot })
  const dispose = () => {
    byteAdapter.dispose()
    fs.closeSync(descriptor)
    fs.rmSync(root, { recursive: true, force: true })
  }
  t?.after(dispose)
  return { root, descriptor, byteAdapter, bootstrap, document, runtimeContext, dispose: t ? undefined : dispose }
}

export function createSyntheticRuntimeFixture(t, { runtimeProjectRoot = projectRoot } = {}) {
  const contractSet = loadApprovedContractSet()
  const generationFixture = createGenerationFixture(t)
  const verifiedGeneration = verifyFixture(contractSet, generationFixture)
  const baselineStateSeal = d91Fixture('logical_state_empty')
  baselineStateSeal.state_payload.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  baselineStateSeal.logical_state_sha256 = canonicalSha256(baselineStateSeal.state_payload)
  baselineStateSeal.record_digest_sha256 = canonicalSha256(baselineStateSeal, { excludedTopLevelField: 'record_digest_sha256' })
  return createSyntheticD92RuntimeContext({
    baselineStateSeal,
    contractSet,
    projectRoot: runtimeProjectRoot,
    verifiedGeneration,
  })
}

export function runtimeFor(runtimeContext, manifest, { componentTestOnly = false } = {}) {
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  return createD92PreflightRuntime(runtimeContext, {
    manifestByteLength: manifestBytes.length,
    componentTestOnly,
  })
}

export function canonicalFixtureBytes(manifest) {
  return Buffer.from(canonicalize(manifest), 'utf8')
}

export function materializeProcessingComponentBundle(fixture) {
  const manifest = structuredClone(goldenBundles().document)
  manifest.manifest_path = 'manifests/synthetic-processing-component.json'
  const rawLocation = manifest.retrieval_locations[0]
  const requestedUrl = 'https://example.invalid/synthetic-start'
  const requestedLocationCode = `location.${crypto.createHash('sha256').update(requestedUrl).digest('hex')}`
  manifest.retrieval_locations.unshift({
    record_code: requestedLocationCode,
    url: requestedUrl,
    recorded_by_principal_code: 'synthetic.human',
    recorded_at: '2030-01-01T00:05:13.000Z',
  })
  manifest.retrieval_events[0].requested_location_code = requestedLocationCode
  manifest.retrieval_events[0].redirects = [{
    record_code: 'synthetic.bundle-002.redirect-001',
    ordinal: 1,
    from_location_code: requestedLocationCode,
    to_location_code: rawLocation.record_code,
    http_status_code: 302,
  }]

  const outputBytes = Buffer.from('synthetic parsed output\n', 'utf8')
  const digest = crypto.createHash('sha256').update(outputBytes).digest('hex')
  const artifactCode = `artifact.derived_output.sha256.${digest}.${outputBytes.length}`
  const stagedPath = `objects/sha256/${digest.slice(0, 2)}/${digest}`
  const outputArtifact = {
    record_code: artifactCode,
    byte_layer_code: 'derived_output',
    hash_algorithm_code: 'sha256',
    sha256: digest,
    byte_length: outputBytes.length,
    staged_path: stagedPath,
    recorded_by_principal_code: 'synthetic.human',
    recorded_at: '2030-01-01T00:06:10.000Z',
  }
  manifest.artifacts.push(outputArtifact)
  manifest.custody_events.push({
    record_code: 'synthetic.bundle-002.custody-derived',
    artifact_code: artifactCode,
    copy_code: 'synthetic.copy-derived',
    event_kind_code: 'placed',
    predecessor_custody_event_code: null,
    custody_class_code: 'restricted_store',
    backend_code: 'pilot_local_cas_v1',
    backend_reference: stagedPath,
    repository_eligibility_declaration: null,
    reason: 'Synthetic component limitation: unverified parser output.',
    occurred_at: '2030-01-01T00:06:06.000Z',
    recorded_by_principal_code: 'synthetic.human',
    recorded_at: '2030-01-01T00:06:11.000Z',
  })
  const configuration = { mode: 'synthetic' }
  manifest.processing_runs = [{
    record_code: 'synthetic.bundle-002.run-parser',
    ordinal: 0,
    input_artifact_code: manifest.artifacts[0].record_code,
    method_code: 'parser',
    processor_principal_code: 'synthetic.collector',
    processor_software_code: 'synthetic-parser',
    processor_version: '9.2.0-test',
    configuration,
    configuration_sha256: canonicalSha256(configuration),
    started_at: '2030-01-01T00:05:20.000Z',
    completed_at: '2030-01-01T00:06:05.000Z',
    outcome_code: 'succeeded',
    failure_code: null,
    outputs: [{
      record_code: 'synthetic.bundle-002.output-text',
      artifact_code: artifactCode,
      staged_path: stagedPath,
      ordinal: 0,
      output_kind_code: 'extracted_text',
      detected_media_type: 'text/plain',
      produced_at: '2030-01-01T00:06:00.000Z',
    }],
    recorded_by_principal_code: 'synthetic.human',
    recorded_at: '2030-01-01T00:06:10.000Z',
  }]
  manifest.candidate_occurrences = [{
    record_code: 'synthetic.bundle-002.candidate-title',
    chain_code: 'synthetic.bundle-002.chain-title',
    record_kind_code: 'assertion',
    corrects_candidate_record_code: null,
    processing_run_code: 'synthetic.bundle-002.run-parser',
    processing_output_code: 'synthetic.bundle-002.output-text',
    claim_type_code: 'suggested.title',
    observed_value: 'synthetic',
    normalized_value: 'synthetic',
    confidence_basis_points: 5000,
    locator_kind_code: 'text_span',
    locator_value: 'text bytes 0..9',
    span_start: 0,
    span_end: 9,
    reason: 'Unverified synthetic candidate; not a legal conclusion.',
    recorded_by_principal_code: 'synthetic.human',
    recorded_at: '2030-01-01T00:06:20.000Z',
  }]
  manifest.bundle_digest_sha256 = canonicalSha256(manifest, { excludedTopLevelField: 'bundle_digest_sha256' })
  writeFile(fixture.root, manifest.manifest_path, `${JSON.stringify(manifest, null, 2)}\n`)
  writeFile(fixture.root, stagedPath, outputBytes)
  return manifest
}
