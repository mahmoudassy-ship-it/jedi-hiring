import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { canonicalize } from '../../d9/control-plane/canonical.mjs'
import { loadApprovedContractSet } from '../../d9/control-plane/contracts.mjs'
import { compileLinuxEnforcement } from '../../d9/control-plane/platform.mjs'
import { createGenerationFixture, fixture, reseal, verifyFixture } from '../d9-1-support/runtime-fixture.mjs'
import { loadApprovedD930ContractSet } from '../../d9/custody/contracts.mjs'
import { compileOneShotIntegrityRuntime, createOneShotIntegrityGrantSink } from '../../d9/custody/integrity.mjs'
import { createD931AdmissionResolver, authenticateSyntheticAdapterPeer, createSyntheticCustodyProjection } from '../../d9/custody/admission.mjs'
import { createAuthenticatedCustodyAdapter, createReviewedStagingRegistry, makeAdapterRequest } from '../../d9/custody/adapter.mjs'
import { createRestrictedLocalCas, custodyReferenceFor } from '../../d9/custody/cas.mjs'
import { createDurableNamespaceStore } from '../../d9/custody/durable-store.mjs'
import { D931_JOURNAL_NAMESPACES, createProtectedJournalBroker } from '../../d9/custody/journal.mjs'
import { appendOperationStarted } from '../../d9/custody/coordinator.mjs'

const d930 = JSON.parse(fs.readFileSync('docs/schema/d9-3-0/fixtures/valid-contracts-v1.json', 'utf8')).records

export function d930Fixture(code) { return structuredClone(d930[code]) }

export function makeClock(start = '2030-01-01T00:20:00.000Z', stepMs = 1_000) {
  let current = Date.parse(start) - stepMs
  return () => new Date(current += stepMs).toISOString()
}

export async function createD931Fixture(t, { integrity = false } = {}) {
  const linux = await compileLinuxEnforcement()
  t.after(() => linux.dispose())
  const integrityBuild = integrity ? compileOneShotIntegrityRuntime() : null
  if (integrityBuild) t.after(() => integrityBuild.dispose())
  const base = loadApprovedContractSet()
  const generationFixture = createGenerationFixture(t, { serviceExecutablePath: integrityBuild?.executable ?? linux.syntheticExecutablePath })
  const generation = verifyFixture(base, generationFixture)
  const contracts = loadApprovedD930ContractSet({ baseContractSet: base })
  const custodyProfile = d930Fixture('custody_profile')
  const journalProfile = d930Fixture('journal_profile')
  const stagingRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-staging-'))
  const casRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-'))
  const journalRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-journal-'))
  for (const directory of [stagingRoot, casRoot, journalRoot]) fs.chmodSync(directory, 0o700)
  t.after(() => { for (const directory of [stagingRoot, casRoot, journalRoot]) fs.rmSync(directory, { force: true, recursive: true }) })
  const handoff = fixture('collector_handoff')
  const seal = fixture('document_bundle_seal')
  handoff.runtime_profile_record_digest_sha256 = generation.runtimeProfile.record_digest_sha256
  handoff.identity_bindings_record_digest_sha256 = generation.identityBindings.record_digest_sha256
  handoff.collector_build_sha256 = generation.runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === 'collector').executable_sha256
  reseal(handoff)
  seal.runtime_profile_record_digest_sha256 = generation.runtimeProfile.record_digest_sha256
  seal.identity_bindings_record_digest_sha256 = generation.identityBindings.record_digest_sha256
  seal.collector_handoffs = [{ format: handoff.format, format_version: handoff.format_version, record_code: handoff.record_code, record_digest_sha256: handoff.record_digest_sha256 }]
  reseal(seal)
  const target = path.join(stagingRoot, handoff.staged_path)
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 })
  fs.writeFileSync(target, fs.readFileSync('docs/schema/d9-0/fixtures/objects/sha256/c7/c76da313046a10971896c921d6bfaf00383159f10e5f1fa6d11f86f6276fc173'), { mode: 0o600 })
  const stagingDescriptor = fs.openSync(stagingRoot, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  t.after(() => { try { fs.closeSync(stagingDescriptor) } catch {} })
  return { base, contracts, generationFixture, generation, custodyProfile, journalProfile, stagingRoot, stagingDescriptor, casRoot, journalRoot, handoff, seal, artifact: structuredClone(handoff.artifact), linux, integrityBuild }
}

export function recordBytes(record) { return Buffer.from(canonicalize(record), 'utf8') }

export function admitFixtureAuthority(admission, fixtureValue) {
  admission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixtureValue.handoff) })
  admission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixtureValue.seal) })
  return admission
}

export async function authenticatedPeerFor(fixtureValue, request) {
  const binding = fixtureValue.generation.identityBindings.bindings.find((entry) => entry.binding_code === request.sender_binding_code)
  const proofRoot = path.join(fixtureValue.generationFixture.root, 'peer-proof')
  fs.mkdirSync(proofRoot, { mode: 0o711, recursive: true })
  const proofFile = path.join(proofRoot, 'proof.bin')
  if (!fs.existsSync(proofFile)) fs.writeFileSync(proofFile, 'synthetic-d9-handle\n', { mode: 0o644 })
  const exchangeOptions = {
    rootPath: proofRoot, relativePath: 'proof.bin', expectedPeerUid: binding.unix_uid, syntheticPeerUid: binding.unix_uid,
    expectedPeerGid: process.getgid(), syntheticPeerGid: process.getgid(), expectedEndpointCode: binding.ipc_endpoint_code,
    requestDigestSha256: request.record_digest_sha256, nonce: request.operation_nonce,
  }
  return authenticateSyntheticAdapterPeer({
    linuxEnforcement: fixtureValue.linux, exchangeOptions, verifiedGeneration: fixtureValue.generation,
    bindingCode: binding.binding_code, expectedEndpointCode: binding.ipc_endpoint_code,
    requestDigestSha256: request.record_digest_sha256, operationNonce: request.operation_nonce, requestCreatedAt: request.created_at,
  })
}

export async function createSyntheticAvailableCustody(t, fixtureValue, { journalFaultInjector = null, expectPrepareFailure = false, expectVerifyFailure = false, expectPublishFailure = false, projectionResolver = null, expectOpenCustodyFailure = false, clockOverride = null } = {}) {
  const admission = createD931AdmissionResolver({ contractSet: fixtureValue.contracts, verifiedGeneration: fixtureValue.generation, custodyProfile: fixtureValue.custodyProfile, journalProfile: fixtureValue.journalProfile })
  const integrityGrantSink = createOneShotIntegrityGrantSink()
  admitFixtureAuthority(admission, fixtureValue)
  const staging = createReviewedStagingRegistry({ stagingRootDescriptor: fixtureValue.stagingDescriptor, admissionResolver: admission })
  const cas = createRestrictedLocalCas({ protectedRootPath: fixtureValue.casRoot })
  const store = createDurableNamespaceStore({ rootPath: fixtureValue.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  const clock = clockOverride ?? makeClock()
  const journal = createProtectedJournalBroker({ store, contractSet: fixtureValue.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock, faultInjector: journalFaultInjector })
  const journalPeerProvider = (request) => authenticatedPeerFor(fixtureValue, request)
  const custodyProjectionResolver = projectionResolver ?? ((request) => createSyntheticCustodyProjection({ artifact: request.payload.artifact, copyCode: request.payload.copy_code, backendCode: request.payload.backend_code, backendReference: request.payload.backend_reference, evaluatedAt: request.response_at ?? request.created_at, knownThroughBundleSequence: 1, leafDigestSha256: 'ab'.repeat(32) }))
  const adapter = createAuthenticatedCustodyAdapter({ admissionResolver: admission, cas, journalBroker: journal, stagingRegistry: staging, adapterBindingCode: 'binding.custody-adapter', journalBindingCode: 'binding.journal-broker', journalPeerProvider, clock, executableSha256: fixtureValue.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.custody-adapter').executable_sha256, custodyProjectionResolver, integrityGrantSink })
  t.after(() => { staging.close(); cas.close(); store.close() })
  const common = {
    operationId: fixtureValue.seal.operation_id, operationNonce: fixtureValue.seal.operation_nonce,
    senderBindingCode: 'binding.importer', adapterBindingCode: 'binding.custody-adapter',
    runtimeProfileDigest: fixtureValue.generation.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: fixtureValue.generation.identityBindings.record_digest_sha256,
    custodyProfileDigest: fixtureValue.custodyProfile.record_digest_sha256,
  }
  const intent = {
    bundle: fixtureValue.seal.bundle, bundle_seal_record_digest_sha256: fixtureValue.seal.record_digest_sha256,
    custody_event_code: 'placement', artifact: fixtureValue.artifact, copy_code: 'copy.primary.synthetic.001',
    custody_class_code: 'restricted_store', backend_code: 'pilot_local_cas_v1', backend_reference: custodyReferenceFor(fixtureValue.artifact),
  }
  const operationStart = await appendOperationStarted({
    journalPeerProvider, journalBroker: journal, journalCode: `journal.${common.operationId}`,
    journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer',
    componentExecutableSha256: fixtureValue.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256,
    journalProfileDigest: fixtureValue.journalProfile.record_digest_sha256, operationModeCode: 'document_import',
    operationId: common.operationId, operationNonce: common.operationNonce,
    authorizationBundleSealDigest: fixtureValue.seal.record_digest_sha256, bundle: fixtureValue.seal.bundle,
    targetLogicalState: fixtureValue.seal.target_logical_state,
    runtimeProfileDigest: fixtureValue.generation.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: fixtureValue.generation.identityBindings.record_digest_sha256,
    eventAt: '2030-01-01T00:19:58.000Z', requestCreatedAt: '2030-01-01T00:19:59.000Z',
  })
  const invoke = async (request, extra = {}) => adapter.handle({ request, authenticatedPeer: await authenticatedPeerFor(fixtureValue, request), ...extra })
  const open = makeAdapterRequest({ ...common, operationCode: 'open_staged', requestSequence: 1, createdAt: '2030-01-01T00:20:01.500Z', payload: { staging_root_slot_code: 'staging_root', relative_path: fixtureValue.handoff.staged_path, collector_handoff_record_digest_sha256: fixtureValue.handoff.record_digest_sha256, bundle_seal_record_digest_sha256: fixtureValue.seal.record_digest_sha256, staging_snapshot_code: fixtureValue.handoff.staging_snapshot_code, custody_intent: intent } })
  const opened = await invoke(open)
  const sourceDigest = opened.response.payload.source_capability_record_digest_sha256
  const prepare = makeAdapterRequest({ ...common, operationCode: 'prepare', requestSequence: 2, createdAt: '2030-01-01T00:20:06.500Z', payload: { artifact: fixtureValue.artifact, custody_intent: intent, source_capability_record_digest_sha256: sourceDigest, source_capability_leaf_record_digest_sha256: sourceDigest } })
  let prepared
  try { prepared = await invoke(prepare, { capabilitySidecars: opened.capabilitySidecars, descriptorSidecars: opened.descriptorSidecars }) } catch (prepareError) {
    try { fs.closeSync(opened.descriptorSidecars.get(1)) } catch {}
    if (!expectPrepareFailure) throw prepareError
    return { admission, cas, store, journal, adapter, clock, common, intent, operationStart, open, opened, prepare, prepareError }
  }
  fs.closeSync(opened.descriptorSidecars.get(1))
  const preparationDigest = prepared.response.payload.preparation_capability_record_digest_sha256
  const verify = makeAdapterRequest({ ...common, operationCode: 'verify_prepared', requestSequence: 3, createdAt: '2030-01-01T00:20:13.500Z', payload: { artifact: fixtureValue.artifact, custody_intent: intent, preparation_capability_record_digest_sha256: preparationDigest, preparation_capability_leaf_record_digest_sha256: preparationDigest } })
  let verified
  try { verified = await invoke(verify, { capabilitySidecars: prepared.capabilitySidecars }) } catch (verifyError) {
    if (!expectVerifyFailure) throw verifyError
    return { admission, cas, store, journal, adapter, clock, common, intent, operationStart, open, opened, prepare, prepared, verify, verifyError }
  }
  const publish = makeAdapterRequest({ ...common, operationCode: 'publish_no_replace', requestSequence: 4, createdAt: '2030-01-01T00:20:20.500Z', payload: { artifact: fixtureValue.artifact, custody_intent: intent, preparation_capability_record_digest_sha256: preparationDigest, preparation_capability_leaf_record_digest_sha256: verified.transition.record_digest_sha256, copy_code: intent.copy_code, backend_code: intent.backend_code, backend_reference: intent.backend_reference } })
  let published
  try { published = await invoke(publish, { capabilitySidecars: verified.capabilitySidecars }) } catch (error) {
    if (!expectPublishFailure) throw error
    return { admission, cas, store, journal, adapter, clock, common, intent, operationStart, open, opened, prepare, prepared, verify, verified, publish, publishError: error }
  }
  const clearance = fixture('clearance_decision')
  clearance.runtime_profile_record_digest_sha256 = fixtureValue.generation.runtimeProfile.record_digest_sha256
  clearance.identity_bindings_record_digest_sha256 = fixtureValue.generation.identityBindings.record_digest_sha256
  clearance.artifact = structuredClone(fixtureValue.artifact)
  clearance.not_before = '2030-01-01T00:19:00.000Z'
  clearance.expires_at = '2030-01-01T01:00:00.000Z'
  reseal(clearance)
  admission.admitBaseRecord({ schemaFile: 'clearance-record-v1.schema.json', recordBytes: recordBytes(clearance) })
  const sealAccess = makeAdapterRequest({ ...common, operationCode: 'seal_custody_access', requestSequence: 1, createdAt: '2030-01-01T00:20:30.500Z', payload: { artifact: fixtureValue.artifact, backend_code: intent.backend_code, backend_reference: intent.backend_reference, copy_code: intent.copy_code, purpose_code: 'integrity', primary_receipt: published.response.payload.primary_receipt, clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256 } })
  const sealed = await invoke(sealAccess)
  const sealedDigest = sealed.response.payload.sealed_capability_record_digest_sha256
  const openCustody = makeAdapterRequest({ ...common, operationCode: 'open_custody', requestSequence: 2, createdAt: '2030-01-01T00:20:37.500Z', payload: { artifact: fixtureValue.artifact, backend_code: intent.backend_code, backend_reference: intent.backend_reference, copy_code: intent.copy_code, purpose_code: 'integrity', primary_receipt: published.response.payload.primary_receipt, sealed_capability_record_digest_sha256: sealedDigest, sealed_capability_leaf_record_digest_sha256: sealedDigest } })
  let available
  try { available = await invoke(openCustody, { capabilitySidecars: sealed.capabilitySidecars }) } catch (openCustodyError) {
    if (!expectOpenCustodyFailure) throw openCustodyError
    return { admission, cas, store, journal, journalPeerProvider, adapter, clock, common, intent, operationStart, published, sealed, openCustody, openCustodyError }
  }
  return { admission, cas, store, journal, journalPeerProvider, adapter, integrityGrantSink, clock, common, intent, operationStart, published, sealed, openCustody, available }
}
