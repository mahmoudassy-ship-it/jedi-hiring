import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { createD931AdmissionResolver, authenticateSyntheticAdapterPeer, createSyntheticCustodyProjection } from '../d9/custody/admission.mjs'
import { createAuthenticatedCustodyAdapter, createReviewedStagingRegistry, makeAdapterRequest } from '../d9/custody/adapter.mjs'
import { createOneShotIntegrityGrantSink, revokeOneShotCustodyDescriptor } from '../d9/custody/integrity.mjs'
import { createRestrictedLocalCas, custodyReferenceFor } from '../d9/custody/cas.mjs'
import { createDurableNamespaceStore } from '../d9/custody/durable-store.mjs'
import { D931_JOURNAL_NAMESPACES, createProtectedJournalBroker } from '../d9/custody/journal.mjs'
import { appendCustodyFinalization, appendOperationStarted } from '../d9/custody/coordinator.mjs'
import { canonicalRecord } from '../d9/custody/contracts.mjs'
import { parseStrictJson } from '../d9/control-plane/canonical.mjs'
import { createD931Fixture, createSyntheticAvailableCustody, makeClock, recordBytes } from './d9-3-1-support/fixture.mjs'
import { fixture as d90Fixture, reseal } from './d9-1-support/runtime-fixture.mjs'

async function peerFor(fixture, request) {
  const binding = fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === request.sender_binding_code)
  const proofRoot = path.join(fixture.generationFixture.root, 'peer-proof')
  fs.mkdirSync(proofRoot, { mode: 0o711, recursive: true })
  const proofFile = path.join(proofRoot, 'proof.bin')
  fs.writeFileSync(proofFile, 'synthetic-d9-handle\n', { mode: 0o644 })
  const exchangeOptions = {
    rootPath: proofRoot, relativePath: 'proof.bin', expectedPeerUid: binding.unix_uid, syntheticPeerUid: binding.unix_uid,
    expectedPeerGid: process.getgid(), syntheticPeerGid: process.getgid(), expectedEndpointCode: binding.ipc_endpoint_code,
    requestDigestSha256: request.record_digest_sha256, nonce: request.operation_nonce,
  }
  return authenticateSyntheticAdapterPeer({ linuxEnforcement: fixture.linux, exchangeOptions, verifiedGeneration: fixture.generation, bindingCode: binding.binding_code, expectedEndpointCode: binding.ipc_endpoint_code, requestDigestSha256: request.record_digest_sha256, operationNonce: request.operation_nonce, requestCreatedAt: request.created_at })
}

test('reviewed staging registry rejects use after its duplicated root descriptor is closed and reused', async (t) => {
  const fixture = await createD931Fixture(t)
  const admission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  const registry = createReviewedStagingRegistry({ stagingRootDescriptor: fixture.stagingDescriptor, admissionResolver: admission })
  const rootReal = fs.realpathSync(fixture.stagingRoot)
  const duplicateFd = fs.readdirSync('/proc/self/fd').map(Number).find((fd) => fd !== fixture.stagingDescriptor && (() => { try { return fs.realpathSync(`/proc/self/fd/${fd}`) === rootReal } catch { return false } })())
  assert.ok(Number.isInteger(duplicateFd))
  registry.close()
  const substitute = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-staging-substitute-'))
  fs.chmodSync(substitute, 0o700)
  const substituteFd = fs.openSync(substitute, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
  assert.equal(substituteFd, duplicateFd, 'the closed staging descriptor must be reused for the adversarial substitute')
  assert.throws(() => registry.open({}), /D931_STAGING_REGISTRY_CLOSED/)
  fs.closeSync(substituteFd)
  fs.rmSync(substitute, { recursive: true, force: true })
})

test('adapter finalizes primary custody only after exact receipt persistence and journals remain separate', async (t) => {
  const fixture = await createD931Fixture(t)
  const admission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  admission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixture.handoff) })
  admission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixture.seal) })
  const staging = createReviewedStagingRegistry({ stagingRootDescriptor: fixture.stagingDescriptor, admissionResolver: admission })
  t.after(() => staging.close())
  const cas = createRestrictedLocalCas({ protectedRootPath: fixture.casRoot })
  t.after(() => cas.close())
  const store = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => store.close())
  const clock = makeClock()
  const journal = createProtectedJournalBroker({ store, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock })
  const custodyProjectionResolver = (request) => createSyntheticCustodyProjection({ artifact: request.payload.artifact, copyCode: request.payload.copy_code, backendCode: request.payload.backend_code, backendReference: request.payload.backend_reference, evaluatedAt: request.response_at ?? request.created_at, knownThroughBundleSequence: 1, leafDigestSha256: 'ab'.repeat(32) })
  assert.throws(() => createAuthenticatedCustodyAdapter({ admissionResolver: admission, cas, journalBroker: journal, stagingRegistry: staging, adapterBindingCode: 'binding.custody-adapter', journalBindingCode: 'binding.journal-broker', journalPeerProvider: (candidate) => peerFor(fixture, candidate), clock, executableSha256: 'ff'.repeat(32), custodyProjectionResolver, integrityGrantSink: createOneShotIntegrityGrantSink() }), /D931_ADAPTER_CONFIGURATION_INVALID/)
  const journalPeerProvider = (request) => peerFor(fixture, request)
  const integrityGrantSink = createOneShotIntegrityGrantSink()
  const adapter = createAuthenticatedCustodyAdapter({ admissionResolver: admission, cas, journalBroker: journal, stagingRegistry: staging, adapterBindingCode: 'binding.custody-adapter', journalBindingCode: 'binding.journal-broker', journalPeerProvider, clock, executableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.custody-adapter').executable_sha256, custodyProjectionResolver, integrityGrantSink })

  const common = {
    operationId: fixture.seal.operation_id, operationNonce: fixture.seal.operation_nonce,
    senderBindingCode: 'binding.importer', adapterBindingCode: 'binding.custody-adapter',
    runtimeProfileDigest: fixture.generation.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: fixture.generation.identityBindings.record_digest_sha256,
    custodyProfileDigest: fixture.custodyProfile.record_digest_sha256,
  }
  const intent = {
    bundle: fixture.seal.bundle, bundle_seal_record_digest_sha256: fixture.seal.record_digest_sha256,
    custody_event_code: 'placement', artifact: fixture.artifact, copy_code: 'copy.primary.synthetic.001',
    custody_class_code: 'restricted_store', backend_code: 'pilot_local_cas_v1', backend_reference: custodyReferenceFor(fixture.artifact),
  }
  await appendOperationStarted({
    journalPeerProvider, journalBroker: journal, journalCode: `journal.${common.operationId}`,
    journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer',
    componentExecutableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256,
    journalProfileDigest: fixture.journalProfile.record_digest_sha256, operationModeCode: 'document_import',
    operationId: common.operationId, operationNonce: common.operationNonce,
    authorizationBundleSealDigest: fixture.seal.record_digest_sha256, bundle: fixture.seal.bundle,
    targetLogicalState: fixture.seal.target_logical_state,
    runtimeProfileDigest: fixture.generation.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: fixture.generation.identityBindings.record_digest_sha256,
    eventAt: '2030-01-01T00:19:58.000Z', requestCreatedAt: '2030-01-01T00:19:59.000Z',
  })
  const open = makeAdapterRequest({ ...common, operationCode: 'open_staged', requestSequence: 1, createdAt: '2030-01-01T00:20:01.500Z', payload: { staging_root_slot_code: 'staging_root', relative_path: fixture.handoff.staged_path, collector_handoff_record_digest_sha256: fixture.handoff.record_digest_sha256, bundle_seal_record_digest_sha256: fixture.seal.record_digest_sha256, staging_snapshot_code: fixture.handoff.staging_snapshot_code, custody_intent: intent } })
  const inventoryBeforeRejectedOpen = store.inventory()
  const overBudgetOpen = structuredClone(open)
  overBudgetOpen.operation_id = 'x'.repeat(41)
  overBudgetOpen.record_code = `adapter.${overBudgetOpen.operation_id}.open_staged.1`
  overBudgetOpen.request_id = `request.${overBudgetOpen.operation_id}.open_staged.1`
  const overBudgetOpenRecord = canonicalRecord(overBudgetOpen)
  const overBudgetOpenPeer = await peerFor(fixture, overBudgetOpenRecord)
  await assert.rejects(() => adapter.handle({ request: overBudgetOpenRecord, authenticatedPeer: overBudgetOpenPeer }), /D931_OPERATION_ID_BUDGET_REJECTED/)
  assert.deepEqual(store.inventory(), inventoryBeforeRejectedOpen, 'derived-identity budget rejection precedes every additional journal mutation')
  const splitSealOpen = structuredClone(open)
  splitSealOpen.payload.custody_intent.bundle_seal_record_digest_sha256 = 'ff'.repeat(32)
  const splitSealOpenRecord = canonicalRecord(splitSealOpen)
  const splitSealOpenPeer = await peerFor(fixture, splitSealOpenRecord)
  await assert.rejects(() => adapter.handle({ request: splitSealOpenRecord, authenticatedPeer: splitSealOpenPeer }), /D930_ADAPTER_CUSTODY_INTENT_REJECTED/)
  const opened = await adapter.handle({ request: open, authenticatedPeer: await peerFor(fixture, open) })
  assert.equal(opened.response.payload.outcome_code, 'opened')

  const sourceDigest = opened.response.payload.source_capability_record_digest_sha256
  const prepare = makeAdapterRequest({ ...common, operationCode: 'prepare', requestSequence: 2, createdAt: '2030-01-01T00:20:06.500Z', payload: { artifact: fixture.artifact, custody_intent: intent, source_capability_record_digest_sha256: sourceDigest, source_capability_leaf_record_digest_sha256: sourceDigest } })
  const prepared = await adapter.handle({ request: prepare, authenticatedPeer: await peerFor(fixture, prepare), capabilitySidecars: opened.capabilitySidecars, descriptorSidecars: opened.descriptorSidecars })
  fs.closeSync(opened.descriptorSidecars.get(1))
  assert.equal(prepared.response.payload.outcome_code, 'prepared')

  const preparationDigest = prepared.response.payload.preparation_capability_record_digest_sha256
  const verify = makeAdapterRequest({ ...common, operationCode: 'verify_prepared', requestSequence: 3, createdAt: '2030-01-01T00:20:13.500Z', payload: { artifact: fixture.artifact, custody_intent: intent, preparation_capability_record_digest_sha256: preparationDigest, preparation_capability_leaf_record_digest_sha256: preparationDigest } })
  const verified = await adapter.handle({ request: verify, authenticatedPeer: await peerFor(fixture, verify), capabilitySidecars: prepared.capabilitySidecars })
  assert.equal(verified.response.payload.outcome_code, 'verified')

  const publish = makeAdapterRequest({ ...common, operationCode: 'publish_no_replace', requestSequence: 4, createdAt: '2030-01-01T00:20:20.500Z', payload: { artifact: fixture.artifact, custody_intent: intent, preparation_capability_record_digest_sha256: preparationDigest, preparation_capability_leaf_record_digest_sha256: verified.transition.record_digest_sha256, copy_code: intent.copy_code, backend_code: intent.backend_code, backend_reference: intent.backend_reference } })
  const published = await adapter.handle({ request: publish, authenticatedPeer: await peerFor(fixture, publish), capabilitySidecars: verified.capabilitySidecars })
  assert.equal(published.response.payload.outcome_code, 'published')
  assert.ok(published.receiptSemantic.completed_at > publish.created_at, 'durability completion is sampled after CAS publication and verification')
  assert.equal(published.publication.fanoutAncestorsPreprovisionedAndSynced, true)
  assert.match(published.response.payload.primary_receipt.receipt_raw_sha256, /^[0-9a-f]{64}$/u)
  assert.equal(journal.resolveReceipt({ ...published.response.payload.primary_receipt, receipt_persisted_at: published.receiptAck.payload.receipt_persisted_at }).semantic.artifact.sha256, fixture.artifact.sha256)
  assert.equal(store.inventory().projection['primary-receipts'].length, 1)
  assert.equal(store.inventory().projection['journal-events'].length, 1, 'physical receipt adds no accepted-evidence event beyond the prior operation-start record')

  const clearance = d90Fixture('clearance_decision')
  clearance.runtime_profile_record_digest_sha256 = fixture.generation.runtimeProfile.record_digest_sha256
  clearance.identity_bindings_record_digest_sha256 = fixture.generation.identityBindings.record_digest_sha256
  clearance.artifact = structuredClone(fixture.artifact)
  clearance.not_before = '2030-01-01T00:19:00.000Z'
  clearance.expires_at = '2030-01-01T01:00:00.000Z'
  reseal(clearance)
  admission.admitBaseRecord({ schemaFile: 'clearance-record-v1.schema.json', recordBytes: recordBytes(clearance) })
  const sealAccess = makeAdapterRequest({ ...common, operationCode: 'seal_custody_access', requestSequence: 1, createdAt: '2030-01-01T00:20:30.500Z', payload: { artifact: fixture.artifact, backend_code: intent.backend_code, backend_reference: intent.backend_reference, copy_code: intent.copy_code, purpose_code: 'integrity', primary_receipt: published.response.payload.primary_receipt, clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256 } })
  const sealed = await adapter.handle({ request: sealAccess, authenticatedPeer: await peerFor(fixture, sealAccess) })
  assert.equal(sealed.response.payload.outcome_code, 'sealed')
  const sealedDigest = sealed.response.payload.sealed_capability_record_digest_sha256
  const openCustody = makeAdapterRequest({ ...common, operationCode: 'open_custody', requestSequence: 2, createdAt: '2030-01-01T00:20:37.500Z', payload: { artifact: fixture.artifact, backend_code: intent.backend_code, backend_reference: intent.backend_reference, copy_code: intent.copy_code, purpose_code: 'integrity', primary_receipt: published.response.payload.primary_receipt, sealed_capability_record_digest_sha256: sealedDigest, sealed_capability_leaf_record_digest_sha256: sealedDigest } })
  const resolvedAvailable = await adapter.handle({ request: openCustody, authenticatedPeer: await peerFor(fixture, openCustody), capabilitySidecars: sealed.capabilitySidecars })
  assert.equal(resolvedAvailable.response.payload.outcome_code, 'available')
  assert.equal(resolvedAvailable.response.ancillary_descriptors[0].role_code, 'custody_source')
  assert.equal(Object.hasOwn(resolvedAvailable, 'descriptorSidecars'), false)
  assert.equal(revokeOneShotCustodyDescriptor({ grantSink: integrityGrantSink, adapterResult: resolvedAvailable }), true)
  const replayPeer = await peerFor(fixture, openCustody)
  await assert.rejects(() => adapter.handle({ request: openCustody, authenticatedPeer: replayPeer, capabilitySidecars: sealed.capabilitySidecars }), /D931_DESCRIPTOR_REPLAY_FORBIDDEN/)

  const exchanges = [
    { request: open, response: opened.response }, { request: prepare, response: prepared.response },
    { request: verify, response: verified.response }, { request: publish, response: published.response },
  ]
  const acks = published.supportingAcks
  const linked = await appendCustodyFinalization({
    journalPeerProvider, journalBroker: journal, journalCode: `journal.${common.operationId}`, journalBindingCode: 'binding.journal-broker',
    custodyAdapterBindingCode: 'binding.custody-adapter', custodyAdapterExecutableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.custody-adapter').executable_sha256,
    journalProfileDigest: fixture.journalProfile.record_digest_sha256,
    targetLogicalState: fixture.seal.target_logical_state, exchanges, publishResult: published, supportingAcks: acks,
    eventAt: clock(), requestCreatedAt: clock(),
  })
  assert.equal(linked.nextStepCode, 'wait_for_d9_5')
  assert.equal(linked.canonicalWriteReachable, false)
  assert.equal(linked.evidenceAcceptanceEstablished, false)
  assert.equal(store.inventory().projection['journal-events'].length, 2)

  const replay = await adapter.handle({ request: publish, authenticatedPeer: await peerFor(fixture, publish), capabilitySidecars: verified.capabilitySidecars })
  assert.equal(replay.response.record_digest_sha256, published.response.record_digest_sha256)
  assert.equal(store.inventory().projection['primary-receipts'].length, 1)
  store.close()
  const reopenedStore = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => reopenedStore.close())
  const missingAuthorityAdmission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  assert.throws(() => createProtectedJournalBroker({ store: reopenedStore, contractSet: fixture.contracts, admissionResolver: missingAuthorityAdmission, journalBindingCode: 'binding.journal-broker', clock }), /D931_ADMISSION_UNRESOLVED/)
  const restartedAdmission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  restartedAdmission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixture.handoff) })
  restartedAdmission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixture.seal) })
  restartedAdmission.admitBaseRecord({ schemaFile: 'clearance-record-v1.schema.json', recordBytes: recordBytes(clearance) })
  assert.throws(() => createProtectedJournalBroker({ store: reopenedStore, contractSet: fixture.contracts, admissionResolver: restartedAdmission, journalBindingCode: 'binding.journal-broker', clock }), /D931_INTEGRITY_RECOVERY_REQUIRED/, 'a persisted available descriptor without a completed lifecycle fails closed after restart')
})

test('adapter rejects peer, request, capability and profile substitution', async (t) => {
  const fixture = await createD931Fixture(t)
  const suppliedCustodyProfile = structuredClone(fixture.custodyProfile)
  const suppliedJournalProfile = structuredClone(fixture.journalProfile)
  const admission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: suppliedCustodyProfile, journalProfile: suppliedJournalProfile })
  suppliedCustodyProfile.record_digest_sha256 = 'ff'.repeat(32)
  suppliedJournalProfile.record_digest_sha256 = 'ee'.repeat(32)
  assert.equal(admission.custodyProfile.record_digest_sha256, fixture.custodyProfile.record_digest_sha256)
  assert.equal(admission.journalProfile.record_digest_sha256, fixture.journalProfile.record_digest_sha256)
  admission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixture.handoff) })
  admission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixture.seal) })
  const forgedAdmission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  const forgedHandoff = structuredClone(fixture.handoff)
  forgedHandoff.collector_build_sha256 = 'ff'.repeat(32)
  reseal(forgedHandoff)
  assert.throws(() => forgedAdmission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(forgedHandoff) }), /CEREMONY_BUILD_MISMATCH/)
  forgedAdmission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(fixture.handoff) })
  const forgedSeal = structuredClone(fixture.seal)
  forgedSeal.submitter_binding_code = 'binding.importer'
  reseal(forgedSeal)
  assert.throws(() => forgedAdmission.admitBaseRecord({ schemaFile: 'collector-handoff-v1.schema.json', recordBytes: recordBytes(forgedSeal) }), /CEREMONY_BINDING|CEREMONY_RECORD|binding/i)
  const staging = createReviewedStagingRegistry({ stagingRootDescriptor: fixture.stagingDescriptor, admissionResolver: admission })
  const cas = createRestrictedLocalCas({ protectedRootPath: fixture.casRoot })
  const store = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  let selectedClock = makeClock()
  const clock = (label) => selectedClock(label)
  let failSupporting = false
  const journal = createProtectedJournalBroker({ store, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock, faultInjector(point) { if (failSupporting && point === 'after_supporting_ack_persist_before_return') throw new Error('synthetic supporting failure') } })
  const custodyProjectionResolver = (request) => createSyntheticCustodyProjection({ artifact: request.payload.artifact, copyCode: request.payload.copy_code, backendCode: request.payload.backend_code, backendReference: request.payload.backend_reference, evaluatedAt: request.response_at ?? request.created_at, knownThroughBundleSequence: 1, leafDigestSha256: 'ab'.repeat(32) })
  const adapter = createAuthenticatedCustodyAdapter({ admissionResolver: admission, cas, journalBroker: journal, stagingRegistry: staging, adapterBindingCode: 'binding.custody-adapter', journalBindingCode: 'binding.journal-broker', journalPeerProvider: (request) => peerFor(fixture, request), clock, executableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.custody-adapter').executable_sha256, custodyProjectionResolver, integrityGrantSink: createOneShotIntegrityGrantSink() })
  t.after(() => { staging.close(); cas.close(); store.close() })
  const request = makeAdapterRequest({ operationCode: 'open_staged', operationId: fixture.seal.operation_id, operationNonce: fixture.seal.operation_nonce, requestSequence: 1, senderBindingCode: 'binding.importer', adapterBindingCode: 'binding.custody-adapter', runtimeProfileDigest: fixture.generation.runtimeProfile.record_digest_sha256, identityBindingsDigest: fixture.generation.identityBindings.record_digest_sha256, custodyProfileDigest: fixture.custodyProfile.record_digest_sha256, createdAt: '2030-01-01T00:20:01.500Z', payload: { staging_root_slot_code: 'staging_root', relative_path: fixture.handoff.staged_path, collector_handoff_record_digest_sha256: fixture.handoff.record_digest_sha256, bundle_seal_record_digest_sha256: fixture.seal.record_digest_sha256, staging_snapshot_code: fixture.handoff.staging_snapshot_code, custody_intent: { bundle: fixture.seal.bundle, bundle_seal_record_digest_sha256: fixture.seal.record_digest_sha256, custody_event_code: 'placement', artifact: fixture.artifact, copy_code: 'copy.primary.synthetic.001', custody_class_code: 'restricted_store', backend_code: 'pilot_local_cas_v1', backend_reference: custodyReferenceFor(fixture.artifact) } } })
  await appendOperationStarted({
    journalPeerProvider: (candidate) => peerFor(fixture, candidate), journalBroker: journal,
    journalCode: `journal.${fixture.seal.operation_id}`, journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer',
    componentExecutableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256,
    journalProfileDigest: fixture.journalProfile.record_digest_sha256, operationModeCode: 'document_import',
    operationId: fixture.seal.operation_id, operationNonce: fixture.seal.operation_nonce,
    authorizationBundleSealDigest: fixture.seal.record_digest_sha256, bundle: fixture.seal.bundle, targetLogicalState: fixture.seal.target_logical_state,
    runtimeProfileDigest: fixture.generation.runtimeProfile.record_digest_sha256, identityBindingsDigest: fixture.generation.identityBindings.record_digest_sha256,
    eventAt: '2030-01-01T00:19:58.000Z', requestCreatedAt: '2030-01-01T00:19:59.000Z',
  })
  await assert.rejects(async () => adapter.handle({ request, authenticatedPeer: {} }), /D931_PEER_AUTHENTICATION_FAILED/)
  const staged = path.join(fixture.stagingRoot, fixture.handoff.staged_path)
  const real = `${staged}.real`
  fs.renameSync(staged, real)
  fs.symlinkSync(path.basename(real), staged)
  const symlinkPeer = await peerFor(fixture, request)
  await assert.rejects(() => adapter.handle({ request, authenticatedPeer: symlinkPeer }), /D931_STAGING_OBJECT_REJECTED|ELOOP/)
  fs.unlinkSync(staged)
  fs.renameSync(real, staged)
  const extraLink = `${staged}.link`
  fs.linkSync(staged, extraLink)
  const hardlinkPeer = await peerFor(fixture, request)
  await assert.rejects(() => adapter.handle({ request, authenticatedPeer: hardlinkPeer }), /D931_STAGING_OBJECT_REJECTED/)
  fs.unlinkSync(extraLink)
  const firstPart = fixture.handoff.staged_path.split('/')[0]
  const ancestor = path.join(fixture.stagingRoot, firstPart)
  const ancestorReal = `${ancestor}.real`
  fs.renameSync(ancestor, ancestorReal)
  fs.symlinkSync(path.basename(ancestorReal), ancestor)
  const ancestorPeer = await peerFor(fixture, request)
  await assert.rejects(() => adapter.handle({ request, authenticatedPeer: ancestorPeer }), /ELOOP|ENOTDIR|D931_STAGING_PATH_REJECTED/)
  fs.unlinkSync(ancestor)
  fs.renameSync(ancestorReal, ancestor)
  const drift = structuredClone(request)
  drift.runtime_profile_record_digest_sha256 = 'ff'.repeat(32)
  await assert.rejects(() => adapter.handle({ request: drift, authenticatedPeer: {} }), /D930_RECORD_DIGEST_MISMATCH/)
  const descriptorCount = () => fs.readdirSync('/proc/self/fd').filter((leaf) => {
    try { return fs.realpathSync(`/proc/self/fd/${leaf}`) === fs.realpathSync(staged) } catch { return false }
  }).length
  selectedClock = makeClock(request.created_at, 0)
  const equalTimePeer = await peerFor(fixture, request)
  const beforeEqualTimeDescriptors = descriptorCount()
  await assert.rejects(() => adapter.handle({ request, authenticatedPeer: equalTimePeer }), /D931_CAPABILITY_TIME_REJECTED/)
  assert.equal(descriptorCount(), beforeEqualTimeDescriptors, 'equal-time capability rejection must precede staged descriptor opening')
  selectedClock = makeClock('2030-01-01T00:30:00.000Z')
  const stalePeer = await peerFor(fixture, request)
  await assert.rejects(() => adapter.handle({ request, authenticatedPeer: stalePeer }), /D931_PEER_CONTEXT_REJECTED/)
  selectedClock = makeClock('2030-01-03T00:00:00.000Z')
  const expiredPeer = await peerFor(fixture, request)
  await assert.rejects(() => adapter.handle({ request, authenticatedPeer: expiredPeer }), /D931_PEER_CONTEXT_REJECTED/)
  selectedClock = makeClock('2030-01-01T00:20:02.000Z')
  const beforeDescriptors = descriptorCount()
  failSupporting = true
  const persistenceFailurePeer = await peerFor(fixture, request)
  await assert.rejects(() => adapter.handle({ request, authenticatedPeer: persistenceFailurePeer }), /synthetic supporting failure/)
  assert.equal(descriptorCount(), beforeDescriptors)

  const persistedSupportingRequest = store.inventory().projection['supporting-records']
    .map((item) => parseStrictJson(store.read({ namespaceCode: 'supporting-records', recordCode: item.record_code }), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true }))
    .find((record) => record.message_kind_code === 'persist_supporting_request')
  assert.ok(persistedSupportingRequest)
  const persistedSupportingResponse = store.inventory().projection['supporting-records']
    .map((item) => parseStrictJson(store.read({ namespaceCode: 'supporting-records', recordCode: item.record_code }), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true }))
    .find((record) => record.message_kind_code === 'persist_supporting_response' && record.request_id === persistedSupportingRequest.request_id)
  assert.ok(persistedSupportingResponse)
  store.close()
  const reopenedStore = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => reopenedStore.close())
  const missingPreReceiptAuthority = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  assert.throws(() => createProtectedJournalBroker({ store: reopenedStore, contractSet: fixture.contracts, admissionResolver: missingPreReceiptAuthority, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:21:00.000Z') }), /D931_ADMISSION_UNRESOLVED/)
  const reopenedJournal = createProtectedJournalBroker({ store: reopenedStore, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:21:00.000Z') })
  const mutableReplay = structuredClone(persistedSupportingRequest)
  const replayPeer = await peerFor(fixture, mutableReplay)
  const reconstructed = reopenedJournal.persistSupporting(mutableReplay, replayPeer)
  mutableReplay.payload.supporting_record.payload.relative_path = 'tampered/after-validation.bin'
  assert.equal(reconstructed.record_digest_sha256, persistedSupportingResponse.record_digest_sha256)
  assert.equal(Object.isFrozen(reconstructed.payload), true)
  assert.notEqual(reopenedJournal.resolveSupportingAck(persistedSupportingRequest.payload.supporting_record_digest_sha256).record.payload.relative_path, mutableReplay.payload.supporting_record.payload.relative_path)
  const collision = structuredClone(persistedSupportingRequest)
  collision.record_code = `${collision.record_code}.collision`
  const collisionRecord = canonicalRecord(collision)
  const collisionPeer = await peerFor(fixture, collisionRecord)
  assert.throws(() => reopenedJournal.persistSupporting(collisionRecord, collisionPeer), /D931_SUPPORTING_REQUEST_REJECTED|D931_SUPPORTING_REPLAY_COLLISION|D931_JOURNAL_REPLAY_COLLISION/)
})

test('open custody rejects a response-bound custody projection change', async (t) => {
  const fixture = await createD931Fixture(t)
  const projectionResolver = (request) => createSyntheticCustodyProjection({
    artifact: request.payload.artifact, copyCode: request.payload.copy_code, backendCode: request.payload.backend_code,
    backendReference: request.payload.backend_reference, evaluatedAt: request.response_at ?? request.created_at,
    knownThroughBundleSequence: 1, leafDigestSha256: (request.projection_phase === 'open_response' ? 'cd' : 'ab').repeat(32),
  })
  const result = await createSyntheticAvailableCustody(t, fixture, { projectionResolver, expectOpenCustodyFailure: true })
  assert.match(result.openCustodyError.message, /D931_CLEARANCE_REJECTED/)

  const expiryFixture = await createD931Fixture(t)
  let current = Date.parse('2030-01-01T00:20:00.000Z') - 1_000
  const delayedClock = (label) => new Date(current += label === 'adapter_open_custody_response' ? 31_000 : 1_000).toISOString()
  const expired = await createSyntheticAvailableCustody(t, expiryFixture, { clockOverride: delayedClock, expectOpenCustodyFailure: true })
  assert.match(expired.openCustodyError.message, /D931_CLEARANCE_REJECTED/)

  const adapterExports = await import('../d9/custody/adapter.mjs')
  assert.equal(Object.hasOwn(adapterExports, 'takeOneShotCustodyDescriptor'), false)

  const throwingFixture = await createD931Fixture(t)
  const finalPath = path.join(throwingFixture.casRoot, custodyReferenceFor(throwingFixture.artifact))
  const exactOpenCount = () => fs.readdirSync('/proc/self/fd').filter((leaf) => {
    try { return fs.realpathSync(`/proc/self/fd/${leaf}`) === fs.realpathSync(finalPath) } catch { return false }
  }).length
  const beforeOpenDescriptors = exactOpenCount()
  const throwingResolver = (request) => {
    if (request.projection_phase === 'open_response') throw new Error('synthetic projection resolution failure')
    return createSyntheticCustodyProjection({ artifact: request.payload.artifact, copyCode: request.payload.copy_code, backendCode: request.payload.backend_code, backendReference: request.payload.backend_reference, evaluatedAt: request.response_at ?? request.created_at, knownThroughBundleSequence: 1, leafDigestSha256: 'ab'.repeat(32) })
  }
  const failedOpen = await createSyntheticAvailableCustody(t, throwingFixture, { projectionResolver: throwingResolver, expectOpenCustodyFailure: true })
  assert.match(failedOpen.openCustodyError.message, /synthetic projection resolution failure/)
  assert.equal(exactOpenCount(), beforeOpenDescriptors)
})
