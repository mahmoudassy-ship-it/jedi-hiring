import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { canonicalRecord } from '../d9/custody/contracts.mjs'
import { canonicalSha256, canonicalize, parseStrictJson } from '../d9/control-plane/canonical.mjs'
import { createD931AdmissionResolver } from '../d9/custody/admission.mjs'
import { createDurableNamespaceStore } from '../d9/custody/durable-store.mjs'
import { createProtectedJournalBroker, D931_JOURNAL_NAMESPACES } from '../d9/custody/journal.mjs'
import { appendOperationStarted } from '../d9/custody/coordinator.mjs'
import { admitFixtureAuthority, authenticatedPeerFor, createD931Fixture, createSyntheticAvailableCustody, d930Fixture, makeClock } from './d9-3-1-support/fixture.mjs'
import { reseal } from './d9-1-support/runtime-fixture.mjs'

test('journal v2 is gapless, exact-replay safe, collision rejecting, and corruption detecting', async (t) => {
  const fixture = await createD931Fixture(t)
  const admission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  admitFixtureAuthority(admission, fixture)
  const store = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  const broker = createProtectedJournalBroker({ store, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:13:00.000Z') })
  let request = d930Fixture('journal_broker_request')
  request.sender_binding_code = 'binding.custody-adapter'
  request.recipient_binding_code = 'binding.journal-broker'
  request.runtime_profile_record_digest_sha256 = fixture.generation.runtimeProfile.record_digest_sha256
  request.identity_bindings_record_digest_sha256 = fixture.generation.identityBindings.record_digest_sha256
  request.d930_journal_profile_record_digest_sha256 = fixture.journalProfile.record_digest_sha256
  request.payload.semantic_assertion.component_binding_code = 'binding.custody-adapter'
  request.payload.semantic_assertion.component_executable_sha256 = fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.custody-adapter').executable_sha256
  request.payload.semantic_assertion.runtime_profile_record_digest_sha256 = fixture.generation.runtimeProfile.record_digest_sha256
  request.payload.semantic_assertion.identity_bindings_record_digest_sha256 = fixture.generation.identityBindings.record_digest_sha256
  request.payload.semantic_assertion.d930_journal_profile_record_digest_sha256 = fixture.journalProfile.record_digest_sha256
  request.payload.semantic_assertion = canonicalRecord(request.payload.semantic_assertion)
  request.payload.semantic_assertion_record_digest_sha256 = request.payload.semantic_assertion.record_digest_sha256
  request = canonicalRecord(request)
  const forbiddenRequestField = structuredClone(request)
  forbiddenRequestField.payload.persisted_record_code = 'forbidden.response-only-field'
  const forbiddenRequestRecord = canonicalRecord(forbiddenRequestField)
  const forbiddenRequestPeer = await authenticatedPeerFor(fixture, forbiddenRequestRecord)
  assert.throws(() => broker.appendSemantic(forbiddenRequestRecord, forbiddenRequestPeer), /D931_JOURNAL_CHAIN_CORRUPT/)
  const ungroundedCustody = structuredClone(request)
  ungroundedCustody.payload.semantic_assertion.record_code = `semantic.custody.${ungroundedCustody.operation_id}`
  ungroundedCustody.payload.semantic_assertion = canonicalRecord(ungroundedCustody.payload.semantic_assertion)
  ungroundedCustody.payload.semantic_assertion_record_digest_sha256 = ungroundedCustody.payload.semantic_assertion.record_digest_sha256
  ungroundedCustody.record_code = `append.${ungroundedCustody.payload.semantic_assertion.record_code}`
  ungroundedCustody.request_id = ungroundedCustody.record_code
  const journalPeerProvider = (candidate) => authenticatedPeerFor(fixture, candidate)
  const root = await appendOperationStarted({
    journalPeerProvider, journalBroker: broker, journalCode: `journal.${fixture.seal.operation_id}`,
    journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer',
    componentExecutableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256,
    journalProfileDigest: fixture.journalProfile.record_digest_sha256, operationModeCode: 'document_import',
    operationId: fixture.seal.operation_id, operationNonce: fixture.seal.operation_nonce,
    authorizationBundleSealDigest: fixture.seal.record_digest_sha256,
    bundle: fixture.seal.bundle, targetLogicalState: fixture.seal.target_logical_state,
    runtimeProfileDigest: fixture.generation.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: fixture.generation.identityBindings.record_digest_sha256,
    eventAt: '2030-01-01T00:12:28.000Z', requestCreatedAt: '2030-01-01T00:12:29.000Z',
  })
  request = root.request
  const wrongJournal = structuredClone(request)
  wrongJournal.payload.journal_code = 'journal.synthetic.substituted'
  const wrongJournalRecord = canonicalRecord(wrongJournal)
  assert.throws(() => broker.appendSemantic(wrongJournalRecord, journalPeerProvider(wrongJournalRecord)), /D931_JOURNAL_CHAIN_CORRUPT/)
  assert.throws(() => broker.appendSemantic(request), /D931_PEER_AUTHENTICATION_FAILED/)
  const first = broker.appendSemantic(request, await journalPeerProvider(request))
  assert.equal(first.payload.expected_event_sequence, 1)
  const protectedHead = broker.head(request.payload.journal_code)
  assert.equal(Object.isFrozen(protectedHead), true)
  assert.equal(Object.isFrozen(protectedHead.semantic_assertion), true)
  assert.throws(() => { protectedHead.event_sequence = 99 }, TypeError)

  ungroundedCustody.payload.expected_event_sequence = 2
  ungroundedCustody.payload.expected_previous_event_record_digest_sha256 = first.payload.persisted_record_digest_sha256
  const ungroundedRecord = canonicalRecord(ungroundedCustody)
  const ungroundedPeer = await journalPeerProvider(ungroundedRecord)
  assert.throws(() => broker.appendSemantic(ungroundedRecord, ungroundedPeer), /D931_ADMISSION_UNRESOLVED|D931_CUSTODY_EVIDENCE_INCOMPLETE|D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE/)

  const forbidden = structuredClone(request)
  forbidden.record_code = 'journal.broker.request.custody-backup'
  forbidden.request_id = 'journal.append.custody-backup'
  forbidden.created_at = '2030-01-01T00:12:33.000Z'
  forbidden.payload.expected_event_sequence = 3
  forbidden.payload.expected_previous_event_record_digest_sha256 = first.payload.persisted_record_digest_sha256
  forbidden.payload.semantic_assertion.record_code = 'journal.semantic.custody-backup.001'
  forbidden.payload.semantic_assertion.event_kind_code = 'stage_succeeded'
  forbidden.payload.semantic_assertion.stage_code = 'custody_backup'
  forbidden.payload.semantic_assertion.event_at = '2030-01-01T00:12:32.000Z'
  forbidden.payload.semantic_assertion.custody_finalization = null
  forbidden.payload.semantic_assertion = canonicalRecord(forbidden.payload.semantic_assertion)
  forbidden.payload.semantic_assertion_record_digest_sha256 = forbidden.payload.semantic_assertion.record_digest_sha256
  forbidden.record_code = `append.${forbidden.payload.semantic_assertion.record_code}`
  forbidden.request_id = forbidden.record_code
  const forbiddenRecord = canonicalRecord(forbidden)
  const forbiddenPeer = await journalPeerProvider(forbiddenRecord)
  assert.throws(() => broker.appendSemantic(forbiddenRecord, forbiddenPeer), /D931_JOURNAL_CHAIN_CORRUPT|D931_JOURNAL_SEMANTIC_POLICY_REJECTED|D931_OPERATION_AUTHORITY_UNAVAILABLE/)
  assert.equal(broker.appendSemantic(request, await journalPeerProvider(request)).record_digest_sha256, first.record_digest_sha256)
  const collision = structuredClone(request)
  collision.created_at = '2030-01-01T00:12:32.000Z'
  const collisionRecord = canonicalRecord(collision)
  const collisionPeer = await journalPeerProvider(collisionRecord)
  assert.throws(() => broker.appendSemantic(collisionRecord, collisionPeer), /D931_JOURNAL_REPLAY_COLLISION/)
  const gap = structuredClone(ungroundedCustody)
  gap.payload.expected_event_sequence = 4
  gap.payload.expected_previous_event_record_digest_sha256 = first.payload.persisted_record_digest_sha256
  const gapRecord = canonicalRecord(gap)
  const gapPeer = await journalPeerProvider(gapRecord)
  assert.throws(() => broker.appendSemantic(gapRecord, gapPeer), /D931_ADMISSION_UNRESOLVED|D931_JOURNAL_FORK_OR_GAP/)
  store.close()

  const eventPath = path.join(fixture.journalRoot, 'journal-events', `journal.${fixture.seal.operation_id}.event.000001`)
  fs.chmodSync(eventPath, 0o600)
  const bytes = fs.readFileSync(eventPath)
  bytes[10] ^= 1
  fs.writeFileSync(eventPath, bytes)
  fs.chmodSync(eventPath, 0o400)
  const reopened = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => reopened.close())
  assert.throws(() => createProtectedJournalBroker({ store: reopened, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock: makeClock() }), /D931_PERSISTED_NONCANONICAL|D930_|JSON/)
})

test('receipt and append acknowledgement replay survives a crash after durable effect', async (t) => {
  const fixture = await createD931Fixture(t)
  let armed = true
  const flow = await createSyntheticAvailableCustody(t, fixture, { expectPublishFailure: true, journalFaultInjector(point) { if (armed && point === 'after_receipt_persist_before_ack') throw new Error('synthetic receipt crash') } })
  assert.match(flow.publishError.message, /synthetic receipt crash/)
  const failedRequestPath = path.join(fixture.journalRoot, 'receipt-exchanges', `receipt.persist.${fixture.seal.operation_id}`)
  const failedRequest = parseStrictJson(fs.readFileSync(failedRequestPath), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
  assert.throws(() => flow.journal.persistPrimaryReceipt(failedRequest), /D931_JOURNAL_RECOVERY_REQUIRED/)
  armed = false
  flow.store.close()
  const store = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => store.close())
  const broker = createProtectedJournalBroker({ store, contractSet: fixture.contracts, admissionResolver: flow.admission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:40:00.000Z') })
  const requestPath = path.join(fixture.journalRoot, 'receipt-exchanges', `receipt.persist.${fixture.seal.operation_id}`)
  const request = parseStrictJson(fs.readFileSync(requestPath), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
  const forbiddenRequestField = structuredClone(request)
  forbiddenRequestField.payload.receipt_raw_sha256 = 'aa'.repeat(32)
  const forbiddenRequestRecord = canonicalRecord(forbiddenRequestField)
  const forbiddenRequestPeer = await authenticatedPeerFor(fixture, forbiddenRequestRecord)
  assert.throws(() => broker.persistPrimaryReceipt(forbiddenRequestRecord, forbiddenRequestPeer), /D931_RECEIPT_CHAIN_CORRUPT/)
  const wrongProducer = structuredClone(request)
  wrongProducer.payload.receipt_semantic.adapter_executable_sha256 = 'ff'.repeat(32)
  wrongProducer.payload.receipt_semantic_sha256 = canonicalSha256(wrongProducer.payload.receipt_semantic)
  const wrongProducerRecord = canonicalRecord(wrongProducer)
  const wrongProducerPeer = await authenticatedPeerFor(fixture, wrongProducerRecord)
  assert.throws(() => broker.persistPrimaryReceipt(wrongProducerRecord, wrongProducerPeer), /D931_RECEIPT_PRODUCER_MISMATCH/)
  const wrongProfile = structuredClone(request)
  wrongProfile.d930_operational_profile_record_digest_sha256 = 'ee'.repeat(32)
  const wrongProfileRecord = canonicalRecord(wrongProfile)
  const wrongProfilePeer = await authenticatedPeerFor(fixture, wrongProfileRecord)
  assert.throws(() => broker.persistPrimaryReceipt(wrongProfileRecord, wrongProfilePeer), /D931_RECEIPT_PRODUCER_MISMATCH/)
  const response = broker.persistPrimaryReceipt(request, await authenticatedPeerFor(fixture, request))
  assert.equal(response.payload.outcome_code, 'persisted')
  assert.equal(store.inventory().projection['primary-receipts'].length, 1)
  assert.equal(store.inventory().projection['receipt-exchanges'].length, 2)
  const wrongDigestPeer = await authenticatedPeerFor(fixture, request)
  assert.throws(() => broker.persistPrimaryReceipt({ ...request, record_digest_sha256: '00'.repeat(32) }, wrongDigestPeer), /D931_PEER_AUTHENTICATION_FAILED|D930_/)

  const corruptFixture = await createD931Fixture(t)
  const corruptFlow = await createSyntheticAvailableCustody(t, corruptFixture, { expectPublishFailure: true, journalFaultInjector(point) { if (point === 'after_receipt_persist_before_ack') throw new Error('synthetic receipt crash') } })
  corruptFlow.store.close()
  const receiptCode = fs.readdirSync(path.join(corruptFixture.journalRoot, 'primary-receipts'))[0]
  const receiptPath = path.join(corruptFixture.journalRoot, 'primary-receipts', receiptCode)
  const corruptReceipt = parseStrictJson(fs.readFileSync(receiptPath), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
  corruptReceipt.semantic.copy_code = 'copy.primary.synthetic.substituted'
  corruptReceipt.semantic_payload_sha256 = canonicalSha256(corruptReceipt.semantic)
  fs.chmodSync(receiptPath, 0o600)
  fs.writeFileSync(receiptPath, canonicalize(corruptReceipt))
  fs.chmodSync(receiptPath, 0o400)
  const corruptStore = createDurableNamespaceStore({ rootPath: corruptFixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => corruptStore.close())
  assert.throws(() => createProtectedJournalBroker({ store: corruptStore, contractSet: corruptFixture.contracts, admissionResolver: corruptFlow.admission, journalBindingCode: 'binding.journal-broker', clock: makeClock() }), /D931_RECEIPT_CHAIN_CORRUPT/)
})

test('receipt persistence rejects a capability digest disconnected from the persisted adapter lineage', async (t) => {
  const fixture = await createD931Fixture(t)
  let mutated = false
  const flow = await createSyntheticAvailableCustody(t, fixture, {
    expectPublishFailure: true,
    journalFaultInjector(point) {
      if (!mutated && point === 'before_capability_link_validation') {
        mutated = true
        return 'source_record_substitution'
      }
    },
  })
  assert.equal(mutated, true)
  assert.match(flow.publishError.message, /D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE/)
  assert.equal(flow.store.inventory().projection['primary-receipts'].length, 0, 'capability-link mismatch must fail before receipt persistence')
  const blockedPeer = await authenticatedPeerFor(fixture, flow.publish)
  await assert.rejects(() => flow.adapter.handle({ request: flow.publish, authenticatedPeer: blockedPeer, capabilitySidecars: flow.verified.capabilitySidecars }), /D931_ADAPTER_RECOVERY_REQUIRED/)
})

test('prepare and verify acknowledgement faults latch the live adapter for classification-only recovery', async (t) => {
  for (const scenario of [{ operation: 'prepare', failAt: 3 }, { operation: 'verify', failAt: 5 }]) {
    const fixture = await createD931Fixture(t)
    let supportingCount = 0
    const flow = await createSyntheticAvailableCustody(t, fixture, {
      expectPrepareFailure: scenario.operation === 'prepare',
      expectVerifyFailure: scenario.operation === 'verify',
      journalFaultInjector(point) {
        if (point === 'after_supporting_ack_persist_before_return' && ++supportingCount === scenario.failAt) throw new Error(`synthetic ${scenario.operation} acknowledgement crash`)
      },
    })
    const stageError = flow.prepareError ?? flow.verifyError
    assert.match(stageError.message, new RegExp(`synthetic ${scenario.operation} acknowledgement crash`))
    const request = flow.verify ?? flow.prepare
    const blockedPeer = await authenticatedPeerFor(fixture, request)
    await assert.rejects(() => flow.adapter.handle({ request, authenticatedPeer: blockedPeer }), /D931_ADAPTER_RECOVERY_REQUIRED/)
  }
})

test('journal pins fresh peer identity, generation, and profile at trusted acceptance time', async (t) => {
  const makeRoot = (fixture, broker, overrides = {}) => appendOperationStarted({
    journalPeerProvider: (request) => authenticatedPeerFor(fixture, request), journalBroker: broker,
    journalCode: `journal.${fixture.seal.operation_id}`,
    journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer',
    componentExecutableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256,
    journalProfileDigest: overrides.journalProfileDigest ?? fixture.journalProfile.record_digest_sha256,
    operationModeCode: 'document_import', operationId: fixture.seal.operation_id,
    operationNonce: fixture.seal.operation_nonce, authorizationBundleSealDigest: fixture.seal.record_digest_sha256,
    bundle: fixture.seal.bundle,
    targetLogicalState: fixture.seal.target_logical_state,
    runtimeProfileDigest: overrides.runtimeProfileDigest ?? fixture.generation.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: overrides.identityBindingsDigest ?? fixture.generation.identityBindings.record_digest_sha256,
    eventAt: overrides.eventAt ?? '2030-01-01T00:12:28.000Z', requestCreatedAt: overrides.requestCreatedAt ?? '2030-01-01T00:12:29.000Z',
  })

  const fixture = await createD931Fixture(t)
  const admission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  admitFixtureAuthority(admission, fixture)
  const store = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => store.close())
  const broker = createProtectedJournalBroker({ store, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:12:30.000Z') })
  await assert.rejects(makeRoot(fixture, broker, { runtimeProfileDigest: 'ff'.repeat(32), identityBindingsDigest: 'ee'.repeat(32), journalProfileDigest: 'dd'.repeat(32) }), /D931_PEER_CONTEXT_REJECTED|D931_JOURNAL_CHAIN_CORRUPT/)
  await assert.rejects(makeRoot(fixture, broker, { eventAt: '2030-01-01T00:12:29.500Z', requestCreatedAt: '2030-01-01T00:12:29.000Z' }), /D931_JOURNAL_TIME_REJECTED/)
  assert.equal(store.inventory().projection['journal-events'].length, 0, 'rejected chronology must not persist an append request or event')

  const expiredFixture = await createD931Fixture(t)
  const expiredAdmission = createD931AdmissionResolver({ contractSet: expiredFixture.contracts, verifiedGeneration: expiredFixture.generation, custodyProfile: expiredFixture.custodyProfile, journalProfile: expiredFixture.journalProfile })
  admitFixtureAuthority(expiredAdmission, expiredFixture)
  const expiredStore = createDurableNamespaceStore({ rootPath: expiredFixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => expiredStore.close())
  const expiredBroker = createProtectedJournalBroker({ store: expiredStore, contractSet: expiredFixture.contracts, admissionResolver: expiredAdmission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-03T00:12:30.000Z') })
  await assert.rejects(makeRoot(expiredFixture, expiredBroker), /D931_PEER_CONTEXT_REJECTED/)

  const delayedFixture = await createD931Fixture(t)
  let delayedCurrent = Date.parse('2030-01-01T00:20:00.000Z') - 1_000
  const delayedClock = (label) => new Date(delayedCurrent += label === 'primary_receipt' ? 301_000 : 1_000).toISOString()
  const delayed = await createSyntheticAvailableCustody(t, delayedFixture, { clockOverride: delayedClock, expectPublishFailure: true })
  assert.match(delayed.publishError.message, /D931_PEER_CONTEXT_REJECTED/)
  assert.equal(delayed.store.inventory().projection['receipt-exchanges'].length, 0)
  assert.equal(delayed.store.inventory().projection['primary-receipts'].length, 0)
})

test('journal seal authority must remain active at trusted acceptance and persistence boundaries', async (t) => {
  for (const scenario of [
    { name: 'expired-before-acceptance', expiresAt: '2030-01-01T00:19:59.500Z', acceptedAt: '2030-01-01T00:20:00.000Z', persistedAt: '2030-01-01T00:20:01.000Z' },
    { name: 'expired-before-persistence', expiresAt: '2030-01-01T00:20:00.500Z', acceptedAt: '2030-01-01T00:20:00.000Z', persistedAt: '2030-01-01T00:20:01.000Z' },
  ]) {
    const fixture = await createD931Fixture(t)
    fixture.seal.expires_at = scenario.expiresAt
    reseal(fixture.seal)
    const admission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
    admitFixtureAuthority(admission, fixture)
    const store = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
    t.after(() => store.close())
    const broker = createProtectedJournalBroker({
      store, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker',
      clock(label) { return label === 'journal_event_acceptance' ? scenario.acceptedAt : scenario.persistedAt },
    })
    const before = canonicalize(store.inventory().projection)
    await assert.rejects(() => appendOperationStarted({
      journalPeerProvider: (request) => authenticatedPeerFor(fixture, request), journalBroker: broker,
      journalCode: `journal.${fixture.seal.operation_id}`, journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer',
      componentExecutableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256,
      journalProfileDigest: fixture.journalProfile.record_digest_sha256, operationModeCode: 'document_import',
      operationId: fixture.seal.operation_id, operationNonce: fixture.seal.operation_nonce,
      authorizationBundleSealDigest: fixture.seal.record_digest_sha256, bundle: fixture.seal.bundle,
      targetLogicalState: fixture.seal.target_logical_state,
      runtimeProfileDigest: fixture.generation.runtimeProfile.record_digest_sha256,
      identityBindingsDigest: fixture.generation.identityBindings.record_digest_sha256,
      eventAt: '2030-01-01T00:19:58.000Z', requestCreatedAt: '2030-01-01T00:19:59.000Z',
    }), /D931_JOURNAL_CHAIN_CORRUPT/, scenario.name)
    assert.equal(canonicalize(store.inventory().projection), before, `${scenario.name} must leave no append request, event, or response`)
  }
})

test('eventless append and receipt requests reserve their exact operation across restart', async (t) => {
  const fixture = await createD931Fixture(t)
  const admission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  admitFixtureAuthority(admission, fixture)
  let interruptAppend = true
  const store = createDurableNamespaceStore({
    rootPath: fixture.journalRoot,
    namespaceCodes: D931_JOURNAL_NAMESPACES,
    faultInjector(point, context) {
      if (interruptAppend && point === 'after_record_write' && context.namespaceCode === 'journal-events') {
        interruptAppend = false
        throw new Error('synthetic eventless append crash')
      }
    },
  })
  const broker = createProtectedJournalBroker({ store, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:12:30.000Z') })
  const operationId = fixture.seal.operation_id
  const args = {
    journalPeerProvider: (request) => authenticatedPeerFor(fixture, request), journalBroker: broker,
    journalCode: `journal.${operationId}`, journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer',
    componentExecutableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256,
    journalProfileDigest: fixture.journalProfile.record_digest_sha256, operationModeCode: 'document_import', operationId,
    operationNonce: fixture.seal.operation_nonce, authorizationBundleSealDigest: fixture.seal.record_digest_sha256,
    bundle: fixture.seal.bundle,
    targetLogicalState: fixture.seal.target_logical_state,
    runtimeProfileDigest: fixture.generation.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: fixture.generation.identityBindings.record_digest_sha256,
    eventAt: '2030-01-01T00:12:28.000Z', requestCreatedAt: '2030-01-01T00:12:29.000Z',
  }
  await assert.rejects(appendOperationStarted(args), /synthetic eventless append crash/)
  store.close()
  const reopenedStore = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => reopenedStore.close())
  const reopenedBroker = createProtectedJournalBroker({ store: reopenedStore, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:12:31.000Z') })
  const appendPath = path.join(fixture.journalRoot, 'supporting-records', `append.semantic.start.${operationId}`)
  const pendingAppend = parseStrictJson(fs.readFileSync(appendPath), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
  const competingAppend = structuredClone(pendingAppend)
  competingAppend.created_at = '2030-01-01T00:12:29.500Z'
  const competingAppendRecord = canonicalRecord(competingAppend)
  const competingAppendPeer = await authenticatedPeerFor(fixture, competingAppendRecord)
  assert.throws(() => reopenedBroker.appendSemantic(competingAppendRecord, competingAppendPeer), /D931_JOURNAL_REPLAY_COLLISION|D931_JOURNAL_OPERATION_FORK/)
  const recoveredAppend = reopenedBroker.appendSemantic(pendingAppend, await authenticatedPeerFor(fixture, pendingAppend))
  assert.equal(recoveredAppend.payload.outcome_code, 'persisted')

  const receiptFixture = await createD931Fixture(t)
  const receiptFlow = await createSyntheticAvailableCustody(t, receiptFixture, {
    expectPublishFailure: true,
    journalFaultInjector(point) { if (point === 'before_receipt_persist') throw new Error('synthetic request-only receipt crash') },
  })
  assert.match(receiptFlow.publishError.message, /synthetic request-only receipt crash/)
  const receiptRequestPath = path.join(receiptFixture.journalRoot, 'receipt-exchanges', `receipt.persist.${receiptFixture.seal.operation_id}`)
  const pendingReceipt = parseStrictJson(fs.readFileSync(receiptRequestPath), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
  receiptFlow.store.close()
  const receiptStore = createDurableNamespaceStore({ rootPath: receiptFixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => receiptStore.close())
  const receiptCompletedMs = Date.parse(pendingReceipt.payload.receipt_semantic.completed_at)
  const receiptReplayBaseMs = Math.max(receiptCompletedMs, Date.parse(pendingReceipt.created_at))
  const receiptBroker = createProtectedJournalBroker({ store: receiptStore, contractSet: receiptFixture.contracts, admissionResolver: receiptFlow.admission, journalBindingCode: 'binding.journal-broker', clock: makeClock(new Date(receiptReplayBaseMs + 500).toISOString()) })
  const competingReceipt = structuredClone(pendingReceipt)
  competingReceipt.created_at = new Date(receiptReplayBaseMs + 250).toISOString()
  const competingReceiptRecord = canonicalRecord(competingReceipt)
  const competingReceiptPeer = await authenticatedPeerFor(receiptFixture, competingReceiptRecord)
  assert.throws(() => receiptBroker.persistPrimaryReceipt(competingReceiptRecord, competingReceiptPeer), /D931_RECEIPT_REPLAY_COLLISION/)
  const recoveredReceipt = receiptBroker.persistPrimaryReceipt(pendingReceipt, await authenticatedPeerFor(receiptFixture, pendingReceipt))
  assert.equal(recoveredReceipt.payload.outcome_code, 'persisted')
})

test('protected namespace append never exposes an unsynchronized final record after restart', () => {
  const recoverableRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-write-'))
  fs.chmodSync(recoverableRoot, 0o700)
  const first = createDurableNamespaceStore({ rootPath: recoverableRoot, namespaceCodes: ['records'], faultInjector(point) { if (point === 'after_record_write') throw new Error('synthetic write crash') } })
  assert.throws(() => first.append({ namespaceCode: 'records', recordCode: 'record.001', bytes: Buffer.from('{}') }), /synthetic write crash/)
  first.close()
  const reopened = createDurableNamespaceStore({ rootPath: recoverableRoot, namespaceCodes: ['records'] })
  assert.equal(reopened.inventory().projection.records.length, 0)
  reopened.close()
  fs.rmSync(recoverableRoot, { recursive: true, force: true })

  const ambiguousRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-publish-'))
  fs.chmodSync(ambiguousRoot, 0o700)
  const second = createDurableNamespaceStore({ rootPath: ambiguousRoot, namespaceCodes: ['records'], faultInjector(point) { if (point === 'after_record_publish_before_directory_sync') throw new Error('synthetic publish crash') } })
  assert.throws(() => second.append({ namespaceCode: 'records', recordCode: 'record.002', bytes: Buffer.from('{}') }), /synthetic publish crash/)
  assert.throws(() => second.append({ namespaceCode: 'records', recordCode: 'record.003', bytes: Buffer.from('{"safe":false}') }), /D931_STORE_RECOVERY_REQUIRED/)
  assert.throws(() => second.read({ namespaceCode: 'records', recordCode: 'record.002' }), /D931_STORE_RECOVERY_REQUIRED/)
  assert.throws(() => second.inventory(), /D931_STORE_RECOVERY_REQUIRED/)
  second.close()
  assert.throws(() => createDurableNamespaceStore({ rootPath: ambiguousRoot, namespaceCodes: ['records'] }), /D931_STORE_RECOVERY_REQUIRED/)
  fs.rmSync(ambiguousRoot, { recursive: true, force: true })
})

test('protected namespace store latches failed EEXIST cleanup and rejects use after descriptor reuse', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-lifecycle-'))
  fs.chmodSync(root, 0o700)
  const store = createDurableNamespaceStore({ rootPath: root, namespaceCodes: ['records'] })
  const rootReal = fs.realpathSync(root)
  const rootFd = fs.readdirSync('/proc/self/fd').map(Number).find((fd) => (() => { try { return fs.realpathSync(`/proc/self/fd/${fd}`) === rootReal } catch { return false } })())
  assert.ok(Number.isInteger(rootFd))
  store.append({ namespaceCode: 'records', recordCode: 'record.001', replayKey: 'first', bytes: Buffer.from('{"safe":true}') })
  const originalUnlink = fs.unlinkSync
  fs.unlinkSync = (target) => {
    if (String(target).includes('/pending/')) {
      const error = new Error('synthetic pending cleanup failure')
      error.code = 'EIO'
      throw error
    }
    return originalUnlink(target)
  }
  try {
    assert.throws(() => store.append({ namespaceCode: 'records', recordCode: 'record.001', replayKey: 'second', bytes: Buffer.from('{"safe":true}') }), /synthetic pending cleanup failure/)
  } finally { fs.unlinkSync = originalUnlink }
  assert.throws(() => store.inventory(), /D931_STORE_RECOVERY_REQUIRED/)
  assert.throws(() => store.read({ namespaceCode: 'records', recordCode: 'record.001' }), /D931_STORE_RECOVERY_REQUIRED/)
  store.close()

  const substitute = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-substitute-'))
  fs.chmodSync(substitute, 0o700)
  fs.mkdirSync(path.join(substitute, 'records'), { mode: 0o700 })
  fs.writeFileSync(path.join(substitute, 'records', 'record.001'), 'substituted', { mode: 0o600 })
  const substituteFd = fs.openSync(substitute, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
  assert.equal(substituteFd, rootFd, 'the closed protected root descriptor must be reused for the adversarial substitute')
  assert.throws(() => store.read({ namespaceCode: 'records', recordCode: 'record.001' }), /D931_STORE_CLOSED/)
  assert.throws(() => store.inventory(), /D931_STORE_CLOSED/)
  fs.closeSync(substituteFd)
  fs.rmSync(root, { recursive: true, force: true })
  fs.rmSync(substitute, { recursive: true, force: true })
})

test('protected namespace store rejects unexpected root entries and closes its descriptor on constructor failure', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-root-inventory-'))
  fs.chmodSync(root, 0o700)
  fs.mkdirSync(path.join(root, 'rogue-on-disk'), { mode: 0o700 })
  const rootReal = fs.realpathSync(root)
  const countRootDescriptors = () => fs.readdirSync('/proc/self/fd').filter((entry) => {
    try { return fs.realpathSync(`/proc/self/fd/${entry}`) === rootReal } catch { return false }
  }).length
  const before = countRootDescriptors()
  assert.throws(() => createDurableNamespaceStore({ rootPath: root, namespaceCodes: ['records'] }), /D931_NAMESPACE_INVALID/)
  assert.equal(countRootDescriptors(), before, 'failed construction must not leak the protected root descriptor')
  fs.rmSync(root, { recursive: true, force: true })

  const partialRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-partial-inventory-'))
  fs.chmodSync(partialRoot, 0o700)
  const initialized = createDurableNamespaceStore({ rootPath: partialRoot, namespaceCodes: ['records', 'receipts'] })
  initialized.close()
  fs.rmdirSync(path.join(partialRoot, 'receipts'))
  assert.throws(() => createDurableNamespaceStore({ rootPath: partialRoot, namespaceCodes: ['records', 'receipts'] }), /D931_NAMESPACE_INVALID/)
  fs.rmSync(partialRoot, { recursive: true, force: true })

  const liveRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-live-inventory-'))
  fs.chmodSync(liveRoot, 0o700)
  const live = createDurableNamespaceStore({ rootPath: liveRoot, namespaceCodes: ['records'] })
  fs.mkdirSync(path.join(liveRoot, 'rogue-live'), { mode: 0o700 })
  assert.throws(() => live.inventory(), /D931_NAMESPACE_INVALID/)
  fs.rmdirSync(path.join(liveRoot, 'rogue-live'))
  fs.chmodSync(liveRoot, 0o755)
  assert.throws(() => live.inventory(), /D931_ROOT_UNPROTECTED/)
  fs.chmodSync(liveRoot, 0o700)
  const movedPending = `${liveRoot}.pending-real`
  fs.renameSync(path.join(liveRoot, 'pending'), movedPending)
  fs.symlinkSync(movedPending, path.join(liveRoot, 'pending'))
  assert.throws(() => live.inventory(), /D931_PATH_SUBSTITUTION/)
  live.close()
  fs.rmSync(liveRoot, { recursive: true, force: true })
  fs.rmSync(movedPending, { recursive: true, force: true })
})

test('protected namespace object-open validation closes descriptors when fstat fails', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-object-open-'))
  fs.chmodSync(root, 0o700)
  const store = createDurableNamespaceStore({ rootPath: root, namespaceCodes: ['records'] })
  store.append({ namespaceCode: 'records', recordCode: 'record.001', bytes: Buffer.from('{"safe":true}') })
  const descriptorCount = () => fs.readdirSync('/proc/self/fd').length
  const before = descriptorCount()
  const originalFstat = fs.fstatSync
  fs.fstatSync = (descriptor, ...args) => {
    let target = ''
    try { target = fs.readlinkSync(`/proc/self/fd/${descriptor}`) } catch {}
    if (target.endsWith('/records/record.001')) throw Object.assign(new Error('synthetic object fstat failure'), { code: 'EIO' })
    return originalFstat(descriptor, ...args)
  }
  try { assert.throws(() => store.read({ namespaceCode: 'records', recordCode: 'record.001' }), /synthetic object fstat failure/) } finally { fs.fstatSync = originalFstat }
  assert.equal(descriptorCount(), before, 'failed object-open validation must not leak a descriptor')
  store.close()
  fs.rmSync(root, { recursive: true, force: true })
})

test('protected namespace store rejects a configured-root swap between path validation and open', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-root-swap-'))
  const substitute = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-store-root-substitute-'))
  fs.chmodSync(root, 0o700)
  fs.chmodSync(substitute, 0o755)
  const originalOpen = fs.openSync
  fs.openSync = (target, ...args) => originalOpen(target === root ? substitute : target, ...args)
  try { assert.throws(() => createDurableNamespaceStore({ rootPath: root, namespaceCodes: ['records'] }), /D931_ROOT_UNPROTECTED/) } finally { fs.openSync = originalOpen }
  assert.deepEqual(fs.readdirSync(root), [])
  assert.deepEqual(fs.readdirSync(substitute), [])
  fs.rmSync(root, { recursive: true, force: true })
  fs.rmSync(substitute, { recursive: true, force: true })
})

test('journal broker latches an ambiguously published store effect and receipt corruption fails restart', async (t) => {
  const faultFixture = await createD931Fixture(t)
  const faultAdmission = createD931AdmissionResolver({ contractSet: faultFixture.contracts, verifiedGeneration: faultFixture.generation, custodyProfile: faultFixture.custodyProfile, journalProfile: faultFixture.journalProfile })
  admitFixtureAuthority(faultAdmission, faultFixture)
  const faultStore = createDurableNamespaceStore({ rootPath: faultFixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES, faultInjector(point, context) { if (point === 'after_record_publish_before_directory_sync' && context.namespaceCode === 'journal-events') throw new Error('ambiguous journal publication') } })
  t.after(() => faultStore.close())
  const faultBroker = createProtectedJournalBroker({ store: faultStore, contractSet: faultFixture.contracts, admissionResolver: faultAdmission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:12:30.000Z') })
  await assert.rejects(() => appendOperationStarted({ journalPeerProvider: (request) => authenticatedPeerFor(faultFixture, request), journalBroker: faultBroker, journalCode: `journal.${faultFixture.seal.operation_id}`, journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer', componentExecutableSha256: faultFixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256, journalProfileDigest: faultFixture.journalProfile.record_digest_sha256, operationModeCode: 'document_import', operationId: faultFixture.seal.operation_id, operationNonce: faultFixture.seal.operation_nonce, authorizationBundleSealDigest: faultFixture.seal.record_digest_sha256, bundle: faultFixture.seal.bundle, targetLogicalState: faultFixture.seal.target_logical_state, runtimeProfileDigest: faultFixture.generation.runtimeProfile.record_digest_sha256, identityBindingsDigest: faultFixture.generation.identityBindings.record_digest_sha256, eventAt: '2030-01-01T00:12:28.000Z', requestCreatedAt: '2030-01-01T00:12:29.000Z' }), /ambiguous journal publication/)
  assert.throws(() => faultBroker.head(`journal.${faultFixture.seal.operation_id}`), /D931_JOURNAL_RECOVERY_REQUIRED/)

  const receiptFixture = await createD931Fixture(t)
  const flow = await createSyntheticAvailableCustody(t, receiptFixture)
  flow.store.close()
  const receiptItem = fs.readdirSync(path.join(receiptFixture.journalRoot, 'primary-receipts'))[0]
  const receiptPath = path.join(receiptFixture.journalRoot, 'primary-receipts', receiptItem)
  const receipt = parseStrictJson(fs.readFileSync(receiptPath), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
  receipt.semantic.copy_code = 'copy.primary.synthetic.corrupt'
  receipt.semantic_payload_sha256 = canonicalSha256(receipt.semantic)
  fs.chmodSync(receiptPath, 0o600)
  fs.writeFileSync(receiptPath, canonicalize(receipt))
  fs.chmodSync(receiptPath, 0o400)
  const reopenedStore = createDurableNamespaceStore({ rootPath: receiptFixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => reopenedStore.close())
  assert.throws(() => createProtectedJournalBroker({ store: reopenedStore, contractSet: receiptFixture.contracts, admissionResolver: flow.admission, journalBindingCode: 'binding.journal-broker', clock: makeClock() }), /D931_RECEIPT_CHAIN_CORRUPT|D931_RECEIPT_BINDING_MISMATCH|D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE|D931_SUPPORTING_CHAIN_CORRUPT/)
})

test('journal restart rejects renamed, wrong-namespace, and orphan protected records', async (t) => {
  const renamedFixture = await createD931Fixture(t)
  const renamedFlow = await createSyntheticAvailableCustody(t, renamedFixture)
  renamedFlow.store.close()
  const renamedDirectory = path.join(renamedFixture.journalRoot, 'supporting-records')
  const renamedSource = fs.readdirSync(renamedDirectory)[0]
  fs.renameSync(path.join(renamedDirectory, renamedSource), path.join(renamedDirectory, 'renamed.valid.record'))
  const renamedStore = createDurableNamespaceStore({ rootPath: renamedFixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => renamedStore.close())
  assert.throws(() => createProtectedJournalBroker({ store: renamedStore, contractSet: renamedFixture.contracts, admissionResolver: renamedFlow.admission, journalBindingCode: 'binding.journal-broker', clock: makeClock() }), /D931_PROTECTED_NAMESPACE_CORRUPT/)

  const misplacedFixture = await createD931Fixture(t)
  const misplacedFlow = await createSyntheticAvailableCustody(t, misplacedFixture)
  misplacedFlow.store.close()
  const eventDirectory = path.join(misplacedFixture.journalRoot, 'receipt-exchanges')
  const eventCode = fs.readdirSync(eventDirectory)[0]
  fs.renameSync(path.join(eventDirectory, eventCode), path.join(misplacedFixture.journalRoot, 'recovery-assessments', eventCode))
  const misplacedStore = createDurableNamespaceStore({ rootPath: misplacedFixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => misplacedStore.close())
  assert.throws(() => createProtectedJournalBroker({ store: misplacedStore, contractSet: misplacedFixture.contracts, admissionResolver: misplacedFlow.admission, journalBindingCode: 'binding.journal-broker', clock: makeClock() }), /D931_PROTECTED_NAMESPACE_CORRUPT/)

  const orphanFixture = await createD931Fixture(t)
  const orphanFlow = await createSyntheticAvailableCustody(t, orphanFixture)
  const subjectItem = orphanFlow.store.inventory().projection['supporting-records'].find((item) => {
    const record = parseStrictJson(orphanFlow.store.read({ namespaceCode: 'supporting-records', recordCode: item.record_code }), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
    return record.format === 'jedi-atlas-custody-adapter-message' && record.message_kind_code === 'request'
  })
  const subject = parseStrictJson(orphanFlow.store.read({ namespaceCode: 'supporting-records', recordCode: subjectItem.record_code }), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
  subject.record_code = `${subject.record_code}.orphan`
  subject.request_id = `${subject.request_id}.orphan`
  const orphan = canonicalRecord(subject)
  orphanFlow.store.append({ namespaceCode: 'supporting-records', recordCode: orphan.record_code, bytes: Buffer.from(canonicalize(orphan), 'utf8') })
  orphanFlow.store.close()
  const orphanStore = createDurableNamespaceStore({ rootPath: orphanFixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => orphanStore.close())
  assert.throws(() => createProtectedJournalBroker({ store: orphanStore, contractSet: orphanFixture.contracts, admissionResolver: orphanFlow.admission, journalBindingCode: 'binding.journal-broker', clock: makeClock() }), /D931_SUPPORTING_CHAIN_CORRUPT/)
})
