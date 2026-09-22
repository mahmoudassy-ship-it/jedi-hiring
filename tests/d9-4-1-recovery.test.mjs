import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { test } from 'node:test'

import { canonicalSha256, canonicalize } from '../d9/control-plane/canonical.mjs'
import * as recoveryApi from '../d9/restriction/recovery.mjs'
import { classifyD941Recovery, reconstructD941RecoveryState } from '../d9/restriction/recovery.mjs'
import * as resolverApi from '../d9/restriction/recovery-resolvers.mjs'
import { createD941ResolverDurabilityStore, createD941SyntheticRecoveryResolverRuntime } from '../d9/restriction/recovery-resolvers.mjs'
import { createD941Fixture, custodyEvidenceForSubject, humanSession, makeControlRecord, serviceSession, subjectFor } from './d9-4-1-support/fixture.mjs'

const expected = Object.freeze({
  before_restriction_persisted: 'safe_no_effect',
  after_restriction_before_capability_revocation: 'restriction_required',
  after_revocation_before_descriptor_termination: 'retain_and_hold',
  after_tombstone_before_unlink: 'retain_and_hold',
  after_unlink_before_directory_sync: 'reconciliation_required',
  after_sync_before_verification: 'reconciliation_required',
  after_verification_before_receipt: 'reconciliation_required',
  after_receipt_before_journal_link: 'reconciliation_required',
})

test('recovery proof issuance is not a public registrar or issuer', () => {
  assert.equal('registerD941Reconstruction' in recoveryApi, false)
  assert.equal('issueD941RecoveryClassificationProof' in recoveryApi, false)
})

test('restart reconstruction reads protected facts and remains classification-only', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const state = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: 'a'.repeat(64) })
  assert.equal(state.ledger_state_code, 'linear_complete')
  assert.equal(state.classification_only, true)
  assert.equal(state.unreceipted_target, false)
})

function baseRecord(subject, semanticActor, persistenceActor, { persistedAt = '2030-01-01T00:10:03.000Z', receiptSequence = 1 } = {}) {
  return {
    format: 'jedi-atlas-d940-recovery-assessment', format_version: '1.0.0', record_code: 'recovery.synthetic.001',
    operation_id: 'operation.recovery.001', operation_nonce: 'e'.repeat(64), subject,
    semantic_actor: semanticActor, persistence_actor: persistenceActor,
    knowledge_boundary: { effective_at: new Date(Date.parse(persistedAt) - 2).toISOString(), recorded_at: new Date(Date.parse(persistedAt) - 1).toISOString(), persisted_at: persistedAt, journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: receiptSequence },
    record_digest_sha256: null,
  }
}

function resolverRuntime(fixture, subject, trustedAt = '2030-01-01T00:10:01.500Z', { durabilityStore = fixture.resolverStore, faultInjector = null, trustedClock = null } = {}) {
  const defaultClock = () => {
    const ledgerPersistedAt = fixture.broker.head().persistedAt
    if (ledgerPersistedAt === null) return trustedAt
    const afterLedger = new Date(Date.parse(ledgerPersistedAt) + 1).toISOString()
    return Date.parse(afterLedger) > Date.parse(trustedAt) ? afterLedger : trustedAt
  }
  return createD941SyntheticRecoveryResolverRuntime({ authorityContext: fixture.authorityContext, authorityRegistry: fixture.registry, broker: fixture.broker, subject, custodyEvidence: custodyEvidenceForSubject(fixture, subject), trustedClock: fixture.createResolverClock(trustedClock ?? defaultClock), durabilityStore, persistenceSession: fixture.resolverPersistenceSession, verifierSession: fixture.resolverVerifierSession, finalizerSession: fixture.resolverFinalizerSession, faultInjector })
}

function resolvedReconstruction(fixture, subject, operationId = 'operation.recovery.001', operationNonce = 'e'.repeat(64), trustedAt) {
  return reconstructD941RecoveryState({
    broker: fixture.broker,
    subjectIdentitySha256: subject.subject_identity_sha256,
    subjectKindCode: subject.subject_kind_code,
    resolverRuntime: resolverRuntime(fixture, subject, trustedAt),
    resolverOperationId: operationId,
    resolverOperationNonce: operationNonce,
  })
}

async function primeProtectedHead(fixture) {
  const journal = await serviceSession(fixture, 'control_submission', 'journal_broker')
  const actor = await humanSession(fixture, 'security_authority', 'recovery_operator')
  const subject = subjectFor(Buffer.from('unrelated protected head\n')).subject
  const persistedAt = fixture.time.reserve()
  const record = makeControlRecord({ fixture, kind: 'restriction_imposed', code: 'control.recovery.prime.001', operationId: 'operation.recovery.prime.001', nonce: 'c'.repeat(64), subject, semanticActor: actor.actor, persistenceActor: journal.actor, sequence: 1, effectiveAt: new Date(Date.parse(persistedAt) - 2).toISOString(), recordedAt: new Date(Date.parse(persistedAt) - 1).toISOString(), persistedAt })
  await fixture.broker.append({ record, semanticSession: actor, persistenceSession: journal })
}

function snapshot(reconstruction) {
  return structuredClone(reconstruction.snapshot_projection)
}

function resealRecord(record) {
  record.record_digest_sha256 = canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' })
  return record
}

function reconstructionFor(fixture, subject) {
  return reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256 })
}

for (const boundary of Object.keys(expected)) {
  test(`recovery boundary ${boundary} refuses without exact external resolvers`, async (t) => {
    const fixture = await createD941Fixture(t)
    await primeProtectedHead(fixture)
    const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
    const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
    const subject = subjectFor().subject
    const reconstruction = reconstructionFor(fixture, subject)
    assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: baseRecord(subject, verifier.actor, journal.actor), reconstruction, crashBoundaryCode: boundary, snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' }), /D941_RECOVERY_RESOLVER_UNAVAILABLE/)
  })
}

test('unknown, contradictory, incomplete, and forked state remains blocked without exact external resolvers', async (t) => {
  const fixture = await createD941Fixture(t); await primeProtectedHead(fixture); const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier'); const record = baseRecord(subjectFor().subject, verifier.actor, journal.actor)
  const subject = record.subject
  const reconstruction = reconstructionFor(fixture, subject)
  assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'fork' }), /D941_RECOVERY_RESOLVER_UNAVAILABLE/)
  assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: { ...record, record_code: 'recovery.synthetic.002' }, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'unavailable', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' }), /D941_RECOVERY_RESOLVER_UNAVAILABLE/)
})

test('D9.5 execution and complete-erasure outcomes remain structurally unreachable', async (t) => {
  const fixture = await createD941Fixture(t); await primeProtectedHead(fixture); const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const reconstruction = reconstructionFor(fixture, subject)
  assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: baseRecord(subject, verifier.actor, journal.actor), reconstruction, crashBoundaryCode: 'd9_5_restore', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' }), /D941_RECOVERY_RESOLVER_UNAVAILABLE/)
})

test('recovery rejects caller-controlled projection fields and unavailable resolver inputs', async (t) => {
  const fixture = await createD941Fixture(t); await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject; const reconstruction = reconstructionFor(fixture, subject); const mutated = { control_head_projection_sha256: 'f'.repeat(64) }
  assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: baseRecord(subject, verifier.actor, journal.actor), reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: mutated, inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' }), /D941_RECOVERY_RESOLVER_UNAVAILABLE/)
})

test('approved D9.1, D9.2, and D9.3 synthetic adapters resolve the exact D9.4 snapshot and append-time attestation', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.001'
  const operationNonce = 'e'.repeat(64)
  const reconstruction = resolvedReconstruction(fixture, subject, operationId, operationNonce)
  assert.equal(reconstruction.snapshot_projection.journal_namespace_code, 'd940.global.control-journal.v1')
  assert.equal(reconstruction.snapshot_projection.known_through_receipt_sequence, fixture.broker.head().sequence)
  assert.equal(reconstruction.snapshot_projection.control_ledger_head_receipt_digest_sha256, fixture.broker.head().digest)
  const persistedAt = fixture.time.reserve(1400)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 })
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  assert.equal(assessment.classification_code, 'safe_no_effect')
  assert.equal(assessment.action_execution_code, 'none_classification_only')
  assert.equal(assessment.recovery_authority_present, false)
  const appended = await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(appended.created, true)
  assert.equal(appended.record.record_digest_sha256, assessment.record_digest_sha256)
})

test('all frozen crash boundaries classify deterministically from one exact technical-evidence snapshot', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const reconstruction = resolvedReconstruction(fixture, subject)
  for (const [boundary, classification] of Object.entries(expected)) {
    const assessment = classifyD941Recovery({
      authorityContext: fixture.authorityContext,
      broker: fixture.broker,
      record: { ...baseRecord(subject, verifier.actor, journal.actor, { persistedAt: '2030-01-01T00:10:02.500Z', receiptSequence: 2 }), record_code: `recovery.synthetic.${boundary}` },
      reconstruction,
      crashBoundaryCode: boundary,
      snapshot: snapshot(reconstruction),
      inventoryStateCode: 'complete',
      accessStateCode: 'none_confirmed',
      controlStateCode: 'linear_complete',
    })
    assert.equal(assessment.classification_code, classification)
    assert.equal(assessment.action_execution_code, 'none_classification_only')
    assert.equal(assessment.recovery_authority_present, false)
  }
})

test('append-time revalidation rejects a source-head move after classification', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const reconstruction = resolvedReconstruction(fixture, subject, 'operation.recovery.001', 'e'.repeat(64), '2030-01-01T00:10:02.000Z')
  const recoveryPersistedAt = '2030-01-01T00:10:03.000Z'
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: baseRecord(subject, verifier.actor, journal.actor, { persistedAt: recoveryPersistedAt, receiptSequence: 2 }), reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  const movementActor = await humanSession(fixture, 'security_authority', 'recovery_operator')
  const movementJournal = await serviceSession(fixture, 'control_submission', 'journal_broker')
  const movedAt = fixture.time.reserve()
  const movement = makeControlRecord({ fixture, kind: 'restriction_imposed', code: 'control.recovery.move.001', operationId: 'operation.recovery.move.001', nonce: 'd'.repeat(64), subject: subjectFor(Buffer.from('head movement\n')).subject, semanticActor: movementActor.actor, persistenceActor: movementJournal.actor, sequence: 1, effectiveAt: new Date(Date.parse(movedAt) - 2).toISOString(), recordedAt: new Date(Date.parse(movedAt) - 1).toISOString(), persistedAt: movedAt })
  await fixture.broker.append({ record: movement, semanticSession: movementActor, persistenceSession: movementJournal })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /D941_RECOVERY_APPEND_REVALIDATION_FAILED/)
  assert.equal(fixture.store.inventory().projection.recovery.length, 0)
})

test('resolver-backed recovery rejects operation, subject, snapshot, and freshness substitution', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const runtime = resolverRuntime(fixture, subject)
  assert.throws(() => createD941SyntheticRecoveryResolverRuntime({ authorityContext: fixture.authorityContext, authorityRegistry: fixture.registry, broker: fixture.broker, subject, custodyEvidence: custodyEvidenceForSubject(fixture, subject), trustedClock: () => '2030-01-01T00:10:01.500Z', durabilityStore: fixture.resolverStore, persistenceSession: fixture.resolverPersistenceSession, verifierSession: fixture.resolverVerifierSession, finalizerSession: fixture.resolverFinalizerSession }), /D941_RESOLVER_CONFIGURATION_INVALID/)
  assert.throws(() => createD941SyntheticRecoveryResolverRuntime({ authorityContext: fixture.authorityContext, authorityRegistry: fixture.registry, broker: fixture.broker, subject, custodyEvidence: custodyEvidenceForSubject(fixture, subject), trustedClock: fixture.createResolverClock(() => '2030-01-01T00:10:01.500Z'), durabilityStore: fixture.resolverStore, persistenceSession: fixture.resolverPersistenceSession, verifierSession: fixture.resolverPersistenceSession, finalizerSession: fixture.resolverFinalizerSession }), /D941_SESSION_SCOPE_MISMATCH/)
  assert.deepEqual(Object.keys(runtime).sort(), ['reconstruct', 'resolveComposite', 'revalidateAtAppend'])
  assert.equal('persistAssessmentLink' in runtime, false)
  assert.equal('durabilityStore' in runtime, false)
  assert.equal('appendD941ResolverAtomic' in resolverApi, false)
  assert.deepEqual(Object.keys(fixture.resolverStore).sort(), ['close', 'entries', 'head', 'inventory'])
  assert.equal('appendAtomic' in fixture.resolverStore, false)
  assert.equal('rawStore' in fixture.resolverStore, false)
  assert.throws(() => runtime.resolveComposite({ subject: subjectFor(Buffer.from('substituted subject\n')).subject, operationId: 'operation.recovery.001', operationNonce: 'e'.repeat(64) }), /D941_RESOLVER_SUBJECT_SUBSTITUTED/)
  const resolverSubject = { subject_kind_code: subject.subject_kind_code, subject_identity_sha256: subject.subject_identity_sha256 }
  assert.throws(() => resolverRuntime(fixture, subject, '2030-01-01T00:10:02Z').resolveComposite({ subject: resolverSubject, operationId: 'operation.recovery.bad-time', operationNonce: 'b'.repeat(64) }), /D941_RESOLVER_TIME_INVALID/)
  assert.throws(() => resolverRuntime(fixture, subject, '2099-01-01T00:00:00.000Z').resolveComposite({ subject: resolverSubject, operationId: 'operation.recovery.expired', operationNonce: 'c'.repeat(64) }), /D941_AUTHORITY_EXPIRED/)
  assert.throws(() => resolverRuntime(fixture, subject, '2030-01-01T00:10:00.500Z', { trustedClock: () => '2030-01-01T00:10:00.500Z' }).resolveComposite({ subject: resolverSubject, operationId: 'operation.recovery.future-head', operationNonce: 'd'.repeat(64) }), /D941_RESOLVER_SOURCE_HEAD_FUTURE/)
  const issued = runtime.resolveComposite({ subject: resolverSubject, operationId: 'operation.recovery.immutable', operationNonce: 'a'.repeat(64) })
  assert.throws(() => { issued.compositeResponse.projection.snapshot.control_head_projection_sha256 = 'f'.repeat(64) }, TypeError)
  const reconstruction = resolvedReconstruction(fixture, subject)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt: '2030-01-01T00:10:02.500Z', receiptSequence: 2 })
  assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: { ...record, operation_id: 'operation.recovery.substituted' }, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' }), /D941_RECOVERY_RESOLVER_CONTEXT_MISMATCH/)
  const mutated = snapshot(reconstruction); mutated.subject_lineage_projection_sha256 = 'f'.repeat(64)
  assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: mutated, inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' }), /D941_RECOVERY_SNAPSHOT_MISMATCH/)
  const lateRecord = baseRecord(subject, verifier.actor, journal.actor, { persistedAt: '2030-01-01T00:10:04.000Z', receiptSequence: 2 })
  const lateAssessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: lateRecord, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: lateAssessment, semanticSession: verifier, persistenceSession: journal }), /D941_RECOVERY_APPEND_REVALIDATION_EXPIRED/)
  assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'd9_5_restore', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' }), /D941_RECOVERY_BOUNDARY_UNKNOWN/)
})

test('v1.1 protected checkpoint bootstrap is exact, empty-only, and technical-evidence-only', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const subject = subjectFor().subject
  const runtime = resolverRuntime(fixture, subject)
  const state = runtime.reconstruct()
  assert.equal(state.checkpoints.length, 1)
  assert.equal(state.checkpoints[0].checkpoint_kind_code, 'bootstrap')
  assert.equal(state.checkpoints[0].sequence, 1)
  assert.equal(state.checkpoints[0].technical_evidence_only, true)
  assert.equal(state.checkpoints[0].authority_granted, false)
  assert.equal(state.durableRecords.length, 0)
  assert.equal(state.links.length, 0)
  assert.deepEqual(fixture.resolverStore.inventory().projection['d9.resolver.checkpoints.v1.1'].map((item) => item.record_code), ['append-000000000001'])
})

test('v1.1 durable evidence and v1.2 receipt-proven progression survive restart and exact replay', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.durable.001'
  const operationNonce = '9'.repeat(64)
  const runtime = resolverRuntime(fixture, subject)
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 })
  record.record_code = 'recovery.synthetic.durable.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  const appended = await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(appended.created, true)
  const beforeRestart = runtime.reconstruct()
  assert.deepEqual(beforeRestart.durableRecords.map((item) => item.wrapper.record_kind_code), ['request', 'response', 'request', 'response', 'request', 'response', 'request', 'response', 'append_attestation'])
  assert.equal(beforeRestart.checkpoints.length, 1)
  assert.equal(beforeRestart.transitions.length, 1)
  assert.equal(beforeRestart.transitions[0].transition.transition_sequence, 2)
  assert.equal(beforeRestart.links.length, 1)
  assert.equal(beforeRestart.links[0].link.technical_evidence_only, true)
  assert.equal(beforeRestart.links[0].link.authority_granted, false)
  const inventoryBefore = fixture.resolverStore.inventory().digest
  fixture.resolverStore.close()
  const reopenedStore = createD941ResolverDurabilityStore({ rootPath: fixture.roots.resolver })
  t.after(() => reopenedStore.close())
  const restarted = resolverRuntime(fixture, subject, '2030-01-01T00:10:04.000Z', { durabilityStore: reopenedStore })
  const replayReconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: restarted, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const replayAssessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction: replayReconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(replayReconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  const replay = await fixture.broker.append({ record: replayAssessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(replay.created, false)
  assert.equal(reopenedStore.inventory().digest, inventoryBefore)
  assert.equal(restarted.reconstruct().links.length, 1)
  const next = restarted.resolveComposite({ subject: { subject_kind_code: subject.subject_kind_code, subject_identity_sha256: subject.subject_identity_sha256 }, operationId: 'operation.recovery.durable.002', operationNonce: '7'.repeat(64) })
  assert.equal(next.durability.checkpoint.checkpoint_contract_version, '1.2.0')
  const secondReconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: restarted, resolverOperationId: 'operation.recovery.durable.002', resolverOperationNonce: '7'.repeat(64) })
  const secondPersistedAt = fixture.time.reserve(2100)
  const secondRecord = baseRecord(subject, verifier.actor, journal.actor, { persistedAt: secondPersistedAt, receiptSequence: fixture.broker.head().sequence + 1 })
  secondRecord.record_code = 'recovery.synthetic.durable.002'; secondRecord.operation_id = 'operation.recovery.durable.002'; secondRecord.operation_nonce = '7'.repeat(64)
  const secondAssessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: secondRecord, reconstruction: secondReconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(secondReconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  const secondAppend = await fixture.broker.append({ record: secondAssessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(secondAppend.created, true)
  assert.equal(restarted.reconstruct().transitions.length, 2)
  assert.equal(restarted.reconstruct().checkpointReferences.at(-1).checkpoint_sequence, 3)
  assert.equal(reopenedStore.entries('d9.resolver.records.v1.1').length, 18)
})

test('response loss after a durable wrapper append reconstructs to an exact no-op instead of forking', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const subject = subjectFor().subject
  const resolverSubject = { subject_kind_code: subject.subject_kind_code, subject_identity_sha256: subject.subject_identity_sha256 }
  let injected = false
  const runtime = resolverRuntime(fixture, subject, '2030-01-01T00:10:01.500Z', {
    faultInjector(boundary, context) {
      if (!injected && boundary === 'after_resolver_atomic_append_before_response' && context.namespaceCode === 'd9.resolver.records.v1.1' && context.payloadRecord.record_kind_code === 'response') {
        injected = true
        throw new Error('synthetic response loss')
      }
    },
  })
  assert.throws(() => runtime.resolveComposite({ subject: resolverSubject, operationId: 'operation.recovery.response-loss.001', operationNonce: '8'.repeat(64) }), /synthetic response loss/)
  assert.equal(fixture.resolverStore.entries('d9.resolver.records.v1.1').length, 2)
  fixture.resolverStore.close()
  const reopenedStore = createD941ResolverDurabilityStore({ rootPath: fixture.roots.resolver })
  t.after(() => reopenedStore.close())
  const restarted = resolverRuntime(fixture, subject, '2030-01-01T00:10:02.000Z', { durabilityStore: reopenedStore })
  const replay = restarted.resolveComposite({ subject: resolverSubject, operationId: 'operation.recovery.response-loss.001', operationNonce: '8'.repeat(64) })
  assert.equal(replay.compositeResponse.operation_id, 'operation.recovery.response-loss.001')
  assert.equal(reopenedStore.entries('d9.resolver.records.v1.1').length, 8)
})

test('checkpoint bootstrap failure before durable publish rolls back to the exact empty namespace and can retry once', async (t) => {
  let injected = false
  const fixture = await createD941Fixture(t, {
    resolverFaultInjector(boundary, context) {
      if (!injected && boundary === 'after_record_write' && context.namespaceCode === 'd9.resolver.checkpoints.v1.1') {
        injected = true
        throw new Error('synthetic bootstrap write failure')
      }
    },
  })
  await primeProtectedHead(fixture)
  const subject = subjectFor().subject
  assert.throws(() => resolverRuntime(fixture, subject), /synthetic bootstrap write failure/)
  assert.equal(fixture.resolverStore.entries('d9.resolver.checkpoints.v1.1').length, 0)
  const recovered = resolverRuntime(fixture, subject)
  assert.equal(recovered.reconstruct().checkpoints.length, 1)
  assert.equal(fixture.resolverStore.entries('d9.resolver.checkpoints.v1.1').length, 1)
})

test('assessment-link response loss leaves exact durable cross-store state and retry is a no-op', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.link-loss.001'
  const operationNonce = '6'.repeat(64)
  let injected = false
  const runtime = resolverRuntime(fixture, subject, '2030-01-01T00:10:01.500Z', {
    faultInjector(boundary, context) {
      if (!injected && boundary === 'after_resolver_atomic_append_before_response' && context.namespaceCode === 'd9.resolver.assessment-links.v1.1') {
        injected = true
        throw new Error('synthetic assessment-link response loss')
      }
    },
  })
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 })
  record.record_code = 'recovery.synthetic.link-loss.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /synthetic assessment-link response loss/)
  assert.equal(fixture.broker.head().sequence, 2)
  assert.equal(runtime.reconstruct().links.length, 1)
  const retry = await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(retry.created, false)
  assert.equal(runtime.reconstruct().links.length, 1)
})

test('restart repairs the exact assessment link when the D9.4 receipt is durable but link persistence never began', async (t) => {
  let injected = false
  const fixture = await createD941Fixture(t, {
    brokerFaultInjector(boundary, context) {
      if (!injected && boundary === 'after_receipt_persisted_before_response' && context.record.format === 'jedi-atlas-d940-recovery-assessment') {
        injected = true
        throw new Error('synthetic post-receipt crash')
      }
    },
  })
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.post-receipt.001'
  const operationNonce = '5'.repeat(64)
  const runtime = resolverRuntime(fixture, subject)
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 })
  record.record_code = 'recovery.synthetic.post-receipt.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /synthetic post-receipt crash/)
  assert.equal(fixture.broker.head().sequence, 2)
  assert.equal(runtime.reconstruct().links.length, 0)
  const resolverDigestBefore = fixture.resolverStore.inventory().digest
  fixture.resolverStore.close()
  const reopenedStore = createD941ResolverDurabilityStore({ rootPath: fixture.roots.resolver })
  t.after(() => reopenedStore.close())
  const restarted = resolverRuntime(fixture, subject, '2030-01-01T00:10:04.000Z', { durabilityStore: reopenedStore })
  const replayReconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: restarted, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const replayAssessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction: replayReconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(replayReconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  assert.deepEqual(replayAssessment, assessment)
  const replay = await fixture.broker.append({ record: replayAssessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(replay.created, false)
  assert.equal(fixture.broker.head().sequence, 2)
  assert.equal(restarted.reconstruct().links.length, 1)
  assert.notEqual(reopenedStore.inventory().digest, resolverDigestBefore)
})

test('authority revocation after the durable D9.4 receipt blocks missing-transition completion', async (t) => {
  let injected = false
  let trustedNow = '2030-01-01T00:10:01.500Z'
  const fixture = await createD941Fixture(t, {
    brokerFaultInjector(boundary, context) {
      if (!injected && boundary === 'after_receipt_persisted_before_response' && context.record.format === 'jedi-atlas-d940-recovery-assessment') {
        injected = true
        throw new Error('synthetic post-receipt revocation boundary')
      }
    },
  })
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.revoked-finalizer.001'
  const operationNonce = 'b'.repeat(64)
  const runtime = resolverRuntime(fixture, subject, undefined, { trustedClock: () => trustedNow })
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 })
  record.record_code = 'recovery.synthetic.revoked-finalizer.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /synthetic post-receipt revocation boundary/)
  assert.equal(fixture.broker.head().sequence, 2)
  assert.equal(runtime.reconstruct().transitions.length, 0)
  const resolverDigestBefore = fixture.resolverStore.inventory().digest
  const revoker = await fixture.launcher.authenticateAuthorityTransition({ roleCode: 'recovery_authority', bindingCode: fixture.byRole.get('recovery_operator').binding_code, at: '2030-01-01T00:10:02.000Z' })
  await fixture.registry.revoke({ targetCode: 'd940_authority_roster', actorSession: revoker, persistedAt: '2030-01-01T00:10:02.100Z' })
  const staleClock = fixture.createResolverClock(() => trustedNow)
  assert.throws(() => staleClock(), /D941_RESOLVER_TIME_ROLLBACK/)
  trustedNow = '2030-01-01T00:10:02.200Z'
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /D941_AUTHORITY_REVOKED/)
  assert.equal(fixture.resolverStore.inventory().digest, resolverDigestBefore)
  assert.equal(fixture.resolverStore.entries('d9.resolver.checkpoint-transitions.v1.2').length, 0)
})

test('durable progression-intent response loss retries without a D9.4 or checkpoint fork', async (t) => {
  let injected = false
  const fixture = await createD941Fixture(t); await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier'); const subject = subjectFor().subject
  const operationId = 'operation.recovery.intent-loss.001'; const operationNonce = '0'.repeat(64)
  const runtime = resolverRuntime(fixture, subject, undefined, { faultInjector(boundary, context) {
    if (!injected && boundary === 'after_progression_atomic_append_before_response' && context.namespaceCode === 'd9.resolver.progression-intents.v1.2' && context.payloadRecord.format.endsWith('append-request')) { injected = true; throw new Error('synthetic progression-intent response loss') }
  } })
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400); const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 }); record.record_code = 'recovery.synthetic.intent-loss.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /synthetic progression-intent response loss/)
  assert.equal(fixture.broker.head().sequence, 1)
  assert.equal(runtime.reconstruct().pendingProgressionRecords.length, 1)
  const replay = await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(replay.created, true)
  assert.equal(runtime.reconstruct().transitions.length, 1)
  assert.equal(runtime.reconstruct().pendingProgressionRecords.length, 0)
})

test('progression stable-identity collisions fail before any protected mutation', async (t) => {
  let injected = false
  const fixture = await createD941Fixture(t); await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier'); const subject = subjectFor().subject
  const operationId = 'operation.recovery.identity-collision.001'; const operationNonce = 'a'.repeat(64)
  const runtime = resolverRuntime(fixture, subject, undefined, { faultInjector(boundary, context) {
    if (!injected && boundary === 'after_progression_atomic_append_before_response' && context.payloadRecord.format.endsWith('append-request')) { injected = true; throw new Error('synthetic retained first intent') }
  } })
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400); const firstRecord = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 }); firstRecord.record_code = 'recovery.synthetic.identity-collision.001'; firstRecord.operation_id = operationId; firstRecord.operation_nonce = operationNonce
  const first = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: firstRecord, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: first, semanticSession: verifier, persistenceSession: journal }), /synthetic retained first intent/)
  const before = fixture.resolverStore.inventory().digest
  const changedRecord = { ...firstRecord, record_code: 'recovery.synthetic.identity-collision.changed' }
  const changed = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record: changedRecord, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: changed, semanticSession: verifier, persistenceSession: journal }), /D941_RESOLVER_PROGRESSION_REPLAY_COLLISION/)
  assert.equal(fixture.resolverStore.inventory().digest, before)
  assert.equal(fixture.broker.head().sequence, 1)
})

test('durable broker-receipt response loss restarts and completes the one exact v1.2 transition', async (t) => {
  let injected = false
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.broker-loss.001'; const operationNonce = '1'.repeat(64)
  const runtime = resolverRuntime(fixture, subject, undefined, { faultInjector(boundary, context) {
    if (!injected && boundary === 'after_progression_atomic_append_before_response' && context.namespaceCode === 'd9.resolver.progression-intents.v1.2' && context.payloadRecord.format === 'jedi-atlas-recovery-checkpoint-assessment-append-broker-receipt') { injected = true; throw new Error('synthetic broker-receipt response loss') }
  } })
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 }); record.record_code = 'recovery.synthetic.broker-loss.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /synthetic broker-receipt response loss/)
  assert.equal(runtime.reconstruct().transitions.length, 0)
  assert.equal(runtime.reconstruct().pendingProgressionRecords.length, 2)
  const replay = await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(replay.created, false)
  assert.equal(runtime.reconstruct().transitions.length, 1)
  assert.equal(runtime.reconstruct().pendingProgressionRecords.length, 0)
})

test('durable transition response loss is an exact replay and cannot fork checkpoint progression', async (t) => {
  let injected = false
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.transition-loss.001'; const operationNonce = '2'.repeat(64)
  const runtime = resolverRuntime(fixture, subject, undefined, { faultInjector(boundary, context) {
    if (!injected && boundary === 'after_progression_atomic_append_before_response' && context.namespaceCode === 'd9.resolver.checkpoint-transitions.v1.2') { injected = true; throw new Error('synthetic transition response loss') }
  } })
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 }); record.record_code = 'recovery.synthetic.transition-loss.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /synthetic transition response loss/)
  assert.equal(runtime.reconstruct().transitions.length, 1)
  const transitionDigest = runtime.reconstruct().transitions[0].transition.record_digest_sha256
  const replay = await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(replay.created, false)
  assert.equal(runtime.reconstruct().transitions.length, 1)
  assert.equal(runtime.reconstruct().transitions[0].transition.record_digest_sha256, transitionDigest)
})

test('an unrelated append before missing-transition completion fails closed as reconciliation required', async (t) => {
  let injected = false
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.extra-append.001'; const operationNonce = '3'.repeat(64)
  const runtime = resolverRuntime(fixture, subject, undefined, { faultInjector(boundary, context) {
    if (!injected && boundary === 'after_progression_atomic_append_before_response' && context.namespaceCode === 'd9.resolver.progression-intents.v1.2' && context.payloadRecord.format.endsWith('broker-receipt')) { injected = true; throw new Error('synthetic pre-transition stop') }
  } })
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 }); record.record_code = 'recovery.synthetic.extra-append.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /synthetic pre-transition stop/)
  const movementActor = await humanSession(fixture, 'security_authority', 'recovery_operator')
  const movementJournal = await serviceSession(fixture, 'control_submission', 'journal_broker')
  const movedAt = fixture.time.reserve()
  const movement = makeControlRecord({ fixture, kind: 'restriction_imposed', code: 'control.recovery.extra.001', operationId: 'operation.recovery.extra.control', nonce: '4'.repeat(64), subject: subjectFor(Buffer.from('extra append\n')).subject, semanticActor: movementActor.actor, persistenceActor: movementJournal.actor, sequence: 1, effectiveAt: new Date(Date.parse(movedAt) - 2).toISOString(), recordedAt: new Date(Date.parse(movedAt) - 1).toISOString(), persistedAt: movedAt })
  await fixture.broker.append({ record: movement, semanticSession: movementActor, persistenceSession: movementJournal })
  await assert.rejects(fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal }), /D941_RESOLVER_PROGRESSION_RECONCILIATION_REQUIRED/)
  assert.equal(runtime.reconstruct().transitions.length, 0)
})

test('concurrent exact assessment submissions serialize to one D9.4 receipt and one v1.2 transition', async (t) => {
  const fixture = await createD941Fixture(t); await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier'); const subject = subjectFor().subject
  const operationId = 'operation.recovery.concurrent.001'; const operationNonce = '5'.repeat(64); const runtime = resolverRuntime(fixture, subject)
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400); const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 }); record.record_code = 'recovery.synthetic.concurrent.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  const concurrent = await Promise.allSettled([1, 2].map(() => fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })))
  assert.equal(concurrent.filter((item) => item.status === 'fulfilled').length, 1)
  assert.match(concurrent.find((item) => item.status === 'rejected').reason.message, /OPERATION_LOCK_UNAVAILABLE/)
  const replay = await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(replay.created, false)
  assert.equal(runtime.reconstruct().transitions.length, 1)
  assert.equal(fixture.broker.validate().filter((item) => item.target_record_digest_sha256 === assessment.record_digest_sha256).length, 1)
})

test('restart fails closed when protected checkpoint bytes are corrupted', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const subject = subjectFor().subject
  resolverRuntime(fixture, subject)
  fixture.resolverStore.close()
  const checkpointFile = path.join(fixture.roots.resolver, 'd9.resolver.checkpoints.v1.1', 'append-000000000001')
  fs.writeFileSync(checkpointFile, Buffer.from('{}', 'utf8'))
  const reopenedStore = createD941ResolverDurabilityStore({ rootPath: fixture.roots.resolver })
  t.after(() => reopenedStore.close())
  assert.throws(() => resolverRuntime(fixture, subject, '2030-01-01T00:10:02.000Z', { durabilityStore: reopenedStore }), /D941_RESOLVER_DURABLE_COMMIT_INVALID/)
})

test('restart rejects resealed v1.2 transition, receipt, and source-head substitutions', async (t) => {
  const fixture = await createD941Fixture(t); await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier'); const subject = subjectFor().subject
  const operationId = 'operation.recovery.progression-tamper.001'; const operationNonce = '6'.repeat(64); const runtime = resolverRuntime(fixture, subject)
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400); const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 }); record.record_code = 'recovery.synthetic.progression-tamper.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  fixture.resolverStore.close()
  const transitionFile = path.join(fixture.roots.resolver, 'd9.resolver.checkpoint-transitions.v1.2', 'append-000000000001')
  const original = fs.readFileSync(transitionFile)
  const assertRestartRejects = (mutate, pattern) => {
    const envelope = JSON.parse(original.toString('utf8')); mutate(envelope)
    envelope.commit_sha256 = canonicalSha256(envelope, { excludedTopLevelField: 'commit_sha256' }); fs.writeFileSync(transitionFile, canonicalize(envelope))
    const reopened = createD941ResolverDurabilityStore({ rootPath: fixture.roots.resolver })
    assert.throws(() => resolverRuntime(fixture, subject, '2030-01-01T00:10:04.000Z', { durabilityStore: reopened }), pattern)
    reopened.close(); fs.writeFileSync(transitionFile, original)
  }
  assertRestartRejects((envelope) => {
    envelope.append_receipt.source_head_compare_and_append.observed_head_at_persist.head_digest_sha256 = 'f'.repeat(64)
    resealRecord(envelope.append_receipt)
  }, /D941_RESOLVER_PROGRESSION_SOURCE_CAS_INVALID/)
  assertRestartRejects((envelope) => {
    const transition = envelope.records[0]; transition.predecessor_checkpoint_record_digest_sha256 = 'f'.repeat(64); resealRecord(transition)
    envelope.append_receipt.persisted_head.record_digest_sha256 = transition.record_digest_sha256; envelope.append_receipt.payload_record_digest_sha256 = transition.record_digest_sha256; resealRecord(envelope.append_receipt)
  }, /D941_RESOLVER_PROGRESSION_TRANSITION_INVALID/)
  assertRestartRejects((envelope) => {
    const transition = envelope.records[0]; transition.component_resolution_attestations[0].component_response_record_digest_sha256 = 'f'.repeat(64); resealRecord(transition)
    envelope.append_receipt.persisted_head.record_digest_sha256 = transition.record_digest_sha256; envelope.append_receipt.payload_record_digest_sha256 = transition.record_digest_sha256; resealRecord(envelope.append_receipt)
  }, /D941_RESOLVER_PROGRESSION_TRANSITION_INVALID/)
})

test('restart rejects a self-consistent circular D9.4 post-head substitution', async (t) => {
  const fixture = await createD941Fixture(t); await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier'); const subject = subjectFor().subject
  const operationId = 'operation.recovery.circular-head.001'; const operationNonce = 'c'.repeat(64); const runtime = resolverRuntime(fixture, subject)
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1400); const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 }); record.record_code = 'recovery.synthetic.circular-head.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  fixture.resolverStore.close()

  const fabricatedInventory = 'f'.repeat(64)
  const brokerFile = path.join(fixture.roots.resolver, 'd9.resolver.progression-intents.v1.2', 'append-000000000002')
  const brokerEnvelope = JSON.parse(fs.readFileSync(brokerFile, 'utf8'))
  const brokerRecord = brokerEnvelope.records[0]
  brokerRecord.post_append_source_head.inventory_digest_sha256 = fabricatedInventory
  resealRecord(brokerRecord)
  brokerEnvelope.append_receipt.persisted_head.record_digest_sha256 = brokerRecord.record_digest_sha256
  brokerEnvelope.append_receipt.payload_record_digest_sha256 = brokerRecord.record_digest_sha256
  resealRecord(brokerEnvelope.append_receipt)
  brokerEnvelope.commit_sha256 = canonicalSha256(brokerEnvelope, { excludedTopLevelField: 'commit_sha256' })
  fs.writeFileSync(brokerFile, canonicalize(brokerEnvelope))

  const transitionFile = path.join(fixture.roots.resolver, 'd9.resolver.checkpoint-transitions.v1.2', 'append-000000000001')
  const transitionEnvelope = JSON.parse(fs.readFileSync(transitionFile, 'utf8'))
  const transition = transitionEnvelope.records[0]
  transition.append_broker_receipt_record_digest_sha256 = brokerRecord.record_digest_sha256
  transition.append_broker_receipt_protected_receipt_record_digest_sha256 = brokerEnvelope.append_receipt.record_digest_sha256
  const postHead = transition.post_append_source_heads.find((item) => item.source_namespace_code === 'd940.global.control-journal.v1')
  postHead.inventory_digest_sha256 = fabricatedInventory
  transition.permitted_d940_delta.after.inventory_digest_sha256 = fabricatedInventory
  transition.post_append_source_heads_digest_sha256 = canonicalSha256(transition.post_append_source_heads)
  resealRecord(transition)
  transitionEnvelope.append_receipt.persisted_head.record_digest_sha256 = transition.record_digest_sha256
  transitionEnvelope.append_receipt.payload_record_digest_sha256 = transition.record_digest_sha256
  transitionEnvelope.append_receipt.source_head_compare_and_append.expected_head.inventory_digest_sha256 = fabricatedInventory
  transitionEnvelope.append_receipt.source_head_compare_and_append.observed_head_at_persist.inventory_digest_sha256 = fabricatedInventory
  resealRecord(transitionEnvelope.append_receipt)
  transitionEnvelope.commit_sha256 = canonicalSha256(transitionEnvelope, { excludedTopLevelField: 'commit_sha256' })
  fs.writeFileSync(transitionFile, canonicalize(transitionEnvelope))

  const reopenedStore = createD941ResolverDurabilityStore({ rootPath: fixture.roots.resolver })
  t.after(() => reopenedStore.close())
  assert.throws(() => resolverRuntime(fixture, subject, '2030-01-01T00:10:04.000Z', { durabilityStore: reopenedStore }), /D941_RESOLVER_PROGRESSION_BROKER_RECEIPT_INVALID/)
})

test('restart rejects semantically identical resolver envelopes whose retained bytes are not canonical', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const subject = subjectFor().subject
  resolverRuntime(fixture, subject)
  fixture.resolverStore.close()
  const checkpointFile = path.join(fixture.roots.resolver, 'd9.resolver.checkpoints.v1.1', 'append-000000000001')
  const envelope = JSON.parse(fs.readFileSync(checkpointFile, 'utf8'))
  fs.writeFileSync(checkpointFile, `${JSON.stringify(envelope, null, 2)}\n`)
  const reopenedStore = createD941ResolverDurabilityStore({ rootPath: fixture.roots.resolver })
  t.after(() => reopenedStore.close())
  assert.throws(() => resolverRuntime(fixture, subject, '2030-01-01T00:10:02.000Z', { durabilityStore: reopenedStore }), /exact canonical UTF-8 representation/)
})

test('restart rejects a schema-valid, fully resealed resolver payload with a substituted route recipient', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const subject = subjectFor().subject
  let injected = false
  const runtime = resolverRuntime(fixture, subject, '2030-01-01T00:10:01.500Z', {
    faultInjector(boundary, context) {
      if (!injected && boundary === 'after_resolver_atomic_append_before_response' && context.namespaceCode === 'd9.resolver.records.v1.1' && context.payloadRecord.record_kind_code === 'response') {
        injected = true
        throw new Error('synthetic route-mutation setup')
      }
    },
  })
  assert.throws(() => runtime.resolveComposite({ subject: { subject_kind_code: subject.subject_kind_code, subject_identity_sha256: subject.subject_identity_sha256 }, operationId: 'operation.recovery.route-mutation.001', operationNonce: '4'.repeat(64) }), /synthetic route-mutation setup/)
  fixture.resolverStore.close()
  const responseFile = path.join(fixture.roots.resolver, 'd9.resolver.records.v1.1', 'append-000000000002')
  const envelope = JSON.parse(fs.readFileSync(responseFile, 'utf8'))
  const wrapper = envelope.records[0]
  const payload = JSON.parse(wrapper.payload_canonical_utf8)
  const substituted = fixture.byRole.get('journal_broker')
  payload.recipient = { runtime_role_code: 'journal_broker', binding_code: substituted.binding_code, endpoint_code: substituted.ipc_endpoint_code, executable_build_sha256: substituted.executable_sha256 }
  resealRecord(payload)
  wrapper.payload_canonical_utf8 = canonicalize(payload)
  wrapper.payload_record_digest_sha256 = payload.record_digest_sha256
  wrapper.response_record_digest_sha256 = payload.record_digest_sha256
  resealRecord(wrapper)
  envelope.append_receipt.persisted_head.record_digest_sha256 = wrapper.record_digest_sha256
  envelope.append_receipt.payload_record_digest_sha256 = wrapper.record_digest_sha256
  resealRecord(envelope.append_receipt)
  envelope.commit_sha256 = canonicalSha256(envelope, { excludedTopLevelField: 'commit_sha256' })
  fs.writeFileSync(responseFile, canonicalize(envelope))
  const reopenedStore = createD941ResolverDurabilityStore({ rootPath: fixture.roots.resolver })
  t.after(() => reopenedStore.close())
  assert.throws(() => resolverRuntime(fixture, subject, '2030-01-01T00:10:02.000Z', { durabilityStore: reopenedStore }), /D941_RESOLVER_DURABLE_ROUTE_INVALID/)
})
