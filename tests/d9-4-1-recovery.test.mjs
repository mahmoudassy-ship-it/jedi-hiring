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
  return createD941SyntheticRecoveryResolverRuntime({ authorityContext: fixture.authorityContext, authorityRegistry: fixture.registry, broker: fixture.broker, subject, custodyEvidence: custodyEvidenceForSubject(fixture, subject), trustedClock: trustedClock ?? defaultClock, durabilityStore, persistenceSession: fixture.resolverPersistenceSession, faultInjector })
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
  const persistedAt = fixture.time.reserve(1500)
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
  assert.throws(() => resolverRuntime(fixture, subject, '2099-01-01T00:00:00.000Z').resolveComposite({ subject: resolverSubject, operationId: 'operation.recovery.expired', operationNonce: 'c'.repeat(64) }), /D941_RESOLVER_IDENTITY_UNAVAILABLE/)
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

test('v1.1 durable wrappers, checkpoint advance, assessment link, restart reconstruction, and exact replay are closed and deterministic', async (t) => {
  const fixture = await createD941Fixture(t)
  await primeProtectedHead(fixture)
  const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const subject = subjectFor().subject
  const operationId = 'operation.recovery.durable.001'
  const operationNonce = '9'.repeat(64)
  const runtime = resolverRuntime(fixture, subject)
  const reconstruction = reconstructD941RecoveryState({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, subjectKindCode: subject.subject_kind_code, resolverRuntime: runtime, resolverOperationId: operationId, resolverOperationNonce: operationNonce })
  const persistedAt = fixture.time.reserve(1500)
  const record = baseRecord(subject, verifier.actor, journal.actor, { persistedAt, receiptSequence: fixture.broker.head().sequence + 1 })
  record.record_code = 'recovery.synthetic.durable.001'; record.operation_id = operationId; record.operation_nonce = operationNonce
  const assessment = classifyD941Recovery({ authorityContext: fixture.authorityContext, broker: fixture.broker, record, reconstruction, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(reconstruction), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  const appended = await fixture.broker.append({ record: assessment, semanticSession: verifier, persistenceSession: journal })
  assert.equal(appended.created, true)
  const beforeRestart = runtime.reconstruct()
  assert.deepEqual(beforeRestart.durableRecords.map((item) => item.wrapper.record_kind_code), ['request', 'response', 'append_attestation'])
  assert.equal(beforeRestart.checkpoints.length, 2)
  assert.equal(beforeRestart.checkpoints[1].checkpoint_kind_code, 'advance')
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
  assert.throws(() => restarted.resolveComposite({ subject: { subject_kind_code: subject.subject_kind_code, subject_identity_sha256: subject.subject_identity_sha256 }, operationId: 'operation.recovery.durable.002', operationNonce: '7'.repeat(64) }), /D941_RESOLVER_CHECKPOINT_SOURCE_MISMATCH/)
  assert.equal(reopenedStore.entries('d9.resolver.records.v1.1').length, 3)
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
  assert.equal(reopenedStore.entries('d9.resolver.records.v1.1').length, 2)
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
  const persistedAt = fixture.time.reserve(1500)
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
  const persistedAt = fixture.time.reserve(1500)
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
