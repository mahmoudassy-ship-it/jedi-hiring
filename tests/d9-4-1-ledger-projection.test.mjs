import assert from 'node:assert/strict'
import { test } from 'node:test'

import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import { createD941LedgerBroker } from '../d9/restriction/ledger.mjs'
import { projectD941Subject } from '../d9/restriction/projection.mjs'
import { controlApprovalScope, createD941Fixture, humanSession, makeAccessRecord, makeApproval, makeControlRecord, replaceApprovals, serviceSession, subjectFor } from './d9-4-1-support/fixture.mjs'

const nonce = (digit) => digit.repeat(64)

async function sessions(fixture) {
  return {
    journal: await serviceSession(fixture, 'control_submission', 'journal_broker'),
    security: await humanSession(fixture, 'security_authority', 'recovery_operator'),
    requester: await humanSession(fixture, 'requester', 'human_submitter'),
    deletion: await humanSession(fixture, 'deletion_authority', 'bootstrap_authority'),
    deletionApprover: await humanSession(fixture, 'deletion_authority', 'recovery_authority'),
    records: await humanSession(fixture, 'legal_records_authority', 'clearance_checker'),
    privacy: await humanSession(fixture, 'privacy_authority', 'clearance_decider'),
    clearance: await humanSession(fixture, 'clearance_authority', 'clearance_decider'),
  }
}

function control(fixture, input) {
  const persistedAt = fixture.time.reserve()
  return makeControlRecord({ fixture, effectiveAt: new Date(Date.parse(persistedAt) - 2).toISOString(), recordedAt: new Date(Date.parse(persistedAt) - 1).toISOString(), persistedAt, ...input })
}

test('protected broker persists a gapless global receipt and exact replay is a no-op', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const { subject } = subjectFor()
  const record = control(fixture, { kind: 'restriction_imposed', code: 'control.restrict.001', operationId: 'operation.restrict.001', nonce: nonce('1'), subject, semanticActor: actors.security.actor, persistenceActor: actors.journal.actor, sequence: 1 })
  const first = await fixture.broker.append({ record, semanticSession: actors.security, persistenceSession: actors.journal })
  const replay = await fixture.broker.append({ record, semanticSession: actors.security, persistenceSession: actors.journal })
  assert.equal(first.created, true); assert.equal(replay.created, false); assert.equal(fixture.broker.head().sequence, 1)
})

test('ledger rejects chain gaps, backdating, nonce collision and actor substitution', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const { subject } = subjectFor()
  const first = control(fixture, { kind: 'restriction_imposed', code: 'control.restrict.001', operationId: 'operation.restrict.001', nonce: nonce('1'), subject, semanticActor: actors.security.actor, persistenceActor: actors.journal.actor, sequence: 1 })
  await fixture.broker.append({ record: first, semanticSession: actors.security, persistenceSession: actors.journal })
  let badChain = control(fixture, { kind: 'restriction_released', code: 'control.release.001', operationId: 'operation.restrict.001', nonce: nonce('1'), subject, semanticActor: actors.clearance.actor, persistenceActor: actors.journal.actor, sequence: 3, predecessor: first.record_digest_sha256, basis: first.record_digest_sha256, approvals: [] })
  const approval = makeApproval({ code: 'approval.release.001', actor: actors.security.actor, scopeSha256: controlApprovalScope(badChain), decidedAt: badChain.knowledge_boundary.recorded_at, expiresAt: '2030-01-01T00:30:00.000Z' })
  badChain = replaceApprovals(badChain, [approval])
  await assert.rejects(fixture.broker.append({ record: badChain, semanticSession: actors.clearance, persistenceSession: actors.journal, approvalSessions: [actors.security] }), /D941_TARGET_CHAIN_INVALID/)
  const wrongActor = structuredClone(badChain); wrongActor.semantic_actor = actors.requester.actor
  wrongActor.record_digest_sha256 = canonicalSha256(wrongActor, { excludedTopLevelField: 'record_digest_sha256' })
  await assert.rejects(fixture.broker.append({ record: wrongActor, semanticSession: actors.security, persistenceSession: actors.journal, approvalSessions: [actors.security] }), /D941_(ACTOR_SESSION_MISMATCH|SEMANTIC_ACTOR_FORBIDDEN)/)
})

test('personal-data deletion authorization requires three distinct eligible humans', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const { subject } = subjectFor()
  const request = control(fixture, { kind: 'deletion_requested', code: 'control.request.001', operationId: 'operation.delete.001', nonce: nonce('2'), subject, semanticActor: actors.requester.actor, persistenceActor: actors.journal.actor, sequence: 1, reason: 'personal_data' })
  await fixture.broker.append({ record: request, semanticSession: actors.requester, persistenceSession: actors.journal })
  const authorization = {
    deletion_request_record_digest_sha256: request.record_digest_sha256, requester_principal_code: actors.requester.actor.principal_code,
    subject_identity_sha256: subject.subject_identity_sha256, operation_id: request.operation_id, operation_nonce: request.operation_nonce,
    reason_category_code: 'personal_data', requested_action_code: 'delete_approved_primary_copy_only',
    d930_operational_profile_record_digest_sha256: 'a'.repeat(64), d930_primary_durability_receipt_sha256: 'b'.repeat(64),
    custody_leaf_projection_sha256: 'c'.repeat(64), control_head_projection_sha256: 'd'.repeat(64), access_head_projection_sha256: 'e'.repeat(64), subject_lineage_projection_sha256: 'f'.repeat(64),
    valid_from: '2030-01-01T00:10:00.000Z', valid_until: '2030-01-01T00:30:00.000Z',
  }
  const scope = canonicalSha256(authorization)
  const approvals = [
    makeApproval({ code: 'approval.records.001', actor: actors.records.actor, scopeSha256: scope, decidedAt: '2030-01-01T00:10:01.999Z', expiresAt: authorization.valid_until }),
    makeApproval({ code: 'approval.privacy.001', actor: actors.privacy.actor, scopeSha256: scope, decidedAt: '2030-01-01T00:10:01.999Z', expiresAt: authorization.valid_until }),
    makeApproval({ code: 'approval.deletion.001', actor: actors.deletionApprover.actor, scopeSha256: scope, decidedAt: '2030-01-01T00:10:01.999Z', expiresAt: authorization.valid_until }),
  ]
  const approved = control(fixture, { kind: 'deletion_authorized', code: 'control.authorize.001', operationId: request.operation_id, nonce: request.operation_nonce, subject, semanticActor: actors.deletion.actor, persistenceActor: actors.journal.actor, sequence: 2, predecessor: request.record_digest_sha256, reason: 'personal_data', approvals, basis: request.record_digest_sha256, authorization })
  const result = await fixture.broker.append({ record: approved, semanticSession: actors.deletion, persistenceSession: actors.journal, approvalSessions: [actors.records, actors.privacy, actors.deletionApprover] })
  assert.equal(result.created, true)
})

test('self approval, repeated humans and insufficient approval count fail closed', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const { subject } = subjectFor()
  const request = control(fixture, { kind: 'deletion_requested', code: 'control.request.002', operationId: 'operation.delete.002', nonce: nonce('3'), subject, semanticActor: actors.requester.actor, persistenceActor: actors.journal.actor, sequence: 1, reason: 'personal_data' })
  await fixture.broker.append({ record: request, semanticSession: actors.requester, persistenceSession: actors.journal })
  const authorization = { deletion_request_record_digest_sha256: request.record_digest_sha256, requester_principal_code: actors.requester.actor.principal_code, subject_identity_sha256: subject.subject_identity_sha256, operation_id: request.operation_id, operation_nonce: request.operation_nonce, reason_category_code: 'personal_data', requested_action_code: 'delete_approved_primary_copy_only', d930_operational_profile_record_digest_sha256: 'a'.repeat(64), d930_primary_durability_receipt_sha256: 'b'.repeat(64), custody_leaf_projection_sha256: 'c'.repeat(64), control_head_projection_sha256: 'd'.repeat(64), access_head_projection_sha256: 'e'.repeat(64), subject_lineage_projection_sha256: 'f'.repeat(64), valid_from: '2030-01-01T00:10:00.000Z', valid_until: '2030-01-01T00:30:00.000Z' }
  const scope = canonicalSha256(authorization)
  const approval = makeApproval({ code: 'approval.records.002', actor: actors.records.actor, scopeSha256: scope, decidedAt: '2030-01-01T00:10:01.000Z', expiresAt: authorization.valid_until })
  const record = control(fixture, { kind: 'deletion_authorized', code: 'control.authorize.002', operationId: authorization.operation_id, nonce: authorization.operation_nonce, subject, semanticActor: actors.deletion.actor, persistenceActor: actors.journal.actor, sequence: 2, predecessor: request.record_digest_sha256, reason: 'personal_data', approvals: [approval], basis: request.record_digest_sha256, authorization })
  await assert.rejects(fixture.broker.append({ record, semanticSession: actors.deletion, persistenceSession: actors.journal, approvalSessions: [actors.records] }), /D941_APPROVAL_(COUNT_INSUFFICIENT|ROLE_MISSING|INVALID)/)
  const repeated = structuredClone(replaceApprovals(record, [approval, approval, approval]))
  repeated.record_code = 'control.authorize.002.repeated'
  repeated.record_digest_sha256 = canonicalSha256(repeated, { excludedTopLevelField: 'record_digest_sha256' })
  await assert.rejects(fixture.broker.append({ record: repeated, semanticSession: actors.deletion, persistenceSession: actors.journal, approvalSessions: [actors.records, actors.records, actors.records] }), /D941_APPROVAL_(NOT_DISTINCT|INVALID)/)
})

test('non-control records enforce the frozen semantic actor matrix', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const { subject } = subjectFor()
  const record = makeAccessRecord({ fixture, kind: 'capability_revoked', code: 'access.wrong-role.001', operationId: 'operation.access.wrong-role.001', nonce: nonce('6'), subject, semanticActor: actors.requester.actor, persistenceActor: actors.journal.actor, sequence: 1, targetKind: 'unconsumed_capability', triggerDigest: '1'.repeat(64) })
  await assert.rejects(fixture.broker.append({ record, semanticSession: actors.requester, persistenceSession: actors.journal }), /D941_ACCESS_MATRIX_REJECTED/)
})

test('historical bounded projection preserves prior restriction state', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const { subject } = subjectFor()
  const imposed = control(fixture, { kind: 'restriction_imposed', code: 'control.restrict.003', operationId: 'operation.restrict.003', nonce: nonce('4'), subject, semanticActor: actors.security.actor, persistenceActor: actors.journal.actor, sequence: 1 })
  await fixture.broker.append({ record: imposed, semanticSession: actors.security, persistenceSession: actors.journal })
  const firstHead = fixture.broker.head()
  let released = control(fixture, { kind: 'restriction_released', code: 'control.release.003', operationId: imposed.operation_id, nonce: imposed.operation_nonce, subject, semanticActor: actors.clearance.actor, persistenceActor: actors.journal.actor, sequence: 2, predecessor: imposed.record_digest_sha256, basis: imposed.record_digest_sha256, approvals: [] })
  const approval = makeApproval({ code: 'approval.release.003', actor: actors.security.actor, scopeSha256: controlApprovalScope(released), decidedAt: released.knowledge_boundary.recorded_at, expiresAt: '2030-01-01T00:30:00.000Z' })
  released = replaceApprovals(released, [approval])
  await fixture.broker.append({ record: released, semanticSession: actors.clearance, persistenceSession: actors.journal, approvalSessions: [actors.security] })
  const prior = projectD941Subject({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, effectiveAsOf: firstHead.persistedAt, knownAt: firstHead.persistedAt, knownThroughSequence: firstHead.sequence })
  const current = projectD941Subject({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, effectiveAsOf: fixture.broker.head().persistedAt, knownAt: fixture.broker.head().persistedAt, knownThroughSequence: fixture.broker.head().sequence })
  assert.equal(prior.active_restriction, true); assert.equal(current.active_restriction, false)
})

test('operation-scoped deletion projections retain subject-wide holds from other operations', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const { subject } = subjectFor()
  let hold = control(fixture, { kind: 'hold_imposed', code: 'control.hold.other-operation.001', operationId: 'operation.other.001', nonce: nonce('8'), subject, semanticActor: actors.security.actor, persistenceActor: actors.journal.actor, sequence: 1, reason: 'security_incident' })
  hold = replaceApprovals(hold, [makeApproval({ code: 'approval.hold.other-operation.001', actor: actors.records.actor, scopeSha256: controlApprovalScope(hold), decidedAt: hold.knowledge_boundary.recorded_at, expiresAt: '2030-01-01T00:30:00.000Z' })])
  await fixture.broker.append({ record: hold, semanticSession: actors.security, persistenceSession: actors.journal, approvalSessions: [actors.records] })
  let secondHold = control(fixture, { kind: 'hold_imposed', code: 'control.hold.second-operation.001', operationId: 'operation.second.001', nonce: nonce('9'), subject, semanticActor: actors.security.actor, persistenceActor: actors.journal.actor, sequence: 1, reason: 'security_incident' })
  secondHold = replaceApprovals(secondHold, [makeApproval({ code: 'approval.hold.second-operation.001', actor: actors.records.actor, scopeSha256: controlApprovalScope(secondHold), decidedAt: secondHold.knowledge_boundary.recorded_at, expiresAt: '2030-01-01T00:30:00.000Z' })])
  await fixture.broker.append({ record: secondHold, semanticSession: actors.security, persistenceSession: actors.journal, approvalSessions: [actors.records] })
  let release = control(fixture, { kind: 'hold_released', code: 'control.hold.second-operation.release.001', operationId: secondHold.operation_id, nonce: secondHold.operation_nonce, subject, semanticActor: actors.privacy.actor, persistenceActor: actors.journal.actor, sequence: 2, predecessor: secondHold.record_digest_sha256, basis: secondHold.record_digest_sha256, reason: 'security_incident' })
  release = replaceApprovals(release, [
    makeApproval({ code: 'approval.release.hold.legal.001', actor: actors.records.actor, scopeSha256: controlApprovalScope(release), decidedAt: release.knowledge_boundary.recorded_at, expiresAt: '2030-01-01T00:30:00.000Z' }),
    makeApproval({ code: 'approval.release.hold.security.001', actor: actors.security.actor, scopeSha256: controlApprovalScope(release), decidedAt: release.knowledge_boundary.recorded_at, expiresAt: '2030-01-01T00:30:00.000Z' }),
  ])
  await fixture.broker.append({ record: release, semanticSession: actors.privacy, persistenceSession: actors.journal, approvalSessions: [actors.records, actors.security] })
  const projection = projectD941Subject({ broker: fixture.broker, subjectIdentitySha256: subject.subject_identity_sha256, effectiveAsOf: fixture.broker.head().persistedAt, knownAt: fixture.broker.head().persistedAt, knownThroughSequence: fixture.broker.head().sequence, operationId: 'operation.delete.001', operationNonce: nonce('a') })
  assert.equal(projection.active_hold, true)
  assert.equal(projection.access_eligibility_code, 'withheld')
})

test('target persisted without receipt forces deterministic recovery-required state', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const { subject } = subjectFor()
  const broken = createD941LedgerBroker({ store: fixture.store, authorityContext: fixture.authorityContext, authorityRegistry: fixture.registry, clock: fixture.time.clock, linuxEnforcement: fixture.linux, operationLockRootPath: fixture.roots.lock, faultInjector(point) { if (point === 'after_target_persisted_before_receipt') throw new Error('synthetic crash') } })
  const record = control(fixture, { kind: 'restriction_imposed', code: 'control.crash.001', operationId: 'operation.crash.001', nonce: nonce('5'), subject, semanticActor: actors.security.actor, persistenceActor: actors.journal.actor, sequence: 1 })
  await assert.rejects(broken.append({ record, semanticSession: actors.security, persistenceSession: actors.journal }), /synthetic crash/)
  assert.throws(() => broken.head(), /D941_LEDGER_RECOVERY_REQUIRED/)
})

test('operation nonce claims are reconstructed from protected records after broker restart', async (t) => {
  const fixture = await createD941Fixture(t); const actors = await sessions(fixture); const firstSubject = subjectFor(Buffer.from('first synthetic subject\n')).subject
  const operationId = 'operation.restart-replay.001'; const operationNonce = nonce('7')
  const first = control(fixture, { kind: 'restriction_imposed', code: 'control.restart-replay.001', operationId, nonce: operationNonce, subject: firstSubject, semanticActor: actors.security.actor, persistenceActor: actors.journal.actor, sequence: 1 })
  await fixture.broker.append({ record: first, semanticSession: actors.security, persistenceSession: actors.journal })
  const restarted = createD941LedgerBroker({ store: fixture.store, authorityContext: fixture.authorityContext, authorityRegistry: fixture.registry, clock: fixture.time.clock, linuxEnforcement: fixture.linux, operationLockRootPath: fixture.roots.lock })
  const secondSubject = subjectFor(Buffer.from('second synthetic subject\n')).subject
  const collision = control(fixture, { kind: 'restriction_imposed', code: 'control.restart-replay.002', operationId, nonce: operationNonce, subject: secondSubject, semanticActor: actors.security.actor, persistenceActor: actors.journal.actor, sequence: 1 })
  await assert.rejects(restarted.append({ record: collision, semanticSession: actors.security, persistenceSession: actors.journal }), /D941_OPERATION_NONCE_COLLISION/)
})
