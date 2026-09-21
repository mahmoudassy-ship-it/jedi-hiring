import assert from 'node:assert/strict'
import { test } from 'node:test'

import * as recoveryApi from '../d9/restriction/recovery.mjs'
import { classifyD941Recovery, reconstructD941RecoveryState } from '../d9/restriction/recovery.mjs'
import { createD941Fixture, humanSession, makeControlRecord, serviceSession, subjectFor } from './d9-4-1-support/fixture.mjs'

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

function baseRecord(subject, semanticActor, persistenceActor) {
  return {
    format: 'jedi-atlas-d940-recovery-assessment', format_version: '1.0.0', record_code: 'recovery.synthetic.001',
    operation_id: 'operation.recovery.001', operation_nonce: 'e'.repeat(64), subject,
    semantic_actor: semanticActor, persistence_actor: persistenceActor,
    knowledge_boundary: { effective_at: '2030-01-01T00:10:01.000Z', recorded_at: '2030-01-01T00:10:02.000Z', persisted_at: '2030-01-01T00:10:03.000Z', journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: 1 },
    record_digest_sha256: null,
  }
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
