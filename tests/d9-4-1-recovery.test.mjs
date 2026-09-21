import assert from 'node:assert/strict'
import { test } from 'node:test'

import { classifyD941Recovery, reconstructD941RecoveryState } from '../d9/restriction/recovery.mjs'
import { createD941Fixture, serviceSession, subjectFor } from './d9-4-1-support/fixture.mjs'

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

test('restart reconstruction reads protected facts and remains classification-only', async (t) => {
  const fixture = await createD941Fixture(t)
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

function snapshot() {
  return { journal_namespace_code: 'd940.global.control-journal.v1', known_through_receipt_sequence: 1, known_through_persisted_at: '2030-01-01T00:10:03.000Z', control_ledger_head_receipt_digest_sha256: '1'.repeat(64), control_head_projection_sha256: '2'.repeat(64), access_head_projection_sha256: '3'.repeat(64), subject_lineage_projection_sha256: '4'.repeat(64), inventory_snapshot_sha256: '5'.repeat(64), custody_leaf_projection_sha256: '6'.repeat(64) }
}

for (const [boundary, classification] of Object.entries(expected)) {
  test(`recovery boundary ${boundary} is classification-only`, async (t) => {
    const fixture = await createD941Fixture(t)
    const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker')
    const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
    const record = classifyD941Recovery({ authorityContext: fixture.authorityContext, record: baseRecord(subjectFor().subject, verifier.actor, journal.actor), crashBoundaryCode: boundary, snapshot: snapshot(), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
    assert.equal(record.classification_code, classification)
    assert.equal(record.action_execution_code, 'none_classification_only')
    assert.equal(record.recovery_authority_present, false)
  })
}

test('unknown, contradictory, incomplete, and forked state overrides optimistic boundary defaults', async (t) => {
  const fixture = await createD941Fixture(t); const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier'); const record = baseRecord(subjectFor().subject, verifier.actor, journal.actor)
  const fork = classifyD941Recovery({ authorityContext: fixture.authorityContext, record, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'fork' })
  assert.equal(fork.classification_code, 'human_decision_required')
  const unknown = classifyD941Recovery({ authorityContext: fixture.authorityContext, record: { ...record, record_code: 'recovery.synthetic.002' }, crashBoundaryCode: 'before_restriction_persisted', snapshot: snapshot(), inventoryStateCode: 'unavailable', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' })
  assert.equal(unknown.classification_code, 'reconciliation_required')
})

test('D9.5 execution and complete-erasure outcomes remain structurally unreachable', async (t) => {
  const fixture = await createD941Fixture(t); const journal = await serviceSession(fixture, 'recovery_classification', 'journal_broker'); const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  assert.throws(() => classifyD941Recovery({ authorityContext: fixture.authorityContext, record: baseRecord(subjectFor().subject, verifier.actor, journal.actor), crashBoundaryCode: 'd9_5_restore', snapshot: snapshot(), inventoryStateCode: 'complete', accessStateCode: 'none_confirmed', controlStateCode: 'linear_complete' }), /D941_RECOVERY_BOUNDARY_UNKNOWN/)
})
