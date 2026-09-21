import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { test } from 'node:test'

import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import { executeSyntheticPrimaryDeletion, shutdownSyntheticAccess } from '../d9/restriction/operations.mjs'
import { createD941SyntheticAccessInventory } from '../d9/restriction/access-control.mjs'
import { projectD941Subject } from '../d9/restriction/projection.mjs'
import { sealD940Record } from '../d9/restriction/contracts.mjs'
import { createD941Fixture, custodyEvidenceForSubject, humanSession, makeAccessRecord, makeApproval, makeControlRecord, makeDeletionReceipt, makeExecutionRecord, prepareCas, serviceSession, subjectFor } from './d9-4-1-support/fixture.mjs'

const nonce = 'd'.repeat(64)

async function setupDeletion(t) {
  const fixture = await createD941Fixture(t)
  const journal = await serviceSession(fixture, 'control_submission', 'journal_broker')
  const executor = await serviceSession(fixture, 'deletion_execution', 'custody_adapter')
  const verifier = await serviceSession(fixture, 'independent_verification', 'independent_verifier')
  const custody = await serviceSession(fixture, 'capability_revocation', 'trusted_launcher')
  const launcher = await serviceSession(fixture, 'access_shutdown', 'trusted_launcher')
  const requester = await humanSession(fixture, 'requester', 'human_submitter')
  const deletion = await humanSession(fixture, 'deletion_authority', 'bootstrap_authority')
  const deletionApprover = await humanSession(fixture, 'deletion_authority', 'recovery_authority')
  const records = await humanSession(fixture, 'legal_records_authority', 'clearance_checker')
  const privacy = await humanSession(fixture, 'privacy_authority', 'clearance_decider')
  const subjectData = subjectFor(); prepareCas(fixture.roots.cas, subjectData.artifact, subjectData.bytes)
  const custodyEvidence = custodyEvidenceForSubject(fixture, subjectData.subject)
  const persist = () => fixture.time.reserve()
  const boundary = (persistedAt) => ({ effectiveAt: new Date(Date.parse(persistedAt) - 2).toISOString(), recordedAt: new Date(Date.parse(persistedAt) - 1).toISOString(), persistedAt })
  let time = boundary(persist())
  const request = makeControlRecord({ fixture, kind: 'deletion_requested', code: 'control.delete.request.001', operationId: 'operation.delete.001', nonce, subject: subjectData.subject, semanticActor: requester.actor, persistenceActor: journal.actor, sequence: 1, reason: 'personal_data', ...time })
  await fixture.broker.append({ record: request, semanticSession: requester, persistenceSession: journal })
  const authScope = { deletion_request_record_digest_sha256: request.record_digest_sha256, requester_principal_code: requester.actor.principal_code, subject_identity_sha256: subjectData.subject.subject_identity_sha256, operation_id: request.operation_id, operation_nonce: nonce, reason_category_code: 'personal_data', requested_action_code: 'delete_approved_primary_copy_only', d930_operational_profile_record_digest_sha256: custodyEvidence.d930OperationalProfileSha256, d930_primary_durability_receipt_sha256: custodyEvidence.d930PrimaryDurabilityReceiptSha256, custody_leaf_projection_sha256: custodyEvidence.custodyLeafProjectionSha256, control_head_projection_sha256: '8'.repeat(64), access_head_projection_sha256: '9'.repeat(64), subject_lineage_projection_sha256: custodyEvidence.subjectLineageProjectionSha256, valid_from: '2030-01-01T00:10:00.000Z', valid_until: '2030-01-01T00:30:00.000Z' }
  const authHash = canonicalSha256(authScope)
  const approvals = [makeApproval({ code: 'approval.records.delete.001', actor: records.actor, scopeSha256: authHash, decidedAt: '2030-01-01T00:10:01.999Z', expiresAt: authScope.valid_until }), makeApproval({ code: 'approval.privacy.delete.001', actor: privacy.actor, scopeSha256: authHash, decidedAt: '2030-01-01T00:10:01.999Z', expiresAt: authScope.valid_until }), makeApproval({ code: 'approval.deletion.delete.001', actor: deletionApprover.actor, scopeSha256: authHash, decidedAt: '2030-01-01T00:10:01.999Z', expiresAt: authScope.valid_until })]
  time = boundary(persist())
  const authorization = makeControlRecord({ fixture, kind: 'deletion_authorized', code: 'control.delete.authorized.001', operationId: request.operation_id, nonce, subject: subjectData.subject, semanticActor: deletion.actor, persistenceActor: journal.actor, sequence: 2, predecessor: request.record_digest_sha256, reason: 'personal_data', approvals, basis: request.record_digest_sha256, authorization: authScope, ...time })
  await fixture.broker.append({ record: authorization, semanticSession: deletion, persistenceSession: journal, approvalSessions: [records, privacy, deletionApprover] })
  time = boundary(persist())
  const tombstone = makeControlRecord({ fixture, kind: 'tombstone_applied', code: 'control.delete.tombstone.001', operationId: request.operation_id, nonce, subject: subjectData.subject, semanticActor: custody.actor, persistenceActor: journal.actor, sequence: 3, predecessor: authorization.record_digest_sha256, reason: 'personal_data', basis: authorization.record_digest_sha256, authorization: authScope, ...time })
  await fixture.broker.append({ record: tombstone, semanticSession: custody, persistenceSession: journal })
  const capability = makeAccessRecord({ fixture, kind: 'capability_revoked', code: 'access.capability.001', operationId: request.operation_id, nonce, subject: subjectData.subject, semanticActor: custody.actor, persistenceActor: journal.actor, sequence: 1, targetKind: 'unconsumed_capability', targetIdentity: 'a'.repeat(64), triggerDigest: tombstone.record_digest_sha256 })
  let descriptorRequest
  const descriptor = ({ prior }) => {
    if (!descriptorRequest) {
      descriptorRequest = makeAccessRecord({ fixture, kind: 'descriptor_termination_requested', code: 'access.descriptor.request.001', operationId: request.operation_id, nonce, subject: subjectData.subject, semanticActor: custody.actor, persistenceActor: journal.actor, sequence: 1, targetKind: 'issued_descriptor', targetIdentity: 'b'.repeat(64), triggerDigest: tombstone.record_digest_sha256 })
      return descriptorRequest
    }
    return makeAccessRecord({ fixture, kind: 'descriptor_termination_confirmed', code: 'access.descriptor.001', operationId: request.operation_id, nonce, subject: subjectData.subject, semanticActor: launcher.actor, persistenceActor: journal.actor, sequence: 2, predecessor: descriptorRequest.record_digest_sha256, targetKind: 'issued_descriptor', targetIdentity: 'b'.repeat(64), triggerDigest: tombstone.record_digest_sha256 })
  }
  const accessInventory = createD941SyntheticAccessInventory(); t.after(() => accessInventory.dispose())
  await shutdownSyntheticAccess({ broker: fixture.broker, accessInventory, records: [capability, descriptor, descriptor], semanticSessions: [custody, custody, launcher], persistenceSession: journal })
  return { fixture, journal, executor, verifier, custody, launcher, requester, deletion, deletionApprover, records, privacy, request, authorization, tombstone, authScope, authHash, subjectData, custodyEvidence }
}

function executionPlan(context) {
  const { fixture, journal, executor, verifier, authorization, tombstone, authHash, subjectData, custodyEvidence } = context
  let started; let inventoried; let unlinked
  const common = { fixture, operationId: authorization.operation_id, nonce, subject: subjectData.subject, persistenceActor: journal.actor, authorizationDigest: authorization.record_digest_sha256, tombstoneDigest: tombstone.record_digest_sha256, authorizationScopeSha256: authHash, artifact: subjectData.artifact, custodyEvidence: custodyEvidence.resolve() }
  return {
    records: [
      ({ head, projection }) => (started = makeExecutionRecord({ ...common, kind: 'execution_started', code: 'execution.started.001', semanticActor: executor.actor, sequence: 1, observed: context.fixture.deleteRuntime.inspect({ rootPath: fixture.roots.cas, artifact: subjectData.artifact, backendReference: subjectData.backendReference }), head, projection })),
      ({ head, projection, observed }) => (inventoried = makeExecutionRecord({ ...common, kind: 'inventory_observed', code: 'execution.inventory.001', semanticActor: executor.actor, sequence: 2, predecessor: started.record_digest_sha256, observed, head, projection })),
      ({ head, projection, observed }) => (unlinked = makeExecutionRecord({ ...common, kind: 'unlink_attempted', code: 'execution.unlink.001', semanticActor: executor.actor, sequence: 3, predecessor: inventoried.record_digest_sha256, observed, head, projection, inventory: inventoried.inventory, effectiveAt: '2030-01-01T00:10:08.500Z' })),
      ({ head, projection, observed }) => makeExecutionRecord({ ...common, kind: 'primary_absence_verified', code: 'execution.verified.001', semanticActor: verifier.actor, sequence: 4, predecessor: unlinked.record_digest_sha256, observed, head: { sequence: unlinked.safety_snapshot.known_through_receipt_sequence, persistedAt: unlinked.safety_snapshot.known_through_persisted_at, digest: unlinked.safety_snapshot.control_ledger_head_receipt_digest_sha256 }, projection, priorTargetObservationRecordDigest: unlinked.record_digest_sha256 }),
    ],
    receipt: ({ unlinkRecord, verificationRecord }) => makeDeletionReceipt({ fixture, operationId: authorization.operation_id, nonce, subject: subjectData.subject, requestDigest: context.request.record_digest_sha256, authorizationDigest: authorization.record_digest_sha256, tombstoneDigest: tombstone.record_digest_sha256, unlinkRecord, verificationRecord, authorizationScopeSha256: authHash, executor: executor.actor, verifier: verifier.actor, persistenceActor: journal.actor, safetySnapshotSha256: unlinkRecord.safety_snapshot.snapshot_sha256, custodyEvidence: custodyEvidence.resolve() }),
  }
}

test('synthetic primary-name deletion is bounded, locked, synced, independently verified and never claims erasure', async (t) => {
  const context = await setupDeletion(t); const plan = executionPlan(context)
  const result = await executeSyntheticPrimaryDeletion({ broker: context.fixture.broker, linuxEnforcement: context.fixture.linux, deleteRuntime: context.fixture.deleteRuntime, rootPath: context.fixture.roots.cas, artifact: context.subjectData.artifact, backendReference: context.subjectData.backendReference, subjectIdentitySha256: context.subjectData.subject.subject_identity_sha256, effectiveAt: '2030-01-01T00:10:08.500Z', knownAt: '2030-01-01T00:30:00.000Z', custodyEvidence: context.custodyEvidence, executionRecords: plan.records, receiptRecord: plan.receipt, executorSession: context.executor, verifierSession: context.verifier, persistenceSession: context.journal })
  assert.equal(result.outcomeCode, 'primary_copy_absence_verified'); assert.equal(result.operational, false); assert.equal(result.d9_5_reachable, false)
  assert.equal(result.boundedReceipt.complete_erasure_claimed, false); assert.equal(result.boundedReceipt.backup_erasure_claimed, false); assert.equal(result.boundedReceipt.legal_compliance_claimed, false)
  assert.equal(fs.existsSync(path.join(context.fixture.roots.cas, context.subjectData.backendReference)), false)
})

test('receipt proof commitments cannot be substituted after the execution graph is durable', async (t) => {
  const context = await setupDeletion(t); const plan = executionPlan(context)
  const result = await executeSyntheticPrimaryDeletion({ broker: context.fixture.broker, linuxEnforcement: context.fixture.linux, deleteRuntime: context.fixture.deleteRuntime, rootPath: context.fixture.roots.cas, artifact: context.subjectData.artifact, backendReference: context.subjectData.backendReference, subjectIdentitySha256: context.subjectData.subject.subject_identity_sha256, effectiveAt: '2030-01-01T00:10:08.500Z', knownAt: '2030-01-01T00:30:00.000Z', custodyEvidence: context.custodyEvidence, executionRecords: plan.records, receiptRecord: plan.receipt, executorSession: context.executor, verifierSession: context.verifier, persistenceSession: context.journal })
  const mutated = structuredClone(result.boundedReceipt)
  mutated.record_code = 'receipt.mutated-proof.001'
  mutated.d930_operational_profile_record_digest_sha256 = 'f'.repeat(64)
  mutated.knowledge_boundary.persisted_at = context.fixture.time.reserve()
  mutated.knowledge_boundary.recorded_at = mutated.knowledge_boundary.persisted_at
  mutated.knowledge_boundary.receipt_sequence = context.fixture.broker.head().sequence + 1
  mutated.record_digest_sha256 = null
  const resealed = sealD940Record(mutated)
  await assert.rejects(context.fixture.broker.append({ record: resealed, semanticSession: context.verifier, persistenceSession: context.journal }), /D941_RECEIPT_BASIS_UNRESOLVED/)
})

test('direct broker appends cannot forge native deletion or absence facts', async (t) => {
  const context = await setupDeletion(t); const plan = executionPlan(context)
  let head = context.fixture.broker.head()
  let projection = projectD941Subject({ broker: context.fixture.broker, subjectIdentitySha256: context.subjectData.subject.subject_identity_sha256, effectiveAsOf: '2030-01-01T00:10:08.500Z', knownAt: '2030-01-01T00:30:00.000Z', knownThroughSequence: head.sequence })
  const started = plan.records[0]({ head, projection }); await context.fixture.broker.append({ record: started, semanticSession: context.executor, persistenceSession: context.journal })
  head = context.fixture.broker.head(); projection = projectD941Subject({ broker: context.fixture.broker, subjectIdentitySha256: context.subjectData.subject.subject_identity_sha256, effectiveAsOf: '2030-01-01T00:10:08.500Z', knownAt: '2030-01-01T00:30:00.000Z', knownThroughSequence: head.sequence })
  const observed = context.fixture.deleteRuntime.inspect({ rootPath: context.fixture.roots.cas, artifact: context.subjectData.artifact, backendReference: context.subjectData.backendReference })
  const inventoried = plan.records[1]({ head, projection, observed }); await context.fixture.broker.append({ record: inventoried, semanticSession: context.executor, persistenceSession: context.journal })
  head = context.fixture.broker.head(); projection = projectD941Subject({ broker: context.fixture.broker, subjectIdentitySha256: context.subjectData.subject.subject_identity_sha256, effectiveAsOf: '2030-01-01T00:10:08.500Z', knownAt: '2030-01-01T00:30:00.000Z', knownThroughSequence: head.sequence })
  const unlink = plan.records[2]({ head, projection, observed })
  await assert.rejects(context.fixture.broker.append({ record: unlink, semanticSession: context.executor, persistenceSession: context.journal }), /D941_DELETE_EFFECT_UNPROVEN/)
})

test('hard links, symlinks, unexpected names and paths outside a synthetic root fail closed', async (t) => {
  const fixture = await createD941Fixture(t); const data = subjectFor(); const target = prepareCas(fixture.roots.cas, data.artifact, data.bytes)
  fs.linkSync(target, `${target}.hardlink`)
  assert.throws(() => fixture.deleteRuntime.inspect({ rootPath: fixture.roots.cas, artifact: data.artifact, backendReference: data.backendReference }), /D941_DELETE_INVENTORY_UNEXPECTED|D941_DELETE_TARGET_UNSAFE/)
  fs.unlinkSync(`${target}.hardlink`); fs.unlinkSync(target); fs.symlinkSync('/etc/passwd', target)
  assert.throws(() => fixture.deleteRuntime.inspect({ rootPath: fixture.roots.cas, artifact: data.artifact, backendReference: data.backendReference }), /D941_DELETE_TARGET_UNSAFE/)
  assert.throws(() => fixture.deleteRuntime.inspect({ rootPath: '/tmp', artifact: data.artifact, backendReference: data.backendReference }), /D941_DELETE_ROOT_FORBIDDEN/)
})

test('pinned deletion root rejects configured-root replacement', async (t) => {
  const fixture = await createD941Fixture(t); const data = subjectFor(); prepareCas(fixture.roots.cas, data.artifact, data.bytes)
  fixture.deleteRuntime.inspect({ rootPath: fixture.roots.cas, artifact: data.artifact, backendReference: data.backendReference })
  const original = `${fixture.roots.cas}.original`; fs.renameSync(fixture.roots.cas, original); fs.mkdirSync(fixture.roots.cas, { mode: 0o700 })
  try { assert.throws(() => fixture.deleteRuntime.inspect({ rootPath: fixture.roots.cas, artifact: data.artifact, backendReference: data.backendReference }), /D941_DELETE_ROOT_SUBSTITUTED/) }
  finally { fs.rmSync(fixture.roots.cas, { recursive: true, force: true }); fs.renameSync(original, fixture.roots.cas) }
})

test('stale safety snapshots and concurrent operation locks cancel deletion before unlink', async (t) => {
  const context = await setupDeletion(t); const plan = executionPlan(context)
  const competing = await context.fixture.linux.holdOperationLock({ rootPath: context.fixture.roots.lock, relativePath: 'd941-operation.lock' })
  await assert.rejects(executeSyntheticPrimaryDeletion({ broker: context.fixture.broker, linuxEnforcement: context.fixture.linux, deleteRuntime: context.fixture.deleteRuntime, rootPath: context.fixture.roots.cas, artifact: context.subjectData.artifact, backendReference: context.subjectData.backendReference, subjectIdentitySha256: context.subjectData.subject.subject_identity_sha256, effectiveAt: '2030-01-01T00:10:08.500Z', knownAt: '2030-01-01T00:30:00.000Z', custodyEvidence: context.custodyEvidence, executionRecords: plan.records, receiptRecord: plan.receipt, executorSession: context.executor, verifierSession: context.verifier, persistenceSession: context.journal }), /OPERATION_LOCK_UNAVAILABLE/)
  await competing.release()
  assert.equal(fs.existsSync(path.join(context.fixture.roots.cas, context.subjectData.backendReference)), true)
})

test('crash after unlink and before parent sync leaves no success receipt and requires classification', async (t) => {
  const context = await setupDeletion(t); const plan = executionPlan(context)
  await assert.rejects(executeSyntheticPrimaryDeletion({ broker: context.fixture.broker, linuxEnforcement: context.fixture.linux, deleteRuntime: context.fixture.deleteRuntime, rootPath: context.fixture.roots.cas, artifact: context.subjectData.artifact, backendReference: context.subjectData.backendReference, subjectIdentitySha256: context.subjectData.subject.subject_identity_sha256, effectiveAt: '2030-01-01T00:10:08.500Z', knownAt: '2030-01-01T00:30:00.000Z', custodyEvidence: context.custodyEvidence, executionRecords: plan.records, receiptRecord: plan.receipt, executorSession: context.executor, verifierSession: context.verifier, persistenceSession: context.journal, faultInjector(point) { if (point === 'after_unlink_before_directory_sync') throw new Error('synthetic crash after unlink') } }), /synthetic crash after unlink/)
  assert.equal(fs.existsSync(path.join(context.fixture.roots.cas, context.subjectData.backendReference)), false)
  assert.equal(context.fixture.store.inventory().projection.receipt.length, 0)
  assert.equal(context.fixture.store.inventory().projection.execution.some((entry) => entry.record_code === 'execution.unlink.001'), false)
})

test('historical restriction projection remains bounded after tombstone and access shutdown', async (t) => {
  const context = await setupDeletion(t); const head = context.fixture.broker.head()
  const projection = projectD941Subject({ broker: context.fixture.broker, subjectIdentitySha256: context.subjectData.subject.subject_identity_sha256, effectiveAsOf: '2030-01-01T00:20:00.000Z', knownAt: '2030-01-01T00:30:00.000Z', knownThroughSequence: head.sequence })
  assert.equal(projection.tombstoned, true); assert.equal(projection.authorization_active, true); assert.equal(projection.access_shutdown_confirmed, true); assert.equal(projection.access_eligibility_code, 'withheld')
})
