import { canonicalSha256 } from '../control-plane/canonical.mjs'
import { assertLinuxEnforcement } from '../control-plane/platform.mjs'
import { assertD941AuthenticatedSession } from './admin-launcher.mjs'
import { assertD941LedgerBroker } from './ledger.mjs'
import { assertD941PrimaryDeleteRuntime } from './primary-delete.mjs'
import { assertD941DeletionEligible, projectD941Subject } from './projection.mjs'
import { failD941 } from './errors.mjs'
import { assertD941SyntheticAccessInventory } from './access-control.mjs'
import { assertD941SyntheticCustodyEvidence } from './custody-evidence.mjs'

function exactInventory(record, observed, artifact) {
  const inventory = record.inventory
  const targetPathIdentity = canonicalSha256({ device: observed.targetDevice, inode: observed.targetInode, sha256: artifact.sha256 })
  const parentIdentity = canonicalSha256({ device: observed.parentDevice, inode: observed.parentInode })
  return inventory.inventory_complete === true && inventory.target_file_type_code === 'regular_file' &&
    inventory.approved_primary_names_checked === 1 && inventory.matching_primary_names === 1 && inventory.backup_state_code === 'not_implemented' &&
    inventory.target_device === observed.targetDevice && inventory.target_inode === observed.targetInode &&
    inventory.parent_directory_device === observed.parentDevice && inventory.parent_directory_inode === observed.parentInode &&
    inventory.observed_target_sha256 === artifact.sha256 && inventory.observed_target_byte_length === artifact.byte_length &&
    inventory.observed_target_link_count === 1 && inventory.hard_links === 0 && inventory.open_descriptors === 0 &&
    inventory.unexpected_replicas === 0 && inventory.temporary_objects === 0 && inventory.symlink_observed === false &&
    inventory.parent_directory_opened_no_follow === true && inventory.target_opened_no_follow === true &&
    inventory.target_path_identity_sha256 === targetPathIdentity && inventory.parent_directory_identity_sha256 === parentIdentity
}

function exactAbsenceInventory(inventory, observed, artifact, unlinkRecord) {
  const targetPathIdentity = canonicalSha256({ device: observed.targetDevice, inode: observed.targetInode, sha256: artifact.sha256 })
  const parentIdentity = canonicalSha256({ device: observed.parentDevice, inode: observed.parentInode })
  return inventory.inventory_complete === true && inventory.target_file_type_code === 'absent' &&
    inventory.approved_primary_names_checked === 1 && inventory.matching_primary_names === 0 && inventory.backup_state_code === 'not_implemented' &&
    inventory.open_descriptors === 0 && inventory.hard_links === 0 && inventory.unexpected_replicas === 0 && inventory.temporary_objects === 0 &&
    inventory.target_device === null && inventory.target_inode === null && inventory.observed_target_sha256 === null && inventory.observed_target_byte_length === null &&
    inventory.observed_target_link_count === null && inventory.parent_directory_device === observed.parentDevice && inventory.parent_directory_inode === observed.parentInode &&
    inventory.parent_directory_identity_sha256 === parentIdentity && inventory.target_path_identity_sha256 === targetPathIdentity &&
    inventory.parent_directory_opened_no_follow === true && inventory.target_opened_no_follow === false && inventory.symlink_observed === false &&
    inventory.prior_target_observation_record_digest_sha256 === unlinkRecord.record_digest_sha256
}

function exactSafetySnapshot(snapshot, head, projection, inventorySha256) {
  const material = {
    journal_namespace_code: 'd940.global.control-journal.v1',
    known_through_receipt_sequence: head.sequence,
    known_through_persisted_at: head.persistedAt,
    control_ledger_head_receipt_digest_sha256: head.digest,
    control_head_projection_sha256: projection.projection_sha256,
    access_head_projection_sha256: projection.projection_sha256,
    subject_lineage_projection_sha256: snapshot.subject_lineage_projection_sha256,
    custody_leaf_projection_sha256: snapshot.custody_leaf_projection_sha256,
    inventory_snapshot_sha256: inventorySha256,
    active_hold_count: projection.active_hold ? 1 : 0,
    unknown_or_conflicting_control_count: 0,
  }
  return snapshot.snapshot_sha256 === canonicalSha256(material) && Object.entries(material).every(([key, value]) => snapshot[key] === value)
}

export async function shutdownSyntheticAccess({ broker, accessInventory, records, semanticSessions, persistenceSession, approvalSessions = [] }) {
  assertD941LedgerBroker(broker)
  assertD941SyntheticAccessInventory(accessInventory)
  if (!Array.isArray(records) || records.length === 0) failD941('D941_ACCESS_INVENTORY_INCOMPLETE', 'complete capability/descriptor inventory is required')
  const results = []
  const resolved = []
  await broker.withDestructiveLock(async (lock) => {
    for (const [index, record] of records.entries()) {
      const value = typeof record === 'function' ? record({ prior: resolved.at(-1) ?? null, head: broker.head() }) : record
      const expected = accessInventory.entries().find((entry) => entry.identity === value.access_target_identity_sha256)
      if (!expected || expected.kind !== value.access_target_kind_code) failD941('D941_ACCESS_INVENTORY_INCOMPLETE', 'record target is outside the live access inventory')
      const effect = async () => {
        if (value.record_kind_code === 'capability_revoked') accessInventory.revokeCapability(expected.identity)
        else if (value.record_kind_code === 'descriptor_termination_confirmed') await accessInventory.terminateAndReap(expected.identity)
        return { runtimeProof: accessInventory.effectProof(value), applied: true }
      }
      const persisted = value.record_kind_code === 'descriptor_termination_requested'
        ? { append: lock.appendLocked({ record: value, semanticSession: semanticSessions[index], persistenceSession, approvalSessions }) }
        : await lock.effectThenAppend({ record: value, semanticSession: semanticSessions[index], persistenceSession, approvalSessions }, effect)
      resolved.push(value)
      results.push(persisted.append ?? persisted)
    }
  })
  const targetKinds = new Set(resolved.map((record) => record.access_target_kind_code))
  if (!targetKinds.has('unconsumed_capability') || !targetKinds.has('issued_descriptor')) failD941('D941_ACCESS_INVENTORY_INCOMPLETE', 'both capability and descriptor targets are required')
  const terminal = new Map()
  for (const record of resolved) terminal.set(record.access_target_identity_sha256, record)
  for (const record of terminal.values()) {
    if (record.access_target_kind_code === 'unconsumed_capability' && record.record_kind_code !== 'capability_revoked') failD941('D941_ACCESS_SHUTDOWN_INCOMPLETE', 'capability remains consumable')
    if (record.access_target_kind_code === 'issued_descriptor' && (record.record_kind_code !== 'descriptor_termination_confirmed' || record.receiver_termination_state_code !== 'confirmed' || record.descriptor_close_state_code !== 'confirmed')) failD941('D941_ACCESS_SHUTDOWN_INCOMPLETE', 'descriptor receiver was not terminated, reaped, and closed')
  }
  if (terminal.size !== accessInventory.entries().length) failD941('D941_ACCESS_INVENTORY_INCOMPLETE', 'not every live access object has a terminal record')
  accessInventory.assertShutdown()
  return Object.freeze(results)
}

export async function executeSyntheticPrimaryDeletion({
  broker, linuxEnforcement, deleteRuntime,
  rootPath, artifact, backendReference, subjectIdentitySha256, effectiveAt, knownAt,
  custodyEvidence,
  executionRecords, receiptRecord, executorSession, verifierSession, persistenceSession,
  faultInjector = null,
}) {
  assertD941LedgerBroker(broker); assertLinuxEnforcement(linuxEnforcement); assertD941PrimaryDeleteRuntime(deleteRuntime)
  const resolvedCustody = assertD941SyntheticCustodyEvidence(custodyEvidence).resolve()
  assertD941AuthenticatedSession(executorSession, 'deletion_execution')
  assertD941AuthenticatedSession(verifierSession, 'independent_verification')
  assertD941AuthenticatedSession(persistenceSession, 'control_submission')
  if (!Array.isArray(executionRecords) || executionRecords.length !== 4) {
    failD941('D941_DELETE_PLAN_INVALID', 'fixed deletion plan must contain exactly four ordered execution facts')
  }

  const resolveRecord = (index, context) => typeof executionRecords[index] === 'function' ? executionRecords[index](context) : executionRecords[index]

  let head = broker.head()
  let projection = assertD941DeletionEligible(projectD941Subject({ broker, subjectIdentitySha256, effectiveAsOf: effectiveAt, knownAt, knownThroughSequence: head.sequence }))
  const startedRecord = resolveRecord(0, { head, projection })
  if (startedRecord.record_kind_code !== 'execution_started') failD941('D941_DELETE_PLAN_INVALID', 'first execution fact must be execution_started')
  await broker.append({ record: startedRecord, semanticSession: executorSession, persistenceSession })
  const observed = deleteRuntime.inspect({ rootPath, artifact, backendReference })
  head = broker.head(); projection = projectD941Subject({ broker, subjectIdentitySha256, effectiveAsOf: effectiveAt, knownAt, knownThroughSequence: head.sequence })
  const inventoryRecord = resolveRecord(1, { head, projection, observed, startedRecord })
  if (inventoryRecord.record_kind_code !== 'inventory_observed' || !exactInventory(inventoryRecord, observed, artifact)) failD941('D941_DELETE_INVENTORY_MISMATCH', 'inventory record differs from the no-follow target observation')
  await broker.append({ record: inventoryRecord, semanticSession: executorSession, persistenceSession })
  faultInjector?.('after_inventory_persisted')

  let removed
  let unlinkAppendResult
  await broker.withDestructiveLock(async (lock) => {
    head = broker.head()
    projection = assertD941DeletionEligible(projectD941Subject({ broker, subjectIdentitySha256, effectiveAsOf: effectiveAt, knownAt, knownThroughSequence: head.sequence }))
    const observedAgain = deleteRuntime.inspect({ rootPath, artifact, backendReference })
    if (canonicalSha256(observedAgain) !== canonicalSha256(observed)) failD941('D941_DELETE_SNAPSHOT_STALE', 'target inventory changed after the persisted observation')
    const inventorySha256 = canonicalSha256(inventoryRecord.inventory)
    const unlinkRecord = resolveRecord(2, { head, projection, observed, startedRecord, inventoryRecord, inventorySha256, resolvedCustody })
    projection = assertD941DeletionEligible(projectD941Subject({ broker, subjectIdentitySha256, effectiveAsOf: effectiveAt, knownAt, knownThroughSequence: head.sequence, operationId: unlinkRecord.operation_id, operationNonce: unlinkRecord.operation_nonce }))
    if (unlinkRecord.record_kind_code !== 'unlink_attempted' || !exactSafetySnapshot(unlinkRecord.safety_snapshot, head, projection, inventorySha256)) failD941('D941_DELETE_SNAPSHOT_STALE', 'unlink record does not pin the exact current cross-store safety snapshot')
    if (unlinkRecord.d930_operational_profile_record_digest_sha256 !== resolvedCustody.d930OperationalProfileSha256 || unlinkRecord.d930_primary_durability_receipt_sha256 !== resolvedCustody.d930PrimaryDurabilityReceiptSha256 ||
      unlinkRecord.safety_snapshot.subject_lineage_projection_sha256 !== resolvedCustody.subjectLineageProjectionSha256 || unlinkRecord.safety_snapshot.custody_leaf_projection_sha256 !== resolvedCustody.custodyLeafProjectionSha256) failD941('D941_CUSTODY_EVIDENCE_MISMATCH', 'execution does not pin the resolved D9.3 evidence')
    if (projection.deletion_authorization_record_digest_sha256 !== unlinkRecord.deletion_authorization_record_digest_sha256 ||
        projection.tombstone_record_digest_sha256 !== unlinkRecord.tombstone_record_digest_sha256 ||
        unlinkRecord.authorization_scope_sha256 !== projection.authorization_scope_sha256) failD941('D941_DELETE_AUTHORIZATION_GRAPH_UNRESOLVED', 'execution is not bound to the exact current authorization, tombstone, and scope projection')
    // The unlink record's immutable effective point, rather than the caller's
    // advisory preflight time, is the authorization boundary for the effect.
    projection = assertD941DeletionEligible(projectD941Subject({ broker, subjectIdentitySha256, effectiveAsOf: unlinkRecord.knowledge_boundary.effective_at, knownAt, knownThroughSequence: head.sequence, operationId: unlinkRecord.operation_id, operationNonce: unlinkRecord.operation_nonce }))
    if (!exactSafetySnapshot(unlinkRecord.safety_snapshot, head, projection, inventorySha256)) failD941('D941_DELETE_SNAPSHOT_STALE', 'unlink authorization was evaluated at a different effective point')
    const destructiveAt = Date.parse(unlinkRecord.knowledge_boundary.effective_at)
    const headAt = Date.parse(head.persistedAt)
    if (destructiveAt < headAt || destructiveAt - headAt > 1_000) failD941('D941_DELETE_SNAPSHOT_STALE', 'destructive safety snapshot falls outside the closed 0–1,000 millisecond window')
    if (broker.head().digest !== head.digest) failD941('D941_DELETE_LEDGER_CHANGED', 'D9.4 ledger head changed before unlink')
    faultInjector?.('immediately_before_unlink')
    lock.assertAuthorityHead()
    broker.revalidateSession(executorSession, unlinkRecord.knowledge_boundary.effective_at)
    broker.revalidateSession(persistenceSession, unlinkRecord.knowledge_boundary.persisted_at)
    unlinkAppendResult = await lock.effectThenAppend({ record: unlinkRecord, semanticSession: executorSession, persistenceSession }, async () => {
      const unlinked = deleteRuntime.unlinkPrimary({ rootPath, artifact, inventory: observed, recordInventory: unlinkRecord.inventory, recordDigestSha256: unlinkRecord.record_digest_sha256, backendReference, operationNonce: unlinkRecord.operation_nonce })
      faultInjector?.('after_unlink_before_directory_sync')
      const synced = deleteRuntime.syncParent({ rootPath, artifact, inventory: observed, operationNonce: unlinkRecord.operation_nonce })
      const effectProof = deleteRuntime.finalizeUnlinkEffect({ unlinkResult: unlinked, syncResult: synced, recordInventory: unlinkRecord.inventory, recordDigestSha256: unlinkRecord.record_digest_sha256, operationNonce: unlinkRecord.operation_nonce })
      removed = Object.freeze({ ...unlinked, effectProof: undefined, syncProof: undefined, directory_synced: synced.directory_synced, reopened_absent: synced.reopened_absent })
      faultInjector?.('after_unlink_before_lock_release')
      return { runtimeProof: effectProof, applied: true, result: removed }
    })
    executionRecords[2] = unlinkRecord
  })

  if (executionRecords[2].execution.method_code !== 'unlink_primary_name_no_follow' || executionRecords[2].execution.outcome_code !== 'primary_name_removed' ||
      executionRecords[2].execution.target_name_removed !== true || executionRecords[2].execution.directory_synced !== true || !removed.reopened_absent) {
    failD941('D941_DELETE_EXECUTION_MISMATCH', 'unlink record overstates or differs from the native result')
  }
  if (!unlinkAppendResult?.append?.created) failD941('D941_DELETE_EXECUTION_REPLAY', 'unlink execution did not produce a new protected receipt')
  faultInjector?.('after_unlink_record_persisted')
  head = broker.head(); projection = projectD941Subject({ broker, subjectIdentitySha256, effectiveAsOf: effectiveAt, knownAt, knownThroughSequence: head.sequence })
  const verificationRecord = resolveRecord(3, { head, projection, observed, startedRecord, inventoryRecord, unlinkRecord: executionRecords[2] })
  // The verifier session is authenticated through the fixed launcher IPC
  // exchange before the native no-follow observer is invoked. The native
  // observer remains a synthetic fixed-function test double; production
  // process isolation is explicitly out of scope for this milestone.
  if (verifierSession.exchange?.status !== 'ok') {
    failD941('D941_IPC_AUTHENTICATION_FAILED', 'independent verifier session has no authenticated fixed-function IPC exchange')
  }
  const verified = deleteRuntime.verifyAbsent({ rootPath, artifact, inventory: observed, recordInventory: verificationRecord.inventory, recordDigestSha256: verificationRecord.record_digest_sha256, operationNonce: verificationRecord.operation_nonce })
  const unlinkRecord = executionRecords[2]
  if (verified.parent_device !== observed.parentDevice || verified.parent_inode !== observed.parentInode ||
      verificationRecord.inventory.parent_directory_device !== verified.parent_device || verificationRecord.inventory.parent_directory_inode !== verified.parent_inode ||
      !exactAbsenceInventory(verificationRecord.inventory, observed, artifact, unlinkRecord) ||
      verificationRecord.inventory.prior_target_observation_record_digest_sha256 !== unlinkRecord.record_digest_sha256 ||
      verificationRecord.deletion_authorization_record_digest_sha256 !== unlinkRecord.deletion_authorization_record_digest_sha256 ||
      verificationRecord.tombstone_record_digest_sha256 !== unlinkRecord.tombstone_record_digest_sha256 ||
      verificationRecord.authorization_scope_sha256 !== unlinkRecord.authorization_scope_sha256 ||
      verificationRecord.d930_operational_profile_record_digest_sha256 !== unlinkRecord.d930_operational_profile_record_digest_sha256 ||
      verificationRecord.d930_primary_durability_receipt_sha256 !== unlinkRecord.d930_primary_durability_receipt_sha256 ||
      verificationRecord.safety_snapshot.subject_lineage_projection_sha256 !== unlinkRecord.safety_snapshot.subject_lineage_projection_sha256 ||
      verificationRecord.safety_snapshot.custody_leaf_projection_sha256 !== unlinkRecord.safety_snapshot.custody_leaf_projection_sha256 ||
      verificationRecord.safety_snapshot.control_ledger_head_receipt_digest_sha256 !== unlinkRecord.safety_snapshot.control_ledger_head_receipt_digest_sha256) {
    failD941('D941_ABSENCE_PROVENANCE_MISMATCH', 'independent absence observation is not bound to the exact unlink graph and namespace identity')
  }
  if (verificationRecord.record_kind_code !== 'primary_absence_verified' || !verified.absent || verificationRecord.execution.method_code !== 'verify_primary_absence_no_follow' || verificationRecord.execution.outcome_code !== 'primary_absence_verified' || verificationRecord.execution.reopened_target_absent !== true) {
    failD941('D941_DELETE_VERIFICATION_MISMATCH', 'verification record differs from independent namespace observation')
  }
  executionRecords[3] = verificationRecord
  await broker.append({ record: verificationRecord, semanticSession: verifierSession, persistenceSession, runtimeProof: verified.effectProof })
  faultInjector?.('after_verification_record_persisted')
  const boundedReceipt = typeof receiptRecord === 'function' ? receiptRecord({ head: broker.head(), projection, observed, startedRecord, inventoryRecord, unlinkRecord: executionRecords[2], verificationRecord }) : receiptRecord
  if (boundedReceipt.complete_erasure_claimed !== false || boundedReceipt.backup_erasure_claimed !== false || boundedReceipt.legal_compliance_claimed !== false ||
      boundedReceipt.executor.identity_binding.binding_code !== executorSession.actor.identity_binding.binding_code || boundedReceipt.independent_verifier.identity_binding.binding_code !== verifierSession.actor.identity_binding.binding_code) {
    failD941('D941_DELETE_RECEIPT_OVERCLAIM', 'bounded receipt claims too much or names unauthenticated actors')
  }
  if (canonicalSha256(boundedReceipt.executor) !== canonicalSha256(executionRecords[2].semantic_actor) ||
      canonicalSha256(boundedReceipt.independent_verifier) !== canonicalSha256(verificationRecord.semantic_actor) ||
      boundedReceipt.operation_id !== verificationRecord.operation_id || boundedReceipt.operation_nonce !== verificationRecord.operation_nonce ||
      boundedReceipt.subject.subject_identity_sha256 !== verificationRecord.subject.subject_identity_sha256) failD941('D941_DELETE_RECEIPT_ACTOR_UNRESOLVED', 'receipt actors and operation context do not match the exact persisted execution and verification actors')
  const receiptProjection = projectD941Subject({ broker, subjectIdentitySha256, effectiveAsOf: verificationRecord.knowledge_boundary.effective_at, knownAt, knownThroughSequence: broker.head().sequence, operationId: boundedReceipt.operation_id, operationNonce: boundedReceipt.operation_nonce })
  if (boundedReceipt.deletion_request_record_digest_sha256 !== receiptProjection.deletion_request_record_digest_sha256 ||
      boundedReceipt.deletion_authorization_record_digest_sha256 !== executionRecords[2].deletion_authorization_record_digest_sha256 ||
      boundedReceipt.tombstone_record_digest_sha256 !== executionRecords[2].tombstone_record_digest_sha256 ||
      boundedReceipt.execution_record_digest_sha256 !== executionRecords[2].record_digest_sha256 ||
      boundedReceipt.verification_record_digest_sha256 !== verificationRecord.record_digest_sha256 ||
      boundedReceipt.d930_operational_profile_record_digest_sha256 !== resolvedCustody.d930OperationalProfileSha256 ||
      boundedReceipt.d930_primary_durability_receipt_sha256 !== resolvedCustody.d930PrimaryDurabilityReceiptSha256 ||
      boundedReceipt.safety_snapshot_sha256 !== executionRecords[2].safety_snapshot.snapshot_sha256 ||
      boundedReceipt.control_ledger_head_receipt_digest_sha256 !== executionRecords[2].safety_snapshot.control_ledger_head_receipt_digest_sha256) failD941('D941_DELETE_RECEIPT_GRAPH_UNRESOLVED', 'receipt is not bound to the exact persisted request, authorization, tombstone, execution, verification, custody, and safety records')
  const result = await broker.append({ record: boundedReceipt, semanticSession: verifierSession, persistenceSession })
  faultInjector?.('after_receipt_persisted')
  return Object.freeze({ outcomeCode: 'primary_copy_absence_verified', receipt: result.receipt, boundedReceipt, operational: false, d9_5_reachable: false })
}
