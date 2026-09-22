import { canonicalSha256 } from '../control-plane/canonical.mjs'
import { sealD940Record, validateD940Record } from './contracts.mjs'
import { failD941 } from './errors.mjs'
import { assertD941LedgerBroker } from './ledger.mjs'
import { assertD941RecoveryResolverRuntime } from './recovery-resolvers.mjs'

const defaults = Object.freeze({
  before_restriction_persisted: 'safe_no_effect',
  after_restriction_before_capability_revocation: 'restriction_required',
  after_revocation_before_descriptor_termination: 'retain_and_hold',
  after_tombstone_before_unlink: 'retain_and_hold',
  after_unlink_before_directory_sync: 'reconciliation_required',
  after_sync_before_verification: 'reconciliation_required',
  after_verification_before_receipt: 'reconciliation_required',
  after_receipt_before_journal_link: 'reconciliation_required',
})
const reconstructionStates = new WeakSet()
const reconstructionMetadata = new WeakMap()
const recoveryProofs = new WeakSet()
const recoveryRecordProofs = new WeakMap()

function assertRecoveryHeadRepresentable({ head }) {
  if (head.sequence < 1 || head.digest === null || head.persistedAt === null) {
    failD941('D941_RECOVERY_EMPTY_HEAD_UNREPRESENTABLE', 'the frozen recovery schema cannot represent an empty protected ledger head')
  }
}

// Reconstructs only the durable facts needed to classify an interrupted
// operation. It never retries, repairs, restores, or writes a recovery record.
export function reconstructD941RecoveryState({ broker, subjectIdentitySha256 = null, resolverRuntime = null, resolverOperationId = null, resolverOperationNonce = null, subjectKindCode = 'custody_copy' } = {}) {
  assertD941LedgerBroker(broker)
  const inventory = broker.store.inventory()
  let receipts
  let ledgerStateCode = 'linear_complete'
  try { receipts = broker.validate() } catch { receipts = []; ledgerStateCode = 'recovery_required' }
  const namespaceByFormat = {
    'jedi-atlas-custody-control-record': 'control',
    'jedi-atlas-access-revocation-record': 'access',
    'jedi-atlas-deletion-execution-record': 'execution',
    'jedi-atlas-deletion-receipt': 'receipt',
    'jedi-atlas-backup-coordination-record': 'backup',
    'jedi-atlas-d940-recovery-assessment': 'recovery',
  }
  const receiptTargets = new Set(receipts.map((item) => `${namespaceByFormat[item.target_format]}/${item.target_record_code}`))
  let unreceiptedTarget = false
  const subjectRecords = []
  for (const [namespaceCode, rows] of Object.entries(inventory.projection)) {
    if (namespaceCode === 'ledger' || namespaceCode === 'authority' || namespaceCode === 'authority-events') continue
    for (const row of rows) {
      const key = `${namespaceCode}/${row.record_code}`
      if (!receiptTargets.has(key)) unreceiptedTarget = true
      if (subjectIdentitySha256 !== null && !['authority', 'authority-events', 'ledger'].includes(namespaceCode)) {
        try {
          const record = JSON.parse(broker.store.read({ namespaceCode, recordCode: row.record_code }).toString('utf8'))
          if (record.subject?.subject_identity_sha256 === subjectIdentitySha256) subjectRecords.push({ namespaceCode, record })
        } catch { ledgerStateCode = 'recovery_required' }
      }
    }
  }
  if (unreceiptedTarget) ledgerStateCode = 'recovery_required'
  const operationKey = (record) => `${record.operation_id}/${record.operation_nonce}`
  const operations = new Map()
  for (const item of subjectRecords) {
    const key = operationKey(item.record)
    const operation = operations.get(key) ?? { execution: [], receipts: [], records: [] }
    operation.records.push(item)
    if (item.namespaceCode === 'execution') operation.execution.push(item.record)
    if (item.namespaceCode === 'receipt') operation.receipts.push(item.record)
    operations.set(key, operation)
  }
  const summaries = [...operations.values()].map((operation) => {
    operation.execution.sort((left, right) => (left.chain?.sequence ?? 0) - (right.chain?.sequence ?? 0) || left.knowledge_boundary.receipt_sequence - right.knowledge_boundary.receipt_sequence)
    operation.receipts.sort((left, right) => left.knowledge_boundary.receipt_sequence - right.knowledge_boundary.receipt_sequence)
    const lastExecution = operation.execution.at(-1) ?? null
    const receipt = operation.receipts.at(-1) ?? null
    const executionDigest = receipt?.execution_record_digest_sha256 ?? null
    const verificationDigest = receipt?.verification_record_digest_sha256 ?? null
    const streams = new Set(operation.execution.map((item) => item.chain?.stream_code))
    const oneGaplessStream = streams.size === 1 && operation.execution.every((item, index) => item.chain?.sequence === index + 1)
    const hasExactReceiptBasis = receipt !== null && oneGaplessStream && operation.execution.some((item) => item.record_digest_sha256 === executionDigest) &&
      operation.execution.some((item) => item.record_digest_sha256 === verificationDigest) &&
      operation.execution.every((item) => item.knowledge_boundary.receipt_sequence <= receipt.knowledge_boundary.receipt_sequence)
    const incomplete = operation.execution.length > 0 && !hasExactReceiptBasis
    return { operation, lastExecution, receipt, incomplete, latestSequence: Math.max(...operation.records.map((item) => item.record.knowledge_boundary?.receipt_sequence ?? 0)) }
  })
  const incomplete = summaries.filter((summary) => summary.incomplete)
  if (incomplete.length > 0 || incomplete.length > 1) ledgerStateCode = 'recovery_required'
  const selected = (incomplete.length === 1 ? incomplete[0] : summaries.sort((left, right) => right.latestSequence - left.latestSequence)[0]) ?? null
  const stage = selected?.lastExecution?.record_kind_code ?? (subjectRecords.some((item) => item.namespaceCode === 'access') ? 'access_shutdown' : subjectRecords.some((item) => item.namespaceCode === 'control') ? 'restriction_persisted' : 'none')
  const head = broker.head()
  assertRecoveryHeadRepresentable({ head })
  let resolution = null
  if (resolverRuntime !== null) {
    assertD941RecoveryResolverRuntime(resolverRuntime)
    if (subjectIdentitySha256 === null || typeof resolverOperationId !== 'string' || typeof resolverOperationNonce !== 'string') {
      failD941('D941_RECOVERY_RESOLVER_CONTEXT_MISSING', 'resolver-backed reconstruction requires an exact subject and recovery operation identity')
    }
    resolution = resolverRuntime.resolveComposite({
      subject: { subject_kind_code: subjectKindCode, subject_identity_sha256: subjectIdentitySha256 },
      operationId: resolverOperationId,
      operationNonce: resolverOperationNonce,
    })
  }
  const snapshotProjection = resolution?.snapshot ?? null
  if (incomplete.length > 1) ledgerStateCode = 'recovery_required'
  const result = Object.freeze({
    subject_identity_sha256: subjectIdentitySha256,
    ledger_state_code: ledgerStateCode,
    protected_inventory_digest_sha256: inventory.digest,
    protected_head_sequence: head.sequence,
    protected_head_digest_sha256: head.digest,
    receipt_count: receipts.length,
    unreceipted_target: unreceiptedTarget,
    operation_stage_code: stage,
    physical_namespace_state_code: selected?.lastExecution?.record_kind_code === 'primary_absence_verified' ? 'primary_absence_observed' : selected?.lastExecution ? 'unknown_requires_independent_reconciliation' : 'not_observed',
    classification_only: true,
    snapshot_projection: snapshotProjection,
  })
  reconstructionStates.add(result)
  reconstructionMetadata.set(result, Object.freeze({ broker, inventoryDigest: inventory.digest, head, snapshotProjection, resolverRuntime, resolution }))
  return result
}

export function classifyD941Recovery({ authorityContext, broker, record, reconstruction, crashBoundaryCode, snapshot, inventoryStateCode, accessStateCode, controlStateCode }) {
  if (!reconstruction || !reconstructionStates.has(reconstruction) || reconstruction.subject_identity_sha256 !== record.subject.subject_identity_sha256) {
    failD941('D941_RECOVERY_RECONSTRUCTION_UNTRUSTED', 'classification requires the fixed protected-state reconstruction')
  }
  const metadata = reconstructionMetadata.get(reconstruction)
  const currentHead = broker?.head?.()
  const currentInventoryDigest = broker?.store?.inventory?.().digest
  if (!metadata || metadata.broker !== broker || !currentHead || currentHead.sequence !== metadata.head.sequence || currentHead.digest !== metadata.head.digest || currentInventoryDigest !== metadata.inventoryDigest || reconstruction.protected_inventory_digest_sha256 !== metadata.inventoryDigest) {
    failD941('D941_RECOVERY_RECONSTRUCTION_STALE', 'classification reconstruction is stale or belongs to another protected store')
  }
  if (!metadata.snapshotProjection) {
    failD941('D941_RECOVERY_RESOLVER_UNAVAILABLE', 'exact D9.4 recovery projection requires the approved D9.2 evidence, D9.1 access, and D9.3 custody resolvers')
  }
  if (metadata.resolution.compositeResponse.operation_id !== record.operation_id || metadata.resolution.compositeResponse.operation_nonce !== record.operation_nonce ||
      metadata.resolution.compositeResponse.subject.subject_identity_sha256 !== record.subject.subject_identity_sha256 || metadata.resolution.compositeResponse.subject.subject_kind_code !== record.subject.subject_kind_code ||
      metadata.resolution.compositeResponse.technical_evidence_only !== true || metadata.resolution.compositeResponse.authority_granted !== false) {
    failD941('D941_RECOVERY_RESOLVER_CONTEXT_MISMATCH', 'resolver response does not bind the exact recovery operation and technical-evidence-only subject')
  }
  if (reconstruction.ledger_state_code !== 'linear_complete' && controlStateCode === 'linear_complete') {
    failD941('D941_RECOVERY_RECONSTRUCTION_CONTRADICTORY', 'caller state claims linear completion despite protected recovery-required facts')
  }
  if (reconstruction.physical_namespace_state_code === 'unknown_requires_independent_reconciliation' && inventoryStateCode === 'complete') {
    failD941('D941_RECOVERY_RECONSTRUCTION_CONTRADICTORY', 'caller state claims complete inventory despite unknown physical namespace state')
  }
  const expected = metadata?.snapshotProjection
  if (Object.keys(expected).some((key) => snapshot?.[key] !== expected[key])) {
    failD941('D941_RECOVERY_SNAPSHOT_MISMATCH', 'classification snapshot does not match the fixed protected projection')
  }
  const earlyBoundaries = new Set(['before_restriction_persisted', 'after_restriction_before_capability_revocation', 'after_revocation_before_descriptor_termination', 'after_tombstone_before_unlink'])
  if (earlyBoundaries.has(crashBoundaryCode) && ['restriction_persisted', 'access_shutdown', 'inventory_observed', 'unlink_attempted', 'primary_absence_verified'].includes(reconstruction.operation_stage_code)) {
    failD941('D941_RECOVERY_BOUNDARY_CONTRADICTORY', 'caller crash boundary predates the protected operation stage')
  }
  if (record.semantic_actor?.role_code !== 'independent_verifier' || record.semantic_actor?.actor_kind_code !== 'service' ||
    record.persistence_actor?.role_code !== 'journal_broker' || record.persistence_actor?.actor_kind_code !== 'service' ||
    record.semantic_actor.identity_binding.binding_code === record.persistence_actor.identity_binding.binding_code) {
    failD941('D941_RECOVERY_ACTOR_REJECTED', 'classification requires separated independent-verifier and journal-broker actors')
  }
  let classificationCode
  if (controlStateCode !== 'linear_complete') classificationCode = 'human_decision_required'
  else if (inventoryStateCode === 'contradictory' || accessStateCode === 'contradictory') classificationCode = 'human_decision_required'
  else if (accessStateCode === 'active_or_unknown' || accessStateCode === 'termination_pending') classificationCode = 'retain_and_hold'
  else if (inventoryStateCode === 'incomplete' || inventoryStateCode === 'unavailable') classificationCode = 'reconciliation_required'
  else classificationCode = defaults[crashBoundaryCode]
  if (!classificationCode) failD941('D941_RECOVERY_BOUNDARY_UNKNOWN', 'unknown crash boundary')
  const result = sealD940Record({
    ...record,
    snapshot_digest_sha256: canonicalSha256(snapshot), snapshot, crash_boundary_code: crashBoundaryCode,
    inventory_state_code: inventoryStateCode, access_state_code: accessStateCode, control_state_code: controlStateCode,
    classification_code: classificationCode, action_execution_code: 'none_classification_only', recovery_authority_present: false,
  })
  validateD940Record({ contractSet: authorityContext.contractSet, record: result })
  const proof = Object.freeze({
    broker,
    record_digest_sha256: result.record_digest_sha256,
    reconstruction_digest_sha256: reconstruction.protected_inventory_digest_sha256,
    subject_identity_sha256: result.subject.subject_identity_sha256,
    ledger_head_digest_sha256: broker.head().digest,
    inventory_digest_sha256: broker.store.inventory().digest,
    resolver_runtime: metadata.resolverRuntime,
    resolver_response: metadata.resolution.compositeResponse,
    append_revalidate_by: metadata.resolution.compositeResponse.append_revalidate_by,
  })
  recoveryProofs.add(proof)
  recoveryRecordProofs.set(result, proof)
  return Object.freeze(result)
}

export function getD941RecoveryClassificationProof(record) { return recoveryRecordProofs.get(record) ?? null }

export function assertD941RecoveryClassificationProof(proof, record, broker) {
  if (!proof || !recoveryProofs.has(proof) || proof.record_digest_sha256 !== record.record_digest_sha256 ||
      proof.subject_identity_sha256 !== record.subject.subject_identity_sha256 || proof.reconstruction_digest_sha256 !== proof.inventory_digest_sha256 || proof.broker !== broker) {
    failD941('D941_RECOVERY_CLASSIFICATION_UNPROVEN', 'recovery assessment lacks a fixed protected-state classification proof')
  }
  proof.resolver_runtime.revalidateAtAppend({ compositeResponse: proof.resolver_response, completedAt: record.knowledge_boundary.persisted_at })
  if (proof.ledger_head_digest_sha256 !== broker.head().digest || proof.inventory_digest_sha256 !== broker.store.inventory().digest) {
    failD941('D941_RECOVERY_CLASSIFICATION_UNPROVEN', 'protected D9.4 state changed after recovery classification')
  }
  return true
}
