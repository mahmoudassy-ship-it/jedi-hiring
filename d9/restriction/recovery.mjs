import { canonicalSha256 } from '../control-plane/canonical.mjs'
import { sealD940Record, validateD940Record } from './contracts.mjs'
import { failD941 } from './errors.mjs'
import { assertD941LedgerBroker } from './ledger.mjs'

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

// Reconstructs only the durable facts needed to classify an interrupted
// operation. It never retries, repairs, restores, or writes a recovery record.
export function reconstructD941RecoveryState({ broker, subjectIdentitySha256 = null } = {}) {
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
    const incomplete = operation.execution.length > 0 && receipt === null
    return { operation, lastExecution, receipt, incomplete, latestSequence: Math.max(...operation.records.map((item) => item.record.knowledge_boundary?.receipt_sequence ?? 0)) }
  })
  const incomplete = summaries.filter((summary) => summary.incomplete)
  if (incomplete.length > 0 || incomplete.length > 1) ledgerStateCode = 'recovery_required'
  const selected = (incomplete.length === 1 ? incomplete[0] : summaries.sort((left, right) => right.latestSequence - left.latestSequence)[0]) ?? null
  const stage = selected?.lastExecution?.record_kind_code ?? (subjectRecords.some((item) => item.namespaceCode === 'access') ? 'access_shutdown' : 'none')
  if (incomplete.length > 1) ledgerStateCode = 'recovery_required'
  return Object.freeze({
    subject_identity_sha256: subjectIdentitySha256,
    ledger_state_code: ledgerStateCode,
    protected_inventory_digest_sha256: inventory.digest,
    receipt_count: receipts.length,
    unreceipted_target: unreceiptedTarget,
    operation_stage_code: stage,
    physical_namespace_state_code: selected?.lastExecution?.record_kind_code === 'primary_absence_verified' ? 'primary_absence_observed' : selected?.lastExecution ? 'unknown_requires_independent_reconciliation' : 'not_observed',
    classification_only: true,
  })
}

export function classifyD941Recovery({ authorityContext, record, crashBoundaryCode, snapshot, inventoryStateCode, accessStateCode, controlStateCode }) {
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
  return Object.freeze(result)
}
