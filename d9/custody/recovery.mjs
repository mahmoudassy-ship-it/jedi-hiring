import { canonicalize } from '../control-plane/canonical.mjs'
import { assertProtectedInventorySnapshot } from './admission.mjs'
import { canonicalRecord, validateD930Record } from './contracts.mjs'
import { failD931 } from './errors.mjs'

function getPath(value, dotted) {
  return dotted.split('.').reduce((current, key) => current?.[key], value)
}

function same(left, right) {
  return canonicalize(left) === canonicalize(right)
}

function predicateMatches(knowledge, observation, predicate) {
  return Object.entries(predicate).every(([pathCode, expected]) => {
    const root = pathCode.startsWith('knowledge.') ? knowledge : observation
    return same(getPath(root, pathCode.replace(/^(knowledge|observation)\./u, '')), expected)
  })
}

function assertObservationConsistency(classifications, observation) {
  for (const rule of classifications.recovery_observation_consistency_rules) {
    if (getPath(observation, rule.when.path_code) !== rule.when.value) continue
    for (const [pathCode, allowed] of Object.entries(rule.require_all)) {
      if (!allowed.includes(getPath(observation, pathCode))) {
        failD931('D931_RECOVERY_OBSERVATION_CONTRADICTION', `${rule.rule_code}/${pathCode}`)
      }
    }
  }
}

export function evaluateRecoveryClassification({ classifications, knowledge, observation }) {
  for (const guard of classifications.recovery_fail_closed_guards) {
    const root = guard.path_code.startsWith('knowledge.') ? knowledge : observation
    const actual = getPath(root, guard.path_code.replace(/^(knowledge|observation)\./u, ''))
    if (guard.unsafe_values.some((value) => same(value, actual))) {
      return classifications.recovery_decision_rules.find((rule) => rule.decision_rule_code === guard.decision_rule_code)
    }
  }
  assertObservationConsistency(classifications, observation)
  const result = classifications.recovery_decision_rules
    .slice()
    .sort((left, right) => left.priority - right.priority)
    .find((rule) => rule.match_any.some((predicate) => predicateMatches(knowledge, observation, predicate)))
  if (!result || result.action_execution_code !== 'none_classification_only') {
    failD931('D931_RECOVERY_MATRIX_INCOMPLETE', 'the frozen recovery matrix did not yield a classification-only result')
  }
  return result
}

export function createClassificationOnlyRecoveryAssessment({
  admissionResolver,
  journalBroker,
  snapshot,
  observation,
  context,
}) {
  const { classifications } = admissionResolver.contractSet
  assertProtectedInventorySnapshot(snapshot, context.subjectOperationId, context.subjectOperationNonce)
  const head = journalBroker.head(context.sourceTerminalJournalCode)
  if (!head || head.event_sequence !== snapshot.journalHead.event_sequence || head.record_digest_sha256 !== snapshot.journalHead.record_digest_sha256 || head.persisted_at !== snapshot.journalHead.persisted_at) {
    failD931('D931_RECOVERY_SNAPSHOT_STALE', 'protected inventory snapshot is not pinned to the exact current pre-append journal head')
  }
  if (!['operation_completed', 'recovery_required'].includes(head.semantic_assertion.event_kind_code)) {
    failD931('D931_RECOVERY_SOURCE_NOT_TERMINAL', 'classification requires an exact terminal source journal; D9.3.1 cannot invent recovery authority')
  }
  const inventory = Object.fromEntries(snapshot.inventoryHeads.map((item) => [item.inventory_code, {
    state_code: item.state_code,
    head_digest_sha256: item.head_digest_sha256,
  }]))
  const required = ['operation_control_inventory', 'capability_inventory', 'primary_receipt_inventory', 'custody_inventory', 'candidate_inventory', 'canonical_state_inventory', 'reference_inventory', 'hold_inventory', 'backup_inventory']
  if (required.some((code) => !inventory[code])) failD931('D931_RECOVERY_SNAPSHOT_INCOMPLETE', 'protected inventory snapshot omits a required inventory')
  const knowledge = {
    subject_operation_id: context.subjectOperationId,
    subject_operation_nonce: context.subjectOperationNonce,
    recovery_operation_id: context.recoveryOperationId,
    recovery_operation_nonce: context.recoveryOperationNonce,
    recovery_lock_storage_slot_code: 'permit_control_store',
    recovery_lock_owner_binding_code: context.recoveryLockOwnerBindingCode,
    recovery_lock_projection_sha256: context.recoveryLockProjectionSha256,
    recovery_lock_acquired_at: context.recoveryLockAcquiredAt,
    recovery_lock_expires_at: context.recoveryLockExpiresAt,
    scan_started_at: context.scanStartedAt,
    scan_completed_at: context.scanCompletedAt,
    snapshot_completeness_code: context.snapshotCompletenessCode,
    known_through_journal_code: context.sourceTerminalJournalCode,
    known_through_journal_sequence: head.event_sequence,
    known_through_journal_head_record_digest_sha256: head.record_digest_sha256,
    known_through_journal_head_persisted_at: head.persisted_at,
    ...inventory,
  }
  const selected = evaluateRecoveryClassification({ classifications, knowledge, observation })
  const recovery = {
    record_kind_code: 'classification_only_recovery_assessment',
    recovery_chain_code: context.recoveryChainCode,
    recovery_attempt_sequence: context.recoveryAttemptSequence,
    prior_attempt_terminal_record_digest_sha256: context.priorAttemptTerminalRecordDigestSha256,
    subject_operation_id: context.subjectOperationId,
    subject_operation_nonce: context.subjectOperationNonce,
    subject_bundle: context.subjectBundle,
    subject_artifact: context.subjectArtifact,
    subject_copy_code: context.subjectCopyCode,
    subject_backend_code: context.subjectBackendCode,
    subject_backend_reference: context.subjectBackendReference,
    source_terminal_journal_code: context.sourceTerminalJournalCode,
    source_terminal_journal_sequence: head.event_sequence,
    source_terminal_journal_head_record_digest_sha256: head.record_digest_sha256,
    source_terminal_journal_persisted_at: head.persisted_at,
    source_terminal_error_code: context.sourceTerminalErrorCode,
    knowledge_snapshot: knowledge,
    observation: structuredClone(observation),
    decision_rule_code: selected.decision_rule_code,
    classification_code: selected.classification_code,
    next_step_code: selected.next_step_code,
    classification_outcome_code: selected.classification_outcome_code,
    blocking_reason_codes: [...selected.blocking_reason_codes],
    action_execution_code: 'none_classification_only',
  }
  const semantic = canonicalRecord({
    ...structuredClone(context.semanticBase),
    format: 'jedi-atlas-operation-journal-semantic-assertion',
    format_version: '1.0.0',
    record_code: `recovery.assessment.${context.recoveryChainCode}.${context.recoveryAttemptSequence}`,
    operation_mode_code: 'recovery', operation_id: context.recoveryOperationId,
    operation_nonce: context.recoveryOperationNonce, event_kind_code: 'stage_succeeded',
    stage_code: 'reconciliation', component_binding_code: context.componentBindingCode,
    custody_finalization: null, integrity_access: null, artifact_backup_receipt: null,
    prior_database_backup_receipt: null, final_backup_receipt: null, recovery,
    canonical_effect_code: 'none_verified', result_outcome_code: null, error_code: null,
    retryability_code: 'human_decision_required', recovery_class_code: 'none', rows_delta: null,
    objects_delta: null, object_disposition_code: 'none', candidate_file_sha256: null,
    candidate_file_seal_record_digest_sha256: null, backup_inventory_sha256: null,
    event_at: context.eventAt, record_digest_sha256: null,
  })
  validateD930Record({ contractSet: admissionResolver.contractSet, record: semantic, bindingRoleResolver: admissionResolver.bindingRole })
  return Object.freeze({ semantic, selected: structuredClone(selected), actionExecuted: false })
}
