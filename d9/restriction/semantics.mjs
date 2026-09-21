import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { assertD941AccessEffectProof } from './access-control.mjs'
import { assertD941PrimaryEffectProof } from './primary-delete.mjs'
import { assertD941RecoveryClassificationProof } from './recovery.mjs'
import { failD941 } from './errors.mjs'

function actorEquals(left, right) {
  return left !== null && right !== null && canonicalize(left) === canonicalize(right)
}

function approvalScope(record) {
  return canonicalSha256({
    record_kind_code: record.record_kind_code,
    subject_identity_sha256: record.subject.subject_identity_sha256,
    operation_id: record.operation_id,
    operation_nonce: record.operation_nonce,
    reason_category_code: record.reason_category_code,
    restriction_scope_code: record.restriction_scope_code,
    basis_record_digest_sha256: record.basis_record_digest_sha256,
    corrects_record_digest_sha256: record.corrects_record_digest_sha256,
    effective_at: record.knowledge_boundary.effective_at,
  })
}

function assertHumanApprovals({ record, semanticSession, approvalSessions, classifications }) {
  const expected = record.authorization_scope_sha256 ?? approvalScope(record)
  if (approvalSessions.length !== record.human_approvals.length) failD941('D941_APPROVAL_SESSION_MISSING', 'every approval requires an authenticated human session')
  const principals = new Set()
  const bindings = new Set()
  for (const [index, approval] of record.human_approvals.entries()) {
    const session = approvalSessions[index]
    if (!actorEquals(approval.actor, session?.actor)) failD941('D941_ACTOR_SESSION_MISMATCH', `approval ${index} differs from its authenticated session`)
    if (approval.actor.actor_kind_code !== 'human' || approval.decision_code !== 'approve' || approval.scope_sha256 !== expected ||
      approval.record_digest_sha256 !== canonicalSha256(approval, { excludedTopLevelField: 'record_digest_sha256' }) ||
      !(record.knowledge_boundary.effective_at <= approval.decided_at && approval.decided_at <= record.knowledge_boundary.recorded_at) ||
      approval.expires_at === null || !(approval.decided_at < approval.expires_at) || approval.expires_at <= record.knowledge_boundary.persisted_at ||
      (record.authorization_expires_at !== null && approval.expires_at < record.authorization_expires_at) ||
      approval.actor.principal_code === record.semantic_actor.principal_code) {
      failD941('D941_APPROVAL_INVALID', 'approval scope, digest, chronology, expiry, identity, or separation is invalid')
    }
    if (principals.has(approval.actor.principal_code) || bindings.has(approval.actor.identity_binding.binding_code)) failD941('D941_APPROVAL_NOT_DISTINCT', 'human approvals must use distinct principals and bindings')
    principals.add(approval.actor.principal_code); bindings.add(approval.actor.identity_binding.binding_code)
  }
  const rule = classifications.action_actor_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  if (!rule || !rule.semantic_role_codes.includes(record.semantic_actor.role_code) || !rule.semantic_actor_kind_codes.includes(record.semantic_actor.actor_kind_code)) failD941('D941_SEMANTIC_ACTOR_FORBIDDEN', 'control actor is outside the frozen action matrix')
  if (principals.size < rule.minimum_distinct_human_approvals) failD941('D941_APPROVAL_COUNT_INSUFFICIENT', 'insufficient distinct human approvals')
  for (const role of rule.required_approval_role_codes) if (!record.human_approvals.some((approval) => approval.actor.role_code === role)) failD941('D941_APPROVAL_ROLE_MISSING', `missing required ${role} approval`)
  if (record.record_kind_code === 'deletion_authorized') {
    if (record.authorization_scope_sha256 !== canonicalSha256(record.authorization_scope) || record.authorization_scope.valid_until !== record.authorization_expires_at ||
      record.authorization_scope.valid_from > record.knowledge_boundary.persisted_at || record.authorization_expires_at <= record.knowledge_boundary.persisted_at ||
      record.human_approvals.some((approval) => approval.actor.principal_code === record.authorization_scope.requester_principal_code)) failD941('D941_AUTHORIZATION_INVALID', 'deletion authorization scope or requester separation is invalid')
    const deletion = classifications.deletion_approval_rules.find((entry) => entry.reason_category_code === record.reason_category_code)
    if (!deletion || deletion.authorization_code !== 'eligible_for_human_decision') failD941('D941_DELETION_REASON_BLOCKED', 'reason is not eligible for deletion')
    for (const role of deletion.required_human_role_codes) if (!record.human_approvals.some((approval) => approval.actor.role_code === role)) failD941('D941_APPROVAL_ROLE_MISSING', `deletion gate lacks ${role}`)
    if (principals.size < deletion.minimum_distinct_humans) failD941('D941_APPROVAL_COUNT_INSUFFICIENT', 'deletion gate lacks distinct humans')
  }
  if (!actorEquals(record.semantic_actor, semanticSession.actor)) failD941('D941_ACTOR_SESSION_MISMATCH', 'semantic actor differs from authenticated session')
}

function accessTargetIdentity(record) {
  return canonicalSha256(record.access_target_kind_code === 'unconsumed_capability'
    ? { access_target_kind_code: record.access_target_kind_code, capability_record_digest_sha256: record.capability_record_digest_sha256, capability_leaf_record_digest_sha256: record.capability_leaf_record_digest_sha256 }
    : { access_target_kind_code: record.access_target_kind_code, descriptor_lifecycle_record_digest_sha256: record.descriptor_lifecycle_record_digest_sha256, receiver_process_instance_code: record.receiver_process_instance_code })
}

function assertControlMatrix({ classifications, record, existingRecords, operationalProfile }) {
  const rule = classifications.control_record_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  if (!rule || Buffer.byteLength(record.reason_summary, 'utf8') > 512 || record.reason_summary.trim().length === 0 ||
    rule.restriction_scope_required !== (record.restriction_scope_code !== null) || rule.basis_required !== (record.basis_record_digest_sha256 !== null) ||
    rule.clearance_reference_required !== (record.clearance_reference !== null) || rule.correction_required !== (record.corrects_record_digest_sha256 !== null) ||
    rule.propagation_required !== (record.propagates_from_subject_identity_sha256 !== null) ||
    rule.authorization_required !== (record.authorization_scope !== null && record.authorization_scope_sha256 !== null && record.authorization_expires_at !== null) ||
    (!rule.authorization_required && (record.authorization_scope !== null || record.authorization_scope_sha256 !== null || record.authorization_expires_at !== null))) {
    failD941('D941_CONTROL_MATRIX_REJECTED', 'control fields do not match the frozen record-kind matrix')
  }
  if (record.record_kind_code === 'control_corrected') {
    if (record.corrected_record_kind_code === null || record.withdrawal_effect_code !== null) failD941('D941_CORRECTION_SEMANTICS_REJECTED', 'correction fields are inconsistent')
  } else if (record.record_kind_code === 'control_withdrawn') {
    if (record.corrected_record_kind_code === null || record.withdrawal_effect_code !== 'void_for_derived_projection_keep_history') failD941('D941_CORRECTION_SEMANTICS_REJECTED', 'withdrawal fields are inconsistent')
  } else if (record.corrected_record_kind_code !== null || record.withdrawal_effect_code !== null) failD941('D941_CORRECTION_SEMANTICS_REJECTED', 'ordinary control invents correction fields')
  if (record.record_kind_code === 'clearance_revoked') failD941('D941_CLEARANCE_RESOLVER_UNAVAILABLE', 'synthetic runtime has no protected D9.0.1 clearance graph resolver')
  const sameStream = existingRecords.filter((item) => item.format === record.format && item.chain.stream_code === record.chain.stream_code).sort((a, b) => a.chain.sequence - b.chain.sequence)
  const prior = sameStream.at(-1) ?? null
  const priorSemanticKind = prior?.record_kind_code === 'control_corrected' ? prior.corrected_record_kind_code : (prior?.record_kind_code ?? 'none')
  const transition = classifications.control_transition_rules.find((entry) => entry.from_code === priorSemanticKind && entry.to_code === record.record_kind_code)
  if (!transition && !['control_corrected', 'control_withdrawn'].includes(record.record_kind_code)) failD941('D941_CONTROL_TRANSITION_REJECTED', 'control transition is absent from the frozen matrix')
  if (transition?.same_restriction_scope && prior.restriction_scope_code !== record.restriction_scope_code) failD941('D941_CONTROL_TRANSITION_REJECTED', 'release changes restriction scope')
  if (transition?.same_reason_category && prior.reason_category_code !== record.reason_category_code) failD941('D941_CONTROL_TRANSITION_REJECTED', 'release changes reason category')
  if (record.basis_record_digest_sha256 !== null) {
    const basis = existingRecords.find((item) => item.record_digest_sha256 === record.basis_record_digest_sha256)
    if (!basis || basis.subject.subject_identity_sha256 !== record.subject.subject_identity_sha256 || basis.knowledge_boundary.persisted_at >= record.knowledge_boundary.persisted_at) failD941('D941_CONTROL_BASIS_UNRESOLVED', 'control basis is missing, later, or belongs to another subject')
  }
  if (prior && !['control_corrected', 'control_withdrawn'].includes(record.record_kind_code)) {
    const expectedBasis = record.record_kind_code === 'deletion_authorization_revoked' && priorSemanticKind === 'tombstone_applied'
      ? sameStream.find((item) => item.record_kind_code === 'deletion_authorized')?.record_digest_sha256
      : prior.record_digest_sha256
    if (transition && record.basis_record_digest_sha256 !== expectedBasis) failD941('D941_CONTROL_TRANSITION_REJECTED', 'control successor does not cite the exact frozen transition basis')
  }
  if (['control_corrected', 'control_withdrawn'].includes(record.record_kind_code)) {
    const target = prior
    const targetSemanticKind = target?.record_kind_code === 'control_corrected' ? target.corrected_record_kind_code : target?.record_kind_code
    const rule = classifications.correction_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
    if (!target || record.corrects_record_digest_sha256 !== target.record_digest_sha256 || !rule?.target_codes.includes(targetSemanticKind) ||
        record.corrected_record_kind_code !== targetSemanticKind ||
        record.subject.subject_identity_sha256 !== target.subject.subject_identity_sha256 ||
        record.operation_id !== target.operation_id || record.operation_nonce !== target.operation_nonce ||
        record.knowledge_boundary.effective_at !== target.knowledge_boundary.effective_at) {
      failD941('D941_CORRECTION_TARGET_REJECTED', 'correction/withdrawal must target the current eligible leaf at the same effective point')
    }
  }
  if (record.record_kind_code === 'deletion_authorized') {
    const maximum = operationalProfile.settings.maximum_authorization_lifetime_ms
    if (Date.parse(record.authorization_expires_at) - Date.parse(record.authorization_scope.valid_from) > maximum) failD941('D941_AUTHORIZATION_LIFETIME_EXCEEDED', 'authorization exceeds the frozen maximum lifetime')
  }
}

function assertExecutionMatrix({ classifications, record, existingRecords, runtimeProof, allowPendingEffect }) {
  const rule = classifications.deletion_execution_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  if (!rule || record.semantic_actor.role_code !== rule.semantic_role_code || record.execution.method_code !== rule.method_code || record.execution.outcome_code !== rule.required_outcome_code) failD941('D941_EXECUTION_MATRIX_REJECTED', 'execution record violates its frozen method/actor matrix')
  if (record.record_kind_code !== 'reconciliation_required' && record.access_shutdown_state_code !== 'confirmed') failD941('D941_ACCESS_SHUTDOWN_REQUIRED', 'execution requires confirmed access shutdown')
  const sameStream = existingRecords.filter((item) => item.format === record.format && item.chain.stream_code === record.chain.stream_code).sort((a, b) => a.chain.sequence - b.chain.sequence)
  const prior = sameStream.at(-1) ?? null
  const priorState = prior === null ? 'none' : ({ execution_started: 'execution_started', inventory_observed: 'inventory_observed', unlink_attempted: 'primary_name_removed' }[prior.record_kind_code] ?? 'recovery_required')
  const transition = classifications.deletion_transition_rules.find((entry) => entry.from_code === priorState && entry.record_kind_code === record.record_kind_code)
  if (!transition) failD941('D941_EXECUTION_TRANSITION_REJECTED', 'deletion execution transition is absent from the frozen matrix')
  const snapshot = record.safety_snapshot
  if (snapshot.journal_namespace_code !== classifications.journal_rules.journal_namespace_code || snapshot.active_hold_count !== 0 || snapshot.unknown_or_conflicting_control_count !== 0 ||
    snapshot.snapshot_sha256 !== canonicalSha256(Object.fromEntries(Object.entries(snapshot).filter(([key]) => key !== 'snapshot_sha256'))) ||
    snapshot.known_through_persisted_at > record.knowledge_boundary.recorded_at || snapshot.known_through_receipt_sequence >= record.knowledge_boundary.receipt_sequence) failD941('D941_SAFETY_SNAPSHOT_REJECTED', 'execution safety snapshot is blocking, stale, or malformed')
  for (const digest of [record.deletion_authorization_record_digest_sha256, record.tombstone_record_digest_sha256]) {
    if (!existingRecords.some((item) => item.record_digest_sha256 === digest && item.subject.subject_identity_sha256 === record.subject.subject_identity_sha256)) failD941('D941_EXECUTION_BASIS_UNRESOLVED', 'execution authorization or tombstone is unresolved')
  }
  if (['inventory_observed', 'unlink_attempted', 'unlink_failed', 'primary_absence_verified'].includes(record.record_kind_code)) {
    const inventory = record.inventory
    if (!inventory.inventory_complete || inventory.open_descriptors || inventory.hard_links || inventory.unexpected_replicas || inventory.temporary_objects || !inventory.parent_directory_opened_no_follow || inventory.symlink_observed) failD941('D941_INVENTORY_BLOCKS_DELETION', 'inventory is incomplete or unsafe')
    if (record.record_kind_code === 'primary_absence_verified') {
      if (inventory.target_file_type_code !== 'absent' || inventory.target_opened_no_follow || [inventory.target_device, inventory.target_inode, inventory.observed_target_sha256, inventory.observed_target_byte_length, inventory.observed_target_link_count].some((value) => value !== null) || inventory.prior_target_observation_record_digest_sha256 === null) failD941('D941_ABSENCE_INVENTORY_INVALID', 'absence inventory is contradictory')
    } else if (inventory.target_file_type_code !== 'regular_file' || !inventory.target_opened_no_follow || inventory.observed_target_sha256 !== record.subject.subject_payload.artifact.sha256 || inventory.observed_target_byte_length !== record.subject.subject_payload.artifact.byte_length || inventory.observed_target_link_count !== 1) failD941('D941_OBSERVED_TARGET_MISMATCH', 'inventory does not resolve the exact artifact')
    }
    if (['unlink_attempted', 'primary_absence_verified'].includes(record.record_kind_code)) {
      if (allowPendingEffect !== true) assertD941PrimaryEffectProof(runtimeProof, record)
    }
  if (record.record_kind_code === 'unlink_attempted' && (!record.execution.target_name_removed || !record.execution.directory_synced || !record.execution.reopened_target_absent)) failD941('D941_UNLINK_RESULT_CONTRADICTORY', 'unlink result overstates absence verification')
  if (record.record_kind_code === 'primary_absence_verified' && (!record.execution.target_name_removed || !record.execution.directory_synced || !record.execution.reopened_target_absent || record.inventory.matching_primary_names !== 0)) failD941('D941_PRIMARY_ABSENCE_NOT_VERIFIED', 'absence result is incomplete')
}

export function assertD941RuntimeSemantics({ contractSet, operationalProfile, record, semanticSession, persistenceSession, approvalSessions, existingRecords, broker = null, runtimeProof = null, allowPendingEffect = false }) {
  if (!actorEquals(record.persistence_actor, persistenceSession.actor) || persistenceSession.actor.role_code !== 'journal_broker') failD941('D941_PERSISTENCE_ACTOR_INVALID', 'persistence actor must be the authenticated journal broker')
  const classifications = contractSet.classifications
  if (record.format === 'jedi-atlas-custody-control-record') {
    assertControlMatrix({ classifications, record, existingRecords, operationalProfile })
    assertHumanApprovals({ record, semanticSession, approvalSessions, classifications })
    return
  }
  if (approvalSessions.length !== 0) failD941('D941_APPROVAL_UNEXPECTED', 'non-control records cannot carry out-of-band approval sessions')
  if (record.format === 'jedi-atlas-access-revocation-record') {
    if (!actorEquals(record.semantic_actor, semanticSession.actor)) failD941('D941_ACTOR_SESSION_MISMATCH', 'access actor differs from authenticated session')
    const rule = classifications.access_revocation_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
    const capabilityPresent = record.capability_record_digest_sha256 !== null && record.capability_leaf_record_digest_sha256 !== null
    const descriptorPresent = record.descriptor_lifecycle_record_digest_sha256 !== null && record.receiver_process_instance_code !== null
    if (!rule || !rule.semantic_role_codes.includes(record.semantic_actor.role_code) || !rule.semantic_actor_kind_codes.includes(record.semantic_actor.actor_kind_code) || record.access_target_identity_sha256 !== accessTargetIdentity(record) || rule.capability_required !== capabilityPresent || rule.descriptor_required !== descriptorPresent) failD941('D941_ACCESS_MATRIX_REJECTED', 'access record violates its frozen actor or target matrix')
    if ((record.access_target_kind_code === 'unconsumed_capability') !== capabilityPresent || (record.access_target_kind_code === 'issued_descriptor') !== descriptorPresent) failD941('D941_ACCESS_MATRIX_REJECTED', 'access target kind and exact reference fields disagree')
    const sameStream = existingRecords.filter((item) => item.format === record.format && item.chain.stream_code === record.chain.stream_code).sort((a, b) => a.chain.sequence - b.chain.sequence)
    const prior = sameStream.at(-1) ?? null
    const validTransition = record.record_kind_code === 'capability_revoked'
      ? prior === null
      : record.record_kind_code === 'descriptor_termination_requested'
        ? prior === null
        : ['descriptor_termination_confirmed', 'descriptor_termination_failed'].includes(record.record_kind_code) && prior?.record_kind_code === 'descriptor_termination_requested'
    if (!validTransition) failD941('D941_ACCESS_TRANSITION_REJECTED', 'access transition is absent from the frozen matrix')
    const terminal = ['sender_close_state_code', 'receiver_termination_state_code', 'descriptor_close_state_code', 'termination_disposition_code']
    if (record.record_kind_code === 'descriptor_termination_confirmed' && terminal.some((field) => record[field] === null || record[field] === 'unknown')) failD941('D941_DESCRIPTOR_TERMINATION_UNCONFIRMED', 'descriptor terminal facts are incomplete')
    if (record.record_kind_code === 'descriptor_termination_failed' && (terminal.some((field) => record[field] === null) || terminal.every((field) => record[field] !== 'unknown'))) failD941('D941_DESCRIPTOR_FAILURE_OVERSTATED', 'failed descriptor termination must have no nulls and at least one unknown terminal fact')
    if (!['descriptor_termination_confirmed', 'descriptor_termination_failed'].includes(record.record_kind_code) && terminal.some((field) => record[field] !== null)) failD941('D941_ACCESS_MATRIX_REJECTED', 'nonterminal access record invents terminal fields')
    if (['capability_revoked', 'descriptor_termination_confirmed'].includes(record.record_kind_code) && !allowPendingEffect) assertD941AccessEffectProof(runtimeProof, record)
    const trigger = existingRecords.find((item) => item.record_digest_sha256 === record.trigger_control_record_digest_sha256)
    if (!trigger || trigger.subject.subject_identity_sha256 !== record.subject.subject_identity_sha256) failD941('D941_ACCESS_TRIGGER_UNRESOLVED', 'access trigger control is unresolved')
    return
  }
  if (record.format === 'jedi-atlas-deletion-execution-record') {
    if (!actorEquals(record.semantic_actor, semanticSession.actor)) failD941('D941_ACTOR_SESSION_MISMATCH', 'execution actor differs from authenticated session')
    assertExecutionMatrix({ classifications, record, existingRecords, runtimeProof, allowPendingEffect })
    return
  }
  if (record.format === 'jedi-atlas-deletion-receipt') {
    if (!actorEquals(record.independent_verifier, semanticSession.actor) || record.independent_verifier.role_code !== 'independent_verifier' || record.executor.role_code !== 'deletion_executor' || record.executor.identity_binding.binding_code === record.independent_verifier.identity_binding.binding_code) failD941('D941_RECEIPT_ROLE_REJECTED', 'receipt actors violate executor/verifier separation')
    const mandatory = ['no_complete_erasure_claim', 'no_backup_erasure_claim', 'no_derived_copy_erasure_claim', 'no_replica_erasure_claim', 'no_open_descriptor_erasure_claim', 'no_storage_medium_overwrite_claim', 'no_legal_compliance_claim', 'compromised_kernel_or_root_out_of_scope', 'observation_is_time_bounded']
    const remaining = ['backup', 'derived', 'open_descriptor', 'replica', 'temporary', 'unknown']
    if (record.complete_erasure_claimed || record.backup_erasure_claimed || record.legal_compliance_claimed || mandatory.some((item) => !record.limitations.includes(item)) || JSON.stringify(record.remaining_copy_classes) !== JSON.stringify(remaining) ||
      !(record.completed_at <= record.knowledge_boundary.recorded_at && record.knowledge_boundary.recorded_at <= record.knowledge_boundary.persisted_at)) failD941('D941_DELETE_RECEIPT_OVERCLAIM', 'receipt exceeds or fails to state the bounded primary-name claim')
    const execution = existingRecords.find((item) => item.record_digest_sha256 === record.execution_record_digest_sha256 && item.format === 'jedi-atlas-deletion-execution-record')
    const verification = existingRecords.find((item) => item.record_digest_sha256 === record.verification_record_digest_sha256 && item.format === 'jedi-atlas-deletion-execution-record')
    const request = existingRecords.find((item) => item.record_digest_sha256 === record.deletion_request_record_digest_sha256 && item.record_kind_code === 'deletion_requested')
    const authorization = existingRecords.find((item) => item.record_digest_sha256 === record.deletion_authorization_record_digest_sha256 && item.record_kind_code === 'deletion_authorized')
    const tombstone = existingRecords.find((item) => item.record_digest_sha256 === record.tombstone_record_digest_sha256 && item.record_kind_code === 'tombstone_applied')
    if (!execution || !verification || execution.record_kind_code !== 'unlink_attempted' || verification.record_kind_code !== 'primary_absence_verified' ||
        execution.subject.subject_identity_sha256 !== record.subject.subject_identity_sha256 || verification.subject.subject_identity_sha256 !== record.subject.subject_identity_sha256 ||
        !request || !authorization || !tombstone || request.operation_id !== record.operation_id || authorization.operation_id !== record.operation_id || tombstone.operation_id !== record.operation_id ||
        request.operation_nonce !== record.operation_nonce || authorization.operation_nonce !== record.operation_nonce || tombstone.operation_nonce !== record.operation_nonce ||
        record.authorization_scope_sha256 !== authorization.authorization_scope_sha256 || verification.knowledge_boundary.persisted_at > record.completed_at ||
        record.d930_operational_profile_record_digest_sha256 !== execution.d930_operational_profile_record_digest_sha256 ||
        record.d930_primary_durability_receipt_sha256 !== execution.d930_primary_durability_receipt_sha256 ||
        record.safety_snapshot_sha256 !== execution.safety_snapshot.snapshot_sha256 ||
        record.control_ledger_head_receipt_digest_sha256 !== execution.safety_snapshot.control_ledger_head_receipt_digest_sha256 ||
        canonicalize(record.executor) !== canonicalize(execution.semantic_actor) || canonicalize(record.independent_verifier) !== canonicalize(verification.semantic_actor) ||
        execution.operation_id !== record.operation_id || execution.operation_nonce !== record.operation_nonce || verification.operation_id !== record.operation_id || verification.operation_nonce !== record.operation_nonce) failD941('D941_RECEIPT_BASIS_UNRESOLVED', 'receipt actors or operation context do not resolve to the exact execution and verification bases')
    return
  }
  if (record.format === 'jedi-atlas-backup-coordination-record') {
    if (!actorEquals(record.semantic_actor, semanticSession.actor)) failD941('D941_ACTOR_SESSION_MISMATCH', 'backup actor differs from authenticated session')
    const rule = classifications.backup_coordination_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
    const basis = existingRecords.find((item) => item.record_digest_sha256 === record.basis_control_record_digest_sha256)
    if (!rule || rule.directive_code !== record.directive_code || !rule.semantic_role_codes.includes(record.semantic_actor.role_code) || record.d95_execution_authority_code !== 'unreachable_until_separately_approved_d9_5' || record.d95_backup_receipt_record_digest_sha256 !== null || !basis || !rule.basis_record_kind_codes.includes(basis.record_kind_code) || basis.subject.subject_identity_sha256 !== record.subject.subject_identity_sha256) failD941('D941_BACKUP_MATRIX_REJECTED', 'backup record violates the frozen D9.5-unreachable matrix')
    return
  }
  if (record.format === 'jedi-atlas-d940-recovery-assessment') {
    let derived
    if (record.control_state_code !== 'linear_complete' || record.inventory_state_code === 'contradictory' || record.access_state_code === 'contradictory') derived = 'human_decision_required'
    else if (['active_or_unknown', 'termination_pending'].includes(record.access_state_code)) derived = 'retain_and_hold'
    else if (['incomplete', 'unavailable'].includes(record.inventory_state_code)) derived = 'reconciliation_required'
    else derived = classifications.recovery_boundary_defaults.find((entry) => entry.crash_boundary_code === record.crash_boundary_code)?.classification_code
    if (!actorEquals(record.semantic_actor, semanticSession.actor) || record.semantic_actor.role_code !== 'independent_verifier' || record.semantic_actor.actor_kind_code !== 'service' || record.action_execution_code !== 'none_classification_only' || record.recovery_authority_present !== false || record.snapshot_digest_sha256 !== canonicalSha256(record.snapshot) || record.classification_code !== derived) failD941('D941_RECOVERY_ACTOR_REJECTED', 'recovery actor, snapshot, or deterministic classification is invalid')
    assertD941RecoveryClassificationProof(runtimeProof, record, broker)
    return
  }
  failD941('D941_LEDGER_TARGET_UNSUPPORTED', 'record format has no runtime semantic verifier')
}
