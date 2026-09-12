import { canonicalRecord } from './contracts.mjs'
import { assertProtectedJournalBroker } from './journal.mjs'
import { failD931 } from './errors.mjs'

function supportingRequest({ record, kindCode, journalCode, journalBindingCode, journalProfileDigest, createdAt }) {
  const senderBindingCode = kindCode === 'integrity_access_lifecycle_record' ? record.producer_binding_code : record.sender_binding_code
  return canonicalRecord({
    format: 'jedi-atlas-operation-journal-broker-message', format_version: '1.0.0',
    record_code: `support.request.${record.record_code}`, message_kind_code: 'persist_supporting_request',
    operation_id: record.operation_id, operation_nonce: record.operation_nonce,
    request_id: `support.${record.record_code}`, sender_binding_code: senderBindingCode, recipient_binding_code: journalBindingCode,
    runtime_profile_record_digest_sha256: record.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: record.identity_bindings_record_digest_sha256,
    d930_journal_profile_record_digest_sha256: journalProfileDigest, request_record_digest_sha256: null, created_at: createdAt,
    payload: { journal_code: journalCode, expected_event_sequence: null, expected_previous_event_record_digest_sha256: null,
      supporting_record_kind_code: kindCode, supporting_record: record, supporting_record_digest_sha256: record.record_digest_sha256,
      semantic_assertion: null, semantic_assertion_record_digest_sha256: null, persisted_record_code: null, persisted_record_digest_sha256: null,
      persisted_at: null, outcome_code: null, error_code: null },
    record_digest_sha256: null,
  })
}

export async function persistSupportingRecord({ journalPeerProvider, journalBroker, record, kindCode, journalCode, journalBindingCode, journalProfileDigest, createdAt }) {
  assertProtectedJournalBroker(journalBroker)
  if (typeof journalPeerProvider !== 'function') failD931('D931_BROKER_AUTHORITY_REJECTED', 'journal request requires its authenticated IPC peer provider')
  const request = supportingRequest({ record, kindCode, journalCode, journalBindingCode, journalProfileDigest, createdAt })
  return journalBroker.persistSupporting(request, await journalPeerProvider(request))
}

export async function appendOperationStarted({ journalPeerProvider, journalBroker, journalCode, journalBindingCode, componentBindingCode, componentExecutableSha256, journalProfileDigest, operationModeCode, operationId, operationNonce, authorizationPermitDigest = null, authorizationBundleSealDigest, bundle, targetLogicalState, runtimeProfileDigest, identityBindingsDigest, eventAt, requestCreatedAt }) {
  const semantic = canonicalRecord({
    format: 'jedi-atlas-operation-journal-semantic-assertion', format_version: '1.0.0',
    record_code: `semantic.start.${operationId}`, operation_mode_code: operationModeCode, operation_id: operationId, operation_nonce: operationNonce,
    event_kind_code: 'operation_started', stage_code: 'startup', component_binding_code: componentBindingCode, component_executable_sha256: componentExecutableSha256,
    runtime_profile_record_digest_sha256: runtimeProfileDigest, identity_bindings_record_digest_sha256: identityBindingsDigest,
    d930_journal_profile_record_digest_sha256: journalProfileDigest, authorization_permit_record_digest_sha256: authorizationPermitDigest,
    authorization_bundle_seal_record_digest_sha256: authorizationBundleSealDigest, prepromotion_authorization_record_digest_sha256: null,
    bundle: structuredClone(bundle), target_logical_state: structuredClone(targetLogicalState), observed_logical_state: null,
    canonical_effect_code: 'none_verified', result_outcome_code: null, error_code: null, retryability_code: 'never', recovery_class_code: 'none',
    rows_delta: { atlas_evidence_bundle_receipts: 0, atlas_retrieval_locations: 0, atlas_artifacts: 0, atlas_retrieval_events: 0, atlas_retrieval_redirects: 0, atlas_artifact_custody_events: 0, atlas_processing_runs: 0, atlas_processing_outputs: 0, atlas_unverified_candidate_occurrences: 0 }, objects_delta: { prepared: 0, reused: 0, orphaned: 0 }, object_disposition_code: 'none', candidate_file_sha256: null,
    candidate_file_seal_record_digest_sha256: null, backup_inventory_sha256: null, custody_finalization: null, integrity_access: null,
    artifact_backup_receipt: null, prior_database_backup_receipt: null, final_backup_receipt: null, event_at: eventAt, recovery: null, record_digest_sha256: null,
  })
  const request = canonicalRecord({
    format: 'jedi-atlas-operation-journal-broker-message', format_version: '1.0.0', record_code: `append.${semantic.record_code}`, message_kind_code: 'append_request',
    operation_id: operationId, operation_nonce: operationNonce, request_id: `append.${semantic.record_code}`, sender_binding_code: componentBindingCode, recipient_binding_code: journalBindingCode,
    runtime_profile_record_digest_sha256: runtimeProfileDigest, identity_bindings_record_digest_sha256: identityBindingsDigest, d930_journal_profile_record_digest_sha256: journalProfileDigest,
    request_record_digest_sha256: null, created_at: requestCreatedAt,
    payload: { journal_code: journalCode, expected_event_sequence: 1, expected_previous_event_record_digest_sha256: null, supporting_record_kind_code: null, supporting_record: null, supporting_record_digest_sha256: null, semantic_assertion: semantic, semantic_assertion_record_digest_sha256: semantic.record_digest_sha256, persisted_record_code: null, persisted_record_digest_sha256: null, persisted_at: null, outcome_code: null, error_code: null },
    record_digest_sha256: null,
  })
  if (typeof journalPeerProvider !== 'function') failD931('D931_BROKER_AUTHORITY_REJECTED', 'journal append requires its authenticated IPC peer provider')
  const acknowledgement = journalBroker.appendSemantic(request, await journalPeerProvider(request))
  return Object.freeze({ semantic, request, acknowledgement })
}

export async function appendCustodyFinalization({
  journalBroker,
  journalPeerProvider,
  journalCode,
  journalBindingCode,
  custodyAdapterBindingCode,
  custodyAdapterExecutableSha256,
  journalProfileDigest,
  operationModeCode = 'document_import',
  targetLogicalState,
  exchanges,
  publishResult,
  supportingAcks,
  eventAt,
  requestCreatedAt,
}) {
  assertProtectedJournalBroker(journalBroker)
  if (!Array.isArray(exchanges) || exchanges.length !== 4 || !Array.isArray(supportingAcks) || supportingAcks.length !== 8) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody journal requires four exact exchanges and eight supporting acknowledgements')
  const operationCodes = ['open_staged', 'prepare', 'verify_prepared', 'publish_no_replace']
  for (const [index, pair] of exchanges.entries()) {
    if (pair.request.operation_code !== operationCodes[index] || pair.response.operation_code !== operationCodes[index] || pair.response.request_record_digest_sha256 !== pair.request.record_digest_sha256) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody exchange order or request binding differs')
  }
  const presentedAcks = new Map(supportingAcks.map((entry) => [entry.payload.supporting_record_digest_sha256, entry.record_digest_sha256]))
  const ackByRecord = new Map()
  for (const pair of exchanges) for (const record of [pair.request, pair.response]) {
    const resolved = journalBroker.resolveSupportingAck(record.record_digest_sha256)
    if (resolved.record.record_digest_sha256 !== record.record_digest_sha256 || presentedAcks.get(record.record_digest_sha256) !== resolved.response.record_digest_sha256) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody exchange lacks its exact protected durable acknowledgement')
    ackByRecord.set(record.record_digest_sha256, resolved.response.record_digest_sha256)
  }
  const publish = exchanges.at(-1)
  const semantic = canonicalRecord({
    format: 'jedi-atlas-operation-journal-semantic-assertion', format_version: '1.0.0',
    record_code: `semantic.custody.${publish.request.operation_id}`, operation_mode_code: operationModeCode,
    operation_id: publish.request.operation_id, operation_nonce: publish.request.operation_nonce,
    event_kind_code: 'custody_object_durable', stage_code: 'custody_prepare',
    component_binding_code: custodyAdapterBindingCode, component_executable_sha256: custodyAdapterExecutableSha256,
    runtime_profile_record_digest_sha256: publish.request.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: publish.request.identity_bindings_record_digest_sha256,
    d930_journal_profile_record_digest_sha256: journalProfileDigest,
    authorization_permit_record_digest_sha256: null,
    authorization_bundle_seal_record_digest_sha256: publish.request.payload.custody_intent.bundle_seal_record_digest_sha256,
    prepromotion_authorization_record_digest_sha256: null,
    bundle: publish.request.payload.custody_intent.bundle,
    target_logical_state: structuredClone(targetLogicalState), observed_logical_state: null,
    canonical_effect_code: 'none_verified', result_outcome_code: null, error_code: null,
    retryability_code: 'never', recovery_class_code: 'none', rows_delta: null,
    objects_delta: { prepared: publishResult.publication.dispositionCode === 'created_new' ? 1 : 0, reused: publishResult.publication.dispositionCode === 'existing_exact' ? 1 : 0, orphaned: 0 },
    object_disposition_code: 'durable_referenced', candidate_file_sha256: null, candidate_file_seal_record_digest_sha256: null, backup_inventory_sha256: null,
    custody_finalization: {
      artifact: publish.request.payload.artifact, copy_code: publish.request.payload.copy_code,
      backend_code: publish.request.payload.backend_code, backend_reference: publish.request.payload.backend_reference,
      exchanges: exchanges.map((pair) => ({
        operation_code: pair.request.operation_code,
        request_record_digest_sha256: pair.request.record_digest_sha256,
        response_record_digest_sha256: pair.response.record_digest_sha256,
        success_outcome_code: pair.response.payload.outcome_code,
        request_persistence_ack_record_digest_sha256: ackByRecord.get(pair.request.record_digest_sha256),
        response_persistence_ack_record_digest_sha256: ackByRecord.get(pair.response.record_digest_sha256),
      })),
      primary_receipt: publish.response.payload.primary_receipt,
      preparation_capability_consumed_transition_digest_sha256: publishResult.transition.record_digest_sha256,
    },
    integrity_access: null, artifact_backup_receipt: null, prior_database_backup_receipt: null, final_backup_receipt: null,
    event_at: eventAt, recovery: null, record_digest_sha256: null,
  })
  const head = journalBroker.head(journalCode)
  const append = canonicalRecord({
    format: 'jedi-atlas-operation-journal-broker-message', format_version: '1.0.0',
    record_code: `append.${semantic.record_code}`, message_kind_code: 'append_request', operation_id: semantic.operation_id,
    operation_nonce: semantic.operation_nonce, request_id: `append.${semantic.record_code}`,
    sender_binding_code: custodyAdapterBindingCode, recipient_binding_code: journalBindingCode,
    runtime_profile_record_digest_sha256: semantic.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: semantic.identity_bindings_record_digest_sha256,
    d930_journal_profile_record_digest_sha256: journalProfileDigest, request_record_digest_sha256: null, created_at: requestCreatedAt,
    payload: { journal_code: journalCode, expected_event_sequence: (head?.event_sequence ?? 0) + 1,
      expected_previous_event_record_digest_sha256: head?.record_digest_sha256 ?? null,
      supporting_record_kind_code: null, supporting_record: null, supporting_record_digest_sha256: null,
      semantic_assertion: semantic, semantic_assertion_record_digest_sha256: semantic.record_digest_sha256,
      persisted_record_code: null, persisted_record_digest_sha256: null, persisted_at: null, outcome_code: null, error_code: null },
    record_digest_sha256: null,
  })
  if (typeof journalPeerProvider !== 'function') failD931('D931_BROKER_AUTHORITY_REJECTED', 'journal append requires its authenticated IPC peer provider')
  const acknowledgement = journalBroker.appendSemantic(append, await journalPeerProvider(append))
  return Object.freeze({ semantic, append, acknowledgement, nextStepCode: 'wait_for_d9_5', canonicalWriteReachable: false, evidenceAcceptanceEstablished: false, legalAuthorityEstablished: false })
}
