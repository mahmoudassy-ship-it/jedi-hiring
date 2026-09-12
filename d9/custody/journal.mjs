import { canonicalSha256, canonicalize, parseStrictJson, sha256Bytes } from '../control-plane/canonical.mjs'
import { assertDurableNamespaceStore, durableJsonBytes } from './durable-store.mjs'
import { canonicalRecord, validateD90CustodyRecord, validateD930Record } from './contracts.mjs'
import { failD931 } from './errors.mjs'
import { assertAuthenticatedPeer, assertAuthenticatedPeerContext, assertD931AdmissionResolver } from './admission.mjs'
import { assertProtectedJournalBroker, registerProtectedJournalBroker } from './trust.mjs'

export const D931_JOURNAL_NAMESPACES = Object.freeze([
  'primary-receipts',
  'receipt-exchanges',
  'supporting-records',
  'journal-events',
  'recovery-assessments',
])

function timestamp(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || new Date(value).toISOString() !== value) {
    failD931('D931_TIME_INVALID', `${label} is not canonical UTC`)
  }
  return value
}

function exactRecordBytes(record) {
  return durableJsonBytes(record)
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

function parseCanonical(bytes) {
  const record = parseStrictJson(bytes, { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
  if (canonicalize(record) !== bytes.toString('utf8')) failD931('D931_PERSISTED_NONCANONICAL', 'protected record bytes are not canonical JSON')
  return record
}

function requestContextEqual(left, right, fields) {
  for (const field of fields) if (canonicalize(left[field]) !== canonicalize(right[field])) failD931('D931_BROKER_CONTEXT_MISMATCH', `${field} differs across the broker exchange`)
}

function role(bindingRoleResolver, code, expected) {
  if (bindingRoleResolver(code) !== expected) failD931('D931_BROKER_ROLE_REJECTED', `${code} is not the required ${expected}`)
}

function milestone(semantic) { return `${semantic.event_kind_code}@${semantic.stage_code}` }

const JOURNAL_REFERENCE_FIELDS = Object.freeze(['custody_finalization', 'integrity_access', 'artifact_backup_receipt', 'prior_database_backup_receipt', 'final_backup_receipt', 'recovery'])

function countSum(value) {
  return value === null ? null : Object.values(value).reduce((sum, item) => sum + item, 0)
}

function assertD931SemanticPolicy(contractSet, semantic) {
  const baseRules = contractSet.baseContractSet.classification.journal_event_rules
  const rule = baseRules.find((entry) => entry.event_kind_code === semantic.event_kind_code)
  if (!rule) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', 'event kind has no frozen D9.0.1 rule')
  const expectedStage = semantic.event_kind_code === 'operation_started' ? 'startup' : semantic.event_kind_code === 'custody_object_durable' ? 'custody_prepare' : null
  if (expectedStage === null || semantic.stage_code !== expectedStage) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', 'event stage differs from the frozen rule')
  if (!rule.allowed_canonical_effects.includes(semantic.canonical_effect_code) || !rule.allowed_dispositions.includes(semantic.object_disposition_code)) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', 'effect or disposition differs from the frozen rule')
  const policies = [
    [semantic.rows_delta, rule.rows_policy, 'rows'],
    [semantic.objects_delta, rule.objects_policy, 'objects'],
    [semantic.candidate_file_sha256, rule.candidate_hash_policy, 'candidate hash'],
    [semantic.backup_inventory_sha256, rule.backup_hash_policy, 'backup hash'],
  ]
  for (const [value, policy, label] of policies) {
    if (policy === 'forbidden' && value !== null) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', `${label} is forbidden`)
    if (policy === 'required_zero' && (value === null || countSum(value) !== 0)) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', `${label} must be known zero`)
    if (policy === 'required_nonzero' && (value === null || countSum(value) <= 0)) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', `${label} must be known nonzero`)
  }
  if (semantic.error_code !== null || semantic.result_outcome_code !== null || semantic.retryability_code !== 'never' || semantic.recovery_class_code !== 'none' || semantic.candidate_file_seal_record_digest_sha256 !== null) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', 'nonterminal success metadata differs from the frozen rule')
  if (semantic.authorization_permit_record_digest_sha256 !== null || semantic.authorization_bundle_seal_record_digest_sha256 === null || semantic.prepromotion_authorization_record_digest_sha256 !== null || semantic.bundle === null || semantic.bundle.bundle_sequence < 2) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', 'document-import authorization or bundle reference differs')
  if (rule.observed_state_policy === 'forbidden' && semantic.observed_logical_state !== null) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', 'observed state is forbidden')
  const candidates = contractSet.classifications.journal_reference_rules.filter((entry) =>
    (entry.event_kind_code === semantic.event_kind_code || entry.event_kind_code === 'default') &&
    (entry.stage_code === semantic.stage_code || entry.stage_code === 'any') &&
    (!entry.operation_mode_code || entry.operation_mode_code === semantic.operation_mode_code))
  candidates.sort((left, right) => Number(right.event_kind_code !== 'default') - Number(left.event_kind_code !== 'default') || Number(Boolean(right.operation_mode_code)) - Number(Boolean(left.operation_mode_code)))
  const referenceRule = candidates[0]
  if (!referenceRule) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', 'journal reference rule is unresolved')
  for (const field of referenceRule.required) if (semantic[field] === null) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', `${field} is required`)
  for (const field of referenceRule.forbidden) if (semantic[field] !== null) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', `${field} is forbidden`)
  for (const field of JOURNAL_REFERENCE_FIELDS) if (!referenceRule.required.includes(field) && !referenceRule.forbidden.includes(field) && semantic[field] !== null) failD931('D931_JOURNAL_SEMANTIC_POLICY_REJECTED', `${field} has no approved disposition`)
}

function assertD931ReachableSemantic(semantic) {
  if (semantic.operation_mode_code !== 'document_import' || semantic.authorization_permit_record_digest_sha256 !== null || semantic.recovery !== null) {
    failD931('D931_OPERATION_AUTHORITY_UNAVAILABLE', 'D9.3.1 accepts only unpermitted document-import journal prefixes; bootstrap, recovery, and backup-dependent completion remain unreachable')
  }
}

function assertD931SemanticProducer(bindingRoleResolver, semantic) {
  const expectedRole = semantic.event_kind_code === 'operation_started' ? 'bundle_importer' : 'custody_adapter'
  if (bindingRoleResolver(semantic.component_binding_code) !== expectedRole) failD931('D931_OPERATION_AUTHORITY_UNAVAILABLE', `${semantic.event_kind_code} requires the protected ${expectedRole} producer`)
}

function assertHistoryPrefix(contractSet, priorSemantics, semantic) {
  const events = [...priorSemantics, semantic]
  const actual = events.map(milestone)
  if (actual[0] !== 'operation_started@startup') failD931('D931_JOURNAL_HISTORY_REJECTED', 'journal must begin with operation_started@startup')
  const bundleKind = semantic.operation_mode_code === 'document_import' ? 'single_document' : semantic.operation_mode_code === 'bootstrap' ? 'principal_bootstrap' : null
  const permitKind = semantic.authorization_permit_record_digest_sha256 === null
    ? 'none'
    : semantic.operation_mode_code === 'bootstrap'
      ? 'bootstrap'
      : semantic.operation_mode_code === 'recovery'
        ? 'post_promotion_completion'
        : 'none'
  const rules = [...contractSet.classifications.journal_history_rules, ...contractSet.classifications.journal_failure_history_rules]
    .filter((rule) => rule.base_selector.operation_mode_code === semantic.operation_mode_code && rule.permit_kind_code === permitKind && (bundleKind === null || rule.bundle_kind_code === bundleKind || rule.bundle_kind_code === 'any'))
  const registeredPrefix = rules.some((rule) => actual.length <= rule.milestones.length && actual.every((value, index) => value === rule.milestones[index]))
  const classificationOnlyRecovery = actual.length === 2 && actual[1] === 'recovery_required@reconciliation' && semantic.operation_mode_code === 'recovery' && semantic.recovery?.action_execution_code === 'none_classification_only'
  if (!registeredPrefix && !classificationOnlyRecovery) failD931('D931_JOURNAL_HISTORY_REJECTED', actual.join(' -> '))
  if (actual.length > 2) failD931('D931_OPERATION_AUTHORITY_UNAVAILABLE', 'D9.3.1 stops after primary custody durability and cannot append backup, candidate, promotion, or completion milestones')
}

export function createProtectedJournalBroker({
  store,
  contractSet,
  admissionResolver,
  journalBindingCode,
  clock,
  faultInjector = null,
}) {
  assertDurableNamespaceStore(store)
  if (canonicalize([...store.namespaceCodes].toSorted()) !== canonicalize([...D931_JOURNAL_NAMESPACES].toSorted())) failD931('D931_BROKER_CONFIGURATION_INVALID', 'broker requires the exact protected journal namespace inventory')
  assertD931AdmissionResolver(admissionResolver)
  if (admissionResolver.contractSet !== contractSet) failD931('D931_BROKER_CONFIGURATION_INVALID', 'broker and admission resolver must share the exact approved contract set')
  const bindingRoleResolver = admissionResolver.bindingRole
  const expectedJournalProfileDigest = admissionResolver.journalProfile.record_digest_sha256
  if (typeof bindingRoleResolver !== 'function' || typeof clock !== 'function') failD931('D931_BROKER_CONFIGURATION_INVALID', 'broker requires closed role and clock providers')
  role(bindingRoleResolver, journalBindingCode, 'journal_broker')
  const receiptResponses = new Map()
  const receiptRequests = new Map()
  const receiptsByRequestDigest = new Map()
  const receiptsByOperation = new Map()
  const pendingReceiptOperations = new Map()
  const journalResponses = new Map()
  const journalAppendRequests = new Map()
  const journalAppendRequestsByDigest = new Map()
  const journalHeads = new Map()
  const journalContexts = new Map()
  const operationJournals = new Map()
  const pendingAppendByJournal = new Map()
  const pendingAppendByOperation = new Map()
  const supportingRequests = new Map()
  const supportingRecords = new Map()
  const supportingResponses = new Map()
  const recoveryAttempts = new Map()
  const journalEventsByRequestDigest = new Map()
  const journalHistories = new Map()
  let recoveryRequired = false
  function assertOperational() {
    if (recoveryRequired) failD931('D931_JOURNAL_RECOVERY_REQUIRED', 'a prior protected journal effect has an unresolved acknowledgement boundary')
  }
  function protectedAppend(input) {
    try {
      return store.append(input)
    } catch (error) {
      try { store.inventory() } catch { recoveryRequired = true }
      throw error
    }
  }
  function exact(value, expected, label, code = 'D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE') {
    if (canonicalize(value) !== canonicalize(expected)) failD931(code, `${label} differs`)
  }
  function resolveAdmittedBundleSeal({ sealDigest, operationId, operationNonce, runtimeProfileDigest, identityBindingsDigest, bundle, targetLogicalState = undefined, importerBindingCode = undefined, activeAt, code = 'D931_JOURNAL_CHAIN_CORRUPT' }) {
    const seal = admissionResolver.resolveRecord(sealDigest)
    if (seal.record_kind_code !== 'bundle_seal' || seal.bundle_kind_code !== 'single_document' || seal.record_digest_sha256 !== sealDigest) failD931(code, 'authorization record is not the exact admitted single-document bundle seal')
    if (seal.operation_id !== operationId || seal.operation_nonce !== operationNonce || seal.runtime_profile_record_digest_sha256 !== runtimeProfileDigest || seal.identity_bindings_record_digest_sha256 !== identityBindingsDigest) failD931(code, 'admitted bundle seal operation or generation differs')
    exact(seal.bundle, bundle, 'admitted bundle seal bundle', code)
    if (targetLogicalState !== undefined) exact(seal.target_logical_state, targetLogicalState, 'admitted bundle seal target state', code)
    if (importerBindingCode !== undefined && seal.importer_binding_code !== importerBindingCode) failD931(code, 'admitted bundle seal importer differs')
    if (!(seal.sealed_at <= activeAt && activeAt < seal.expires_at)) failD931(code, 'admitted bundle seal is not active at the bounded event')
    return seal
  }
  function assertAdmittedStagedOpen(openRequest, activeAt, code = 'D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE') {
    if (openRequest.operation_code !== 'open_staged' || !openRequest.payload.custody_intent) failD931(code, 'staged-open authorization requires the exact open request and custody intent')
    const intent = openRequest.payload.custody_intent
    const sealDigest = openRequest.payload.bundle_seal_record_digest_sha256
    if (sealDigest !== intent.bundle_seal_record_digest_sha256) failD931(code, 'open request and custody intent do not name one bundle seal')
    const seal = resolveAdmittedBundleSeal({
      sealDigest,
      operationId: openRequest.operation_id,
      operationNonce: openRequest.operation_nonce,
      runtimeProfileDigest: openRequest.runtime_profile_record_digest_sha256,
      identityBindingsDigest: openRequest.identity_bindings_record_digest_sha256,
      bundle: intent.bundle,
      importerBindingCode: openRequest.sender_binding_code,
      activeAt,
      code,
    })
    const handoffDigest = openRequest.payload.collector_handoff_record_digest_sha256
    const handoff = admissionResolver.resolveRecord(handoffDigest)
    if (handoff.record_kind_code !== 'collector_handoff' || handoff.record_digest_sha256 !== handoffDigest) failD931(code, 'open does not resolve to the exact admitted collector handoff')
    if (!seal.collector_handoffs.some((entry) => entry.record_code === handoff.record_code && entry.record_digest_sha256 === handoff.record_digest_sha256 && entry.format === handoff.format && entry.format_version === handoff.format_version)) failD931(code, 'collector handoff is not an exact member of the admitted bundle seal')
    if (handoff.runtime_profile_record_digest_sha256 !== openRequest.runtime_profile_record_digest_sha256 || handoff.identity_bindings_record_digest_sha256 !== openRequest.identity_bindings_record_digest_sha256 || handoff.staged_path !== openRequest.payload.relative_path || handoff.staging_snapshot_code !== openRequest.payload.staging_snapshot_code) failD931(code, 'admitted handoff generation or staging coordinates differ')
    exact(handoff.artifact, intent.artifact, 'admitted handoff artifact', code)
    if (!(handoff.handoff_recorded_at <= activeAt && activeAt < handoff.expires_at)) failD931(code, 'admitted collector handoff is not active at the bounded staged-open event')
    return { handoff, seal }
  }
  function assertAdmittedOpenContext(openRequest, openResponse, semantic) {
    const code = 'D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE'
    const sealDigest = openRequest.payload.bundle_seal_record_digest_sha256
    if (sealDigest !== openRequest.payload.custody_intent.bundle_seal_record_digest_sha256 || sealDigest !== semantic.bundle_seal_record_digest_sha256) failD931(code, 'open, custody intent, and receipt do not name one bundle seal')
    assertPersistedOperationStartForOpen(openRequest, code)
    assertAdmittedStagedOpen(openRequest, openResponse.created_at, code)
    exact(openRequest.payload.custody_intent.bundle, semantic.bundle, 'receipt bundle', code)
    exact(openRequest.payload.custody_intent.artifact, semantic.artifact, 'receipt artifact', code)
  }
  function assertAdmittedJournalAuthorization(semantic, acceptedAt) {
    const seal = resolveAdmittedBundleSeal({
      sealDigest: semantic.authorization_bundle_seal_record_digest_sha256,
      operationId: semantic.operation_id,
      operationNonce: semantic.operation_nonce,
      runtimeProfileDigest: semantic.runtime_profile_record_digest_sha256,
      identityBindingsDigest: semantic.identity_bindings_record_digest_sha256,
      bundle: semantic.bundle,
      targetLogicalState: semantic.target_logical_state,
      importerBindingCode: semantic.event_kind_code === 'operation_started' ? semantic.component_binding_code : undefined,
      activeAt: semantic.event_at,
      code: 'D931_JOURNAL_CHAIN_CORRUPT',
    })
    if (!(seal.sealed_at <= acceptedAt && acceptedAt < seal.expires_at)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'admitted bundle seal is not active at the trusted broker boundary')
  }
  function assertPersistedOperationStartForOpen(openRequest, code = 'D931_SUPPORTING_CHAIN_CORRUPT') {
    const journalCode = `journal.${openRequest.operation_id}`
    const root = persistedEvents.find((candidate) => candidate.journal_code === journalCode && candidate.event_sequence === 1)
    const start = root?.semantic_assertion
    const seal = admissionResolver.resolveRecord(openRequest.payload.bundle_seal_record_digest_sha256)
    if (!root || start?.event_kind_code !== 'operation_started' || start.operation_mode_code !== 'document_import' || start.operation_id !== openRequest.operation_id || start.operation_nonce !== openRequest.operation_nonce || start.authorization_bundle_seal_record_digest_sha256 !== seal.record_digest_sha256 || start.component_binding_code !== openRequest.sender_binding_code || start.runtime_profile_record_digest_sha256 !== openRequest.runtime_profile_record_digest_sha256 || start.identity_bindings_record_digest_sha256 !== openRequest.identity_bindings_record_digest_sha256 || canonicalize(start.bundle) !== canonicalize(openRequest.payload.custody_intent.bundle) || canonicalize(start.target_logical_state) !== canonicalize(seal.target_logical_state) || root.persisted_at > openRequest.created_at) failD931(code, 'exact durably persisted operation start does not precede the protected staged-open stream')
  }
  function assertExactNonnullPayload(record, expectedFields, code, label) {
    const actual = Object.entries(record.payload)
      .filter(([, value]) => value !== null)
      .map(([field]) => field)
      .toSorted()
    if (canonicalize(actual) !== canonicalize([...expectedFields].toSorted())) {
      failD931(code, `${label} has a field set outside the frozen D9.3.0 matrix`)
    }
  }
  function assertReceiptBrokerMatrix(record) {
    const rules = contractSet.classifications.receipt_broker_rules
    const request = record.message_kind_code === 'persist_request'
    if (request !== (record.request_record_digest_sha256 === null)) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt broker request chain differs')
    if (request) {
      assertExactNonnullPayload(record, rules.request_nonnull_fields, 'D931_RECEIPT_CHAIN_CORRUPT', 'receipt persist request')
      return
    }
    const outcome = record.payload.outcome_code
    if (rules.success_outcome_codes.includes(outcome)) {
      assertExactNonnullPayload(record, rules.success_nonnull_fields, 'D931_RECEIPT_CHAIN_CORRUPT', 'receipt persist success response')
      return
    }
    const failure = rules.failure_error_rules.find((entry) => entry.outcome_code === outcome)
    if (!failure || record.payload.error_code !== failure.error_code) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt broker failure outcome or error differs')
    assertExactNonnullPayload(record, rules.failure_nonnull_fields, 'D931_RECEIPT_CHAIN_CORRUPT', 'receipt persist failure response')
  }
  function assertJournalBrokerMatrix(record) {
    const rules = contractSet.classifications.journal_broker_rules
    const request = record.message_kind_code.endsWith('_request')
    if (request !== (record.request_record_digest_sha256 === null)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'journal broker request chain differs')
    let expectedFields
    if (record.message_kind_code === 'persist_supporting_request') expectedFields = rules.supporting_request_required_fields
    else if (record.message_kind_code === 'append_request') {
      expectedFields = rules.append_request_required_fields.filter((field) => field !== 'expected_previous_event_record_digest_sha256' || record.payload[field] !== null)
    } else {
      const outcome = record.payload.outcome_code
      if (rules.success_outcome_codes.includes(outcome)) {
        if (record.message_kind_code === 'persist_supporting_response') expectedFields = rules.supporting_response_required_fields
        else if (record.message_kind_code === 'append_response') expectedFields = rules.append_response_required_fields.filter((field) => field !== 'expected_previous_event_record_digest_sha256' || record.payload[field] !== null)
      } else {
        const errorRules = record.message_kind_code === 'persist_supporting_response' ? rules.supporting_failure_error_rules : record.message_kind_code === 'append_response' ? rules.append_failure_error_rules : []
        const failure = errorRules.find((entry) => entry.outcome_code === outcome)
        if (!failure || record.payload.error_code !== failure.error_code) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'journal broker failure outcome or error differs')
        expectedFields = rules.failure_nonnull_fields
      }
    }
    if (!expectedFields) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'journal broker message kind or outcome is outside the frozen matrix')
    assertExactNonnullPayload(record, expectedFields, 'D931_JOURNAL_CHAIN_CORRUPT', record.message_kind_code)
  }
  function loadProtectedRecord(namespaceCode, item) {
    const record = validateD930Record({ contractSet, record: parseCanonical(store.read({ namespaceCode, recordCode: item.record_code })), bindingRoleResolver })
    if (record.format === 'jedi-atlas-durability-receipt-broker-message') assertReceiptBrokerMatrix(record)
    if (record.format === 'jedi-atlas-operation-journal-broker-message') assertJournalBrokerMatrix(record)
    if (record.record_code !== item.record_code) failD931('D931_PROTECTED_NAMESPACE_CORRUPT', 'protected filename does not equal the canonical record code')
    return record
  }
  function supportingPair(digest) {
    const record = supportingRecords.get(digest)
    const request = [...supportingRequests.values()].find((candidate) => candidate.payload.supporting_record_digest_sha256 === digest)
    const response = request ? supportingResponses.get(request.request_id) : null
    if (!record || !request || !response || response.request_record_digest_sha256 !== request.record_digest_sha256 || response.payload.persisted_record_digest_sha256 !== digest) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'supporting record has no exact protected acknowledgement')
    return { record, request, response }
  }
  function supportingKind(record) {
    if (record.format === 'jedi-atlas-custody-adapter-message') return 'custody_adapter_message'
    if (record.format === 'jedi-atlas-integrity-access-lifecycle-record') return 'integrity_access_lifecycle_record'
    failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'supporting subject kind is not approved')
  }
  function supportingProducer(record) {
    return record.format === 'jedi-atlas-custody-adapter-message' ? record.sender_binding_code : record.producer_binding_code
  }
  function assertAdapterPair(request, response) {
    if (request.record_code !== `adapter.${request.operation_id}.${request.operation_code}.${request.request_sequence}` || request.request_id !== `request.${request.operation_id}.${request.operation_code}.${request.request_sequence}` || request.message_kind_code !== 'request' || request.request_record_digest_sha256 !== null || response.message_kind_code !== 'response' || response.record_code !== `${request.record_code}.response` || response.request_record_digest_sha256 !== request.record_digest_sha256 || request.operation_code !== response.operation_code || request.sender_binding_code !== response.recipient_binding_code || request.recipient_binding_code !== response.sender_binding_code) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'adapter request-response pairing differs')
    for (const field of ['operation_id', 'operation_nonce', 'request_id', 'request_sequence', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256']) exact(request[field], response[field], `adapter ${field}`)
    if (response.created_at < request.created_at) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'adapter response predates its request')
    const messageRule = contractSet.classifications.custody_message_rules.find((entry) => entry.operation_code === request.operation_code)
    const pairRule = contractSet.classifications.custody_message_pair_rules.find((entry) => entry.operation_code === request.operation_code)
    if (!messageRule || !pairRule) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'adapter operation lacks a frozen pair rule')
    if (messageRule.success_outcomes.includes(response.payload.outcome_code)) {
      for (const field of pairRule.exact_echo_fields) exact(request.payload[field], response.payload[field], `adapter echo ${field}`)
    }
  }
  function assertAdapterSubjectIdentity(record, code = 'D931_SUPPORTING_CHAIN_CORRUPT') {
    const requestCode = `adapter.${record.operation_id}.${record.operation_code}.${record.request_sequence}`
    const expectedCode = record.message_kind_code === 'request' ? requestCode : `${requestCode}.response`
    const expectedRequestId = `request.${record.operation_id}.${record.operation_code}.${record.request_sequence}`
    if (record.record_code !== expectedCode || record.request_id !== expectedRequestId || (record.message_kind_code === 'request') !== (record.request_record_digest_sha256 === null)) failD931(code, 'adapter supporting subject has a noncanonical identity')
  }
  function assertSupportingBrokerPair(request, response, record) {
    assertJournalBrokerMatrix(request)
    assertJournalBrokerMatrix(response)
    if (request.message_kind_code !== 'persist_supporting_request' || request.request_record_digest_sha256 !== null || response.message_kind_code !== 'persist_supporting_response' || response.request_record_digest_sha256 !== request.record_digest_sha256 || request.sender_binding_code !== response.recipient_binding_code || request.recipient_binding_code !== response.sender_binding_code || response.sender_binding_code !== journalBindingCode) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'supporting broker peers or request chain differ')
    for (const field of ['operation_id', 'operation_nonce', 'request_id', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_journal_profile_record_digest_sha256']) exact(request[field], response[field], `supporting broker ${field}`, 'D931_SUPPORTING_CHAIN_CORRUPT')
    const kind = supportingKind(record)
    if (request.record_code !== `support.request.${record.record_code}` || request.request_id !== `support.${record.record_code}` || response.record_code !== `support.response.${record.record_code}` || request.sender_binding_code !== supportingProducer(record) || request.recipient_binding_code !== journalBindingCode || request.runtime_profile_record_digest_sha256 !== admissionResolver.verifiedGeneration.runtimeProfile.record_digest_sha256 || request.identity_bindings_record_digest_sha256 !== admissionResolver.verifiedGeneration.identityBindings.record_digest_sha256 || request.d930_journal_profile_record_digest_sha256 !== expectedJournalProfileDigest || request.payload.journal_code !== `journal.${record.operation_id}` || request.payload.journal_code !== response.payload.journal_code || request.payload.supporting_record_kind_code !== kind || response.payload.supporting_record_kind_code !== kind || request.payload.supporting_record_digest_sha256 !== record.record_digest_sha256 || response.payload.supporting_record_digest_sha256 !== record.record_digest_sha256 || response.payload.persisted_record_code !== record.record_code || response.payload.persisted_record_digest_sha256 !== record.record_digest_sha256 || response.payload.outcome_code !== 'persisted' || response.payload.error_code !== null) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'supporting broker payload differs')
    if (canonicalize(request.payload.supporting_record) !== canonicalize(record) || request.operation_id !== record.operation_id || request.operation_nonce !== record.operation_nonce || request.runtime_profile_record_digest_sha256 !== record.runtime_profile_record_digest_sha256 || request.identity_bindings_record_digest_sha256 !== record.identity_bindings_record_digest_sha256 || record.d930_operational_profile_record_digest_sha256 !== admissionResolver.custodyProfile.record_digest_sha256) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'supporting subject context or selected custody profile differs')
    const producedAt = record.created_at ?? record.event_at
    if (producedAt > request.created_at || request.created_at > response.payload.persisted_at || response.payload.persisted_at !== response.created_at) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'supporting chronology differs')
    const producerBinding = admissionResolver.resolveBinding(request.sender_binding_code)
    const brokerBinding = admissionResolver.resolveBinding(journalBindingCode)
    const runtime = admissionResolver.verifiedGeneration.runtimeProfile
    const identities = admissionResolver.verifiedGeneration.identityBindings
    if (!(producerBinding.valid_from <= producedAt && producedAt < producerBinding.valid_until) || !(producerBinding.valid_from <= request.created_at && request.created_at < producerBinding.valid_until) || !(producerBinding.valid_from <= response.payload.persisted_at && response.payload.persisted_at < producerBinding.valid_until) || !(brokerBinding.valid_from <= response.payload.persisted_at && response.payload.persisted_at < brokerBinding.valid_until) || !(runtime.issued_at <= response.payload.persisted_at) || !(identities.issued_at <= response.payload.persisted_at && response.payload.persisted_at < identities.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'supporting producer, broker, or generation is not active through persistence')
  }
  function assertReceiptRequestEffect(request, receipt) {
    assertReceiptBrokerMatrix(request)
    assertReceiptRequestEnvelope(request)
    if (request.message_kind_code !== 'persist_request' || request.recipient_binding_code !== journalBindingCode || request.sender_binding_code !== receipt.semantic.adapter_binding_code || request.runtime_profile_record_digest_sha256 !== receipt.runtime_profile_record_digest_sha256 || request.identity_bindings_record_digest_sha256 !== receipt.identity_bindings_record_digest_sha256 || request.d930_operational_profile_record_digest_sha256 !== receipt.d930_operational_profile_record_digest_sha256 || request.d930_journal_profile_record_digest_sha256 !== expectedJournalProfileDigest) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt request identity or profile differs')
    if (receipt.format !== 'jedi-atlas-primary-durability-receipt' || receipt.format_version !== '1.0.0' || receipt.receipt_file_profile_code !== 'canonical_json_utf8_no_lf_v1' || receipt.hash_algorithm_code !== 'sha256' || request.payload.receipt_record_code !== receipt.record_code || canonicalize(request.payload.receipt_semantic) !== canonicalize(receipt.semantic) || request.payload.receipt_semantic_sha256 !== receipt.semantic_payload_sha256 || receipt.semantic_payload_sha256 !== canonicalSha256(receipt.semantic) || receipt.persistence_request_record_digest_sha256 !== request.record_digest_sha256 || receipt.persisted_by_binding_code !== journalBindingCode) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt is not the exact deterministic effect of its request')
    if (receipt.semantic.completed_at > request.created_at || request.created_at > receipt.persisted_at) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt request chronology differs')
    const adapter = admissionResolver.resolveBinding(receipt.semantic.adapter_binding_code)
    const brokerBinding = admissionResolver.resolveBinding(journalBindingCode)
    const runtime = admissionResolver.verifiedGeneration.runtimeProfile
    const identities = admissionResolver.verifiedGeneration.identityBindings
    if (!(adapter.valid_from <= receipt.persisted_at && receipt.persisted_at < adapter.valid_until) || !(brokerBinding.valid_from <= receipt.persisted_at && receipt.persisted_at < brokerBinding.valid_until) || !(runtime.issued_at <= receipt.persisted_at) || !(identities.issued_at <= receipt.persisted_at && receipt.persisted_at < identities.expires_at)) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt producer, broker, or generation is not active at persistence')
  }
  function assertReceiptBrokerPair(request, response, receipt) {
    assertReceiptBrokerMatrix(response)
    assertReceiptRequestEffect(request, receipt)
    if (request.message_kind_code !== 'persist_request' || response.message_kind_code !== 'persist_response' || response.record_code !== `${request.record_code}.response` || response.request_record_digest_sha256 !== request.record_digest_sha256 || request.sender_binding_code !== response.recipient_binding_code || request.recipient_binding_code !== response.sender_binding_code || response.sender_binding_code !== journalBindingCode) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt broker peers, deterministic response identity, or request chain differ')
    for (const field of ['operation_id', 'operation_nonce', 'request_id', 'request_sequence', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256', 'd930_journal_profile_record_digest_sha256']) exact(request[field], response[field], `receipt broker ${field}`, 'D931_RECEIPT_CHAIN_CORRUPT')
    if (request.payload.receipt_record_code !== receipt.record_code || canonicalize(request.payload.receipt_semantic) !== canonicalize(receipt.semantic) || request.payload.receipt_semantic_sha256 !== receipt.semantic_payload_sha256 || receipt.persistence_request_record_digest_sha256 !== request.record_digest_sha256 || receipt.persisted_by_binding_code !== journalBindingCode || response.payload.receipt_record_code !== receipt.record_code || response.payload.receipt_raw_sha256 !== sha256Bytes(exactRecordBytes(receipt)) || response.payload.receipt_persisted_at !== receipt.persisted_at || response.payload.outcome_code !== 'persisted' || response.payload.error_code !== null) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt broker payload differs')
    if (receipt.semantic.completed_at > request.created_at || request.created_at > receipt.persisted_at || receipt.persisted_at !== response.created_at) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt broker chronology differs')
  }
  function assertAppendExchange(request, response, event) {
    if (request) assertJournalBrokerMatrix(request)
    if (response) assertJournalBrokerMatrix(response)
    if (request) assertAppendRequestEnvelope(request)
    if (!event || !request || request.message_kind_code !== 'append_request' || request.record_digest_sha256 !== event.append_request_record_digest_sha256 || canonicalize(request.payload.semantic_assertion) !== canonicalize(event.semantic_assertion) || request.payload.semantic_assertion_record_digest_sha256 !== event.semantic_assertion_record_digest_sha256 || request.payload.journal_code !== event.journal_code || request.payload.expected_event_sequence !== event.event_sequence || request.payload.expected_previous_event_record_digest_sha256 !== event.previous_event_record_digest_sha256) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'append request does not exactly project to the event')
    const semantic = event.semantic_assertion
    if (request.sender_binding_code !== semantic.component_binding_code || request.recipient_binding_code !== journalBindingCode || request.operation_id !== semantic.operation_id || request.operation_nonce !== semantic.operation_nonce || request.runtime_profile_record_digest_sha256 !== semantic.runtime_profile_record_digest_sha256 || request.identity_bindings_record_digest_sha256 !== semantic.identity_bindings_record_digest_sha256 || request.d930_journal_profile_record_digest_sha256 !== semantic.d930_journal_profile_record_digest_sha256 || semantic.event_at > request.created_at || request.created_at > event.persisted_at) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'append request envelope or chronology differs')
    if (!response) return
    if (response.message_kind_code !== 'append_response' || response.request_record_digest_sha256 !== request.record_digest_sha256 || response.record_code !== `${request.record_code}.response` || response.request_id !== request.request_id || response.sender_binding_code !== journalBindingCode || response.recipient_binding_code !== event.semantic_assertion.component_binding_code || response.operation_id !== event.semantic_assertion.operation_id || response.operation_nonce !== event.semantic_assertion.operation_nonce || response.runtime_profile_record_digest_sha256 !== event.semantic_assertion.runtime_profile_record_digest_sha256 || response.identity_bindings_record_digest_sha256 !== event.semantic_assertion.identity_bindings_record_digest_sha256 || response.d930_journal_profile_record_digest_sha256 !== event.semantic_assertion.d930_journal_profile_record_digest_sha256) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'append response context differs')
    const payload = response.payload
    if (payload.journal_code !== event.journal_code || payload.expected_event_sequence !== event.event_sequence || payload.expected_previous_event_record_digest_sha256 !== event.previous_event_record_digest_sha256 || payload.semantic_assertion_record_digest_sha256 !== event.semantic_assertion_record_digest_sha256 || payload.persisted_record_code !== event.record_code || payload.persisted_record_digest_sha256 !== event.record_digest_sha256 || payload.persisted_at !== event.persisted_at || payload.outcome_code !== 'persisted' || payload.error_code !== null || response.created_at !== event.persisted_at) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'append response projection differs')
  }
  function expectedIntent(semantic) {
    return { bundle: semantic.bundle, bundle_seal_record_digest_sha256: semantic.bundle_seal_record_digest_sha256, custody_event_code: 'placement', artifact: semantic.artifact, copy_code: semantic.copy_code, custody_class_code: 'restricted_store', backend_code: semantic.backend_code, backend_reference: semantic.backend_reference }
  }
  function assertPersistedEvent(record) {
    const semantic = record.semantic_assertion
    const runtime = admissionResolver.verifiedGeneration.runtimeProfile
    const identities = admissionResolver.verifiedGeneration.identityBindings
    if (record.record_code !== `${record.journal_code}.event.${String(record.event_sequence).padStart(6, '0')}` || record.persisted_by_binding_code !== journalBindingCode) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'persisted event identity or broker differs')
    if (semantic.record_digest_sha256 !== canonicalSha256(semantic, { excludedTopLevelField: 'record_digest_sha256' }) || record.semantic_assertion_record_digest_sha256 !== semantic.record_digest_sha256) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'persisted event semantic digest differs')
    if (semantic.event_at > record.persisted_at) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'persisted event chronology differs')
    if (semantic.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || semantic.identity_bindings_record_digest_sha256 !== identities.record_digest_sha256 || semantic.d930_journal_profile_record_digest_sha256 !== expectedJournalProfileDigest) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'persisted event generation or profile differs')
    if (!(runtime.issued_at <= record.persisted_at) || !(identities.issued_at <= record.persisted_at && record.persisted_at < identities.expires_at)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'persisted event generation is not active')
    assertAdmittedJournalAuthorization(semantic, record.persisted_at)
    const producer = admissionResolver.resolveBinding(semantic.component_binding_code)
    const brokerBinding = admissionResolver.resolveBinding(journalBindingCode)
    if (semantic.component_executable_sha256 !== producer.executable_sha256 || !(producer.valid_from <= semantic.event_at && semantic.event_at < producer.valid_until) || !(producer.valid_from <= record.persisted_at && record.persisted_at < producer.valid_until) || !(brokerBinding.valid_from <= record.persisted_at && record.persisted_at < brokerBinding.valid_until)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'persisted event producer or broker binding is not exact and active')
  }
  function assertAppendRequestEnvelope(request) {
    assertJournalBrokerMatrix(request)
    const semantic = request.payload.semantic_assertion
    if (Buffer.byteLength(request.operation_id, 'utf8') > 40) failD931('D931_OPERATION_ID_BUDGET_REJECTED', 'operation ID exceeds the closed 40-byte descendant-identity budget')
    const expectedSemanticCode = semantic.event_kind_code === 'operation_started' ? `semantic.start.${semantic.operation_id}` : semantic.event_kind_code === 'custody_object_durable' ? `semantic.custody.${semantic.operation_id}` : null
    if (semantic.record_code !== expectedSemanticCode || request.record_code !== `append.${semantic.record_code}` || request.request_id !== `append.${semantic.record_code}` || request.payload.journal_code !== `journal.${semantic.operation_id}` || request.message_kind_code !== 'append_request' || request.request_record_digest_sha256 !== null || request.recipient_binding_code !== journalBindingCode || request.sender_binding_code !== semantic.component_binding_code || request.payload.semantic_assertion_record_digest_sha256 !== semantic.record_digest_sha256 || semantic.record_digest_sha256 !== canonicalSha256(semantic, { excludedTopLevelField: 'record_digest_sha256' })) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'append request envelope, deterministic journal identity, or semantic digest differs')
    assertD931ReachableSemantic(semantic)
    assertD931SemanticPolicy(contractSet, semantic)
    assertD931SemanticProducer(bindingRoleResolver, semantic)
    assertAdmittedJournalAuthorization(semantic, request.created_at)
    const producer = admissionResolver.resolveBinding(semantic.component_binding_code)
    const brokerBinding = admissionResolver.resolveBinding(journalBindingCode)
    const runtime = admissionResolver.verifiedGeneration.runtimeProfile
    const identities = admissionResolver.verifiedGeneration.identityBindings
    if (semantic.event_at > request.created_at) failD931('D931_JOURNAL_TIME_REJECTED', 'semantic event postdates its append request')
    if (semantic.component_executable_sha256 !== producer.executable_sha256 || !(producer.valid_from <= semantic.event_at && semantic.event_at < producer.valid_until) || !(brokerBinding.valid_from <= request.created_at && request.created_at < brokerBinding.valid_until)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'append request producer or broker binding differs')
    for (const field of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) exact(request[field], semantic[field], `append request ${field}`, 'D931_JOURNAL_CHAIN_CORRUPT')
    if (request.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || request.identity_bindings_record_digest_sha256 !== identities.record_digest_sha256 || request.d930_journal_profile_record_digest_sha256 !== expectedJournalProfileDigest || semantic.d930_journal_profile_record_digest_sha256 !== expectedJournalProfileDigest || !(runtime.issued_at <= request.created_at) || !(identities.issued_at <= request.created_at && request.created_at < identities.expires_at)) failD931('D931_PEER_CONTEXT_REJECTED', 'append request generation or profile differs')
  }
  function assertReceiptRequestEnvelope(request) {
    assertReceiptBrokerMatrix(request)
    const semantic = request.payload.receipt_semantic
    const runtime = admissionResolver.verifiedGeneration.runtimeProfile
    const identities = admissionResolver.verifiedGeneration.identityBindings
    if (Buffer.byteLength(request.operation_id, 'utf8') > 40 || request.record_code !== `receipt.persist.${request.operation_id}` || request.request_id !== request.record_code || request.request_sequence !== 1 || request.payload.receipt_record_code !== `receipt.primary.${request.operation_id}` || request.message_kind_code !== 'persist_request' || request.request_record_digest_sha256 !== null || request.recipient_binding_code !== journalBindingCode || request.sender_binding_code !== semantic.adapter_binding_code || request.payload.receipt_semantic_sha256 !== canonicalSha256(semantic)) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt request envelope or semantic digest differs')
    const adapter = admissionResolver.resolveBinding(semantic.adapter_binding_code)
    const brokerBinding = admissionResolver.resolveBinding(journalBindingCode)
    if (adapter.runtime_role_code !== 'custody_adapter' || semantic.adapter_executable_sha256 !== adapter.executable_sha256 || semantic.completed_at > request.created_at || !(adapter.valid_from <= semantic.completed_at && semantic.completed_at < adapter.valid_until) || !(brokerBinding.valid_from <= request.created_at && request.created_at < brokerBinding.valid_until)) failD931('D931_RECEIPT_PRODUCER_MISMATCH', 'receipt request producer, broker, or chronology differs')
    for (const field of ['operation_id', 'operation_nonce']) exact(semantic[field], request[field], `receipt request ${field}`, 'D931_RECEIPT_CHAIN_CORRUPT')
    if (request.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || request.identity_bindings_record_digest_sha256 !== identities.record_digest_sha256 || request.d930_operational_profile_record_digest_sha256 !== admissionResolver.custodyProfile.record_digest_sha256 || request.d930_journal_profile_record_digest_sha256 !== expectedJournalProfileDigest || !(runtime.issued_at <= request.created_at) || !(identities.issued_at <= request.created_at && request.created_at < identities.expires_at)) failD931('D931_RECEIPT_PRODUCER_MISMATCH', 'receipt request generation or profile differs')
    if (semantic.backend_reference !== `objects/sha256/${semantic.artifact.sha256.slice(0, 2)}/${semantic.artifact.sha256}`) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt request backend reference differs')
    const receiptRule = contractSet.classifications.primary_receipt_rules.find((entry) => entry.finalization_outcome_code === semantic.finalization_outcome_code)
    if (!receiptRule || receiptRule.no_replace_disposition_code !== semantic.no_replace_disposition_code || receiptRule.required_claims.some((claim) => semantic[claim] !== true)) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt request durability policy differs')
  }
  function reconstructFinalizationCapabilities(adapterPairs, publishRequest, publishResponse = null) {
    const open = adapterPairs.get('open_staged')
    const prepare = adapterPairs.get('prepare')
    const verify = adapterPairs.get('verify_prepared')
    if (!open || !prepare || !verify) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'capability reconstruction requires the exact first three adapter exchanges')
    const issuance = ({ kindCode, basisRequest, artifact, grantScope, issuedAt, expiresAt }) => canonicalRecord({
      format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_issuance',
      record_code: `capability.${kindCode}.${basisRequest.record_digest_sha256.slice(0, 32)}`,
      capability_kind_code: kindCode, issued_by_binding_code: basisRequest.recipient_binding_code,
      requester_binding_code: basisRequest.sender_binding_code, adapter_binding_code: basisRequest.recipient_binding_code,
      operation_id: basisRequest.operation_id, operation_nonce: basisRequest.operation_nonce,
      runtime_profile_record_digest_sha256: basisRequest.runtime_profile_record_digest_sha256,
      identity_bindings_record_digest_sha256: basisRequest.identity_bindings_record_digest_sha256,
      artifact: structuredClone(artifact),
      allowed_consumer_operation_codes: kindCode === 'source_handle' ? ['prepare'] : ['verify_prepared', 'publish_no_replace', 'abandon_temp'],
      replay_policy_code: kindCode === 'source_handle' ? 'single_consume_prepare' : 'ordered_verify_then_publish_or_abandon',
      grant_scope: structuredClone(grantScope), issued_at: issuedAt, expires_at: expiresAt,
      record_digest_sha256: null,
    })
    const transition = ({ capability, previous = null, request, response = null, toStateCode, transitionCode, reasonCode, occurredAt }) => canonicalRecord({
      format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_transition',
      record_code: `${capability.record_code}.transition.${previous ? previous.transition_sequence + 1 : 1}`,
      capability_kind_code: capability.capability_kind_code,
      capability_record_digest_sha256: capability.record_digest_sha256,
      transition_sequence: previous ? previous.transition_sequence + 1 : 1,
      previous_transition_record_digest_sha256: previous?.record_digest_sha256 ?? null,
      from_state_code: previous?.to_state_code ?? 'ready', to_state_code: toStateCode, transition_code: transitionCode,
      request_record_digest_sha256: request.record_digest_sha256,
      response_record_digest_sha256: response?.record_digest_sha256 ?? null,
      recorded_by_binding_code: capability.adapter_binding_code, occurred_at: occurredAt,
      reason_code: reasonCode, record_digest_sha256: null,
    })
    const sourceIssuance = issuance({
      kindCode: 'source_handle', basisRequest: open.request, artifact: open.request.payload.custody_intent.artifact,
      grantScope: {
        scope_kind_code: 'source_handle', basis_request_record_digest_sha256: open.request.record_digest_sha256,
        collector_handoff_record_digest_sha256: open.request.payload.collector_handoff_record_digest_sha256,
        bundle_seal_record_digest_sha256: open.request.payload.bundle_seal_record_digest_sha256,
        staging_snapshot_code: open.request.payload.staging_snapshot_code, staging_root_slot_code: 'staging_root',
        relative_path: open.request.payload.relative_path, descriptor_role_code: 'staged_source', staged_source_descriptor_ordinal: 1,
      },
      issuedAt: open.response.created_at, expiresAt: new Date(Date.parse(open.response.created_at) + 30_000).toISOString(),
    })
    const sourceConsumed = transition({
      capability: sourceIssuance, request: prepare.request, toStateCode: 'consumed', transitionCode: 'consumer_succeeded',
      reasonCode: 'request_claimed', occurredAt: prepare.response.created_at,
    })
    const preparationIssuance = issuance({
      kindCode: 'preparation', basisRequest: prepare.request, artifact: prepare.request.payload.artifact,
      grantScope: {
        scope_kind_code: 'preparation', basis_request_record_digest_sha256: prepare.request.record_digest_sha256,
        source_capability_record_digest_sha256: sourceIssuance.record_digest_sha256,
        pending_object_code: `pending.${prepare.request.operation_id}`,
      },
      issuedAt: prepare.response.created_at, expiresAt: new Date(Date.parse(prepare.response.created_at) + 60_000).toISOString(),
    })
    const preparationVerified = transition({
      capability: preparationIssuance, request: verify.request, response: verify.response,
      toStateCode: 'verified', transitionCode: 'verification_succeeded', reasonCode: 'verified_response', occurredAt: verify.response.created_at,
    })
    const result = { sourceIssuance, sourceConsumed, preparationIssuance, preparationVerified, preparationConsumed: null }
    if (publishResponse) result.preparationConsumed = transition({
      capability: preparationIssuance, previous: preparationVerified, request: publishRequest, response: publishResponse,
      toStateCode: 'consumed', transitionCode: 'consumer_succeeded', reasonCode: 'successful_response', occurredAt: publishResponse.created_at,
    })
    const requireChronology = (condition, label) => {
      if (!condition) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${label} violates the frozen capability chronology`)
    }
    requireChronology(open.request.created_at < sourceIssuance.issued_at && sourceIssuance.issued_at < sourceIssuance.expires_at && open.response.created_at === sourceIssuance.issued_at, 'source issuance')
    requireChronology(sourceIssuance.issued_at < prepare.request.created_at && prepare.request.created_at <= sourceConsumed.occurred_at && sourceConsumed.occurred_at === prepare.response.created_at && sourceConsumed.occurred_at < sourceIssuance.expires_at, 'source consumption')
    requireChronology(prepare.request.created_at < preparationIssuance.issued_at && preparationIssuance.issued_at === prepare.response.created_at && preparationIssuance.issued_at < preparationIssuance.expires_at, 'preparation issuance')
    requireChronology(preparationIssuance.issued_at < verify.request.created_at && verify.request.created_at <= preparationVerified.occurred_at && preparationVerified.occurred_at === verify.response.created_at && preparationVerified.occurred_at < preparationIssuance.expires_at, 'preparation verification')
    if (publishResponse) requireChronology(preparationVerified.occurred_at < publishRequest.created_at && publishRequest.created_at <= result.preparationConsumed.occurred_at && result.preparationConsumed.occurred_at === publishResponse.created_at && result.preparationConsumed.occurred_at < preparationIssuance.expires_at, 'preparation consumption')
    const injectedCapabilityMismatch = faultInjector?.('before_capability_link_validation', { operationId: publishRequest.operation_id }) === 'source_record_substitution'
    const requireLink = (actual, expected, label) => {
      if (actual !== expected) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${label} does not bind the deterministically reconstructed capability leaf`)
    }
    requireLink(injectedCapabilityMismatch ? 'ff'.repeat(32) : open.response.payload.source_capability_record_digest_sha256, sourceIssuance.record_digest_sha256, 'open response source capability record')
    requireLink(open.response.payload.source_capability_leaf_record_digest_sha256, sourceIssuance.record_digest_sha256, 'open response source capability leaf')
    for (const [label, record] of [['prepare request', prepare.request], ['prepare response', prepare.response]]) {
      requireLink(record.payload.source_capability_record_digest_sha256, sourceIssuance.record_digest_sha256, `${label} source capability record`)
      requireLink(record.payload.source_capability_leaf_record_digest_sha256, sourceIssuance.record_digest_sha256, `${label} source capability leaf`)
    }
    requireLink(prepare.response.payload.preparation_capability_record_digest_sha256, preparationIssuance.record_digest_sha256, 'prepare response preparation capability record')
    requireLink(prepare.response.payload.preparation_capability_leaf_record_digest_sha256, preparationIssuance.record_digest_sha256, 'prepare response preparation capability leaf')
    for (const [label, record] of [['verify request', verify.request], ['verify response', verify.response]]) {
      requireLink(record.payload.preparation_capability_record_digest_sha256, preparationIssuance.record_digest_sha256, `${label} preparation capability record`)
      requireLink(record.payload.preparation_capability_leaf_record_digest_sha256, preparationIssuance.record_digest_sha256, `${label} preparation capability leaf`)
    }
    requireLink(publishRequest.payload.preparation_capability_record_digest_sha256, preparationIssuance.record_digest_sha256, 'publish request preparation capability record')
    requireLink(publishRequest.payload.preparation_capability_leaf_record_digest_sha256, preparationVerified.record_digest_sha256, 'publish request preparation capability leaf')
    if (publishResponse) {
      requireLink(publishResponse.payload.preparation_capability_record_digest_sha256, preparationIssuance.record_digest_sha256, 'publish response preparation capability record')
      requireLink(publishResponse.payload.preparation_capability_leaf_record_digest_sha256, preparationVerified.record_digest_sha256, 'publish response preparation capability leaf')
    }
    for (const record of Object.values(result)) if (record) validateD90CustodyRecord({ contractSet, record })
    return result
  }
  function validateReceiptPrerequisites(request, pairs) {
    const semantic = request.payload.receipt_semantic
    assertReceiptRequestEnvelope(request)
    for (const field of ['operation_id', 'operation_nonce']) exact(semantic[field], request[field], `receipt ${field}`)
    if (request.sender_binding_code !== semantic.adapter_binding_code || semantic.adapter_executable_sha256 !== admissionResolver.resolveBinding(semantic.adapter_binding_code).executable_sha256) failD931('D931_RECEIPT_PRODUCER_MISMATCH', 'receipt semantic adapter identity differs')
    if (request.runtime_profile_record_digest_sha256 !== admissionResolver.verifiedGeneration.runtimeProfile.record_digest_sha256 || request.identity_bindings_record_digest_sha256 !== admissionResolver.verifiedGeneration.identityBindings.record_digest_sha256 || request.d930_operational_profile_record_digest_sha256 !== admissionResolver.custodyProfile.record_digest_sha256) failD931('D931_RECEIPT_PRODUCER_MISMATCH', 'receipt generation or profile differs')
    if (semantic.completed_at > request.created_at || semantic.backend_reference !== `objects/sha256/${semantic.artifact.sha256.slice(0, 2)}/${semantic.artifact.sha256}`) failD931('D931_RECEIPT_BINDING_MISMATCH', 'receipt chronology or backend reference differs')
    const receiptRule = contractSet.classifications.primary_receipt_rules.find((entry) => entry.finalization_outcome_code === semantic.finalization_outcome_code)
    if (!receiptRule || receiptRule.no_replace_disposition_code !== semantic.no_replace_disposition_code || receiptRule.required_claims.some((claim) => semantic[claim] !== true)) failD931('D931_RECEIPT_BINDING_MISMATCH', 'receipt outcome or durability claims differ from the frozen matrix')
    const records = new Map(pairs.map((pair) => [pair.record.record_digest_sha256, pair]))
    const used = new Set()
    const adapterPairs = new Map()
    const adapterRequestIds = new Set()
    for (const pair of pairs) {
      assertSupportingBrokerPair(pair.request, pair.response, pair.record)
      for (const field of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) exact(pair.record[field], request[field], `receipt supporting ${field}`)
      exact(pair.record.d930_operational_profile_record_digest_sha256, request.d930_operational_profile_record_digest_sha256, 'receipt supporting custody profile')
      if (pair.response.created_at > request.created_at) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'supporting acknowledgement postdates receipt request')
    }
    for (const [field, operationCode, outcomeCode, requestSequence] of [
      ['open_staged_response_record_digest_sha256', 'open_staged', 'opened', 1],
      ['prepare_response_record_digest_sha256', 'prepare', 'prepared', 2],
      ['verify_prepared_response_record_digest_sha256', 'verify_prepared', 'verified', 3],
    ]) {
      const responsePair = records.get(semantic[field])
      const requestPair = responsePair ? records.get(responsePair.record.request_record_digest_sha256) : null
      if (!responsePair || !requestPair || responsePair.record.operation_code !== operationCode || responsePair.record.payload.outcome_code !== outcomeCode || requestPair.record.operation_code !== operationCode) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${field} does not resolve exactly`)
      assertAdapterPair(requestPair.record, responsePair.record)
      if (requestPair.record.request_sequence !== requestSequence || adapterRequestIds.has(requestPair.record.request_id)) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${operationCode} request sequence or identity differs from the frozen stream`)
      adapterRequestIds.add(requestPair.record.request_id)
      if (requestPair.record.recipient_binding_code !== semantic.adapter_binding_code || responsePair.record.sender_binding_code !== semantic.adapter_binding_code || requestPair.record.d930_operational_profile_record_digest_sha256 !== request.d930_operational_profile_record_digest_sha256 || responsePair.record.d930_operational_profile_record_digest_sha256 !== request.d930_operational_profile_record_digest_sha256) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${operationCode} adapter or custody profile differs`)
      exact(requestPair.record.payload.custody_intent, expectedIntent(semantic), `${operationCode} custody intent`)
      if (operationCode === 'open_staged') exact(responsePair.record.payload.artifact, semantic.artifact, 'open artifact')
      else exact(requestPair.record.payload.artifact, semantic.artifact, `${operationCode} artifact`)
      if (responsePair.record.created_at > semantic.completed_at) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${operationCode} response postdates receipt completion`)
      used.add(requestPair.record.record_digest_sha256)
      used.add(responsePair.record.record_digest_sha256)
      adapterPairs.set(operationCode, { request: requestPair.record, response: responsePair.record })
    }
    assertAdmittedOpenContext(adapterPairs.get('open_staged').request, adapterPairs.get('open_staged').response, semantic)
    const receiptOpenRequest = adapterPairs.get('open_staged').request
    for (const pair of adapterPairs.values()) if (pair.request.sender_binding_code !== receiptOpenRequest.sender_binding_code || pair.request.recipient_binding_code !== receiptOpenRequest.recipient_binding_code) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'receipt adapter stream changes requester or adapter identity')
    const publishPair = records.get(semantic.publish_request_record_digest_sha256)
    if (!publishPair || publishPair.record.message_kind_code !== 'request' || publishPair.record.operation_code !== 'publish_no_replace' || publishPair.record.created_at > semantic.completed_at) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'publish request does not resolve exactly')
    if (publishPair.record.recipient_binding_code !== semantic.adapter_binding_code || publishPair.record.d930_operational_profile_record_digest_sha256 !== request.d930_operational_profile_record_digest_sha256) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'publish request adapter or custody profile differs')
    if (publishPair.record.sender_binding_code !== receiptOpenRequest.sender_binding_code) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'publish requester differs from the admitted staged-open requester')
    if (publishPair.record.request_sequence !== 4 || adapterRequestIds.has(publishPair.record.request_id)) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'publish request sequence or identity differs from the frozen stream')
    adapterRequestIds.add(publishPair.record.request_id)
    exact(publishPair.record.payload.custody_intent, expectedIntent(semantic), 'publish custody intent')
    for (const field of ['artifact', 'copy_code', 'backend_code', 'backend_reference']) exact(publishPair.record.payload[field], semantic[field], `publish ${field}`)
    used.add(publishPair.record.record_digest_sha256)
    if (records.size !== 7 || used.size !== 7 || [...records.keys()].some((digest) => !used.has(digest))) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'supporting prerequisite graph is not bijective')
    const journals = new Set(pairs.map((pair) => pair.request.payload.journal_code))
    if (journals.size !== 1 || [...journals][0] !== `journal.${request.operation_id}`) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'supporting records target another journal')
    const capabilities = reconstructFinalizationCapabilities(adapterPairs, publishPair.record)
    if (semantic.source_capability_consumed_transition_digest_sha256 !== capabilities.sourceConsumed.record_digest_sha256 ||
        semantic.preparation_capability_issuance_digest_sha256 !== capabilities.preparationIssuance.record_digest_sha256 ||
        semantic.preparation_capability_verified_transition_digest_sha256 !== capabilities.preparationVerified.record_digest_sha256 ||
        semantic.preparation_capability_verified_transition_digest_sha256 !== publishPair.record.payload.preparation_capability_leaf_record_digest_sha256) {
      failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'deterministically reconstructed capability lineage differs')
    }
    return { records, semantic }
  }
  function collectReceiptPrerequisitePairs(request) {
    const supportingDigests = [
      request.payload.receipt_semantic.open_staged_response_record_digest_sha256,
      request.payload.receipt_semantic.prepare_response_record_digest_sha256,
      request.payload.receipt_semantic.verify_prepared_response_record_digest_sha256,
      request.payload.receipt_semantic.publish_request_record_digest_sha256,
    ]
    const pairs = []
    for (const digest of supportingDigests) {
      const record = supportingRecords.get(digest)
      const supportingRequest = [...supportingRequests.values()].find((candidate) => candidate.payload.supporting_record_digest_sha256 === digest)
      const supportingResponse = supportingRequest ? supportingResponses.get(supportingRequest.request_id) : null
      if (!record || !supportingRequest || !supportingResponse) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'receipt prerequisite is not durably persisted')
      pairs.push({ record, request: supportingRequest, response: supportingResponse })
      if (record.message_kind_code === 'response') {
        const requestRecord = [...supportingRecords.values()].find((candidate) => candidate.record_digest_sha256 === record.request_record_digest_sha256)
        if (!requestRecord) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'adapter response prerequisite has no exact request')
        const requestSupport = [...supportingRequests.values()].find((candidate) => candidate.payload.supporting_record_digest_sha256 === requestRecord.record_digest_sha256)
        const requestAck = requestSupport ? supportingResponses.get(requestSupport.request_id) : null
        if (!requestSupport || !requestAck) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'adapter request prerequisite is not durably persisted')
        pairs.push({ record: requestRecord, request: requestSupport, response: requestAck })
      }
    }
    const unique = new Map(pairs.map((pair) => [pair.record.record_digest_sha256, pair]))
    if (unique.size !== 7) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'receipt requires exactly seven distinct pre-response supporting records')
    return [...unique.values()]
  }
  function validatePendingAppendRequest(request) {
    assertAppendRequestEnvelope(request)
    const semantic = request.payload.semantic_assertion
    const prior = journalHeads.get(request.payload.journal_code)
    const expectedSequence = (prior?.event_sequence ?? 0) + 1
    const expectedPrevious = prior?.record_digest_sha256 ?? null
    if (request.payload.expected_event_sequence !== expectedSequence || request.payload.expected_previous_event_record_digest_sha256 !== expectedPrevious) failD931('D931_JOURNAL_FORK_OR_GAP', 'eventless append request does not extend the reconstructed exact head')
    if (!prior && semantic.event_kind_code !== 'operation_started') failD931('D931_JOURNAL_HISTORY_REJECTED', 'eventless journal root is not operation_started')
    if (prior && ['operation_completed', 'recovery_required'].includes(prior.semantic_assertion.event_kind_code)) failD931('D931_JOURNAL_HISTORY_REJECTED', 'eventless request extends a terminal journal')
    if (prior?.format_version && prior.format_version !== '2.0.0') failD931('D931_JOURNAL_VERSION_MIXED', 'eventless request would mix journal versions')
    if (prior && !(prior.semantic_assertion.event_at < semantic.event_at)) failD931('D931_JOURNAL_TIME_REJECTED', 'eventless request semantic time is not after the reconstructed head')
    const stableContext = [semantic.operation_id, semantic.operation_nonce, semantic.operation_mode_code, semantic.runtime_profile_record_digest_sha256, semantic.identity_bindings_record_digest_sha256, semantic.d930_journal_profile_record_digest_sha256, semantic.authorization_permit_record_digest_sha256, semantic.authorization_bundle_seal_record_digest_sha256, semantic.bundle, semantic.target_logical_state]
    const priorContext = journalContexts.get(request.payload.journal_code)
    if (priorContext && canonicalize(priorContext) !== canonicalize(stableContext)) failD931('D931_JOURNAL_CONTEXT_DRIFT', 'eventless request changes the reconstructed operation context')
    const operationKey = `${semantic.operation_id}/${semantic.operation_nonce}`
    const operationJournal = operationJournals.get(operationKey)
    if (operationJournal && operationJournal !== request.payload.journal_code) failD931('D931_JOURNAL_OPERATION_FORK', 'eventless request forks one operation across journals')
    assertHistoryPrefix(contractSet, journalHistories.get(request.payload.journal_code) ?? [], semantic)
    validateCustodyFinalization(semantic, request.payload.journal_code)
  }
  function assertIntegrityLifecycleProducer(record, verifiedPeer = null) {
    if (record.format !== 'jedi-atlas-integrity-access-lifecycle-record') return
    const expectedCode = record.record_kind_code === 'descriptor_delivery' ? `integrity.delivery.${record.operation_id}` : record.record_kind_code === 'verifier_result' ? `integrity.result.${record.operation_id}` : record.record_kind_code === 'access_closed_and_receiver_terminated' ? `integrity.terminal.${record.operation_id}` : null
    if (record.record_code !== expectedCode) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity lifecycle record has a noncanonical identity')
    const verifier = admissionResolver.resolveBinding(record.verifier_binding_code)
    if (verifier.runtime_role_code !== 'independent_verifier' || verifier.executable_sha256 !== record.verifier_executable_sha256 || admissionResolver.bindingRole(record.sender_binding_code) !== 'bundle_importer' || record.receiver_binding_code !== record.verifier_binding_code) failD931('D931_SUPPORTING_ROLE_REJECTED', 'integrity lifecycle participant bindings differ')
    const expectedProducerRole = record.record_kind_code === 'verifier_result' ? 'independent_verifier' : 'trusted_launcher'
    if (admissionResolver.bindingRole(record.producer_binding_code) !== expectedProducerRole || (record.record_kind_code === 'verifier_result' && record.producer_binding_code !== record.verifier_binding_code) || (verifiedPeer && (verifiedPeer.bindingCode !== record.producer_binding_code || verifiedPeer.executableSha256 !== admissionResolver.resolveBinding(record.producer_binding_code).executable_sha256))) failD931('D931_SUPPORTING_ROLE_REJECTED', 'integrity lifecycle producer is not the exact frozen role/build')
    if (record.backend_reference !== `objects/sha256/${record.artifact.sha256.slice(0, 2)}/${record.artifact.sha256}`) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity lifecycle backend reference differs')
    if (record.record_kind_code === 'verifier_result' && ((record.verification_outcome_code === 'passed') !== (canonicalize(record.recomputed_artifact) === canonicalize(record.artifact)))) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity verifier result differs from the exact artifact')
    if (record.record_kind_code === 'access_closed_and_receiver_terminated') {
      const complete = record.sender_close_state_code === 'confirmed' && record.receiver_termination_state_code === 'confirmed' && record.receiver_descriptor_closed_by_termination === true && ['clean_exit_reaped', 'signaled_reaped', 'forced_kill_reaped'].includes(record.termination_disposition_code)
      if ((record.lifecycle_outcome_code === 'completed_verified' && !complete) || record.sender_closed_at > record.event_at || record.receiver_terminated_at > record.event_at) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity lifecycle terminal state or chronology differs')
    }
    const serialized = canonicalize(record)
    for (const prohibited of ['raw_descriptor', 'bearer', 'token', 'socket_path', 'credential', 'absolute_path']) if (serialized.includes(`\"${prohibited}`)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity lifecycle contains a prohibited secret or path field')
  }
  function reconstructIntegrityCapability(sealRequest, sealResponse) {
    const clearance = admissionResolver.resolveRecord(sealRequest.payload.clearance_decision_record_digest_sha256)
    if (clearance.record_kind_code !== 'clearance_decision' || clearance.decision_code !== 'restricted_store_only' || clearance.record_digest_sha256 !== sealRequest.payload.clearance_decision_record_digest_sha256 || clearance.clearance_scope_sha256 !== sealRequest.payload.clearance_scope_sha256 || canonicalize(clearance.artifact) !== canonicalize(sealRequest.payload.artifact) || !(clearance.not_before <= sealResponse.created_at && sealResponse.created_at < clearance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity stream clearance is not the exact active admitted synthetic decision')
    const expiresAt = new Date(Math.min(Date.parse(clearance.expires_at), Date.parse(sealResponse.created_at) + 30_000)).toISOString()
    const issuance = canonicalRecord({
      format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_issuance',
      record_code: `capability.sealed_custody_access.${sealRequest.record_digest_sha256.slice(0, 32)}`, capability_kind_code: 'sealed_custody_access',
      issued_by_binding_code: sealRequest.recipient_binding_code, requester_binding_code: sealRequest.sender_binding_code, adapter_binding_code: sealRequest.recipient_binding_code,
      operation_id: sealRequest.operation_id, operation_nonce: sealRequest.operation_nonce, runtime_profile_record_digest_sha256: sealRequest.runtime_profile_record_digest_sha256,
      identity_bindings_record_digest_sha256: sealRequest.identity_bindings_record_digest_sha256, artifact: structuredClone(sealRequest.payload.artifact),
      allowed_consumer_operation_codes: ['open_custody'], replay_policy_code: 'single_consume_open_custody',
      grant_scope: { scope_kind_code: 'sealed_custody_access', basis_request_record_digest_sha256: sealRequest.record_digest_sha256, clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256, custody_leaf_projection_sha256: sealResponse.payload.custody_leaf_projection_sha256, backend_code: sealResponse.payload.backend_code, backend_reference: sealResponse.payload.backend_reference, copy_code: sealResponse.payload.copy_code, purpose_code: 'integrity', custody_evaluated_at: sealResponse.payload.custody_evaluated_at, known_through_bundle_sequence: sealResponse.payload.known_through_bundle_sequence },
      issued_at: sealResponse.created_at, expires_at: expiresAt, record_digest_sha256: null,
    })
    validateD90CustodyRecord({ contractSet, record: issuance })
    if (sealResponse.payload.sealed_capability_record_digest_sha256 !== issuance.record_digest_sha256 || sealResponse.payload.sealed_capability_leaf_record_digest_sha256 !== issuance.record_digest_sha256 || !(sealRequest.created_at < issuance.issued_at && issuance.issued_at < issuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'sealed capability identity or chronology differs from deterministic reconstruction')
    return issuance
  }
  function assertIntegrityAdapterStream(requests, adapterResponsesByRequest) {
    requests.sort((left, right) => left.request_sequence - right.request_sequence)
    if (requests.length > 2 || requests[0]?.operation_code !== 'seal_custody_access' || requests[0].request_sequence !== 1) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity adapter stream does not begin with access sealing')
    const sealRequest = requests[0]
    const sealResponse = adapterResponsesByRequest.get(sealRequest.record_digest_sha256)
    if (!sealResponse && requests.length > 1) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'open custody follows an unacknowledged seal request')
    let issuance = null
    if (sealResponse) {
      assertAdapterPair(sealRequest, sealResponse)
      if (sealResponse.payload.outcome_code === 'sealed') issuance = reconstructIntegrityCapability(sealRequest, sealResponse)
      else if (requests.length > 1) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'open custody follows a failed seal response')
    }
    const openRequest = requests[1]
    if (!openRequest) return { sealRequest, sealResponse, openRequest: null, openResponse: null, issuance }
    if (openRequest.operation_code !== 'open_custody' || openRequest.request_sequence !== 2) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity adapter stream is gapped or reordered')
    for (const field of ['operation_id', 'operation_nonce', 'sender_binding_code', 'recipient_binding_code', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256']) exact(openRequest[field], sealRequest[field], `integrity stream ${field}`, 'D931_SUPPORTING_CHAIN_CORRUPT')
    for (const field of ['artifact', 'backend_code', 'backend_reference', 'copy_code', 'primary_receipt', 'purpose_code']) exact(openRequest.payload[field], sealRequest.payload[field], `integrity stream ${field}`, 'D931_SUPPORTING_CHAIN_CORRUPT')
    if (!issuance || sealResponse.created_at >= openRequest.created_at || openRequest.created_at >= issuance.expires_at || openRequest.payload.sealed_capability_record_digest_sha256 !== issuance.record_digest_sha256 || openRequest.payload.sealed_capability_leaf_record_digest_sha256 !== issuance.record_digest_sha256) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'open custody does not claim the exact live sealed capability')
    const receipt = [...receiptsByOperation.values()].find((candidate) => candidate.record_code === openRequest.payload.primary_receipt.record_code)
    if (!receipt || sha256Bytes(exactRecordBytes(receipt)) !== openRequest.payload.primary_receipt.receipt_raw_sha256 || canonicalize(receipt.semantic.artifact) !== canonicalize(openRequest.payload.artifact) || receipt.semantic.copy_code !== openRequest.payload.copy_code || receipt.semantic.backend_code !== openRequest.payload.backend_code || receipt.semantic.backend_reference !== openRequest.payload.backend_reference || receipt.persisted_at > sealRequest.created_at) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity stream receipt does not bind and predate the exact primary copy access')
    const openResponse = adapterResponsesByRequest.get(openRequest.record_digest_sha256)
    if (openResponse) {
      assertAdapterPair(openRequest, openResponse)
      if (openResponse.payload.outcome_code === 'available') {
        if (!(openRequest.created_at < openResponse.created_at && openResponse.created_at < issuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'available custody response violates capability chronology')
        for (const field of ['clearance_decision_record_digest_sha256', 'clearance_scope_sha256', 'known_through_bundle_sequence', 'custody_leaf_projection_sha256']) exact(openResponse.payload[field], sealResponse.payload[field], `integrity response ${field}`, 'D931_SUPPORTING_CHAIN_CORRUPT')
        if (openResponse.payload.custody_evaluated_at !== openResponse.created_at) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'open custody response does not expose its exact response-time projection evaluation')
      }
    }
    return { sealRequest, sealResponse, openRequest, openResponse, issuance, receipt, openResponsePersistedAt: openResponse ? supportingPair(openResponse.record_digest_sha256).response.payload.persisted_at : null }
  }
  function assertIntegrityLifecycleGraphs(integrityStreams) {
    const groups = new Map()
    for (const record of supportingRecords.values()) if (record.format === 'jedi-atlas-integrity-access-lifecycle-record') {
      const key = `${record.operation_id}/${record.operation_nonce}`
      const group = groups.get(key) ?? []
      group.push(record)
      groups.set(key, group)
    }
    const order = ['descriptor_delivery', 'verifier_result', 'access_closed_and_receiver_terminated']
    for (const records of groups.values()) {
      records.sort((left, right) => left.event_at.localeCompare(right.event_at))
      if (records.length > 3 || records.some((record, index) => record.record_kind_code !== order[index])) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity lifecycle is not one ordered prefix')
      const delivery = records[0]
      const stream = integrityStreams.get(`${delivery.operation_id}/${delivery.operation_nonce}`)
      if (!stream?.openResponse || stream.openResponse.payload.outcome_code !== 'available') failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity lifecycle has no exact available custody exchange')
      const stableFields = ['operation_id', 'operation_nonce', 'bundle', 'artifact', 'copy_code', 'backend_code', 'backend_reference', 'purpose_code', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256', 'open_custody_request_record_digest_sha256', 'open_custody_response_record_digest_sha256', 'sealed_capability_record_digest_sha256', 'sealed_capability_consumed_transition_digest_sha256', 'sender_binding_code', 'receiver_binding_code', 'verifier_binding_code', 'verifier_executable_sha256', 'receiver_process']
      for (const record of records.slice(1)) for (const field of stableFields) exact(record[field], delivery[field], `integrity lifecycle ${field}`, 'D931_SUPPORTING_CHAIN_CORRUPT')
      if (delivery.open_custody_request_record_digest_sha256 !== stream.openRequest.record_digest_sha256 || delivery.open_custody_response_record_digest_sha256 !== stream.openResponse.record_digest_sha256 || delivery.sealed_capability_record_digest_sha256 !== stream.issuance.record_digest_sha256 || canonicalize(delivery.bundle) !== canonicalize(stream.receipt.semantic.bundle) || canonicalize(delivery.artifact) !== canonicalize(stream.openRequest.payload.artifact) || delivery.copy_code !== stream.openRequest.payload.copy_code || delivery.backend_code !== stream.openRequest.payload.backend_code || delivery.backend_reference !== stream.openRequest.payload.backend_reference || delivery.sender_binding_code !== stream.openRequest.sender_binding_code || delivery.runtime_profile_record_digest_sha256 !== stream.openRequest.runtime_profile_record_digest_sha256 || delivery.identity_bindings_record_digest_sha256 !== stream.openRequest.identity_bindings_record_digest_sha256 || delivery.d930_operational_profile_record_digest_sha256 !== stream.openRequest.d930_operational_profile_record_digest_sha256 || !(stream.openResponse.created_at < delivery.event_at) || !(stream.openResponsePersistedAt < delivery.event_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'integrity lifecycle differs from or predates the exact durably acknowledged custody stream')
      const verifier = records[1]
      const deliveryPersistedAt = supportingPair(delivery.record_digest_sha256).response.payload.persisted_at
      if (verifier && (verifier.descriptor_delivery_record_digest_sha256 !== delivery.record_digest_sha256 || !(delivery.event_at < verifier.event_at) || !(deliveryPersistedAt < verifier.event_at))) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'verifier result is not linked after durable descriptor delivery')
      const terminal = records[2]
      const verifierPersistedAt = verifier ? supportingPair(verifier.record_digest_sha256).response.payload.persisted_at : null
      if (terminal && (!verifier || terminal.descriptor_delivery_record_digest_sha256 !== delivery.record_digest_sha256 || terminal.verifier_result_record_digest_sha256 !== verifier.record_digest_sha256 || !(verifier.event_at < terminal.event_at) || !(verifierPersistedAt < terminal.receiver_terminated_at) || (terminal.lifecycle_outcome_code === 'completed_verified' && (verifier.verification_outcome_code !== 'passed' || canonicalize(verifier.recomputed_artifact) !== canonicalize(verifier.artifact))))) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'terminal lifecycle record is not linked after a durably acknowledged successful verifier result')
    }
    for (const [key, stream] of integrityStreams) if (stream.openResponse?.payload.outcome_code === 'available') {
      const records = groups.get(key)
      if (records?.length !== 3 || records[2].lifecycle_outcome_code !== 'completed_verified') failD931('D931_INTEGRITY_RECOVERY_REQUIRED', 'an available one-shot custody descriptor has no complete verified lifecycle after restart')
    }
  }
  function assertPublishResponseReceipt(publishRequest, publishResponse, code = 'D931_SUPPORTING_CHAIN_CORRUPT') {
    if (!['published', 'reused_verified'].includes(publishResponse.payload.outcome_code)) return
    const reference = publishResponse.payload.primary_receipt
    const receipt = [...receiptsByOperation.values()].find((candidate) => candidate.record_code === reference?.record_code)
    if (!receipt || sha256Bytes(exactRecordBytes(receipt)) !== reference.receipt_raw_sha256) failD931(code, 'successful publish response does not resolve its exact primary receipt')
    const receiptRequest = [...receiptRequests.values()].find((candidate) => candidate.record_digest_sha256 === receipt.persistence_request_record_digest_sha256)
    const receiptResponse = receiptRequest ? receiptResponses.get(receiptRequest.request_id) : null
    if (!receiptRequest || !receiptResponse || publishResponse.payload.receipt_broker_ack_record_digest_sha256 !== receiptResponse.record_digest_sha256 || publishResponse.created_at !== receiptResponse.created_at || receipt.semantic.publish_request_record_digest_sha256 !== publishRequest.record_digest_sha256 || receipt.semantic.finalization_outcome_code !== publishResponse.payload.outcome_code) failD931(code, 'successful publish response receipt acknowledgement, outcome, or chronology differs')
    for (const field of ['artifact', 'copy_code', 'backend_code', 'backend_reference']) exact(publishRequest.payload[field], receipt.semantic[field], `publish receipt ${field}`, code)
  }
  function validateCustodyFinalization(semantic, journalCode) {
    if (semantic.event_kind_code !== 'custody_object_durable') return
    const finalization = semantic.custody_finalization
    if (!finalization || finalization.backend_reference !== `objects/sha256/${finalization.artifact.sha256.slice(0, 2)}/${finalization.artifact.sha256}`) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody finalization or backend reference is missing')
    const expected = [['open_staged', 'opened'], ['prepare', 'prepared'], ['verify_prepared', 'verified'], ['publish_no_replace', null]]
    if (finalization.exchanges.length !== expected.length) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody exchange cardinality differs')
    const adapterPairs = new Map()
    for (const [index, exchange] of finalization.exchanges.entries()) {
      const [operationCode, requiredOutcome] = expected[index]
      const requestPair = supportingPair(exchange.request_record_digest_sha256)
      const responsePair = supportingPair(exchange.response_record_digest_sha256)
      if (requestPair.request.payload.journal_code !== journalCode || responsePair.request.payload.journal_code !== journalCode || requestPair.response.record_digest_sha256 !== exchange.request_persistence_ack_record_digest_sha256 || responsePair.response.record_digest_sha256 !== exchange.response_persistence_ack_record_digest_sha256) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody exchange acknowledgement or journal differs')
      assertAdapterPair(requestPair.record, responsePair.record)
      if (exchange.operation_code !== operationCode || requestPair.record.operation_code !== operationCode || responsePair.record.operation_code !== operationCode || responsePair.record.payload.outcome_code !== exchange.success_outcome_code || (requiredOutcome !== null && exchange.success_outcome_code !== requiredOutcome)) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody exchange operation or outcome differs')
      if (requestPair.record.recipient_binding_code !== semantic.component_binding_code || responsePair.record.sender_binding_code !== semantic.component_binding_code || requestPair.record.d930_operational_profile_record_digest_sha256 !== admissionResolver.custodyProfile.record_digest_sha256 || responsePair.record.d930_operational_profile_record_digest_sha256 !== admissionResolver.custodyProfile.record_digest_sha256) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody exchange adapter or profile differs')
      for (const field of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) exact(requestPair.record[field], semantic[field], `finalization ${field}`, 'D931_CUSTODY_EVIDENCE_INCOMPLETE')
      if (requestPair.response.created_at > semantic.event_at || responsePair.response.created_at > semantic.event_at) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'custody supporting acknowledgement postdates semantic event')
      adapterPairs.set(operationCode, { request: requestPair.record, response: responsePair.record })
    }
    const rootEvent = persistedEvents.find((candidate) => candidate.journal_code === journalCode && candidate.event_sequence === 1)
    const openRequest = adapterPairs.get('open_staged').request
    if (!rootEvent || rootEvent.semantic_assertion.event_kind_code !== 'operation_started' || rootEvent.semantic_assertion.event_at > openRequest.created_at || rootEvent.persisted_at > openRequest.created_at) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'durably persisted operation start must precede the first custody request')
    const receipt = [...receiptsByOperation.values()].find((candidate) => candidate.record_code === finalization.primary_receipt.record_code)
    if (!receipt || sha256Bytes(exactRecordBytes(receipt)) !== finalization.primary_receipt.receipt_raw_sha256) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'primary receipt reference is unresolved')
    if (receipt.record_code !== `receipt.primary.${semantic.operation_id}` || receipt.semantic.operation_id !== semantic.operation_id || receipt.semantic.operation_nonce !== semantic.operation_nonce || receipt.semantic.bundle_seal_record_digest_sha256 !== semantic.authorization_bundle_seal_record_digest_sha256) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'primary receipt does not bind the exact finalization operation and bundle seal')
    for (const field of ['artifact', 'copy_code', 'backend_code', 'backend_reference']) exact(finalization[field], receipt.semantic[field], `finalization ${field}`, 'D931_CUSTODY_EVIDENCE_INCOMPLETE')
    exact(semantic.bundle, receipt.semantic.bundle, 'finalization bundle', 'D931_CUSTODY_EVIDENCE_INCOMPLETE')
    if (semantic.component_binding_code !== receipt.semantic.adapter_binding_code || semantic.component_executable_sha256 !== receipt.semantic.adapter_executable_sha256 || finalization.exchanges.at(-1).success_outcome_code !== receipt.semantic.finalization_outcome_code) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'finalization adapter identity or outcome differs')
    const publishResponse = supportingPair(finalization.exchanges.at(-1).response_record_digest_sha256).record
    const receiptRequest = [...receiptRequests.values()].find((candidate) => candidate.record_digest_sha256 === receipt.persistence_request_record_digest_sha256)
    const receiptResponse = receiptRequest ? receiptResponses.get(receiptRequest.request_id) : null
    if (!receiptRequest || !receiptResponse || publishResponse.payload.receipt_broker_ack_record_digest_sha256 !== receiptResponse.record_digest_sha256 || canonicalize(publishResponse.payload.primary_receipt) !== canonicalize(finalization.primary_receipt) || receiptResponse.created_at !== publishResponse.created_at || publishResponse.created_at > semantic.event_at) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'publish response receipt reference or chronology differs')
    assertPublishResponseReceipt(adapterPairs.get('publish_no_replace').request, publishResponse, 'D931_CUSTODY_EVIDENCE_INCOMPLETE')
    const capabilities = reconstructFinalizationCapabilities(adapterPairs, adapterPairs.get('publish_no_replace').request, publishResponse)
    if (finalization.preparation_capability_consumed_transition_digest_sha256 !== capabilities.preparationConsumed.record_digest_sha256) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'deterministically reconstructed finalization capability transition differs')
    const created = receipt.semantic.no_replace_disposition_code === 'created_new'
    if (semantic.object_disposition_code !== 'durable_referenced' || semantic.objects_delta.prepared !== Number(created) || semantic.objects_delta.reused !== Number(!created) || semantic.objects_delta.orphaned !== 0) failD931('D931_CUSTODY_EVIDENCE_INCOMPLETE', 'finalization object projection differs')
  }

  // Reconstruct exact heads and replay maps from the protected namespaces.
  const persistedEvents = [...store.inventory().projection['journal-events'].map((item) => ({ ...item, namespace: 'journal-events' })), ...store.inventory().projection['recovery-assessments'].map((item) => ({ ...item, namespace: 'recovery-assessments' }))]
    .map((item) => {
      const record = loadProtectedRecord(item.namespace, item)
      if (record.format !== 'jedi-atlas-operation-journal-event' || (item.namespace === 'journal-events') !== (record.semantic_assertion.recovery === null)) failD931('D931_PROTECTED_NAMESPACE_CORRUPT', 'journal record kind does not match its protected namespace')
      return record
    })
    .sort((left, right) => left.journal_code.localeCompare(right.journal_code) || left.event_sequence - right.event_sequence)
  const eventCodes = new Set()
  for (const record of persistedEvents) {
    if (eventCodes.has(record.record_code)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'journal event appears in more than one protected namespace')
    eventCodes.add(record.record_code)
    assertPersistedEvent(record)
    assertD931ReachableSemantic(record.semantic_assertion)
    assertD931SemanticProducer(bindingRoleResolver, record.semantic_assertion)
    if (journalEventsByRequestDigest.has(record.append_request_record_digest_sha256)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'multiple events bind one append request')
    journalEventsByRequestDigest.set(record.append_request_record_digest_sha256, record)
    const prior = journalHeads.get(record.journal_code)
    if (record.event_sequence !== (prior?.event_sequence ?? 0) + 1 || record.previous_event_record_digest_sha256 !== (prior?.record_digest_sha256 ?? null)) {
      failD931('D931_JOURNAL_CHAIN_CORRUPT', 'persisted journal is gapped or forked')
    }
    if (prior && !(prior.persisted_at < record.persisted_at)) failD931('D931_JOURNAL_TIME_CORRUPT', 'persisted journal time is not strictly increasing')
    if (!prior && record.semantic_assertion.event_kind_code !== 'operation_started') failD931('D931_JOURNAL_HISTORY_REJECTED', 'persisted journal root is not operation_started')
    if (prior && ['operation_completed', 'recovery_required'].includes(prior.semantic_assertion.event_kind_code)) failD931('D931_JOURNAL_HISTORY_REJECTED', 'persisted terminal journal was extended')
    const priorSemantics = journalHistories.get(record.journal_code) ?? []
    assertHistoryPrefix(contractSet, priorSemantics, record.semantic_assertion)
    const semantic = record.semantic_assertion
    if (prior && !(prior.semantic_assertion.event_at < semantic.event_at)) failD931('D931_JOURNAL_TIME_CORRUPT', 'semantic event time is not strictly increasing')
    const context = [semantic.operation_id, semantic.operation_nonce, semantic.operation_mode_code, semantic.runtime_profile_record_digest_sha256, semantic.identity_bindings_record_digest_sha256, semantic.d930_journal_profile_record_digest_sha256, semantic.authorization_permit_record_digest_sha256, semantic.authorization_bundle_seal_record_digest_sha256, semantic.bundle, semantic.target_logical_state]
    const previousContext = journalContexts.get(record.journal_code)
    if (previousContext && canonicalize(previousContext) !== canonicalize(context)) failD931('D931_JOURNAL_CONTEXT_DRIFT', 'journal operation context changed')
    const priorJournal = operationJournals.get(`${semantic.operation_id}/${semantic.operation_nonce}`)
    if (priorJournal && priorJournal !== record.journal_code) failD931('D931_JOURNAL_OPERATION_FORK', 'one operation appears in multiple journals')
    journalContexts.set(record.journal_code, context)
    operationJournals.set(`${semantic.operation_id}/${semantic.operation_nonce}`, record.journal_code)
    if (semantic.recovery) {
      const recovery = semantic.recovery
      const priorRecovery = recoveryAttempts.get(recovery.recovery_chain_code)
      if (recovery.recovery_attempt_sequence !== (priorRecovery?.sequence ?? 0) + 1 || recovery.prior_attempt_terminal_record_digest_sha256 !== (priorRecovery?.digest ?? null)) failD931('D931_RECOVERY_ATTEMPT_FORK', 'recovery attempt chain is gapped or forked')
      recoveryAttempts.set(recovery.recovery_chain_code, { sequence: recovery.recovery_attempt_sequence, digest: semantic.record_digest_sha256 })
    }
    journalHeads.set(record.journal_code, record)
    journalHistories.set(record.journal_code, [...priorSemantics, record.semantic_assertion])
  }
  for (const item of store.inventory().projection['receipt-exchanges']) {
    const record = loadProtectedRecord('receipt-exchanges', item)
    if (record.format !== 'jedi-atlas-durability-receipt-broker-message' || !['persist_request', 'persist_response'].includes(record.message_kind_code)) failD931('D931_PROTECTED_NAMESPACE_CORRUPT', 'receipt exchange record kind does not match its protected namespace')
    const target = record.message_kind_code === 'persist_request' ? receiptRequests : receiptResponses
    if (target.has(record.request_id)) failD931('D931_RECEIPT_REPLAY_COLLISION', 'duplicate persisted receipt request identity')
    if (record.message_kind_code === 'persist_request') assertReceiptRequestEnvelope(record)
    target.set(record.request_id, record)
  }
  for (const item of store.inventory().projection['primary-receipts']) {
    const record = loadProtectedRecord('primary-receipts', item)
    if (record.format !== 'jedi-atlas-primary-durability-receipt') failD931('D931_PROTECTED_NAMESPACE_CORRUPT', 'primary receipt record kind does not match its protected namespace')
    if (receiptsByRequestDigest.has(record.persistence_request_record_digest_sha256)) failD931('D931_RECEIPT_REPLAY_COLLISION', 'multiple receipts bind one persistence request')
    const operationKey = `${record.semantic.operation_id}/${record.semantic.operation_nonce}`
    if (receiptsByOperation.has(operationKey)) failD931('D931_RECEIPT_REPLAY_COLLISION', 'multiple primary receipts bind one operation')
    receiptsByRequestDigest.set(record.persistence_request_record_digest_sha256, record)
    receiptsByOperation.set(operationKey, record)
  }
  for (const item of store.inventory().projection['supporting-records']) {
    const record = loadProtectedRecord('supporting-records', item)
    if (record.format === 'jedi-atlas-operation-journal-broker-message') {
      if (record.message_kind_code === 'persist_supporting_request') {
        if (supportingRequests.has(record.request_id)) failD931('D931_SUPPORTING_REPLAY_COLLISION', 'duplicate persisted supporting request identity')
        supportingRequests.set(record.request_id, record)
      } else if (record.message_kind_code === 'persist_supporting_response') {
        if (supportingResponses.has(record.request_id) || journalResponses.has(record.request_id)) failD931('D931_SUPPORTING_REPLAY_COLLISION', 'duplicate persisted supporting response identity')
        supportingResponses.set(record.request_id, record)
        journalResponses.set(record.request_id, record)
      } else if (record.message_kind_code === 'append_response') {
        if (journalResponses.has(record.request_id)) failD931('D931_JOURNAL_REPLAY_COLLISION', 'duplicate persisted journal response identity')
        journalResponses.set(record.request_id, record)
      } else if (record.message_kind_code === 'append_request') {
        if (journalAppendRequests.has(record.request_id) || journalAppendRequestsByDigest.has(record.record_digest_sha256)) failD931('D931_JOURNAL_REPLAY_COLLISION', 'duplicate persisted append request identity')
        assertAppendRequestEnvelope(record)
        journalAppendRequests.set(record.request_id, record)
        journalAppendRequestsByDigest.set(record.record_digest_sha256, record)
      }
      else failD931('D931_PERSISTED_RECORD_REJECTED', 'unexpected broker message in supporting namespace')
    } else if (record.format === 'jedi-atlas-custody-adapter-message' || record.format === 'jedi-atlas-integrity-access-lifecycle-record') {
      const digest = record.record_digest_sha256
      if (supportingRecords.has(digest)) failD931('D931_SUPPORTING_REPLAY_COLLISION', 'duplicate supporting record digest')
      if (record.format === 'jedi-atlas-custody-adapter-message') assertAdapterSubjectIdentity(record)
      assertIntegrityLifecycleProducer(record)
      supportingRecords.set(digest, record)
    } else failD931('D931_PROTECTED_NAMESPACE_CORRUPT', 'supporting record kind does not match its protected namespace')
  }
  for (const [requestId, request] of supportingRequests) {
    const response = supportingResponses.get(requestId)
    const record = supportingRecords.get(request.payload.supporting_record_digest_sha256)
    if (!record || !response) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'persisted supporting exchange is incomplete')
    assertSupportingBrokerPair(request, response, record)
  }
  for (const requestId of supportingResponses.keys()) if (!supportingRequests.has(requestId)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'supporting response has no request')
  const supportingReferenceCounts = new Map()
  for (const request of supportingRequests.values()) supportingReferenceCounts.set(request.payload.supporting_record_digest_sha256, (supportingReferenceCounts.get(request.payload.supporting_record_digest_sha256) ?? 0) + 1)
  for (const digest of supportingRecords.keys()) if (supportingReferenceCounts.get(digest) !== 1) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'supporting subject does not have exactly one protected request and response')
  const partialCustodyStreams = new Map()
  const partialIntegrityStreams = new Map()
  const adapterResponsesByRequest = new Map()
  for (const record of supportingRecords.values()) if (record.format === 'jedi-atlas-custody-adapter-message') {
    if (record.message_kind_code === 'response') {
      if (adapterResponsesByRequest.has(record.request_record_digest_sha256)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'multiple adapter responses bind one protected request')
      adapterResponsesByRequest.set(record.request_record_digest_sha256, record)
    } else if (['open_staged', 'prepare', 'verify_prepared', 'publish_no_replace'].includes(record.operation_code)) {
      const key = `${record.operation_id}/${record.operation_nonce}`
      const stream = partialCustodyStreams.get(key) ?? []
      stream.push(record)
      partialCustodyStreams.set(key, stream)
    } else if (['seal_custody_access', 'open_custody'].includes(record.operation_code)) {
      const key = `${record.operation_id}/${record.operation_nonce}`
      const stream = partialIntegrityStreams.get(key) ?? []
      stream.push(record)
      partialIntegrityStreams.set(key, stream)
    }
  }
  for (const response of adapterResponsesByRequest.values()) if (!supportingRecords.has(response.request_record_digest_sha256)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'protected adapter response has no exact protected request')
  const finalizationOperations = ['open_staged', 'prepare', 'verify_prepared', 'publish_no_replace']
  for (const requests of partialCustodyStreams.values()) {
    requests.sort((left, right) => left.request_sequence - right.request_sequence)
    const open = requests[0]
    if (open.operation_code !== 'open_staged' || open.request_sequence !== 1) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial custody stream does not begin with staged open')
    const intent = open.payload.custody_intent
    let previousResponse = null
    for (const [index, request] of requests.entries()) {
      if (request.request_sequence !== index + 1 || request.operation_code !== finalizationOperations[index] || canonicalize(request.payload.custody_intent) !== canonicalize(intent)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial custody stream is gapped, duplicated, reordered, or changes intent')
      for (const field of ['sender_binding_code', 'recipient_binding_code', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256']) exact(request[field], open[field], `partial custody ${field}`, 'D931_SUPPORTING_CHAIN_CORRUPT')
      if (request.operation_code !== 'open_staged') exact(request.payload.artifact, intent.artifact, `partial custody ${request.operation_code} artifact`, 'D931_SUPPORTING_CHAIN_CORRUPT')
      if (request.operation_code === 'publish_no_replace') for (const field of ['copy_code', 'backend_code', 'backend_reference']) exact(request.payload[field], intent[field], `partial custody publish ${field}`, 'D931_SUPPORTING_CHAIN_CORRUPT')
      if (previousResponse && !(previousResponse.created_at < request.created_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial custody response does not strictly precede its successor request')
      const response = adapterResponsesByRequest.get(request.record_digest_sha256)
      if (response) {
        assertAdapterPair(request, response)
        if (index < requests.length - 1) {
          const operationRule = contractSet.classifications.custody_message_rules.find((entry) => entry.operation_code === request.operation_code)
          if (!operationRule?.success_outcomes.includes(response.payload.outcome_code)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'failed adapter response cannot have a successor request')
        }
      }
      else if (index !== requests.length - 1) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'nonterminal partial custody request lacks its protected response')
      previousResponse = response ?? previousResponse
    }
    const openResponse = adapterResponsesByRequest.get(open.record_digest_sha256)
    const persistence = supportingPair(open.record_digest_sha256)
    assertPersistedOperationStartForOpen(open)
    assertAdmittedStagedOpen(open, openResponse?.created_at ?? persistence.response.payload.persisted_at, 'D931_SUPPORTING_CHAIN_CORRUPT')
    if (openResponse?.payload.outcome_code === 'opened') {
      exact(openResponse.payload.artifact, intent.artifact, 'partial staged-open response artifact', 'D931_SUPPORTING_CHAIN_CORRUPT')
      const sourceIssuance = canonicalRecord({
        format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_issuance',
        record_code: `capability.source_handle.${open.record_digest_sha256.slice(0, 32)}`, capability_kind_code: 'source_handle',
        issued_by_binding_code: open.recipient_binding_code, requester_binding_code: open.sender_binding_code, adapter_binding_code: open.recipient_binding_code,
        operation_id: open.operation_id, operation_nonce: open.operation_nonce, runtime_profile_record_digest_sha256: open.runtime_profile_record_digest_sha256,
        identity_bindings_record_digest_sha256: open.identity_bindings_record_digest_sha256, artifact: structuredClone(intent.artifact),
        allowed_consumer_operation_codes: ['prepare'], replay_policy_code: 'single_consume_prepare',
        grant_scope: { scope_kind_code: 'source_handle', basis_request_record_digest_sha256: open.record_digest_sha256, collector_handoff_record_digest_sha256: open.payload.collector_handoff_record_digest_sha256, bundle_seal_record_digest_sha256: open.payload.bundle_seal_record_digest_sha256, staging_snapshot_code: open.payload.staging_snapshot_code, staging_root_slot_code: 'staging_root', relative_path: open.payload.relative_path, descriptor_role_code: 'staged_source', staged_source_descriptor_ordinal: 1 },
        issued_at: openResponse.created_at, expires_at: new Date(Date.parse(openResponse.created_at) + 30_000).toISOString(), record_digest_sha256: null,
      })
      validateD90CustodyRecord({ contractSet, record: sourceIssuance })
      if (!(open.created_at < openResponse.created_at && sourceIssuance.expires_at === new Date(Date.parse(sourceIssuance.issued_at) + 30_000).toISOString()) || openResponse.payload.source_capability_record_digest_sha256 !== sourceIssuance.record_digest_sha256 || openResponse.payload.source_capability_leaf_record_digest_sha256 !== sourceIssuance.record_digest_sha256) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial staged-open source capability identity, lifetime, or chronology differs')
      const prepare = requests[1]
      if (prepare && (prepare.payload.source_capability_record_digest_sha256 !== sourceIssuance.record_digest_sha256 || prepare.payload.source_capability_leaf_record_digest_sha256 !== sourceIssuance.record_digest_sha256)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial prepare does not consume the reconstructed source capability')
      if (prepare && !(sourceIssuance.issued_at < prepare.created_at && prepare.created_at < sourceIssuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial prepare request falls outside the source capability lifetime')
      const prepareResponse = prepare ? adapterResponsesByRequest.get(prepare.record_digest_sha256) : null
      if (prepare && !prepareResponse && !(supportingPair(prepare.record_digest_sha256).response.payload.persisted_at < sourceIssuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'unanswered prepare request was durably observed after source capability expiry')
      if (prepareResponse?.payload.outcome_code === 'prepared') {
        const preparationIssuance = canonicalRecord({
          format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_issuance',
          record_code: `capability.preparation.${prepare.record_digest_sha256.slice(0, 32)}`, capability_kind_code: 'preparation',
          issued_by_binding_code: prepare.recipient_binding_code, requester_binding_code: prepare.sender_binding_code, adapter_binding_code: prepare.recipient_binding_code,
          operation_id: prepare.operation_id, operation_nonce: prepare.operation_nonce, runtime_profile_record_digest_sha256: prepare.runtime_profile_record_digest_sha256,
          identity_bindings_record_digest_sha256: prepare.identity_bindings_record_digest_sha256, artifact: structuredClone(intent.artifact),
          allowed_consumer_operation_codes: ['verify_prepared', 'publish_no_replace', 'abandon_temp'], replay_policy_code: 'ordered_verify_then_publish_or_abandon',
          grant_scope: { scope_kind_code: 'preparation', basis_request_record_digest_sha256: prepare.record_digest_sha256, source_capability_record_digest_sha256: sourceIssuance.record_digest_sha256, pending_object_code: `pending.${prepare.operation_id}` },
          issued_at: prepareResponse.created_at, expires_at: new Date(Date.parse(prepareResponse.created_at) + 60_000).toISOString(), record_digest_sha256: null,
        })
        validateD90CustodyRecord({ contractSet, record: preparationIssuance })
        if (!(sourceIssuance.issued_at < prepare.created_at && prepare.created_at < prepareResponse.created_at && prepareResponse.created_at < sourceIssuance.expires_at && preparationIssuance.expires_at === new Date(Date.parse(preparationIssuance.issued_at) + 60_000).toISOString()) || prepareResponse.payload.preparation_capability_record_digest_sha256 !== preparationIssuance.record_digest_sha256 || prepareResponse.payload.preparation_capability_leaf_record_digest_sha256 !== preparationIssuance.record_digest_sha256) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial prepare capability identity, lifetime, or chronology differs')
        const verify = requests[2]
        if (verify && (verify.payload.preparation_capability_record_digest_sha256 !== preparationIssuance.record_digest_sha256 || verify.payload.preparation_capability_leaf_record_digest_sha256 !== preparationIssuance.record_digest_sha256)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial verification does not consume the reconstructed preparation capability')
        if (verify && !(preparationIssuance.issued_at < verify.created_at && verify.created_at < preparationIssuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial verification request falls outside the preparation capability lifetime')
        const verifyResponse = verify ? adapterResponsesByRequest.get(verify.record_digest_sha256) : null
        if (verify && !verifyResponse && !(supportingPair(verify.record_digest_sha256).response.payload.persisted_at < preparationIssuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'unanswered verification request was durably observed after preparation capability expiry')
        if (verifyResponse && !(preparationIssuance.issued_at < verify.created_at && verify.created_at <= verifyResponse.created_at && verifyResponse.created_at < preparationIssuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial verification violates preparation capability chronology')
        const publish = requests[3]
        if (publish && !(preparationIssuance.issued_at < publish.created_at && publish.created_at < preparationIssuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial publish request falls outside the preparation capability lifetime')
        if (publish && !adapterResponsesByRequest.get(publish.record_digest_sha256) && !(supportingPair(publish.record_digest_sha256).response.payload.persisted_at < preparationIssuance.expires_at)) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'unanswered publish request was durably observed after preparation capability expiry')
        if (verifyResponse?.payload.outcome_code === 'verified' && publish) {
          const verifiedTransition = canonicalRecord({
            format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_transition',
            record_code: `${preparationIssuance.record_code}.transition.1`, capability_kind_code: 'preparation', capability_record_digest_sha256: preparationIssuance.record_digest_sha256,
            transition_sequence: 1, previous_transition_record_digest_sha256: null, from_state_code: 'ready', to_state_code: 'verified', transition_code: 'verification_succeeded',
            request_record_digest_sha256: verify.record_digest_sha256, response_record_digest_sha256: verifyResponse.record_digest_sha256,
            recorded_by_binding_code: preparationIssuance.adapter_binding_code, occurred_at: verifyResponse.created_at, reason_code: 'verified_response', record_digest_sha256: null,
          })
          if (publish.payload.preparation_capability_record_digest_sha256 !== preparationIssuance.record_digest_sha256 || publish.payload.preparation_capability_leaf_record_digest_sha256 !== verifiedTransition.record_digest_sha256) failD931('D931_SUPPORTING_CHAIN_CORRUPT', 'partial publish does not consume the reconstructed verified preparation leaf')
        }
        if (verifyResponse?.payload.outcome_code === 'verified' && publish) {
          const pairs = new Map([
            ['open_staged', { request: open, response: openResponse }],
            ['prepare', { request: prepare, response: prepareResponse }],
            ['verify_prepared', { request: verify, response: verifyResponse }],
          ])
          const publishResponse = adapterResponsesByRequest.get(publish.record_digest_sha256) ?? null
          reconstructFinalizationCapabilities(pairs, publish, publishResponse)
          if (publishResponse) assertPublishResponseReceipt(publish, publishResponse)
        }
      }
    }
  }
  const resolvedIntegrityStreams = new Map()
  for (const [key, requests] of partialIntegrityStreams) resolvedIntegrityStreams.set(key, assertIntegrityAdapterStream(requests, adapterResponsesByRequest))
  assertIntegrityLifecycleGraphs(resolvedIntegrityStreams)
  for (const receipt of receiptsByRequestDigest.values()) {
    const request = [...receiptRequests.values()].find((candidate) => candidate.record_digest_sha256 === receipt.persistence_request_record_digest_sha256)
    if (!request || receipt.semantic_payload_sha256 !== canonicalSha256(receipt.semantic)) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'primary receipt request or semantic digest differs')
    assertReceiptRequestEffect(request, receipt)
    const semantic = receipt.semantic
    const pairs = [semantic.open_staged_response_record_digest_sha256, semantic.prepare_response_record_digest_sha256, semantic.verify_prepared_response_record_digest_sha256]
      .flatMap((digest) => { const responsePair = supportingPair(digest); return [supportingPair(responsePair.record.request_record_digest_sha256), responsePair] })
    pairs.push(supportingPair(semantic.publish_request_record_digest_sha256))
    validateReceiptPrerequisites(request, pairs)
    const response = receiptResponses.get(request.request_id)
    if (response) assertReceiptBrokerPair(request, response, receipt)
  }
  for (const response of receiptResponses.values()) {
    const request = receiptRequests.get(response.request_id)
    const receipt = request ? receiptsByRequestDigest.get(request.record_digest_sha256) : null
    if (!request || !receipt) failD931('D931_RECEIPT_CHAIN_CORRUPT', 'receipt response has no exact request and receipt')
  }
  for (const request of receiptRequests.values()) {
    if (receiptsByRequestDigest.has(request.record_digest_sha256)) continue
    const operationKey = `${request.operation_id}/${request.operation_nonce}`
    const priorRequest = pendingReceiptOperations.get(operationKey)
    if (priorRequest && priorRequest.record_digest_sha256 !== request.record_digest_sha256) failD931('D931_RECEIPT_REPLAY_COLLISION', 'multiple receipt requests bind one operation')
    pendingReceiptOperations.set(operationKey, request)
    validateReceiptPrerequisites(request, collectReceiptPrerequisitePairs(request))
  }
  for (const request of journalAppendRequests.values()) if (!journalEventsByRequestDigest.has(request.record_digest_sha256)) {
    if (journalResponses.has(request.request_id)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'eventless append request has an acknowledgement')
    const operationKey = `${request.operation_id}/${request.operation_nonce}`
    if (pendingAppendByJournal.has(request.payload.journal_code)) failD931('D931_JOURNAL_REPLAY_COLLISION', 'multiple eventless requests target one journal head')
    if (pendingAppendByOperation.has(operationKey)) failD931('D931_JOURNAL_OPERATION_FORK', 'multiple eventless requests reserve one operation')
    pendingAppendByJournal.set(request.payload.journal_code, request)
    pendingAppendByOperation.set(operationKey, request)
    validatePendingAppendRequest(request)
  }
  for (const event of persistedEvents) {
    assertD931SemanticPolicy(contractSet, event.semantic_assertion)
    validateCustodyFinalization(event.semantic_assertion, event.journal_code)
    const request = journalAppendRequestsByDigest.get(event.append_request_record_digest_sha256)
    const response = request ? journalResponses.get(request.request_id) : null
    assertAppendExchange(request, response, event)
  }
  const appendResponseDigests = new Set()
  for (const response of journalResponses.values()) if (response.message_kind_code === 'append_response') {
    if (appendResponseDigests.has(response.request_record_digest_sha256)) failD931('D931_JOURNAL_CHAIN_CORRUPT', 'multiple append responses bind one request digest')
    appendResponseDigests.add(response.request_record_digest_sha256)
    const request = journalAppendRequests.get(response.request_id)
    const event = journalEventsByRequestDigest.get(response.request_record_digest_sha256)
    assertAppendExchange(request, response, event)
  }

  const broker = Object.freeze({
    persistPrimaryReceipt(request, authenticatedPeer) {
      assertProtectedJournalBroker(broker)
      assertOperational()
      request = validateD930Record({ contractSet, record: request, bindingRoleResolver })
      assertReceiptRequestEnvelope(request)
      const verifiedPeer = assertAuthenticatedPeer(authenticatedPeer, bindingRoleResolver(request.sender_binding_code), request.sender_binding_code, request.record_digest_sha256, request.operation_nonce, request.created_at)
      const acceptedAt = timestamp(clock('primary_receipt_acceptance'), 'receipt acceptance time')
      if (request.message_kind_code !== 'persist_request' || request.request_record_digest_sha256 !== null) failD931('D931_RECEIPT_REQUEST_REJECTED', 'message is not a primary-receipt persist request')
      role(bindingRoleResolver, request.sender_binding_code, 'custody_adapter')
      if (request.recipient_binding_code !== journalBindingCode) failD931('D931_BROKER_ROLE_REJECTED', 'receipt request targets another broker')
      if (request.d930_operational_profile_record_digest_sha256 !== admissionResolver.custodyProfile.record_digest_sha256) failD931('D931_RECEIPT_PRODUCER_MISMATCH', 'receipt request does not pin the selected custody profile')
      if (canonicalSha256(request.payload.receipt_semantic) !== request.payload.receipt_semantic_sha256) failD931('D931_RECEIPT_SEMANTIC_DIGEST_MISMATCH', 'receipt semantic digest differs')
      if (request.payload.receipt_semantic.adapter_binding_code !== verifiedPeer.bindingCode || request.payload.receipt_semantic.adapter_executable_sha256 !== verifiedPeer.executableSha256) failD931('D931_RECEIPT_PRODUCER_MISMATCH', 'receipt semantic producer differs from the kernel-authenticated adapter')
      const prior = receiptResponses.get(request.request_id)
      const persistedRequest = receiptRequests.get(request.request_id)
      assertAuthenticatedPeerContext(verifiedPeer, request, acceptedAt, expectedJournalProfileDigest, { enforceFreshness: !prior && !persistedRequest })
      if (prior) {
        if (prior.request_record_digest_sha256 !== request.record_digest_sha256) failD931('D931_RECEIPT_REPLAY_COLLISION', 'request identity was reused with different content')
        return prior
      }
      if (persistedRequest && persistedRequest.record_digest_sha256 !== request.record_digest_sha256) failD931('D931_RECEIPT_REPLAY_COLLISION', 'persisted request identity was reused with different content')
      const operationKey = `${request.operation_id}/${request.operation_nonce}`
      const pendingOperationRequest = pendingReceiptOperations.get(operationKey)
      if (pendingOperationRequest && pendingOperationRequest.record_digest_sha256 !== request.record_digest_sha256) failD931('D931_RECEIPT_REPLAY_COLLISION', 'operation has another eventless receipt request')
      const operationReceipt = receiptsByOperation.get(operationKey)
      if (operationReceipt && operationReceipt.persistence_request_record_digest_sha256 !== request.record_digest_sha256) failD931('D931_RECEIPT_REPLAY_COLLISION', 'operation already has another primary receipt request')
      const pairs = collectReceiptPrerequisitePairs(request)
      validateReceiptPrerequisites(request, pairs)
      for (const { record, request: supportRequest, response: supportResponse } of pairs) {
        for (const key of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) if (record[key] !== request[key]) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${key} differs`)
        if (supportResponse.request_record_digest_sha256 !== supportRequest.record_digest_sha256 || supportResponse.payload.persisted_record_digest_sha256 !== record.record_digest_sha256 || supportResponse.created_at > request.created_at) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'supporting acknowledgement binding or chronology differs')
      }
      const existingReceipt = receiptsByRequestDigest.get(request.record_digest_sha256)
      const persistedAt = existingReceipt?.persisted_at ?? timestamp(clock('primary_receipt'), 'receipt persistence time')
      assertAuthenticatedPeerContext(verifiedPeer, request, persistedAt, expectedJournalProfileDigest, { enforceFreshness: !persistedRequest && !existingReceipt })
      if (!existingReceipt && persistedAt < acceptedAt) failD931('D931_RECEIPT_TIME_REJECTED', 'new receipt persistence predates trusted acceptance')
      if (persistedAt < request.created_at || persistedAt < request.payload.receipt_semantic.completed_at) failD931('D931_RECEIPT_TIME_REJECTED', 'receipt persistence predates its request or semantic completion')
      if (!persistedRequest) {
        protectedAppend({ namespaceCode: 'receipt-exchanges', recordCode: request.record_code, bytes: exactRecordBytes(request), replayKey: `${request.request_id}.request` })
        receiptRequests.set(request.request_id, request)
        pendingReceiptOperations.set(operationKey, request)
      }
      const receipt = validateD930Record({ contractSet, bindingRoleResolver, record: {
        format: 'jedi-atlas-primary-durability-receipt',
        format_version: '1.0.0',
        record_code: request.payload.receipt_record_code,
        receipt_file_profile_code: 'canonical_json_utf8_no_lf_v1',
        hash_algorithm_code: 'sha256',
        runtime_profile_record_digest_sha256: request.runtime_profile_record_digest_sha256,
        identity_bindings_record_digest_sha256: request.identity_bindings_record_digest_sha256,
        d930_operational_profile_record_digest_sha256: request.d930_operational_profile_record_digest_sha256,
        semantic: structuredClone(request.payload.receipt_semantic),
        semantic_payload_sha256: request.payload.receipt_semantic_sha256,
        persistence_request_record_digest_sha256: request.record_digest_sha256,
        persisted_by_binding_code: journalBindingCode,
        persisted_at: persistedAt,
      } })
      const receiptBytes = exactRecordBytes(receipt)
      faultInjector?.('before_receipt_persist')
      const stored = existingReceipt
        ? { digest: sha256Bytes(exactRecordBytes(existingReceipt)), bytes: exactRecordBytes(existingReceipt), recordCode: existingReceipt.record_code }
        : protectedAppend({ namespaceCode: 'primary-receipts', recordCode: receipt.record_code, bytes: receiptBytes, replayKey: request.request_id })
      if (existingReceipt && canonicalize(existingReceipt) !== canonicalize(receipt)) failD931('D931_RECEIPT_REPLAY_COLLISION', 'persisted receipt differs from deterministic reconstruction')
      receiptsByRequestDigest.set(request.record_digest_sha256, receipt)
      receiptsByOperation.set(operationKey, receipt)
      pendingReceiptOperations.delete(operationKey)
      try { faultInjector?.('after_receipt_persist_before_ack') } catch (error) { recoveryRequired = true; throw error }
      const response = canonicalRecord({
        format: 'jedi-atlas-durability-receipt-broker-message', format_version: '1.0.0',
        record_code: `${request.record_code}.response`, message_kind_code: 'persist_response',
        operation_id: request.operation_id, operation_nonce: request.operation_nonce,
        request_id: request.request_id, request_sequence: request.request_sequence,
        sender_binding_code: journalBindingCode, recipient_binding_code: request.sender_binding_code,
        runtime_profile_record_digest_sha256: request.runtime_profile_record_digest_sha256,
        identity_bindings_record_digest_sha256: request.identity_bindings_record_digest_sha256,
        d930_operational_profile_record_digest_sha256: request.d930_operational_profile_record_digest_sha256,
        d930_journal_profile_record_digest_sha256: request.d930_journal_profile_record_digest_sha256,
        request_record_digest_sha256: request.record_digest_sha256, created_at: persistedAt,
        payload: { receipt_record_code: receipt.record_code, receipt_semantic: null, receipt_semantic_sha256: null, receipt_raw_sha256: stored.digest, receipt_persisted_at: persistedAt, outcome_code: 'persisted', error_code: null },
        record_digest_sha256: null,
      })
      validateD930Record({ contractSet, record: response, bindingRoleResolver })
      assertReceiptBrokerMatrix(response)
      protectedAppend({ namespaceCode: 'receipt-exchanges', recordCode: response.record_code, bytes: exactRecordBytes(response), replayKey: `${request.request_id}.response` })
      receiptResponses.set(request.request_id, response)
      return response
    },
    persistSupporting(request, authenticatedPeer) {
      assertOperational()
      request = validateD930Record({ contractSet, record: request, bindingRoleResolver })
      assertJournalBrokerMatrix(request)
      const supportingRecord = request.payload.supporting_record
      if (Buffer.byteLength(request.operation_id, 'utf8') > 40 || request.record_code !== `support.request.${supportingRecord.record_code}` || request.request_id !== `support.${supportingRecord.record_code}` || request.payload.journal_code !== `journal.${request.operation_id}` || Buffer.byteLength(`support.response.${supportingRecord.record_code}`, 'utf8') > 96) failD931('D931_SUPPORTING_REQUEST_REJECTED', 'supporting request, deterministic journal, or response identity differs')
      const verifiedPeer = assertAuthenticatedPeer(authenticatedPeer, bindingRoleResolver(request.sender_binding_code), request.sender_binding_code, request.record_digest_sha256, request.operation_nonce, request.created_at)
      const acceptedAt = timestamp(clock('supporting_record_acceptance'), 'supporting acceptance time')
      if (request.message_kind_code !== 'persist_supporting_request' || request.request_record_digest_sha256 !== null) failD931('D931_SUPPORTING_REQUEST_REJECTED', 'message is not a supporting-record request')
      const supportingProducer = request.payload.supporting_record_kind_code === 'integrity_access_lifecycle_record'
        ? request.payload.supporting_record.producer_binding_code
        : request.payload.supporting_record.sender_binding_code
      if (request.recipient_binding_code !== journalBindingCode || request.sender_binding_code !== supportingProducer) {
        failD931('D931_SUPPORTING_ROLE_REJECTED', 'supporting producer or broker target differs')
      }
      if (request.payload.supporting_record.record_digest_sha256 !== request.payload.supporting_record_digest_sha256) failD931('D931_SUPPORTING_DIGEST_MISMATCH', 'supporting record digest differs')
      const prior = journalResponses.get(request.request_id)
      const persistedRequest = supportingRequests.get(request.request_id)
      assertAuthenticatedPeerContext(verifiedPeer, request, acceptedAt, expectedJournalProfileDigest, { enforceFreshness: !prior && !persistedRequest })
      if (prior) {
        if (prior.request_record_digest_sha256 !== request.record_digest_sha256) failD931('D931_JOURNAL_REPLAY_COLLISION', 'supporting request collision')
        return prior
      }
      if (persistedRequest && persistedRequest.record_digest_sha256 !== request.record_digest_sha256) failD931('D931_SUPPORTING_REPLAY_COLLISION', 'persisted supporting request identity was reused with different content')
      validateD930Record({ contractSet, record: request.payload.supporting_record, bindingRoleResolver })
      if (request.payload.supporting_record.format === 'jedi-atlas-custody-adapter-message') assertAdapterSubjectIdentity(request.payload.supporting_record, 'D931_SUPPORTING_REQUEST_REJECTED')
      assertIntegrityLifecycleProducer(request.payload.supporting_record, verifiedPeer)
      if (request.payload.supporting_record.runtime_profile_record_digest_sha256 !== verifiedPeer.runtimeProfileDigest || request.payload.supporting_record.identity_bindings_record_digest_sha256 !== verifiedPeer.identityBindingsDigest || request.payload.supporting_record.d930_operational_profile_record_digest_sha256 !== admissionResolver.custodyProfile.record_digest_sha256) failD931('D931_SUPPORTING_ROLE_REJECTED', 'supporting record does not pin the authenticated generation and custody profile')
      const persistedAt = timestamp(clock('supporting_record'), 'supporting persistence time')
      assertAuthenticatedPeerContext(verifiedPeer, request, persistedAt, expectedJournalProfileDigest, { enforceFreshness: !persistedRequest })
      if (persistedAt < acceptedAt) failD931('D931_SUPPORTING_TIME_REJECTED', 'supporting persistence predates trusted acceptance')
      const producedAt = request.payload.supporting_record.created_at ?? request.payload.supporting_record.event_at
      if (!producedAt || persistedAt < request.created_at || persistedAt < producedAt || request.created_at < producedAt) failD931('D931_SUPPORTING_TIME_REJECTED', 'supporting persistence is noncausal')
      protectedAppend({ namespaceCode: 'supporting-records', recordCode: request.record_code, bytes: exactRecordBytes(request), replayKey: `${request.request_id}.request` })
      const stored = protectedAppend({ namespaceCode: 'supporting-records', recordCode: request.payload.supporting_record.record_code, bytes: exactRecordBytes(request.payload.supporting_record), replayKey: request.payload.supporting_record_digest_sha256 })
      const response = canonicalRecord({
        ...structuredClone(request), record_code: `support.response.${request.payload.supporting_record.record_code}`, message_kind_code: 'persist_supporting_response',
        sender_binding_code: journalBindingCode, recipient_binding_code: request.sender_binding_code,
        request_record_digest_sha256: request.record_digest_sha256, created_at: persistedAt,
        payload: { journal_code: request.payload.journal_code, expected_event_sequence: null, expected_previous_event_record_digest_sha256: null, supporting_record_kind_code: request.payload.supporting_record_kind_code, supporting_record: null, supporting_record_digest_sha256: request.payload.supporting_record_digest_sha256, semantic_assertion: null, semantic_assertion_record_digest_sha256: null, persisted_record_code: request.payload.supporting_record.record_code, persisted_record_digest_sha256: request.payload.supporting_record.record_digest_sha256, persisted_at: persistedAt, outcome_code: 'persisted', error_code: null },
        record_digest_sha256: null,
      })
      validateD930Record({ contractSet, record: response, bindingRoleResolver })
      assertJournalBrokerMatrix(response)
      protectedAppend({ namespaceCode: 'supporting-records', recordCode: response.record_code, bytes: exactRecordBytes(response), replayKey: `${request.request_id}.response` })
      journalResponses.set(request.request_id, response)
      supportingRequests.set(request.request_id, request)
      supportingRecords.set(request.payload.supporting_record_digest_sha256, request.payload.supporting_record)
      supportingResponses.set(request.request_id, response)
      try { faultInjector?.('after_supporting_ack_persist_before_return') } catch (error) { recoveryRequired = true; throw error }
      return response
    },
    appendSemantic(request, authenticatedPeer) {
      assertOperational()
      request = validateD930Record({ contractSet, record: request, bindingRoleResolver })
      assertAppendRequestEnvelope(request)
      const verifiedPeer = assertAuthenticatedPeer(authenticatedPeer, bindingRoleResolver(request.sender_binding_code), request.sender_binding_code, request.record_digest_sha256, request.operation_nonce, request.created_at)
      const acceptedAt = timestamp(clock('journal_event_acceptance'), 'journal acceptance time')
      if (request.message_kind_code !== 'append_request' || request.request_record_digest_sha256 !== null) failD931('D931_JOURNAL_REQUEST_REJECTED', 'message is not an append request')
      if (request.recipient_binding_code !== journalBindingCode || request.sender_binding_code !== request.payload.semantic_assertion.component_binding_code) failD931('D931_JOURNAL_ROLE_REJECTED', 'semantic origin or broker target differs')
      if (request.payload.semantic_assertion.record_digest_sha256 !== request.payload.semantic_assertion_record_digest_sha256) failD931('D931_JOURNAL_SEMANTIC_DIGEST_MISMATCH', 'semantic assertion digest differs')
      const semantic = request.payload.semantic_assertion
      assertD931ReachableSemantic(semantic)
      assertD931SemanticPolicy(contractSet, semantic)
      assertD931SemanticProducer(bindingRoleResolver, semantic)
      if (semantic.component_executable_sha256 !== verifiedPeer.executableSha256) failD931('D931_JOURNAL_ROLE_REJECTED', 'semantic executable differs from the kernel-authenticated producer binding')
      if (semantic.event_at > request.created_at) failD931('D931_JOURNAL_TIME_REJECTED', 'semantic event postdates its append request')
      for (const key of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) if (request[key] !== semantic[key]) failD931('D931_JOURNAL_CONTEXT_DRIFT', `${key} differs between append request and semantic assertion`)
      if (request.d930_journal_profile_record_digest_sha256 !== semantic.d930_journal_profile_record_digest_sha256) failD931('D931_JOURNAL_CONTEXT_DRIFT', 'journal profile differs between append request and semantic assertion')
      const priorResponse = journalResponses.get(request.request_id)
      const persistedEvent = journalEventsByRequestDigest.get(request.record_digest_sha256)
      const persistedAppendRequest = journalAppendRequests.get(request.request_id)
      const operationKey = `${semantic.operation_id}/${semantic.operation_nonce}`
      const pendingJournalRequest = pendingAppendByJournal.get(request.payload.journal_code)
      const pendingOperationRequest = pendingAppendByOperation.get(operationKey)
      if (pendingJournalRequest && pendingJournalRequest.record_digest_sha256 !== request.record_digest_sha256) failD931('D931_JOURNAL_REPLAY_COLLISION', 'journal head is reserved by another eventless append request')
      if (pendingOperationRequest && pendingOperationRequest.record_digest_sha256 !== request.record_digest_sha256) failD931('D931_JOURNAL_OPERATION_FORK', 'operation is reserved by another eventless append request')
      if (persistedAppendRequest && persistedAppendRequest.record_digest_sha256 !== request.record_digest_sha256) failD931('D931_JOURNAL_REPLAY_COLLISION', 'append request identity was reused with different content')
      if (!persistedAppendRequest && journalAppendRequestsByDigest.has(request.record_digest_sha256)) failD931('D931_JOURNAL_REPLAY_COLLISION', 'append request digest is bound to another request identity')
      assertAuthenticatedPeerContext(verifiedPeer, request, acceptedAt, expectedJournalProfileDigest, { enforceFreshness: !priorResponse && !persistedEvent && !persistedAppendRequest })
      if (!priorResponse && !persistedEvent) assertAdmittedJournalAuthorization(semantic, acceptedAt)
      if (priorResponse) {
        assertAppendExchange(persistedAppendRequest, priorResponse, persistedEvent)
        return priorResponse
      }
      if (persistedEvent) {
        assertAppendExchange(persistedAppendRequest, null, persistedEvent)
        const response = canonicalRecord({
          ...structuredClone(request), record_code: `${request.record_code}.response`, message_kind_code: 'append_response',
          sender_binding_code: journalBindingCode, recipient_binding_code: request.sender_binding_code,
          request_record_digest_sha256: request.record_digest_sha256, created_at: persistedEvent.persisted_at,
          payload: { journal_code: request.payload.journal_code, expected_event_sequence: persistedEvent.event_sequence, expected_previous_event_record_digest_sha256: persistedEvent.previous_event_record_digest_sha256, supporting_record_kind_code: null, supporting_record: null, supporting_record_digest_sha256: null, semantic_assertion: null, semantic_assertion_record_digest_sha256: request.payload.semantic_assertion_record_digest_sha256, persisted_record_code: persistedEvent.record_code, persisted_record_digest_sha256: persistedEvent.record_digest_sha256, persisted_at: persistedEvent.persisted_at, outcome_code: 'persisted', error_code: null },
          record_digest_sha256: null,
        })
        validateD930Record({ contractSet, record: response, bindingRoleResolver })
        assertJournalBrokerMatrix(response)
        protectedAppend({ namespaceCode: 'supporting-records', recordCode: response.record_code, bytes: exactRecordBytes(response), replayKey: `${request.request_id}.response` })
        journalResponses.set(request.request_id, response)
        return response
      }
      const prior = journalHeads.get(request.payload.journal_code)
      const expectedSequence = (prior?.event_sequence ?? 0) + 1
      const expectedPrevious = prior?.record_digest_sha256 ?? null
      if (request.payload.expected_event_sequence !== expectedSequence || request.payload.expected_previous_event_record_digest_sha256 !== expectedPrevious) failD931('D931_JOURNAL_FORK_OR_GAP', 'append does not extend the current exact head')
      if (!prior && semantic.event_kind_code !== 'operation_started') failD931('D931_JOURNAL_HISTORY_REJECTED', 'journal must begin with operation_started')
      if (prior && ['operation_completed', 'recovery_required'].includes(prior.semantic_assertion.event_kind_code)) failD931('D931_JOURNAL_HISTORY_REJECTED', 'terminal journal cannot be extended')
      if (prior?.format_version && prior.format_version !== '2.0.0') failD931('D931_JOURNAL_VERSION_MIXED', 'journal versions cannot mix within an operation')
      if (prior && !(prior.semantic_assertion.event_at < semantic.event_at)) failD931('D931_JOURNAL_TIME_REJECTED', 'semantic event time is not strictly increasing')
      const stableContext = [semantic.operation_id, semantic.operation_nonce, semantic.operation_mode_code, semantic.runtime_profile_record_digest_sha256, semantic.identity_bindings_record_digest_sha256, semantic.d930_journal_profile_record_digest_sha256, semantic.authorization_permit_record_digest_sha256, semantic.authorization_bundle_seal_record_digest_sha256, semantic.bundle, semantic.target_logical_state]
      const priorContext = journalContexts.get(request.payload.journal_code)
      if (priorContext && canonicalize(priorContext) !== canonicalize(stableContext)) failD931('D931_JOURNAL_CONTEXT_DRIFT', 'journal stable operation context changed')
      const operationJournal = operationJournals.get(operationKey)
      if (operationJournal && operationJournal !== request.payload.journal_code) failD931('D931_JOURNAL_OPERATION_FORK', 'one operation cannot have multiple journals')
      if (semantic.recovery) {
        const recovery = semantic.recovery
        const priorRecovery = recoveryAttempts.get(recovery.recovery_chain_code)
        if (recovery.recovery_attempt_sequence !== (priorRecovery?.sequence ?? 0) + 1 || recovery.prior_attempt_terminal_record_digest_sha256 !== (priorRecovery?.digest ?? null)) failD931('D931_RECOVERY_ATTEMPT_FORK', 'recovery attempt chain is gapped or forked')
      }
      const priorSemantics = journalHistories.get(request.payload.journal_code) ?? []
      assertHistoryPrefix(contractSet, priorSemantics, semantic)
      validateCustodyFinalization(semantic, request.payload.journal_code)
      const persistedAt = timestamp(clock('journal_event'), 'journal persistence time')
      assertAuthenticatedPeerContext(verifiedPeer, request, persistedAt, expectedJournalProfileDigest)
      if (persistedAt < acceptedAt) failD931('D931_JOURNAL_TIME_REJECTED', 'journal persistence predates trusted acceptance')
      if (persistedAt < request.created_at || persistedAt < request.payload.semantic_assertion.event_at || prior && !(prior.persisted_at < persistedAt)) failD931('D931_JOURNAL_TIME_REJECTED', 'journal persistence chronology is invalid')
      assertAdmittedJournalAuthorization(semantic, persistedAt)
      const event = canonicalRecord({
        format: 'jedi-atlas-operation-journal-event', format_version: '2.0.0',
        record_code: `${request.payload.journal_code}.event.${String(expectedSequence).padStart(6, '0')}`,
        journal_code: request.payload.journal_code, event_sequence: expectedSequence,
        previous_event_record_digest_sha256: expectedPrevious,
        semantic_assertion: structuredClone(request.payload.semantic_assertion),
        semantic_assertion_record_digest_sha256: request.payload.semantic_assertion_record_digest_sha256,
        append_request_record_digest_sha256: request.record_digest_sha256,
        persisted_by_binding_code: journalBindingCode, persisted_at: persistedAt,
        record_digest_sha256: null,
      })
      validateD930Record({ contractSet, record: event, bindingRoleResolver })
      assertPersistedEvent(event)
      if (!persistedAppendRequest) {
        protectedAppend({ namespaceCode: 'supporting-records', recordCode: request.record_code, bytes: exactRecordBytes(request), replayKey: `${request.request_id}.request` })
        journalAppendRequests.set(request.request_id, request)
        journalAppendRequestsByDigest.set(request.record_digest_sha256, request)
        pendingAppendByJournal.set(request.payload.journal_code, request)
        pendingAppendByOperation.set(operationKey, request)
      }
      const namespaceCode = event.semantic_assertion.recovery === null ? 'journal-events' : 'recovery-assessments'
      protectedAppend({ namespaceCode, recordCode: event.record_code, bytes: exactRecordBytes(event), replayKey: request.request_id })
      try { faultInjector?.('after_journal_persist_before_ack') } catch (error) { recoveryRequired = true; throw error }
      journalHeads.set(event.journal_code, event)
      persistedEvents.push(event)
      journalHistories.set(event.journal_code, [...priorSemantics, event.semantic_assertion])
      journalEventsByRequestDigest.set(request.record_digest_sha256, event)
      pendingAppendByJournal.delete(request.payload.journal_code)
      pendingAppendByOperation.delete(operationKey)
      journalContexts.set(event.journal_code, stableContext)
      operationJournals.set(operationKey, event.journal_code)
      if (semantic.recovery) recoveryAttempts.set(semantic.recovery.recovery_chain_code, { sequence: semantic.recovery.recovery_attempt_sequence, digest: semantic.record_digest_sha256 })
      const response = canonicalRecord({
        ...structuredClone(request), record_code: `${request.record_code}.response`, message_kind_code: 'append_response',
        sender_binding_code: journalBindingCode, recipient_binding_code: request.sender_binding_code,
        request_record_digest_sha256: request.record_digest_sha256, created_at: persistedAt,
        payload: { journal_code: request.payload.journal_code, expected_event_sequence: expectedSequence, expected_previous_event_record_digest_sha256: expectedPrevious, supporting_record_kind_code: null, supporting_record: null, supporting_record_digest_sha256: null, semantic_assertion: null, semantic_assertion_record_digest_sha256: request.payload.semantic_assertion_record_digest_sha256, persisted_record_code: event.record_code, persisted_record_digest_sha256: event.record_digest_sha256, persisted_at: persistedAt, outcome_code: 'persisted', error_code: null },
        record_digest_sha256: null,
      })
      validateD930Record({ contractSet, record: response, bindingRoleResolver })
      assertJournalBrokerMatrix(response)
      protectedAppend({ namespaceCode: 'supporting-records', recordCode: response.record_code, bytes: exactRecordBytes(response), replayKey: `${request.request_id}.response` })
      journalResponses.set(request.request_id, response)
      return response
    },
    resolveReceipt(reference) {
      const bytes = store.read({ namespaceCode: 'primary-receipts', recordCode: reference.record_code })
      if (sha256Bytes(bytes) !== reference.receipt_raw_sha256) failD931('D931_RECEIPT_CORRUPT', 'receipt bytes differ from their exact reference')
      const receipt = validateD930Record({ contractSet, record: parseCanonical(bytes), bindingRoleResolver })
      if (Object.hasOwn(reference, 'receipt_persisted_at') && receipt.persisted_at !== reference.receipt_persisted_at) failD931('D931_RECEIPT_REFERENCE_MISMATCH', 'receipt persistence time differs')
      return receipt
    },
    resolveSupportingAck(referenceDigest) {
      const record = supportingRecords.get(referenceDigest)
      const request = [...supportingRequests.values()].find((candidate) => candidate.payload.supporting_record_digest_sha256 === referenceDigest)
      const response = request ? supportingResponses.get(request.request_id) : null
      if (!record || !request || !response) failD931('D931_SUPPORTING_UNRESOLVED', 'supporting exchange does not resolve from protected storage')
      return deepFreeze({ record: structuredClone(record), request: structuredClone(request), response: structuredClone(response) })
    },
    head(journalCode) {
      assertOperational()
      const head = journalHeads.get(journalCode)
      return head ? deepFreeze(structuredClone(head)) : null
    },
    inventory: () => store.inventory(),
  })
  return registerProtectedJournalBroker(broker)
}

export { assertProtectedJournalBroker } from './trust.mjs'
