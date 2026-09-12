import fs from 'node:fs'
import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { assertAuthenticatedPeer, assertAuthenticatedPeerContext, assertD931AdmissionResolver, assertSyntheticCustodyProjection } from './admission.mjs'
import { assertRestrictedLocalCas, custodyReferenceFor } from './cas.mjs'
import { canonicalRecord, validateD930Record } from './contracts.mjs'
import { failD931 } from './errors.mjs'
import { assertProtectedJournalBroker } from './journal.mjs'
import { persistSupportingRecord } from './coordinator.mjs'
import { assertOneShotIntegrityGrantSink, registerOneShotCustodyDescriptor } from './integrity.mjs'

const adapters = new WeakSet()
const stagingRegistries = new WeakSet()
const adapterResults = new WeakSet()
const SHA = /^[0-9a-f]{64}$/u
const PAYLOAD_FIELDS = Object.freeze([
  'staging_root_slot_code', 'relative_path', 'collector_handoff_record_digest_sha256', 'bundle_seal_record_digest_sha256', 'staging_snapshot_code',
  'custody_intent', 'artifact', 'source_capability_record_digest_sha256', 'source_capability_leaf_record_digest_sha256',
  'preparation_capability_record_digest_sha256', 'preparation_capability_leaf_record_digest_sha256', 'copy_code', 'backend_code', 'backend_reference',
  'purpose_code', 'custody_evaluated_at', 'known_through_bundle_sequence', 'clearance_decision_record_digest_sha256', 'clearance_scope_sha256',
  'custody_leaf_projection_sha256', 'sealed_capability_record_digest_sha256', 'sealed_capability_leaf_record_digest_sha256', 'primary_receipt',
  'receipt_broker_ack_record_digest_sha256', 'outcome_code', 'error_code',
])

function emptyPayload() { return Object.fromEntries(PAYLOAD_FIELDS.map((key) => [key, null])) }

function exactArtifact(left, right) {
  return canonicalize(left) === canonicalize(right)
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

function safeRelative(value) {
  return typeof value === 'string' && Buffer.byteLength(value) <= 512 && /^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/u.test(value) && value.split('/').every((part) => part !== '.' && part !== '..' && Buffer.byteLength(part) <= 180)
}

function secureOpen(rootDescriptor, relativePath, expectedArtifact) {
  if (!safeRelative(relativePath)) failD931('D931_STAGING_PATH_REJECTED', 'staging path is not root-confined')
  const parts = relativePath.split('/')
  let currentDescriptor = fs.openSync(`/proc/self/fd/${rootDescriptor}`, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_CLOEXEC)
  try {
    for (const part of parts.slice(0, -1)) {
      const next = fs.openSync(`/proc/self/fd/${currentDescriptor}/${part}`, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
      try {
        const status = fs.fstatSync(next, { bigint: true })
        if (!status.isDirectory() || status.isSymbolicLink()) failD931('D931_STAGING_PATH_REJECTED', 'staging ancestor is not a real directory')
      } catch (error) {
        fs.closeSync(next)
        throw error
      }
      fs.closeSync(currentDescriptor)
      currentDescriptor = next
    }
    const file = `/proc/self/fd/${currentDescriptor}/${parts.at(-1)}`
    const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
    try {
      const opened = fs.fstatSync(descriptor, { bigint: true })
      if (!opened.isFile() || opened.isSymbolicLink() || opened.nlink !== 1n || opened.size !== BigInt(expectedArtifact.byte_length)) failD931('D931_STAGING_OBJECT_REJECTED', 'staged object is not a single-link regular file')
    } catch (error) {
      fs.closeSync(descriptor)
      throw error
    }
    return descriptor
  } finally {
    fs.closeSync(currentDescriptor)
  }
}

export function createReviewedStagingRegistry({ stagingRootDescriptor, admissionResolver }) {
  assertD931AdmissionResolver(admissionResolver)
  const root = fs.fstatSync(stagingRootDescriptor, { bigint: true })
  if (!root.isDirectory() || root.uid !== BigInt(process.getuid()) || (root.mode & 0o077n) !== 0n) failD931('D931_STAGING_ROOT_REJECTED', 'staging root descriptor is not an owned private directory')
  const duplicate = fs.openSync(`/proc/self/fd/${stagingRootDescriptor}`, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_CLOEXEC)
  try {
    const opened = fs.fstatSync(duplicate, { bigint: true })
    if (!opened.isDirectory() || opened.dev !== root.dev || opened.ino !== root.ino || opened.uid !== root.uid || (opened.mode & 0o077n) !== 0n) failD931('D931_STAGING_ROOT_REJECTED', 'duplicated staging root identity differs')
  } catch (error) {
    fs.closeSync(duplicate)
    throw error
  }
  const registry = Object.freeze({
    open({ handoffDigest, bundleSealDigest, relativePath, artifact, stagingSnapshotCode, operationId, operationNonce, runtimeProfileDigest, identityBindingsDigest, importerBindingCode, bundle, asOf }) {
      if (!stagingRegistries.has(registry)) failD931('D931_STAGING_REGISTRY_CLOSED', 'reviewed staging registry is closed')
      const handoff = admissionResolver.resolveRecord(handoffDigest)
      const seal = admissionResolver.resolveRecord(bundleSealDigest)
      if (handoff.record_kind_code !== 'collector_handoff' || seal.record_kind_code !== 'bundle_seal') failD931('D931_STAGING_ADMISSION_REJECTED', 'handoff or seal has the wrong kind')
      if (!seal.collector_handoffs.some((entry) => entry.format === handoff.format && entry.format_version === handoff.format_version && entry.record_digest_sha256 === handoffDigest && entry.record_code === handoff.record_code)) failD931('D931_STAGING_ADMISSION_REJECTED', 'handoff is not a member of the exact bundle seal')
      if (seal.operation_id !== operationId || seal.operation_nonce !== operationNonce || seal.runtime_profile_record_digest_sha256 !== runtimeProfileDigest || seal.identity_bindings_record_digest_sha256 !== identityBindingsDigest || seal.importer_binding_code !== importerBindingCode || !exactArtifact(seal.bundle, bundle) || handoff.runtime_profile_record_digest_sha256 !== runtimeProfileDigest || handoff.identity_bindings_record_digest_sha256 !== identityBindingsDigest) failD931('D931_STAGING_ADMISSION_REJECTED', 'seal or handoff context differs from the authenticated operation')
      if (handoff.staging_snapshot_code !== stagingSnapshotCode) failD931('D931_STAGING_ADMISSION_REJECTED', 'staging snapshot differs from handoff')
      if (!(handoff.handoff_recorded_at <= asOf && asOf < handoff.expires_at && seal.sealed_at <= asOf && asOf < seal.expires_at)) failD931('D931_STAGING_ADMISSION_REJECTED', 'handoff or seal is not active at request acceptance')
      if (handoff.staged_path !== relativePath) failD931('D931_STAGING_ADMISSION_REJECTED', 'staged path differs from handoff')
      const handoffArtifact = handoff.artifact
      if (handoffArtifact && !exactArtifact(handoffArtifact, artifact)) failD931('D931_STAGING_ADMISSION_REJECTED', 'handoff artifact differs')
      return secureOpen(duplicate, relativePath, artifact)
    },
    close() { if (stagingRegistries.delete(registry)) fs.closeSync(duplicate) },
  })
  stagingRegistries.add(registry)
  return registry
}

function responseBase(request, createdAt) {
  return {
    format: 'jedi-atlas-custody-adapter-message', format_version: '2.0.0',
    record_code: `${request.record_code}.response`, message_kind_code: 'response', operation_code: request.operation_code,
    operation_id: request.operation_id, request_id: request.request_id, request_sequence: request.request_sequence,
    operation_nonce: request.operation_nonce, sender_binding_code: request.recipient_binding_code, recipient_binding_code: request.sender_binding_code,
    runtime_profile_record_digest_sha256: request.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: request.identity_bindings_record_digest_sha256,
    d930_operational_profile_record_digest_sha256: request.d930_operational_profile_record_digest_sha256,
    request_record_digest_sha256: request.record_digest_sha256, created_at: createdAt,
    ancillary_descriptors: [], payload: emptyPayload(), record_digest_sha256: null,
  }
}

function receiptRequest({ request, semantic, journalProfileDigest, adapterBindingCode, journalBindingCode, createdAt }) {
  return canonicalRecord({
    format: 'jedi-atlas-durability-receipt-broker-message', format_version: '1.0.0',
    record_code: `receipt.persist.${request.operation_id}`, message_kind_code: 'persist_request',
    operation_id: request.operation_id, operation_nonce: request.operation_nonce,
    request_id: `receipt.persist.${request.operation_id}`, request_sequence: 1,
    sender_binding_code: adapterBindingCode, recipient_binding_code: journalBindingCode,
    runtime_profile_record_digest_sha256: request.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: request.identity_bindings_record_digest_sha256,
    d930_operational_profile_record_digest_sha256: request.d930_operational_profile_record_digest_sha256,
    d930_journal_profile_record_digest_sha256: journalProfileDigest,
    request_record_digest_sha256: null, created_at: createdAt,
    payload: { receipt_record_code: `receipt.primary.${request.operation_id}`, receipt_semantic: semantic, receipt_semantic_sha256: canonicalSha256(semantic), receipt_raw_sha256: null, receipt_persisted_at: null, outcome_code: null, error_code: null },
    record_digest_sha256: null,
  })
}

export function createAuthenticatedCustodyAdapter({ admissionResolver, cas, journalBroker, stagingRegistry, adapterBindingCode, journalBindingCode, journalPeerProvider, clock, executableSha256, custodyProjectionResolver = null, integrityGrantSink }) {
  assertD931AdmissionResolver(admissionResolver)
  assertRestrictedLocalCas(cas)
  assertProtectedJournalBroker(journalBroker)
  assertOneShotIntegrityGrantSink(integrityGrantSink)
  if (!stagingRegistries.has(stagingRegistry) || typeof journalPeerProvider !== 'function' || typeof clock !== 'function' || !SHA.test(executableSha256) || typeof custodyProjectionResolver !== 'function') failD931('D931_ADAPTER_CONFIGURATION_INVALID', 'adapter dependencies are not verified')
  if (admissionResolver.bindingRole(adapterBindingCode) !== 'custody_adapter' || admissionResolver.bindingRole(journalBindingCode) !== 'journal_broker') failD931('D931_ADAPTER_CONFIGURATION_INVALID', 'adapter or broker binding has the wrong role')
  if (admissionResolver.resolveBinding(adapterBindingCode).executable_sha256 !== executableSha256) failD931('D931_ADAPTER_CONFIGURATION_INVALID', 'adapter executable hash differs from the verified binding')
  const streams = new Map()
  const exactReplays = new Map()
  const preparations = new Map()
  const sealedContexts = new Map()
  let primaryPublicationInFlight = false
  let custodyMutationInFlight = false

  const adapter = Object.freeze({
    async handle({ request, authenticatedPeer, capabilitySidecars = new Map(), descriptorSidecars = new Map() }) {
      if (!adapters.has(adapter)) failD931('D931_ADAPTER_CLOSED', 'adapter is closed')
      if (primaryPublicationInFlight || custodyMutationInFlight) failD931('D931_ADAPTER_RECOVERY_REQUIRED', 'a custody mutation lacks a completely acknowledged durability chain')
      request = validateD930Record({ contractSet: admissionResolver.contractSet ?? undefined, record: request, bindingRoleResolver: admissionResolver.bindingRole })
      if (Buffer.byteLength(request.operation_id, 'utf8') > 40) failD931('D931_OPERATION_ID_BUDGET_REJECTED', 'operation ID exceeds the closed 40-byte budget for all deterministic D9.3.1 descendant record codes')
      if (request.record_code !== `adapter.${request.operation_id}.${request.operation_code}.${request.request_sequence}` || request.request_id !== `request.${request.operation_id}.${request.operation_code}.${request.request_sequence}`) failD931('D931_ADAPTER_REQUEST_IDENTITY_REJECTED', 'adapter request identity differs from the closed deterministic formula')
      admissionResolver.assertRequestContext(request)
      if (request.recipient_binding_code !== adapterBindingCode) failD931('D931_ADAPTER_RECIPIENT_REJECTED', 'request targets another adapter')
      const verifiedPeer = assertAuthenticatedPeer(authenticatedPeer, 'bundle_importer', request.sender_binding_code, request.record_digest_sha256, request.operation_nonce, request.created_at)
      const now = clock(`adapter_${request.operation_code}`)
      assertAuthenticatedPeerContext(verifiedPeer, request, now)
      const replay = exactReplays.get(request.request_id)
      if (replay) {
        if (replay.requestDigest !== request.record_digest_sha256) failD931('D931_ADAPTER_REPLAY_COLLISION', 'request ID was reused with different content')
        if (['open_staged', 'open_custody'].includes(request.operation_code)) failD931('D931_DESCRIPTOR_REPLAY_FORBIDDEN', 'descriptor-bearing responses are never replayed')
        return replay.result
      }
      const streamKind = ['open_staged', 'prepare', 'verify_prepared', 'publish_no_replace'].includes(request.operation_code) ? 'custody_finalization' : 'integrity_access'
      const streamKey = `${request.operation_id}/${request.operation_nonce}/${streamKind}`
      const expected = streamKind === 'custody_finalization' ? ['open_staged', 'prepare', 'verify_prepared', 'publish_no_replace'] : ['seal_custody_access', 'open_custody']
      const stream = streams.get(streamKey) ?? { index: 0, terminal: false }
      if (stream.terminal || expected[stream.index] !== request.operation_code || request.request_sequence !== stream.index + 1) failD931('D931_ADAPTER_SEQUENCE_REJECTED', 'adapter request stream is gapped, forked, or terminal')
      if (request.operation_code !== 'open_staged' && streamKind === 'custody_finalization' && canonicalize(request.payload.custody_intent) !== canonicalize(stream.custodyIntent)) failD931('D931_CUSTODY_INTENT_DRIFT', 'custody intent changed after the admitted staged open')
      if (['open_staged', 'prepare', 'seal_custody_access'].includes(request.operation_code) && !(request.created_at < now)) failD931('D931_CAPABILITY_TIME_REJECTED', 'a capability-producing request must strictly precede trusted issuance time')
      let response = responseBase(request, now)
      let result
      let pendingDescriptorGrant = null
      if (request.operation_code === 'open_staged') {
        const operationHead = journalBroker.head(`journal.${request.operation_id}`)
        const start = operationHead?.semantic_assertion
        const admittedSeal = admissionResolver.resolveRecord(request.payload.bundle_seal_record_digest_sha256)
        if (!operationHead || operationHead.event_sequence !== 1 || start?.event_kind_code !== 'operation_started' || start.operation_mode_code !== 'document_import' || start.operation_id !== request.operation_id || start.operation_nonce !== request.operation_nonce || start.authorization_bundle_seal_record_digest_sha256 !== admittedSeal.record_digest_sha256 || start.component_binding_code !== request.sender_binding_code || start.runtime_profile_record_digest_sha256 !== request.runtime_profile_record_digest_sha256 || start.identity_bindings_record_digest_sha256 !== request.identity_bindings_record_digest_sha256 || canonicalize(start.bundle) !== canonicalize(request.payload.custody_intent.bundle) || canonicalize(start.target_logical_state) !== canonicalize(admittedSeal.target_logical_state) || operationHead.persisted_at > request.created_at) failD931('D931_OPERATION_START_REQUIRED', 'exact durably persisted operation start must precede staged custody access')
        const fd = stagingRegistry.open({
          handoffDigest: request.payload.collector_handoff_record_digest_sha256,
          bundleSealDigest: request.payload.bundle_seal_record_digest_sha256,
          relativePath: request.payload.relative_path,
          artifact: request.payload.custody_intent.artifact,
          stagingSnapshotCode: request.payload.staging_snapshot_code,
          operationId: request.operation_id,
          operationNonce: request.operation_nonce,
          runtimeProfileDigest: request.runtime_profile_record_digest_sha256,
          identityBindingsDigest: request.identity_bindings_record_digest_sha256,
          importerBindingCode: request.sender_binding_code,
          bundle: request.payload.custody_intent.bundle,
          asOf: now,
        })
        try {
          const cap = admissionResolver.issueSyntheticCapability({ kindCode: 'source_handle', basisRequest: request, artifact: request.payload.custody_intent.artifact,
            grantScope: { scope_kind_code: 'source_handle', basis_request_record_digest_sha256: request.record_digest_sha256, collector_handoff_record_digest_sha256: request.payload.collector_handoff_record_digest_sha256, bundle_seal_record_digest_sha256: request.payload.bundle_seal_record_digest_sha256, staging_snapshot_code: request.payload.staging_snapshot_code, staging_root_slot_code: 'staging_root', relative_path: request.payload.relative_path, descriptor_role_code: 'staged_source', staged_source_descriptor_ordinal: 1 },
            issuedAt: now, expiresAt: new Date(Date.parse(now) + 30_000).toISOString(), adapterBindingCode, requesterBindingCode: request.sender_binding_code })
          response.ancillary_descriptors = [{ ordinal: 1, role_code: 'staged_source', access_code: 'read_only', file_type_code: 'regular_file' }]
          Object.assign(response.payload, { custody_intent: request.payload.custody_intent, artifact: request.payload.custody_intent.artifact, bundle_seal_record_digest_sha256: request.payload.bundle_seal_record_digest_sha256, source_capability_record_digest_sha256: cap.issuance.record_digest_sha256, source_capability_leaf_record_digest_sha256: cap.issuance.record_digest_sha256, outcome_code: 'opened' })
          response = canonicalRecord(response)
          result = Object.freeze({ response, descriptorSidecars: new Map([[1, fd]]), capabilitySidecars: new Map([[cap.issuance.record_digest_sha256, cap.bearerBytes]]) })
        } catch (error) {
          try { fs.closeSync(fd) } catch {}
          throw error
        }
      } else if (request.operation_code === 'prepare') {
        if (!exactArtifact(request.payload.artifact, stream.custodyIntent.artifact)) failD931('D931_CUSTODY_INTENT_DRIFT', 'prepare artifact differs from the admitted custody intent')
        const digest = request.payload.source_capability_record_digest_sha256
        const claim = admissionResolver.claimCapability({ capabilityRecordDigest: digest, capabilityLeafDigest: request.payload.source_capability_leaf_record_digest_sha256, bearerBytes: capabilitySidecars.get(digest), request, now, expectedKind: 'source_handle' })
        custodyMutationInFlight = true
        const sourceFd = descriptorSidecars.get(1)
        const transition = admissionResolver.transitionCapability({ capabilityRecordDigest: digest, request, response: null, toStateCode: 'consumed', transitionCode: 'consumer_succeeded', reasonCode: 'request_claimed', occurredAt: now })
        const prepared = cas.prepare({ operationId: request.operation_id, operationNonce: request.operation_nonce, artifact: request.payload.artifact, sourceDescriptor: sourceFd })
        const cap = admissionResolver.issueSyntheticCapability({ kindCode: 'preparation', basisRequest: request, artifact: request.payload.artifact,
          grantScope: { scope_kind_code: 'preparation', basis_request_record_digest_sha256: request.record_digest_sha256, source_capability_record_digest_sha256: claim.issuance.record_digest_sha256, pending_object_code: `pending.${request.operation_id}` },
          issuedAt: now, expiresAt: new Date(Date.parse(now) + 60_000).toISOString(), adapterBindingCode, requesterBindingCode: request.sender_binding_code })
        Object.assign(response.payload, { custody_intent: request.payload.custody_intent, source_capability_record_digest_sha256: digest, source_capability_leaf_record_digest_sha256: request.payload.source_capability_leaf_record_digest_sha256, preparation_capability_record_digest_sha256: cap.issuance.record_digest_sha256, preparation_capability_leaf_record_digest_sha256: cap.issuance.record_digest_sha256, outcome_code: 'prepared' })
        response = canonicalRecord(response)
        preparations.set(cap.issuance.record_digest_sha256, { prepared, sourceTransition: transition, issuance: cap.issuance })
        result = Object.freeze({ response, descriptorSidecars: new Map(), capabilitySidecars: new Map([[cap.issuance.record_digest_sha256, cap.bearerBytes]]), transition })
      } else if (request.operation_code === 'verify_prepared') {
        if (!exactArtifact(request.payload.artifact, stream.custodyIntent.artifact)) failD931('D931_CUSTODY_INTENT_DRIFT', 'verification artifact differs from the admitted custody intent')
        const digest = request.payload.preparation_capability_record_digest_sha256
        admissionResolver.claimCapability({ capabilityRecordDigest: digest, capabilityLeafDigest: request.payload.preparation_capability_leaf_record_digest_sha256, bearerBytes: capabilitySidecars.get(digest), request, now, expectedKind: 'preparation' })
        custodyMutationInFlight = true
        const state = preparations.get(digest)
        if (!state) failD931('D931_PREPARATION_UNRESOLVED', 'preparation state is unavailable')
        state.prepared = cas.verifyPrepared(state.prepared)
        Object.assign(response.payload, { artifact: request.payload.artifact, custody_intent: request.payload.custody_intent, preparation_capability_record_digest_sha256: digest, preparation_capability_leaf_record_digest_sha256: request.payload.preparation_capability_leaf_record_digest_sha256, outcome_code: 'verified' })
        response = canonicalRecord(response)
        const transition = admissionResolver.transitionCapability({ capabilityRecordDigest: digest, request, response, toStateCode: 'verified', transitionCode: 'verification_succeeded', reasonCode: 'verified_response', occurredAt: now })
        state.verifiedTransition = transition
        result = Object.freeze({ response, descriptorSidecars: new Map(), capabilitySidecars: new Map([[digest, capabilitySidecars.get(digest)]]), transition })
      } else if (request.operation_code === 'publish_no_replace') {
        if (!exactArtifact(request.payload.artifact, stream.custodyIntent.artifact) || request.payload.copy_code !== stream.custodyIntent.copy_code || request.payload.backend_code !== stream.custodyIntent.backend_code || request.payload.backend_reference !== stream.custodyIntent.backend_reference) failD931('D931_CUSTODY_INTENT_DRIFT', 'publish target differs from the admitted custody intent')
        const digest = request.payload.preparation_capability_record_digest_sha256
        if (request.payload.backend_code !== cas.backendCode || request.payload.backend_reference !== custodyReferenceFor(request.payload.artifact)) failD931('D931_BACKEND_REFERENCE_MISMATCH', 'publish request does not name the exact CAS target')
        admissionResolver.claimCapability({ capabilityRecordDigest: digest, capabilityLeafDigest: request.payload.preparation_capability_leaf_record_digest_sha256, bearerBytes: capabilitySidecars.get(digest), request, now, expectedKind: 'preparation' })
        const state = preparations.get(digest)
        if (!state?.verifiedTransition || state.verifiedTransition.record_digest_sha256 !== request.payload.preparation_capability_leaf_record_digest_sha256) failD931('D931_PREPARATION_UNVERIFIED', 'publish requires the exact verified leaf')
        const publication = cas.publishNoReplace(state.prepared)
        primaryPublicationInFlight = true
        const publicationCompletedAt = clock('adapter_publish_completed')
        if (request.payload.backend_code !== publication.backendCode || request.payload.backend_reference !== publication.backendReference) failD931('D931_BACKEND_REFERENCE_MISMATCH', 'publish request does not name the exact CAS target')
        const semantic = {
          operation_id: request.operation_id, operation_nonce: request.operation_nonce,
          bundle: request.payload.custody_intent.bundle,
          bundle_seal_record_digest_sha256: request.payload.custody_intent.bundle_seal_record_digest_sha256,
          artifact: request.payload.artifact, copy_code: request.payload.copy_code,
          custody_class_code: request.payload.custody_intent.custody_class_code,
          backend_code: publication.backendCode, backend_reference: publication.backendReference,
          open_staged_response_record_digest_sha256: streams.get(streamKey)?.responseDigests?.[0] ?? failD931('D931_STREAM_EVIDENCE_MISSING', 'open response is unavailable'),
          prepare_response_record_digest_sha256: streams.get(streamKey)?.responseDigests?.[1] ?? failD931('D931_STREAM_EVIDENCE_MISSING', 'prepare response is unavailable'),
          verify_prepared_response_record_digest_sha256: streams.get(streamKey)?.responseDigests?.[2] ?? failD931('D931_STREAM_EVIDENCE_MISSING', 'verify response is unavailable'),
          publish_request_record_digest_sha256: request.record_digest_sha256,
          source_capability_consumed_transition_digest_sha256: state.sourceTransition.record_digest_sha256,
          preparation_capability_issuance_digest_sha256: state.issuance.record_digest_sha256,
          preparation_capability_verified_transition_digest_sha256: state.verifiedTransition.record_digest_sha256,
          finalization_outcome_code: publication.outcomeCode,
          no_replace_disposition_code: publication.dispositionCode,
          adapter_binding_code: adapterBindingCode, adapter_executable_sha256: executableSha256,
          durability_profile_code: 'local_posix_file_and_directory_sync_v1', file_data_synced: publication.fileDataSynced,
          parent_directory_synced: publication.parentDirectorySynced, no_replace_enforced: publication.noReplaceEnforced,
          reopened_and_rehashed: publication.reopenedAndRehashed, completed_at: publicationCompletedAt,
        }
        const journalCode = `journal.${request.operation_id}`
        const requestAck = await persistSupportingRecord({ journalPeerProvider, journalBroker, record: request, kindCode: 'custody_adapter_message', journalCode, journalBindingCode, journalProfileDigest: admissionResolver.journalProfile.record_digest_sha256, createdAt: clock('publish_request_supporting') })
        const preReceiptSupportingAcks = [...(stream.supportingAcks ?? []), requestAck]
        if (preReceiptSupportingAcks.length !== 7) failD931('D931_RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'publish receipt requires seven durable pre-response records')
        const brokerRequest = receiptRequest({ request, semantic, journalProfileDigest: admissionResolver.journalProfile.record_digest_sha256, adapterBindingCode, journalBindingCode, createdAt: clock('primary_receipt_request') })
        const receiptAck = journalBroker.persistPrimaryReceipt(brokerRequest, await journalPeerProvider(brokerRequest))
        const primaryReceipt = { format: 'jedi-atlas-primary-durability-receipt', format_version: '1.0.0', record_code: brokerRequest.payload.receipt_record_code, receipt_raw_sha256: receiptAck.payload.receipt_raw_sha256 }
        response = responseBase(request, receiptAck.created_at)
        Object.assign(response.payload, { artifact: request.payload.artifact, backend_code: request.payload.backend_code, backend_reference: request.payload.backend_reference, copy_code: request.payload.copy_code, custody_intent: request.payload.custody_intent, preparation_capability_record_digest_sha256: digest, preparation_capability_leaf_record_digest_sha256: request.payload.preparation_capability_leaf_record_digest_sha256, primary_receipt: primaryReceipt, receipt_broker_ack_record_digest_sha256: receiptAck.record_digest_sha256, outcome_code: publication.outcomeCode })
        response = canonicalRecord(response)
        const transition = admissionResolver.transitionCapability({ capabilityRecordDigest: digest, request, response, toStateCode: 'consumed', transitionCode: 'consumer_succeeded', reasonCode: 'successful_response', occurredAt: response.created_at })
        preparations.delete(digest)
        result = Object.freeze({ response, descriptorSidecars: new Map(), capabilitySidecars: new Map(), receiptAck, receiptSemantic: semantic, transition, publication, preReceiptSupportingAcks })
      } else if (request.operation_code === 'seal_custody_access') {
        const clearance = admissionResolver.resolveRecord(request.payload.clearance_decision_record_digest_sha256)
        if (clearance.record_kind_code !== 'clearance_decision' || clearance.decision_code !== 'restricted_store_only' || clearance.clearance_scope_sha256 !== request.payload.clearance_scope_sha256 || !exactArtifact(clearance.artifact, request.payload.artifact) || !(clearance.not_before <= now && now < clearance.expires_at)) failD931('D931_CLEARANCE_REJECTED', 'exact active synthetic clearance is unavailable')
        const receipt = journalBroker.resolveReceipt(request.payload.primary_receipt)
        if (!exactArtifact(receipt.semantic.artifact, request.payload.artifact) || receipt.semantic.copy_code !== request.payload.copy_code || receipt.semantic.backend_reference !== request.payload.backend_reference || receipt.persisted_at > request.created_at) failD931('D931_RECEIPT_REFERENCE_MISMATCH', 'receipt does not bind or predates the requested copy access')
        const projection = assertSyntheticCustodyProjection(custodyProjectionResolver({ ...request, response_at: now, projection_phase: 'seal' }), request)
        if (projection.evaluatedAt !== now) failD931('D931_CUSTODY_PROJECTION_REJECTED', 'custody projection was not evaluated at the trusted seal time')
        const capabilityExpiresAt = new Date(Math.min(Date.parse(clearance.expires_at), Date.parse(now) + 30_000)).toISOString()
        const cap = admissionResolver.issueSyntheticCapability({ kindCode: 'sealed_custody_access', basisRequest: request, artifact: request.payload.artifact,
          grantScope: { scope_kind_code: 'sealed_custody_access', basis_request_record_digest_sha256: request.record_digest_sha256, clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256, custody_leaf_projection_sha256: projection.leafDigestSha256, backend_code: projection.backendCode, backend_reference: projection.backendReference, copy_code: projection.copyCode, purpose_code: 'integrity', custody_evaluated_at: projection.evaluatedAt, known_through_bundle_sequence: projection.knownThroughBundleSequence },
          issuedAt: now, expiresAt: capabilityExpiresAt, adapterBindingCode, requesterBindingCode: request.sender_binding_code })
        sealedContexts.set(cap.issuance.record_digest_sha256, { receipt: structuredClone(request.payload.primary_receipt), clearanceDigest: clearance.record_digest_sha256, projection })
        Object.assign(response.payload, { artifact: request.payload.artifact, backend_code: request.payload.backend_code, backend_reference: request.payload.backend_reference, copy_code: request.payload.copy_code, purpose_code: 'integrity', primary_receipt: request.payload.primary_receipt, clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256, custody_evaluated_at: projection.evaluatedAt, known_through_bundle_sequence: projection.knownThroughBundleSequence, custody_leaf_projection_sha256: projection.leafDigestSha256, sealed_capability_record_digest_sha256: cap.issuance.record_digest_sha256, sealed_capability_leaf_record_digest_sha256: cap.issuance.record_digest_sha256, outcome_code: 'sealed' })
        response = canonicalRecord(response)
        result = Object.freeze({ response, descriptorSidecars: new Map(), capabilitySidecars: new Map([[cap.issuance.record_digest_sha256, cap.bearerBytes]]), issuance: cap.issuance })
      } else if (request.operation_code === 'open_custody') {
        const digest = request.payload.sealed_capability_record_digest_sha256
        const claim = admissionResolver.claimCapability({ capabilityRecordDigest: digest, capabilityLeafDigest: request.payload.sealed_capability_leaf_record_digest_sha256, bearerBytes: capabilitySidecars.get(digest), request, now, expectedKind: 'sealed_custody_access' })
        const scope = claim.issuance.grant_scope
        if (scope.backend_reference !== request.payload.backend_reference || scope.copy_code !== request.payload.copy_code || scope.purpose_code !== 'integrity') failD931('D931_CAPABILITY_CONTEXT_MISMATCH', 'sealed scope differs from requested copy')
        const sealedContext = sealedContexts.get(digest)
        if (!sealedContext || !exactArtifact(sealedContext.receipt, request.payload.primary_receipt)) failD931('D931_RECEIPT_REFERENCE_MISMATCH', 'open request does not present the exact receipt sealed at issuance')
        const clearance = admissionResolver.resolveRecord(scope.clearance_decision_record_digest_sha256)
        if (clearance.record_kind_code !== 'clearance_decision' || clearance.decision_code !== 'restricted_store_only' || clearance.clearance_scope_sha256 !== scope.clearance_scope_sha256 || !(clearance.not_before <= now && now < clearance.expires_at)) failD931('D931_CLEARANCE_REJECTED', 'clearance is not current at open claim')
        const projection = assertSyntheticCustodyProjection(custodyProjectionResolver({ ...request, response_at: now, projection_phase: 'open_acceptance' }), request)
        if (projection.evaluatedAt !== now) failD931('D931_CUSTODY_PROJECTION_REJECTED', 'custody projection was not evaluated at the trusted open time')
        if (projection.leafDigestSha256 !== scope.custody_leaf_projection_sha256 || projection.knownThroughBundleSequence < scope.known_through_bundle_sequence) failD931('D931_CUSTODY_PROJECTION_REJECTED', 'current custody projection differs from the sealed scope')
        const receipt = journalBroker.resolveReceipt(request.payload.primary_receipt)
        if (!exactArtifact(receipt.semantic.artifact, request.payload.artifact) || receipt.semantic.copy_code !== request.payload.copy_code || receipt.semantic.backend_reference !== request.payload.backend_reference) failD931('D931_RECEIPT_REFERENCE_MISMATCH', 'open receipt does not bind the exact copy')
        const transition = admissionResolver.transitionCapability({ capabilityRecordDigest: digest, request, response: null, toStateCode: 'consumed', transitionCode: 'consumer_succeeded', reasonCode: 'request_claimed', occurredAt: now })
        const descriptor = cas.openIntegrity({ artifact: request.payload.artifact, backendReference: request.payload.backend_reference })
        try {
        const responseNow = clock('adapter_open_custody_response')
        const responseClearance = admissionResolver.resolveRecord(scope.clearance_decision_record_digest_sha256)
        const responseProjection = assertSyntheticCustodyProjection(custodyProjectionResolver({ ...request, response_at: responseNow, projection_phase: 'open_response' }), request)
        if (responseClearance.record_digest_sha256 !== clearance.record_digest_sha256 || responseClearance.clearance_scope_sha256 !== scope.clearance_scope_sha256 || !(responseClearance.not_before <= responseNow && responseNow < responseClearance.expires_at) || !(responseNow < claim.issuance.expires_at) || responseProjection.evaluatedAt !== responseNow || responseProjection.leafDigestSha256 !== projection.leafDigestSha256 || responseProjection.knownThroughBundleSequence !== projection.knownThroughBundleSequence) failD931('D931_CLEARANCE_REJECTED', 'clearance, capability, or custody projection changed or expired before open response')
        response.created_at = responseNow
        response.ancillary_descriptors = [{ ordinal: 1, role_code: 'custody_source', access_code: 'read_only', file_type_code: 'regular_file' }]
        Object.assign(response.payload, { artifact: request.payload.artifact, backend_code: request.payload.backend_code, backend_reference: request.payload.backend_reference, copy_code: request.payload.copy_code, purpose_code: 'integrity', primary_receipt: request.payload.primary_receipt, clearance_decision_record_digest_sha256: scope.clearance_decision_record_digest_sha256, clearance_scope_sha256: scope.clearance_scope_sha256, custody_evaluated_at: responseProjection.evaluatedAt, known_through_bundle_sequence: scope.known_through_bundle_sequence, custody_leaf_projection_sha256: scope.custody_leaf_projection_sha256, sealed_capability_record_digest_sha256: digest, sealed_capability_leaf_record_digest_sha256: request.payload.sealed_capability_leaf_record_digest_sha256, outcome_code: 'available' })
        response = canonicalRecord(response)
        sealedContexts.delete(digest)
        result = Object.freeze({ response, descriptorGrantAvailable: true, transition })
        pendingDescriptorGrant = { descriptor, lifecycleContext: deepFreeze({ operationId: request.operation_id, operationNonce: request.operation_nonce, bundle: structuredClone(receipt.semantic.bundle), artifact: structuredClone(request.payload.artifact), copyCode: request.payload.copy_code, backendReference: request.payload.backend_reference, purposeCode: 'integrity', runtimeProfileDigest: request.runtime_profile_record_digest_sha256, identityBindingsDigest: request.identity_bindings_record_digest_sha256, custodyProfileDigest: request.d930_operational_profile_record_digest_sha256, openRequestDigest: request.record_digest_sha256, openResponseDigest: response.record_digest_sha256, sealedCapabilityDigest: digest, sealedCapabilityTransitionDigest: transition.record_digest_sha256, importerBindingCode: request.sender_binding_code }) }
        } catch (error) {
          fs.closeSync(descriptor)
          throw error
        }
      }
      try {
      validateD930Record({ contractSet: admissionResolver.contractSet ?? undefined, record: result.response, bindingRoleResolver: admissionResolver.bindingRole })
      const journalCode = `journal.${request.operation_id}`
      let supportingAcks = [...(result.preReceiptSupportingAcks ?? stream.supportingAcks ?? [])]
      if (request.operation_code !== 'publish_no_replace') {
        supportingAcks.push(await persistSupportingRecord({ journalPeerProvider, journalBroker, record: request, kindCode: 'custody_adapter_message', journalCode, journalBindingCode, journalProfileDigest: admissionResolver.journalProfile.record_digest_sha256, createdAt: clock(`${request.operation_code}_request_supporting`) }))
      }
      supportingAcks.push(await persistSupportingRecord({ journalPeerProvider, journalBroker, record: result.response, kindCode: 'custody_adapter_message', journalCode, journalBindingCode, journalProfileDigest: admissionResolver.journalProfile.record_digest_sha256, createdAt: clock(`${request.operation_code}_response_supporting`) }))
      const next = { index: stream.index + 1, terminal: false, responseDigests: [...(stream.responseDigests ?? []), result.response.record_digest_sha256], supportingAcks, custodyIntent: stream.custodyIntent ?? deepFreeze(structuredClone(request.payload.custody_intent)) }
      streams.set(streamKey, next)
      const durableResult = Object.freeze({ ...result, supportingAcks: Object.freeze([...supportingAcks]) })
      adapterResults.add(durableResult)
      if (pendingDescriptorGrant) registerOneShotCustodyDescriptor({ grantSink: integrityGrantSink, adapterResult: durableResult, ...pendingDescriptorGrant })
      exactReplays.set(request.request_id, { requestDigest: request.record_digest_sha256, result: durableResult })
      if (request.operation_code === 'publish_no_replace') primaryPublicationInFlight = false
      if (['prepare', 'verify_prepared'].includes(request.operation_code)) custodyMutationInFlight = false
      return durableResult
      } catch (error) {
        if (pendingDescriptorGrant) fs.closeSync(pendingDescriptorGrant.descriptor)
        for (const descriptor of result?.descriptorSidecars?.values?.() ?? []) {
          try { fs.closeSync(descriptor) } catch {}
        }
        throw error
      }
    },
  })
  adapters.add(adapter)
  return adapter
}

export function assertD931CustodyAdapterResult(value) {
  if (!adapterResults.has(value)) failD931('D931_CUSTODY_DESCRIPTOR_UNAVAILABLE', 'descriptor registration requires an exact custody-adapter result')
  return value
}

export function makeAdapterRequest({ operationCode, operationId, operationNonce, requestSequence, senderBindingCode, adapterBindingCode, runtimeProfileDigest, identityBindingsDigest, custodyProfileDigest, createdAt, payload }) {
  const fullPayload = emptyPayload()
  Object.assign(fullPayload, structuredClone(payload))
  return canonicalRecord({
    format: 'jedi-atlas-custody-adapter-message', format_version: '2.0.0', record_code: `adapter.${operationId}.${operationCode}.${requestSequence}`,
    message_kind_code: 'request', operation_code: operationCode, operation_id: operationId,
    request_id: `request.${operationId}.${operationCode}.${requestSequence}`, request_sequence: requestSequence,
    operation_nonce: operationNonce, sender_binding_code: senderBindingCode, recipient_binding_code: adapterBindingCode,
    runtime_profile_record_digest_sha256: runtimeProfileDigest, identity_bindings_record_digest_sha256: identityBindingsDigest,
    d930_operational_profile_record_digest_sha256: custodyProfileDigest, request_record_digest_sha256: null,
    created_at: createdAt, ancillary_descriptors: operationCode === 'prepare' ? [{ ordinal: 1, role_code: 'staged_source', access_code: 'read_only', file_type_code: 'regular_file' }] : [],
    payload: fullPayload, record_digest_sha256: null,
  })
}
