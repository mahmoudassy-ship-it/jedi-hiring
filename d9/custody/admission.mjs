import { randomBytes } from 'node:crypto'
import { canonicalize } from '../control-plane/canonical.mjs'
import { assertVerifiedRuntimeGeneration } from '../control-plane/contracts.mjs'
import { validateBundleSealSemantics, validateCollectorHandoffSemantics } from '../control-plane/ceremony-semantics.mjs'
import { assertLinuxEnforcement } from '../control-plane/platform.mjs'
import { canonicalRecord, validateD90CustodyRecord, validateD930Record } from './contracts.mjs'
import { failD931 } from './errors.mjs'
import { assertProtectedJournalBroker } from './trust.mjs'

const resolvers = new WeakSet()
const peerProofs = new WeakMap()
const snapshots = new WeakSet()
const snapshotReaders = new WeakSet()
const custodyProjections = new WeakSet()
const SHA = /^[0-9a-f]{64}$/u
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const INVENTORY_CODES = Object.freeze(['operation_control_inventory', 'capability_inventory', 'primary_receipt_inventory', 'custody_inventory', 'candidate_inventory', 'canonical_state_inventory', 'reference_inventory', 'hold_inventory', 'backup_inventory'])
const INVENTORY_STATES = new Set(['complete_empty', 'complete_nonempty', 'unavailable', 'unavailable_d9_4', 'unavailable_d9_5'])

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

function canonicalTimestamp(value, label) {
  if (typeof value !== 'string' || !UTC.test(value) || new Date(value).toISOString() !== value) failD931('D931_TIME_INVALID', `${label} is not canonical UTC`)
  return value
}

function bindingByCode(generation, code) {
  const matches = generation.identityBindings.bindings.filter((entry) => entry.binding_code === code)
  if (matches.length !== 1) failD931('D931_BINDING_UNRESOLVED', `binding does not resolve exactly once: ${code}`)
  return matches[0]
}

export async function authenticateSyntheticAdapterPeer({ linuxEnforcement, exchangeOptions, verifiedGeneration, bindingCode, expectedEndpointCode, requestDigestSha256, operationNonce, requestCreatedAt }) {
  assertVerifiedRuntimeGeneration(verifiedGeneration)
  assertLinuxEnforcement(linuxEnforcement)
  if (!exchangeOptions || exchangeOptions.requestDigestSha256 !== requestDigestSha256 || exchangeOptions.nonce !== operationNonce || exchangeOptions.expectedEndpointCode !== expectedEndpointCode) failD931('D931_PEER_AUTHENTICATION_FAILED', 'native peer exchange is not bound to the exact request and operation')
  const linuxExchangeResult = await linuxEnforcement.runSyntheticPeerExchange(exchangeOptions)
  if (!linuxExchangeResult || linuxExchangeResult.syntheticPeer !== true || linuxExchangeResult.status !== 'ok' ||
      linuxExchangeResult.ack_same_channel !== true || linuxExchangeResult.termination_confirmed !== true ||
      linuxExchangeResult.authenticatedEndpointCode !== expectedEndpointCode) {
    failD931('D931_PEER_AUTHENTICATION_FAILED', `kernel-authenticated synthetic IPC proof is incomplete (${linuxExchangeResult?.error_code ?? linuxExchangeResult?.status ?? 'missing'})`)
  }
  const binding = bindingByCode(verifiedGeneration, bindingCode)
  canonicalTimestamp(requestCreatedAt, 'peer-bound request time')
  if (!(binding.valid_from <= requestCreatedAt && requestCreatedAt < binding.valid_until)) failD931('D931_PEER_IDENTITY_MISMATCH', 'kernel peer binding is not active for the exact request time')
  if (binding.unix_uid !== linuxExchangeResult.peer_uid || binding.ipc_endpoint_code !== expectedEndpointCode) {
    failD931('D931_PEER_IDENTITY_MISMATCH', 'kernel peer facts do not match the protected binding')
  }
  const result = Object.freeze({
    bindingCode,
    runtimeRoleCode: binding.runtime_role_code,
    uid: linuxExchangeResult.peer_uid,
    gid: linuxExchangeResult.peer_gid,
    pid: linuxExchangeResult.peer_pid,
    endpointCode: expectedEndpointCode,
    executableSha256: binding.executable_sha256,
    requestDigestSha256,
    operationNonce,
    requestCreatedAt,
    bindingValidFrom: binding.valid_from,
    bindingValidUntil: binding.valid_until,
    runtimeProfileDigest: verifiedGeneration.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: verifiedGeneration.identityBindings.record_digest_sha256,
    transportCode: 'unix_sock_seqpacket_so_peercred_scm_rights_synthetic',
  })
  peerProofs.set(result, { consumed: false })
  return result
}

export function assertAuthenticatedPeer(value, expectedRole, expectedBinding, requestDigestSha256, operationNonce, requestCreatedAt) {
  const state = peerProofs.get(value)
  if (!state || state.consumed || value.runtimeRoleCode !== expectedRole || value.bindingCode !== expectedBinding || value.requestDigestSha256 !== requestDigestSha256 || value.operationNonce !== operationNonce || value.requestCreatedAt !== requestCreatedAt) failD931('D931_PEER_AUTHENTICATION_FAILED', 'peer proof is not valid for this exact request')
  state.consumed = true
  return value
}

export function assertAuthenticatedPeerContext(value, request, acceptedAt, expectedJournalProfileDigest = null, { enforceFreshness = true } = {}) {
  canonicalTimestamp(acceptedAt, 'peer-bound acceptance time')
  if (value.runtimeProfileDigest !== request.runtime_profile_record_digest_sha256 ||
      value.identityBindingsDigest !== request.identity_bindings_record_digest_sha256 ||
      (expectedJournalProfileDigest !== null && request.d930_journal_profile_record_digest_sha256 !== expectedJournalProfileDigest) ||
      !(value.bindingValidFrom <= acceptedAt && acceptedAt < value.bindingValidUntil) ||
      request.created_at > acceptedAt || (enforceFreshness && Date.parse(acceptedAt) - Date.parse(request.created_at) > 300_000)) {
    failD931('D931_PEER_CONTEXT_REJECTED', 'peer generation, profile, active interval, or request freshness differs at trusted acceptance time')
  }
  return value
}

export function createD931AdmissionResolver({ contractSet, verifiedGeneration, custodyProfile, journalProfile }) {
  assertVerifiedRuntimeGeneration(verifiedGeneration)
  const role = (code) => bindingByCode(verifiedGeneration, code).runtime_role_code
  const verifiedCustodyProfile = deepFreeze(structuredClone(validateD930Record({ contractSet, record: custodyProfile, bindingRoleResolver: role })))
  const verifiedJournalProfile = deepFreeze(structuredClone(validateD930Record({ contractSet, record: journalProfile, bindingRoleResolver: role })))
  if (verifiedCustodyProfile.profile_kind_code !== 'custody_adapter' || verifiedJournalProfile.profile_kind_code !== 'journal') failD931('D931_PROFILE_KIND_MISMATCH', 'D9.3 profiles have the wrong kind')
  const records = new Map()
  const capabilities = new Map()
  const consumedBearers = new Set()
  function admitIssuedCapability({ recordBytes, record, bearerBytes }) {
    const verified = validateD90CustodyRecord({ contractSet, ...(recordBytes !== undefined ? { recordBytes } : { record }) })
    if (verified.record_kind_code !== 'capability_issuance') failD931('D931_CAPABILITY_INVALID', 'only issuance records can introduce bearer sidecars')
    if (!Buffer.isBuffer(bearerBytes) || bearerBytes.length !== 32) failD931('D931_CAPABILITY_BEARER_INVALID', 'capability bearer must be a 256-bit sidecar')
    const prior = capabilities.get(verified.record_digest_sha256)
    if (prior && (!prior.bearerBytes.equals(bearerBytes) || canonicalize(prior.issuance) !== canonicalize(verified))) failD931('D931_CAPABILITY_COLLISION', 'capability identity collision')
    capabilities.set(verified.record_digest_sha256, { issuance: verified, leaf: verified, bearerBytes: Buffer.from(bearerBytes), terminal: false })
    records.set(verified.record_digest_sha256, verified)
    return verified
  }

  const resolver = Object.freeze({
    contractSet,
    verifiedGeneration,
    custodyProfile: verifiedCustodyProfile,
    journalProfile: verifiedJournalProfile,
    bindingRole: role,
    resolveBinding: (code) => structuredClone(bindingByCode(verifiedGeneration, code)),
    admitBaseRecord({ schemaFile, recordBytes, record }) {
      const verified = validateD90CustodyRecord({ contractSet, schemaFile, ...(recordBytes !== undefined ? { recordBytes } : { record }) })
      if (Object.hasOwn(verified, 'runtime_profile_record_digest_sha256') && verified.runtime_profile_record_digest_sha256 !== verifiedGeneration.runtimeProfile.record_digest_sha256) failD931('D931_ADMISSION_GENERATION_MISMATCH', 'base record pins another runtime profile')
      if (Object.hasOwn(verified, 'identity_bindings_record_digest_sha256') && verified.identity_bindings_record_digest_sha256 !== verifiedGeneration.identityBindings.record_digest_sha256) failD931('D931_ADMISSION_GENERATION_MISMATCH', 'base record pins another identity generation')
      if (verified.record_kind_code === 'collector_handoff') {
        validateCollectorHandoffSemantics({ contractSet: contractSet.baseContractSet, verifiedGeneration, collectorHandoff: verified })
      } else if (verified.record_kind_code === 'bundle_seal') {
        const handoffs = verified.collector_handoffs.map((reference) => {
          const handoff = records.get(reference.record_digest_sha256)
          if (!handoff || handoff.record_kind_code !== 'collector_handoff' || handoff.record_code !== reference.record_code || handoff.format !== reference.format || handoff.format_version !== reference.format_version) failD931('D931_ADMISSION_UNRESOLVED', 'bundle seal does not resolve its exact previously admitted collector handoff')
          return handoff
        })
        validateBundleSealSemantics({ contractSet: contractSet.baseContractSet, verifiedGeneration, bundleSeal: verified, collectorHandoffs: handoffs })
      }
      const digest = verified.record_digest_sha256
      const prior = records.get(digest)
      if (prior && canonicalize(prior) !== canonicalize(verified)) failD931('D931_ADMISSION_COLLISION', 'same digest resolved to different base records')
      records.set(digest, verified)
      return verified
    },
    issueSyntheticCapability({ kindCode, basisRequest, artifact, grantScope, issuedAt, expiresAt, adapterBindingCode, requesterBindingCode }) {
      if (!['source_handle', 'preparation', 'sealed_custody_access'].includes(kindCode)) failD931('D931_CAPABILITY_INVALID', 'unknown capability kind')
      const capabilityPolicy = contractSet.baseContractSet.classification.custody_capability_rules.find((entry) => entry.capability_kind_code === kindCode)
      const lifetimeMs = Date.parse(expiresAt) - Date.parse(issuedAt)
      if (!capabilityPolicy || !(basisRequest.created_at < issuedAt) || !Number.isSafeInteger(lifetimeMs) || lifetimeMs <= 0 || lifetimeMs > capabilityPolicy.lifetime_ms_max || basisRequest.operation_code !== capabilityPolicy.issuance_operation_code) failD931('D931_CAPABILITY_INVALID', 'capability basis, chronology, or lifetime differs from the frozen policy')
      const allowed = kindCode === 'source_handle' ? ['prepare'] : kindCode === 'preparation' ? ['verify_prepared', 'publish_no_replace', 'abandon_temp'] : ['open_custody']
      const replay = kindCode === 'source_handle' ? 'single_consume_prepare' : kindCode === 'preparation' ? 'ordered_verify_then_publish_or_abandon' : 'single_consume_open_custody'
      const issuance = canonicalRecord({
        format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_issuance',
        record_code: `capability.${kindCode}.${basisRequest.record_digest_sha256.slice(0, 32)}`,
        capability_kind_code: kindCode, issued_by_binding_code: adapterBindingCode,
        requester_binding_code: requesterBindingCode, adapter_binding_code: adapterBindingCode,
        operation_id: basisRequest.operation_id, operation_nonce: basisRequest.operation_nonce,
        runtime_profile_record_digest_sha256: basisRequest.runtime_profile_record_digest_sha256,
        identity_bindings_record_digest_sha256: basisRequest.identity_bindings_record_digest_sha256,
        artifact: structuredClone(artifact), allowed_consumer_operation_codes: allowed, replay_policy_code: replay,
        grant_scope: structuredClone(grantScope), issued_at: issuedAt, expires_at: expiresAt,
        record_digest_sha256: null,
      })
      const bytes = Buffer.from(canonicalize(issuance), 'utf8')
      const bearerBytes = randomBytes(32)
      admitIssuedCapability({ recordBytes: bytes, record: issuance, bearerBytes })
      return Object.freeze({ issuance, bearerBytes })
    },
    claimCapability({ capabilityRecordDigest, capabilityLeafDigest, bearerBytes, request, now, expectedKind }) {
      const state = capabilities.get(capabilityRecordDigest)
      if (!state || state.issuance.capability_kind_code !== expectedKind || state.leaf.record_digest_sha256 !== capabilityLeafDigest || state.terminal) failD931('D931_CAPABILITY_UNAVAILABLE', 'capability or current leaf is unavailable')
      if (!Buffer.isBuffer(bearerBytes) || !state.bearerBytes.equals(bearerBytes)) failD931('D931_CAPABILITY_BEARER_REJECTED', 'capability bearer sidecar differs')
      if (consumedBearers.has(bearerBytes.toString('hex'))) failD931('D931_CAPABILITY_REPLAY', 'terminal bearer was reused')
      const issuance = state.issuance
      if (!(issuance.issued_at <= now && now < issuance.expires_at) || !issuance.allowed_consumer_operation_codes.includes(request.operation_code)) failD931('D931_CAPABILITY_EXPIRED_OR_WRONG_OPERATION', 'capability is expired or does not authorize this operation')
      const leafKnownAt = state.leaf === issuance ? issuance.issued_at : state.leaf.occurred_at
      if (!(leafKnownAt < request.created_at && request.created_at <= now)) failD931('D931_CAPABILITY_CONTEXT_MISMATCH', 'request chronology predates the presented capability leaf')
      for (const key of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) if (issuance[key] !== request[key]) failD931('D931_CAPABILITY_CONTEXT_MISMATCH', `${key} differs from the capability`)
      if (issuance.requester_binding_code !== request.sender_binding_code || issuance.adapter_binding_code !== request.recipient_binding_code || canonicalize(issuance.artifact) !== canonicalize(request.payload.artifact ?? issuance.artifact)) failD931('D931_CAPABILITY_CONTEXT_MISMATCH', 'request actor or artifact differs')
      return Object.freeze({ issuance, leaf: state.leaf })
    },
    transitionCapability({ capabilityRecordDigest, request, response = null, toStateCode, transitionCode, reasonCode, occurredAt }) {
      const state = capabilities.get(capabilityRecordDigest)
      if (!state || state.terminal) failD931('D931_CAPABILITY_TRANSITION_REJECTED', 'capability is unavailable or terminal')
      const previous = state.leaf === state.issuance ? null : state.leaf
      const fromState = previous?.to_state_code ?? 'ready'
      const priorKnownAt = previous?.occurred_at ?? state.issuance.issued_at
      const transitionRules = contractSet.baseContractSet.classification.custody_capability_transition_rules.filter((rule) => rule.capability_kind_code === state.issuance.capability_kind_code && rule.from_state_code === fromState && rule.to_state_code === toStateCode && rule.transition_code === transitionCode && rule.reason_code === reasonCode)
      if (transitionRules.length !== 1 || !(priorKnownAt < request.created_at && request.created_at <= occurredAt && occurredAt < state.issuance.expires_at)) failD931('D931_CAPABILITY_TRANSITION_REJECTED', 'transition rule or chronology differs from the frozen policy')
      const transitionRule = transitionRules[0]
      if (request.operation_code !== transitionRule.consumer_operation_code || (transitionRule.response_policy_code === 'must_be_null') !== (response === null) || (response && (response.request_record_digest_sha256 !== request.record_digest_sha256 || response.created_at !== occurredAt))) failD931('D931_CAPABILITY_TRANSITION_REJECTED', 'transition consumer or response binding differs from the frozen policy')
      if (response) {
        const operationRule = contractSet.classifications.custody_message_rules.find((entry) => entry.operation_code === request.operation_code)
        const expectedOutcome = transitionRule.response_policy_code === 'required_corrupt' ? response.payload.outcome_code === 'corrupt' : operationRule?.success_outcomes.includes(response.payload.outcome_code)
        if (!expectedOutcome) failD931('D931_CAPABILITY_TRANSITION_REJECTED', 'transition response outcome differs from the frozen policy')
      }
      const transition = canonicalRecord({
        format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_transition',
        record_code: `${state.issuance.record_code}.transition.${previous ? previous.transition_sequence + 1 : 1}`,
        capability_kind_code: state.issuance.capability_kind_code,
        capability_record_digest_sha256: state.issuance.record_digest_sha256,
        transition_sequence: previous ? previous.transition_sequence + 1 : 1,
        previous_transition_record_digest_sha256: previous?.record_digest_sha256 ?? null,
        from_state_code: fromState, to_state_code: toStateCode, transition_code: transitionCode,
        request_record_digest_sha256: request.record_digest_sha256,
        response_record_digest_sha256: response?.record_digest_sha256 ?? null,
        recorded_by_binding_code: state.issuance.adapter_binding_code, occurred_at: occurredAt,
        reason_code: reasonCode, record_digest_sha256: null,
      })
      const bytes = Buffer.from(canonicalize(transition), 'utf8')
      validateD90CustodyRecord({ contractSet, recordBytes: bytes })
      const terminal = ['consumed', 'abandoned', 'invalidated'].includes(toStateCode)
      capabilities.set(capabilityRecordDigest, { ...state, leaf: transition, terminal })
      records.set(transition.record_digest_sha256, transition)
      if (terminal) consumedBearers.add(state.bearerBytes.toString('hex'))
      return transition
    },
    resolveRecord(digest) {
      if (!SHA.test(digest) || !records.has(digest)) failD931('D931_ADMISSION_UNRESOLVED', 'protected record digest is unresolved')
      return records.get(digest)
    },
    assertRequestContext(request) {
      if (request.runtime_profile_record_digest_sha256 !== verifiedGeneration.runtimeProfile.record_digest_sha256 ||
          request.identity_bindings_record_digest_sha256 !== verifiedGeneration.identityBindings.record_digest_sha256 ||
          request.d930_operational_profile_record_digest_sha256 !== verifiedCustodyProfile.record_digest_sha256) {
        failD931('D931_REQUEST_PROFILE_MISMATCH', 'request does not pin the selected D9.0.1/D9.3.0 generation')
      }
      return true
    },
  })
  resolvers.add(resolver)
  return resolver
}

export function assertD931AdmissionResolver(value) {
  if (!resolvers.has(value)) failD931('D931_ADMISSION_UNTRUSTED', 'resolver is not fixed-function D9.3.1 admission')
  return value
}

export function createProtectedInventorySnapshotReader({ journalBroker, inventoryReaders, clock }) {
  assertProtectedJournalBroker(journalBroker)
  if (typeof clock !== 'function' || !inventoryReaders || Object.keys(inventoryReaders).toSorted().join('|') !== [...INVENTORY_CODES].toSorted().join('|') || Object.values(inventoryReaders).some((reader) => typeof reader !== 'function')) failD931('D931_INVENTORY_READER_REJECTED', 'snapshot reader requires nine exact protected inventory readers and a journal resolver')
  const reader = Object.freeze({
    capture({ operationId, operationNonce, journalCode }) {
      if (!snapshotReaders.has(reader) || typeof operationId !== 'string' || !SHA.test(operationNonce) || typeof journalCode !== 'string') failD931('D931_INVENTORY_SNAPSHOT_REJECTED', 'snapshot subject is invalid')
      const journalHead = journalBroker.head(journalCode)
      if (!journalHead) failD931('D931_INVENTORY_SNAPSHOT_REJECTED', 'source journal has no protected head')
      const inventoryHeads = INVENTORY_CODES.map((inventoryCode) => {
        const value = inventoryReaders[inventoryCode]({ operationId, operationNonce })
        if (!value || !INVENTORY_STATES.has(value.state_code) || (value.state_code === 'complete_nonempty') !== SHA.test(value.head_digest_sha256 ?? '') || (value.state_code !== 'complete_nonempty' && value.head_digest_sha256 !== null)) failD931('D931_INVENTORY_SNAPSHOT_REJECTED', `invalid ${inventoryCode} projection`)
        return { inventory_code: inventoryCode, state_code: value.state_code, head_digest_sha256: value.head_digest_sha256 }
      })
      const capturedAt = canonicalTimestamp(clock('protected_inventory_snapshot'), 'snapshot capture time')
      if (capturedAt < journalHead.persisted_at) failD931('D931_INVENTORY_SNAPSHOT_REJECTED', 'snapshot predates the protected journal head')
      const snapshot = deepFreeze({ operationId, operationNonce, journalCode, journalHead: structuredClone(journalHead), inventoryHeads, capturedAt, atomic: false, captureModeCode: 'synthetic_sequential_unactivated' })
      snapshots.add(snapshot)
      return snapshot
    },
  })
  snapshotReaders.add(reader)
  return reader
}

export function assertProtectedInventorySnapshot(value, operationId, operationNonce) {
  if (!snapshots.has(value) || value.atomic !== true || value.operationId !== operationId || value.operationNonce !== operationNonce || !Object.isFrozen(value) || !Object.isFrozen(value.journalHead) || !Object.isFrozen(value.inventoryHeads) || value.inventoryHeads.some((entry) => !Object.isFrozen(entry))) failD931('D931_INVENTORY_SNAPSHOT_REJECTED', 'D9.3.1 rejects the synthetic sequential snapshot because no protected cross-store atomic snapshot authority exists')
  return value
}

export function createSyntheticCustodyProjection({ artifact, copyCode, backendCode, backendReference, evaluatedAt, knownThroughBundleSequence, leafDigestSha256 }) {
  if (!artifact || backendCode !== 'pilot_local_cas_v1' || !SHA.test(leafDigestSha256) || !Number.isSafeInteger(knownThroughBundleSequence) || knownThroughBundleSequence < 1) {
    failD931('D931_CUSTODY_PROJECTION_REJECTED', 'synthetic custody projection is incomplete')
  }
  const projection = deepFreeze({ artifact: structuredClone(artifact), copyCode, backendCode, backendReference, evaluatedAt, knownThroughBundleSequence, leafDigestSha256 })
  custodyProjections.add(projection)
  return projection
}

export function assertSyntheticCustodyProjection(value, request) {
  if (!custodyProjections.has(value) || canonicalize(value.artifact) !== canonicalize(request.payload.artifact) || value.copyCode !== request.payload.copy_code || value.backendCode !== request.payload.backend_code || value.backendReference !== request.payload.backend_reference) {
    failD931('D931_CUSTODY_PROJECTION_REJECTED', 'custody projection does not match the exact request subject')
  }
  return value
}
