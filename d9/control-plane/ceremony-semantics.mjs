import { canonicalize } from './canonical.mjs'
import {
  assertVerifiedApprovedRecord,
  assertVerifiedRuntimeGeneration,
} from './contracts.mjs'

const semanticRecords = new WeakMap()
const MAXIMUM_BOOTSTRAP_PERMIT_LIFETIME_MS = 3_600_000

export class D9CeremonySemanticError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`)
    this.name = 'D9CeremonySemanticError'
    this.code = code
  }
}

function fail(code, message) {
  throw new D9CeremonySemanticError(code, message)
}

function sameValue(left, right) {
  return canonicalize(left) === canonicalize(right)
}

function assertRuntimePins(record, generation) {
  if (
    record.runtime_profile_record_digest_sha256 !== generation.runtimeProfile.record_digest_sha256
    || record.identity_bindings_record_digest_sha256 !== generation.identityBindings.record_digest_sha256
  ) fail('CEREMONY_GENERATION_MISMATCH', 'record does not pin the verified runtime generation')
}

function bindingFor(generation, roleCode, bindingCode) {
  const matches = generation.identityBindings.bindings.filter((binding) =>
    binding.runtime_role_code === roleCode && binding.binding_code === bindingCode,
  )
  if (matches.length !== 1) {
    fail('CEREMONY_BINDING_MISMATCH', `${bindingCode} is not the unique ${roleCode} binding`)
  }
  return matches[0]
}

function assertBindingActiveAt(generation, binding, at, label) {
  if (!(generation.identityBindings.issued_at <= at && at < generation.identityBindings.expires_at)) {
    fail('CEREMONY_BINDING_INACTIVE', `${label} is outside the identity-generation lifetime`)
  }
  if (!(binding.valid_from <= at && at < binding.valid_until)) {
    fail('CEREMONY_BINDING_INACTIVE', `${binding.binding_code} is inactive at ${label}`)
  }
}

function assertBindingCovers(generation, binding, from, until, label) {
  if (
    !(generation.identityBindings.issued_at <= from && until <= generation.identityBindings.expires_at)
    || !(binding.valid_from <= from && until <= binding.valid_until)
  ) fail('CEREMONY_BINDING_LIFETIME', `${binding.binding_code} does not cover ${label}`)
}

function logicalStateReference(record) {
  return {
    state_seal_code: record.record_code,
    state_seal_record_digest_sha256: record.record_digest_sha256,
    logical_state_sha256: record.logical_state_sha256,
  }
}

function assertEmptyLogicalStateRecord(record, generation) {
  const payload = record.state_payload
  if (
    payload.runtime_profile_record_digest_sha256 !== generation.runtimeProfile.record_digest_sha256
    || payload.receipt_head !== null
    || payload.prior_logical_state_sha256 !== null
    || payload.principal_roster.length !== 0
    || payload.atlas_tables.some((entry) => entry.row_count !== 0)
  ) fail('CEREMONY_TARGET_NOT_EMPTY', 'logical-state seal does not describe the pre-bootstrap empty state')
}

function mark(record, details) {
  semanticRecords.set(record, Object.freeze(details))
  return record
}

function assertMarked(record, kindCode, generation) {
  const details = semanticRecords.get(record)
  if (!details || details.kindCode !== kindCode || details.generation !== generation) {
    fail('CEREMONY_RECORD_UNVERIFIED', `${kindCode} did not pass semantic validation for this generation`)
  }
  return details
}

export function assertSemanticallyVerifiedCeremonyRecord(record, {
  kindCode,
  verifiedGeneration,
} = {}) {
  const details = semanticRecords.get(record)
  if (!details) fail('CEREMONY_RECORD_UNVERIFIED', 'record did not pass D9.1 ceremony semantic validation')
  if (kindCode !== undefined && details.kindCode !== kindCode) {
    fail('CEREMONY_RECORD_UNVERIFIED', `record is not a verified ${kindCode}`)
  }
  if (verifiedGeneration !== undefined && details.generation !== verifiedGeneration) {
    fail('CEREMONY_RECORD_UNVERIFIED', 'record was verified for a different runtime generation')
  }
  return record
}

export function validateCollectorHandoffSemantics({
  contractSet,
  verifiedGeneration,
  collectorHandoff,
}) {
  const generation = assertVerifiedRuntimeGeneration(verifiedGeneration)
  const record = assertVerifiedApprovedRecord(collectorHandoff, {
    contractSet,
    schemaFile: 'collector-handoff-v1.schema.json',
  })
  if (record.record_kind_code !== 'collector_handoff') {
    fail('CEREMONY_RECORD_KIND_MISMATCH', 'collector handoff validator received another record kind')
  }
  assertRuntimePins(record, generation)
  if (!(
    record.collection_started_at <= record.collection_completed_at
    && record.collection_completed_at <= record.handoff_recorded_at
    && record.handoff_recorded_at < record.expires_at
  )) fail('CEREMONY_CHRONOLOGY_INVALID', 'collector handoff chronology is invalid')

  const collector = bindingFor(generation, 'collector', record.collector_binding_code)
  const broker = bindingFor(generation, 'handoff_broker', record.handoff_broker_binding_code)
  if (collector.atlas_principal_code !== record.collector_principal_code) {
    fail('CEREMONY_BINDING_MISMATCH', 'collector attribution differs from its verified binding')
  }
  const collectorRelease = generation.runtimeProfile.component_releases.find(
    (release) => release.runtime_role_code === 'collector',
  )
  if (collectorRelease?.executable_sha256 !== record.collector_build_sha256) {
    fail('CEREMONY_BUILD_MISMATCH', 'collector handoff does not pin the verified collector build')
  }
  assertBindingActiveAt(generation, collector, record.collection_started_at, 'collection_started_at')
  assertBindingActiveAt(generation, collector, record.collection_completed_at, 'collection_completed_at')
  assertBindingActiveAt(generation, broker, record.handoff_recorded_at, 'handoff_recorded_at')
  return mark(record, { kindCode: 'collector_handoff', generation })
}

export function validateBundleSealSemantics({
  contractSet,
  verifiedGeneration,
  bundleSeal,
  collectorHandoffs = [],
}) {
  const generation = assertVerifiedRuntimeGeneration(verifiedGeneration)
  const record = assertVerifiedApprovedRecord(bundleSeal, {
    contractSet,
    schemaFile: 'collector-handoff-v1.schema.json',
  })
  if (record.record_kind_code !== 'bundle_seal') {
    fail('CEREMONY_RECORD_KIND_MISMATCH', 'bundle-seal validator received another record kind')
  }
  assertRuntimePins(record, generation)
  if (!(record.sealed_at < record.expires_at)) {
    fail('CEREMONY_CHRONOLOGY_INVALID', 'bundle seal must expire after it is sealed')
  }

  for (const [roleCode, bindingCode] of [
    ['human_submitter', record.submitter_binding_code],
    ['bundle_importer', record.importer_binding_code],
    ['trusted_launcher', record.launcher_binding_code],
  ]) {
    assertBindingActiveAt(generation, bindingFor(generation, roleCode, bindingCode), record.sealed_at, 'sealed_at')
  }

  if (record.bundle_kind_code === 'principal_bootstrap') {
    if (record.collector_handoffs.length !== 0 || collectorHandoffs.length !== 0) {
      fail('CEREMONY_HANDOFF_CARDINALITY', 'bootstrap bundle seals must contain and resolve zero collector handoffs')
    }
  } else if (record.bundle_kind_code === 'single_document') {
    if (record.collector_handoffs.length !== 1 || collectorHandoffs.length !== 1) {
      fail('CEREMONY_HANDOFF_CARDINALITY', 'single-document bundle seals must contain and resolve exactly one collector handoff')
    }
    const handoff = collectorHandoffs[0]
    assertMarked(handoff, 'collector_handoff', generation)
    const reference = record.collector_handoffs[0]
    if (
      reference.record_code !== handoff.record_code
      || reference.record_digest_sha256 !== handoff.record_digest_sha256
      || record.sealed_at < handoff.handoff_recorded_at
      || !(record.sealed_at < handoff.expires_at)
    ) fail('CEREMONY_HANDOFF_MISMATCH', 'document bundle seal does not resolve one current, unexpired handoff')
  } else {
    fail('CEREMONY_BUNDLE_KIND_UNSUPPORTED', 'unsupported bundle kind')
  }

  return mark(record, { kindCode: 'bundle_seal', generation })
}

export function validateBootstrapPermitSemantics({
  contractSet,
  verifiedGeneration,
  bootstrapPermit,
  bootstrapBundleSeals,
  emptyLogicalStateSeal,
}) {
  const generation = assertVerifiedRuntimeGeneration(verifiedGeneration)
  const permit = assertVerifiedApprovedRecord(bootstrapPermit, {
    contractSet,
    schemaFile: 'bootstrap-control-v1.schema.json',
  })
  const emptyState = assertVerifiedApprovedRecord(emptyLogicalStateSeal, {
    contractSet,
    schemaFile: 'logical-state-seal-v1.schema.json',
  })
  if (permit.record_kind_code !== 'permit_issuance' || permit.permit_kind_code !== 'bootstrap') {
    fail('CEREMONY_RECORD_KIND_MISMATCH', 'bootstrap-permit validator received another permit kind')
  }
  assertRuntimePins(permit, generation)
  assertEmptyLogicalStateRecord(emptyState, generation)
  if (!sameValue(permit.target_empty_logical_state, logicalStateReference(emptyState))) {
    fail('CEREMONY_TARGET_NOT_EMPTY', 'permit does not target the verified empty logical-state seal')
  }
  if (permit.canonical_lineage_code !== emptyState.state_payload.canonical_lineage_code) {
    fail('CEREMONY_LINEAGE_MISMATCH', 'permit and empty state use different canonical lineages')
  }
  if (!(
    permit.issued_at <= permit.not_before
    && permit.not_before < permit.expires_at
    && Date.parse(permit.expires_at) - Date.parse(permit.issued_at) <= MAXIMUM_BOOTSTRAP_PERMIT_LIFETIME_MS
  )) fail('CEREMONY_PERMIT_LIFETIME_INVALID', 'bootstrap permit chronology or maximum lifetime is invalid')

  if (!Array.isArray(bootstrapBundleSeals)) {
    fail('CEREMONY_SEAL_MATCH_INVALID', 'bootstrap bundle seal candidates must be an array')
  }
  const matches = bootstrapBundleSeals.filter((seal) => {
    assertMarked(seal, 'bundle_seal', generation)
    return seal.bundle_kind_code === 'principal_bootstrap'
      && sameValue(seal.bundle, permit.bootstrap_bundle)
      && seal.manifest_path === permit.manifest_path
      && seal.reviewed_git_commit === permit.reviewed_git_commit
      && seal.operation_nonce === permit.operation_nonce
      && sameValue(seal.target_logical_state, permit.target_empty_logical_state)
      && seal.runtime_profile_record_digest_sha256 === permit.runtime_profile_record_digest_sha256
      && seal.identity_bindings_record_digest_sha256 === permit.identity_bindings_record_digest_sha256
      && seal.submitter_binding_code === permit.submitter_binding_code
      && seal.importer_binding_code === permit.importer_binding_code
  })
  if (matches.length !== 1) {
    fail('CEREMONY_SEAL_MATCH_INVALID', 'permit must match exactly one verified bootstrap bundle seal')
  }
  const seal = matches[0]
  if (!(seal.sealed_at <= permit.issued_at && permit.issued_at < seal.expires_at)) {
    fail('CEREMONY_SEAL_EXPIRED', 'bootstrap permit was not issued while its exact bundle seal was current')
  }

  const participantRoles = [
    ['human_submitter', permit.submitter_binding_code],
    ['operational_witness', permit.witness_binding_code],
    ['bootstrap_authority', permit.issuer_binding_code],
    ['bundle_importer', permit.importer_binding_code],
  ]
  const participants = participantRoles.map(([roleCode, bindingCode]) => {
    const binding = bindingFor(generation, roleCode, bindingCode)
    assertBindingCovers(generation, binding, permit.issued_at, permit.expires_at, 'the complete bootstrap-permit lifetime')
    return binding
  })
  const humans = participants.slice(0, 3)
  if (
    humans.some((binding) => binding.principal_kind_code !== 'human')
    || new Set(humans.map((binding) => binding.unix_uid)).size !== humans.length
  ) fail('CEREMONY_SEPARATION_OF_DUTY', 'bootstrap submitter, witness, and issuer must be distinct human subjects')

  const importerRelease = generation.runtimeProfile.component_releases.find(
    (release) => release.runtime_role_code === 'bundle_importer',
  )
  if (importerRelease?.executable_sha256 !== permit.importer_release_sha256) {
    fail('CEREMONY_BUILD_MISMATCH', 'bootstrap permit does not pin the verified importer build')
  }

  return mark(permit, {
    kindCode: 'bootstrap_permit',
    generation,
    matchedBundleSeal: seal,
    deferredChecks: Object.freeze([
      'expected_principal_roster_sha256_against_reopened_manifest',
    ]),
  })
}
