import { canonicalize } from './canonical.mjs'
import {
  assertApprovedContractSet,
} from './contracts.mjs'

const selectorFields = [
  'operation_mode_code',
  'bundle_kind_code',
  'source_authorization_code',
  'permit_kind_code',
  'permit_scope_code',
]
const grantFields = ['slot_code', 'runtime_role_code', 'access_code']
const derivedScopes = new WeakMap()
const verifiedFactSets = new WeakMap()

const SYNTHETIC_FACT_VECTORS = Object.freeze([
  Object.freeze({ operation_mode_code: 'no_op_verification', bundle_kind_code: 'principal_bootstrap', source_authorization_code: 'accepted_receipt', permit_kind_code: null, permit_scope_code: null }),
  Object.freeze({ operation_mode_code: 'no_op_verification', bundle_kind_code: 'single_document', source_authorization_code: 'accepted_receipt', permit_kind_code: null, permit_scope_code: null }),
  Object.freeze({ operation_mode_code: 'bootstrap', bundle_kind_code: 'principal_bootstrap', source_authorization_code: 'bootstrap_permit_and_zero_handoff_bundle_seal', permit_kind_code: 'bootstrap', permit_scope_code: 'canonical_first_acceptance_only' }),
  Object.freeze({ operation_mode_code: 'recovery', bundle_kind_code: 'principal_bootstrap', source_authorization_code: 'recovery_permit_and_replay_certificate', permit_kind_code: 'recovery', permit_scope_code: 'exact_bootstrap_reconstruction_only' }),
  Object.freeze({ operation_mode_code: 'document_import', bundle_kind_code: 'single_document', source_authorization_code: 'single_document_bundle_seal', permit_kind_code: null, permit_scope_code: null }),
  Object.freeze({ operation_mode_code: 'recovery', bundle_kind_code: 'principal_bootstrap', source_authorization_code: 'post_promotion_completion_permit_and_bootstrap_transition', permit_kind_code: 'post_promotion_completion', permit_scope_code: 'noncanonical_completion_only' }),
  Object.freeze({ operation_mode_code: 'recovery', bundle_kind_code: 'single_document', source_authorization_code: 'post_promotion_completion_permit_and_document_bundle_seal', permit_kind_code: 'post_promotion_completion', permit_scope_code: 'noncanonical_completion_only' }),
])

export class D9ScopeError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`)
    this.name = 'D9ScopeError'
    this.code = code
  }
}

function fail(code, message) {
  throw new D9ScopeError(code, message)
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('HANDLE_SCOPE_MISMATCH', `${label} must be an object`)
  if (canonicalize(Object.keys(value).toSorted()) !== canonicalize([...expected].toSorted())) {
    fail('HANDLE_SCOPE_MISMATCH', `${label} has unknown or missing fields`)
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function selector(rule) {
  return Object.fromEntries(selectorFields.map((field) => [field, rule[field]]))
}

function brandFacts(contractSet, facts, sourceCode) {
  const result = deepFreeze(structuredClone(facts))
  verifiedFactSets.set(result, { contractSet, sourceCode })
  return result
}

/**
 * Brands the one bootstrap selector only after the launcher's explicit D9.2
 * roster-verifier test double has matched the immutable permit commitment.
 * This is a synthetic control-plane seam, not a manifest or roster verifier.
 */
export function syntheticBootstrapFirstAcceptanceFacts({
  bundleSeal,
  contractSet,
  observedPrincipalRosterSha256,
  permit,
} = {}) {
  assertApprovedContractSet(contractSet)
  if (
    !permit
    || permit.record_kind_code !== 'permit_issuance'
    || permit.permit_kind_code !== 'bootstrap'
    || permit.scope_code !== 'canonical_first_acceptance_only'
    || !bundleSeal
    || bundleSeal.record_kind_code !== 'bundle_seal'
    || bundleSeal.bundle_kind_code !== 'principal_bootstrap'
    || bundleSeal.operation_nonce !== permit.operation_nonce
    || bundleSeal.bundle?.bundle_digest_sha256 !== permit.bootstrap_bundle?.bundle_digest_sha256
    || observedPrincipalRosterSha256 !== permit.expected_principal_roster_sha256
  ) fail('HANDLE_SCOPE_UNVERIFIED_FACTS', 'synthetic bootstrap facts do not bind the exact seal, permit, and roster commitment')
  return brandFacts(contractSet, SYNTHETIC_FACT_VECTORS[2], 'synthetic_bootstrap_roster_verification')
}

/**
 * Returns the seven closed synthetic fact vectors used only to exercise every
 * approved D9.0.1 partition. They are deliberately independent of the frozen
 * rule payload so a selector mutation cannot validate itself.
 */
export function syntheticVerifiedOperationFactSets({ contractSet }) {
  assertApprovedContractSet(contractSet)
  return Object.freeze(SYNTHETIC_FACT_VECTORS.map((facts) => brandFacts(contractSet, facts, 'synthetic_partition_audit')))
}

export function handleGrantKey(grant) {
  exactKeys(grant, grantFields, 'handle grant')
  for (const field of grantFields) {
    if (typeof grant[field] !== 'string' || grant[field].length === 0) fail('HANDLE_SCOPE_MISMATCH', `handle grant ${field} must be a nonempty string`)
  }
  return `${grant.slot_code}|${grant.runtime_role_code}|${grant.access_code}`
}

function globalHandleGrants(contractSet) {
  return contractSet.classification.logical_handle_slot_rules.flatMap((slot) => slot.recipients.map((recipient) => ({
    slot_code: slot.slot_code,
    runtime_role_code: recipient.runtime_role_code,
    access_code: recipient.access_code,
  })))
}

function assertScopePartition(contractSet, rule) {
  const global = globalHandleGrants(contractSet).map(handleGrantKey).toSorted()
  const required = rule.required_handle_grants.map(handleGrantKey)
  const forbidden = rule.forbidden_handle_grants.map(handleGrantKey)
  if (new Set(global).size !== 33 || global.length !== 33) fail('HANDLE_SCOPE_MISMATCH', 'approved global handle universe is not exactly 33 unique grants')
  if (new Set([...required, ...forbidden]).size !== 33) fail('HANDLE_SCOPE_MISMATCH', `${rule.operation_scope_code} partition overlaps or omits a grant`)
  if (canonicalize([...required, ...forbidden].toSorted()) !== canonicalize(global)) {
    fail('HANDLE_SCOPE_MISMATCH', `${rule.operation_scope_code} is not the exact global required/forbidden partition`)
  }
}

export function deriveHandleScope({ contractSet, verifiedFacts }) {
  assertApprovedContractSet(contractSet)
  const provenance = verifiedFactSets.get(verifiedFacts)
  if (!provenance || provenance.contractSet !== contractSet) {
    fail('HANDLE_SCOPE_UNVERIFIED_FACTS', 'operation facts were not derived by an approved fixed-function resolver')
  }
  exactKeys(verifiedFacts, selectorFields, 'verified operation facts')
  for (const field of selectorFields) {
    const value = verifiedFacts[field]
    if (value !== null && (typeof value !== 'string' || value.length === 0)) {
      fail('HANDLE_SCOPE_MISMATCH', `verified operation fact ${field} must be a nonempty string or null`)
    }
  }

  const target = canonicalize(verifiedFacts)
  const matches = contractSet.classification.operation_handle_scope_rules.filter((rule) => canonicalize(selector(rule)) === target)
  if (matches.length !== 1) fail('HANDLE_SCOPE_UNMATCHED', `verified operation facts matched ${matches.length} approved scopes`)
  assertScopePartition(contractSet, matches[0])

  const scope = deepFreeze(structuredClone(matches[0]))
  derivedScopes.set(scope, { contractSet, operationScopeCode: scope.operation_scope_code })
  return scope
}

export function verifyIssuedHandleGrants({ contractSet, scope, issuedGrants }) {
  assertApprovedContractSet(contractSet)
  const derivation = derivedScopes.get(scope)
  if (!derivation || derivation.contractSet !== contractSet || derivation.operationScopeCode !== scope.operation_scope_code) {
    fail('HANDLE_SCOPE_MISMATCH', 'scope was not derived from verified facts and this approved contract set')
  }
  if (!Array.isArray(issuedGrants)) fail('HANDLE_SCOPE_MISMATCH', 'issued handle grants must be an array')
  assertScopePartition(contractSet, scope)

  const actualKeys = issuedGrants.map(handleGrantKey)
  if (new Set(actualKeys).size !== actualKeys.length) fail('HANDLE_SCOPE_MISMATCH', 'issued handle grants contain a duplicate')
  const expectedKeys = scope.required_handle_grants.map(handleGrantKey)
  if (canonicalize(actualKeys.toSorted()) !== canonicalize(expectedKeys.toSorted())) {
    const expected = new Set(expectedKeys)
    const actual = new Set(actualKeys)
    const missing = expectedKeys.filter((key) => !actual.has(key))
    const additional = actualKeys.filter((key) => !expected.has(key))
    fail('HANDLE_SCOPE_MISMATCH', `issued handle grants differ from the exact required set (missing=${missing.join(',') || 'none'}; additional=${additional.join(',') || 'none'})`)
  }

  return deepFreeze(issuedGrants.map((grant) => ({ ...grant })))
}
