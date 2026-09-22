import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import { applyMigrations } from '../../data/lib/migrations.mjs'
import { canonicalize, canonicalSha256, parseStrictJson, sha256Bytes } from '../../d9/control-plane/canonical.mjs'
import { loadApprovedContractSet, verifyRuntimeGeneration } from '../../d9/control-plane/contracts.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const project = path.resolve(here, '../..')
const root = path.join(here, 'd9-recovery-resolvers')
const fixturesRoot = path.join(root, 'fixtures')
const migrationsRoot = path.join(project, 'data/migrations')
const frozenD90Root = path.join(here, 'd9-0')
const frozenD940Fixture = path.join(here, 'd9-4-0/fixtures/valid-contracts-v1.json')

const expected = Object.freeze({
  catalog: 'df33cbf575f8f4b430ef22384f0d73350e521abed6443f07006d13bb3b968ba3',
  classifications: '9f137c1ca9905b5a02754292a1b828bbdd7174af78bd385b3b4a3584fd1abe04',
  digestProfiles: 'b7adfc736b04ef5c657e94bf2a621a602e518165cbf9b08f2b3c0653963abf90',
  fieldRegistry: 'd6f9ec22ae8fdb6bbb998374680f13a89f02ffef2431d9eb8c6003294a3db1d8',
  projectionProfiles: 'c9c7a09c4a29814b1a6b55112e9b11075f1e1cc654e393561e6e3d79ad1ae6ff',
  rootInventory: '93832dc8a6f12ae030515781169fd8ac9dd5431aa68f62699168469da3da6f31',
})

const frozenMigrations = Object.freeze({
  '001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  '002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  '003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
  '004_tranche_1a_foundations.sql': '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
  '005_tranche_2a_source_quarantine.sql': '1f83b484ca998be3bf5756492d4dffd958e2a6b37dbcc837e399226fdf41026b',
})

const frozenRoots = Object.freeze({
  'docs/schema/d9-0/contract-catalog-v1.json': 'e0a5663b378453a00626f02961465a60a474e145dd5160bf85a1797cd9316d2a',
  'docs/schema/d9-3-0/contract-catalog-v1.json': 'cd91f67c25941a472b89fe2fa6f19b012714dec96661b65b76ecfacf7f48e87c',
  'docs/schema/d9-4-0/contract-catalog-v1.json': '12da4237efade65cf6e2cc19d2df936e98caf505c8f6d30b38e7df8c4d349ad7',
})

const approvedCommits = [
  '79046c27dfa6923383be33a1d0aaa5a7641f5d1f',
  '460547b7fe75a94f689dabc97fd91ee6f803934a',
  'd960a03f4b8ac8a78d3f6b40ba909eb24b5f3442',
]

const atlasTables = [
  'atlas_principals', 'atlas_languages', 'atlas_jurisdictions', 'atlas_jurisdiction_versions',
  'atlas_evidence_bundle_receipts', 'atlas_retrieval_locations', 'atlas_artifacts', 'atlas_retrieval_events',
  'atlas_retrieval_redirects', 'atlas_artifact_custody_events', 'atlas_processing_runs',
  'atlas_processing_outputs', 'atlas_unverified_candidate_occurrences',
]

const roleEndpoints = Object.freeze({ trusted_launcher: 'ipc.launcher', independent_verifier: 'ipc.verifier', journal_broker: 'ipc.journal' })
const routeRules = Object.freeze({
  d901_control_access: ['independent_verifier', 'trusted_launcher', 'trusted_launcher', 'independent_verifier'],
  d920_accepted_evidence: ['trusted_launcher', 'independent_verifier', 'independent_verifier', 'trusted_launcher'],
  d930_custody: ['independent_verifier', 'journal_broker', 'journal_broker', 'independent_verifier'],
  d940_composite_snapshot: ['trusted_launcher', 'independent_verifier', 'independent_verifier', 'trusted_launcher'],
})
const requiredNamespaces = Object.freeze({
  d901_control_access: ['d901.capability-state.v1', 'd901.control-state.v1', 'd930.custody-journal.v1', 'd940.global.control-journal.v1'],
  d920_accepted_evidence: ['d920.accepted-evidence.v1'],
  d930_custody: ['d930.custody-journal.v1', 'd930.primary-receipts.v1'],
  d940_composite_snapshot: ['d901.capability-state.v1', 'd901.control-state.v1', 'd920.accepted-evidence.v1', 'd930.custody-journal.v1', 'd930.primary-receipts.v1', 'd940.global.control-journal.v1'],
})

const d901ComponentFixtureFiles = Object.freeze({
  backup_adapter: 'docs/schema/d9-0/bootstrap-control-v1.schema.json',
  bundle_importer: 'docs/schema/d9-0/clearance-record-v1.schema.json',
  clearance_broker: 'docs/schema/d9-0/collector-handoff-v1.schema.json',
  cloner_promoter: 'docs/schema/d9-0/common-v1.schema.json',
  collector: 'docs/schema/d9-0/custody-adapter-message-v1.schema.json',
  custody_adapter: 'docs/schema/d9-0/custody-capability-control-v1.schema.json',
  database_writer: 'docs/schema/d9-0/identity-bindings-v1.schema.json',
  handoff_broker: 'docs/schema/d9-0/importer-result-v1.schema.json',
  independent_verifier: 'docs/schema/d9-0/logical-state-seal-v1.schema.json',
  journal_broker: 'docs/schema/d9-0/operation-journal-event-v1.schema.json',
  scanner: 'docs/schema/d9-0/runtime-profile-v1.schema.json',
  trusted_launcher: 'docs/schema/tranche-2a-evidence-bundle-v1.schema.json',
})
const d901OperationalFixtureFiles = Object.freeze({
  backup: 'docs/schema/d9-0/contract-catalog-v1.json',
  clearance: 'docs/schema/d9-0/classifications-v1.json',
  custody_adapter: 'docs/schema/d9-0/digest-profiles-v1.json',
  handoff: 'docs/schema/d9-0/field-registry-v1.json',
  journal: 'docs/schema/d9-0/fixtures/golden-vectors-v1.json',
  scanner_registry: 'docs/schema/d9-0/fixtures/invalid-contracts-v1.json',
})
const d901ScannerFixtureFiles = Object.freeze({
  malware: ['docs/schema/d9-0/bootstrap-control-v1.schema.json', 'docs/schema/d9-0/classifications-v1.json'],
  personal_data: ['docs/schema/d9-0/clearance-record-v1.schema.json', 'docs/schema/d9-0/digest-profiles-v1.json'],
  secrets: ['docs/schema/d9-0/collector-handoff-v1.schema.json', 'docs/schema/d9-0/field-registry-v1.json'],
})

function readJson(file) {
  return parseStrictJson(fs.readFileSync(file), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 96, maximumMembers: 50000 })
}
function rawSha(file) { return sha256Bytes(fs.readFileSync(file)) }
function fail(code, detail = '') { throw new Error(`${code}${detail ? `: ${detail}` : ''}`) }
function expectCode(fn, code) { assert.throws(fn, (error) => String(error.message).includes(code), `expected ${code}`) }
function clone(value) { return structuredClone(value) }
function recordDigest(record) { return canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' }) }
function projectionDigest(projection) { return canonicalSha256(projection, { excludedTopLevelField: 'projection_sha256' }) }
function ms(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) fail('TIMESTAMP_REJECTED')
  const result = Date.parse(value)
  if (!Number.isFinite(result) || new Date(result).toISOString() !== value) fail('TIMESTAMP_REJECTED')
  return result
}
function sortedUnique(values) { return values.every((value, index) => index === 0 || values[index - 1] < value) }
function sourceMap(values, pointer) {
  const map = new Map()
  for (const item of values) {
    const namespace = item.source_namespace_code ?? item.before?.source_namespace_code
    if (map.has(namespace)) fail('SOURCE_NAMESPACE_DUPLICATE', `${pointer}/${namespace}`)
    map.set(namespace, item)
  }
  return map
}
function same(value1, value2) { return canonicalize(value1) === canonicalize(value2) }

function d901ProductionVerificationContext() {
  const frozenFixtures = readJson(path.join(frozenD90Root, 'fixtures/valid-contracts-v1.json'))
  const runtime = clone(frozenFixtures.fixtures.find((entry) => entry.fixture_code === 'runtime_profile')?.value)
  const componentFiles = {}
  const dependencyLock = path.join(project, 'docs/schema/d9-0/field-registry-v1.json')
  for (const release of runtime.component_releases) {
    const executable = path.join(project, d901ComponentFixtureFiles[release.runtime_role_code])
    release.executable_sha256 = rawSha(executable)
    release.dependency_lock_sha256 = rawSha(dependencyLock)
    componentFiles[release.runtime_role_code] = { executable, dependencyLock }
  }
  const operationalProfileFiles = {}
  for (const profile of runtime.operational_profiles) {
    const file = path.join(project, d901OperationalFixtureFiles[profile.profile_kind_code])
    profile.profile_sha256 = rawSha(file)
    operationalProfileFiles[profile.profile_kind_code] = file
  }
  const scannerFiles = {}
  for (const scanner of runtime.scanner_policy.required_scanners) {
    const [buildRelative, rulesRelative] = d901ScannerFixtureFiles[scanner.scanner_code]
    const build = path.join(project, buildRelative)
    const rules = path.join(project, rulesRelative)
    scanner.build_sha256 = rawSha(build)
    scanner.rules_sha256 = rawSha(rules)
    scannerFiles[scanner.scanner_code] = { build, rules }
  }
  const runtimeDomainFile = path.join(project, 'docs/schema/d9-0/common-v1.schema.json')
  runtime.runtime_domain_sha256 = rawSha(runtimeDomainFile)
  runtime.record_digest_sha256 = recordDigest(runtime)
  return { runtime, componentFiles, operationalProfileFiles, scannerFiles, runtimeDomainFile }
}

function verifiedD901Generation() {
  const d940Fixture = readJson(frozenD940Fixture)
  const bindings = d940Fixture.records.identity_bindings
  const { runtime, ...files } = d901ProductionVerificationContext()
  return verifyRuntimeGeneration({
    contractSet: loadApprovedContractSet({ contractRoot: frozenD90Root }),
    runtimeProfileBytes: Buffer.from(canonicalize(runtime), 'utf8'),
    identityBindingsBytes: Buffer.from(canonicalize(bindings), 'utf8'),
    selection: {
      profile_code: runtime.profile_code,
      profile_generation: runtime.profile_generation,
      runtime_profile_record_digest_sha256: runtime.record_digest_sha256,
      binding_set_code: bindings.binding_set_code,
      binding_generation: bindings.binding_generation,
      identity_bindings_record_digest_sha256: bindings.record_digest_sha256,
    },
    asOf: '2030-01-01T00:10:00.000Z',
    migrationsDirectory: migrationsRoot,
    evidenceBundleSchemaPath: path.join(project, 'docs/schema/tranche-2a-evidence-bundle-v1.schema.json'),
    ...files,
  })
}

const catalog = readJson(path.join(root, 'contract-catalog-v1.json'))
const classifications = readJson(path.join(root, 'classifications-v1.json'))
const sourceProfiles = new Map(classifications.source_profiles.map((item) => [item.source_namespace_code, item.source_contract_fingerprint_sha256]))
const resultErrors = new Map(classifications.result_error_rules.map((item) => [item.result_code, new Set(item.error_codes)]))
const digestProfiles = readJson(path.join(root, 'digest-profiles-v1.json'))
const fieldRegistry = readJson(path.join(root, 'field-source-registry-v1.json'))
const projectionProfiles = readJson(path.join(root, 'projection-profiles-v1.json'))
const frozenD940DigestProfiles = readJson(path.join(here, 'd9-4-0/digest-profiles-v1.json'))
const inventory = readJson(path.join(root, 'root-inventory-v1.json'))
const fixture = readJson(path.join(fixturesRoot, 'valid-contracts-v1.json'))
const invalid = readJson(path.join(fixturesRoot, 'invalid-contracts-v1.json'))
const golden = readJson(path.join(fixturesRoot, 'golden-vectors-v1.json'))
const syntheticSourceState = readJson(path.join(fixturesRoot, 'synthetic-source-state-v1.json'))
const commonSchema = readJson(path.join(root, 'common-v1.schema.json'))
const requestSchema = readJson(path.join(root, 'resolution-request-v1.schema.json'))
const responseSchema = readJson(path.join(root, 'resolution-response-v1.schema.json'))
const appendSchema = readJson(path.join(root, 'append-revalidation-attestation-v1.schema.json'))
const verifiedGeneration = verifiedD901Generation()
const verifiedBindings = new Map(verifiedGeneration.identityBindings.bindings.map((binding) => [binding.runtime_role_code, binding]))

const ajv = new Ajv2020({ allErrors: true, strict: false })
for (const schema of [commonSchema, requestSchema, responseSchema, appendSchema]) ajv.addSchema(schema)
const validateRequestSchema = ajv.getSchema(requestSchema.$id)
const validateResponseSchema = ajv.getSchema(responseSchema.$id)
const validateAppendSchema = ajv.getSchema(appendSchema.$id)

function validateSchema(record) {
  const validator = record.format.endsWith('-request') ? validateRequestSchema : record.format.endsWith('-attestation') ? validateAppendSchema : validateResponseSchema
  if (!validator(record)) fail('SCHEMA_REJECTED', ajv.errorsText(validator.errors))
}

function validateIdentity(identity, runtimeGeneration, at) {
  if (identity.endpoint_code !== roleEndpoints[identity.runtime_role_code]) fail('ROLE_ENDPOINT_REJECTED')
  if (runtimeGeneration.runtime_profile_record_digest_sha256 !== verifiedGeneration.runtimeProfile.record_digest_sha256 ||
      runtimeGeneration.identity_bindings_record_digest_sha256 !== verifiedGeneration.identityBindings.record_digest_sha256 ||
      runtimeGeneration.binding_generation !== verifiedGeneration.identityBindings.binding_generation) fail('IDENTITY_GENERATION_REJECTED')
  const binding = verifiedBindings.get(identity.runtime_role_code)
  if (!binding || identity.binding_code !== binding.binding_code || identity.endpoint_code !== binding.ipc_endpoint_code || identity.executable_build_sha256 !== binding.executable_sha256) fail('IDENTITY_BINDING_REJECTED')
  if (!binding.allowed_operation_modes.includes('recovery') || !(binding.valid_from <= at && at < binding.valid_until)) fail('IDENTITY_BINDING_INACTIVE')
}

function idempotencyPayload(request) {
  return {
    resolver_kind_code: request.resolver_kind_code,
    request_code: request.request_code,
    operation_id: request.operation_id,
    operation_nonce: request.operation_nonce,
    sender: request.sender,
    recipient: request.recipient,
    runtime_generation: request.runtime_generation,
    subject: request.subject,
    requested_at: request.requested_at,
    expires_at: request.expires_at,
    knowledge_boundary: request.knowledge_boundary,
    prior_accepted_source_heads: request.prior_accepted_source_heads,
    source_contract_fingerprints: request.source_contract_fingerprints,
    input_response_record_digests: request.input_response_record_digests,
  }
}

function validateRequest(request, baseline = null) {
  validateSchema(request)
  const route = routeRules[request.resolver_kind_code]
  if (request.sender.runtime_role_code !== route[0] || request.recipient.runtime_role_code !== route[1]) fail('ROLE_ROUTE_REJECTED')
  validateIdentity(request.sender, request.runtime_generation, request.requested_at)
  validateIdentity(request.recipient, request.runtime_generation, request.requested_at)
  if (request.sender.binding_code === request.recipient.binding_code) fail('ROLE_SEPARATION_REJECTED')
  if (ms(request.requested_at) < ms(request.knowledge_boundary.known_at) || ms(request.expires_at) - ms(request.requested_at) > 5000 || ms(request.expires_at) <= ms(request.requested_at)) fail('REQUEST_TIME_REJECTED')
  const heads = sourceMap(request.prior_accepted_source_heads, 'prior heads')
  if (!sortedUnique([...heads.keys()])) fail('ORDERING_REJECTED')
  const expectedNamespaces = requiredNamespaces[request.resolver_kind_code]
  if (!same([...heads.keys()], expectedNamespaces)) fail('SOURCE_SET_REJECTED')
  if (!sortedUnique(request.source_contract_fingerprints)) fail('ORDERING_REJECTED')
  const exactFingerprints = [...new Set([...heads.values()].map((head) => head.source_contract_fingerprint_sha256))].sort()
  if (!same(request.source_contract_fingerprints, exactFingerprints)) fail('SOURCE_PROFILE_SET_REJECTED')
  for (const [namespace, head] of heads) if (head.source_contract_fingerprint_sha256 !== sourceProfiles.get(namespace)) fail('SOURCE_PROFILE_SUBSTITUTED')
  if (request.resolver_kind_code !== 'd940_composite_snapshot' && request.input_response_record_digests.length !== 0) fail('COMPOSITE_INPUT_REJECTED')
  if (request.resolver_kind_code === 'd940_composite_snapshot' && request.input_response_record_digests.length !== 3) fail('COMPOSITE_INPUT_REJECTED')
  const idem = canonicalSha256(idempotencyPayload(request))
  if (request.idempotency_key_sha256 !== idem) fail('IDEMPOTENCY_MISMATCH')
  if (recordDigest(request) !== request.record_digest_sha256) fail('DIGEST_MISMATCH')
  if (baseline && (request.idempotency_key_sha256 === baseline.idempotency_key_sha256 || request.request_code === baseline.request_code) && !same(request, baseline)) fail('REPLAY_COLLISION')
  return request
}

function validateStableSources(response, request) {
  const prior = sourceMap(request.prior_accepted_source_heads, 'prior heads')
  const observations = sourceMap(response.source_observations, 'source observations')
  if (!sortedUnique([...observations.keys()])) fail('ORDERING_REJECTED')
  if (!same([...observations.keys()], requiredNamespaces[response.resolver_kind_code])) fail('SOURCE_SET_REJECTED')
  let hasNonStableObservation = false
  for (const [namespace, observation] of observations) {
    const anchor = prior.get(namespace)
    if (!anchor) fail('SOURCE_HEAD_MISSING')
    if (response.result_code === 'resolved') {
      if (!observation.before || !observation.after || observation.stability_code !== 'stable' || !same(observation.before, observation.after) || !same(observation.before, anchor)) fail('SOURCE_HEAD_UNSTABLE')
    } else if (observation.stability_code !== 'stable' || !observation.before || !observation.after || !same(observation.before, observation.after)) {
      hasNonStableObservation = true
    }
    if (ms(observation.observed_before_at) < ms(request.requested_at) || ms(observation.observed_after_at) < ms(observation.observed_before_at) || ms(observation.observed_after_at) > ms(response.responded_at)) fail('OBSERVATION_TIME_REJECTED')
    for (const head of [observation.before, observation.after].filter(Boolean)) {
      if (head.source_namespace_code !== namespace) fail('SOURCE_NAMESPACE_MISMATCH')
      if (head.source_contract_fingerprint_sha256 !== anchor.source_contract_fingerprint_sha256) fail('SOURCE_SUBSTITUTED')
      if (head.head_sequence < anchor.head_sequence) fail('SOURCE_ROLLBACK')
      if (head.head_sequence === anchor.head_sequence && !same(head, anchor)) fail('SOURCE_FORK')
      if (head.head_sequence > anchor.head_sequence) fail('SOURCE_GAP_UNPROVEN')
      if (ms(head.head_persisted_at) > ms(request.knowledge_boundary.known_at) || ms(head.head_persisted_at) > ms(observation.observed_before_at)) fail('SOURCE_HEAD_FUTURE')
    }
  }
  const earliestObservation = Math.min(...[...observations.values()].map((item) => ms(item.observed_before_at)))
  if (ms(response.observed_at) !== earliestObservation) fail('OBSERVATION_TIME_REJECTED')
  if (response.result_code !== 'resolved' && !hasNonStableObservation && !['source_contradictory', 'global_snapshot_unprovable'].includes(response.error_code)) fail('NONRESOLVED_SOURCE_DISPOSITION_INVALID')
  return observations
}

function deriveSyntheticSourceHeads(sourceState = syntheticSourceState) {
  const sources = sourceState.sources
  const boundaries = new Map()
  for (const boundary of sources.source_boundaries) {
    if (boundaries.has(boundary.source_namespace_code) || !sortedUnique(boundary.source_payload_codes)) fail('SOURCE_BOUNDARY_REJECTED')
    const payload_commitments = boundary.source_payload_codes.map((source_payload_code) => {
      if (!(source_payload_code in sources) || source_payload_code === 'source_boundaries') fail('SOURCE_BOUNDARY_REJECTED')
      return { source_payload_code, raw_payload_sha256: canonicalSha256(sources[source_payload_code]) }
    })
    const inventory_digest_sha256 = canonicalSha256({ source_namespace_code: boundary.source_namespace_code, head_sequence: boundary.head_sequence, payload_commitments })
    const head_digest_sha256 = canonicalSha256({ source_namespace_code: boundary.source_namespace_code, head_sequence: boundary.head_sequence, head_persisted_at: boundary.head_persisted_at, inventory_digest_sha256 })
    boundaries.set(boundary.source_namespace_code, {
      source_namespace_code: boundary.source_namespace_code,
      source_contract_fingerprint_sha256: sourceProfiles.get(boundary.source_namespace_code),
      head_sequence: boundary.head_sequence,
      head_digest_sha256,
      head_persisted_at: boundary.head_persisted_at,
      inventory_digest_sha256,
    })
  }
  if (!same([...boundaries.keys()].sort(), requiredNamespaces.d940_composite_snapshot)) fail('SOURCE_BOUNDARY_REJECTED')
  return boundaries
}

function deriveProjectionOutputs(sourceState = syntheticSourceState, authenticatedHeads = null) {
  const sources = sourceState.sources
  const sourceHeads = deriveSyntheticSourceHeads(sourceState)
  if (authenticatedHeads) {
    for (const [namespace, head] of authenticatedHeads) {
      if (!head || !same(head, sourceHeads.get(namespace))) fail('PROJECTION_SOURCE_BOUNDARY_MISMATCH')
    }
  }
  const pick = (record, fields) => Object.fromEntries(fields.map((field) => [field, record[field]]))
  const contiguous = (records, field) => records.every((record, index) => record[field] === index + 1)
  const controlBoundary = sourceHeads.get('d940.global.control-journal.v1')
  if (sources.control_records.known_through_receipt_sequence !== controlBoundary.head_sequence) fail('PROJECTION_PREFIX_REJECTED')
  const control = sources.control_records.records.map((record) => pick(record, ['receipt_sequence', 'record_kind_code', 'record_digest_sha256'])).sort((a, b) => a.receipt_sequence - b.receipt_sequence)
  if (!sortedUnique(control.map((record) => String(record.receipt_sequence).padStart(16, '0'))) || control.some((record) => record.receipt_sequence > controlBoundary.head_sequence)) fail('PROJECTION_PREFIX_REJECTED')
  const sourceAccess = clone(sources.source_access_state)
  sourceAccess.capabilities.sort((a, b) => a.capability_record_digest_sha256 < b.capability_record_digest_sha256 ? -1 : 1)
  sourceAccess.descriptor_lifecycle_records.sort((a, b) => canonicalize(a) < canonicalize(b) ? -1 : 1)
  sourceAccess.adapter_message_record_digests.sort()
  if (sourceAccess.store_snapshot.capability_record_count !== sourceAccess.capabilities.length || sourceAccess.store_snapshot.descriptor_record_count !== sourceAccess.descriptor_lifecycle_records.length || sourceAccess.store_snapshot.adapter_message_record_count !== sourceAccess.adapter_message_record_digests.length) fail('PROJECTION_COMPLETENESS_REJECTED')
  if (sourceAccess.store_snapshot.capability_store_head_sha256 !== canonicalSha256(sourceAccess.capabilities) ||
      sourceAccess.store_snapshot.descriptor_store_head_sha256 !== canonicalSha256(sourceAccess.descriptor_lifecycle_records) ||
      sourceAccess.store_snapshot.adapter_message_store_head_sha256 !== canonicalSha256(sourceAccess.adapter_message_record_digests) ||
      sourceAccess.store_snapshot.d901_control_state_head_sha256 !== canonicalSha256(sources.d901_control_state)) fail('PROJECTION_COMPLETENESS_REJECTED')
  const sourceAccessHash = canonicalSha256(sourceAccess)
  const custodyBoundary = sourceHeads.get('d930.custody-journal.v1')
  if (sources.access_shutdown_state.known_through_journal_sequence !== custodyBoundary.head_sequence) fail('PROJECTION_PREFIX_REJECTED')
  const terminalByCapability = new Map()
  for (const record of sources.access_shutdown_state.capability_terminal_records) {
    if (terminalByCapability.has(record.capability_record_digest_sha256) || record.terminal_state_code !== 'revoked') fail('PROJECTION_COMPLETENESS_REJECTED')
    terminalByCapability.set(record.capability_record_digest_sha256, record.terminal_record_digest_sha256)
  }
  if (terminalByCapability.size !== sourceAccess.capabilities.length || sourceAccess.capabilities.some((record) => !terminalByCapability.has(record.capability_record_digest_sha256))) fail('PROJECTION_COMPLETENESS_REJECTED')
  const descriptorKeys = new Set(sourceAccess.descriptor_lifecycle_records.map((record) => record.descriptor_lifecycle_record_digest_sha256))
  const leafKeys = new Set(sources.access_shutdown_state.descriptor_leaves.map((record) => record.descriptor_lifecycle_record_digest_sha256))
  if (descriptorKeys.size !== sourceAccess.descriptor_lifecycle_records.length || leafKeys.size !== sources.access_shutdown_state.descriptor_leaves.length || descriptorKeys.size !== leafKeys.size || [...descriptorKeys].some((key) => !leafKeys.has(key)) || sources.access_shutdown_state.descriptor_leaves.some((record) => record.terminal_state_code !== 'closed')) fail('PROJECTION_COMPLETENESS_REJECTED')
  const shutdown = { source_access_inventory_sha256: sourceAccessHash, capability_terminal_record_digests: [...terminalByCapability.values()].sort(), descriptor_leaves: [...sources.access_shutdown_state.descriptor_leaves].sort((a, b) => canonicalize(a) < canonicalize(b) ? -1 : 1) }
  const evidenceBoundary = sourceHeads.get('d920.accepted-evidence.v1')
  if (sources.accepted_receipts.known_through_bundle_sequence !== evidenceBoundary.head_sequence || sources.accepted_logical_records.known_through_bundle_sequence !== evidenceBoundary.head_sequence || sources.lineage_store.store_snapshot.known_through_bundle_sequence !== evidenceBoundary.head_sequence) fail('PROJECTION_PREFIX_REJECTED')
  const acceptedReceipts = sources.accepted_receipts.records.map((record) => pick(record, ['bundle_sequence', 'bundle_code', 'receipt_digest_sha256'])).sort((a, b) => a.bundle_sequence - b.bundle_sequence)
  if (!contiguous(acceptedReceipts, 'bundle_sequence') || acceptedReceipts.at(-1)?.bundle_sequence !== evidenceBoundary.head_sequence) fail('PROJECTION_PREFIX_REJECTED')
  const logical = sources.accepted_logical_records.records.filter((record) => record.accepted_in_bundle_sequence <= evidenceBoundary.head_sequence).map((record) => pick(record, ['table_code', 'stable_key', 'record_digest_sha256'])).sort((a, b) => `${a.table_code}\0${a.stable_key}` < `${b.table_code}\0${b.stable_key}` ? -1 : 1)
  if (logical.length !== sources.accepted_logical_records.records.length) fail('PROJECTION_PREFIX_REJECTED')
  if (new Set(logical.map((record) => `${record.table_code}\0${record.stable_key}`)).size !== logical.length) fail('PROJECTION_COMPLETENESS_REJECTED')
  const lineage = clone(sources.lineage_store)
  lineage.nodes.sort((a, b) => a.subject_identity_sha256 < b.subject_identity_sha256 ? -1 : 1)
  lineage.edges.sort((a, b) => `${a.from_subject_identity_sha256}\0${a.to_subject_identity_sha256}` < `${b.from_subject_identity_sha256}\0${b.to_subject_identity_sha256}` ? -1 : 1)
  if (lineage.target_subject_identity_sha256 !== sourceState.subject_identity_sha256 || lineage.store_snapshot.node_count !== lineage.nodes.length || lineage.store_snapshot.edge_count !== lineage.edges.length) fail('PROJECTION_COMPLETENESS_REJECTED')
  const nodes = new Set(lineage.nodes.map((node) => node.subject_identity_sha256))
  const edgeKeys = new Set(lineage.edges.map((edge) => `${edge.from_subject_identity_sha256}\0${edge.to_subject_identity_sha256}`))
  if (nodes.size !== lineage.nodes.length || edgeKeys.size !== lineage.edges.length || !nodes.has(lineage.target_subject_identity_sha256) || lineage.edges.some((edge) => !nodes.has(edge.from_subject_identity_sha256) || !nodes.has(edge.to_subject_identity_sha256) || edge.from_subject_identity_sha256 === edge.to_subject_identity_sha256)) fail('PROJECTION_LINEAGE_REJECTED')
  if (lineage.store_snapshot.node_store_head_sha256 !== canonicalSha256(lineage.nodes) || lineage.store_snapshot.edge_store_head_sha256 !== canonicalSha256(lineage.edges)) fail('PROJECTION_COMPLETENESS_REJECTED')
  const outgoing = new Map([...nodes].map((node) => [node, []]))
  const incoming = new Map([...nodes].map((node) => [node, []]))
  for (const edge of lineage.edges) {
    outgoing.get(edge.from_subject_identity_sha256).push(edge.to_subject_identity_sha256)
    incoming.get(edge.to_subject_identity_sha256).push(edge.from_subject_identity_sha256)
  }
  const visiting = new Set()
  const visited = new Set()
  const visit = (node) => {
    if (visiting.has(node)) fail('PROJECTION_LINEAGE_REJECTED')
    if (visited.has(node)) return
    visiting.add(node)
    for (const next of outgoing.get(node)) visit(next)
    visiting.delete(node)
    visited.add(node)
  }
  for (const node of nodes) visit(node)
  const ancestors = new Set([lineage.target_subject_identity_sha256])
  const pending = [lineage.target_subject_identity_sha256]
  while (pending.length) {
    for (const predecessor of incoming.get(pending.pop())) {
      if (ancestors.has(predecessor)) continue
      ancestors.add(predecessor)
      pending.push(predecessor)
    }
  }
  if (ancestors.size !== nodes.size) fail('PROJECTION_LINEAGE_REJECTED')
  const primaryBoundary = sourceHeads.get('d930.primary-receipts.v1')
  if (sources.primary_receipts.known_through_receipt_sequence !== primaryBoundary.head_sequence || sources.custody_candidates.known_through_journal_sequence !== custodyBoundary.head_sequence) fail('PROJECTION_PREFIX_REJECTED')
  for (const receipt of sources.primary_receipts.records) {
    const payload = clone(receipt); delete payload.receipt_digest_sha256
    if (receipt.receipt_digest_sha256 !== canonicalSha256(payload)) fail('PROJECTION_RECEIPT_REJECTED')
  }
  const primaryReceipts = sources.primary_receipts.records.map((record) => pick(record, ['receipt_sequence', 'receipt_code', 'receipt_digest_sha256'])).sort((a, b) => a.receipt_sequence - b.receipt_sequence)
  if (!contiguous(primaryReceipts, 'receipt_sequence') || primaryReceipts.at(-1)?.receipt_sequence !== primaryBoundary.head_sequence) fail('PROJECTION_PREFIX_REJECTED')
  const custodyMatches = sources.custody_candidates.records.filter((record) => record.subject_identity_sha256 === sourceState.subject_identity_sha256)
  if (custodyMatches.length !== 1) fail('PROJECTION_CUSTODY_REJECTED')
  const custody = pick(custodyMatches[0], ['d930_operational_profile_record_digest_sha256', 'd930_primary_durability_receipt_sha256', 'artifact', 'copy_code', 'backend_code', 'backend_reference'])
  const supportingReceipt = sources.primary_receipts.records.find((record) => record.receipt_digest_sha256 === custody.d930_primary_durability_receipt_sha256)
  if (!supportingReceipt || !same(pick(supportingReceipt, ['d930_operational_profile_record_digest_sha256', 'artifact', 'copy_code', 'backend_code', 'backend_reference']), pick(custody, ['d930_operational_profile_record_digest_sha256', 'artifact', 'copy_code', 'backend_code', 'backend_reference']))) fail('PROJECTION_CUSTODY_REJECTED')
  if (custody.artifact.hash_algorithm_code !== 'sha256' || custody.backend_reference !== `objects/sha256/${custody.artifact.sha256.slice(0, 2)}/${custody.artifact.sha256}`) fail('PROJECTION_CUSTODY_REJECTED')
  const inventoryHeads = authenticatedHeads && authenticatedHeads.size === requiredNamespaces.d940_composite_snapshot.length ? authenticatedHeads : sourceHeads
  const inventory = [...inventoryHeads.values()].map((record) => pick(record, ['source_namespace_code', 'head_sequence', 'inventory_digest_sha256'])).sort((a, b) => a.source_namespace_code < b.source_namespace_code ? -1 : 1)
  if (!same(inventory.map((record) => record.source_namespace_code), requiredNamespaces.d940_composite_snapshot)) fail('PROJECTION_INVENTORY_REJECTED')
  return new Map([
    ['control_head_projection_sha256', canonicalSha256(control)],
    ['source_access_inventory_sha256', sourceAccessHash],
    ['access_head_projection_sha256', canonicalSha256(shutdown)],
    ['accepted_receipt_prefix_sha256', canonicalSha256(acceptedReceipts)],
    ['accepted_logical_state_sha256', canonicalSha256(logical)],
    ['subject_lineage_projection_sha256', canonicalSha256(lineage)],
    ['primary_receipt_prefix_sha256', canonicalSha256(primaryReceipts)],
    ['custody_leaf_projection_sha256', canonicalSha256(custody)],
    ['inventory_snapshot_sha256', canonicalSha256(inventory)],
  ])
}

function validateProjection(response, observations) {
  const projection = response.projection
  if (response.result_code === 'resolved') {
    if (!projection || response.error_code !== null || projection.projection_kind_code !== response.resolver_kind_code) fail('RESULT_PROJECTION_MISMATCH')
  } else if (projection !== null || response.error_code === null) fail('RESULT_PROJECTION_MISMATCH')
  if (!projection) return
  if (projectionDigest(projection) !== projection.projection_sha256) fail('DIGEST_MISMATCH')
  const authenticatedHeads = new Map([...observations].map(([namespace, observation]) => [namespace, observation.after]))
  const computedOutputs = deriveProjectionOutputs(syntheticSourceState, authenticatedHeads)
  if (response.resolver_kind_code === 'd901_control_access') {
    const head = observations.get('d940.global.control-journal.v1').after
    if (projection.known_through_receipt_sequence !== head.head_sequence || projection.known_through_persisted_at !== head.head_persisted_at || projection.control_ledger_head_receipt_digest_sha256 !== head.head_digest_sha256) fail('PROJECTION_SOURCE_MISMATCH')
    for (const field of ['control_head_projection_sha256', 'access_head_projection_sha256']) if (projection[field] !== computedOutputs.get(field)) fail('PROJECTION_SOURCE_MISMATCH', field)
  }
  if (response.resolver_kind_code === 'd920_accepted_evidence') {
    if (projection.known_through_bundle_sequence !== observations.get('d920.accepted-evidence.v1').after.head_sequence) fail('PROJECTION_SOURCE_MISMATCH')
    for (const field of ['accepted_receipt_prefix_sha256', 'accepted_logical_state_sha256', 'subject_lineage_projection_sha256']) if (projection[field] !== computedOutputs.get(field)) fail('PROJECTION_SOURCE_MISMATCH', `${field}: ${projection[field]} != ${computedOutputs.get(field)}`)
  }
  if (response.resolver_kind_code === 'd930_custody') {
    const head = observations.get('d930.custody-journal.v1').after
    if (projection.known_through_journal_sequence !== head.head_sequence || projection.known_through_journal_persisted_at !== head.head_persisted_at || projection.custody_journal_head_digest_sha256 !== head.head_digest_sha256) fail('PROJECTION_SOURCE_MISMATCH')
    for (const field of ['primary_receipt_prefix_sha256', 'custody_leaf_projection_sha256']) if (projection[field] !== computedOutputs.get(field)) fail('PROJECTION_SOURCE_MISMATCH', field)
  }
}

function validateResponse(response, request, baseline = null) {
  validateSchema(response)
  if (response.resolver_kind_code !== request.resolver_kind_code) fail('REQUEST_BINDING_MISMATCH')
  const route = routeRules[response.resolver_kind_code]
  if (response.sender.runtime_role_code !== route[2] || response.recipient.runtime_role_code !== route[3]) fail('ROLE_ROUTE_REJECTED')
  validateIdentity(response.sender, response.runtime_generation, response.responded_at)
  validateIdentity(response.recipient, response.runtime_generation, response.responded_at)
  if (!same(response.sender, request.recipient) || !same(response.recipient, request.sender)) fail('RESPONSE_PEER_MISMATCH')
  if (response.request_record_digest_sha256 !== request.record_digest_sha256 || response.idempotency_key_sha256 !== request.idempotency_key_sha256) fail('REQUEST_BINDING_MISMATCH')
  for (const key of ['operation_id', 'operation_nonce']) if (response[key] !== request[key]) fail('CONTEXT_MISMATCH')
  for (const key of ['runtime_generation', 'subject']) if (!same(response[key], request[key])) fail('CONTEXT_MISMATCH')
  if (ms(response.observed_at) < ms(request.requested_at) || ms(response.responded_at) < ms(response.observed_at) || ms(response.responded_at) > ms(request.expires_at)) fail('RESPONSE_STALE')
  if (ms(response.append_revalidate_by) - ms(response.responded_at) !== 1000) fail('APPEND_REVALIDATION_WINDOW_REJECTED')
  if (response.result_code === 'resolved' ? response.projection === null || response.error_code !== null : response.projection !== null || response.error_code === null) fail('RESULT_PROJECTION_MISMATCH')
  if (response.result_code !== 'resolved' && !resultErrors.get(response.result_code)?.has(response.error_code)) fail('RESULT_ERROR_MISMATCH')
  if (response.error_code === 'global_snapshot_unprovable' && response.resolver_kind_code !== 'd940_composite_snapshot') fail('RESULT_ERROR_MISMATCH')
  const observations = validateStableSources(response, request)
  validateProjection(response, observations)
  if (response.technical_evidence_only !== true || response.authority_granted !== false) fail('AUTHORITY_BOUNDARY_REJECTED')
  if (recordDigest(response) !== response.record_digest_sha256) fail('DIGEST_MISMATCH')
  if (baseline && (response.request_record_digest_sha256 === baseline.request_record_digest_sha256 || response.idempotency_key_sha256 === baseline.idempotency_key_sha256) && !same(response, baseline)) fail('REPLAY_COLLISION')
  return response
}

function validateComposite(request, response, sourceResponses, sourceRequests) {
  validateRequest(request)
  validateResponse(response, request)
  const orderedKinds = ['d901_control_access', 'd920_accepted_evidence', 'd930_custody']
  if (!same(sourceResponses.map((item) => item.resolver_kind_code), orderedKinds)) fail('ORDERING_REJECTED')
  if (!same(sourceRequests.map((item) => item.resolver_kind_code), orderedKinds)) fail('ORDERING_REJECTED')
  if (!same(request.input_response_record_digests, sourceResponses.map((item) => item.record_digest_sha256))) fail('COMPOSITE_INPUT_REJECTED')
  for (let index = 0; index < sourceResponses.length; index += 1) {
    const source = sourceResponses[index]
    const sourceRequest = sourceRequests[index]
    validateRequest(sourceRequest)
    validateResponse(source, sourceRequest)
    if (source.operation_id !== request.operation_id || source.operation_nonce !== request.operation_nonce || sourceRequest.operation_id !== request.operation_id || sourceRequest.operation_nonce !== request.operation_nonce) fail('MIXED_OPERATION')
    if (!same(source.runtime_generation, request.runtime_generation)) fail('MIXED_GENERATION')
    if (!same(source.subject, request.subject)) fail('MIXED_SUBJECT')
    if (ms(request.requested_at) < ms(source.responded_at) || ms(request.requested_at) > ms(source.append_revalidate_by)) fail('SOURCE_RESPONSE_STALE')
  }
  const sourceFinalHeads = new Map()
  for (const source of sourceResponses) {
    for (const observation of source.source_observations) {
      if (!observation.after) continue
      const prior = sourceFinalHeads.get(observation.source_namespace_code)
      if (prior && !same(prior, observation.after)) fail('MIXED_SOURCE_HEAD')
      sourceFinalHeads.set(observation.source_namespace_code, observation.after)
    }
  }
  const compositeAnchors = sourceMap(request.prior_accepted_source_heads, 'composite source heads')
  for (const [namespace, head] of sourceFinalHeads) if (!same(compositeAnchors.get(namespace), head)) fail('COMPOSITE_SOURCE_HEAD_MISMATCH')
  const allObservations = [...sourceResponses.flatMap((item) => item.source_observations), ...response.source_observations]
  const windowStart = Math.min(...allObservations.map((item) => ms(item.observed_before_at)))
  const windowEnd = Math.max(...allObservations.map((item) => ms(item.observed_after_at)))
  const allSourcesResolved = sourceResponses.every((item) => item.result_code === 'resolved' && item.projection)
  if (response.result_code !== 'resolved') {
    if (!allSourcesResolved) {
      const firstFailureIndex = sourceResponses.findIndex((item) => item.result_code !== 'resolved')
      const sourceFailure = sourceResponses[firstFailureIndex]
      if (response.result_code !== sourceFailure.result_code || response.error_code !== sourceFailure.error_code) fail('COMPOSITE_FAILURE_MISMATCH')
      const sourceFailureObservation = sourceFailure.source_observations.find((item) => item.stability_code !== 'stable' || !item.after) ?? (sourceFailure.error_code === 'source_contradictory' ? sourceFailure.source_observations[0] : null)
      const failedNamespace = sourceFailureObservation?.source_namespace_code
      const compositeObservation = response.source_observations.find((item) => item.source_namespace_code === failedNamespace)
      if (!failedNamespace || !compositeObservation || compositeObservation.stability_code !== sourceFailureObservation.stability_code || !same(compositeObservation.before, sourceFailureObservation.before) || !same(compositeObservation.after, sourceFailureObservation.after)) fail('COMPOSITE_FAILURE_MISMATCH')
      return
    }
    if (response.error_code === 'global_snapshot_unprovable' && windowEnd - windowStart > 1000) return
    fail('COMPOSITE_NONSUCCESS_UNJUSTIFIED')
  }
  if (!allSourcesResolved) fail('COMPOSITE_INPUT_UNRESOLVED')
  const [control, evidence, custody] = sourceResponses.map((item) => item.projection)
  const compositeHeadMap = new Map(response.source_observations.map((observation) => [observation.source_namespace_code, observation.after]))
  const compositeOutputs = deriveProjectionOutputs(syntheticSourceState, compositeHeadMap)
  const snapshot = response.projection.snapshot
  const expectedSnapshot = {
    journal_namespace_code: control.journal_namespace_code,
    known_through_receipt_sequence: control.known_through_receipt_sequence,
    known_through_persisted_at: control.known_through_persisted_at,
    control_ledger_head_receipt_digest_sha256: control.control_ledger_head_receipt_digest_sha256,
    control_head_projection_sha256: control.control_head_projection_sha256,
    access_head_projection_sha256: control.access_head_projection_sha256,
    subject_lineage_projection_sha256: evidence.subject_lineage_projection_sha256,
    inventory_snapshot_sha256: compositeOutputs.get('inventory_snapshot_sha256'),
    custody_leaf_projection_sha256: custody.custody_leaf_projection_sha256,
  }
  if (!same(snapshot, expectedSnapshot)) fail('COMPOSITE_SNAPSHOT_MISMATCH')
  if (response.projection.snapshot_digest_sha256 !== canonicalSha256(snapshot)) fail('DIGEST_MISMATCH')
  if (!same(response.projection.source_response_record_digests, request.input_response_record_digests)) fail('COMPOSITE_INPUT_REJECTED')
  if (windowEnd - windowStart > 1000) fail('GLOBAL_SNAPSHOT_UNPROVABLE')
}

function validateAppendAttestation(attestation, compositeResponse, baseline = null) {
  validateSchema(attestation)
  validateIdentity(attestation.sender, attestation.runtime_generation, attestation.completed_at)
  validateIdentity(attestation.recipient, attestation.runtime_generation, attestation.completed_at)
  if (attestation.sender.runtime_role_code !== 'independent_verifier' || attestation.recipient.runtime_role_code !== 'journal_broker') fail('ROLE_ROUTE_REJECTED')
  if (attestation.composite_response_record_digest_sha256 !== compositeResponse.record_digest_sha256) fail('REQUEST_BINDING_MISMATCH')
  for (const key of ['operation_id', 'operation_nonce']) if (attestation[key] !== compositeResponse[key]) fail('CONTEXT_MISMATCH')
  for (const key of ['runtime_generation', 'subject']) if (!same(attestation[key], compositeResponse[key])) fail('CONTEXT_MISMATCH')
  if (ms(attestation.observed_at) < ms(compositeResponse.responded_at) || ms(attestation.completed_at) < ms(attestation.observed_at) || ms(attestation.completed_at) > ms(compositeResponse.append_revalidate_by)) fail('APPEND_REVALIDATION_WINDOW_REJECTED')
  const expectedHeads = sourceMap(compositeResponse.source_observations, 'composite observations')
  const observedHeads = sourceMap(attestation.source_heads, 'append heads')
  if (!sortedUnique([...observedHeads.keys()]) || !same([...observedHeads.keys()], requiredNamespaces.d940_composite_snapshot)) fail('ORDERING_REJECTED')
  const exact = [...expectedHeads].every(([namespace, observation]) => observation.after && same(observation.after, observedHeads.get(namespace)))
  if (attestation.result_code === 'revalidated') {
    if (attestation.error_code !== null || !exact) fail('APPEND_REVALIDATION_FAILED')
  } else if (attestation.error_code !== 'append_revalidation_failed' || exact) fail('APPEND_REVALIDATION_FAILED')
  if (attestation.technical_evidence_only !== true || attestation.authority_granted !== false) fail('AUTHORITY_BOUNDARY_REJECTED')
  if (recordDigest(attestation) !== attestation.record_digest_sha256) fail('DIGEST_MISMATCH')
  if (baseline && attestation.composite_response_record_digest_sha256 === baseline.composite_response_record_digest_sha256 && !same(attestation, baseline)) fail('REPLAY_COLLISION')
}

function reseal(record) {
  if (record.projection) {
    if (record.projection.snapshot) record.projection.snapshot_digest_sha256 = canonicalSha256(record.projection.snapshot)
    record.projection.projection_sha256 = projectionDigest(record.projection)
  }
  if (record.format.endsWith('-request')) {
    record.idempotency_key_sha256 = canonicalSha256(idempotencyPayload(record))
  }
  record.record_digest_sha256 = recordDigest(record)
  return record
}

function setPointer(value, pointer, replacement, operation) {
  const parts = pointer.split('/').slice(1)
  let cursor = value
  for (const part of parts.slice(0, -1)) cursor = cursor[Number.isInteger(Number(part)) && String(Number(part)) === part ? Number(part) : part]
  const key = parts.at(-1)
  if (operation === 'delete') delete cursor[key]
  else if (operation === 'reverse') cursor[key].reverse()
  else cursor[key] = clone(replacement)
}

function fixtureRecord(code) {
  return [...fixture.requests, ...fixture.responses, fixture.composite_request, fixture.composite_response, fixture.append_revalidation_attestation].find((item) => item.request_code === code || item.response_code === code || item.attestation_code === code)
}

function validateAll() {
  assert.equal(rawSha(path.join(root, 'contract-catalog-v1.json')), expected.catalog)
  assert.equal(rawSha(path.join(root, 'classifications-v1.json')), expected.classifications)
  assert.equal(rawSha(path.join(root, 'digest-profiles-v1.json')), expected.digestProfiles)
  assert.equal(rawSha(path.join(root, 'field-source-registry-v1.json')), expected.fieldRegistry)
  assert.equal(rawSha(path.join(root, 'projection-profiles-v1.json')), expected.projectionProfiles)
  assert.equal(rawSha(path.join(root, 'root-inventory-v1.json')), expected.rootInventory)
  assert.equal(catalog.status_code, 'design_only_contract_freeze')
  assert.equal(catalog.authority_code, 'technical_recovery_evidence_only_no_operational_authority')
  assert.equal(classifications.authority_boundary.d95_authority_granted, false)
  assert.equal(projectionProfiles.canonicalization_profile, frozenD940DigestProfiles.canonical_json_profile.profile_code)
  assert.equal(projectionProfiles.frozen_d940_digest_profiles_raw_sha256, rawSha(path.join(here, 'd9-4-0/digest-profiles-v1.json')))
  assert.equal(projectionProfiles.frozen_d940_digest_profiles_record_digest_sha256, frozenD940DigestProfiles.record_digest_sha256)
  const frozenProjectionCodes = new Set([...frozenD940DigestProfiles.projection_profiles, ...frozenD940DigestProfiles.payload_profiles].map((profile) => profile.profile_code))
  for (const profile of projectionProfiles.profiles) if (profile.base_d940_profile_code !== null && !frozenProjectionCodes.has(profile.base_d940_profile_code)) fail('PROJECTION_PROFILE_REFERENCE_REJECTED')
  assert.equal(new Set(projectionProfiles.profiles.map((profile) => profile.output_field)).size, projectionProfiles.profiles.length)
  const executedProfiles = {
    control_head_projection_sha256: { source_payload_code: 'control_records', selected_fields: ['receipt_sequence', 'record_kind_code', 'record_digest_sha256'], source_namespace_codes: ['d940.global.control-journal.v1'] },
    source_access_inventory_sha256: { source_payload_code: 'source_access_state', selected_fields: ['store_snapshot', 'capabilities', 'descriptor_lifecycle_records', 'adapter_message_record_digests'], source_namespace_codes: ['d901.capability-state.v1', 'd901.control-state.v1'] },
    access_head_projection_sha256: { source_payload_code: 'access_shutdown_state', selected_fields: ['source_access_inventory_sha256', 'capability_terminal_record_digests', 'descriptor_leaves'], source_namespace_codes: ['d901.capability-state.v1', 'd901.control-state.v1', 'd930.custody-journal.v1'] },
    accepted_receipt_prefix_sha256: { source_payload_code: 'accepted_receipts', selected_fields: ['bundle_sequence', 'bundle_code', 'receipt_digest_sha256'], source_namespace_codes: ['d920.accepted-evidence.v1'] },
    accepted_logical_state_sha256: { source_payload_code: 'accepted_logical_records', selected_fields: ['table_code', 'stable_key', 'record_digest_sha256'], source_namespace_codes: ['d920.accepted-evidence.v1'] },
    subject_lineage_projection_sha256: { source_payload_code: 'lineage_store', selected_fields: ['target_subject_identity_sha256', 'store_snapshot', 'nodes', 'edges'], source_namespace_codes: ['d920.accepted-evidence.v1'] },
    primary_receipt_prefix_sha256: { source_payload_code: 'primary_receipts', selected_fields: ['receipt_sequence', 'receipt_code', 'receipt_digest_sha256'], source_namespace_codes: ['d930.primary-receipts.v1'] },
    custody_leaf_projection_sha256: { source_payload_code: 'custody_candidates', selected_fields: ['d930_operational_profile_record_digest_sha256', 'd930_primary_durability_receipt_sha256', 'artifact', 'copy_code', 'backend_code', 'backend_reference'], source_namespace_codes: ['d930.custody-journal.v1', 'd930.primary-receipts.v1'] },
    inventory_snapshot_sha256: { source_payload_code: 'authenticated_source_heads', selected_fields: ['source_namespace_code', 'head_sequence', 'inventory_digest_sha256'], source_namespace_codes: requiredNamespaces.d940_composite_snapshot },
  }
  for (const profile of projectionProfiles.profiles) assert.deepEqual({ source_payload_code: profile.source_payload_code, selected_fields: profile.selected_fields, source_namespace_codes: profile.source_namespace_codes }, executedProfiles[profile.output_field])
  const derivedBaseline = deriveProjectionOutputs()
  const reorderedBoundaries = clone(syntheticSourceState); reorderedBoundaries.sources.source_boundaries.reverse()
  assert.deepEqual(deriveProjectionOutputs(reorderedBoundaries), derivedBaseline)
  const reorderedRecords = clone(syntheticSourceState); reorderedRecords.sources.control_records.records.reverse(); reorderedRecords.sources.accepted_receipts.records.reverse(); reorderedRecords.sources.primary_receipts.records.reverse()
  const reorderedOutputs = deriveProjectionOutputs(reorderedRecords)
  for (const [field, digest] of derivedBaseline) if (field !== 'inventory_snapshot_sha256') assert.equal(reorderedOutputs.get(field), digest)
  assert.notEqual(reorderedOutputs.get('inventory_snapshot_sha256'), derivedBaseline.get('inventory_snapshot_sha256'))
  const changedRawSource = clone(syntheticSourceState); changedRawSource.sources.control_records.records[0].record_digest_sha256 = 'f'.repeat(64)
  assert.notEqual(deriveProjectionOutputs(changedRawSource).get('control_head_projection_sha256'), derivedBaseline.get('control_head_projection_sha256'))
  const originalHeads = deriveSyntheticSourceHeads()
  expectCode(() => deriveProjectionOutputs(changedRawSource, originalHeads), 'PROJECTION_SOURCE_BOUNDARY_MISMATCH')
  const gappedRawSource = clone(syntheticSourceState); gappedRawSource.sources.accepted_receipts.records[0].bundle_sequence = 3
  expectCode(() => deriveProjectionOutputs(gappedRawSource), 'PROJECTION_PREFIX_REJECTED')
  const cyclicLineage = clone(syntheticSourceState); cyclicLineage.sources.lineage_store.edges[0].from_subject_identity_sha256 = cyclicLineage.sources.lineage_store.edges[0].to_subject_identity_sha256
  expectCode(() => deriveProjectionOutputs(cyclicLineage), 'PROJECTION_LINEAGE_REJECTED')
  const multiNodeCycle = clone(syntheticSourceState); multiNodeCycle.sources.lineage_store.edges.push({ from_subject_identity_sha256: multiNodeCycle.subject_identity_sha256, to_subject_identity_sha256: multiNodeCycle.sources.lineage_store.nodes[1].subject_identity_sha256 }); multiNodeCycle.sources.lineage_store.store_snapshot.edge_count += 1; multiNodeCycle.sources.lineage_store.edges.sort((a, b) => `${a.from_subject_identity_sha256}\0${a.to_subject_identity_sha256}` < `${b.from_subject_identity_sha256}\0${b.to_subject_identity_sha256}` ? -1 : 1); multiNodeCycle.sources.lineage_store.store_snapshot.edge_store_head_sha256 = canonicalSha256(multiNodeCycle.sources.lineage_store.edges)
  expectCode(() => deriveProjectionOutputs(multiNodeCycle), 'PROJECTION_LINEAGE_REJECTED')
  const unrelatedLineageNode = clone(syntheticSourceState); unrelatedLineageNode.sources.lineage_store.nodes.push({ subject_identity_sha256: '4f'.repeat(32), subject_kind_code: 'unrelated' }); unrelatedLineageNode.sources.lineage_store.store_snapshot.node_count += 1; unrelatedLineageNode.sources.lineage_store.nodes.sort((a, b) => a.subject_identity_sha256 < b.subject_identity_sha256 ? -1 : 1); unrelatedLineageNode.sources.lineage_store.store_snapshot.node_store_head_sha256 = canonicalSha256(unrelatedLineageNode.sources.lineage_store.nodes)
  expectCode(() => deriveProjectionOutputs(unrelatedLineageNode), 'PROJECTION_LINEAGE_REJECTED')
  const incompleteShutdown = clone(syntheticSourceState); incompleteShutdown.sources.access_shutdown_state.capability_terminal_records = []
  expectCode(() => deriveProjectionOutputs(incompleteShutdown), 'PROJECTION_COMPLETENESS_REJECTED')
  const duplicateLineageNode = clone(syntheticSourceState); duplicateLineageNode.sources.lineage_store.nodes.push(clone(duplicateLineageNode.sources.lineage_store.nodes[0])); duplicateLineageNode.sources.lineage_store.store_snapshot.node_count += 1
  expectCode(() => deriveProjectionOutputs(duplicateLineageNode), 'PROJECTION_LINEAGE_REJECTED')
  const extraTerminal = clone(syntheticSourceState); extraTerminal.sources.access_shutdown_state.capability_terminal_records.push({ capability_record_digest_sha256: '4e'.repeat(32), terminal_record_digest_sha256: '4d'.repeat(32), terminal_state_code: 'revoked' })
  expectCode(() => deriveProjectionOutputs(extraTerminal), 'PROJECTION_COMPLETENESS_REJECTED')
  const wrongDescriptorLeaf = clone(syntheticSourceState); wrongDescriptorLeaf.sources.access_shutdown_state.descriptor_leaves[0].descriptor_lifecycle_record_digest_sha256 = '4c'.repeat(32)
  expectCode(() => deriveProjectionOutputs(wrongDescriptorLeaf), 'PROJECTION_COMPLETENESS_REJECTED')
  const receiptMismatch = clone(syntheticSourceState); receiptMismatch.sources.custody_candidates.records[0].backend_code = 'substituted'
  expectCode(() => deriveProjectionOutputs(receiptMismatch), 'PROJECTION_CUSTODY_REJECTED')
  const ambiguousCustody = clone(syntheticSourceState); ambiguousCustody.sources.custody_candidates.records.push(clone(ambiguousCustody.sources.custody_candidates.records[0]))
  expectCode(() => deriveProjectionOutputs(ambiguousCustody), 'PROJECTION_CUSTODY_REJECTED')
  for (const rule of classifications.resolver_rules) {
    assert.deepEqual(routeRules[rule.resolver_kind_code], [rule.request_sender_role_code, rule.request_recipient_role_code, rule.response_sender_role_code, rule.response_recipient_role_code])
    assert.deepEqual(requiredNamespaces[rule.resolver_kind_code], rule.required_source_namespaces)
  }

  const actualInventory = []
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) walk(absolute)
      else if (entry.isFile()) {
        const relative = path.relative(root, absolute).split(path.sep).join('/')
        if (relative !== 'root-inventory-v1.json') actualInventory.push({ path: relative, raw_sha256: rawSha(absolute) })
      } else fail('SPECIAL_FILE_REJECTED')
    }
  }
  walk(root); actualInventory.sort((a, b) => a.path < b.path ? -1 : 1)
  assert.deepEqual(actualInventory, inventory.files)
  for (const item of catalog.schemas) assert.equal(rawSha(path.join(root, item.schema_file)), item.raw_sha256)
  for (const item of [...catalog.registries, ...catalog.fixtures]) assert.equal(rawSha(path.join(root, item.file)), item.raw_sha256)

  for (const [file, digest] of Object.entries(frozenMigrations)) assert.equal(rawSha(path.join(migrationsRoot, file)), digest)
  for (const [relative, digest] of Object.entries(frozenRoots)) assert.equal(rawSha(path.join(project, relative)), digest)
  for (const commit of approvedCommits) execFileSync('git', ['cat-file', '-e', `${commit}^{commit}`], { cwd: project })
  const projectionSources = [
    ['d91', catalog.approved_dependencies.d91_implementation_commit, catalog.approved_dependencies.d91_control_state_projection_path, catalog.approved_dependencies.d91_control_state_projection_sha256],
    ['d92', catalog.approved_dependencies.d92_implementation_commit, catalog.approved_dependencies.d92_accepted_state_projection_path, catalog.approved_dependencies.d92_accepted_state_projection_sha256],
    ['d931', catalog.approved_dependencies.d931_implementation_commit, catalog.approved_dependencies.d931_custody_journal_projection_path, catalog.approved_dependencies.d931_custody_journal_projection_sha256],
  ]
  for (const [, commit, file, digest] of projectionSources) assert.equal(sha256Bytes(execFileSync('git', ['show', `${commit}:${file}`], { cwd: project })), digest)

  const requestMap = new Map()
  for (const request of fixture.requests) { validateRequest(request); requestMap.set(request.resolver_kind_code, request) }
  const responseMap = new Map()
  for (const response of fixture.responses) { validateResponse(response, requestMap.get(response.resolver_kind_code)); responseMap.set(response.resolver_kind_code, response) }
  const orderedSourceRequests = ['d901_control_access', 'd920_accepted_evidence', 'd930_custody'].map((kind) => requestMap.get(kind))
  const orderedSourceResponses = ['d901_control_access', 'd920_accepted_evidence', 'd930_custody'].map((kind) => responseMap.get(kind))
  validateComposite(fixture.composite_request, fixture.composite_response, orderedSourceResponses, orderedSourceRequests)
  validateAppendAttestation(fixture.append_revalidation_attestation, fixture.composite_response)

  for (const vector of golden.vectors.filter((item) => item.canonical_utf8)) {
    const parsed = JSON.parse(vector.canonical_utf8)
    assert.equal(canonicalize(parsed), vector.canonical_utf8)
    assert.equal(crypto.createHash('sha256').update(vector.canonical_utf8).digest('hex'), vector.sha256)
  }
  const complete = canonicalize(fixture.composite_response)
  const fullGolden = golden.vectors.find((item) => item.vector_code === 'complete-composite-response-fixed')
  assert.equal(Buffer.byteLength(complete), fullGolden.canonical_utf8_byte_length)
  assert.equal(crypto.createHash('sha256').update(complete).digest('hex'), fullGolden.canonical_sha256)
  assert.equal(fixture.composite_response.record_digest_sha256, fullGolden.record_digest_sha256)
  assert.equal(fixture.composite_response.projection.projection_sha256, fullGolden.projection_sha256)
  assert.equal(fixture.composite_response.projection.snapshot_digest_sha256, fullGolden.snapshot_digest_sha256)
  assert.throws(() => parseStrictJson(Buffer.from('{"a":1,"a":2}')), /duplicate/i)
  assert.throws(() => canonicalize({ unsafe: Number.MAX_SAFE_INTEGER + 1 }))
  for (const record of [...fixture.requests, ...fixture.responses, fixture.composite_request, fixture.composite_response, fixture.append_revalidation_attestation]) {
    const code = record.request_code ?? record.response_code ?? record.attestation_code
    assert.equal(record.record_digest_sha256, golden.fixed_record_digests[code])
  }

  // Direct mutations exercise every trust-boundary class, independent of schema-only checks.
  const baselineRequest = fixture.requests[0]
  for (const mutation of invalid.mutations) {
    const original = fixtureRecord(mutation.target_code)
    const mutated = clone(original)
    setPointer(mutated, mutation.pointer, mutation.value, mutation.operation)
    if (['future-head', 'rollback', 'fork'].includes(mutation.case_code)) mutated.source_observations[0].after = clone(mutated.source_observations[0].before)
    if (mutation.operation !== 'delete') reseal(mutated)
    const isRequest = mutated.format.endsWith('-request')
    const request = isRequest ? mutated : (mutated.resolver_kind_code === 'd940_composite_snapshot' ? fixture.composite_request : requestMap.get(mutated.resolver_kind_code))
    expectCode(() => {
      if (isRequest) validateRequest(mutated, baselineRequest)
      else if (mutated.resolver_kind_code === 'd940_composite_snapshot') validateComposite(request, mutated, orderedSourceResponses, orderedSourceRequests)
      else validateResponse(mutated, request, original)
    }, mutation.expected_error_code)
  }

  const unavailable = clone(fixture.responses[1])
  unavailable.result_code = 'unavailable'; unavailable.error_code = 'source_unavailable'; unavailable.projection = null
  unavailable.source_observations[0].stability_code = 'unavailable'; unavailable.source_observations[0].after = null
  reseal(unavailable); validateResponse(unavailable, fixture.requests[1])

  const multiSourceUnavailable = clone(fixture.responses[0])
  multiSourceUnavailable.result_code = 'unavailable'; multiSourceUnavailable.error_code = 'source_unavailable'; multiSourceUnavailable.projection = null
  multiSourceUnavailable.source_observations[0].stability_code = 'unavailable'; multiSourceUnavailable.source_observations[0].after = null
  reseal(multiSourceUnavailable); validateResponse(multiSourceUnavailable, fixture.requests[0])
  const stableContradiction = clone(fixture.responses[0]); stableContradiction.result_code = 'ambiguous'; stableContradiction.error_code = 'source_contradictory'; stableContradiction.projection = null; reseal(stableContradiction)
  validateResponse(stableContradiction, fixture.requests[0])
  const invalidConstituentGlobal = clone(fixture.responses[0]); invalidConstituentGlobal.result_code = 'reconciliation_required'; invalidConstituentGlobal.error_code = 'global_snapshot_unprovable'; invalidConstituentGlobal.projection = null; reseal(invalidConstituentGlobal)
  expectCode(() => validateResponse(invalidConstituentGlobal, fixture.requests[0]), 'RESULT_ERROR_MISMATCH')

  const failedConstituents = clone(fixture.responses)
  failedConstituents[1].result_code = 'unavailable'; failedConstituents[1].error_code = 'source_unavailable'; failedConstituents[1].projection = null
  failedConstituents[1].source_observations[0].stability_code = 'unavailable'; failedConstituents[1].source_observations[0].after = null; reseal(failedConstituents[1])
  const failureCompositeRequest = clone(fixture.composite_request); failureCompositeRequest.input_response_record_digests = failedConstituents.map((item) => item.record_digest_sha256); reseal(failureCompositeRequest)
  const failureCompositeResponse = clone(fixture.composite_response); failureCompositeResponse.request_record_digest_sha256 = failureCompositeRequest.record_digest_sha256; failureCompositeResponse.idempotency_key_sha256 = failureCompositeRequest.idempotency_key_sha256; failureCompositeResponse.result_code = 'unavailable'; failureCompositeResponse.error_code = 'source_unavailable'; failureCompositeResponse.projection = null
  failureCompositeResponse.source_observations = failureCompositeResponse.source_observations.map((item) => item.source_namespace_code === 'd920.accepted-evidence.v1' ? { ...item, stability_code: 'unavailable', after: null } : item); reseal(failureCompositeResponse)
  validateComposite(failureCompositeRequest, failureCompositeResponse, failedConstituents, fixture.requests)
  const unrelatedCompositeFailure = clone(failureCompositeResponse); unrelatedCompositeFailure.result_code = 'ambiguous'; unrelatedCompositeFailure.error_code = 'source_head_moved'; reseal(unrelatedCompositeFailure)
  expectCode(() => validateComposite(failureCompositeRequest, unrelatedCompositeFailure, failedConstituents, fixture.requests), 'COMPOSITE_FAILURE_MISMATCH')

  const contradictoryConstituents = clone(fixture.responses); contradictoryConstituents[0] = stableContradiction
  const contradictionCompositeRequest = clone(fixture.composite_request); contradictionCompositeRequest.input_response_record_digests = contradictoryConstituents.map((item) => item.record_digest_sha256); reseal(contradictionCompositeRequest)
  const contradictionCompositeResponse = clone(fixture.composite_response); contradictionCompositeResponse.request_record_digest_sha256 = contradictionCompositeRequest.record_digest_sha256; contradictionCompositeResponse.idempotency_key_sha256 = contradictionCompositeRequest.idempotency_key_sha256; contradictionCompositeResponse.result_code = 'ambiguous'; contradictionCompositeResponse.error_code = 'source_contradictory'; contradictionCompositeResponse.projection = null; reseal(contradictionCompositeResponse)
  validateComposite(contradictionCompositeRequest, contradictionCompositeResponse, contradictoryConstituents, fixture.requests)

  const replayRequest = clone(fixture.requests[0]); replayRequest.expires_at = '2030-01-01T00:10:04.999Z'; reseal(replayRequest)
  expectCode(() => validateRequest(replayRequest, fixture.requests[0]), 'REPLAY_COLLISION')
  const replayResponse = clone(fixture.responses[2]); replayResponse.response_code = 'response.custody.changed'; reseal(replayResponse)
  expectCode(() => validateResponse(replayResponse, fixture.requests[2], fixture.responses[2]), 'REPLAY_COLLISION')

  const peerSubstitution = clone(fixture.responses[1]); peerSubstitution.sender.binding_code = 'binding.substituted'; reseal(peerSubstitution)
  expectCode(() => validateResponse(peerSubstitution, fixture.requests[1]), 'IDENTITY_BINDING_REJECTED')
  const mixedOperationResponses = clone(fixture.responses); mixedOperationResponses[1].operation_id = 'operation.other'; reseal(mixedOperationResponses[1])
  const mixedOperationRequest = clone(fixture.composite_request); mixedOperationRequest.input_response_record_digests = mixedOperationResponses.map((item) => item.record_digest_sha256); reseal(mixedOperationRequest)
  const mixedOperationComposite = clone(fixture.composite_response); mixedOperationComposite.request_record_digest_sha256 = mixedOperationRequest.record_digest_sha256; mixedOperationComposite.idempotency_key_sha256 = mixedOperationRequest.idempotency_key_sha256; mixedOperationComposite.projection.source_response_record_digests = [...mixedOperationRequest.input_response_record_digests]; reseal(mixedOperationComposite)
  expectCode(() => validateComposite(mixedOperationRequest, mixedOperationComposite, mixedOperationResponses, fixture.requests), 'CONTEXT_MISMATCH')
  const advancedComposite = clone(fixture.composite_response); advancedComposite.source_observations[0].before.head_sequence += 1; advancedComposite.source_observations[0].after = clone(advancedComposite.source_observations[0].before); reseal(advancedComposite)
  expectCode(() => validateComposite(fixture.composite_request, advancedComposite, fixture.responses, fixture.requests), 'SOURCE_HEAD_UNSTABLE')
  const lateObservation = clone(fixture.responses[0]); lateObservation.source_observations[0].observed_before_at = '2030-01-01T00:10:00.050Z'; reseal(lateObservation)
  expectCode(() => validateResponse(lateObservation, fixture.requests[0]), 'OBSERVATION_TIME_REJECTED')
  const inventoryFork = clone(fixture.responses[1]); inventoryFork.source_observations[0].before.inventory_digest_sha256 = 'f'.repeat(64); inventoryFork.source_observations[0].after = clone(inventoryFork.source_observations[0].before); reseal(inventoryFork)
  expectCode(() => validateResponse(inventoryFork, fixture.requests[1]), 'SOURCE_HEAD_UNSTABLE')
  const tamperedSource = clone(fixture.responses); tamperedSource[1].projection.subject_lineage_projection_sha256 = 'f'.repeat(64); reseal(tamperedSource[1])
  expectCode(() => validateResponse(tamperedSource[1], fixture.requests[1]), 'PROJECTION_SOURCE_MISMATCH')
  expectCode(() => validateComposite(fixture.composite_request, fixture.composite_response, tamperedSource, fixture.requests), 'COMPOSITE_INPUT_REJECTED')
  const failedAppend = clone(fixture.append_revalidation_attestation); failedAppend.source_heads[0].head_digest_sha256 = 'f'.repeat(64); failedAppend.result_code = 'failed'; failedAppend.error_code = 'append_revalidation_failed'; reseal(failedAppend)
  validateAppendAttestation(failedAppend, fixture.composite_response)
  const falseAppend = clone(fixture.append_revalidation_attestation); falseAppend.source_heads[0].head_digest_sha256 = 'f'.repeat(64); reseal(falseAppend)
  expectCode(() => validateAppendAttestation(falseAppend, fixture.composite_response), 'APPEND_REVALIDATION_FAILED')
  const appendReplay = clone(fixture.append_revalidation_attestation); appendReplay.attestation_code = 'attestation.composite.changed'; reseal(appendReplay)
  expectCode(() => validateAppendAttestation(appendReplay, fixture.composite_response, fixture.append_revalidation_attestation), 'REPLAY_COLLISION')
  const wideWindowComposite = clone(fixture.composite_response); wideWindowComposite.responded_at = '2030-01-01T00:10:01.300Z'; wideWindowComposite.append_revalidate_by = '2030-01-01T00:10:02.300Z'; for (const observation of wideWindowComposite.source_observations) observation.observed_after_at = '2030-01-01T00:10:01.200Z'; reseal(wideWindowComposite)
  expectCode(() => validateComposite(fixture.composite_request, wideWindowComposite, fixture.responses, fixture.requests), 'GLOBAL_SNAPSHOT_UNPROVABLE')
  wideWindowComposite.result_code = 'reconciliation_required'; wideWindowComposite.error_code = 'global_snapshot_unprovable'; wideWindowComposite.projection = null; reseal(wideWindowComposite)
  validateComposite(fixture.composite_request, wideWindowComposite, fixture.responses, fixture.requests)
  const staleDigestSource = clone(fixture.responses); staleDigestSource[1].projection.subject_lineage_projection_sha256 = 'f'.repeat(64)
  const staleDigestRequest = clone(fixture.composite_request); staleDigestRequest.input_response_record_digests = staleDigestSource.map((item) => item.record_digest_sha256); reseal(staleDigestRequest)
  expectCode(() => validateComposite(staleDigestRequest, fixture.composite_response, staleDigestSource, fixture.requests), 'DIGEST_MISMATCH')

  const mixed = clone(fixture.composite_request); mixed.runtime_generation.binding_generation = 2; reseal(mixed)
  expectCode(() => validateComposite(mixed, fixture.composite_response, fixture.responses, fixture.requests), 'IDENTITY_GENERATION_REJECTED')
  const mixedInventoryComposite = clone(fixture.composite_response); mixedInventoryComposite.projection.snapshot.inventory_snapshot_sha256 = 'f'.repeat(64); reseal(mixedInventoryComposite)
  expectCode(() => validateComposite(fixture.composite_request, mixedInventoryComposite, fixture.responses, fixture.requests), 'COMPOSITE_SNAPSHOT_MISMATCH')
  const substitutedProfile = clone(fixture.requests[1]); substitutedProfile.prior_accepted_source_heads[0].source_contract_fingerprint_sha256 = 'f'.repeat(64); substitutedProfile.source_contract_fingerprints = ['f'.repeat(64)]; reseal(substitutedProfile)
  expectCode(() => validateRequest(substitutedProfile), 'SOURCE_PROFILE_SUBSTITUTED')
  const prefixDrift = clone(fixture.responses[1]); prefixDrift.projection.accepted_receipt_prefix_sha256 = 'f'.repeat(64); reseal(prefixDrift)
  expectCode(() => validateResponse(prefixDrift, fixture.requests[1], fixture.responses[1]), 'PROJECTION_SOURCE_MISMATCH')
  const changedAtAppend = clone(fixture.composite_response); changedAtAppend.source_observations[0].after.head_digest_sha256 = 'f'.repeat(64); changedAtAppend.source_observations[0].stability_code = 'moved'; reseal(changedAtAppend)
  expectCode(() => validateComposite(fixture.composite_request, changedAtAppend, fixture.responses, fixture.requests), 'SOURCE_HEAD_UNSTABLE')

  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-recovery-contract-'))
  try {
    const databasePath = path.join(temporary, 'atlas.sqlite')
    applyMigrations({ databasePath, migrationsDirectory: migrationsRoot })
    const database = new DatabaseSync(databasePath)
    database.exec('PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON;')
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
    assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
    for (const table of atlasTables) assert.equal(database.prepare(`SELECT count(*) AS count FROM ${table}`).get().count, 0)
    database.close()
  } finally { fs.rmSync(temporary, { recursive: true, force: true }) }

  return {
    records: 9,
    invalidMutations: invalid.mutations.length + 32,
    schemas: 4,
    registries: 4,
    rootFiles: inventory.files.length + 1,
  }
}

const result = validateAll()
console.log(`D9 recovery-projection resolver contracts validated: ${result.records} records, ${result.invalidMutations} adversarial cases, ${result.schemas} schemas, ${result.registries} registries, ${result.rootFiles} root files.`)
