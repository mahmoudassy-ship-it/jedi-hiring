import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import { canonicalSha256, canonicalize, parseStrictJson, sha256Bytes } from '../control-plane/canonical.mjs'
import { assertD941LedgerBroker } from './ledger.mjs'
import { assertD941SyntheticCustodyEvidence } from './custody-evidence.mjs'
import { assertD941AuthorityRegistry } from './authority.mjs'
import { failD941 } from './errors.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const contractRoot = path.resolve(here, '../../docs/schema/d9-recovery-resolvers')
const expectedFingerprints = Object.freeze({
  'contract-catalog-v1.json': 'df33cbf575f8f4b430ef22384f0d73350e521abed6443f07006d13bb3b968ba3',
  'classifications-v1.json': '9f137c1ca9905b5a02754292a1b828bbdd7174af78bd385b3b4a3584fd1abe04',
  'digest-profiles-v1.json': 'b7adfc736b04ef5c657e94bf2a621a602e518165cbf9b08f2b3c0653963abf90',
  'field-source-registry-v1.json': 'd6f9ec22ae8fdb6bbb998374680f13a89f02ffef2431d9eb8c6003294a3db1d8',
  'projection-profiles-v1.json': 'c9c7a09c4a29814b1a6b55112e9b11075f1e1cc654e393561e6e3d79ad1ae6ff',
  'root-inventory-v1.json': '93832dc8a6f12ae030515781169fd8ac9dd5431aa68f62699168469da3da6f31',
  'fixtures/synthetic-source-state-v1.json': '5f70546d53327940af8fd27f347745d2c8177ba3c194a9cf36397e564a6b75a4',
})

const namespaces = Object.freeze([
  'd901.capability-state.v1',
  'd901.control-state.v1',
  'd920.accepted-evidence.v1',
  'd930.custody-journal.v1',
  'd930.primary-receipts.v1',
  'd940.global.control-journal.v1',
])
const namespaceSets = Object.freeze({
  d901_control_access: Object.freeze(['d901.capability-state.v1', 'd901.control-state.v1', 'd930.custody-journal.v1', 'd940.global.control-journal.v1']),
  d920_accepted_evidence: Object.freeze(['d920.accepted-evidence.v1']),
  d930_custody: Object.freeze(['d930.custody-journal.v1', 'd930.primary-receipts.v1']),
  d940_composite_snapshot: namespaces,
})
const routes = Object.freeze({
  d901_control_access: Object.freeze(['independent_verifier', 'trusted_launcher']),
  d920_accepted_evidence: Object.freeze(['trusted_launcher', 'independent_verifier']),
  d930_custody: Object.freeze(['independent_verifier', 'journal_broker']),
  d940_composite_snapshot: Object.freeze(['trusted_launcher', 'independent_verifier']),
})
const endpoints = Object.freeze({ trusted_launcher: 'ipc.launcher', independent_verifier: 'ipc.verifier', journal_broker: 'ipc.journal' })
const runtimes = new WeakSet()

function readFrozen(relativePath) {
  const absolute = path.join(contractRoot, relativePath)
  const stat = fs.lstatSync(absolute)
  if (!stat.isFile() || stat.isSymbolicLink()) failD941('D941_RESOLVER_CONTRACT_UNPROTECTED', `${relativePath} is not a regular file`)
  const bytes = fs.readFileSync(absolute)
  const expected = expectedFingerprints[relativePath]
  if (expected && sha256Bytes(bytes) !== expected) failD941('D941_RESOLVER_CONTRACT_CHANGED', `${relativePath} differs from the approved recovery-resolver freeze`)
  return parseStrictJson(bytes, { maximumBytes: 4 * 1024 * 1024, maximumDepth: 128, maximumMembers: 100_000, contractNumbers: true })
}

function clone(value) { return structuredClone(value) }
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child)
    Object.freeze(value)
  }
  return value
}
function same(left, right) { return canonicalize(left) === canonicalize(right) }
function plus(timestamp, deltaMs) { return new Date(Date.parse(timestamp) + deltaMs).toISOString() }
function recordDigest(record) { return canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' }) }
function projectionDigest(record) { return canonicalSha256(record, { excludedTopLevelField: 'projection_sha256' }) }
function sorted(values) { return [...values].sort((left, right) => left < right ? -1 : left > right ? 1 : 0) }
function pick(record, fields) { return Object.fromEntries(fields.map((field) => [field, record[field]])) }

function timestamp(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u.test(value) ||
      Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    failD941('D941_RESOLVER_TIME_INVALID', `${label} must be a canonical UTC timestamp`)
  }
  return value
}

function loadContract() {
  for (const relativePath of Object.keys(expectedFingerprints)) readFrozen(relativePath)
  const catalog = readFrozen('contract-catalog-v1.json')
  const classifications = readFrozen('classifications-v1.json')
  if (catalog.status_code !== 'design_only_contract_freeze' || catalog.instance_policy.runtime_implementation_authorized !== false || catalog.instance_policy.operational_activation_authorized !== false) {
    failD941('D941_RESOLVER_CONTRACT_BOUNDARY_INVALID', 'resolver contract does not retain its design-only, unactivated boundary')
  }
  const common = readFrozen('common-v1.schema.json')
  const request = readFrozen('resolution-request-v1.schema.json')
  const response = readFrozen('resolution-response-v1.schema.json')
  const attestation = readFrozen('append-revalidation-attestation-v1.schema.json')
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  for (const schema of [common, request, response, attestation]) ajv.addSchema(schema)
  return Object.freeze({
    catalog,
    classifications,
    sourceProfiles: new Map(classifications.source_profiles.map((item) => [item.source_namespace_code, item.source_contract_fingerprint_sha256])),
    validateRequest: ajv.getSchema(request.$id),
    validateResponse: ajv.getSchema(response.$id),
    validateAttestation: ajv.getSchema(attestation.$id),
    sourceTemplate: readFrozen('fixtures/synthetic-source-state-v1.json'),
  })
}

function assertSchema(validator, value, label) {
  if (!validator(value)) failD941('D941_RESOLVER_SCHEMA_REJECTED', `${label} violates the approved schema: ${validator.errors?.map((item) => `${item.instancePath || '/'} ${item.message}`).join('; ')}`, { details: validator.errors })
}

function actorFor(authorityContext, runtimeRoleCode, at) {
  timestamp(at, `${runtimeRoleCode} evaluation time`)
  const generation = authorityContext.verifiedGeneration
  const binding = generation.identityBindings.bindings.find((item) => item.runtime_role_code === runtimeRoleCode)
  if (!binding || binding.principal_kind_code !== 'service' || !binding.allowed_operation_modes.includes('recovery') ||
      binding.ipc_endpoint_code !== endpoints[runtimeRoleCode] ||
      !(generation.identityBindings.issued_at <= at && at < generation.identityBindings.expires_at) ||
      !(binding.valid_from <= at && at < binding.valid_until)) {
    failD941('D941_RESOLVER_IDENTITY_UNAVAILABLE', `${runtimeRoleCode} is not an eligible recovery service binding`)
  }
  return Object.freeze({
    runtime_role_code: runtimeRoleCode,
    binding_code: binding.binding_code,
    endpoint_code: endpoints[runtimeRoleCode],
    executable_build_sha256: binding.executable_sha256,
  })
}

function runtimeGeneration(authorityContext) {
  const generation = authorityContext.verifiedGeneration
  return Object.freeze({
    runtime_profile_record_digest_sha256: generation.runtimeProfile.record_digest_sha256,
    identity_bindings_record_digest_sha256: generation.identityBindings.record_digest_sha256,
    binding_generation: generation.identityBindings.binding_generation,
  })
}

function receiptRecords(broker) {
  const namespaceByFormat = new Map([
    ['jedi-atlas-custody-control-record', 'control'],
    ['jedi-atlas-access-revocation-record', 'access'],
    ['jedi-atlas-deletion-execution-record', 'execution'],
    ['jedi-atlas-deletion-receipt', 'receipt'],
    ['jedi-atlas-backup-coordination-record', 'backup'],
    ['jedi-atlas-d940-recovery-assessment', 'recovery'],
  ])
  return broker.validate().map((receipt) => {
    const namespaceCode = namespaceByFormat.get(receipt.target_format)
    if (!namespaceCode) failD941('D941_RESOLVER_SOURCE_CONTRADICTORY', 'D9.4 receipt names an unknown target format')
    const record = parseStrictJson(broker.store.read({ namespaceCode, recordCode: receipt.target_record_code }), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 128, maximumMembers: 100_000, contractNumbers: true })
    if (record.record_digest_sha256 !== receipt.target_record_digest_sha256) failD941('D941_RESOLVER_SOURCE_CONTRADICTORY', 'D9.4 receipt target digest differs from protected bytes')
    return { receipt, record }
  })
}

function dynamicSourceState(template, broker, subject, custodyEvidence) {
  const state = clone(template)
  const sources = state.sources
  const subjectIdentitySha256 = subject.subject_identity_sha256
  state.subject_identity_sha256 = subjectIdentitySha256
  const lineage = sources.lineage_store
  const oldSubject = lineage.target_subject_identity_sha256
  const oldArtifact = lineage.nodes.find((node) => node.subject_identity_sha256 !== oldSubject)?.subject_identity_sha256
  const artifactIdentity = canonicalSha256({ subject_kind_code: 'artifact', artifact: subject.subject_payload.artifact })
  lineage.target_subject_identity_sha256 = subjectIdentitySha256
  for (const node of lineage.nodes) if (node.subject_identity_sha256 === oldSubject) node.subject_identity_sha256 = subjectIdentitySha256
  for (const node of lineage.nodes) if (node.subject_identity_sha256 === oldArtifact) node.subject_identity_sha256 = artifactIdentity
  for (const edge of lineage.edges) {
    if (edge.from_subject_identity_sha256 === oldSubject) edge.from_subject_identity_sha256 = subjectIdentitySha256
    if (edge.to_subject_identity_sha256 === oldSubject) edge.to_subject_identity_sha256 = subjectIdentitySha256
    if (edge.from_subject_identity_sha256 === oldArtifact) edge.from_subject_identity_sha256 = artifactIdentity
    if (edge.to_subject_identity_sha256 === oldArtifact) edge.to_subject_identity_sha256 = artifactIdentity
  }
  lineage.nodes.sort((a, b) => a.subject_identity_sha256 < b.subject_identity_sha256 ? -1 : 1)
  lineage.edges.sort((a, b) => `${a.from_subject_identity_sha256}\0${a.to_subject_identity_sha256}` < `${b.from_subject_identity_sha256}\0${b.to_subject_identity_sha256}` ? -1 : 1)
  lineage.store_snapshot.node_store_head_sha256 = canonicalSha256(lineage.nodes)
  lineage.store_snapshot.edge_store_head_sha256 = canonicalSha256(lineage.edges)
  const receipt = sources.primary_receipts.records[0]
  receipt.subject_identity_sha256 = subjectIdentitySha256
  receipt.d930_operational_profile_record_digest_sha256 = custodyEvidence.d930OperationalProfileSha256
  receipt.artifact = clone(subject.subject_payload.artifact)
  receipt.copy_code = subject.subject_payload.copy_code
  receipt.backend_code = subject.subject_payload.backend_code
  receipt.backend_reference = subject.subject_payload.backend_reference
  receipt.receipt_digest_sha256 = canonicalSha256(Object.fromEntries(Object.entries(receipt).filter(([key]) => key !== 'receipt_digest_sha256')))
  const candidate = sources.custody_candidates.records[0]
  candidate.subject_identity_sha256 = subjectIdentitySha256
  candidate.d930_operational_profile_record_digest_sha256 = custodyEvidence.d930OperationalProfileSha256
  candidate.d930_primary_durability_receipt_sha256 = receipt.receipt_digest_sha256
  candidate.artifact = clone(subject.subject_payload.artifact)
  candidate.copy_code = subject.subject_payload.copy_code
  candidate.backend_code = subject.subject_payload.backend_code
  candidate.backend_reference = subject.subject_payload.backend_reference

  const protectedRecords = receiptRecords(broker)
  const head = broker.head()
  const controls = protectedRecords
    .filter(({ record }) => record.format === 'jedi-atlas-custody-control-record')
    .map(({ receipt: journalReceipt, record }) => ({
      receipt_sequence: journalReceipt.receipt_sequence,
      record_kind_code: record.record_kind_code,
      record_digest_sha256: record.record_digest_sha256,
    }))
  sources.control_records = { known_through_receipt_sequence: head.sequence, records: controls }
  const d940Boundary = sources.source_boundaries.find((item) => item.source_namespace_code === 'd940.global.control-journal.v1')
  d940Boundary.head_sequence = head.sequence
  d940Boundary.head_persisted_at = head.persistedAt
  return state
}

function deriveHeads(contract, sourceState, broker) {
  const heads = new Map()
  for (const boundary of sourceState.sources.source_boundaries) {
    const payloadCommitments = boundary.source_payload_codes.map((sourcePayloadCode) => ({
      source_payload_code: sourcePayloadCode,
      raw_payload_sha256: canonicalSha256(sourceState.sources[sourcePayloadCode]),
    }))
    const inventoryDigest = canonicalSha256({ source_namespace_code: boundary.source_namespace_code, head_sequence: boundary.head_sequence, payload_commitments: payloadCommitments })
    const derivedHead = canonicalSha256({ source_namespace_code: boundary.source_namespace_code, head_sequence: boundary.head_sequence, head_persisted_at: boundary.head_persisted_at, inventory_digest_sha256: inventoryDigest })
    const d940Head = boundary.source_namespace_code === 'd940.global.control-journal.v1' ? broker.head() : null
    heads.set(boundary.source_namespace_code, Object.freeze({
      source_namespace_code: boundary.source_namespace_code,
      source_contract_fingerprint_sha256: contract.sourceProfiles.get(boundary.source_namespace_code),
      head_sequence: boundary.head_sequence,
      head_digest_sha256: d940Head?.digest ?? derivedHead,
      head_persisted_at: boundary.head_persisted_at,
      inventory_digest_sha256: boundary.source_namespace_code === 'd940.global.control-journal.v1' ? broker.store.inventory().digest : inventoryDigest,
    }))
  }
  if (!same(sorted(heads.keys()), namespaces)) failD941('D941_RESOLVER_SOURCE_SET_INVALID', 'synthetic adapters do not expose the complete approved source set')
  return heads
}

function deriveOutputs(sourceState, heads) {
  const sources = sourceState.sources
  const control = sources.control_records.records
    .map((record) => pick(record, ['receipt_sequence', 'record_kind_code', 'record_digest_sha256']))
    .sort((a, b) => a.receipt_sequence - b.receipt_sequence)
  const sourceAccess = clone(sources.source_access_state)
  sourceAccess.capabilities.sort((a, b) => a.capability_record_digest_sha256 < b.capability_record_digest_sha256 ? -1 : 1)
  sourceAccess.descriptor_lifecycle_records.sort((a, b) => canonicalize(a) < canonicalize(b) ? -1 : 1)
  sourceAccess.adapter_message_record_digests.sort()
  const sourceAccessHash = canonicalSha256(sourceAccess)
  const terminal = sources.access_shutdown_state.capability_terminal_records.map((item) => item.terminal_record_digest_sha256).sort()
  const descriptorLeaves = [...sources.access_shutdown_state.descriptor_leaves].sort((a, b) => canonicalize(a) < canonicalize(b) ? -1 : 1)
  const shutdown = { source_access_inventory_sha256: sourceAccessHash, capability_terminal_record_digests: terminal, descriptor_leaves: descriptorLeaves }
  const acceptedReceipts = sources.accepted_receipts.records
    .map((record) => pick(record, ['bundle_sequence', 'bundle_code', 'receipt_digest_sha256']))
    .sort((a, b) => a.bundle_sequence - b.bundle_sequence)
  const logical = sources.accepted_logical_records.records
    .map((record) => pick(record, ['table_code', 'stable_key', 'record_digest_sha256']))
    .sort((a, b) => `${a.table_code}\0${a.stable_key}` < `${b.table_code}\0${b.stable_key}` ? -1 : 1)
  const lineage = clone(sources.lineage_store)
  const primaryReceipts = sources.primary_receipts.records
    .map((record) => pick(record, ['receipt_sequence', 'receipt_code', 'receipt_digest_sha256']))
    .sort((a, b) => a.receipt_sequence - b.receipt_sequence)
  const custodySource = sources.custody_candidates.records.find((record) => record.subject_identity_sha256 === sourceState.subject_identity_sha256)
  if (!custodySource) failD941('D941_RESOLVER_CUSTODY_UNAVAILABLE', 'synthetic D9.3 adapter has no exact subject custody leaf')
  const custody = pick(custodySource, ['d930_operational_profile_record_digest_sha256', 'd930_primary_durability_receipt_sha256', 'artifact', 'copy_code', 'backend_code', 'backend_reference'])
  const inventory = [...heads.values()]
    .map((head) => pick(head, ['source_namespace_code', 'head_sequence', 'inventory_digest_sha256']))
    .sort((a, b) => a.source_namespace_code < b.source_namespace_code ? -1 : 1)
  return Object.freeze({
    control_head_projection_sha256: canonicalSha256(control),
    access_head_projection_sha256: canonicalSha256(shutdown),
    accepted_receipt_prefix_sha256: canonicalSha256(acceptedReceipts),
    accepted_logical_state_sha256: canonicalSha256(logical),
    subject_lineage_projection_sha256: canonicalSha256(lineage),
    primary_receipt_prefix_sha256: canonicalSha256(primaryReceipts),
    custody_leaf_projection_sha256: canonicalSha256(custody),
    inventory_snapshot_sha256: canonicalSha256(inventory),
  })
}

function makeRequest({ contract, kind, authorityContext, subject, operationId, operationNonce, requestedAt, heads, inputDigests = [] }) {
  timestamp(requestedAt, 'resolver request time')
  const [senderRole, recipientRole] = routes[kind]
  const selected = namespaceSets[kind].map((namespace) => heads.get(namespace))
  if (selected.some((head) => head.head_persisted_at > requestedAt)) failD941('D941_RESOLVER_SOURCE_HEAD_FUTURE', 'resolver source head is later than the trusted knowledge boundary')
  const request = {
    format: 'jedi-atlas-recovery-projection-resolution-request', format_version: '1.0.0', resolver_kind_code: kind,
    request_code: `resolver.request.${kind}.${canonicalSha256({ operationId, operationNonce, kind }).slice(0, 16)}`,
    operation_id: operationId, operation_nonce: operationNonce, idempotency_key_sha256: null,
    sender: actorFor(authorityContext, senderRole, requestedAt), recipient: actorFor(authorityContext, recipientRole, requestedAt),
    runtime_generation: runtimeGeneration(authorityContext), subject,
    requested_at: requestedAt, expires_at: plus(requestedAt, 5000),
    knowledge_boundary: { known_at: requestedAt, known_through_receipt_sequence: Math.max(...selected.map((head) => head.head_sequence)), trusted_clock_role_code: 'trusted_launcher' },
    prior_accepted_source_heads: selected, source_contract_fingerprints: sorted(new Set(selected.map((head) => head.source_contract_fingerprint_sha256))),
    input_response_record_digests: inputDigests, record_digest_sha256: null,
  }
  request.idempotency_key_sha256 = canonicalSha256(Object.fromEntries(Object.entries(request).filter(([key]) => !['idempotency_key_sha256', 'record_digest_sha256', 'format', 'format_version'].includes(key))))
  // The approved profile includes resolver identity fields but excludes only the two digest fields.
  request.idempotency_key_sha256 = canonicalSha256({
    resolver_kind_code: request.resolver_kind_code, request_code: request.request_code, operation_id: request.operation_id,
    operation_nonce: request.operation_nonce, sender: request.sender, recipient: request.recipient, runtime_generation: request.runtime_generation,
    subject: request.subject, requested_at: request.requested_at, expires_at: request.expires_at, knowledge_boundary: request.knowledge_boundary,
    prior_accepted_source_heads: request.prior_accepted_source_heads, source_contract_fingerprints: request.source_contract_fingerprints,
    input_response_record_digests: request.input_response_record_digests,
  })
  request.record_digest_sha256 = recordDigest(request)
  assertSchema(contract.validateRequest, request, 'resolver request')
  return deepFreeze(request)
}

function makeObservation(before, after, beforeAt, afterAt) {
  const stable = same(before, after)
  return Object.freeze({ before, after, observed_before_at: beforeAt, observed_after_at: afterAt, stability_code: stable ? 'stable' : 'moved', source_namespace_code: before.source_namespace_code })
}

function makeProjection(kind, sourceState, heads, outputs, sourceResponses = []) {
  if (kind === 'd901_control_access') {
    const head = heads.get('d940.global.control-journal.v1')
    return { projection_kind_code: kind, journal_namespace_code: head.source_namespace_code, known_through_receipt_sequence: head.head_sequence, known_through_persisted_at: head.head_persisted_at, control_ledger_head_receipt_digest_sha256: head.head_digest_sha256, control_head_projection_sha256: outputs.control_head_projection_sha256, access_head_projection_sha256: outputs.access_head_projection_sha256, projection_sha256: null }
  }
  if (kind === 'd920_accepted_evidence') return { projection_kind_code: kind, known_through_bundle_sequence: heads.get('d920.accepted-evidence.v1').head_sequence, accepted_receipt_prefix_sha256: outputs.accepted_receipt_prefix_sha256, accepted_logical_state_sha256: outputs.accepted_logical_state_sha256, subject_lineage_projection_sha256: outputs.subject_lineage_projection_sha256, projection_sha256: null }
  if (kind === 'd930_custody') {
    const head = heads.get('d930.custody-journal.v1')
    return { projection_kind_code: kind, known_through_journal_sequence: head.head_sequence, known_through_journal_persisted_at: head.head_persisted_at, custody_journal_head_digest_sha256: head.head_digest_sha256, primary_receipt_prefix_sha256: outputs.primary_receipt_prefix_sha256, custody_leaf_projection_sha256: outputs.custody_leaf_projection_sha256, projection_sha256: null }
  }
  const [control, evidence, custody] = sourceResponses.map((item) => item.projection)
  const snapshot = { journal_namespace_code: control.journal_namespace_code, known_through_receipt_sequence: control.known_through_receipt_sequence, known_through_persisted_at: control.known_through_persisted_at, control_ledger_head_receipt_digest_sha256: control.control_ledger_head_receipt_digest_sha256, control_head_projection_sha256: control.control_head_projection_sha256, access_head_projection_sha256: control.access_head_projection_sha256, subject_lineage_projection_sha256: evidence.subject_lineage_projection_sha256, inventory_snapshot_sha256: outputs.inventory_snapshot_sha256, custody_leaf_projection_sha256: custody.custody_leaf_projection_sha256 }
  return { projection_kind_code: kind, consistency_code: 'stable_double_collect_no_atomic_global_snapshot', source_response_record_digests: sourceResponses.map((item) => item.record_digest_sha256), snapshot, snapshot_digest_sha256: canonicalSha256(snapshot), projection_sha256: null }
}

function makeResponse({ contract, request, sourceState, beforeHeads, heads, outputs, observedAt, observedAfterAt, respondedAt, sourceResponses = [] }) {
  const projection = makeProjection(request.resolver_kind_code, sourceState, heads, outputs, sourceResponses)
  projection.projection_sha256 = projectionDigest(projection)
  const response = {
    format: 'jedi-atlas-recovery-projection-resolution-response', format_version: '1.0.0', resolver_kind_code: request.resolver_kind_code,
    response_code: request.request_code.replace('resolver.request.', 'resolver.response.'), operation_id: request.operation_id,
    operation_nonce: request.operation_nonce, request_record_digest_sha256: request.record_digest_sha256,
    idempotency_key_sha256: request.idempotency_key_sha256, sender: request.recipient, recipient: request.sender,
    runtime_generation: request.runtime_generation, subject: request.subject, result_code: 'resolved', error_code: null,
    observed_at: observedAt, responded_at: respondedAt, append_revalidate_by: plus(respondedAt, 1000),
    source_observations: namespaceSets[request.resolver_kind_code].map((namespace) => makeObservation(beforeHeads.get(namespace), heads.get(namespace), observedAt, observedAfterAt)),
    projection, technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
  }
  response.record_digest_sha256 = recordDigest(response)
  assertSchema(contract.validateResponse, response, 'resolver response')
  return deepFreeze(response)
}

export function createD941SyntheticRecoveryResolverRuntime({ authorityContext, authorityRegistry, broker, subject: configuredSubject, custodyEvidence, trustedClock }) {
  assertD941LedgerBroker(broker)
  assertD941AuthorityRegistry(authorityRegistry)
  assertD941SyntheticCustodyEvidence(custodyEvidence)
  if (!authorityContext?.verifiedGeneration || authorityRegistry.authorityContext !== authorityContext || typeof trustedClock !== 'function' || configuredSubject?.subject_kind_code !== 'custody_copy' || typeof configuredSubject?.subject_identity_sha256 !== 'string') failD941('D941_RESOLVER_CONFIGURATION_INVALID', 'synthetic resolver requires the selected authority registry, one exact custody subject, and a trusted launcher clock')
  const contract = loadContract()
  const responses = new Map()

  function observe(subjectIdentitySha256) {
    if (subjectIdentitySha256 !== configuredSubject.subject_identity_sha256) failD941('D941_RESOLVER_SUBJECT_SUBSTITUTED', 'resolver request differs from the configured D9.3 custody subject')
    const sourceState = dynamicSourceState(contract.sourceTemplate, broker, configuredSubject, custodyEvidence)
    const heads = deriveHeads(contract, sourceState, broker)
    const outputs = deriveOutputs(sourceState, heads)
    return deepFreeze({ sourceState, heads, outputs })
  }

  function assertAuthorityActive(at) {
    const authorityState = authorityRegistry.stateAt(at)
    if (authorityState.revoked.size !== 0) failD941('D941_RESOLVER_AUTHORITY_REVOKED', 'resolver authority generation has a revoked required target')
  }

  function collectStable(kind, subjectIdentitySha256, requestedAt) {
    const observedAt = timestamp(trustedClock(), 'resolver before-observation time')
    if (observedAt < requestedAt) failD941('D941_RESOLVER_TIME_INVALID', 'resolver before-observation time precedes its request')
    const before = observe(subjectIdentitySha256)
    const after = observe(subjectIdentitySha256)
    const observedAfterAt = timestamp(trustedClock(), 'resolver after-observation time')
    if (observedAfterAt < observedAt) failD941('D941_RESOLVER_TIME_INVALID', 'resolver after-observation time precedes its before observation')
    const moved = namespaceSets[kind].filter((namespace) => !same(before.heads.get(namespace), after.heads.get(namespace)))
    if (moved.length !== 0) failD941('D941_RESOLVER_SOURCE_HEAD_MOVED', 'one or more resolver source heads moved during the required double collection', { details: { namespaces: moved } })
    const respondedAt = timestamp(trustedClock(), 'resolver response time')
    if (respondedAt < observedAfterAt) failD941('D941_RESOLVER_TIME_INVALID', 'resolver response time precedes its after observation')
    return deepFreeze({ ...after, beforeHeads: before.heads, observedAt, observedAfterAt, respondedAt })
  }

  // These are deliberately closed, in-process synthetic adapters. They model
  // the three approved resolver boundaries without exposing arbitrary source
  // callbacks or granting a handle to any protected store.
  function createSourceAdapter(kind) {
    const ownedNamespaces = namespaceSets[kind]
    return Object.freeze({
      kind,
      resolve({ subject, operationId, operationNonce }) {
        const requestedAt = timestamp(trustedClock(), 'trusted resolver request clock')
        assertAuthorityActive(requestedAt)
        const observed = collectStable(kind, subject.subject_identity_sha256, requestedAt)
        const request = makeRequest({ contract, kind, authorityContext, subject, operationId, operationNonce, requestedAt, heads: observed.heads })
        return Object.freeze({
          request,
          response: makeResponse({ contract, request, ...observed }),
          ownedNamespaces,
        })
      },
    })
  }
  const sourceAdapters = Object.freeze([
    createSourceAdapter('d901_control_access'),
    createSourceAdapter('d920_accepted_evidence'),
    createSourceAdapter('d930_custody'),
  ])

  function resolveComposite({ subject, operationId, operationNonce }) {
    if (subject?.subject_kind_code !== configuredSubject.subject_kind_code || subject?.subject_identity_sha256 !== configuredSubject.subject_identity_sha256) failD941('D941_RESOLVER_SUBJECT_SUBSTITUTED', 'resolver request differs from the configured D9.3 custody subject')
    const sourceResults = sourceAdapters.map((adapter) => adapter.resolve({ subject, operationId, operationNonce }))
    const requests = sourceResults.map((item) => item.request)
    const sourceResponses = sourceResults.map((item) => item.response)
    const requestedAt = timestamp(trustedClock(), 'trusted composite request clock')
    assertAuthorityActive(requestedAt)
    const observed = collectStable('d940_composite_snapshot', subject.subject_identity_sha256, requestedAt)
    for (const response of sourceResponses) for (const sourceObservation of response.source_observations) {
      if (!same(sourceObservation.after, observed.beforeHeads.get(sourceObservation.source_namespace_code))) failD941('D941_RESOLVER_MIXED_SOURCE_HEAD', 'constituent final source head differs from the composite anchor')
    }
    const compositeRequest = makeRequest({ contract, kind: 'd940_composite_snapshot', authorityContext, subject, operationId, operationNonce, requestedAt, heads: observed.heads, inputDigests: sourceResponses.map((item) => item.record_digest_sha256) })
    const compositeResponse = makeResponse({ contract, request: compositeRequest, ...observed, sourceResponses })
    const existing = responses.get(compositeRequest.idempotency_key_sha256)
    if (existing && !same(existing, compositeResponse)) failD941('D941_RESOLVER_REPLAY_COLLISION', 'resolver replay identity is paired with different content')
    responses.set(compositeRequest.idempotency_key_sha256, compositeResponse)
    return deepFreeze({ requests, sourceResponses, compositeRequest, compositeResponse, snapshot: compositeResponse.projection.snapshot })
  }

  function revalidateAtAppend({ compositeResponse, completedAt }) {
    if (!responses.has(compositeResponse.idempotency_key_sha256) || responses.get(compositeResponse.idempotency_key_sha256) !== compositeResponse) failD941('D941_RECOVERY_RESOLVER_RESPONSE_UNTRUSTED', 'append revalidation requires the exact locally issued composite response')
    timestamp(completedAt, 'append revalidation completion time')
    const authorityState = authorityRegistry.stateAt(completedAt)
    if (authorityState.revoked.size !== 0) failD941('D941_RESOLVER_AUTHORITY_REVOKED', 'resolver authority generation has a revoked required target')
    actorFor(authorityContext, 'independent_verifier', completedAt)
    actorFor(authorityContext, 'journal_broker', completedAt)
    if (completedAt < compositeResponse.responded_at || completedAt > compositeResponse.append_revalidate_by) failD941('D941_RECOVERY_APPEND_REVALIDATION_EXPIRED', 'append occurs outside the resolver freshness window')
    const before = observe(compositeResponse.subject.subject_identity_sha256)
    const current = observe(compositeResponse.subject.subject_identity_sha256)
    const expected = new Map(compositeResponse.source_observations.map((item) => [item.source_namespace_code, item.after]))
    const exact = namespaces.every((namespace) => same(before.heads.get(namespace), current.heads.get(namespace)) && same(current.heads.get(namespace), expected.get(namespace)))
    const attestation = {
      format: 'jedi-atlas-recovery-projection-append-revalidation-attestation', format_version: '1.0.0',
      attestation_code: `resolver.attestation.${canonicalSha256({ response: compositeResponse.record_digest_sha256, completedAt }).slice(0, 16)}`,
      operation_id: compositeResponse.operation_id, operation_nonce: compositeResponse.operation_nonce,
      composite_response_record_digest_sha256: compositeResponse.record_digest_sha256,
      sender: actorFor(authorityContext, 'independent_verifier', completedAt), recipient: actorFor(authorityContext, 'journal_broker', completedAt),
      runtime_generation: compositeResponse.runtime_generation, subject: compositeResponse.subject,
      observed_at: completedAt, completed_at: completedAt, result_code: exact ? 'revalidated' : 'failed', error_code: exact ? null : 'append_revalidation_failed',
      source_heads: namespaces.map((namespace) => current.heads.get(namespace)), technical_evidence_only: true, authority_granted: false,
      record_digest_sha256: null,
    }
    attestation.record_digest_sha256 = recordDigest(attestation)
    assertSchema(contract.validateAttestation, attestation, 'append revalidation attestation')
    if (!exact) failD941('D941_RECOVERY_APPEND_REVALIDATION_FAILED', 'one or more resolver source heads changed before append', { details: { attestation } })
    return deepFreeze(attestation)
  }

  const runtime = Object.freeze({ resolveComposite, revalidateAtAppend })
  runtimes.add(runtime)
  return runtime
}

export function assertD941RecoveryResolverRuntime(value) {
  if (!runtimes.has(value)) failD941('D941_RECOVERY_RESOLVER_UNTRUSTED', 'recovery resolver was not created by the fixed synthetic factory')
  return value
}
