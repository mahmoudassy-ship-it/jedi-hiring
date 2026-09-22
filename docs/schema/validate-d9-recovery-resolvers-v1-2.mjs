import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { canonicalSha256, canonicalize, parseStrictJson, sha256Bytes } from '../../d9/control-plane/canonical.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const project = path.resolve(here, '../..')
const root = path.join(here, 'd9-recovery-resolvers-v1-2')
const v1Root = path.join(here, 'd9-recovery-resolvers')
const v11Root = path.join(here, 'd9-recovery-resolvers-v1-1')
const d90Root = path.join(here, 'd9-0')
const d940Root = path.join(here, 'd9-4-0')
const ZERO = '0'.repeat(64)

function fail(code, detail = code) { const error = new Error(`${code}: ${detail}`); error.code = code; throw error }
function readJson(file) { return parseStrictJson(fs.readFileSync(file), { maximumBytes: 8 * 1024 * 1024, maximumDepth: 192, maximumMembers: 200_000, contractNumbers: true }) }
function rawSha256(file) { return sha256Bytes(fs.readFileSync(file)) }
function clone(value) { return structuredClone(value) }
function same(left, right) { return canonicalize(left) === canonicalize(right) }
function seal(record) { record.record_digest_sha256 = canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' }); return record }
function ms(value, label = 'timestamp') { const parsed = Date.parse(value); if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) fail('TIME_INVALID', label); return parsed }
function assertDigest(record, label = 'record') { assert.equal(record.record_digest_sha256, canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' }), `${label} self digest`) }
function projectionDigest(projection) { return canonicalSha256(projection, { excludedTopLevelField: 'projection_sha256' }) }

const frozen = {
  'docs/schema/d9-recovery-resolvers/contract-catalog-v1.json': 'df33cbf575f8f4b430ef22384f0d73350e521abed6443f07006d13bb3b968ba3',
  'docs/schema/d9-recovery-resolvers/root-inventory-v1.json': '93832dc8a6f12ae030515781169fd8ac9dd5431aa68f62699168469da3da6f31',
  'docs/schema/d9-recovery-resolvers-v1-1/contract-catalog-v1-1.json': 'aa846c01c5d055050c810249316d11eba7a48d1080681f9538be3e71d371bb26',
  'docs/schema/d9-recovery-resolvers-v1-1/root-inventory-v1-1.json': 'b3711db55ed73a1a74621a808014aae35b2e05319e5cf0aeba5df0d62b1933bf',
  'docs/schema/d9-0/contract-catalog-v1.json': 'e0a5663b378453a00626f02961465a60a474e145dd5160bf85a1797cd9316d2a',
  'docs/schema/d9-3-0/contract-catalog-v1.json': 'cd91f67c25941a472b89fe2fa6f19b012714dec96661b65b76ecfacf7f48e87c',
  'docs/schema/d9-4-0/contract-catalog-v1.json': '12da4237efade65cf6e2cc19d2df936e98caf505c8f6d30b38e7df8c4d349ad7',
  'docs/schema/validate-d9-recovery-resolvers.mjs': 'bc36de4475ee6d8b9fd354f80163799f431496ae91765b5dd4903fdde9763ef5',
  'docs/schema/validate-d9-recovery-resolvers-v1-1.mjs': 'f6e8aa1f242198febd6e3b5bfa0a93ddf0f9829bc4850d920a1ca9be941235c5',
  'docs/schema/validate-d9-4-0.mjs': '711f575425a1bffcbd09255f327b966df8dacc5ca58e10312bfa189a6a6f8ef6',
  'data/migrations/001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  'data/migrations/002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  'data/migrations/003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
  'data/migrations/004_tranche_1a_foundations.sql': '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
  'data/migrations/005_tranche_2a_source_quarantine.sql': '1f83b484ca998be3bf5756492d4dffd958e2a6b37dbcc837e399226fdf41026b',
}
for (const [relative, digest] of Object.entries(frozen)) assert.equal(rawSha256(path.join(project, relative)), digest, `${relative} frozen`)
for (const validator of ['docs/schema/validate-d9-recovery-resolvers.mjs', 'docs/schema/validate-d9-recovery-resolvers-v1-1.mjs', 'docs/schema/validate-d9-4-0.mjs']) execFileSync(process.execPath, ['--disable-warning=ExperimentalWarning', validator], { cwd: project, stdio: 'pipe' })

const localSchemaFiles = ['common-v1-2.schema.json', 'assessment-append-request-v1-2.schema.json', 'assessment-append-broker-receipt-v1-2.schema.json', 'checkpoint-transition-v1-2.schema.json', 'protected-append-receipt-v1-2.schema.json', 'finalization-result-v1-2.schema.json']
const dependencyFiles = [
  [d90Root, 'common-v1.schema.json'], [v1Root, 'common-v1.schema.json'],
  [v1Root, 'resolution-request-v1.schema.json'], [v1Root, 'resolution-response-v1.schema.json'], [v1Root, 'append-revalidation-attestation-v1.schema.json'],
  [v11Root, 'common-v1-1.schema.json'], [v11Root, 'checkpoint-record-v1-1.schema.json'], [v11Root, 'append-receipt-v1-1.schema.json'], [v11Root, 'durable-resolver-record-v1-1.schema.json'],
  [d940Root, 'common-v1.schema.json'], [d940Root, 'recovery-assessment-v1.schema.json'], [d940Root, 'journal-append-receipt-v1.schema.json'],
]
const localSchemas = localSchemaFiles.map((file) => readJson(path.join(root, file)))
const dependencies = dependencyFiles.map(([base, file]) => readJson(path.join(base, file)))
const ajv = new Ajv2020({ allErrors: true, strict: false })
for (const schema of [...dependencies, ...localSchemas]) ajv.addSchema(schema)
function validateByFile(file, value) { const schema = [...localSchemas, ...dependencies].find((item) => item.$id?.endsWith(`/${file}`)); const validate = ajv.getSchema(schema.$id); if (!validate(value)) fail('SCHEMA_REJECTED', `${file}: ${ajv.errorsText(validate.errors)}`) }

const fixture = readJson(path.join(root, 'fixtures/valid-progression-v1-2.json'))
const invalidFixture = readJson(path.join(root, 'fixtures/invalid-progression-v1-2.json'))
const v1Fixture = readJson(path.join(v1Root, 'fixtures/valid-contracts-v1.json'))
const sourceStateBase = readJson(path.join(v1Root, 'fixtures/synthetic-source-state-v1.json'))
const d940Fixture = readJson(path.join(d940Root, 'fixtures/valid-contracts-v1.json'))
const d940Classifications = readJson(path.join(d940Root, 'classifications-v1.json'))
const sourceProfiles = new Map(readJson(path.join(v1Root, 'classifications-v1.json')).source_profiles.map((item) => [item.source_namespace_code, item.source_contract_fingerprint_sha256]))
const sourceOrder = [...sourceProfiles.keys()].sort()
const unchangedOrder = sourceOrder.filter((item) => item !== 'd940.global.control-journal.v1')
const frozenBindings = new Map(d940Fixture.records.identity_bindings.bindings.map((item) => [item.runtime_role_code, item]))
const generation = fixture.runtime_generation
const { launcher, verifier, broker } = fixture.actors
const requiredNamespaces = {
  d901_control_access: ['d901.capability-state.v1', 'd901.control-state.v1', 'd930.custody-journal.v1', 'd940.global.control-journal.v1'],
  d920_accepted_evidence: ['d920.accepted-evidence.v1'],
  d930_custody: ['d930.custody-journal.v1', 'd930.primary-receipts.v1'],
  d940_composite_snapshot: sourceOrder,
}

function assertGeneration(value) { if (!same(value, generation) || value.identity_bindings_record_digest_sha256 !== d940Fixture.records.identity_bindings.record_digest_sha256) fail('GENERATION_REJECTED') }
function assertActor(actor, role) { const binding = frozenBindings.get(role); if (!binding || actor.runtime_role_code !== role || actor.binding_code !== binding.binding_code || actor.endpoint_code !== binding.ipc_endpoint_code || actor.executable_build_sha256 !== binding.executable_sha256 || actor.binding_generation !== generation.binding_generation) fail('ACTOR_BINDING_REJECTED', role) }
for (const [actor, role] of [[launcher, 'trusted_launcher'], [verifier, 'independent_verifier'], [broker, 'journal_broker']]) assertActor(actor, role)
function assertHeads(heads) { assert.deepEqual(heads.map((item) => item.source_namespace_code), sourceOrder); assert.equal(new Set(heads.map((item) => item.source_namespace_code)).size, 6); for (const head of heads) { assert.equal(head.source_contract_fingerprint_sha256, sourceProfiles.get(head.source_namespace_code)); ms(head.head_persisted_at) } }

function deriveSourceHeads(sourceState) {
  const result = new Map()
  for (const boundary of sourceState.sources.source_boundaries) {
    const payload_commitments = boundary.source_payload_codes.map((source_payload_code) => ({ source_payload_code, raw_payload_sha256: canonicalSha256(sourceState.sources[source_payload_code]) }))
    const inventory_digest_sha256 = canonicalSha256({ source_namespace_code: boundary.source_namespace_code, head_sequence: boundary.head_sequence, payload_commitments })
    const head_digest_sha256 = canonicalSha256({ source_namespace_code: boundary.source_namespace_code, head_sequence: boundary.head_sequence, head_persisted_at: boundary.head_persisted_at, inventory_digest_sha256 })
    result.set(boundary.source_namespace_code, { source_namespace_code: boundary.source_namespace_code, source_contract_fingerprint_sha256: sourceProfiles.get(boundary.source_namespace_code), head_sequence: boundary.head_sequence, head_digest_sha256, head_persisted_at: boundary.head_persisted_at, inventory_digest_sha256 })
  }
  const heads = [...result.values()].sort((a, b) => a.source_namespace_code < b.source_namespace_code ? -1 : 1)
  assertHeads(heads)
  return heads
}

function snapshotFromSourceState(sourceState) {
  const heads = deriveSourceHeads(sourceState)
  const controlHead = heads.find((item) => item.source_namespace_code === 'd940.global.control-journal.v1')
  const control = sourceState.sources.control_records.records.map(({ receipt_sequence, record_kind_code, record_digest_sha256 }) => ({ receipt_sequence, record_kind_code, record_digest_sha256 })).sort((a, b) => a.receipt_sequence - b.receipt_sequence)
  const inventory = heads.map(({ source_namespace_code, head_sequence, inventory_digest_sha256 }) => ({ source_namespace_code, head_sequence, inventory_digest_sha256 }))
  const baseline = v1Fixture.composite_response.projection.snapshot
  return { journal_namespace_code: 'd940.global.control-journal.v1', known_through_receipt_sequence: controlHead.head_sequence, known_through_persisted_at: controlHead.head_persisted_at, control_ledger_head_receipt_digest_sha256: controlHead.head_digest_sha256, control_head_projection_sha256: canonicalSha256(control), access_head_projection_sha256: baseline.access_head_projection_sha256, subject_lineage_projection_sha256: baseline.subject_lineage_projection_sha256, inventory_snapshot_sha256: canonicalSha256(inventory), custody_leaf_projection_sha256: baseline.custody_leaf_projection_sha256 }
}
assert.deepEqual(snapshotFromSourceState(sourceStateBase), v1Fixture.composite_response.projection.snapshot, 'frozen v1 source derivation reproduced')

const d940Subject = d940Fixture.records.restriction.subject
const resolverSubject = { subject_kind_code: d940Subject.subject_kind_code, subject_identity_sha256: d940Subject.subject_identity_sha256 }
const roster = d940Fixture.records.authority_roster
const verifierAssignment = roster.assignments.find((item) => item.role_code === 'independent_verifier')
const d940Verifier = { identity_binding: { identity_bindings_record_digest_sha256: generation.identity_bindings_record_digest_sha256, binding_set_code: d940Fixture.records.identity_bindings.binding_set_code, binding_generation: generation.binding_generation, binding_code: verifierAssignment.binding_code }, authority_roster_record_digest_sha256: roster.record_digest_sha256, actor_kind_code: 'service', role_code: 'independent_verifier', principal_code: null }
const d940Broker = d940Fixture.records.restriction.persistence_actor

function sourceObservation(head, operation) { return { source_namespace_code: head.source_namespace_code, before: clone(head), after: clone(head), observed_before_at: operation.authorized_at, observed_after_at: operation.authorized_at, stability_code: 'stable' } }
function idempotencyPayload(request) { const copy = clone(request); delete copy.idempotency_key_sha256; delete copy.record_digest_sha256; return copy }
function resealV1Request(template, operation, kind, heads, inputDigests = []) {
  const request = clone(template)
  Object.assign(request, { resolver_kind_code: kind, request_code: `request.${kind}.${operation.operation_id.split('.').at(-1)}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: generation, subject: resolverSubject, requested_at: operation.authorized_at, expires_at: operation.append_revalidate_by, knowledge_boundary: { known_at: operation.authorized_at, known_through_receipt_sequence: heads.find((head) => head.source_namespace_code === 'd940.global.control-journal.v1')?.head_sequence ?? 1, trusted_clock_role_code: 'trusted_launcher' }, prior_accepted_source_heads: heads.filter((head) => requiredNamespaces[kind].includes(head.source_namespace_code)), source_contract_fingerprints: [...new Set(heads.filter((head) => requiredNamespaces[kind].includes(head.source_namespace_code)).map((head) => head.source_contract_fingerprint_sha256))].sort(), input_response_record_digests: inputDigests, record_digest_sha256: ZERO })
  request.idempotency_key_sha256 = canonicalSha256(idempotencyPayload(request))
  seal(request); validateByFile('resolution-request-v1.schema.json', request); return request
}
function componentProjection(kind, snapshot, template) {
  const projection = clone(template.projection)
  if (kind === 'd901_control_access') Object.assign(projection, { known_through_receipt_sequence: snapshot.known_through_receipt_sequence, known_through_persisted_at: snapshot.known_through_persisted_at, control_ledger_head_receipt_digest_sha256: snapshot.control_ledger_head_receipt_digest_sha256, control_head_projection_sha256: snapshot.control_head_projection_sha256, access_head_projection_sha256: snapshot.access_head_projection_sha256 })
  projection.projection_sha256 = projectionDigest(projection)
  return projection
}
function resealV1Response(template, request, operation, heads, projection) {
  const response = clone(template)
  Object.assign(response, { response_code: `response.${request.resolver_kind_code}.${operation.operation_id.split('.').at(-1)}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, request_record_digest_sha256: request.record_digest_sha256, idempotency_key_sha256: request.idempotency_key_sha256, runtime_generation: generation, subject: resolverSubject, observed_at: operation.authorized_at, responded_at: operation.authorized_at, append_revalidate_by: operation.append_revalidate_by, source_observations: heads.filter((head) => requiredNamespaces[request.resolver_kind_code].includes(head.source_namespace_code)).map((head) => sourceObservation(head, operation)), projection, record_digest_sha256: ZERO })
  seal(response); validateByFile('resolution-response-v1.schema.json', response); return response
}
function producerActor(serviceIdentity) { return { ...clone(serviceIdentity), binding_generation: generation.binding_generation } }
function durableRecord(payload, kind, operation, checkpoint, sequence, predecessor, requestDigest, responseDigest, attestationDigest) {
  const record = seal({ format: 'jedi-atlas-recovery-resolver-durable-record', format_version: '1.1.0', record_code: `durable.${operation.operation_id}.${sequence}`, record_kind_code: kind, resolver_kind_code: payload.resolver_kind_code ?? 'd940_composite_snapshot', sequence, predecessor_record_digest_sha256: predecessor, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: generation, subject: resolverSubject, payload_format: payload.format, payload_canonical_utf8: canonicalize(payload), payload_record_digest_sha256: payload.record_digest_sha256, semantic_verifier_code: 'd9_recovery_resolvers_v1_0_full_semantics', semantic_verifier_sha256: frozen['docs/schema/validate-d9-recovery-resolvers.mjs'], request_record_digest_sha256: requestDigest, response_record_digest_sha256: responseDigest, attestation_record_digest_sha256: attestationDigest, payload_producer: producerActor(payload.sender), semantic_actor: verifier, persistence_actor: broker, accepted_at: operation.authorized_at, persisted_at: operation.authorized_at, checkpoint_sequence: checkpoint.checkpoint_sequence, checkpoint_record_digest_sha256: checkpoint.checkpoint_record_digest_sha256, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateByFile('durable-resolver-record-v1-1.schema.json', record); assertDigest(record); assert.deepEqual(parseStrictJson(Buffer.from(record.payload_canonical_utf8)), payload); return record
}
function makeEvidence(operation, sourceState, checkpoint) {
  const heads = deriveSourceHeads(sourceState); const snapshot = snapshotFromSourceState(sourceState)
  const componentRequests = []; const componentResponses = []; const componentDurables = []
  for (let index = 0; index < 3; index += 1) {
    const kind = v1Fixture.requests[index].resolver_kind_code
    const request = resealV1Request(v1Fixture.requests[index], operation, kind, heads)
    const response = resealV1Response(v1Fixture.responses[index], request, operation, heads, componentProjection(kind, snapshot, v1Fixture.responses[index]))
    const durable = durableRecord(response, 'response', operation, checkpoint, index + 1, index ? componentDurables[index - 1].record_digest_sha256 : null, request.record_digest_sha256, response.record_digest_sha256, null)
    componentRequests.push(request); componentResponses.push(response); componentDurables.push(durable)
  }
  const compositeRequest = resealV1Request(v1Fixture.composite_request, operation, 'd940_composite_snapshot', heads, componentResponses.map((item) => item.record_digest_sha256))
  const compositeProjection = { projection_kind_code: 'd940_composite_snapshot', consistency_code: 'stable_double_collect_no_atomic_global_snapshot', source_response_record_digests: componentResponses.map((item) => item.record_digest_sha256), snapshot, snapshot_digest_sha256: canonicalSha256(snapshot), projection_sha256: ZERO }
  compositeProjection.projection_sha256 = projectionDigest(compositeProjection)
  const compositeResponse = resealV1Response(v1Fixture.composite_response, compositeRequest, operation, heads, compositeProjection)
  const compositeDurable = durableRecord(compositeResponse, 'response', operation, checkpoint, 4, componentDurables.at(-1).record_digest_sha256, compositeRequest.record_digest_sha256, compositeResponse.record_digest_sha256, null)
  const attestation = clone(v1Fixture.append_revalidation_attestation)
  Object.assign(attestation, { attestation_code: `attestation.${operation.operation_id}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, composite_response_record_digest_sha256: compositeResponse.record_digest_sha256, runtime_generation: generation, subject: resolverSubject, observed_at: operation.authorized_at, completed_at: operation.authorized_at, source_heads: heads, record_digest_sha256: ZERO })
  seal(attestation); validateByFile('append-revalidation-attestation-v1.schema.json', attestation)
  const attestationDurable = durableRecord(attestation, 'append_attestation', operation, checkpoint, 5, compositeDurable.record_digest_sha256, compositeRequest.record_digest_sha256, compositeResponse.record_digest_sha256, attestation.record_digest_sha256)
  return { heads, snapshot, componentRequests, componentResponses, componentDurables, componentAttestations: componentResponses.map((response, index) => ({ resolver_kind_code: response.resolver_kind_code, component_response_record_digest_sha256: response.record_digest_sha256, component_response_durable_record_digest_sha256: componentDurables[index].record_digest_sha256 })), compositeRequest, compositeResponse, compositeDurable, attestation, attestationDurable }
}

function makeInitialAnchor(sourceHeads) {
  const checkpoint = seal({ format: 'jedi-atlas-recovery-resolver-checkpoint-record', format_version: '1.1.0', checkpoint_code: 'checkpoint.progression.anchor', checkpoint_kind_code: 'bootstrap', sequence: 1, predecessor_record_digest_sha256: null, operation_id: 'operation.progression.anchor', operation_nonce: 'a'.repeat(64), runtime_generation: generation, semantic_actor: verifier, persistence_actor: broker, observed_at: '2030-01-01T00:09:59.700Z', persisted_at: '2030-01-01T00:09:59.800Z', source_heads: sourceHeads, composite_response_record_digest_sha256: null, append_attestation_record_digest_sha256: null, bootstrap_permit_record_digest_sha256: 'b'.repeat(64), technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateByFile('checkpoint-record-v1-1.schema.json', checkpoint)
  const receipt = seal({ format: 'jedi-atlas-recovery-resolver-append-receipt', format_version: '1.1.0', receipt_code: 'receipt.progression.anchor', namespace_code: 'd9.resolver.checkpoints.v1.1', expected_predecessor: { namespace_code: 'd9.resolver.checkpoints.v1.1', sequence: 0, record_digest_sha256: null }, persisted_head: { namespace_code: 'd9.resolver.checkpoints.v1.1', sequence: 1, record_digest_sha256: checkpoint.record_digest_sha256 }, payload_record_digest_sha256: checkpoint.record_digest_sha256, persistence_actor: broker, accepted_at: checkpoint.persisted_at, persisted_at: checkpoint.persisted_at, record_digest_sha256: ZERO })
  validateByFile('append-receipt-v1-1.schema.json', receipt)
  return { checkpoint, receipt, reference: { checkpoint_contract_version: '1.1.0', checkpoint_namespace_code: 'd9.resolver.checkpoints.v1.1', checkpoint_sequence: 1, checkpoint_record_digest_sha256: checkpoint.record_digest_sha256, checkpoint_append_receipt_record_digest_sha256: receipt.record_digest_sha256, source_heads: clone(sourceHeads), source_heads_digest_sha256: canonicalSha256(sourceHeads) } }
}

function d940Head(heads) { return heads.find((item) => item.source_namespace_code === 'd940.global.control-journal.v1') }
function expectedPosition(preHead, assessment) { return { journal_namespace_code: 'd940.global.control-journal.v1', predecessor_receipt_sequence: preHead.head_sequence, predecessor_receipt_record_digest_sha256: preHead.head_digest_sha256, target_receipt_sequence: preHead.head_sequence + 1, target_format: assessment.format, target_record_code: assessment.record_code, target_record_digest_sha256: assessment.record_digest_sha256, target_subject_identity_sha256: assessment.subject.subject_identity_sha256 } }
function expectedClassification(assessment) { if (assessment.control_state_code !== 'linear_complete') return 'human_decision_required'; if (assessment.inventory_state_code === 'contradictory' || assessment.access_state_code === 'contradictory') return 'human_decision_required'; if (['active_or_unknown', 'termination_pending'].includes(assessment.access_state_code)) return 'retain_and_hold'; if (['incomplete', 'unavailable'].includes(assessment.inventory_state_code)) return 'reconciliation_required'; return d940Classifications.recovery_boundary_defaults.find((item) => item.crash_boundary_code === assessment.crash_boundary_code)?.classification_code }
function makeAssessment(operation, evidence) {
  const assessment = seal({ format: 'jedi-atlas-d940-recovery-assessment', format_version: '1.0.0', record_code: `recovery.assessment.${operation.operation_id.split('.').at(-1)}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, subject: d940Subject, snapshot_digest_sha256: canonicalSha256(evidence.snapshot), snapshot: clone(evidence.snapshot), crash_boundary_code: 'after_receipt_before_journal_link', inventory_state_code: 'complete', access_state_code: 'none_confirmed', control_state_code: 'linear_complete', classification_code: 'reconciliation_required', action_execution_code: 'none_classification_only', recovery_authority_present: false, semantic_actor: d940Verifier, persistence_actor: d940Broker, knowledge_boundary: { effective_at: operation.authorized_at, recorded_at: operation.assessment_recorded_at, persisted_at: operation.assessment_persisted_at, journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: d940Head(evidence.heads).head_sequence + 1 }, record_digest_sha256: ZERO })
  validateByFile('recovery-assessment-v1.schema.json', assessment); assert.equal(expectedClassification(assessment), assessment.classification_code); assert.equal(assessment.snapshot_digest_sha256, canonicalSha256(assessment.snapshot)); assert.deepEqual(assessment.snapshot, evidence.compositeResponse.projection.snapshot); assert.deepEqual(assessment.semantic_actor, d940Verifier); assert.deepEqual(assessment.persistence_actor, d940Broker); return assessment
}
function makeAppendRequest(operation, checkpoint, evidence, assessment) {
  const request = { format: 'jedi-atlas-recovery-checkpoint-assessment-append-request', format_version: '1.2.0', request_code: `progression.request.${operation.operation_id.split('.').at(-1)}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, idempotency_key_sha256: ZERO, runtime_generation: generation, subject: resolverSubject, prior_checkpoint: clone(checkpoint), component_resolution_attestations: clone(evidence.componentAttestations), composite_response_record_digest_sha256: evidence.compositeResponse.record_digest_sha256, composite_response_durable_record_digest_sha256: evidence.compositeDurable.record_digest_sha256, composite_append_attestation_record_digest_sha256: evidence.attestation.record_digest_sha256, composite_append_attestation_durable_record_digest_sha256: evidence.attestationDurable.record_digest_sha256, assessment_format: assessment.format, assessment_record_code: assessment.record_code, assessment_canonical_utf8: canonicalize(assessment), assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: expectedPosition(d940Head(checkpoint.source_heads), assessment), pre_append_source_heads: clone(checkpoint.source_heads), pre_append_source_heads_digest_sha256: canonicalSha256(checkpoint.source_heads), authorized_delta_namespace_code: 'd940.global.control-journal.v1', semantic_actor: verifier, broker_recipient: broker, authorized_at: operation.authorized_at, append_revalidate_by: operation.append_revalidate_by, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO }
  request.idempotency_key_sha256 = canonicalSha256({ operation_id: request.operation_id, operation_nonce: request.operation_nonce, prior_checkpoint_record_digest_sha256: checkpoint.checkpoint_record_digest_sha256, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: request.expected_d940_append_position })
  return seal(request)
}

function validateAppendRequest(request, { checkpoint, evidence, assessment }) {
  validateByFile('assessment-append-request-v1-2.schema.json', request); assertDigest(request); assertGeneration(request.runtime_generation); assertActor(request.semantic_actor, 'independent_verifier'); assertActor(request.broker_recipient, 'journal_broker')
  assertHeads(request.prior_checkpoint.source_heads); if (!same(request.prior_checkpoint, checkpoint) || !same(request.pre_append_source_heads, checkpoint.source_heads) || request.pre_append_source_heads_digest_sha256 !== canonicalSha256(checkpoint.source_heads)) fail('PRIOR_CHECKPOINT_REJECTED')
  if (!same(request.component_resolution_attestations, evidence.componentAttestations) || request.composite_response_record_digest_sha256 !== evidence.compositeResponse.record_digest_sha256 || request.composite_response_durable_record_digest_sha256 !== evidence.compositeDurable.record_digest_sha256 || request.composite_append_attestation_record_digest_sha256 !== evidence.attestation.record_digest_sha256 || request.composite_append_attestation_durable_record_digest_sha256 !== evidence.attestationDurable.record_digest_sha256) fail('EVIDENCE_LINK_REJECTED')
  for (let index = 0; index < evidence.componentResponses.length; index += 1) { assert.equal(evidence.componentDurables[index].payload_record_digest_sha256, evidence.componentResponses[index].record_digest_sha256); assert.equal(canonicalize(evidence.componentResponses[index]), evidence.componentDurables[index].payload_canonical_utf8) }
  const opened = parseStrictJson(Buffer.from(request.assessment_canonical_utf8)); if (!same(opened, assessment) || canonicalize(opened) !== request.assessment_canonical_utf8 || request.assessment_record_digest_sha256 !== assessment.record_digest_sha256 || assessment.snapshot_digest_sha256 !== evidence.compositeResponse.projection.snapshot_digest_sha256 || !same(assessment.snapshot, evidence.compositeResponse.projection.snapshot) || expectedClassification(assessment) !== assessment.classification_code) fail('ASSESSMENT_REJECTED')
  if (!same(request.expected_d940_append_position, expectedPosition(d940Head(checkpoint.source_heads), assessment))) fail('APPEND_POSITION_REJECTED')
  if (request.idempotency_key_sha256 !== canonicalSha256({ operation_id: request.operation_id, operation_nonce: request.operation_nonce, prior_checkpoint_record_digest_sha256: checkpoint.checkpoint_record_digest_sha256, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: request.expected_d940_append_position })) fail('IDEMPOTENCY_REJECTED')
  if (request.authorized_at !== evidence.attestation.completed_at || request.append_revalidate_by !== evidence.compositeResponse.append_revalidate_by || ms(request.authorized_at) >= ms(request.append_revalidate_by)) fail('APPEND_FRESHNESS_REJECTED')
}

function makeD940Receipt(operation, assessment, position) { const receipt = seal({ format: 'jedi-atlas-d940-journal-append-receipt', format_version: '1.0.0', record_code: `receipt.${assessment.record_code}`, journal_namespace_code: position.journal_namespace_code, receipt_sequence: position.target_receipt_sequence, previous_receipt_record_digest_sha256: position.predecessor_receipt_record_digest_sha256, target_format: assessment.format, target_record_code: assessment.record_code, target_record_digest_sha256: assessment.record_digest_sha256, target_subject_identity_sha256: assessment.subject.subject_identity_sha256, operation_id: assessment.operation_id, operation_nonce: assessment.operation_nonce, semantic_actor: d940Verifier, persistence_actor: d940Broker, semantic_recorded_at: assessment.knowledge_boundary.recorded_at, persisted_at: operation.assessment_persisted_at, durability_state_code: 'record_and_receipt_flushed_in_protected_d940_ledger', record_digest_sha256: ZERO }); validateByFile('journal-append-receipt-v1.schema.json', receipt); return receipt }
function appendAssessmentToSourceState(sourceState, assessment, receipt) { const next = clone(sourceState); next.sources.control_records.known_through_receipt_sequence = receipt.receipt_sequence; next.sources.control_records.records.push({ receipt_sequence: receipt.receipt_sequence, record_kind_code: 'recovery_assessment', record_digest_sha256: assessment.record_digest_sha256 }); const boundary = next.sources.source_boundaries.find((item) => item.source_namespace_code === 'd940.global.control-journal.v1'); boundary.head_sequence = receipt.receipt_sequence; boundary.head_persisted_at = receipt.persisted_at; return next }
function validateD940Receipt(receipt, assessment, position) { validateByFile('journal-append-receipt-v1.schema.json', receipt); assertDigest(receipt); if (receipt.journal_namespace_code !== position.journal_namespace_code || receipt.receipt_sequence !== position.target_receipt_sequence || receipt.previous_receipt_record_digest_sha256 !== position.predecessor_receipt_record_digest_sha256 || receipt.target_format !== assessment.format || receipt.target_record_code !== assessment.record_code || receipt.target_record_digest_sha256 !== assessment.record_digest_sha256 || receipt.target_subject_identity_sha256 !== assessment.subject.subject_identity_sha256 || receipt.operation_id !== assessment.operation_id || receipt.operation_nonce !== assessment.operation_nonce || !same(receipt.semantic_actor, assessment.semantic_actor) || !same(receipt.persistence_actor, assessment.persistence_actor) || receipt.semantic_recorded_at !== assessment.knowledge_boundary.recorded_at || receipt.persisted_at !== assessment.knowledge_boundary.persisted_at) fail('D940_RECEIPT_REJECTED') }
function makeBrokerReceipt(operation, request, assessment, d940Receipt, postHead) { return seal({ format: 'jedi-atlas-recovery-checkpoint-assessment-append-broker-receipt', format_version: '1.2.0', receipt_code: `progression.broker.${operation.operation_id.split('.').at(-1)}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: generation, subject: resolverSubject, append_request_record_digest_sha256: request.record_digest_sha256, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: clone(request.expected_d940_append_position), pre_append_source_head: clone(d940Head(request.pre_append_source_heads)), d940_append_receipt_canonical_utf8: canonicalize(d940Receipt), d940_append_receipt_record_digest_sha256: d940Receipt.record_digest_sha256, post_append_source_head: clone(postHead), source_head_derivation_profile_code: 'frozen_v1_raw_payload_commitments', post_head_observer_actor: verifier, broker_actor: broker, accepted_at: operation.post_head_observed_at, assessment_persisted_at: operation.assessment_persisted_at, post_head_observed_at: operation.post_head_observed_at, exact_single_append: true, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO }) }
function validateBrokerReceipt(receipt, { request, assessment, d940Receipt, sourceStateAfter }) { validateByFile('assessment-append-broker-receipt-v1-2.schema.json', receipt); assertDigest(receipt); assertGeneration(receipt.runtime_generation); assertActor(receipt.post_head_observer_actor, 'independent_verifier'); assertActor(receipt.broker_actor, 'journal_broker'); validateD940Receipt(d940Receipt, assessment, request.expected_d940_append_position); const opened = parseStrictJson(Buffer.from(receipt.d940_append_receipt_canonical_utf8)); if (!same(opened, d940Receipt) || receipt.d940_append_receipt_canonical_utf8 !== canonicalize(d940Receipt) || receipt.append_request_record_digest_sha256 !== request.record_digest_sha256 || receipt.assessment_record_digest_sha256 !== assessment.record_digest_sha256 || !same(receipt.expected_d940_append_position, request.expected_d940_append_position) || !same(receipt.pre_append_source_head, d940Head(request.pre_append_source_heads)) || !same(receipt.post_append_source_head, d940Head(deriveSourceHeads(sourceStateAfter))) || receipt.assessment_persisted_at !== d940Receipt.persisted_at || ms(receipt.assessment_persisted_at) > ms(receipt.post_head_observed_at) || ms(receipt.post_head_observed_at) > ms(receipt.accepted_at)) fail('BROKER_RECEIPT_REJECTED') }

function emptyHead(namespace_code) { return { namespace_code, sequence: 0, record_digest_sha256: null } }
function createModel() { return { protected: { 'd9.resolver.progression-intents.v1.2': [], 'd9.resolver.checkpoint-transitions.v1.2': [] } } }
function protectedHead(model, namespace) { const retained = model.protected[namespace].at(-1); return retained ? { namespace_code: namespace, sequence: model.protected[namespace].length, record_digest_sha256: retained.record.record_digest_sha256 } : emptyHead(namespace) }
function recordIdentity(record) { if (record.format.endsWith('append-request')) return [`request:${record.request_code}`, `request-operation:${record.operation_id}`, `idempotency:${record.idempotency_key_sha256}`]; if (record.format.endsWith('broker-receipt')) return [`receipt:${record.receipt_code}`, `broker-operation:${record.operation_id}`, `broker-request:${record.append_request_record_digest_sha256}`]; return [`transition:${record.transition_code}`, `transition-sequence:${record.transition_sequence}`, `transition-operation:${record.operation_id}`, `transition-predecessor:${record.predecessor_checkpoint_record_digest_sha256}`] }
function makeProtectedReceipt(namespace, record, predecessor, persistedAt, sourceHead = null) { return seal({ format: 'jedi-atlas-recovery-checkpoint-progression-append-receipt', format_version: '1.2.0', receipt_code: `progression.receipt.${namespace.split('.').at(-2)}.${predecessor.sequence + 1}`, namespace_code: namespace, expected_predecessor: clone(predecessor), persisted_head: { namespace_code: namespace, sequence: predecessor.sequence + 1, record_digest_sha256: record.record_digest_sha256 }, payload_record_digest_sha256: record.record_digest_sha256, source_head_compare_and_append: sourceHead ? { source_namespace_code: 'd940.global.control-journal.v1', expected_head: clone(sourceHead), observed_head_at_persist: clone(sourceHead) } : null, source_head_observer_actor: sourceHead ? clone(verifier) : null, persistence_actor: broker, accepted_at: persistedAt, persisted_at: persistedAt, record_digest_sha256: ZERO }) }
function validateProtectedReceipt(receipt, record, expectedHead, currentD940Head = null) { validateByFile('protected-append-receipt-v1-2.schema.json', receipt); assertDigest(receipt); assertActor(receipt.persistence_actor, 'journal_broker'); if (receipt.namespace_code !== expectedHead.namespace_code || !same(receipt.expected_predecessor, expectedHead) || receipt.persisted_head.sequence !== expectedHead.sequence + 1 || receipt.persisted_head.record_digest_sha256 !== record.record_digest_sha256 || receipt.payload_record_digest_sha256 !== record.record_digest_sha256) fail('PROTECTED_RECEIPT_REJECTED'); if (receipt.namespace_code === 'd9.resolver.checkpoint-transitions.v1.2') { assertActor(receipt.source_head_observer_actor, 'independent_verifier'); if (!currentD940Head || !same(receipt.source_head_compare_and_append.expected_head, currentD940Head) || !same(receipt.source_head_compare_and_append.observed_head_at_persist, currentD940Head)) fail('SOURCE_HEAD_CAS_REJECTED') } }
function appendProtected(model, namespace, record, receipt, { currentD940Head = null, injectFailure = false } = {}) { const identities = recordIdentity(record); const entries = model.protected[namespace]; for (const entry of entries) { const overlap = recordIdentity(entry.record).some((identity) => identities.includes(identity)); if (overlap) { if (same(entry.record, record) && same(entry.receipt, receipt)) return 'exact_replay_no_op'; fail('REPLAY_COLLISION') } } const head = protectedHead(model, namespace); validateProtectedReceipt(receipt, record, head, currentD940Head); const before = canonicalize(model); if (injectFailure) { assert.equal(canonicalize(model), before); fail('INJECTED_ATOMIC_FAILURE') } entries.push({ record: clone(record), receipt: clone(receipt) }); return 'persisted' }

function makeTransition(operation, checkpoint, evidence, request, requestReceipt, assessment, d940Receipt, brokerReceipt, brokerStoreReceipt, postHeads) { return seal({ format: 'jedi-atlas-recovery-checkpoint-transition', format_version: '1.2.0', transition_code: `transition.${operation.operation_id.split('.').at(-1)}`, transition_sequence: checkpoint.checkpoint_sequence + 1, predecessor_checkpoint_record_digest_sha256: checkpoint.checkpoint_record_digest_sha256, predecessor_checkpoint_append_receipt_record_digest_sha256: checkpoint.checkpoint_append_receipt_record_digest_sha256, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: generation, subject: resolverSubject, prior_checkpoint: clone(checkpoint), component_resolution_attestations: clone(evidence.componentAttestations), composite_response_record_digest_sha256: evidence.compositeResponse.record_digest_sha256, composite_response_durable_record_digest_sha256: evidence.compositeDurable.record_digest_sha256, composite_append_attestation_record_digest_sha256: evidence.attestation.record_digest_sha256, composite_append_attestation_durable_record_digest_sha256: evidence.attestationDurable.record_digest_sha256, append_request_record_digest_sha256: request.record_digest_sha256, append_request_protected_receipt_record_digest_sha256: requestReceipt.record_digest_sha256, append_broker_receipt_record_digest_sha256: brokerReceipt.record_digest_sha256, append_broker_receipt_protected_receipt_record_digest_sha256: brokerStoreReceipt.record_digest_sha256, assessment_record_code: assessment.record_code, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: clone(request.expected_d940_append_position), d940_append_receipt_record_digest_sha256: d940Receipt.record_digest_sha256, pre_append_source_heads: clone(checkpoint.source_heads), post_append_source_heads: clone(postHeads), unchanged_source_namespace_codes: unchangedOrder, permitted_d940_delta: { source_namespace_code: 'd940.global.control-journal.v1', before: clone(d940Head(checkpoint.source_heads)), after: clone(d940Head(postHeads)), delta_code: 'single_authorized_assessment_append' }, post_append_source_heads_digest_sha256: canonicalSha256(postHeads), finalizer_actor: launcher, semantic_actor: verifier, persistence_actor: broker, attestation_completed_at: evidence.attestation.completed_at, append_authorized_until: request.append_revalidate_by, assessment_persisted_at: d940Receipt.persisted_at, finalizer_observed_at: operation.finalizer_observed_at, persisted_at: operation.transition_persisted_at, freshness_boundary_code: 'assessment_append_within_attestation_window_and_exact_post_head_still_current', technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO }) }
function validateTransition(transition, context) { const { checkpoint, evidence, request, requestReceipt, assessment, d940Receipt, brokerReceipt, brokerStoreReceipt, currentHeads } = context; validateByFile('checkpoint-transition-v1-2.schema.json', transition); assertDigest(transition); assertActor(transition.finalizer_actor, 'trusted_launcher'); assertActor(transition.semantic_actor, 'independent_verifier'); assertActor(transition.persistence_actor, 'journal_broker'); assertHeads(currentHeads); if (transition.transition_sequence !== checkpoint.checkpoint_sequence + 1 || transition.predecessor_checkpoint_record_digest_sha256 !== checkpoint.checkpoint_record_digest_sha256 || transition.predecessor_checkpoint_append_receipt_record_digest_sha256 !== checkpoint.checkpoint_append_receipt_record_digest_sha256 || !same(transition.prior_checkpoint, checkpoint) || transition.append_request_record_digest_sha256 !== request.record_digest_sha256 || transition.append_request_protected_receipt_record_digest_sha256 !== requestReceipt.record_digest_sha256 || transition.append_broker_receipt_record_digest_sha256 !== brokerReceipt.record_digest_sha256 || transition.append_broker_receipt_protected_receipt_record_digest_sha256 !== brokerStoreReceipt.record_digest_sha256 || transition.d940_append_receipt_record_digest_sha256 !== d940Receipt.record_digest_sha256 || !same(transition.component_resolution_attestations, evidence.componentAttestations) || !same(transition.pre_append_source_heads, checkpoint.source_heads) || !same(transition.post_append_source_heads, currentHeads)) fail('TRANSITION_LINK_REJECTED'); for (const namespace of unchangedOrder) if (!same(transition.pre_append_source_heads.find((head) => head.source_namespace_code === namespace), transition.post_append_source_heads.find((head) => head.source_namespace_code === namespace))) fail('UNEXPLAINED_HEAD_CHANGE'); const before = d940Head(transition.pre_append_source_heads); const after = d940Head(transition.post_append_source_heads); if (!same(transition.permitted_d940_delta.before, before) || !same(transition.permitted_d940_delta.after, after) || after.head_sequence !== before.head_sequence + 1 || !same(after, brokerReceipt.post_append_source_head) || transition.post_append_source_heads_digest_sha256 !== canonicalSha256(currentHeads)) fail('WRONG_D940_DELTA'); if (transition.assessment_record_digest_sha256 !== assessment.record_digest_sha256 || ms(transition.attestation_completed_at) > ms(transition.assessment_persisted_at) || ms(transition.assessment_persisted_at) > ms(transition.append_authorized_until) || ms(transition.assessment_persisted_at) > ms(transition.finalizer_observed_at) || ms(transition.finalizer_observed_at) > ms(transition.persisted_at)) fail('TRANSITION_TIME_REJECTED') }
function nextCheckpoint(transition, receipt) { return { checkpoint_contract_version: '1.2.0', checkpoint_namespace_code: 'd9.resolver.checkpoint-transitions.v1.2', checkpoint_sequence: transition.transition_sequence, checkpoint_record_digest_sha256: transition.record_digest_sha256, checkpoint_append_receipt_record_digest_sha256: receipt.record_digest_sha256, source_heads: clone(transition.post_append_source_heads), source_heads_digest_sha256: transition.post_append_source_heads_digest_sha256 } }

const model = createModel()
let sourceState = clone(sourceStateBase)
const anchor = makeInitialAnchor(deriveSourceHeads(sourceState))
let checkpoint = anchor.reference
const built = []
for (const operation of fixture.operations) {
  const evidence = makeEvidence(operation, sourceState, checkpoint)
  const assessment = makeAssessment(operation, evidence)
  const request = makeAppendRequest(operation, checkpoint, evidence, assessment)
  validateAppendRequest(request, { checkpoint, evidence, assessment })
  const requestHead = protectedHead(model, 'd9.resolver.progression-intents.v1.2')
  const requestReceipt = makeProtectedReceipt('d9.resolver.progression-intents.v1.2', request, requestHead, operation.authorized_at)
  assert.equal(appendProtected(model, 'd9.resolver.progression-intents.v1.2', request, requestReceipt), 'persisted')
  const d940Receipt = makeD940Receipt(operation, assessment, request.expected_d940_append_position)
  validateD940Receipt(d940Receipt, assessment, request.expected_d940_append_position)
  sourceState = appendAssessmentToSourceState(sourceState, assessment, d940Receipt)
  const sourceStateAfter = clone(sourceState)
  const postHeads = deriveSourceHeads(sourceStateAfter)
  const brokerReceipt = makeBrokerReceipt(operation, request, assessment, d940Receipt, d940Head(postHeads))
  validateBrokerReceipt(brokerReceipt, { request, assessment, d940Receipt, sourceStateAfter })
  const brokerHead = protectedHead(model, 'd9.resolver.progression-intents.v1.2')
  const brokerStoreReceipt = makeProtectedReceipt('d9.resolver.progression-intents.v1.2', brokerReceipt, brokerHead, operation.post_head_observed_at)
  assert.equal(appendProtected(model, 'd9.resolver.progression-intents.v1.2', brokerReceipt, brokerStoreReceipt), 'persisted')
  const transition = makeTransition(operation, checkpoint, evidence, request, requestReceipt, assessment, d940Receipt, brokerReceipt, brokerStoreReceipt, postHeads)
  validateTransition(transition, { checkpoint, evidence, request, requestReceipt, assessment, d940Receipt, brokerReceipt, brokerStoreReceipt, currentHeads: postHeads })
  const transitionHead = protectedHead(model, 'd9.resolver.checkpoint-transitions.v1.2')
  const transitionReceipt = makeProtectedReceipt('d9.resolver.checkpoint-transitions.v1.2', transition, transitionHead, operation.transition_persisted_at, d940Head(postHeads))
  assert.equal(appendProtected(model, 'd9.resolver.checkpoint-transitions.v1.2', transition, transitionReceipt, { currentD940Head: d940Head(postHeads) }), 'persisted')
  assert.equal(appendProtected(model, 'd9.resolver.checkpoint-transitions.v1.2', transition, transitionReceipt, { currentD940Head: d940Head(postHeads) }), 'exact_replay_no_op')
  built.push({ operation, checkpoint, evidence, assessment, request, requestReceipt, d940Receipt, brokerReceipt, brokerStoreReceipt, sourceStateAfter, postHeads, transition, transitionReceipt })
  checkpoint = nextCheckpoint(transition, transitionReceipt)
}
assert.equal(built.length, 2)
assert.equal(built[1].checkpoint.checkpoint_record_digest_sha256, built[0].transition.record_digest_sha256)
assert.equal(built[1].assessment.snapshot.known_through_receipt_sequence, built[0].d940Receipt.receipt_sequence)
assert.equal(d940Head(built[1].postHeads).head_sequence, d940Head(built[0].postHeads).head_sequence + 1)

// Response loss after the D9.4 append is reconstructable from retained request, assessment, receipt and raw source state only.
function reconstructBrokerReceipt(item) { const rebuilt = makeBrokerReceipt(item.operation, item.request, item.assessment, item.d940Receipt, d940Head(deriveSourceHeads(item.sourceStateAfter))); validateBrokerReceipt(rebuilt, { request: item.request, assessment: item.assessment, d940Receipt: item.d940Receipt, sourceStateAfter: item.sourceStateAfter }); return rebuilt }
assert.deepEqual(reconstructBrokerReceipt(built[0]), built[0].brokerReceipt)
assert.deepEqual(reconstructBrokerReceipt(built[1]), built[1].brokerReceipt)

const first = built[0]
const movedHead = clone(d940Head(first.postHeads)); movedHead.head_sequence += 1; movedHead.head_digest_sha256 = 'f'.repeat(64)
const staleTransitionReceipt = makeProtectedReceipt('d9.resolver.checkpoint-transitions.v1.2', first.transition, emptyHead('d9.resolver.checkpoint-transitions.v1.2'), first.operation.transition_persisted_at, d940Head(first.postHeads))
assert.throws(() => validateProtectedReceipt(staleTransitionReceipt, first.transition, emptyHead('d9.resolver.checkpoint-transitions.v1.2'), movedHead), /SOURCE_HEAD_CAS_REJECTED/)

const requestMutations = [
  ['component_missing', (x) => x.component_resolution_attestations.pop()],
  ['component_reordered', (x) => x.component_resolution_attestations.reverse()],
  ['prior_checkpoint_receipt', (x) => { x.prior_checkpoint.checkpoint_append_receipt_record_digest_sha256 = 'f'.repeat(64) }],
  ['assessment_bytes', (x) => { x.assessment_canonical_utf8 += ' ' }],
  ['idempotency', (x) => { x.idempotency_key_sha256 = 'f'.repeat(64) }],
  ['wrong_verifier', (x) => { x.semantic_actor = clone(broker) }],
  ['wrong_generation', (x) => { x.runtime_generation.binding_generation = 2 }],
  ['expired', (x) => { x.append_revalidate_by = x.authorized_at }],
  ['authority', (x) => { x.authority_granted = true }],
]
for (const [label, mutate] of requestMutations) { const changed = clone(first.request); mutate(changed); seal(changed); assert.throws(() => validateAppendRequest(changed, { checkpoint: first.checkpoint, evidence: first.evidence, assessment: first.assessment }), undefined, label) }
const brokerMutations = [
  ['observer', (x) => { x.post_head_observer_actor = clone(broker) }],
  ['receipt_target', (x) => { const opened = JSON.parse(x.d940_append_receipt_canonical_utf8); opened.target_format = 'wrong'; x.d940_append_receipt_canonical_utf8 = canonicalize(opened) }],
  ['post_head', (x) => { x.post_append_source_head.head_digest_sha256 = 'f'.repeat(64) }],
  ['profile', (x) => { x.source_head_derivation_profile_code = 'rolling' }],
]
for (const [label, mutate] of brokerMutations) { const changed = clone(first.brokerReceipt); mutate(changed); seal(changed); assert.throws(() => validateBrokerReceipt(changed, { request: first.request, assessment: first.assessment, d940Receipt: first.d940Receipt, sourceStateAfter: first.sourceStateAfter }), undefined, label) }
const transitionMutations = [
  ['request_receipt', (x) => { x.append_request_protected_receipt_record_digest_sha256 = 'f'.repeat(64) }],
  ['broker_store_receipt', (x) => { x.append_broker_receipt_protected_receipt_record_digest_sha256 = 'f'.repeat(64) }],
  ['predecessor_receipt', (x) => { x.predecessor_checkpoint_append_receipt_record_digest_sha256 = 'f'.repeat(64) }],
  ['unchanged_head', (x) => { x.post_append_source_heads[0].head_digest_sha256 = 'f'.repeat(64) }],
  ['extra_delta', (x) => { d940Head(x.post_append_source_heads).head_sequence += 1 }],
  ['wrong_finalizer', (x) => { x.finalizer_actor = clone(verifier) }],
]
for (const [label, mutate] of transitionMutations) { const changed = clone(first.transition); mutate(changed); seal(changed); assert.throws(() => validateTransition(changed, { ...first, currentHeads: first.postHeads }), undefined, label) }

const collisionModel = createModel()
const initialReceipt = makeProtectedReceipt('d9.resolver.progression-intents.v1.2', first.request, emptyHead('d9.resolver.progression-intents.v1.2'), first.operation.authorized_at)
appendProtected(collisionModel, 'd9.resolver.progression-intents.v1.2', first.request, initialReceipt)
for (const mutate of [
  (x) => { x.operation_id = 'operation.changed' },
  (x) => { x.request_code = 'request.changed' },
  (x) => { x.request_code = 'request.other'; x.operation_id = 'operation.other' },
]) { const changed = clone(first.request); mutate(changed); seal(changed); const receipt = makeProtectedReceipt('d9.resolver.progression-intents.v1.2', changed, protectedHead(collisionModel, 'd9.resolver.progression-intents.v1.2'), first.operation.authorized_at); assert.throws(() => appendProtected(collisionModel, 'd9.resolver.progression-intents.v1.2', changed, receipt), /REPLAY_COLLISION/) }
const rollbackModel = createModel()
const rollbackReceipt = makeProtectedReceipt('d9.resolver.progression-intents.v1.2', first.request, emptyHead('d9.resolver.progression-intents.v1.2'), first.operation.authorized_at)
const beforeRollback = canonicalize(rollbackModel)
assert.throws(() => appendProtected(rollbackModel, 'd9.resolver.progression-intents.v1.2', first.request, rollbackReceipt, { injectFailure: true }), /INJECTED_ATOMIC_FAILURE/)
assert.equal(canonicalize(rollbackModel), beforeRollback)

function makeResult(outcome, error, transition = null, receipt = null) { return seal({ format: 'jedi-atlas-recovery-checkpoint-progression-finalization-result', format_version: '1.2.0', result_code: `progression.result.${outcome}`, operation_id: first.operation.operation_id, append_request_record_digest_sha256: first.request.record_digest_sha256, outcome_code: outcome, error_code: error, transition_record_digest_sha256: transition?.record_digest_sha256 ?? null, transition_append_receipt_record_digest_sha256: receipt?.record_digest_sha256 ?? null, observed_at: first.operation.transition_persisted_at, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO }) }
for (const value of [makeResult('persisted', null, first.transition, first.transitionReceipt), makeResult('exact_replay_no_op', null, first.transition, first.transitionReceipt), makeResult('not_yet_appendable', 'assessment_absent'), makeResult('reconciliation_required', 'head_mismatch'), makeResult('rejected', 'replay_collision')]) validateByFile('finalization-result-v1-2.schema.json', value)
for (const value of [makeResult('persisted', 'head_mismatch', first.transition, first.transitionReceipt), makeResult('not_yet_appendable', null), makeResult('rejected', 'replay_collision', first.transition, first.transitionReceipt)]) assert.throws(() => validateByFile('finalization-result-v1-2.schema.json', value))

const executedMutationCodes = new Set([...requestMutations, ...brokerMutations, ...transitionMutations].map(([code]) => code))
for (const item of invalidFixture.mutations) assert.ok(executedMutationCodes.has(item.mutation_code), `declared mutation executed: ${item.mutation_code}`)
const golden = readJson(path.join(root, 'fixtures/golden-vectors-v1-2.json'))
for (const vector of golden.vectors) { assert.equal(canonicalize(vector.input), vector.canonical_utf8, `${vector.vector_code} canonical form`); assert.equal(crypto.createHash('sha256').update(Buffer.from(vector.canonical_utf8)).digest('hex'), vector.sha256, `${vector.vector_code} hash`) }

const catalog = readJson(path.join(root, 'contract-catalog-v1-2.json'))
const inventory = readJson(path.join(root, 'root-inventory-v1-2.json'))
assert.equal(catalog.format_version, '1.2.0'); assert.equal(catalog.status_code, 'design_only_contract_freeze'); assert.equal(catalog.supersedes_scope, 'post_assessment_checkpoint_progression_only'); assert.equal(catalog.instance_policy.runtime_implementation_authorized, false); assert.equal(catalog.instance_policy.recovery_actions_authorized, false); assert.equal(catalog.instance_policy.legal_conclusions_authorized, false)
const disk = []
function walk(directory, prefix = '') { for (const entry of fs.readdirSync(directory, { withFileTypes: true })) { const relative = path.posix.join(prefix, entry.name); if (entry.isDirectory()) walk(path.join(directory, entry.name), relative); else if (relative !== 'root-inventory-v1-2.json') disk.push(relative) } }
walk(root); disk.sort(); assert.deepEqual(inventory.files.map((item) => item.path), disk)
for (const item of inventory.files) assert.equal(rawSha256(path.join(root, item.path)), item.raw_sha256, item.path)
for (const item of [...catalog.schemas, ...catalog.registries, ...catalog.fixtures, ...(catalog.validators ?? [])]) assert.equal(rawSha256(path.resolve(root, item.file)), item.raw_sha256, item.file)

console.log('D9 recovery checkpoint progression v1.2 validation passed')
console.log('  frozen v1 source derivation, genuine v1/v1.1 artifacts and D9.4 semantics passed')
console.log('  two consecutive receipt-bound assessments and append-time source-head CAS passed')
console.log('  restart reconstruction, replay identity, crash rollback and declared mutations passed')
console.log('  technical journal continuity only; no recovery or legal authority granted')
