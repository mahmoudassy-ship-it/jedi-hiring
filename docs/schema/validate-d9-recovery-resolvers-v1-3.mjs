import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { canonicalSha256, canonicalize, parseStrictJson, sha256Bytes } from '../../d9/control-plane/canonical.mjs'
import { loadApprovedContractSet } from '../../d9/control-plane/contracts.mjs'
import { createGenerationFixture, verifyFixture } from '../../tests/d9-1-support/runtime-fixture.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const project = path.resolve(here, '../..')
const root = path.join(here, 'd9-recovery-resolvers-v1-3')
const d90Root = path.join(here, 'd9-0')
const v1Root = path.join(here, 'd9-recovery-resolvers')
const v11Root = path.join(here, 'd9-recovery-resolvers-v1-1')
const d940Root = path.join(here, 'd9-4-0')
const ZERO = '0'.repeat(64)

function fail(code, detail = code) { const error = new Error(`${code}: ${detail}`); error.code = code; throw error }
function readJson(file) { return parseStrictJson(fs.readFileSync(file), { maximumBytes: 16 * 1024 * 1024, maximumDepth: 256, maximumMembers: 500_000, contractNumbers: true }) }
function rawSha256(file) { return sha256Bytes(fs.readFileSync(file)) }
function clone(value) { return structuredClone(value) }
function same(left, right) { return canonicalize(left) === canonicalize(right) }
function seal(value) { value.record_digest_sha256 = canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' }); return value }
function ms(value, label = 'time') { const parsed = Date.parse(value); if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) fail('TIME_INVALID', label); return parsed }
function assertDigest(value, label) { assert.equal(value.record_digest_sha256, canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' }), `${label} self digest`) }

const frozen = {
  'docs/schema/d9-recovery-resolvers/contract-catalog-v1.json': 'df33cbf575f8f4b430ef22384f0d73350e521abed6443f07006d13bb3b968ba3',
  'docs/schema/d9-recovery-resolvers/root-inventory-v1.json': '93832dc8a6f12ae030515781169fd8ac9dd5431aa68f62699168469da3da6f31',
  'docs/schema/d9-recovery-resolvers-v1-1/contract-catalog-v1-1.json': 'aa846c01c5d055050c810249316d11eba7a48d1080681f9538be3e71d371bb26',
  'docs/schema/d9-recovery-resolvers-v1-1/root-inventory-v1-1.json': 'b3711db55ed73a1a74621a808014aae35b2e05319e5cf0aeba5df0d62b1933bf',
  'docs/schema/d9-recovery-resolvers-v1-2/contract-catalog-v1-2.json': 'b6fd085a5718fdccc51ae4cfbf10645aaa3a1f79929d9ebe896247350d3ddb3c',
  'docs/schema/d9-recovery-resolvers-v1-2/root-inventory-v1-2.json': '3bc242bbd7147597e9b34aad16293d8e397cb23d4b7b7a6ca3578b371403c1ad',
  'docs/schema/d9-0/contract-catalog-v1.json': 'e0a5663b378453a00626f02961465a60a474e145dd5160bf85a1797cd9316d2a',
  'docs/schema/d9-3-0/contract-catalog-v1.json': 'cd91f67c25941a472b89fe2fa6f19b012714dec96661b65b76ecfacf7f48e87c',
  'docs/schema/d9-4-0/contract-catalog-v1.json': '12da4237efade65cf6e2cc19d2df936e98caf505c8f6d30b38e7df8c4d349ad7',
  'docs/schema/validate-d9-recovery-resolvers.mjs': 'bc36de4475ee6d8b9fd354f80163799f431496ae91765b5dd4903fdde9763ef5',
  'docs/schema/validate-d9-recovery-resolvers-v1-1.mjs': 'f6e8aa1f242198febd6e3b5bfa0a93ddf0f9829bc4850d920a1ca9be941235c5',
  'docs/schema/validate-d9-recovery-resolvers-v1-2.mjs': '4708ae4c43fe8bfd83e13e216b1d5fc8fc15077e6ec38e24eda78f0b859f5ad7',
  'tests/d9-1-support/runtime-fixture.mjs': '421ec225d07b835f1888975b09293941bace35cb12978ea49f8a7ac69002c3e9',
  'd9/control-plane/canonical.mjs': 'e0905b2e87991c67907b63d0a9b5db58c54cc982c2ab603501316ec26d648567',
  'd9/control-plane/contracts.mjs': 'c54a65f1033fd241a7da2728b568f5b92b79dc472810c9e9f6c85b943c0dbded',
  'data/migrations/001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  'data/migrations/002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  'data/migrations/003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
  'data/migrations/004_tranche_1a_foundations.sql': '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
  'data/migrations/005_tranche_2a_source_quarantine.sql': '1f83b484ca998be3bf5756492d4dffd958e2a6b37dbcc837e399226fdf41026b'
}
for (const [relative, digest] of Object.entries(frozen)) assert.equal(rawSha256(path.join(project, relative)), digest, `${relative} frozen`)
for (const validator of ['docs/schema/validate-d9-recovery-resolvers.mjs', 'docs/schema/validate-d9-recovery-resolvers-v1-1.mjs', 'docs/schema/validate-d9-recovery-resolvers-v1-2.mjs']) execFileSync(process.execPath, ['--disable-warning=ExperimentalWarning', validator], { cwd: project, stdio: 'pipe' })

const localSchemaFiles = [
  'common-v1-3.schema.json',
  'source-head-receipt-correspondence-v1-3.schema.json',
  'control-access-projection-v1-3.schema.json',
  'checkpoint-identity-v1-3.schema.json',
  'assessment-append-request-v1-3.schema.json',
  'assessment-append-broker-receipt-v1-3.schema.json',
  'checkpoint-transition-v1-3.schema.json',
  'recovery-assessment-link-v1-3.schema.json',
  'protected-append-receipt-v1-3.schema.json',
  'append-result-v1-3.schema.json'
]
const dependencyFiles = [
  [d90Root, 'common-v1.schema.json'],
  [v1Root, 'common-v1.schema.json'],
  [v11Root, 'common-v1-1.schema.json'],
  [d940Root, 'common-v1.schema.json'],
  [d940Root, 'journal-append-receipt-v1.schema.json'],
  [d940Root, 'recovery-assessment-v1.schema.json']
]
const localSchemas = localSchemaFiles.map((file) => readJson(path.join(root, file)))
const dependencies = dependencyFiles.map(([base, file]) => readJson(path.join(base, file)))
const ajv = new Ajv2020({ allErrors: true, strict: false })
for (const schema of [...dependencies, ...localSchemas]) ajv.addSchema(schema)
function validateByFile(file, value) {
  const schema = [...localSchemas, ...dependencies].find((item) => item.$id?.endsWith(`/${file}`))
  const validate = ajv.getSchema(schema.$id)
  if (!validate(value)) fail('SCHEMA_REJECTED', `${file}: ${ajv.errorsText(validate.errors)}`)
}

const fixture = readJson(path.join(root, 'fixtures/valid-identity-correction-v1-3.json'))
const invalidFixture = readJson(path.join(root, 'fixtures/invalid-identity-correction-v1-3.json'))
const d940Fixture = readJson(path.join(d940Root, 'fixtures/valid-contracts-v1.json'))
const d940ReceiptSchemaFile = 'journal-append-receipt-v1.schema.json'
const d940Subject = d940Fixture.records.restriction.subject.subject_identity_sha256
assert.equal(fixture.subject_identity_sha256, d940Subject)
const d940SemanticActor = d940Fixture.records.restriction.semantic_actor
const d940PersistenceActor = d940Fixture.records.restriction.persistence_actor
const generationFixture = createGenerationFixture(null)
const verifiedGeneration = verifyFixture(loadApprovedContractSet({ contractRoot: path.join(here, 'd9-0') }), generationFixture)
const bindingsByRole = new Map(verifiedGeneration.identityBindings.bindings.map((item) => [item.runtime_role_code, item]))
const runtimeGeneration = {
  runtime_profile_record_digest_sha256: verifiedGeneration.runtimeProfile.record_digest_sha256,
  identity_bindings_record_digest_sha256: verifiedGeneration.identityBindings.record_digest_sha256,
  binding_generation: verifiedGeneration.identityBindings.binding_generation
}
function actorFor(role) {
  const binding = bindingsByRole.get(role)
  assert.ok(binding, `verified binding for ${role}`)
  return {
    runtime_role_code: role,
    binding_code: binding.binding_code,
    endpoint_code: binding.ipc_endpoint_code,
    executable_build_sha256: binding.executable_sha256,
    binding_generation: binding.binding_generation ?? verifiedGeneration.identityBindings.binding_generation
  }
}
const verifier = actorFor('independent_verifier')
const broker = actorFor('journal_broker')
const launcher = actorFor('trusted_launcher')

function assertActor(actor, expected, role, at) {
  const binding = bindingsByRole.get(role)
  if (!binding || !same(actor, expected) || actor.runtime_role_code !== role || actor.binding_code !== binding.binding_code || actor.endpoint_code !== binding.ipc_endpoint_code || actor.executable_build_sha256 !== binding.executable_sha256 || actor.binding_generation !== verifiedGeneration.identityBindings.binding_generation) fail('ACTOR_REJECTED', role)
  if (at && (ms(at) < ms(binding.valid_from) || ms(at) >= ms(binding.valid_until))) fail('ACTOR_TIME_REJECTED', role)
}
assertActor(verifier, actorFor('independent_verifier'), 'independent_verifier')
assertActor(broker, actorFor('journal_broker'), 'journal_broker')

function makeReceipt(seed, sequence, predecessor) {
  const value = seal({
    format: 'jedi-atlas-d940-journal-append-receipt',
    format_version: '1.0.0',
    record_code: `receipt.identity.${sequence}`,
    journal_namespace_code: 'd940.global.control-journal.v1',
    receipt_sequence: sequence,
    previous_receipt_record_digest_sha256: predecessor,
    target_format: 'jedi-atlas-d940-recovery-assessment',
    target_record_code: seed.assessment_record_code ?? `record.identity.${sequence}`,
    target_record_digest_sha256: seed.assessment_record_digest_sha256,
    target_subject_identity_sha256: fixture.subject_identity_sha256,
    operation_id: seed.operation_id,
    operation_nonce: seed.operation_nonce,
    semantic_actor: clone(d940SemanticActor),
    persistence_actor: clone(d940PersistenceActor),
    semantic_recorded_at: seed.semantic_recorded_at,
    persisted_at: seed.persisted_at,
    durability_state_code: 'record_and_receipt_flushed_in_protected_d940_ledger',
    record_digest_sha256: ZERO
  })
  validateByFile(d940ReceiptSchemaFile, value)
  return value
}

function prefixEntry(receipt) {
  return {
    receipt_sequence: receipt.receipt_sequence,
    receipt_canonical_utf8: canonicalize(receipt),
    receipt_record_digest_sha256: receipt.record_digest_sha256,
    predecessor_receipt_record_digest_sha256: receipt.previous_receipt_record_digest_sha256,
    target_format: receipt.target_format,
    target_record_code: receipt.target_record_code,
    target_record_digest_sha256: receipt.target_record_digest_sha256,
    receipt_persisted_at: receipt.persisted_at
  }
}

function rawPayload(receipts, recordKinds) {
  return {
    known_through_receipt_sequence: receipts.length ? receipts.at(-1).receipt_sequence : 0,
    records: receipts.map((receipt, index) => ({ receipt_sequence: receipt.receipt_sequence, record_kind_code: recordKinds[index], record_digest_sha256: receipt.target_record_digest_sha256 }))
  }
}

function deriveStateHead(receipts, recordKinds) {
  const payload = rawPayload(receipts, recordKinds)
  const rawPayloadSha = canonicalSha256(payload)
  const headSequence = receipts.length ? receipts.at(-1).receipt_sequence : 0
  const payloadCommitments = [{ source_payload_code: 'control_records', raw_payload_sha256: rawPayloadSha }]
  const inventory = canonicalSha256({ source_namespace_code: 'd940.global.control-journal.v1', head_sequence: headSequence, payload_commitments: payloadCommitments })
  const persistedAt = receipts.length ? receipts.at(-1).persisted_at : '1970-01-01T00:00:00.000Z'
  const stateDigest = canonicalSha256({ source_namespace_code: 'd940.global.control-journal.v1', head_sequence: headSequence, head_persisted_at: persistedAt, inventory_digest_sha256: inventory })
  return {
    stateHead: {
      source_namespace_code: 'd940.global.control-journal.v1',
      source_contract_fingerprint_sha256: frozen['docs/schema/d9-4-0/contract-catalog-v1.json'],
      head_sequence: headSequence,
      head_persisted_at: persistedAt,
      raw_payload_inventory_digest_sha256: inventory,
      state_head_digest_sha256: stateDigest,
      derivation_profile_code: 'frozen_v1_raw_payload_commitments'
    },
    commitment: { source_payload_code: 'control_records', raw_payload_canonical_utf8: canonicalize(payload), raw_payload_sha256: rawPayloadSha }
  }
}

function makeCorrespondence(code, operationId, operationNonce, observedAt, receipts, recordKinds) {
  const { stateHead, commitment } = deriveStateHead(receipts, recordKinds)
  const tipReceipt = receipts.at(-1)
  const prefix = receipts.map(prefixEntry)
  return seal({
    format: 'jedi-atlas-d940-source-head-receipt-correspondence',
    format_version: '1.3.0',
    correspondence_code: code,
    operation_id: operationId,
    operation_nonce: operationNonce,
    runtime_generation: clone(runtimeGeneration),
    state_head: stateHead,
    journal_tip: tipReceipt ? {
      journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: tipReceipt.receipt_sequence,
      receipt_record_digest_sha256: tipReceipt.record_digest_sha256, target_format: tipReceipt.target_format, target_record_code: tipReceipt.target_record_code, target_record_digest_sha256: tipReceipt.target_record_digest_sha256,
      predecessor_receipt_record_digest_sha256: tipReceipt.previous_receipt_record_digest_sha256, receipt_persisted_at: tipReceipt.persisted_at
    } : {
      journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: 0, receipt_record_digest_sha256: null,
      target_format: null, target_record_code: null, target_record_digest_sha256: null, predecessor_receipt_record_digest_sha256: null, receipt_persisted_at: null
    },
    authenticated_receipt_prefix: prefix,
    raw_payload_commitments: [commitment],
    raw_prefix_digest_sha256: canonicalSha256(prefix.map(({ receipt_canonical_utf8, ...identity }) => identity)),
    semantic_verifier_actor: clone(verifier),
    persistence_broker_actor: clone(broker),
    observed_at: observedAt,
    technical_journal_continuity_only: true,
    authority_granted: false,
    record_digest_sha256: ZERO
  })
}

function correspondenceReference(value) {
  return {
    correspondence_code: value.correspondence_code,
    correspondence_record_digest_sha256: value.record_digest_sha256,
    state_head_digest_sha256: value.state_head.state_head_digest_sha256,
    journal_tip_receipt_record_digest_sha256: value.journal_tip.receipt_record_digest_sha256,
    receipt_sequence: value.journal_tip.receipt_sequence
  }
}

function validateCorrespondence(value) {
  validateByFile('source-head-receipt-correspondence-v1-3.schema.json', value)
  assertDigest(value, 'correspondence')
  assertGeneration(value.runtime_generation)
  assertActor(value.semantic_verifier_actor, verifier, 'independent_verifier', value.observed_at)
  assertActor(value.persistence_broker_actor, broker, 'journal_broker', value.observed_at)
  ms(value.observed_at)
  const prefix = value.authenticated_receipt_prefix
  assert.equal(prefix.length, value.journal_tip.receipt_sequence, 'complete receipt prefix')
  let predecessor = null
  for (let index = 0; index < prefix.length; index += 1) {
    const item = prefix[index]
    assert.equal(item.receipt_sequence, index + 1, 'gapless receipt sequence')
    assert.equal(item.predecessor_receipt_record_digest_sha256, predecessor, 'receipt predecessor')
    const receipt = parseStrictJson(Buffer.from(item.receipt_canonical_utf8))
    validateByFile(d940ReceiptSchemaFile, receipt)
    assertDigest(receipt, 'D9.4 receipt')
    assert.equal(canonicalize(receipt), item.receipt_canonical_utf8, 'canonical receipt bytes')
    assert.equal(receipt.record_digest_sha256, item.receipt_record_digest_sha256)
    assert.equal(receipt.receipt_sequence, item.receipt_sequence)
    assert.equal(receipt.previous_receipt_record_digest_sha256, item.predecessor_receipt_record_digest_sha256)
    assert.equal(receipt.target_format, item.target_format)
    assert.equal(receipt.target_record_code, item.target_record_code)
    assert.equal(receipt.target_record_digest_sha256, item.target_record_digest_sha256)
    assert.equal(receipt.persisted_at, item.receipt_persisted_at)
    if (index && ms(item.receipt_persisted_at) < ms(prefix[index - 1].receipt_persisted_at)) fail('RECEIPT_TIME_ROLLBACK')
    predecessor = item.receipt_record_digest_sha256
  }
  const tip = prefix.at(-1)
  assert.deepEqual(value.journal_tip, tip ? {
    journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: tip.receipt_sequence,
    receipt_record_digest_sha256: tip.receipt_record_digest_sha256, target_format: tip.target_format, target_record_code: tip.target_record_code, target_record_digest_sha256: tip.target_record_digest_sha256,
    predecessor_receipt_record_digest_sha256: tip.predecessor_receipt_record_digest_sha256, receipt_persisted_at: tip.receipt_persisted_at
  } : {
    journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: 0, receipt_record_digest_sha256: null,
    target_format: null, target_record_code: null, target_record_digest_sha256: null, predecessor_receipt_record_digest_sha256: null, receipt_persisted_at: null
  })
  const payloadCommitment = value.raw_payload_commitments[0]
  const payload = parseStrictJson(Buffer.from(payloadCommitment.raw_payload_canonical_utf8))
  assert.equal(canonicalize(payload), payloadCommitment.raw_payload_canonical_utf8, 'canonical raw payload')
  assert.equal(canonicalSha256(payload), payloadCommitment.raw_payload_sha256)
  assert.equal(payload.known_through_receipt_sequence, value.journal_tip.receipt_sequence)
  assert.equal(payload.records.length, value.journal_tip.receipt_sequence)
  for (let index = 0; index < payload.records.length; index += 1) {
    assert.equal(payload.records[index].receipt_sequence, index + 1)
    assert.equal(payload.records[index].record_digest_sha256, prefix[index].target_record_digest_sha256)
    if (prefix[index].target_format === 'jedi-atlas-d940-recovery-assessment') assert.equal(payload.records[index].record_kind_code, 'recovery_assessment')
  }
  const commitments = [{ source_payload_code: payloadCommitment.source_payload_code, raw_payload_sha256: payloadCommitment.raw_payload_sha256 }]
  const inventory = canonicalSha256({ source_namespace_code: value.state_head.source_namespace_code, head_sequence: value.state_head.head_sequence, payload_commitments: commitments })
  assert.equal(value.state_head.head_sequence, value.journal_tip.receipt_sequence)
  assert.equal(value.state_head.head_persisted_at, tip ? tip.receipt_persisted_at : '1970-01-01T00:00:00.000Z')
  assert.equal(value.state_head.raw_payload_inventory_digest_sha256, inventory)
  assert.equal(value.state_head.state_head_digest_sha256, canonicalSha256({ source_namespace_code: value.state_head.source_namespace_code, head_sequence: value.state_head.head_sequence, head_persisted_at: value.state_head.head_persisted_at, inventory_digest_sha256: inventory }))
  assert.equal(value.raw_prefix_digest_sha256, canonicalSha256(prefix.map(({ receipt_canonical_utf8, ...identity }) => identity)))
  if (tip) {
    const tipReceipt = parseStrictJson(Buffer.from(tip.receipt_canonical_utf8))
    assert.equal(value.operation_id, tipReceipt.operation_id, 'correspondence operation matches tip')
    assert.equal(value.operation_nonce, tipReceipt.operation_nonce, 'correspondence nonce matches tip')
    assert.notEqual(value.state_head.state_head_digest_sha256, value.journal_tip.receipt_record_digest_sha256, 'state head and receipt identities must be distinct')
    if (ms(value.observed_at) < ms(tip.receipt_persisted_at)) fail('OBSERVATION_PRECEDES_TIP')
  }
}

const receipts = []
const recordKinds = []
let correspondence = makeCorrespondence('correspondence.identity.empty', 'operation.identity.empty', '0101010101010101010101010101010101010101010101010101010101010101', fixture.empty_state_observed_at, receipts, recordKinds)
validateCorrespondence(correspondence)
const built = []

const subject = { subject_kind_code: 'custody_copy', subject_identity_sha256: fixture.subject_identity_sha256 }
function assertGeneration(value) { if (!same(value, runtimeGeneration)) fail('GENERATION_REJECTED') }
function assertRef(reference, value) { if (!same(reference, correspondenceReference(value))) fail('CORRESPONDENCE_REFERENCE_REJECTED') }
function checkpointCasPayload(sequence, predecessorCheckpoint, ref) { return { checkpoint_sequence: sequence, predecessor_checkpoint_identity_record_digest_sha256: predecessorCheckpoint, correspondence_record_digest_sha256: ref.correspondence_record_digest_sha256, state_head_digest_sha256: ref.state_head_digest_sha256 } }
function checkpointIdentity(sequence, correspondenceValue, predecessorCheckpoint, predecessorReceipt, createdAt) {
  const ref = correspondenceReference(correspondenceValue)
  const value = seal({ format: 'jedi-atlas-recovery-checkpoint-source-identity', format_version: '1.3.0', checkpoint_identity_code: `checkpoint.identity.${sequence}`, anchor_kind_code: sequence === 0 ? 'empty_runtime_genesis' : 'receipt_proven_transition', checkpoint_sequence: sequence, predecessor_checkpoint_identity_record_digest_sha256: predecessorCheckpoint, predecessor_transition_receipt_record_digest_sha256: predecessorReceipt, d940_correspondence: ref, checkpoint_cas_identity_sha256: canonicalSha256(checkpointCasPayload(sequence, predecessorCheckpoint, ref)), created_at: createdAt, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateByFile('checkpoint-identity-v1-3.schema.json', value); assertDigest(value, 'checkpoint identity'); assertRef(value.d940_correspondence, correspondenceValue); assert.equal(value.checkpoint_cas_identity_sha256, canonicalSha256(checkpointCasPayload(sequence, predecessorCheckpoint, ref))); return value
}

function payloadIdentity(value) { return `${value.format}:${value.request_code ?? value.receipt_code ?? value.transition_code ?? value.link_code ?? value.projection_code ?? value.checkpoint_identity_code ?? value.correspondence_code}` }
function payloadCollisionKeys(value) {
  const keys = [`primary:${payloadIdentity(value)}`]
  if (value.operation_id && value.operation_nonce) keys.push(`operation:${value.format}:${value.operation_id}:${value.operation_nonce}`)
  if (value.transition_sequence !== undefined) keys.push(`transition-sequence:${value.transition_sequence}`)
  if (value.checkpoint_sequence !== undefined) keys.push(`checkpoint-sequence:${value.checkpoint_sequence}`)
  if (value.target_receipt_sequence !== undefined) keys.push(`request-target:${value.target_receipt_sequence}`)
  return keys
}
function createProtectedModel() { return new Map([['d9.resolver.source-head-correspondence.v1.3', []], ['d9.resolver.identity-corrections.v1.3', []]]) }
function appendProtected(model, namespace, payload, sourceCas, persistedAt, { responseLoss = false, beforeAppendFailure = false, observedSourceCas, preflight } = {}) {
  const entries = model.get(namespace); if (!entries) fail('NAMESPACE_REJECTED')
  if (typeof preflight !== 'function') fail('PREFLIGHT_REQUIRED')
  preflight()
  if (sourceCas !== observedSourceCas) fail('SOURCE_HEAD_CAS_MISMATCH')
  if (classifyProtectedEntries(entries, namespace) !== 'consistent') fail('PROTECTED_STATE_RECONCILIATION_REQUIRED')
  if (beforeAppendFailure) fail('BEFORE_APPEND_FAILURE')
  const identity = payloadIdentity(payload)
  const collisionKeys = payloadCollisionKeys(payload)
  const existing = entries.find((item) => item.identity === identity)
  if (existing) {
    if (!same(existing.payload, payload)) fail('REPLAY_COLLISION')
    if (existing.receipt.namespace_code !== namespace || existing.receipt.source_head_cas_digest_sha256 !== sourceCas || existing.receipt.payload_record_digest_sha256 !== payload.record_digest_sha256 || !same(existing.receipt.semantic_actor, verifier) || !same(existing.receipt.persistence_actor, broker)) fail('REPLAY_RECEIPT_MISMATCH')
    return { outcome: 'exact_replay_no_op', receipt: clone(existing.receipt) }
  }
  if (entries.some((item) => item.collisionKeys.some((key) => collisionKeys.includes(key)))) fail('REPLAY_COLLISION')
  const previous = entries.at(-1)?.receipt ?? null
  const receipt = seal({ format: 'jedi-atlas-recovery-source-identity-protected-append-receipt', format_version: '1.3.0', receipt_code: `protected.${namespace.split('.').at(-2)}.${entries.length + 1}`, namespace_code: namespace, sequence: entries.length + 1, predecessor_receipt_record_digest_sha256: previous?.record_digest_sha256 ?? null, payload_format: payload.format, payload_record_digest_sha256: payload.record_digest_sha256, source_head_cas_digest_sha256: sourceCas, semantic_actor: clone(verifier), persistence_actor: clone(broker), accepted_at: persistedAt, persisted_at: persistedAt, record_digest_sha256: ZERO })
  validateByFile('protected-append-receipt-v1-3.schema.json', receipt); assertDigest(receipt, 'protected append receipt'); assertActor(receipt.semantic_actor, verifier, 'independent_verifier'); assertActor(receipt.persistence_actor, broker, 'journal_broker')
  entries.push({ identity, collisionKeys, payload: clone(payload), receipt: clone(receipt) })
  if (responseLoss) fail('RESPONSE_LOST_AFTER_DURABLE_APPEND')
  return { outcome: 'persisted', receipt }
}

function appendResult(code, payloadDigest, outcome, error, receiptDigest, observedAt) {
  const value = seal({ format: 'jedi-atlas-recovery-source-identity-append-result', format_version: '1.3.0', result_code: code, payload_record_digest_sha256: payloadDigest, outcome_code: outcome, error_code: error, protected_append_receipt_record_digest_sha256: receiptDigest, observed_at: observedAt, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateByFile('append-result-v1-3.schema.json', value); assertDigest(value, 'append result'); return value
}

function classifyProtectedEntries(entries, expectedNamespace) {
  let predecessor = null
  const identities = new Set()
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index]
    if (!entry?.payload || !entry?.receipt) return 'incomplete_state'
    if (entry.receipt.sequence !== index + 1) return entry.receipt.sequence <= index ? 'rollback' : 'gap'
    if (entry.receipt.predecessor_receipt_record_digest_sha256 !== predecessor) return 'fork'
    try { validateByFile('protected-append-receipt-v1-3.schema.json', entry.receipt); assertDigest(entry.receipt, 'protected receipt') } catch { return 'corrupt_state' }
    if (entry.receipt.namespace_code !== expectedNamespace || !same(entry.receipt.semantic_actor, verifier) || !same(entry.receipt.persistence_actor, broker)) return 'corrupt_state'
    try { assertActor(entry.receipt.semantic_actor, verifier, 'independent_verifier', entry.receipt.accepted_at); assertActor(entry.receipt.persistence_actor, broker, 'journal_broker', entry.receipt.persisted_at) } catch { return 'corrupt_state' }
    if (entry.receipt.payload_record_digest_sha256 !== entry.payload.record_digest_sha256 || entry.receipt.payload_format !== entry.payload.format) return 'corrupt_state'
    try { assertDigest(entry.payload, 'protected payload') } catch { return 'corrupt_state' }
    const expectedIdentity = payloadIdentity(entry.payload)
    const expectedKeys = payloadCollisionKeys(entry.payload)
    if (entry.identity !== expectedIdentity || !same(entry.collisionKeys, expectedKeys)) return 'corrupt_state'
    if (expectedKeys.some((key) => identities.has(key))) return 'fork'
    for (const key of expectedKeys) identities.add(key)
    if (index && ms(entry.receipt.persisted_at) < ms(entries[index - 1].receipt.persisted_at)) return 'rollback'
    predecessor = entry.receipt.record_digest_sha256
  }
  return 'consistent'
}
function appendChecked(model, namespace, payload, sourceCas, persistedAt, preflight, extra = {}) {
  return appendProtected(model, namespace, payload, sourceCas, persistedAt, { ...extra, observedSourceCas: sourceCas, preflight })
}

const protectedModel = createProtectedModel()
const emptyCorrespondenceAppend = appendChecked(protectedModel, 'd9.resolver.source-head-correspondence.v1.3', correspondence, correspondence.state_head.state_head_digest_sha256, fixture.empty_state_observed_at, () => validateCorrespondence(correspondence))
let checkpoint = checkpointIdentity(0, correspondence, null, null, fixture.empty_state_observed_at)
appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', checkpoint, correspondence.state_head.state_head_digest_sha256, fixture.empty_state_observed_at, () => { validateByFile('checkpoint-identity-v1-3.schema.json', checkpoint); assertDigest(checkpoint, 'genesis checkpoint') })

function validateAppendRequest(value, context) {
  validateByFile('assessment-append-request-v1-3.schema.json', value); assertDigest(value, 'append request'); assertGeneration(value.runtime_generation); assert.deepEqual(value.subject, subject); assertActor(value.semantic_actor, verifier, 'independent_verifier', value.authorized_at); assertActor(value.broker_recipient, broker, 'journal_broker', value.append_revalidate_by); assertRef(value.pre_append_correspondence, context.pre); assert.equal(value.pre_append_checkpoint_identity_record_digest_sha256, context.checkpoint.record_digest_sha256); assert.equal(value.expected_predecessor_receipt_sequence, context.pre.journal_tip.receipt_sequence); assert.equal(value.expected_predecessor_receipt_record_digest_sha256, context.pre.journal_tip.receipt_record_digest_sha256); assert.equal(value.target_receipt_sequence, context.pre.journal_tip.receipt_sequence + 1); const assessment = parseStrictJson(Buffer.from(value.assessment_canonical_utf8)); validateByFile('recovery-assessment-v1.schema.json', assessment); assert.equal(canonicalize(assessment), value.assessment_canonical_utf8); assert.equal(assessment.format, value.assessment_format); assert.equal(assessment.record_code, value.assessment_record_code); assert.equal(assessment.operation_id, value.operation_id); assert.equal(assessment.operation_nonce, value.operation_nonce); assert.equal(assessment.subject.subject_kind_code, value.subject.subject_kind_code); assert.equal(assessment.subject.subject_identity_sha256, value.subject.subject_identity_sha256); assert.equal(canonicalSha256(assessment, { excludedTopLevelField: 'record_digest_sha256' }), value.target_assessment_record_digest_sha256); if (ms(value.authorized_at) >= ms(value.append_revalidate_by)) fail('REQUEST_TIME_REJECTED')
}
function validateBrokerReceipt(value, context) {
  validateByFile('assessment-append-broker-receipt-v1-3.schema.json', value); assertDigest(value, 'broker receipt'); assertGeneration(value.runtime_generation); assert.deepEqual(value.subject, subject); assertActor(value.broker_actor, broker, 'journal_broker', value.persisted_at); assertActor(value.semantic_verifier_actor, verifier, 'independent_verifier', value.accepted_at); assert.equal(value.operation_id, context.request.operation_id); assert.equal(value.operation_nonce, context.request.operation_nonce); assert.equal(value.append_request_record_digest_sha256, context.request.record_digest_sha256); assertRef(value.pre_append_correspondence, context.pre); assertRef(value.post_append_correspondence, context.post); const receipt = parseStrictJson(Buffer.from(value.d940_append_receipt_canonical_utf8)); validateByFile(d940ReceiptSchemaFile, receipt); assertDigest(receipt, 'embedded D9.4 receipt'); assert.equal(canonicalize(receipt), value.d940_append_receipt_canonical_utf8); assert.equal(receipt.record_digest_sha256, value.d940_append_receipt_record_digest_sha256); assert.equal(receipt.record_digest_sha256, context.post.journal_tip.receipt_record_digest_sha256); assert.equal(receipt.previous_receipt_record_digest_sha256, context.pre.journal_tip.receipt_record_digest_sha256); assert.equal(receipt.receipt_sequence, context.request.target_receipt_sequence); assert.equal(receipt.target_record_digest_sha256, context.request.target_assessment_record_digest_sha256); assert.equal(receipt.target_record_digest_sha256, value.assessment_record_digest_sha256); assert.equal(receipt.target_record_code, context.request.assessment_record_code); assert.equal(receipt.target_format, context.request.assessment_format); assert.equal(receipt.operation_id, context.request.operation_id); assert.equal(receipt.operation_nonce, context.request.operation_nonce); assert.equal(receipt.target_subject_identity_sha256, context.request.subject.subject_identity_sha256); if (ms(value.accepted_at) > ms(value.persisted_at)) fail('BROKER_TIME_REJECTED')
}
function validateTransition(value, context) {
  validateByFile('checkpoint-transition-v1-3.schema.json', value); assertDigest(value, 'transition'); assertGeneration(value.runtime_generation); assert.deepEqual(value.subject, subject); assertActor(value.finalizer_actor, launcher, 'trusted_launcher', value.persisted_at); assertActor(value.semantic_actor, verifier, 'independent_verifier', value.persisted_at); assertActor(value.persistence_actor, broker, 'journal_broker', value.persisted_at); assert.equal(value.operation_id, context.request.operation_id); assert.equal(value.operation_nonce, context.request.operation_nonce); assert.equal(value.append_request_record_digest_sha256, context.request.record_digest_sha256); assert.equal(value.append_broker_receipt_record_digest_sha256, context.brokerReceipt.record_digest_sha256); assert.equal(value.pre_append_checkpoint_identity_record_digest_sha256, context.checkpoint.record_digest_sha256); assert.equal(value.post_checkpoint_sequence, context.checkpoint.checkpoint_sequence + 1); assertRef(value.pre_append_correspondence, context.pre); assertRef(value.post_append_correspondence, context.post); assert.equal(value.source_head_cas_digest_sha256, context.post.state_head.state_head_digest_sha256); assert.equal(value.journal_tip_receipt_record_digest_sha256, context.post.journal_tip.receipt_record_digest_sha256); assert.equal(value.post_checkpoint_cas_identity_sha256, canonicalSha256(checkpointCasPayload(value.post_checkpoint_sequence, context.checkpoint.record_digest_sha256, correspondenceReference(context.post)))); assert.notEqual(value.source_head_cas_digest_sha256, value.journal_tip_receipt_record_digest_sha256)
}
function validateProjection(value, context) {
  validateByFile('control-access-projection-v1-3.schema.json', value); assertDigest(value, 'projection'); assertGeneration(value.runtime_generation); assert.deepEqual(value.subject, subject); assertActor(value.semantic_actor, verifier, 'independent_verifier', value.observed_at); assertRef(value.source_correspondence, context.post); assert.equal(value.operation_id, context.operation.operation_id); assert.equal(value.operation_nonce, context.operation.operation_nonce); assert.equal(value.known_through_receipt_sequence, context.post.journal_tip.receipt_sequence); assert.equal(value.known_through_persisted_at, context.post.journal_tip.receipt_persisted_at); assert.equal(value.control_ledger_head_receipt_digest_sha256, context.post.journal_tip.receipt_record_digest_sha256); assert.equal(value.d940_state_head_digest_sha256, context.post.state_head.state_head_digest_sha256); assert.equal(value.control_head_projection_sha256, canonicalSha256(rawPayload(receipts.slice(0, value.known_through_receipt_sequence), recordKinds.slice(0, value.known_through_receipt_sequence)).records)); assert.equal(value.access_head_projection_sha256, canonicalSha256({ subject: value.subject, known_through_receipt_sequence: value.known_through_receipt_sequence, access_records: [] })); assert.notEqual(value.control_ledger_head_receipt_digest_sha256, value.d940_state_head_digest_sha256)
}

function makeAssessment(operation, index, pre) {
  const boundarySequence = Math.max(1, pre.journal_tip.receipt_sequence)
  const boundaryTime = pre.journal_tip.receipt_persisted_at ?? '1970-01-01T00:00:00.000Z'
  const snapshot = { journal_namespace_code: 'd940.global.control-journal.v1', known_through_receipt_sequence: boundarySequence, known_through_persisted_at: boundaryTime, control_ledger_head_receipt_digest_sha256: pre.journal_tip.receipt_record_digest_sha256 ?? ZERO, control_head_projection_sha256: canonicalSha256(rawPayload(receipts, recordKinds).records), access_head_projection_sha256: canonicalSha256({ subject, known_through_receipt_sequence: pre.journal_tip.receipt_sequence, access_records: [] }), subject_lineage_projection_sha256: 'b'.repeat(64), inventory_snapshot_sha256: 'c'.repeat(64), custody_leaf_projection_sha256: 'd'.repeat(64) }
  return seal({ format: 'jedi-atlas-d940-recovery-assessment', format_version: '1.0.0', record_code: `assessment.identity.${index + 1}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, subject: clone(d940Fixture.records.restriction.subject), snapshot_digest_sha256: canonicalSha256(snapshot), snapshot, crash_boundary_code: 'before_restriction_persisted', inventory_state_code: 'complete', access_state_code: 'none_confirmed', control_state_code: 'linear_complete', classification_code: 'safe_no_effect', action_execution_code: 'none_classification_only', recovery_authority_present: false, semantic_actor: clone(d940SemanticActor), persistence_actor: clone(d940PersistenceActor), knowledge_boundary: { effective_at: operation.semantic_recorded_at, recorded_at: operation.semantic_recorded_at, persisted_at: operation.persisted_at, journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: boundarySequence }, record_digest_sha256: ZERO })
}
function validateAssessmentLink(value, context) {
  validateByFile('recovery-assessment-link-v1-3.schema.json', value); assertDigest(value, 'assessment link'); assertGeneration(value.runtime_generation); assert.deepEqual(value.subject, subject); assertActor(value.semantic_actor, verifier, 'independent_verifier', value.classified_at); assertActor(value.persistence_actor, broker, 'journal_broker', value.persisted_at); assert.equal(value.operation_id, context.operation.operation_id); assert.equal(value.operation_nonce, context.operation.operation_nonce); assert.equal(value.assessment_record_digest_sha256, context.assessment.record_digest_sha256); assert.equal(value.assessment_receipt_record_digest_sha256, context.post.journal_tip.receipt_record_digest_sha256); assertRef(value.post_append_correspondence, context.post); assert.equal(value.checkpoint_identity_record_digest_sha256, context.postCheckpoint.record_digest_sha256); if (ms(value.classified_at) > ms(value.persisted_at)) fail('LINK_TIME_REJECTED')
}

for (let index = 0; index < fixture.operations.length; index += 1) {
  const operation = fixture.operations[index]
  const pre = correspondence
  const assessment = makeAssessment(operation, index, pre)
  validateByFile('recovery-assessment-v1.schema.json', assessment); assertDigest(assessment, 'D9.4 assessment')
  const assessmentCanonical = canonicalize(assessment)
  const appendRequest = seal({ format: 'jedi-atlas-recovery-assessment-append-request', format_version: '1.3.0', request_code: `request.identity.${index + 1}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: clone(runtimeGeneration), subject: clone(subject), pre_append_checkpoint_identity_record_digest_sha256: checkpoint.record_digest_sha256, pre_append_correspondence: correspondenceReference(pre), expected_predecessor_receipt_sequence: pre.journal_tip.receipt_sequence, expected_predecessor_receipt_record_digest_sha256: pre.journal_tip.receipt_record_digest_sha256, target_receipt_sequence: pre.journal_tip.receipt_sequence + 1, assessment_format: 'jedi-atlas-d940-recovery-assessment', assessment_record_code: assessment.record_code, assessment_canonical_utf8: assessmentCanonical, target_assessment_record_digest_sha256: assessment.record_digest_sha256, semantic_actor: clone(verifier), broker_recipient: clone(broker), authorized_at: operation.semantic_recorded_at, append_revalidate_by: operation.persisted_at, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateAppendRequest(appendRequest, { pre, checkpoint })
  const requestAppend = appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', appendRequest, pre.state_head.state_head_digest_sha256, operation.semantic_recorded_at, () => validateAppendRequest(appendRequest, { pre, checkpoint }))
  const receiptSeed = { ...operation, assessment_record_digest_sha256: assessment.record_digest_sha256, assessment_record_code: assessment.record_code }
  const receipt = makeReceipt(receiptSeed, receipts.length + 1, receipts.at(-1)?.record_digest_sha256 ?? null)
  receipts.push(receipt); recordKinds.push(operation.record_kind_code)
  const post = makeCorrespondence(`correspondence.identity.${index + 1}`, operation.operation_id, operation.operation_nonce, operation.observed_at, receipts, recordKinds)
  validateCorrespondence(post)
  const correspondenceAppend = appendChecked(protectedModel, 'd9.resolver.source-head-correspondence.v1.3', post, post.state_head.state_head_digest_sha256, operation.observed_at, () => validateCorrespondence(post))
  const brokerReceipt = seal({ format: 'jedi-atlas-recovery-assessment-append-broker-receipt', format_version: '1.3.0', receipt_code: `broker.identity.${index + 1}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: clone(runtimeGeneration), subject: clone(subject), append_request_record_digest_sha256: appendRequest.record_digest_sha256, pre_append_correspondence: correspondenceReference(pre), post_append_correspondence: correspondenceReference(post), d940_append_receipt_canonical_utf8: canonicalize(receipt), d940_append_receipt_record_digest_sha256: receipt.record_digest_sha256, assessment_record_digest_sha256: assessment.record_digest_sha256, broker_actor: clone(broker), semantic_verifier_actor: clone(verifier), accepted_at: operation.persisted_at, persisted_at: operation.observed_at, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateBrokerReceipt(brokerReceipt, { request: appendRequest, pre, post })
  const brokerAppend = appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', brokerReceipt, post.state_head.state_head_digest_sha256, operation.observed_at, () => validateBrokerReceipt(brokerReceipt, { request: appendRequest, pre, post }))
  const nextCas = canonicalSha256(checkpointCasPayload(checkpoint.checkpoint_sequence + 1, checkpoint.record_digest_sha256, correspondenceReference(post)))
  const transition = seal({ format: 'jedi-atlas-recovery-checkpoint-transition', format_version: '1.3.0', transition_code: `transition.identity.${index + 1}`, transition_sequence: index + 1, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: clone(runtimeGeneration), subject: clone(subject), append_request_record_digest_sha256: appendRequest.record_digest_sha256, append_broker_receipt_record_digest_sha256: brokerReceipt.record_digest_sha256, pre_append_checkpoint_identity_record_digest_sha256: checkpoint.record_digest_sha256, post_checkpoint_sequence: checkpoint.checkpoint_sequence + 1, post_checkpoint_cas_identity_sha256: nextCas, pre_append_correspondence: correspondenceReference(pre), post_append_correspondence: correspondenceReference(post), source_head_cas_digest_sha256: post.state_head.state_head_digest_sha256, journal_tip_receipt_record_digest_sha256: post.journal_tip.receipt_record_digest_sha256, finalizer_actor: clone(launcher), semantic_actor: clone(verifier), persistence_actor: clone(broker), persisted_at: operation.observed_at, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateTransition(transition, { request: appendRequest, brokerReceipt, checkpoint, pre, post })
  const transitionAppend = appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', transition, post.state_head.state_head_digest_sha256, operation.observed_at, () => validateTransition(transition, { request: appendRequest, brokerReceipt, checkpoint, pre, post }))
  validateTransition(transition, { request: appendRequest, brokerReceipt, checkpoint, pre, post })
  const postCheckpoint = checkpointIdentity(checkpoint.checkpoint_sequence + 1, post, checkpoint.record_digest_sha256, transitionAppend.receipt.record_digest_sha256, operation.observed_at)
  const checkpointAppend = appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', postCheckpoint, post.state_head.state_head_digest_sha256, operation.observed_at, () => { validateByFile('checkpoint-identity-v1-3.schema.json', postCheckpoint); assertDigest(postCheckpoint, 'post checkpoint'); assert.equal(postCheckpoint.predecessor_transition_receipt_record_digest_sha256, transitionAppend.receipt.record_digest_sha256); assert.equal(transitionAppend.receipt.payload_record_digest_sha256, transition.record_digest_sha256) })
  const assessmentLink = seal({ format: 'jedi-atlas-recovery-assessment-source-identity-link', format_version: '1.3.0', link_code: `assessment.link.identity.${index + 1}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: clone(runtimeGeneration), subject: clone(subject), assessment_record_digest_sha256: assessment.record_digest_sha256, assessment_receipt_record_digest_sha256: receipt.record_digest_sha256, post_append_correspondence: correspondenceReference(post), checkpoint_identity_record_digest_sha256: postCheckpoint.record_digest_sha256, semantic_actor: clone(verifier), persistence_actor: clone(broker), classified_at: operation.semantic_recorded_at, persisted_at: operation.observed_at, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateAssessmentLink(assessmentLink, { operation, assessment, post, postCheckpoint })
  appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', assessmentLink, post.state_head.state_head_digest_sha256, operation.observed_at, () => validateAssessmentLink(assessmentLink, { operation, assessment, post, postCheckpoint }))
  const projection = seal({ format: 'jedi-atlas-d940-control-access-projection', format_version: '1.3.0', projection_code: `projection.identity.${index + 1}`, operation_id: operation.operation_id, operation_nonce: operation.operation_nonce, runtime_generation: clone(runtimeGeneration), subject: clone(subject), source_correspondence: correspondenceReference(post), journal_namespace_code: 'd940.global.control-journal.v1', known_through_receipt_sequence: post.journal_tip.receipt_sequence, known_through_persisted_at: post.journal_tip.receipt_persisted_at, control_ledger_head_receipt_digest_sha256: post.journal_tip.receipt_record_digest_sha256, d940_state_head_digest_sha256: post.state_head.state_head_digest_sha256, control_head_projection_sha256: canonicalSha256(rawPayload(receipts, recordKinds).records), access_head_projection_sha256: canonicalSha256({ subject, known_through_receipt_sequence: post.journal_tip.receipt_sequence, access_records: [] }), semantic_actor: clone(verifier), observed_at: operation.observed_at, technical_evidence_only: true, authority_granted: false, record_digest_sha256: ZERO })
  validateProjection(projection, { operation, post })
  appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', projection, post.state_head.state_head_digest_sha256, operation.observed_at, () => validateProjection(projection, { operation, post }))
  built.push({ operation, assessment, pre, preCheckpoint: checkpoint, appendRequest, requestAppend, receipt, post, correspondenceAppend, brokerReceipt, brokerAppend, postCheckpoint, checkpointAppend, transition, transitionAppend, assessmentLink, projection })
  checkpoint = postCheckpoint
  correspondence = post
}

assert.equal(built.length, 2)
assert.equal(built[1].pre.record_digest_sha256, built[0].post.record_digest_sha256)
assert.equal(built[1].post.journal_tip.receipt_sequence, built[0].post.journal_tip.receipt_sequence + 1)
const alteredEmbeddedReceiptBroker = clone(built[0].brokerReceipt)
const alteredEmbeddedReceipt = parseStrictJson(Buffer.from(alteredEmbeddedReceiptBroker.d940_append_receipt_canonical_utf8))
alteredEmbeddedReceipt.semantic_recorded_at = '2030-01-01T00:11:01.101Z'
alteredEmbeddedReceiptBroker.d940_append_receipt_canonical_utf8 = canonicalize(alteredEmbeddedReceipt)
seal(alteredEmbeddedReceiptBroker)
assert.throws(() => validateBrokerReceipt(alteredEmbeddedReceiptBroker, { request: built[0].appendRequest, pre: built[0].pre, post: built[0].post }), undefined, 'embedded receipt self-digest mutation rejected')

// Protected append liveness/crash semantics are design-only synthetic models.
const replay = appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', built[0].appendRequest, built[0].pre.state_head.state_head_digest_sha256, built[0].operation.semantic_recorded_at, () => validateAppendRequest(built[0].appendRequest, { pre: built[0].pre, checkpoint: built[0].preCheckpoint }))
assert.equal(replay.outcome, 'exact_replay_no_op')
assert.equal(replay.receipt.record_digest_sha256, built[0].requestAppend.receipt.record_digest_sha256)
appendResult('result.identity.replay', built[0].appendRequest.record_digest_sha256, 'exact_replay_no_op', null, replay.receipt.record_digest_sha256, built[1].operation.observed_at)
const changedReplay = clone(built[0].appendRequest); changedReplay.request_code = 'request.identity.changed-code'; seal(changedReplay)
assert.throws(() => appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', changedReplay, built[0].pre.state_head.state_head_digest_sha256, built[0].operation.semantic_recorded_at, () => { validateByFile('assessment-append-request-v1-3.schema.json', changedReplay); assertDigest(changedReplay, 'changed replay') }), /REPLAY_COLLISION/)
appendResult('result.identity.collision', changedReplay.record_digest_sha256, 'rejected', 'replay_collision', null, built[1].operation.observed_at)

const beforeFailure = clone(built[1].projection); beforeFailure.projection_code = 'projection.identity.before-failure'; seal(beforeFailure)
const identityEntries = protectedModel.get('d9.resolver.identity-corrections.v1.3')
const countBeforeFailure = identityEntries.length
assert.throws(() => appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', beforeFailure, built[1].post.state_head.state_head_digest_sha256, built[1].operation.observed_at, () => { validateByFile('control-access-projection-v1-3.schema.json', beforeFailure); assertDigest(beforeFailure, 'before failure') }, { beforeAppendFailure: true }), /BEFORE_APPEND_FAILURE/)
assert.equal(identityEntries.length, countBeforeFailure)

const lostResponse = clone(built[1].projection); lostResponse.projection_code = 'projection.identity.response-loss'; lostResponse.operation_id = 'operation.identity.response-loss'; lostResponse.operation_nonce = '9999999999999999999999999999999999999999999999999999999999999999'; seal(lostResponse)
assert.throws(() => appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', lostResponse, built[1].post.state_head.state_head_digest_sha256, built[1].operation.observed_at, () => { validateByFile('control-access-projection-v1-3.schema.json', lostResponse); assertDigest(lostResponse, 'lost response') }, { responseLoss: true }), /RESPONSE_LOST_AFTER_DURABLE_APPEND/)
appendResult('result.identity.response-loss-ambiguous', lostResponse.record_digest_sha256, 'reconciliation_required', 'response_loss_ambiguous', null, built[1].operation.observed_at)
const recoveredReplay = appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', lostResponse, built[1].post.state_head.state_head_digest_sha256, built[1].operation.observed_at, () => { validateByFile('control-access-projection-v1-3.schema.json', lostResponse); assertDigest(lostResponse, 'recovered replay') })
assert.equal(recoveredReplay.outcome, 'exact_replay_no_op')
appendResult('result.identity.response-loss', lostResponse.record_digest_sha256, 'exact_replay_no_op', null, recoveredReplay.receipt.record_digest_sha256, built[1].operation.observed_at)
assert.throws(() => appendProtected(protectedModel, 'd9.resolver.identity-corrections.v1.3', beforeFailure, 'f'.repeat(64), built[1].operation.observed_at, { observedSourceCas: built[1].post.state_head.state_head_digest_sha256, preflight: () => { validateByFile('control-access-projection-v1-3.schema.json', beforeFailure); assertDigest(beforeFailure, 'CAS rejection') } }), /SOURCE_HEAD_CAS_MISMATCH/)

assert.equal(classifyProtectedEntries(identityEntries, 'd9.resolver.identity-corrections.v1.3'), 'consistent')
for (const [classification, mutate] of [
  ['incomplete_state', (entries) => { entries[0].receipt = null }],
  ['corrupt_state', (entries) => { entries[0].receipt.payload_record_digest_sha256 = 'f'.repeat(64); seal(entries[0].receipt) }],
  ['gap', (entries) => { entries[1].receipt.sequence += 1; seal(entries[1].receipt) }],
  ['fork', (entries) => { entries[1].receipt.predecessor_receipt_record_digest_sha256 = 'f'.repeat(64); seal(entries[1].receipt) }],
  ['rollback', (entries) => { entries[1].receipt.sequence = 1; seal(entries[1].receipt) }]
]) {
  const changed = clone(identityEntries); mutate(changed); assert.equal(classifyProtectedEntries(changed, 'd9.resolver.identity-corrections.v1.3'), classification)
  appendResult(`result.identity.${classification}`, built[0].appendRequest.record_digest_sha256, 'reconciliation_required', classification, null, built[1].operation.observed_at)
}

const corruptReplayModel = new Map([...protectedModel].map(([key, entries]) => [key, clone(entries)]))
corruptReplayModel.get('d9.resolver.identity-corrections.v1.3')[0].receipt.payload_record_digest_sha256 = 'f'.repeat(64)
seal(corruptReplayModel.get('d9.resolver.identity-corrections.v1.3')[0].receipt)
assert.throws(() => appendChecked(corruptReplayModel, 'd9.resolver.identity-corrections.v1.3', built[0].appendRequest, built[0].pre.state_head.state_head_digest_sha256, built[0].operation.semantic_recorded_at, () => validateAppendRequest(built[0].appendRequest, { pre: built[0].pre, checkpoint: built[0].preCheckpoint })), /PROTECTED_STATE_RECONCILIATION_REQUIRED/)
for (const mutate of [
  (receipt) => { receipt.namespace_code = 'd9.resolver.source-head-correspondence.v1.3' },
  (receipt) => { receipt.source_head_cas_digest_sha256 = 'f'.repeat(64) }
]) {
  const changedModel = new Map([...protectedModel].map(([key, entries]) => [key, clone(entries)]))
  const retained = changedModel.get('d9.resolver.identity-corrections.v1.3').find((entry) => entry.identity === payloadIdentity(built[0].appendRequest))
  mutate(retained.receipt); seal(retained.receipt)
  assert.throws(() => appendChecked(changedModel, 'd9.resolver.identity-corrections.v1.3', built[0].appendRequest, built[0].pre.state_head.state_head_digest_sha256, built[0].operation.semantic_recorded_at, () => validateAppendRequest(built[0].appendRequest, { pre: built[0].pre, checkpoint: built[0].preCheckpoint })), /PROTECTED_STATE_RECONCILIATION_REQUIRED|REPLAY_RECEIPT_MISMATCH/)
}

const substitutedCheckpoint = clone(built[0].postCheckpoint)
substitutedCheckpoint.checkpoint_identity_code = 'checkpoint.identity.substituted'
substitutedCheckpoint.predecessor_transition_receipt_record_digest_sha256 = 'f'.repeat(64)
seal(substitutedCheckpoint)
const countBeforeCheckpointRejection = identityEntries.length
assert.throws(() => appendChecked(protectedModel, 'd9.resolver.identity-corrections.v1.3', substitutedCheckpoint, built[0].post.state_head.state_head_digest_sha256, built[0].operation.observed_at, () => { assert.equal(substitutedCheckpoint.predecessor_transition_receipt_record_digest_sha256, built[0].transitionAppend.receipt.record_digest_sha256); assert.equal(built[0].transitionAppend.receipt.payload_record_digest_sha256, built[0].transition.record_digest_sha256) }), undefined)
assert.equal(identityEntries.length, countBeforeCheckpointRejection)

const genesisResponseLossModel = createProtectedModel()
assert.throws(() => appendChecked(genesisResponseLossModel, 'd9.resolver.source-head-correspondence.v1.3', built[0].pre, built[0].pre.state_head.state_head_digest_sha256, fixture.empty_state_observed_at, () => validateCorrespondence(built[0].pre), { responseLoss: true }), /RESPONSE_LOST_AFTER_DURABLE_APPEND/)
const genesisReplay = appendChecked(genesisResponseLossModel, 'd9.resolver.source-head-correspondence.v1.3', built[0].pre, built[0].pre.state_head.state_head_digest_sha256, fixture.empty_state_observed_at, () => validateCorrespondence(built[0].pre))
assert.equal(genesisReplay.outcome, 'exact_replay_no_op')

const workflowStages = ['request_persisted', 'd940_receipt_persisted', 'correspondence_persisted', 'broker_receipt_persisted', 'transition_persisted', 'checkpoint_persisted', 'link_persisted', 'projection_persisted']
function classifyWorkflowPrefix(state) {
  let missingSeen = false
  for (const stage of workflowStages) { if (!state[stage]) missingSeen = true; else if (missingSeen) return { outcome: 'reconciliation_required', error: 'corrupt_state', next_stage: null, automatic_action: false } }
  const nextStage = workflowStages.find((stage) => !state[stage]) ?? null
  return { outcome: nextStage ? 'reconciliation_required' : 'complete', error: nextStage ? 'response_loss_ambiguous' : null, next_stage: nextStage, automatic_action: false }
}
for (let persistedCount = 0; persistedCount < workflowStages.length; persistedCount += 1) {
  const state = Object.fromEntries(workflowStages.map((stage, index) => [stage, index < persistedCount]))
  const classification = classifyWorkflowPrefix(state)
  assert.equal(classification.outcome, 'reconciliation_required'); assert.equal(classification.next_stage, workflowStages[persistedCount]); assert.equal(classification.automatic_action, false)
  appendResult(`result.boundary.${persistedCount + 1}`, built[0].appendRequest.record_digest_sha256, 'reconciliation_required', 'response_loss_ambiguous', null, built[0].operation.observed_at)
}
const gappedWorkflow = Object.fromEntries(workflowStages.map((stage, index) => [stage, index === 0 || index === 2]))
assert.deepEqual(classifyWorkflowPrefix(gappedWorkflow), { outcome: 'reconciliation_required', error: 'corrupt_state', next_stage: null, automatic_action: false })

function mutationTest(label, mutate) {
  const changed = clone(built[0].post)
  mutate(changed)
  seal(changed)
  assert.throws(() => validateCorrespondence(changed), undefined, label)
}
const mutationTests = [
  ['wrong_tip', (x) => { x.journal_tip.receipt_record_digest_sha256 = 'f'.repeat(64) }],
  ['wrong_target', (x) => { x.journal_tip.target_record_digest_sha256 = 'f'.repeat(64) }],
  ['wrong_predecessor', (x) => { x.journal_tip.predecessor_receipt_record_digest_sha256 = 'f'.repeat(64) }],
  ['wrong_sequence', (x) => { x.journal_tip.receipt_sequence += 1 }],
  ['wrong_time', (x) => { x.journal_tip.receipt_persisted_at = '2030-01-01T00:00:00.000Z' }],
  ['wrong_inventory', (x) => { x.state_head.raw_payload_inventory_digest_sha256 = 'f'.repeat(64) }],
  ['wrong_raw_prefix', (x) => { x.authenticated_receipt_prefix[0].target_record_digest_sha256 = 'f'.repeat(64) }],
  ['wrong_producer', (x) => { x.semantic_verifier_actor = clone(broker) }],
  ['wrong_build', (x) => { x.semantic_verifier_actor.executable_build_sha256 = 'f'.repeat(64) }],
  ['swapped_state_and_receipt', (x) => { const state = x.state_head.state_head_digest_sha256; x.state_head.state_head_digest_sha256 = x.journal_tip.receipt_record_digest_sha256; x.journal_tip.receipt_record_digest_sha256 = state }],
  ['accidental_equality', (x) => { x.state_head.state_head_digest_sha256 = x.journal_tip.receipt_record_digest_sha256 }],
  ['fork', (x) => { x.authenticated_receipt_prefix.at(-1).receipt_record_digest_sha256 = 'e'.repeat(64) }],
  ['gap', (x) => { x.authenticated_receipt_prefix.at(-1).receipt_sequence += 1 }],
  ['rollback', (x) => { x.state_head.head_sequence -= 1 }],
  ['extra_append', (x) => { x.authenticated_receipt_prefix.push(clone(x.authenticated_receipt_prefix.at(-1))) }]
]
for (const [label, mutate] of mutationTests) mutationTest(label, mutate)

// Every correspondence leaf is digest-covered and mutation-sensitive.
function leafPaths(value, prefix = []) {
  const paths = []
  if (value === null || typeof value !== 'object') return [prefix]
  if (Array.isArray(value)) for (let index = 0; index < value.length; index += 1) paths.push(...leafPaths(value[index], [...prefix, index]))
  else for (const key of Object.keys(value)) if (key !== 'record_digest_sha256') paths.push(...leafPaths(value[key], [...prefix, key]))
  return paths
}
function setAt(value, pointer, replacement) { let cursor = value; for (const key of pointer.slice(0, -1)) cursor = cursor[key]; cursor[pointer.at(-1)] = replacement }
for (const pointer of leafPaths(built[0].post)) {
  const changed = clone(built[0].post)
  let current = changed
  for (const key of pointer) current = current[key]
  const replacement = typeof current === 'boolean' ? !current : typeof current === 'number' ? current + 1 : current === null ? 'x' : `${current}x`
  setAt(changed, pointer, replacement)
  assert.notEqual(canonicalSha256(changed, { excludedTopLevelField: 'record_digest_sha256' }), built[0].post.record_digest_sha256, `leaf mutation covered: ${pointer.join('/')}`)
}

// Response loss and restart reconstruct byte-identical correspondence; changed replay conflicts.
const reconstructed = makeCorrespondence(built[0].post.correspondence_code, built[0].operation.operation_id, built[0].operation.operation_nonce, built[0].operation.observed_at, receipts.slice(0, 1), recordKinds.slice(0, 1))
validateCorrespondence(reconstructed)
assert.deepEqual(reconstructed, built[0].post, 'restart/response-loss reconstruction exact')
const conflictingReplay = clone(reconstructed); conflictingReplay.operation_id = 'operation.identity.conflict'; seal(conflictingReplay)
assert.notEqual(conflictingReplay.record_digest_sha256, reconstructed.record_digest_sha256, 'conflicting replay rejected by identity')

const executedMutations = new Set([...mutationTests.map(([code]) => code), 'response_loss', 'response_loss_ambiguous', 'restart', 'exact_replay', 'conflicting_replay', 'correspondence_field_mutation', 'source_head_cas_mismatch', 'corrupt_state', 'incomplete_state'])
for (const code of invalidFixture.mutations) assert.ok(executedMutations.has(code), `declared mutation executed: ${code}`)

const golden = readJson(path.join(root, 'fixtures/golden-vectors-v1-3.json'))
for (const vector of golden.vectors.filter((item) => item.canonical_utf8)) assert.equal(crypto.createHash('sha256').update(Buffer.from(vector.canonical_utf8)).digest('hex'), vector.sha256, `${vector.vector_code} independent SHA-256`)
assert.equal(golden.vectors[0].canonical_utf8, canonicalize(built[0].post.state_head), 'state head golden')
assert.equal(golden.vectors[1].canonical_utf8, canonicalize(built[0].post.journal_tip), 'journal tip golden')
const correspondenceWithoutSelf = clone(built[0].post); delete correspondenceWithoutSelf.record_digest_sha256
assert.equal(Buffer.byteLength(canonicalize(correspondenceWithoutSelf)), golden.vectors[2].canonical_byte_length, 'complete correspondence byte length golden')
assert.equal(canonicalSha256(correspondenceWithoutSelf), golden.vectors[2].sha256, 'complete correspondence digest golden')

const catalog = readJson(path.join(root, 'contract-catalog-v1-3.json'))
const inventory = readJson(path.join(root, 'root-inventory-v1-3.json'))
assert.equal(catalog.format_version, '1.3.0')
assert.equal(catalog.status_code, 'design_only_contract_freeze')
assert.equal(catalog.supersedes_scope, 'd940_source_head_receipt_identity_route_only')
assert.equal(catalog.instance_policy.runtime_implementation_authorized, false)
assert.equal(catalog.instance_policy.recovery_actions_authorized, false)
assert.equal(catalog.instance_policy.legal_conclusions_authorized, false)
const disk = []
function walk(directory, prefix = '') { for (const entry of fs.readdirSync(directory, { withFileTypes: true })) { const relative = path.posix.join(prefix, entry.name); if (entry.isDirectory()) walk(path.join(directory, entry.name), relative); else if (relative !== 'root-inventory-v1-3.json') disk.push(relative) } }
walk(root); disk.sort(); assert.deepEqual(inventory.files.map((item) => item.path), disk)
for (const item of inventory.files) assert.equal(rawSha256(path.join(root, item.path)), item.raw_sha256, item.path)
for (const item of [...catalog.schemas, ...catalog.registries, ...catalog.fixtures, ...catalog.validators]) assert.equal(rawSha256(path.resolve(root, item.file)), item.raw_sha256, item.file)

console.log('D9 recovery source-head/receipt identity correction v1.3 validation passed')
console.log('  distinct state head, journal tip and exact authenticated correspondence passed')
console.log('  two consecutive assessments, restart, response loss, replay and mutation matrix passed')
console.log('  frozen v1/v1.1/v1.2 artifacts and migrations remained unchanged')
console.log('  technical journal continuity only; no recovery or legal authority granted')
