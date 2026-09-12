import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { applyMigrations } from '../../data/lib/migrations.mjs'
import {
  canonicalize,
  canonicalSha256,
  parseStrictJson,
  sha256Bytes,
} from '../../d9/control-plane/canonical.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const project = path.resolve(here, '../..')
const root = path.join(here, 'd9-4-0')
const frozenD90Root = path.join(here, 'd9-0')
const frozenD930Root = path.join(here, 'd9-3-0')
const fixtureRoot = path.join(root, 'fixtures')

const frozenMigrations = {
  '001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  '002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  '003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
  '004_tranche_1a_foundations.sql': '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
  '005_tranche_2a_source_quarantine.sql': '1f83b484ca998be3bf5756492d4dffd958e2a6b37dbcc837e399226fdf41026b',
}

const frozen = {
  d901_catalog: 'e0a5663b378453a00626f02961465a60a474e145dd5160bf85a1797cd9316d2a',
  d901_classification: '8d7b64822663edf09dac0d613ed9da30de0569acb8a1258a84e1850af656deef',
  d930_catalog: 'cd91f67c25941a472b89fe2fa6f19b012714dec96661b65b76ecfacf7f48e87c',
  d930_classification: 'b61fff46a6094aeb23dfcfb0d02f808b9ac83d345a832a9d914d8de8b641a5e8',
  d930_root: 'cf073b571a70b347ba3ea8e0e851d5d44013fe701fd9f77a235673302b423ba3',
  d931_tree: 'b9741646402f606a28e7faf05ffc672308a26fb3',
}

const expected = {
  catalog: '7f36ca6922cc92ef32b01b0a5b5e896d78f7a359affd06a2bd943a9b28b6c2bc',
  classification: 'f929f22495ebbbc9849b76890ecc5d0eb4ee23cc0b1e2a6d528993c8063f8585',
  digest_profiles: '48e7bcb3941630df7e728995f3e48936e591eac3cb874ccb78a1ec77f710da8b',
  field_registry: 'bc707e9946b885c48bc6eaab59ddacaed5c8fbeec6739c3c15d097a6e7002991',
  root_inventory: '9ca5e3099e362c73f0a61616d02b81acc0df3cbd14fd3891b460e82875b4f64e',
  subject_rules: '86557dc7eaeb3449ab5db26c93b2dbc125ae4f89c07deaef11e84a549cbbb745',
  role_and_separation: '882a3523645dc95775ff312d15950102708777842f9f7054a70eba4290c528f0',
  restriction_projection: 'ca4b30c5d3463e393193b20f219e81da5b046b4b1ba403b1bfdc72a122e6b752',
  deletion_lifecycle: 'daff0b0e4cc3b1ba4f094a8eb49ea8608d876df6769dab86611bfeebba3081fc',
  recovery_and_backup: 'eb5214b374cca1dddb8a7fb76d17b3c645615d6bcc3c4067e98e57b870efbe16',
}

const schemaFiles = [
  'operational-profile-v1.schema.json',
  'authority-roster-v1.schema.json',
  'authority-roster-adoption-v1.schema.json',
  'custody-control-record-v1.schema.json',
  'access-revocation-record-v1.schema.json',
  'deletion-execution-record-v1.schema.json',
  'deletion-receipt-v1.schema.json',
  'backup-coordination-record-v1.schema.json',
  'recovery-assessment-v1.schema.json',
  'journal-append-receipt-v1.schema.json',
]

const atlasTables = [
  'atlas_principals', 'atlas_languages', 'atlas_jurisdictions', 'atlas_jurisdiction_versions',
  'atlas_evidence_bundle_receipts', 'atlas_retrieval_locations', 'atlas_artifacts',
  'atlas_retrieval_events', 'atlas_retrieval_redirects', 'atlas_artifact_custody_events',
  'atlas_processing_runs', 'atlas_processing_outputs', 'atlas_unverified_candidate_occurrences',
]

function readJson(file) {
  return parseStrictJson(fs.readFileSync(file), {
    maximumBytes: 4 * 1024 * 1024,
    maximumDepth: 96,
    maximumMembers: 50000,
  })
}

function rawSha(file) {
  return sha256Bytes(fs.readFileSync(file))
}

function recordDigest(record) {
  return canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' })
}

function fail(code, detail = '') {
  throw new Error(`${code}${detail ? `: ${detail}` : ''}`)
}

function expectCode(fn, code) {
  assert.throws(fn, (error) => String(error.message).includes(code), `expected ${code}`)
}

function clone(value) {
  return structuredClone(value)
}

function pointerSet(value, pointer, replacement, add = false) {
  const result = clone(value)
  const parts = pointer.split('/').slice(1).map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'))
  let current = result
  for (const part of parts.slice(0, -1)) current = current[part]
  if (!add && !(parts.at(-1) in current)) fail('MUTATION_POINTER_MISSING', pointer)
  current[parts.at(-1)] = clone(replacement)
  return result
}

function isTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false
  const date = new Date(value)
  return !Number.isNaN(date.valueOf()) && date.toISOString() === value
}

function validateStringsAndTimes(value, pointer = '') {
  if (typeof value === 'string') {
    if (/\0|[\u0001-\u001f\u007f]/u.test(value)) fail('UNSAFE_STRING_REJECTED', pointer)
    return
  }
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    const next = `${pointer}/${key}`
    if (key.endsWith('_at') && child !== null && !isTimestamp(child)) fail('TIMESTAMP_REJECTED', next)
    validateStringsAndTimes(child, next)
  }
}

function inventoryDigest() {
  const inventory = []
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) walk(absolute)
      else if (entry.isFile()) inventory.push({
        path: path.relative(root, absolute).split(path.sep).join('/'),
        raw_sha256: rawSha(absolute),
      })
      else fail('SPECIAL_FILE_IN_CONTRACT_ROOT', entry.name)
    }
  }
  walk(root)
  inventory.sort((left, right) => left.path.localeCompare(right.path))
  return canonicalSha256(inventory)
}

const catalog = readJson(path.join(root, 'contract-catalog-v1.json'))
const classifications = readJson(path.join(root, 'classifications-v1.json'))
const digestProfiles = readJson(path.join(root, 'digest-profiles-v1.json'))
const fieldRegistry = readJson(path.join(root, 'field-registry-v1.json'))
const validFixtures = readJson(path.join(fixtureRoot, 'valid-contracts-v1.json'))
const invalidFixtures = readJson(path.join(fixtureRoot, 'invalid-contracts-v1.json'))
const golden = readJson(path.join(fixtureRoot, 'golden-vectors-v1.json'))
const frozenCommon = readJson(path.join(frozenD90Root, 'common-v1.schema.json'))
const frozenD90CapabilitySchema = readJson(path.join(frozenD90Root, 'custody-capability-control-v1.schema.json'))
const frozenD90IdentityBindingsSchema = readJson(path.join(frozenD90Root, 'identity-bindings-v1.schema.json'))
const frozenD90RuntimeProfileSchema = readJson(path.join(frozenD90Root, 'runtime-profile-v1.schema.json'))
const frozenD90ClearanceSchema = readJson(path.join(frozenD90Root, 'clearance-record-v1.schema.json'))
const frozenD90CustodyMessageSchema = readJson(path.join(frozenD90Root, 'custody-adapter-message-v1.schema.json'))
const frozenD90Fixtures = readJson(path.join(frozenD90Root, 'fixtures/valid-contracts-v1.json'))
const frozenD930Common = readJson(path.join(frozenD930Root, 'common-v1.schema.json'))
const frozenD930OperationalProfileSchema = readJson(path.join(frozenD930Root, 'operational-profile-v1.schema.json'))
const frozenD930PrimaryReceiptSchema = readJson(path.join(frozenD930Root, 'primary-durability-receipt-v1.schema.json'))
const frozenD930IntegrityLifecycleSchema = readJson(path.join(frozenD930Root, 'integrity-access-lifecycle-record-v1.schema.json'))
const frozenD930Fixtures = readJson(path.join(frozenD930Root, 'fixtures/valid-contracts-v1.json'))
const common = readJson(path.join(root, 'common-v1.schema.json'))
const schemas = new Map(schemaFiles.map((file) => [file, readJson(path.join(root, file))]))

const ajv = new Ajv2020({ allErrors: true, strict: false })
ajv.addSchema(frozenCommon)
ajv.addSchema(frozenD90CapabilitySchema)
ajv.addSchema(frozenD90IdentityBindingsSchema)
ajv.addSchema(frozenD90RuntimeProfileSchema)
ajv.addSchema(frozenD90ClearanceSchema)
ajv.addSchema(frozenD90CustodyMessageSchema)
ajv.addSchema(frozenD930Common)
ajv.addSchema(frozenD930OperationalProfileSchema)
ajv.addSchema(frozenD930PrimaryReceiptSchema)
ajv.addSchema(frozenD930IntegrityLifecycleSchema)
ajv.addSchema(common)
for (const schema of schemas.values()) ajv.addSchema(schema)

const schemaByFormat = new Map(schemaFiles.map((file) => {
  const schema = schemas.get(file)
  return [`${schema.properties.format.const}/${schema.properties.format_version.const}`, schema]
}))

function validateSchema(record) {
  const schema = schemaByFormat.get(`${record.format}/${record.format_version}`)
  if (!schema) fail('UNSUPPORTED_CONTRACT', `${record.format}/${record.format_version}`)
  const validator = ajv.getSchema(schema.$id)
  if (!validator(record)) fail('SCHEMA_REJECTED', ajv.errorsText(validator.errors))
}

function validateFrozenSchema(schema, record) {
  const validator = ajv.getSchema(schema.$id)
  if (!validator(record)) fail('FROZEN_SCHEMA_REJECTED', ajv.errorsText(validator.errors))
}

function validateSubject(subject) {
  const computed = canonicalSha256({ subject_kind_code: subject.subject_kind_code, subject_payload: subject.subject_payload })
  if (computed !== subject.subject_identity_sha256) fail('SUBJECT_IDENTITY_MISMATCH')
  const expectedKeys = {
    artifact: ['artifact'],
    custody_copy: ['artifact', 'backend_code', 'backend_reference', 'copy_code'],
    evidence_bundle: ['bundle'],
    processing_output: ['artifact', 'bundle', 'processing_output_code', 'processing_run_code'],
    candidate_occurrence: ['bundle', 'candidate_chain_code', 'candidate_record_code'],
    authority_draft: ['draft_code', 'draft_version_sha256'],
  }
  if (canonicalize(Object.keys(subject.subject_payload).sort()) !== canonicalize(expectedKeys[subject.subject_kind_code])) fail('SUBJECT_KIND_PAYLOAD_MISMATCH')
}

function bindingCode(actor) {
  return actor.identity_binding.binding_code
}

function validateD901IdentityGeneration(bindings = validFixtures.records.identity_bindings) {
  validateFrozenSchema(frozenD90IdentityBindingsSchema, bindings)
  if (bindings.record_digest_sha256 !== recordDigest(bindings)) fail('IDENTITY_BINDINGS_DIGEST_MISMATCH')
  const runtime = frozenD90Fixtures.fixtures.find((entry) => entry.fixture_code === 'runtime_profile')?.value
  validateFrozenSchema(frozenD90RuntimeProfileSchema, runtime)
  if (runtime.record_digest_sha256 !== recordDigest(runtime) || bindings.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || bindings.runtime_domain_sha256 !== runtime.runtime_domain_sha256) fail('D901_RUNTIME_PROFILE_MISMATCH')
  if (bindings.issued_at < runtime.issued_at) fail('D901_IDENTITY_BINDING_CHRONOLOGY_REJECTED')
  const osSubjects = new Set()
  const serviceEndpoints = new Set()
  for (const binding of bindings.bindings) {
    const subjectIdentity = `${bindings.runtime_domain_sha256}/${binding.subject_kind_code}/${binding.unix_uid}`
    if (osSubjects.has(subjectIdentity)) fail('D901_OS_SUBJECT_COLLISION')
    osSubjects.add(subjectIdentity)
    if (binding.principal_kind_code === 'service') {
      if (binding.executable_sha256 === null || binding.ipc_endpoint_code === null) fail('D901_SERVICE_IDENTITY_INCOMPLETE')
      if (serviceEndpoints.has(binding.ipc_endpoint_code)) fail('D901_SERVICE_ENDPOINT_COLLISION')
      serviceEndpoints.add(binding.ipc_endpoint_code)
    }
  }
  return bindings
}

function validateAuthorityRoster(record) {
  validateRecord(record)
  const bindings = validateD901IdentityGeneration()
  if (record.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || record.binding_set_code !== bindings.binding_set_code || record.binding_generation !== bindings.binding_generation) fail('IDENTITY_BINDING_GENERATION_MISMATCH')
  if (!(record.valid_from < record.valid_until)) fail('ROSTER_INTERVAL_REJECTED')
  if (new Set(record.assignments.map((entry) => entry.binding_code)).size !== record.assignments.length) fail('ROSTER_BINDING_COLLISION')
  for (const assignment of record.assignments) {
    const rule = classifications.role_assignment_rules.find((entry) => entry.role_code === assignment.role_code)
    if (!rule || rule.actor_kind_code !== assignment.actor_kind_code || !rule.allowed_d901_runtime_role_codes.includes(assignment.d901_runtime_role_code)) fail('ROLE_ASSIGNMENT_REJECTED')
    if ((assignment.actor_kind_code === 'human') !== (assignment.principal_code !== null)) fail('ROLE_ASSIGNMENT_PRINCIPAL_REJECTED')
  }
}

function rosterAdoptionScope(roster, bindings) {
  return canonicalSha256({
    authority_roster_record_digest_sha256: roster.record_digest_sha256,
    identity_bindings_record_digest_sha256: bindings.record_digest_sha256,
    binding_set_code: bindings.binding_set_code,
    binding_generation: bindings.binding_generation,
    roster_generation: roster.roster_generation,
  })
}

function validateAuthorityRosterAdoption(record, roster = validFixtures.records.authority_roster, bindings = validFixtures.records.identity_bindings) {
  validateRecord(record)
  const scope = rosterAdoptionScope(roster, bindings)
  if (record.authority_roster_record_digest_sha256 !== roster.record_digest_sha256 || record.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || record.binding_set_code !== bindings.binding_set_code || record.binding_generation !== bindings.binding_generation || record.scope_sha256 !== scope) fail('ROSTER_ADOPTION_SCOPE_MISMATCH')
  const decisionBindings = new Set()
  const decisionPrincipals = new Set()
  for (const decision of record.decisions) {
    const binding = bindings.bindings.find((entry) => entry.binding_code === decision.binding_code)
    if (!binding || binding.principal_kind_code !== 'human' || binding.runtime_role_code !== decision.runtime_role_code || binding.atlas_principal_code !== decision.principal_code || !['operational_witness', 'recovery_authority', 'bootstrap_authority'].includes(binding.runtime_role_code)) fail('ROSTER_ADOPTION_ACTOR_REJECTED')
    if (roster.assignments.some((entry) => entry.binding_code === binding.binding_code)) fail('ROSTER_SELF_ADOPTION_REJECTED')
    if (decision.scope_sha256 !== scope || !(bindings.issued_at <= decision.decided_at && decision.decided_at < bindings.expires_at && binding.valid_from <= decision.decided_at && decision.decided_at < binding.valid_until && decision.decided_at <= record.adopted_at)) fail('ROSTER_ADOPTION_CHRONOLOGY_REJECTED')
    if (decision.decision_digest_sha256 !== canonicalSha256(Object.fromEntries(Object.entries(decision).filter(([key]) => key !== 'decision_digest_sha256')))) fail('ROSTER_ADOPTION_DECISION_DIGEST_MISMATCH')
    if (decisionBindings.has(binding.binding_code)) fail('ROSTER_INDEPENDENT_APPROVAL_REQUIRED')
    if (decisionPrincipals.has(binding.atlas_principal_code)) fail('ROSTER_INDEPENDENT_APPROVAL_REQUIRED')
    decisionBindings.add(binding.binding_code)
    decisionPrincipals.add(binding.atlas_principal_code)
  }
  if (decisionBindings.size < 2 || decisionPrincipals.size < 2 || record.adopted_at < roster.valid_from || record.adopted_at >= roster.valid_until) fail('ROSTER_INDEPENDENT_APPROVAL_REQUIRED')
}

function validateActor(actor, at = '2030-01-01T00:00:00.000Z') {
  const roster = validFixtures.records.authority_roster
  const bindings = validFixtures.records.identity_bindings
  const adoption = validFixtures.records.authority_roster_adoption
  validateAuthorityRosterAdoption(adoption, roster, bindings)
  if (actor.authority_roster_record_digest_sha256 !== roster.record_digest_sha256) fail('AUTHORITY_ROSTER_MISMATCH')
  const ref = actor.identity_binding
  if (ref.identity_bindings_record_digest_sha256 !== roster.identity_bindings_record_digest_sha256 || ref.binding_set_code !== roster.binding_set_code || ref.binding_generation !== roster.binding_generation) fail('IDENTITY_BINDING_GENERATION_MISMATCH')
  if (!(roster.valid_from <= at && adoption.adopted_at <= at && at < roster.valid_until)) fail('AUTHORITY_ROSTER_EXPIRED_OR_INACTIVE')
  const assignment = roster.assignments.find((entry) => entry.binding_code === ref.binding_code)
  if (!assignment) fail('ACTOR_BINDING_UNRESOLVED')
  const binding = bindings.bindings.find((entry) => entry.binding_code === ref.binding_code)
  if (!binding || binding.runtime_role_code !== assignment.d901_runtime_role_code || binding.principal_kind_code !== assignment.actor_kind_code || binding.atlas_principal_code !== assignment.principal_code) fail('D901_IDENTITY_BINDING_UNRESOLVED')
  if (!(bindings.issued_at <= at && at < bindings.expires_at && binding.valid_from <= at && at < binding.valid_until)) fail('D901_IDENTITY_BINDING_EXPIRED_OR_INACTIVE')
  for (const field of ['actor_kind_code', 'role_code', 'principal_code']) if (actor[field] !== assignment[field]) fail('ACTOR_CLAIM_MISMATCH')
  if (actor.actor_kind_code === 'human' && actor.principal_code === null) fail('HUMAN_PRINCIPAL_REQUIRED')
  if (actor.actor_kind_code === 'service' && actor.role_code.endsWith('_authority')) fail('SERVICE_HUMAN_AUTHORITY_REJECTED')
}

function resolveD901Binding(code, expectedRole, at, expectedPrincipalKind = null) {
  const bindings = validFixtures.records.identity_bindings
  if (!(bindings.issued_at <= at && at < bindings.expires_at)) fail('D901_IDENTITY_BINDING_EXPIRED_OR_INACTIVE')
  const binding = bindings.bindings.find((entry) => entry.binding_code === code)
  if (!binding || binding.runtime_role_code !== expectedRole || (expectedPrincipalKind !== null && binding.principal_kind_code !== expectedPrincipalKind)) fail('D901_IDENTITY_BINDING_UNRESOLVED')
  if (!(binding.valid_from <= at && at < binding.valid_until)) fail('D901_IDENTITY_BINDING_EXPIRED_OR_INACTIVE')
  return binding
}

function validateRecord(record) {
  validateSchema(record)
  validateStringsAndTimes(record)
  if (record.record_digest_sha256 !== recordDigest(record)) fail('DIGEST_MISMATCH', record.record_code)
  if (record.subject) validateSubject(record.subject)
}

function validateKnowledge(record) {
  const boundary = record.knowledge_boundary
  if (!(boundary.effective_at <= boundary.recorded_at && boundary.recorded_at <= boundary.persisted_at)) fail('KNOWLEDGE_CHRONOLOGY_REJECTED')
  if (boundary.journal_namespace_code !== classifications.journal_rules.journal_namespace_code) fail('JOURNAL_NAMESPACE_MISMATCH')
  const semanticActor = record.semantic_actor ?? record.independent_verifier
  if (!semanticActor) fail('SEMANTIC_ACTOR_MISSING')
  validateActor(semanticActor, boundary.recorded_at)
  validateActor(record.persistence_actor, boundary.persisted_at)
  if (record.persistence_actor.actor_kind_code !== 'service' || record.persistence_actor.role_code !== 'journal_broker') fail('PERSISTENCE_ACTOR_REJECTED')
  if (bindingCode(semanticActor) === bindingCode(record.persistence_actor)) fail('ROLE_SEPARATION_REJECTED')
}

function validateChain(records) {
  const byStream = Map.groupBy(records, (record) => record.chain.stream_code)
  for (const stream of byStream.values()) {
    const sorted = stream.slice().sort((left, right) => left.chain.sequence - right.chain.sequence)
    const root = sorted[0]
    for (let index = 0; index < sorted.length; index += 1) {
      const record = sorted[index]
      if (record.format !== root.format || record.operation_id !== root.operation_id || record.operation_nonce !== root.operation_nonce || record.subject.subject_identity_sha256 !== root.subject.subject_identity_sha256) fail('CHAIN_CONTEXT_MISMATCH')
      if (record.chain.sequence !== index + 1) fail('CHAIN_GAP')
      const expectedPredecessor = index === 0 ? null : sorted[index - 1].record_digest_sha256
      if (record.chain.predecessor_record_digest_sha256 !== expectedPredecessor) fail('CHAIN_FORK_OR_PREDECESSOR_MISMATCH')
      if (index && record.knowledge_boundary.persisted_at <= sorted[index - 1].knowledge_boundary.persisted_at) fail('CHAIN_BACKDATING_REJECTED')
      if (index && record.knowledge_boundary.receipt_sequence <= sorted[index - 1].knowledge_boundary.receipt_sequence) fail('KNOWLEDGE_SEQUENCE_REJECTED')
      if (record.format === 'jedi-atlas-custody-control-record') {
        if (index === 0 && ['control_corrected', 'control_withdrawn'].includes(record.record_kind_code)) fail('CONTROL_TRANSITION_REJECTED')
        if (index > 0) {
          const prior = sorted[index - 1]
          if (['control_corrected', 'control_withdrawn'].includes(record.record_kind_code)) {
            const rule = classifications.correction_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
            const priorSemanticKind = ['control_corrected'].includes(prior.record_kind_code) ? prior.corrected_record_kind_code : prior.record_kind_code
            if (!rule.target_codes.includes(priorSemanticKind) || record.corrects_record_digest_sha256 !== prior.record_digest_sha256 || record.corrected_record_kind_code !== priorSemanticKind || record.knowledge_boundary.effective_at !== prior.knowledge_boundary.effective_at) fail('CORRECTION_TARGET_REJECTED')
          } else {
            const priorSemanticKind = prior.record_kind_code === 'control_corrected' ? prior.corrected_record_kind_code : prior.record_kind_code
            const transition = classifications.control_transition_rules.find((entry) => entry.from_code === priorSemanticKind && entry.to_code === record.record_kind_code)
            const expectedBasis = record.record_kind_code === 'deletion_authorization_revoked' && priorSemanticKind === 'tombstone_applied'
              ? sorted.find((entry) => entry.record_kind_code === 'deletion_authorized')?.record_digest_sha256
              : prior.record_digest_sha256
            if (!transition || record.basis_record_digest_sha256 !== expectedBasis) fail('CONTROL_TRANSITION_REJECTED')
            if (['restriction_released', 'quarantine_released', 'hold_released'].includes(record.record_kind_code) && (record.restriction_scope_code !== prior.restriction_scope_code || record.reason_category_code !== prior.reason_category_code)) fail('CONTROL_RELEASE_CONTEXT_MISMATCH')
          }
        } else if (!classifications.control_transition_rules.some((entry) => entry.from_code === 'none' && entry.to_code === record.record_kind_code)) fail('CONTROL_TRANSITION_REJECTED')
      }
      if (record.format === 'jedi-atlas-deletion-execution-record') {
        const from = index === 0 ? 'none' : ({ execution_started: 'execution_started', inventory_observed: 'inventory_observed', unlink_attempted: 'primary_name_removed' }[sorted[index - 1].record_kind_code] ?? 'recovery_required')
        if (!classifications.deletion_transition_rules.some((entry) => entry.from_code === from && entry.record_kind_code === record.record_kind_code)) fail('EXECUTION_TRANSITION_REJECTED')
      }
      if (record.format === 'jedi-atlas-access-revocation-record') {
        if (record.access_target_identity_sha256 !== root.access_target_identity_sha256 || record.access_target_kind_code !== root.access_target_kind_code) fail('ACCESS_TARGET_CONTEXT_MISMATCH')
        if (root.access_target_kind_code === 'unconsumed_capability') {
          if (sorted.length !== 1 || index !== 0 || record.record_kind_code !== 'capability_revoked') fail('ACCESS_TRANSITION_REJECTED')
        } else {
          if ((index === 0 && record.record_kind_code !== 'descriptor_termination_requested') || (index === 1 && !['descriptor_termination_confirmed', 'descriptor_termination_failed'].includes(record.record_kind_code)) || index > 1) fail('ACCESS_TRANSITION_REJECTED')
          if (index > 0 && (record.descriptor_lifecycle_record_digest_sha256 !== root.descriptor_lifecycle_record_digest_sha256 || record.receiver_process_instance_code !== root.receiver_process_instance_code)) fail('ACCESS_DESCRIPTOR_CONTEXT_MISMATCH')
        }
      }
    }
  }
}

function controlApprovalScope(record) {
  return canonicalSha256({
    record_kind_code: record.record_kind_code,
    subject_identity_sha256: record.subject.subject_identity_sha256,
    operation_id: record.operation_id,
    operation_nonce: record.operation_nonce,
    reason_category_code: record.reason_category_code,
    restriction_scope_code: record.restriction_scope_code,
    basis_record_digest_sha256: record.basis_record_digest_sha256,
    corrects_record_digest_sha256: record.corrects_record_digest_sha256,
    effective_at: record.knowledge_boundary.effective_at,
  })
}

function validateHumanApprovals(record, requiredScope) {
  const principals = new Set()
  for (const approval of record.human_approvals) {
    validateActor(approval.actor, approval.decided_at)
    if (approval.actor.actor_kind_code !== 'human' || approval.decision_code !== 'approve') fail('HUMAN_GATE_REJECTED')
    if (approval.scope_sha256 !== requiredScope) fail('APPROVAL_SCOPE_MISMATCH')
    if (!(record.knowledge_boundary.effective_at <= approval.decided_at && approval.decided_at <= record.knowledge_boundary.recorded_at)) fail('APPROVAL_CHRONOLOGY_REJECTED')
    if (approval.expires_at === null || !(approval.decided_at < approval.expires_at) || approval.expires_at <= record.knowledge_boundary.persisted_at) fail('APPROVAL_EXPIRED')
    if (record.authorization_expires_at !== null && approval.expires_at < record.authorization_expires_at) fail('AUTHORIZATION_OUTLIVES_APPROVAL')
    if (approval.record_digest_sha256 !== recordDigest(approval)) fail('APPROVAL_DIGEST_MISMATCH')
    if (principals.has(approval.actor.principal_code)) fail('DISTINCT_HUMANS_REQUIRED')
    principals.add(approval.actor.principal_code)
    if (approval.actor.principal_code === record.semantic_actor.principal_code) fail('SELF_APPROVAL_REJECTED')
  }
  return principals
}

function validateControl(record, clearanceGraph = null) {
  validateRecord(record)
  validateKnowledge(record)
  const rule = classifications.control_record_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  if (!rule) fail('CONTROL_MATRIX_REJECTED')
  if (Buffer.byteLength(record.reason_summary, 'utf8') > 512 || record.reason_summary.trim().length === 0) fail('REASON_SUMMARY_REJECTED')
  if (rule.restriction_scope_required !== (record.restriction_scope_code !== null)) fail('CONTROL_MATRIX_REJECTED')
  if (rule.basis_required !== (record.basis_record_digest_sha256 !== null)) fail('CONTROL_MATRIX_REJECTED', `${record.record_kind_code}/basis`)
  if (rule.clearance_reference_required !== (record.clearance_reference !== null)) fail('CONTROL_MATRIX_REJECTED')
  if (record.record_kind_code === 'clearance_revoked') validateClearanceReference(record, clearanceGraph ?? { decision: d901ClearanceDecision, transitions: [d901ClearanceTransition] })
  if (rule.correction_required !== (record.corrects_record_digest_sha256 !== null)) fail('CONTROL_MATRIX_REJECTED')
  if (rule.propagation_required !== (record.propagates_from_subject_identity_sha256 !== null)) fail('CONTROL_MATRIX_REJECTED')
  if (rule.authorization_required !== (record.authorization_scope !== null && record.authorization_scope_sha256 !== null && record.authorization_expires_at !== null)) fail('CONTROL_MATRIX_REJECTED')
  if (!rule.authorization_required && record.authorization_scope !== null) fail('CONTROL_MATRIX_REJECTED')
  if (record.record_kind_code === 'control_corrected') {
    if (record.corrected_record_kind_code === null || record.withdrawal_effect_code !== null) fail('CORRECTION_SEMANTICS_REJECTED')
  } else if (record.record_kind_code === 'control_withdrawn') {
    if (record.corrected_record_kind_code === null || record.withdrawal_effect_code !== 'void_for_derived_projection_keep_history') fail('WITHDRAWAL_SEMANTICS_REJECTED')
  } else if (record.corrected_record_kind_code !== null || record.withdrawal_effect_code !== null) fail('CORRECTION_SEMANTICS_REJECTED')
  const actorRule = classifications.action_actor_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  if (!actorRule.semantic_role_codes.includes(record.semantic_actor.role_code)) fail('ROLE_SUBSTITUTION_REJECTED')
  if (!actorRule.semantic_actor_kind_codes.includes(record.semantic_actor.actor_kind_code)) fail('HUMAN_GATE_REJECTED')
  const deletionApprovalRule = record.record_kind_code === 'deletion_authorized'
    ? classifications.deletion_approval_rules.find((entry) => entry.reason_category_code === record.reason_category_code)
    : null
  if (deletionApprovalRule?.authorization_code === 'blocked_while_hold_active') fail('DELETION_AUTHORIZATION_BLOCKED')
  const requiredScope = record.authorization_scope_sha256 ?? controlApprovalScope(record)
  const humans = validateHumanApprovals(record, requiredScope)
  if (humans.size < actorRule.minimum_distinct_human_approvals) fail('HUMAN_GATE_REJECTED')
  for (const role of actorRule.required_approval_role_codes) if (!record.human_approvals.some((entry) => entry.actor.role_code === role)) fail('REQUIRED_APPROVAL_ROLE_MISSING')
  if (record.record_kind_code === 'deletion_authorized') {
    if (record.authorization_scope_sha256 !== canonicalSha256(record.authorization_scope)) fail('AUTHORIZATION_SCOPE_MISMATCH')
    if (record.human_approvals.some((approval) => approval.actor.principal_code === record.authorization_scope.requester_principal_code)) fail('SELF_APPROVAL_REJECTED')
    if (record.authorization_scope.valid_until !== record.authorization_expires_at || record.authorization_scope.valid_from > record.knowledge_boundary.persisted_at || record.authorization_expires_at <= record.knowledge_boundary.persisted_at) fail('AUTHORIZATION_INTERVAL_REJECTED')
    if (Date.parse(record.authorization_expires_at) - Date.parse(record.authorization_scope.valid_from) > validFixtures.records.operational_profile.settings.maximum_authorization_lifetime_ms) fail('AUTHORIZATION_LIFETIME_EXCEEDED')
    const approvalRule = deletionApprovalRule
    if (!approvalRule || approvalRule.authorization_code !== 'eligible_for_human_decision') fail('DELETION_AUTHORIZATION_BLOCKED')
    for (const role of approvalRule.required_human_role_codes) if (!record.human_approvals.some((approval) => approval.actor.role_code === role)) fail('DELETION_APPROVAL_ROLES_MISSING')
    if (humans.size < approvalRule.minimum_distinct_humans) fail('DISTINCT_HUMANS_REQUIRED')
  }
}

function accessTargetIdentity(record) {
  return canonicalSha256(record.access_target_kind_code === 'unconsumed_capability'
    ? { access_target_kind_code: record.access_target_kind_code, capability_record_digest_sha256: record.capability_record_digest_sha256, capability_leaf_record_digest_sha256: record.capability_leaf_record_digest_sha256 }
    : { access_target_kind_code: record.access_target_kind_code, descriptor_lifecycle_record_digest_sha256: record.descriptor_lifecycle_record_digest_sha256, receiver_process_instance_code: record.receiver_process_instance_code })
}

function validateAccess(record) {
  validateRecord(record)
  validateKnowledge(record)
  if (record.subject.subject_kind_code !== 'custody_copy') fail('ACCESS_SUBJECT_REJECTED')
  const rule = classifications.access_revocation_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  if (!rule) fail('ACCESS_MATRIX_REJECTED')
  if (!rule.semantic_role_codes.includes(record.semantic_actor.role_code) || !rule.semantic_actor_kind_codes.includes(record.semantic_actor.actor_kind_code)) fail('ACCESS_ACTOR_REJECTED')
  if (rule.capability_required !== (record.capability_record_digest_sha256 !== null && record.capability_leaf_record_digest_sha256 !== null)) fail('ACCESS_MATRIX_REJECTED')
  if (rule.descriptor_required !== (record.descriptor_lifecycle_record_digest_sha256 !== null && record.receiver_process_instance_code !== null)) fail('ACCESS_MATRIX_REJECTED')
  if (record.access_target_kind_code === 'unconsumed_capability') {
    if (!rule.capability_required || record.descriptor_lifecycle_record_digest_sha256 !== null || record.receiver_process_instance_code !== null) fail('ACCESS_TARGET_REJECTED')
  } else if (!rule.descriptor_required || record.capability_record_digest_sha256 !== null || record.capability_leaf_record_digest_sha256 !== null) fail('ACCESS_TARGET_REJECTED')
  if (record.access_target_identity_sha256 !== accessTargetIdentity(record)) fail('ACCESS_TARGET_IDENTITY_MISMATCH')
  const terminalFields = ['sender_close_state_code', 'receiver_termination_state_code', 'descriptor_close_state_code', 'termination_disposition_code']
  if (record.record_kind_code === 'descriptor_termination_confirmed') {
    if (terminalFields.some((field) => record[field] === null || record[field] === 'unknown')) fail('DESCRIPTOR_TERMINATION_UNCONFIRMED')
  } else if (record.record_kind_code === 'descriptor_termination_failed') {
    if (terminalFields.some((field) => record[field] === null) || !terminalFields.some((field) => record[field] === 'unknown')) fail('DESCRIPTOR_FAILURE_STATE_REJECTED')
  } else if (terminalFields.some((field) => record[field] !== null)) fail('ACCESS_MATRIX_REJECTED')
}

function validateExecution(record) {
  validateRecord(record)
  validateKnowledge(record)
  if (record.subject.subject_kind_code !== 'custody_copy') fail('DELETION_SUBJECT_REJECTED')
  const rule = classifications.deletion_execution_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  if (!rule || record.execution.method_code !== rule.method_code || record.execution.outcome_code !== rule.required_outcome_code || record.semantic_actor.role_code !== rule.semantic_role_code) fail('EXECUTION_MATRIX_REJECTED')
  if (record.record_kind_code !== 'reconciliation_required' && record.access_shutdown_state_code !== 'confirmed') fail('ACCESS_SHUTDOWN_REQUIRED')
  if (record.safety_snapshot.journal_namespace_code !== classifications.journal_rules.journal_namespace_code || record.safety_snapshot.active_hold_count !== 0 || record.safety_snapshot.unknown_or_conflicting_control_count !== 0) fail('SAFETY_SNAPSHOT_BLOCKS_DELETION')
  const snapshotPayload = Object.fromEntries(Object.entries(record.safety_snapshot).filter(([key]) => key !== 'snapshot_sha256'))
  if (record.safety_snapshot.snapshot_sha256 !== canonicalSha256(snapshotPayload)) fail('SAFETY_SNAPSHOT_MISMATCH')
  if (record.safety_snapshot.known_through_persisted_at > record.knowledge_boundary.recorded_at || record.safety_snapshot.known_through_receipt_sequence >= record.knowledge_boundary.receipt_sequence) fail('SAFETY_SNAPSHOT_CHRONOLOGY_REJECTED')
  if (['inventory_observed', 'unlink_attempted', 'unlink_failed', 'primary_absence_verified'].includes(record.record_kind_code)) {
    const inventory = record.inventory
    if (!inventory.inventory_complete || inventory.open_descriptors || inventory.hard_links || inventory.unexpected_replicas || inventory.temporary_objects || !inventory.parent_directory_opened_no_follow || inventory.symlink_observed) fail('INVENTORY_BLOCKS_DELETION')
    if (record.record_kind_code === 'primary_absence_verified') {
      if (inventory.target_file_type_code !== 'absent' || inventory.target_opened_no_follow || [inventory.target_device, inventory.target_inode, inventory.observed_target_sha256, inventory.observed_target_byte_length, inventory.observed_target_link_count].some((value) => value !== null) || inventory.prior_target_observation_record_digest_sha256 === null) fail('ABSENCE_INVENTORY_STATE_MISMATCH')
    } else if (inventory.target_file_type_code !== 'regular_file' || !inventory.target_opened_no_follow || inventory.target_device === null || inventory.target_inode === null || inventory.observed_target_sha256 !== record.subject.subject_payload.artifact.sha256 || inventory.observed_target_byte_length !== record.subject.subject_payload.artifact.byte_length || inventory.observed_target_link_count !== 1 || inventory.prior_target_observation_record_digest_sha256 !== null) fail('OBSERVED_TARGET_IDENTITY_MISMATCH')
  }
  if (record.record_kind_code === 'unlink_attempted' && (!record.execution.target_name_removed || !record.execution.directory_synced || record.execution.reopened_target_absent)) fail('UNLINK_RESULT_CONTRADICTORY')
  if (record.record_kind_code === 'primary_absence_verified') {
    if (record.inventory.approved_primary_names_checked < 1 || record.inventory.matching_primary_names !== 0 || record.inventory.target_file_type_code !== 'absent' || !record.execution.target_name_removed || !record.execution.directory_synced || !record.execution.reopened_target_absent) fail('PRIMARY_ABSENCE_NOT_VERIFIED')
  }
}

function validateObservedIdentityAgainstBaseline(record, baselineIdentity) {
  for (const field of ['parent_directory_device', 'parent_directory_inode']) if (record.inventory[field] !== baselineIdentity[field]) fail('CUSTODY_OBSERVED_IDENTITY_DIVERGENCE')
  if (record.record_kind_code !== 'primary_absence_verified') for (const field of ['target_device', 'target_inode', 'observed_target_sha256', 'observed_target_byte_length', 'observed_target_link_count']) if (record.inventory[field] !== baselineIdentity[field]) fail('CUSTODY_OBSERVED_IDENTITY_DIVERGENCE')
}

function validateReceipt(record) {
  validateRecord(record)
  validateKnowledge(record)
  validateActor(record.executor, record.knowledge_boundary.persisted_at)
  validateActor(record.independent_verifier, record.knowledge_boundary.persisted_at)
  validateActor(record.persistence_actor, record.knowledge_boundary.persisted_at)
  if (record.subject.subject_kind_code !== 'custody_copy') fail('DELETION_SUBJECT_REJECTED')
  if (record.executor.role_code !== 'deletion_executor' || record.independent_verifier.role_code !== 'independent_verifier') fail('RECEIPT_ROLE_REJECTED')
  if (bindingCode(record.executor) === bindingCode(record.independent_verifier)) fail('ROLE_SEPARATION_REJECTED')
  const executorBinding = resolveD901Binding(bindingCode(record.executor), 'custody_adapter', record.knowledge_boundary.persisted_at, 'service')
  const verifierBinding = resolveD901Binding(bindingCode(record.independent_verifier), 'independent_verifier', record.knowledge_boundary.persisted_at, 'service')
  if (executorBinding.unix_uid === verifierBinding.unix_uid) fail('ROLE_SEPARATION_REJECTED')
  if (record.complete_erasure_claimed || record.backup_erasure_claimed || record.legal_compliance_claimed) fail('OVERCLAIM_REJECTED')
  const mandatory = ['no_complete_erasure_claim', 'no_backup_erasure_claim', 'no_derived_copy_erasure_claim', 'no_replica_erasure_claim', 'no_open_descriptor_erasure_claim', 'no_storage_medium_overwrite_claim', 'no_legal_compliance_claim', 'compromised_kernel_or_root_out_of_scope', 'observation_is_time_bounded']
  for (const item of mandatory) if (!record.limitations.includes(item)) fail('RECEIPT_LIMITATION_MISSING')
  if (record.persistence_actor.role_code !== 'journal_broker' || !(record.completed_at <= record.knowledge_boundary.recorded_at && record.knowledge_boundary.recorded_at <= record.knowledge_boundary.persisted_at)) fail('KNOWLEDGE_CHRONOLOGY_REJECTED')
  const failClosedRemainingClasses = ['backup', 'derived', 'open_descriptor', 'replica', 'temporary', 'unknown']
  if (canonicalize(record.remaining_copy_classes) !== canonicalize(failClosedRemainingClasses)) fail('REMAINING_COPY_CLASSES_NOT_FAIL_CLOSED')
}

function validateBackup(record) {
  validateRecord(record)
  validateKnowledge(record)
  if (record.d95_execution_authority_code !== 'unreachable_until_separately_approved_d9_5') fail('D95_AUTHORITY_INVENTED')
  if (record.d95_backup_receipt_record_digest_sha256 !== null) fail('D95_RECEIPT_INVENTED')
  const rule = classifications.backup_coordination_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  if (!rule || rule.directive_code !== record.directive_code || !rule.semantic_role_codes.includes(record.semantic_actor.role_code)) fail('BACKUP_MATRIX_REJECTED')
}

function validateBackupBasis(record, controlRecords) {
  const rule = classifications.backup_coordination_rules.find((entry) => entry.record_kind_code === record.record_kind_code)
  const basis = controlRecords.find((entry) => entry.record_digest_sha256 === record.basis_control_record_digest_sha256)
  if (!rule || !basis || !rule.basis_record_kind_codes.includes(basis.record_kind_code)) fail('BACKUP_DIRECTIVE_BASIS_UNRESOLVED')
  if (basis.subject.subject_identity_sha256 !== record.subject.subject_identity_sha256 || basis.knowledge_boundary.receipt_sequence >= record.knowledge_boundary.receipt_sequence || basis.knowledge_boundary.persisted_at >= record.knowledge_boundary.persisted_at) fail('BACKUP_DIRECTIVE_BASIS_CONTEXT_MISMATCH')
  return basis
}

function validateRecovery(record) {
  validateRecord(record)
  validateKnowledge(record)
  if (record.action_execution_code !== 'none_classification_only' || record.recovery_authority_present) fail('RECOVERY_AUTHORITY_INVENTED')
  if (record.semantic_actor.role_code !== 'independent_verifier' || record.semantic_actor.actor_kind_code !== 'service') fail('RECOVERY_ACTOR_REJECTED')
  if (record.snapshot_digest_sha256 !== canonicalSha256(record.snapshot)) fail('RECOVERY_SNAPSHOT_MISMATCH')
  let derived
  if (record.control_state_code !== 'linear_complete') derived = 'human_decision_required'
  else if (record.inventory_state_code === 'contradictory' || record.access_state_code === 'contradictory') derived = 'human_decision_required'
  else if (['active_or_unknown', 'termination_pending'].includes(record.access_state_code)) derived = 'retain_and_hold'
  else if (['incomplete', 'unavailable'].includes(record.inventory_state_code)) derived = 'reconciliation_required'
  else derived = classifications.recovery_boundary_defaults.find((entry) => entry.crash_boundary_code === record.crash_boundary_code)?.classification_code
  if (!derived || derived !== record.classification_code) fail('RECOVERY_CLASSIFICATION_MISMATCH')
}

function addDigest(record) {
  record.record_digest_sha256 = recordDigest(record)
  return record
}

const subject = clone(validFixtures.records.restriction.subject)
const frozenD90Fixture = (code) => clone(frozenD90Fixtures.fixtures.find((entry) => entry.fixture_code === code)?.value)

function clearanceScopeDigest(decision) {
  return canonicalSha256({
    artifact: decision.artifact,
    capture_context_code: decision.capture_context_code,
    conditions: decision.conditions,
    contains_credentials: decision.contains_credentials,
    contains_personal_data: decision.contains_personal_data,
    decision_code: decision.decision_code,
    derivative_use_code: decision.derivative_use_code,
    expires_at: decision.expires_at,
    git_permanence_acknowledged: decision.git_permanence_acknowledged,
    limitations: decision.limitations,
    not_before: decision.not_before,
    redistribution_scope_code: decision.redistribution_scope_code,
    repository_declarations: decision.repository_declarations,
    retention_scope_code: decision.retention_scope_code,
    sensitivity_code: decision.sensitivity_code,
  })
}

const d901ClearanceDecision = frozenD90Fixture('clearance_decision')
d901ClearanceDecision.record_code = 'clearance.decision.d940-reference.001'
d901ClearanceDecision.clearance_code = 'clearance.d940-reference.001'
d901ClearanceDecision.artifact = clone(subject.subject_payload.artifact)
d901ClearanceDecision.identity_bindings_record_digest_sha256 = validFixtures.records.identity_bindings.record_digest_sha256
d901ClearanceDecision.runtime_profile_record_digest_sha256 = validFixtures.records.identity_bindings.runtime_profile_record_digest_sha256
d901ClearanceDecision.scanner_results.forEach((result, index) => { result.completed_at = `2030-01-01T00:00:${String(25 + index).padStart(2, '0')}.000Z` })
d901ClearanceDecision.decided_by_binding_code = 'binding.clearance.decider.synthetic'
d901ClearanceDecision.independently_checked_by_binding_code = 'binding.clearance.synthetic'
d901ClearanceDecision.decided_at = '2030-01-01T00:00:30.000Z'
d901ClearanceDecision.not_before = '2030-01-01T00:00:31.000Z'
d901ClearanceDecision.recorded_at = '2030-01-01T00:00:31.000Z'
d901ClearanceDecision.expires_at = '2030-01-02T00:00:00.000Z'
d901ClearanceDecision.clearance_scope_sha256 = clearanceScopeDigest(d901ClearanceDecision)
d901ClearanceDecision.record_digest_sha256 = recordDigest(d901ClearanceDecision)
validateFrozenSchema(frozenD90ClearanceSchema, d901ClearanceDecision)

const d901ClearanceTransition = frozenD90Fixture('clearance_transition')
d901ClearanceTransition.record_code = 'clearance.transition.d940-reference.001'
d901ClearanceTransition.clearance_code = d901ClearanceDecision.clearance_code
d901ClearanceTransition.decision_record_digest_sha256 = d901ClearanceDecision.record_digest_sha256
d901ClearanceTransition.recorded_by_binding_code = 'binding.clearance.broker.synthetic'
d901ClearanceTransition.occurred_at = '2030-01-01T00:03:00.000Z'
d901ClearanceTransition.record_digest_sha256 = recordDigest(d901ClearanceTransition)
validateFrozenSchema(frozenD90ClearanceSchema, d901ClearanceTransition)

function validateClearanceReference(control, graph) {
  const { decision, transitions } = graph
  validateFrozenSchema(frozenD90ClearanceSchema, decision)
  if (decision.record_digest_sha256 !== recordDigest(decision)) fail('CLEARANCE_DECISION_DIGEST_MISMATCH')
  const bindings = validFixtures.records.identity_bindings
  if (decision.runtime_profile_record_digest_sha256 !== bindings.runtime_profile_record_digest_sha256 || decision.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256) fail('CLEARANCE_IDENTITY_GENERATION_MISMATCH')
  if (canonicalize(decision.artifact) !== canonicalize(control.subject.subject_payload.artifact) || decision.clearance_scope_sha256 !== clearanceScopeDigest(decision)) fail('CLEARANCE_SCOPE_MISMATCH')
  const decider = resolveD901Binding(decision.decided_by_binding_code, 'clearance_decider', decision.decided_at, 'human')
  const checker = resolveD901Binding(decision.independently_checked_by_binding_code, 'clearance_checker', decision.decided_at, 'human')
  if (decider.unix_uid === checker.unix_uid || !(decision.decided_at <= decision.not_before && decision.not_before <= decision.recorded_at && decision.recorded_at < decision.expires_at)) fail('CLEARANCE_DECISION_INVALID')
  if (transitions.length !== 1) fail('CLEARANCE_CURRENT_LEAF_AMBIGUOUS')
  const transition = transitions[0]
  validateFrozenSchema(frozenD90ClearanceSchema, transition)
  if (transition.record_digest_sha256 !== recordDigest(transition) || transition.clearance_code !== decision.clearance_code || transition.decision_record_digest_sha256 !== decision.record_digest_sha256 || transition.transition_sequence !== 1 || transition.previous_transition_record_digest_sha256 !== null || transition.state_code !== 'revoked' || transition.replacement_clearance_record_digest_sha256 !== null || transition.occurred_at <= decision.recorded_at) fail('CLEARANCE_TRANSITION_INVALID')
  resolveD901Binding(transition.recorded_by_binding_code, 'clearance_broker', transition.occurred_at, 'service')
  const reference = control.clearance_reference
  if (reference.clearance_code !== decision.clearance_code || reference.clearance_decision_record_digest_sha256 !== decision.record_digest_sha256 || reference.clearance_transition_record_digest_sha256 !== transition.record_digest_sha256 || reference.clearance_scope_sha256 !== decision.clearance_scope_sha256 || transition.occurred_at > control.knowledge_boundary.recorded_at) fail('CLEARANCE_REFERENCE_MISMATCH')
}

const d930OperationalProfile = clone(frozenD930Fixtures.records.custody_profile)
d930OperationalProfile.record_code = 'profile.custody.d940-reference.001'
d930OperationalProfile.issued_at = '2030-01-01T00:00:05.000Z'
d930OperationalProfile.record_digest_sha256 = recordDigest(d930OperationalProfile)
validateFrozenSchema(frozenD930OperationalProfileSchema, d930OperationalProfile)

const d930PrimaryReceipt = clone(frozenD930Fixtures.records.primary_receipt)
d930PrimaryReceipt.record_code = 'receipt.primary.d940-reference.001'
d930PrimaryReceipt.d930_operational_profile_record_digest_sha256 = d930OperationalProfile.record_digest_sha256
d930PrimaryReceipt.runtime_profile_record_digest_sha256 = validFixtures.records.identity_bindings.runtime_profile_record_digest_sha256
d930PrimaryReceipt.identity_bindings_record_digest_sha256 = validFixtures.records.identity_bindings.record_digest_sha256
d930PrimaryReceipt.semantic.operation_id = 'operation.custody.d940-reference.001'
d930PrimaryReceipt.semantic.operation_nonce = '30'.repeat(32)
d930PrimaryReceipt.semantic.artifact = clone(subject.subject_payload.artifact)
d930PrimaryReceipt.semantic.copy_code = subject.subject_payload.copy_code
d930PrimaryReceipt.semantic.backend_code = subject.subject_payload.backend_code
d930PrimaryReceipt.semantic.backend_reference = subject.subject_payload.backend_reference
d930PrimaryReceipt.semantic.adapter_binding_code = 'binding.custody.synthetic'
d930PrimaryReceipt.persisted_by_binding_code = 'binding.journal.synthetic'
d930PrimaryReceipt.semantic.completed_at = '2030-01-01T00:00:15.000Z'
d930PrimaryReceipt.persisted_at = '2030-01-01T00:00:16.000Z'
d930PrimaryReceipt.semantic_payload_sha256 = canonicalSha256(d930PrimaryReceipt.semantic)
d930PrimaryReceipt.persistence_request_record_digest_sha256 = '31'.repeat(32)
validateFrozenSchema(frozenD930PrimaryReceiptSchema, d930PrimaryReceipt)
const d930PrimaryReceiptSha256 = canonicalSha256(d930PrimaryReceipt)
function sealD930PrimaryReceiptStore(receipts) {
  return {
    selection_boundary_code: 'complete_protected_d930_primary_receipt_store_snapshot',
    receipt_count: receipts.length,
    receipt_store_head_sha256: canonicalSha256(receipts.map((receipt) => canonicalSha256(receipt)).sort()),
    receipts,
  }
}
const d930PrimaryReceiptStore = sealD930PrimaryReceiptStore([d930PrimaryReceipt])
const d930CustodyLeafProjectionSha256 = canonicalSha256({
  d930_operational_profile_record_digest_sha256: d930OperationalProfile.record_digest_sha256,
  d930_primary_durability_receipt_sha256: d930PrimaryReceiptSha256,
  artifact: subject.subject_payload.artifact,
  copy_code: subject.subject_payload.copy_code,
  backend_code: subject.subject_payload.backend_code,
  backend_reference: subject.subject_payload.backend_reference,
})

const sourceCapability = frozenD90Fixture('capability_sealed_issuance')
sourceCapability.record_code = 'capability.sealed.d940-reference.001'
sourceCapability.operation_id = 'operation.access.unconsumed.d940-reference.001'
sourceCapability.operation_nonce = '32'.repeat(32)
sourceCapability.issued_by_binding_code = 'binding.custody.synthetic'
sourceCapability.requester_binding_code = 'binding.importer.synthetic'
sourceCapability.adapter_binding_code = 'binding.custody.synthetic'
sourceCapability.runtime_profile_record_digest_sha256 = validFixtures.records.identity_bindings.runtime_profile_record_digest_sha256
sourceCapability.identity_bindings_record_digest_sha256 = validFixtures.records.identity_bindings.record_digest_sha256
sourceCapability.artifact = clone(subject.subject_payload.artifact)
sourceCapability.grant_scope.backend_code = subject.subject_payload.backend_code
sourceCapability.grant_scope.backend_reference = subject.subject_payload.backend_reference
sourceCapability.grant_scope.copy_code = subject.subject_payload.copy_code
sourceCapability.grant_scope.custody_leaf_projection_sha256 = d930CustodyLeafProjectionSha256
sourceCapability.grant_scope.clearance_decision_record_digest_sha256 = d901ClearanceDecision.record_digest_sha256
sourceCapability.grant_scope.clearance_scope_sha256 = d901ClearanceDecision.clearance_scope_sha256
sourceCapability.grant_scope.custody_evaluated_at = '2030-01-01T00:02:50.000Z'
sourceCapability.issued_at = '2030-01-01T00:02:50.000Z'
sourceCapability.expires_at = '2030-01-01T00:03:20.000Z'
sourceCapability.record_digest_sha256 = recordDigest(sourceCapability)
validateFrozenSchema(frozenD90CapabilitySchema, sourceCapability)

function consumedCapability(ordinal) {
  const issuance = clone(sourceCapability)
  issuance.record_code = `capability.sealed.d940-consumed.${String(ordinal).padStart(3, '0')}`
  issuance.operation_id = `operation.access.consumed.d940-reference.${String(ordinal).padStart(3, '0')}`
  issuance.operation_nonce = String(40 + ordinal).repeat(64).slice(0, 64)
  issuance.issued_at = `2030-01-01T00:02:${String(48 + ordinal * 3).padStart(2, '0')}.000Z`
  issuance.expires_at = new Date(Date.parse(issuance.issued_at) + 30000).toISOString()
  issuance.grant_scope.custody_evaluated_at = issuance.issued_at
  issuance.record_digest_sha256 = recordDigest(issuance)
  validateFrozenSchema(frozenD90CapabilitySchema, issuance)
  const request = d901OpenCustodyRequest(issuance, ordinal)
  const transition = frozenD90Fixture('capability_sealed_transition')
  transition.record_code = `capability.transition.d940-consumed.${String(ordinal).padStart(3, '0')}`
  transition.capability_record_digest_sha256 = issuance.record_digest_sha256
  transition.request_record_digest_sha256 = request.record_digest_sha256
  transition.recorded_by_binding_code = issuance.adapter_binding_code
  transition.occurred_at = new Date(Date.parse(issuance.issued_at) + 2000).toISOString()
  transition.record_digest_sha256 = recordDigest(transition)
  validateFrozenSchema(frozenD90CapabilitySchema, transition)
  const response = d901OpenCustodyResponse(issuance, request, transition, ordinal)
  return { issuance, current_leaf: transition, state_code: 'consumed', open_pair: { request, response } }
}

const consumedCapabilityOne = consumedCapability(1)
const consumedCapabilityTwo = consumedCapability(2)

function d901OpenCustodyRequest(issuance, ordinal) {
  const request = frozenD90Fixture('custody_open_access_request')
  request.record_code = `custody.open-request.d940-reference.${String(ordinal).padStart(3, '0')}`
  request.operation_id = issuance.operation_id
  request.operation_nonce = issuance.operation_nonce
  request.request_id = `request.open-custody.d940-reference.${String(ordinal).padStart(3, '0')}`
  request.request_sequence = ordinal
  request.sender_binding_code = 'binding.importer.synthetic'
  request.recipient_binding_code = 'binding.custody.synthetic'
  request.runtime_profile_record_digest_sha256 = issuance.runtime_profile_record_digest_sha256
  request.created_at = new Date(Date.parse(issuance.issued_at) + 1000).toISOString()
  request.payload.artifact = clone(issuance.artifact)
  request.payload.backend_code = issuance.grant_scope.backend_code
  request.payload.backend_reference = issuance.grant_scope.backend_reference
  request.payload.copy_code = issuance.grant_scope.copy_code
  request.payload.purpose_code = issuance.grant_scope.purpose_code
  request.payload.sealed_capability_token = {
    capability_kind_code: issuance.capability_kind_code,
    capability_sha256: issuance.record_digest_sha256,
    issued_by_binding_code: issuance.issued_by_binding_code,
    requester_binding_code: issuance.requester_binding_code,
    adapter_binding_code: issuance.adapter_binding_code,
    operation_id: issuance.operation_id,
    operation_nonce: issuance.operation_nonce,
    runtime_profile_record_digest_sha256: issuance.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: issuance.identity_bindings_record_digest_sha256,
    artifact: clone(issuance.artifact),
    allowed_consumer_operation_codes: clone(issuance.allowed_consumer_operation_codes),
    replay_policy_code: issuance.replay_policy_code,
    issued_at: issuance.issued_at,
    expires_at: issuance.expires_at,
  }
  request.record_digest_sha256 = recordDigest(request)
  validateFrozenSchema(frozenD90CustodyMessageSchema, request)
  return request
}

function d901OpenCustodyResponse(issuance, request, transition, ordinal) {
  const response = frozenD90Fixture('custody_open_access_response')
  response.record_code = `custody.open-response.d940-reference.${String(ordinal).padStart(3, '0')}`
  response.operation_id = request.operation_id
  response.operation_nonce = request.operation_nonce
  response.request_id = request.request_id
  response.request_sequence = request.request_sequence
  response.sender_binding_code = request.recipient_binding_code
  response.recipient_binding_code = request.sender_binding_code
  response.runtime_profile_record_digest_sha256 = request.runtime_profile_record_digest_sha256
  response.request_record_digest_sha256 = request.record_digest_sha256
  response.created_at = new Date(Date.parse(transition.occurred_at) + 1000).toISOString()
  response.payload.artifact = clone(issuance.artifact)
  response.payload.backend_code = issuance.grant_scope.backend_code
  response.payload.backend_reference = issuance.grant_scope.backend_reference
  response.payload.copy_code = issuance.grant_scope.copy_code
  response.payload.purpose_code = issuance.grant_scope.purpose_code
  response.payload.custody_evaluated_at = issuance.grant_scope.custody_evaluated_at
  response.payload.known_through_bundle_sequence = issuance.grant_scope.known_through_bundle_sequence
  response.payload.clearance_decision_record_digest_sha256 = issuance.grant_scope.clearance_decision_record_digest_sha256
  response.payload.clearance_scope_sha256 = issuance.grant_scope.clearance_scope_sha256
  response.payload.custody_leaf_projection_sha256 = issuance.grant_scope.custody_leaf_projection_sha256
  response.record_digest_sha256 = recordDigest(response)
  validateFrozenSchema(frozenD90CustodyMessageSchema, response)
  return response
}

const sourceOpenPairOne = consumedCapabilityOne.open_pair
const sourceOpenPairTwo = consumedCapabilityTwo.open_pair

function d930DescriptorDelivery(code, processCode, pid, capability, pair) {
  const record = {
    format: 'jedi-atlas-integrity-access-lifecycle-record', format_version: '1.0.0', record_kind_code: 'descriptor_delivery',
    record_code: code, operation_id: capability.issuance.operation_id, operation_nonce: capability.issuance.operation_nonce,
    bundle: clone(d930PrimaryReceipt.semantic.bundle), artifact: clone(subject.subject_payload.artifact),
    copy_code: subject.subject_payload.copy_code, backend_code: subject.subject_payload.backend_code,
    backend_reference: subject.subject_payload.backend_reference, purpose_code: 'integrity',
    runtime_profile_record_digest_sha256: d930PrimaryReceipt.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: d930PrimaryReceipt.identity_bindings_record_digest_sha256,
    d930_operational_profile_record_digest_sha256: d930OperationalProfile.record_digest_sha256,
    open_custody_request_record_digest_sha256: pair.request.record_digest_sha256, open_custody_response_record_digest_sha256: pair.response.record_digest_sha256,
    sealed_capability_record_digest_sha256: capability.issuance.record_digest_sha256,
    sealed_capability_consumed_transition_digest_sha256: capability.current_leaf.record_digest_sha256,
    producer_binding_code: 'binding.custody.synthetic', sender_binding_code: 'binding.importer.synthetic',
    receiver_binding_code: 'binding.independent.verifier.synthetic', verifier_binding_code: 'binding.independent.verifier.synthetic', verifier_executable_sha256: '11'.repeat(32),
    receiver_process: { process_instance_code: processCode, pid, uid: 62010, gid: 62010, start_time_ticks: pid + 1000, executable_device: 1, executable_inode: pid + 2000 },
    descriptor_delivery_record_digest_sha256: null, verifier_result_record_digest_sha256: null,
    transport_code: 'launcher_supervised_scm_rights', descriptor_role_code: 'custody_source', access_code: 'read_only', file_type_code: 'regular_file',
    peer_credentials_verified: true, pidfd_supervision_active: true, verification_outcome_code: null, recomputed_artifact: null,
    sender_close_state_code: null, sender_closed_at: null, receiver_termination_state_code: null, receiver_terminated_at: null,
    termination_disposition_code: null, receiver_descriptor_closed_by_termination: null, lifecycle_outcome_code: null,
    event_at: new Date(Date.parse(pair.response.created_at) + 1000).toISOString(), record_digest_sha256: '',
  }
  addDigest(record)
  validateFrozenSchema(frozenD930IntegrityLifecycleSchema, record)
  return record
}

const sourceDescriptorOne = d930DescriptorDelivery('descriptor.delivery.d940-reference.001', 'process.verifier.synthetic.001', 41001, consumedCapabilityOne, sourceOpenPairOne)
const sourceDescriptorTwo = d930DescriptorDelivery('descriptor.delivery.d940-reference.002', 'process.verifier.synthetic.002', 41002, consumedCapabilityTwo, sourceOpenPairTwo)
function sealSourceAccessInventory(inventory) {
  const capabilityRecords = inventory.capabilities.flatMap((entry) => [entry.issuance, ...(entry.current_leaf.record_digest_sha256 === entry.issuance.record_digest_sha256 ? [] : [entry.current_leaf])])
  const adapterMessages = inventory.adapter_messages ?? []
  return {
    ...inventory,
    adapter_messages: adapterMessages,
    store_snapshot: {
      selection_boundary_code: 'complete_matching_subject_copy_backend_at_unlink_transaction_snapshot',
      capability_record_count: capabilityRecords.length,
      descriptor_record_count: inventory.descriptors.length,
      adapter_message_record_count: adapterMessages.length,
      capability_store_head_sha256: canonicalSha256(capabilityRecords.map((record) => record.record_digest_sha256).sort()),
      descriptor_store_head_sha256: canonicalSha256(inventory.descriptors.map((record) => record.record_digest_sha256).sort()),
      adapter_message_store_head_sha256: canonicalSha256(adapterMessages.map((record) => record.record_digest_sha256).sort()),
    },
  }
}
const sourceAccessInventory = sealSourceAccessInventory({
  capabilities: [
    { issuance: sourceCapability, current_leaf: sourceCapability, state_code: 'ready' },
    consumedCapabilityOne,
    consumedCapabilityTwo,
  ],
  descriptors: [sourceDescriptorOne, sourceDescriptorTwo],
  adapter_messages: [sourceOpenPairOne.request, sourceOpenPairOne.response, sourceOpenPairTwo.request, sourceOpenPairTwo.response],
})

function sourceAccessInventoryProjection(inventory = sourceAccessInventory) {
  const resealed = sealSourceAccessInventory({ capabilities: inventory.capabilities, descriptors: inventory.descriptors, adapter_messages: inventory.adapter_messages })
  if (canonicalize(inventory.store_snapshot) !== canonicalize(resealed.store_snapshot)) fail('SOURCE_ACCESS_STORE_SNAPSHOT_MISMATCH')
  return canonicalSha256({
    store_snapshot: inventory.store_snapshot,
    capabilities: inventory.capabilities.map((entry) => ({
      capability_record_digest_sha256: entry.issuance.record_digest_sha256,
      capability_leaf_record_digest_sha256: entry.current_leaf.record_digest_sha256,
      state_code: entry.state_code,
    })).sort((left, right) => left.capability_record_digest_sha256.localeCompare(right.capability_record_digest_sha256)),
    descriptor_lifecycle_records: inventory.descriptors.map((record) => ({
      descriptor_lifecycle_record_digest_sha256: record.record_digest_sha256,
      receiver_process_instance_code: record.receiver_process.process_instance_code,
    })).sort((left, right) => left.receiver_process_instance_code.localeCompare(right.receiver_process_instance_code)),
    adapter_message_record_digests: inventory.adapter_messages.map((record) => record.record_digest_sha256).sort(),
  })
}

function controlProjection(records) {
  return canonicalSha256(records.map((record) => ({
    receipt_sequence: record.knowledge_boundary.receipt_sequence,
    record_kind_code: record.record_kind_code,
    record_digest_sha256: record.record_digest_sha256,
  })).sort((left, right) => left.receipt_sequence - right.receipt_sequence))
}

function sealSubjectLineage(inventory) {
  return {
    ...inventory,
    store_snapshot: {
      selection_boundary_code: 'complete_d920_lineage_for_subject_at_candidate_snapshot',
      node_count: inventory.nodes.length,
      edge_count: inventory.edges.length,
      node_store_head_sha256: canonicalSha256(inventory.nodes.slice().sort((a, b) => a.subject_identity_sha256.localeCompare(b.subject_identity_sha256))),
      edge_store_head_sha256: canonicalSha256(inventory.edges.slice().sort((a, b) => `${a.from_subject_identity_sha256}/${a.to_subject_identity_sha256}`.localeCompare(`${b.from_subject_identity_sha256}/${b.to_subject_identity_sha256}`))),
    },
  }
}

const subjectLineageInventory = sealSubjectLineage({
  nodes: [{ subject_identity_sha256: subject.subject_identity_sha256, subject_kind_code: subject.subject_kind_code }],
  edges: [],
})

function subjectLineageProjection(inventory = subjectLineageInventory, targetSubjectIdentity = subject.subject_identity_sha256) {
  const resealed = sealSubjectLineage({ nodes: inventory.nodes, edges: inventory.edges })
  if (canonicalize(inventory.store_snapshot) !== canonicalize(resealed.store_snapshot)) fail('SUBJECT_LINEAGE_STORE_SNAPSHOT_MISMATCH')
  const nodes = new Map()
  for (const node of inventory.nodes) {
    if (nodes.has(node.subject_identity_sha256)) fail('SUBJECT_LINEAGE_NODE_COLLISION')
    nodes.set(node.subject_identity_sha256, node)
  }
  if (!nodes.has(targetSubjectIdentity)) fail('SUBJECT_LINEAGE_TARGET_MISSING')
  const incoming = new Map(inventory.nodes.map((node) => [node.subject_identity_sha256, []]))
  for (const edge of inventory.edges) {
    if (!nodes.has(edge.from_subject_identity_sha256) || !nodes.has(edge.to_subject_identity_sha256) || edge.from_subject_identity_sha256 === edge.to_subject_identity_sha256) fail('SUBJECT_LINEAGE_EDGE_REJECTED')
    incoming.get(edge.to_subject_identity_sha256).push(edge.from_subject_identity_sha256)
  }
  const relevant = new Set()
  const visiting = new Set()
  const walk = (id) => {
    if (visiting.has(id)) fail('SUBJECT_LINEAGE_CYCLE')
    if (relevant.has(id)) return
    visiting.add(id)
    for (const parent of incoming.get(id) ?? []) walk(parent)
    visiting.delete(id)
    relevant.add(id)
  }
  walk(targetSubjectIdentity)
  if (relevant.size !== nodes.size) fail('SUBJECT_LINEAGE_INVENTORY_INCOMPLETE_OR_EXTRANEOUS')
  return {
    digest: canonicalSha256({
      target_subject_identity_sha256: targetSubjectIdentity,
      store_snapshot: inventory.store_snapshot,
      nodes: inventory.nodes.slice().sort((a, b) => a.subject_identity_sha256.localeCompare(b.subject_identity_sha256)),
      edges: inventory.edges.slice().sort((a, b) => `${a.from_subject_identity_sha256}/${a.to_subject_identity_sha256}`.localeCompare(`${b.from_subject_identity_sha256}/${b.to_subject_identity_sha256}`)),
    }),
    relevant_subject_identity_codes: relevant,
  }
}

function validatePropagationAssertions(controlRecords, lineageInventory, targetSubjectIdentity, effectiveAsOf = '9999-12-31T23:59:59.999Z', recordedAsOf = '9999-12-31T23:59:59.999Z', knownThroughSequence = Number.MAX_SAFE_INTEGER) {
  const lineage = subjectLineageProjection(lineageInventory, targetSubjectIdentity)
  const edgeKeys = new Set(lineageInventory.edges.map((edge) => `${edge.from_subject_identity_sha256}/${edge.to_subject_identity_sha256}`))
  const byDigest = new Map(controlRecords.map((record) => [record.record_digest_sha256, record]))
  const active = activeControlLeaves(controlRecords, effectiveAsOf, recordedAsOf, knownThroughSequence)
  const assertions = active.filter((record) => record.record_kind_code === 'propagation_asserted')
  for (const assertion of assertions) {
    const source = assertion.propagates_from_subject_identity_sha256
    const edgeKey = `${source}/${assertion.subject.subject_identity_sha256}`
    const sourceNode = lineageInventory.nodes.find((node) => node.subject_identity_sha256 === source)
    const targetNode = lineageInventory.nodes.find((node) => node.subject_identity_sha256 === assertion.subject.subject_identity_sha256)
    const allowed = classifications.propagation_rules.find((entry) => entry.source_subject_kind_code === sourceNode?.subject_kind_code)?.target_subject_kind_codes.includes(targetNode?.subject_kind_code)
    const basis = byDigest.get(assertion.basis_record_digest_sha256)
    if (!edgeKeys.has(edgeKey) || !allowed || !basis || basis.subject.subject_identity_sha256 !== source || !['restriction_imposed', 'quarantine_imposed', 'hold_imposed', 'clearance_revoked', 'tombstone_applied'].includes(basis.record_kind_code)) fail('PROPAGATION_ASSERTION_UNRESOLVED')
    if (basis.knowledge_boundary.receipt_sequence >= assertion.knowledge_boundary.receipt_sequence || basis.knowledge_boundary.persisted_at >= assertion.knowledge_boundary.persisted_at) fail('PROPAGATION_BASIS_CHRONOLOGY_REJECTED')
  }
  for (const control of active) {
    if (control.subject.subject_identity_sha256 === targetSubjectIdentity || !['restriction_imposed', 'quarantine_imposed', 'hold_imposed', 'clearance_revoked', 'tombstone_applied'].includes(control.record_kind_code)) continue
    const reachesTarget = assertions.some((entry) => entry.basis_record_digest_sha256 === control.record_digest_sha256 && entry.subject.subject_identity_sha256 === targetSubjectIdentity)
    if (!reachesTarget) fail('PROPAGATION_ASSERTION_MISSING')
  }
  return lineage
}

function activeControlLeaves(records, effectiveAsOf = '9999-12-31T23:59:59.999Z', knownAt = '9999-12-31T23:59:59.999Z', knownThroughSequence = Number.MAX_SAFE_INTEGER) {
  validateChain(records)
  const leaves = []
  for (const stream of Map.groupBy(records, (record) => record.chain.stream_code).values()) {
    const sorted = stream
      .filter((record) => record.knowledge_boundary.effective_at <= effectiveAsOf && record.knowledge_boundary.persisted_at <= knownAt && record.knowledge_boundary.receipt_sequence <= knownThroughSequence)
      .sort((left, right) => left.chain.sequence - right.chain.sequence)
    if (sorted.length === 0) continue
    const semantic = []
    for (const record of sorted) {
      if (record.record_kind_code === 'control_corrected') {
        const prior = semantic.pop()
        semantic.push({ ...prior, reason_summary: record.reason_summary, knowledge_boundary: { ...record.knowledge_boundary, effective_at: prior.knowledge_boundary.effective_at }, record_digest_sha256: record.record_digest_sha256 })
      } else if (record.record_kind_code === 'control_withdrawn') semantic.pop()
      else semantic.push(record)
    }
    const stickyTombstone = semantic.find((record) => record.record_kind_code === 'tombstone_applied')
    if (stickyTombstone) leaves.push(stickyTombstone)
    if (semantic.length && semantic.at(-1) !== stickyTombstone) leaves.push(semantic.at(-1))
  }
  return leaves
}

function resolveD930Custody(profile, receipt, receiptSha256, expectedSubject, receiptStore = d930PrimaryReceiptStore) {
  validateFrozenSchema(frozenD930OperationalProfileSchema, profile)
  validateFrozenSchema(frozenD930PrimaryReceiptSchema, receipt)
  if (profile.record_digest_sha256 !== recordDigest(profile) || receipt.semantic_payload_sha256 !== canonicalSha256(receipt.semantic) || receiptSha256 !== canonicalSha256(receipt)) fail('D930_RECORD_DIGEST_MISMATCH')
  const resealedStore = sealD930PrimaryReceiptStore(receiptStore.receipts)
  if (receiptStore.selection_boundary_code !== resealedStore.selection_boundary_code || receiptStore.receipt_count !== resealedStore.receipt_count || receiptStore.receipt_store_head_sha256 !== resealedStore.receipt_store_head_sha256 || !receiptStore.receipts.some((entry) => canonicalSha256(entry) === receiptSha256)) fail('D930_PRIMARY_RECEIPT_STORE_MISMATCH')
  if (receipt.d930_operational_profile_record_digest_sha256 !== profile.record_digest_sha256) fail('D930_PROFILE_REFERENCE_MISMATCH')
  const bindings = validFixtures.records.identity_bindings
  if (receipt.runtime_profile_record_digest_sha256 !== bindings.runtime_profile_record_digest_sha256 || receipt.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256) fail('D930_IDENTITY_GENERATION_MISMATCH')
  resolveD901Binding(receipt.semantic.adapter_binding_code, 'custody_adapter', receipt.semantic.completed_at, 'service')
  resolveD901Binding(receipt.persisted_by_binding_code, 'journal_broker', receipt.persisted_at, 'service')
  if (!(profile.issued_at <= receipt.semantic.completed_at && receipt.semantic.completed_at <= receipt.persisted_at)) fail('D930_RECEIPT_CHRONOLOGY_MISMATCH')
  const payload = expectedSubject.subject_payload
  const expectedReference = `objects/sha256/${payload.artifact.sha256.slice(0, 2)}/${payload.artifact.sha256}`
  if (payload.backend_code !== 'pilot_local_cas_v1' || payload.artifact.byte_layer_code !== 'retrieved_body' || payload.artifact.hash_algorithm_code !== 'sha256' || payload.backend_reference !== expectedReference) fail('D930_CAS_REFERENCE_MISMATCH')
  if (canonicalize(receipt.semantic.artifact) !== canonicalize(payload.artifact) || receipt.semantic.copy_code !== payload.copy_code || receipt.semantic.backend_code !== payload.backend_code || receipt.semantic.backend_reference !== payload.backend_reference) fail('D930_CUSTODY_SUBJECT_MISMATCH')
  return canonicalSha256({
    d930_operational_profile_record_digest_sha256: profile.record_digest_sha256,
    d930_primary_durability_receipt_sha256: receiptSha256,
    artifact: payload.artifact,
    copy_code: payload.copy_code,
    backend_code: payload.backend_code,
    backend_reference: payload.backend_reference,
  })
}

function accessInventoryWith(overrides = {}) {
  return sealSourceAccessInventory({
    capabilities: overrides.capabilities ?? sourceAccessInventory.capabilities,
    descriptors: overrides.descriptors ?? sourceAccessInventory.descriptors,
    adapter_messages: overrides.adapter_messages ?? sourceAccessInventory.adapter_messages,
  })
}

function custodyPathIdentity(profile, expectedSubject) {
  return {
    target_path_identity_sha256: canonicalSha256({
      profile_code: 'd940_primary_target_path_identity_v1',
      d930_operational_profile_record_digest_sha256: profile.record_digest_sha256,
      backend_code: expectedSubject.subject_payload.backend_code,
      backend_reference: expectedSubject.subject_payload.backend_reference,
      copy_code: expectedSubject.subject_payload.copy_code,
    }),
    parent_directory_identity_sha256: canonicalSha256({
      profile_code: 'd940_primary_parent_directory_identity_v1',
      d930_operational_profile_record_digest_sha256: profile.record_digest_sha256,
      backend_code: expectedSubject.subject_payload.backend_code,
      backend_reference_parent_code: 'approved_primary_namespace_parent_of_exact_backend_reference',
    }),
  }
}

const blockingControlKinds = new Set(['restriction_imposed', 'quarantine_imposed', 'hold_imposed', 'clearance_revoked', 'tombstone_applied'])

function applicableBlockingControls(controlRecords, expectedSubject, lineageInventory, effectiveAsOf, recordedAsOf, knownThroughSequence) {
  const active = activeControlLeaves(controlRecords, effectiveAsOf, recordedAsOf, knownThroughSequence)
  const activeByDigest = new Map(active.map((record) => [record.record_digest_sha256, record]))
  const candidates = active.filter((record) => blockingControlKinds.has(record.record_kind_code) && record.subject.subject_identity_sha256 === expectedSubject.subject_identity_sha256)
  const propagationAssertions = active.filter((record) => record.record_kind_code === 'propagation_asserted' && record.subject.subject_identity_sha256 === expectedSubject.subject_identity_sha256)
  if (propagationAssertions.length && !lineageInventory) fail('PROPAGATION_ASSERTION_UNRESOLVED')
  if (propagationAssertions.length) subjectLineageProjection(lineageInventory, expectedSubject.subject_identity_sha256)
  for (const assertion of propagationAssertions) {
    const source = assertion.propagates_from_subject_identity_sha256
    const basis = activeByDigest.get(assertion.basis_record_digest_sha256)
    const sourceNode = lineageInventory.nodes.find((node) => node.subject_identity_sha256 === source)
    const targetNode = lineageInventory.nodes.find((node) => node.subject_identity_sha256 === expectedSubject.subject_identity_sha256)
    const edgeExists = lineageInventory.edges.some((edge) => edge.from_subject_identity_sha256 === source && edge.to_subject_identity_sha256 === expectedSubject.subject_identity_sha256)
    const allowed = classifications.propagation_rules.find((entry) => entry.source_subject_kind_code === sourceNode?.subject_kind_code)?.target_subject_kind_codes.includes(targetNode?.subject_kind_code)
    if (!basis || !blockingControlKinds.has(basis.record_kind_code) || basis.subject.subject_identity_sha256 !== source || !edgeExists || !allowed) fail('PROPAGATION_ASSERTION_UNRESOLVED')
    if (basis.knowledge_boundary.receipt_sequence >= assertion.knowledge_boundary.receipt_sequence || basis.knowledge_boundary.persisted_at >= assertion.knowledge_boundary.persisted_at) fail('PROPAGATION_BASIS_CHRONOLOGY_REJECTED')
    candidates.push(assertion)
  }
  return candidates.sort((left, right) => left.knowledge_boundary.receipt_sequence - right.knowledge_boundary.receipt_sequence || left.knowledge_boundary.persisted_at.localeCompare(right.knowledge_boundary.persisted_at))
}

function firstBlockingKnownControl(controlRecords, expectedSubject = subject, lineageInventory = subjectLineageInventory, effectiveAsOf = '9999-12-31T23:59:59.999Z', recordedAsOf = '9999-12-31T23:59:59.999Z', knownThroughSequence = Number.MAX_SAFE_INTEGER) {
  return applicableBlockingControls(controlRecords, expectedSubject, lineageInventory, effectiveAsOf, recordedAsOf, knownThroughSequence)[0]
}

function assertAccessCreatedBeforeTrigger(createdAt, trigger) {
  if (createdAt >= trigger.knowledge_boundary.persisted_at) fail('POST_RESTRICTION_ACCESS_CREATED')
}

function validateExactOpenExchange(issuance, transition, request, response, descriptor) {
  const expectedToken = {
    capability_kind_code: issuance.capability_kind_code,
    capability_sha256: issuance.record_digest_sha256,
    issued_by_binding_code: issuance.issued_by_binding_code,
    requester_binding_code: issuance.requester_binding_code,
    adapter_binding_code: issuance.adapter_binding_code,
    operation_id: issuance.operation_id,
    operation_nonce: issuance.operation_nonce,
    runtime_profile_record_digest_sha256: issuance.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: issuance.identity_bindings_record_digest_sha256,
    artifact: issuance.artifact,
    allowed_consumer_operation_codes: issuance.allowed_consumer_operation_codes,
    replay_policy_code: issuance.replay_policy_code,
    issued_at: issuance.issued_at,
    expires_at: issuance.expires_at,
  }
  if (canonicalize(request.payload.sealed_capability_token) !== canonicalize(expectedToken)) fail('DESCRIPTOR_CAPABILITY_TOKEN_MISMATCH')
  const expectedRequestPayload = {
    staging_root_slot_code: null,
    relative_path: null,
    artifact: issuance.artifact,
    source_handle_token: null,
    preparation_token: null,
    backend_code: issuance.grant_scope.backend_code,
    backend_reference: issuance.grant_scope.backend_reference,
    copy_code: issuance.grant_scope.copy_code,
    purpose_code: issuance.grant_scope.purpose_code,
    custody_evaluated_at: null,
    known_through_bundle_sequence: null,
    clearance_decision_record_digest_sha256: null,
    clearance_scope_sha256: null,
    custody_leaf_projection_sha256: null,
    sealed_capability_token: expectedToken,
    outcome_code: null,
    durability_receipt_sha256: null,
    error_code: null,
    collector_handoff_record_digest_sha256: null,
    staging_snapshot_code: null,
    bundle_seal_record_digest_sha256: null,
  }
  if (canonicalize(request.payload) !== canonicalize(expectedRequestPayload) || request.sender_binding_code !== issuance.requester_binding_code || request.recipient_binding_code !== issuance.adapter_binding_code || request.runtime_profile_record_digest_sha256 !== issuance.runtime_profile_record_digest_sha256) fail('DESCRIPTOR_ADAPTER_REQUEST_SCOPE_MISMATCH')
  if (transition.capability_kind_code !== issuance.capability_kind_code || transition.capability_record_digest_sha256 !== issuance.record_digest_sha256 || transition.transition_sequence !== 1 || transition.previous_transition_record_digest_sha256 !== null || transition.from_state_code !== 'ready' || transition.to_state_code !== 'consumed' || transition.transition_code !== 'consumer_succeeded' || transition.request_record_digest_sha256 !== request.record_digest_sha256 || transition.response_record_digest_sha256 !== null || transition.recorded_by_binding_code !== issuance.adapter_binding_code || transition.reason_code !== 'request_claimed') fail('CAPABILITY_LEAF_STATE_MISMATCH')
  const expectedResponsePayload = {
    staging_root_slot_code: null,
    relative_path: null,
    artifact: issuance.artifact,
    source_handle_token: null,
    preparation_token: null,
    backend_code: issuance.grant_scope.backend_code,
    backend_reference: issuance.grant_scope.backend_reference,
    copy_code: issuance.grant_scope.copy_code,
    purpose_code: issuance.grant_scope.purpose_code,
    custody_evaluated_at: issuance.grant_scope.custody_evaluated_at,
    known_through_bundle_sequence: issuance.grant_scope.known_through_bundle_sequence,
    clearance_decision_record_digest_sha256: issuance.grant_scope.clearance_decision_record_digest_sha256,
    clearance_scope_sha256: issuance.grant_scope.clearance_scope_sha256,
    custody_leaf_projection_sha256: issuance.grant_scope.custody_leaf_projection_sha256,
    sealed_capability_token: null,
    outcome_code: 'available',
    durability_receipt_sha256: null,
    error_code: null,
    collector_handoff_record_digest_sha256: null,
    staging_snapshot_code: null,
    bundle_seal_record_digest_sha256: null,
  }
  if (canonicalize(response.payload) !== canonicalize(expectedResponsePayload) || response.sender_binding_code !== issuance.adapter_binding_code || response.recipient_binding_code !== issuance.requester_binding_code || response.runtime_profile_record_digest_sha256 !== issuance.runtime_profile_record_digest_sha256) fail('DESCRIPTOR_ADAPTER_RESPONSE_SCOPE_MISMATCH')
  if (descriptor.producer_binding_code !== issuance.adapter_binding_code || descriptor.sender_binding_code !== issuance.requester_binding_code || descriptor.d930_operational_profile_record_digest_sha256 !== d930OperationalProfile.record_digest_sha256 || canonicalize(descriptor.bundle) !== canonicalize(d930PrimaryReceipt.semantic.bundle)) fail('DESCRIPTOR_D930_CONTEXT_MISMATCH')
}

function resolveAccessShutdown(records, inventory = sourceAccessInventory, expectedSubject = subject, expectedCustodyProjection = d930CustodyLeafProjectionSha256, controlRecords = [validFixtures.records.restriction, deletionRequest, deletionAuthorization, tombstone], lineageInventory = subjectLineageInventory) {
  const firstShutdownRecord = records.slice().sort((left, right) => left.knowledge_boundary.receipt_sequence - right.knowledge_boundary.receipt_sequence)[0]
  const firstBlockingControl = firstShutdownRecord && firstBlockingKnownControl(controlRecords, expectedSubject, lineageInventory, firstShutdownRecord.knowledge_boundary.effective_at, firstShutdownRecord.knowledge_boundary.recorded_at, firstShutdownRecord.knowledge_boundary.receipt_sequence - 1)
  if (!firstBlockingControl) fail('ACCESS_TRIGGER_UNRESOLVED')
  const capabilityByDigest = new Map()
  for (const entry of inventory.capabilities) {
    const issuance = entry.issuance
    validateFrozenSchema(frozenD90CapabilitySchema, issuance)
    validateFrozenSchema(frozenD90CapabilitySchema, entry.current_leaf)
    if (issuance.record_digest_sha256 !== recordDigest(issuance) || entry.current_leaf.record_digest_sha256 !== recordDigest(entry.current_leaf)) fail('CAPABILITY_DIGEST_MISMATCH')
    const bindings = validFixtures.records.identity_bindings
    if (issuance.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || issuance.runtime_profile_record_digest_sha256 !== bindings.runtime_profile_record_digest_sha256) fail('CAPABILITY_IDENTITY_GENERATION_MISMATCH')
    resolveD901Binding(issuance.issued_by_binding_code, 'custody_adapter', issuance.issued_at, 'service')
    resolveD901Binding(issuance.adapter_binding_code, 'custody_adapter', issuance.issued_at, 'service')
    resolveD901Binding(issuance.requester_binding_code, 'bundle_importer', issuance.issued_at, 'service')
    const capabilityScope = issuance.grant_scope
    assertAccessCreatedBeforeTrigger(issuance.issued_at, firstBlockingControl)
    if (issuance.capability_kind_code !== 'sealed_custody_access' || canonicalize(issuance.allowed_consumer_operation_codes) !== canonicalize(['open_custody']) || issuance.replay_policy_code !== 'single_consume_open_custody' || issuance.grant_scope.scope_kind_code !== 'sealed_custody_access') fail('CAPABILITY_SEMANTICS_MISMATCH')
    const lifetimeMs = Date.parse(issuance.expires_at) - Date.parse(issuance.issued_at)
    if (lifetimeMs < 1 || lifetimeMs > 30000 || issuance.grant_scope.custody_evaluated_at !== issuance.issued_at) fail('CAPABILITY_CHRONOLOGY_MISMATCH')
    if (issuance.grant_scope.clearance_decision_record_digest_sha256 !== d901ClearanceDecision.record_digest_sha256 || issuance.grant_scope.clearance_scope_sha256 !== d901ClearanceDecision.clearance_scope_sha256 || !(d901ClearanceDecision.not_before <= issuance.issued_at && issuance.issued_at < d901ClearanceDecision.expires_at && issuance.issued_at < d901ClearanceTransition.occurred_at)) fail('CAPABILITY_CLEARANCE_MISMATCH')
    if (canonicalize(issuance.artifact) !== canonicalize(expectedSubject.subject_payload.artifact) || capabilityScope.copy_code !== expectedSubject.subject_payload.copy_code || capabilityScope.backend_code !== expectedSubject.subject_payload.backend_code || capabilityScope.backend_reference !== expectedSubject.subject_payload.backend_reference || capabilityScope.custody_leaf_projection_sha256 !== expectedCustodyProjection) fail('CAPABILITY_SUBJECT_SCOPE_MISMATCH')
    if (entry.state_code === 'ready') {
      if (entry.current_leaf.record_kind_code !== 'capability_issuance' || entry.current_leaf.record_digest_sha256 !== issuance.record_digest_sha256) fail('CAPABILITY_LEAF_STATE_MISMATCH')
    } else if (entry.state_code === 'consumed') {
      const leaf = entry.current_leaf
      if (leaf.record_kind_code !== 'capability_transition' || leaf.capability_record_digest_sha256 !== issuance.record_digest_sha256 || leaf.transition_sequence !== 1 || leaf.previous_transition_record_digest_sha256 !== null || leaf.from_state_code !== 'ready' || leaf.to_state_code !== 'consumed' || leaf.transition_code !== 'consumer_succeeded' || leaf.reason_code !== 'request_claimed' || leaf.recorded_by_binding_code !== issuance.adapter_binding_code || !(issuance.issued_at < leaf.occurred_at && leaf.occurred_at < issuance.expires_at)) fail('CAPABILITY_LEAF_STATE_MISMATCH')
      resolveD901Binding(leaf.recorded_by_binding_code, 'custody_adapter', leaf.occurred_at, 'service')
    } else fail('CAPABILITY_LEAF_STATE_MISMATCH')
    if (capabilityByDigest.has(issuance.record_digest_sha256)) fail('CAPABILITY_INVENTORY_COLLISION')
    capabilityByDigest.set(issuance.record_digest_sha256, entry)
  }
  const descriptorProcesses = new Set()
  const descriptorCapabilities = new Set()
  const adapterMessages = new Map()
  for (const message of inventory.adapter_messages) {
    validateFrozenSchema(frozenD90CustodyMessageSchema, message)
    if (message.record_digest_sha256 !== recordDigest(message) || adapterMessages.has(message.record_digest_sha256)) fail('ADAPTER_MESSAGE_DIGEST_OR_COLLISION')
    adapterMessages.set(message.record_digest_sha256, message)
  }
  for (const descriptor of inventory.descriptors) {
    validateFrozenSchema(frozenD930IntegrityLifecycleSchema, descriptor)
    if (descriptor.record_digest_sha256 !== recordDigest(descriptor)) fail('DESCRIPTOR_DIGEST_MISMATCH')
    const bindings = validFixtures.records.identity_bindings
    if (descriptor.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || descriptor.runtime_profile_record_digest_sha256 !== bindings.runtime_profile_record_digest_sha256) fail('DESCRIPTOR_IDENTITY_GENERATION_MISMATCH')
    assertAccessCreatedBeforeTrigger(descriptor.event_at, firstBlockingControl)
    resolveD901Binding(descriptor.producer_binding_code, 'custody_adapter', descriptor.event_at, 'service')
    resolveD901Binding(descriptor.sender_binding_code, 'bundle_importer', descriptor.event_at, 'service')
    const receiver = resolveD901Binding(descriptor.receiver_binding_code, 'independent_verifier', descriptor.event_at, 'service')
    const verifier = resolveD901Binding(descriptor.verifier_binding_code, 'independent_verifier', descriptor.event_at, 'service')
    if (receiver.binding_code !== verifier.binding_code || descriptor.receiver_process.uid !== receiver.unix_uid || descriptor.verifier_executable_sha256 !== verifier.executable_sha256) fail('DESCRIPTOR_PROCESS_BINDING_MISMATCH')
    const capability = capabilityByDigest.get(descriptor.sealed_capability_record_digest_sha256)
    if (!capability || capability.state_code !== 'consumed' || descriptor.operation_id !== capability.issuance.operation_id || descriptor.operation_nonce !== capability.issuance.operation_nonce || descriptor.sealed_capability_consumed_transition_digest_sha256 !== capability.current_leaf.record_digest_sha256 || canonicalize(descriptor.artifact) !== canonicalize(capability.issuance.artifact) || descriptor.copy_code !== capability.issuance.grant_scope.copy_code || descriptor.backend_code !== capability.issuance.grant_scope.backend_code || descriptor.backend_reference !== capability.issuance.grant_scope.backend_reference) fail('DESCRIPTOR_CAPABILITY_SCOPE_MISMATCH')
    const request = adapterMessages.get(descriptor.open_custody_request_record_digest_sha256)
    const response = adapterMessages.get(descriptor.open_custody_response_record_digest_sha256)
    if (!request || !response || request.message_kind_code !== 'request' || response.message_kind_code !== 'response' || request.operation_code !== 'open_custody' || response.operation_code !== 'open_custody' || response.request_record_digest_sha256 !== request.record_digest_sha256 || capability.current_leaf.request_record_digest_sha256 !== request.record_digest_sha256 || request.operation_id !== capability.issuance.operation_id || request.operation_nonce !== capability.issuance.operation_nonce || response.operation_id !== request.operation_id || response.operation_nonce !== request.operation_nonce || response.request_id !== request.request_id || response.request_sequence !== request.request_sequence) fail('DESCRIPTOR_ADAPTER_EXCHANGE_MISMATCH')
    resolveD901Binding(request.sender_binding_code, 'bundle_importer', request.created_at, 'service')
    resolveD901Binding(request.recipient_binding_code, 'custody_adapter', request.created_at, 'service')
    resolveD901Binding(response.sender_binding_code, 'custody_adapter', response.created_at, 'service')
    resolveD901Binding(response.recipient_binding_code, 'bundle_importer', response.created_at, 'service')
    validateExactOpenExchange(capability.issuance, capability.current_leaf, request, response, descriptor)
    if (!(capability.issuance.issued_at <= request.created_at && request.created_at < capability.current_leaf.occurred_at && capability.current_leaf.occurred_at < response.created_at && response.created_at < descriptor.event_at && descriptor.event_at < capability.issuance.expires_at)) fail('DESCRIPTOR_DELIVERY_CHRONOLOGY_MISMATCH')
    if (descriptorProcesses.has(descriptor.receiver_process.process_instance_code)) fail('DESCRIPTOR_INVENTORY_COLLISION')
    if (descriptorCapabilities.has(descriptor.sealed_capability_record_digest_sha256)) fail('DESCRIPTOR_CAPABILITY_BIJECTION_MISMATCH')
    descriptorProcesses.add(descriptor.receiver_process.process_instance_code)
    descriptorCapabilities.add(descriptor.sealed_capability_record_digest_sha256)
  }
  const consumedCapabilityDigests = inventory.capabilities.filter((entry) => entry.state_code === 'consumed').map((entry) => entry.issuance.record_digest_sha256)
  if (descriptorCapabilities.size !== consumedCapabilityDigests.length || consumedCapabilityDigests.some((digest) => !descriptorCapabilities.has(digest))) fail('DESCRIPTOR_CAPABILITY_BIJECTION_MISMATCH')
  for (const record of records) validateAccess(record)
  validateChain(records)
  for (const record of records) {
    if (record.trigger_control_record_digest_sha256 !== firstBlockingControl.record_digest_sha256) fail('ACCESS_TRIGGER_NOT_EARLIEST')
    const trigger = firstBlockingKnownControl(controlRecords, record.subject, lineageInventory, record.knowledge_boundary.effective_at, record.knowledge_boundary.recorded_at, record.knowledge_boundary.receipt_sequence - 1)
    if (!trigger || trigger.record_digest_sha256 !== firstBlockingControl.record_digest_sha256) fail('ACCESS_TRIGGER_UNRESOLVED')
    if (trigger.knowledge_boundary.receipt_sequence >= record.knowledge_boundary.receipt_sequence || trigger.knowledge_boundary.persisted_at >= record.knowledge_boundary.persisted_at) fail('ACCESS_TRIGGER_CONTEXT_MISMATCH')
    if (Date.parse(record.knowledge_boundary.persisted_at) - Date.parse(trigger.knowledge_boundary.persisted_at) > validFixtures.records.operational_profile.settings.maximum_descriptor_termination_ms) fail('ACCESS_SHUTDOWN_DEADLINE_EXCEEDED')
  }
  const readyCapabilities = inventory.capabilities.filter((entry) => entry.state_code === 'ready')
  const capabilityRecords = records.filter((record) => record.access_target_kind_code === 'unconsumed_capability')
  if (capabilityRecords.length !== readyCapabilities.length) fail('CAPABILITY_SHUTDOWN_INCOMPLETE')
  for (const capability of readyCapabilities) {
    if (capability.issuance.expires_at <= firstBlockingControl.knowledge_boundary.persisted_at) fail('READY_CAPABILITY_NOT_ACTIVE_AT_RESTRICTION')
    const terminal = capabilityRecords.find((record) => record.capability_record_digest_sha256 === capability.issuance.record_digest_sha256)
    if (!terminal || terminal.record_kind_code !== 'capability_revoked' || terminal.capability_leaf_record_digest_sha256 !== capability.current_leaf.record_digest_sha256) fail('CAPABILITY_SHUTDOWN_INCOMPLETE')
  }
  const descriptorLeaves = []
  for (const descriptor of inventory.descriptors) {
    const matching = records.filter((record) => record.descriptor_lifecycle_record_digest_sha256 === descriptor.record_digest_sha256)
    const terminal = matching.find((record) => record.record_kind_code === 'descriptor_termination_confirmed')
    if (matching.length !== 2 || !terminal || terminal.receiver_process_instance_code !== descriptor.receiver_process.process_instance_code || terminal.sender_close_state_code !== 'confirmed' || terminal.receiver_termination_state_code !== 'confirmed' || terminal.descriptor_close_state_code !== 'confirmed' || terminal.termination_disposition_code === 'unknown') fail('DESCRIPTOR_SHUTDOWN_INCOMPLETE')
    descriptorLeaves.push({ access_target_identity_sha256: terminal.access_target_identity_sha256, terminal_record_digest_sha256: terminal.record_digest_sha256 })
  }
  if (records.length !== readyCapabilities.length + inventory.descriptors.length * 2) fail('ACCESS_INVENTORY_COVERAGE_MISMATCH')
  return canonicalSha256({
    source_access_inventory_sha256: sourceAccessInventoryProjection(inventory),
    capability_terminal_record_digests: capabilityRecords.map((record) => record.record_digest_sha256).sort(),
    descriptor_leaves: descriptorLeaves.sort((left, right) => left.access_target_identity_sha256.localeCompare(right.access_target_identity_sha256)),
  })
}
const journalActor = clone(validFixtures.records.restriction.persistence_actor)
const actor = (binding, kind, role, principal = null) => ({
  identity_binding: {
    identity_bindings_record_digest_sha256: validFixtures.records.authority_roster.identity_bindings_record_digest_sha256,
    binding_set_code: validFixtures.records.authority_roster.binding_set_code,
    binding_generation: validFixtures.records.authority_roster.binding_generation,
    binding_code: binding,
  },
  authority_roster_record_digest_sha256: validFixtures.records.authority_roster.record_digest_sha256,
  actor_kind_code: kind,
  role_code: role,
  principal_code: principal,
})
const knowledge = (persistedAt, sequence) => {
  const persisted = new Date(persistedAt)
  return {
    effective_at: new Date(persisted.valueOf() - 2000).toISOString(),
    recorded_at: new Date(persisted.valueOf() - 1000).toISOString(),
    persisted_at: persisted.toISOString(),
    journal_namespace_code: 'd940.global.control-journal.v1',
    receipt_sequence: sequence,
  }
}

const approvalBindings = {
  legal_records_authority: 'binding.records.synthetic', privacy_authority: 'binding.privacy.synthetic',
  security_authority: 'binding.security.synthetic', clearance_authority: 'binding.clearance.synthetic',
  deletion_authority: 'binding.deletion.approver.synthetic',
}
function approval(code, role, principal, scope, binding = approvalBindings[role]) {
  return addDigest({
    approval_code: code,
    actor: actor(binding, 'human', role, principal),
    decision_code: 'approve',
    scope_sha256: scope,
    decided_at: '2030-01-01T00:03:01.000Z',
    expires_at: '2030-01-02T00:03:00.000Z',
    record_digest_sha256: '',
  })
}

const deletionRequest = clone(validFixtures.records.deletion_request)
const authorizationScopePayload = {
  deletion_request_record_digest_sha256: deletionRequest.record_digest_sha256,
  requester_principal_code: deletionRequest.semantic_actor.principal_code,
  subject_identity_sha256: subject.subject_identity_sha256,
  operation_id: deletionRequest.operation_id,
  operation_nonce: deletionRequest.operation_nonce,
  reason_category_code: deletionRequest.reason_category_code,
  requested_action_code: 'delete_approved_primary_copy_only',
  d930_operational_profile_record_digest_sha256: d930OperationalProfile.record_digest_sha256,
  d930_primary_durability_receipt_sha256: d930PrimaryReceiptSha256,
  custody_leaf_projection_sha256: d930CustodyLeafProjectionSha256,
  control_head_projection_sha256: controlProjection([validFixtures.records.restriction, deletionRequest]),
  access_head_projection_sha256: sourceAccessInventoryProjection(),
  subject_lineage_projection_sha256: subjectLineageProjection().digest,
  valid_from: '2030-01-01T00:03:07.000Z',
  valid_until: '2030-01-02T00:03:00.000Z',
}
const authorizationScope = canonicalSha256(authorizationScopePayload)
const deletionAuthorization = clone(deletionRequest)
Object.assign(deletionAuthorization, {
  record_kind_code: 'deletion_authorized',
  record_code: 'control.deletion-authorized.synthetic.001',
  chain: { stream_code: deletionRequest.chain.stream_code, sequence: 2, predecessor_record_digest_sha256: deletionRequest.record_digest_sha256 },
  semantic_actor: actor('binding.deletion.synthetic', 'human', 'deletion_authority', 'person.deletion.synthetic'),
  knowledge_boundary: knowledge('2030-01-01T00:03:09.000Z', 3),
  authorization_scope_sha256: authorizationScope,
  authorization_scope: clone(authorizationScopePayload),
  authorization_expires_at: '2030-01-02T00:03:00.000Z',
  human_approvals: [
    approval('approval.records.synthetic.001', 'legal_records_authority', 'person.records.synthetic', authorizationScope),
    approval('approval.deletion.synthetic.001', 'deletion_authority', 'person.deletion.approver.synthetic', authorizationScope, 'binding.deletion.approver.synthetic'),
  ].map((entry) => { entry.decided_at = '2030-01-01T00:03:08.000Z'; return addDigest(entry) }),
  basis_record_digest_sha256: deletionRequest.record_digest_sha256,
})
addDigest(deletionAuthorization)

const deletionAuthorizationRevocation = clone(deletionAuthorization)
Object.assign(deletionAuthorizationRevocation, {
  record_kind_code: 'deletion_authorization_revoked',
  record_code: 'control.deletion-authorization-revoked.synthetic.001',
  chain: { stream_code: deletionRequest.chain.stream_code, sequence: 3, predecessor_record_digest_sha256: deletionAuthorization.record_digest_sha256 },
  semantic_actor: actor('binding.privacy.synthetic', 'human', 'privacy_authority', 'person.privacy.synthetic'),
  knowledge_boundary: knowledge('2030-01-01T00:03:12.000Z', 4),
  authorization_scope_sha256: null,
  authorization_scope: null,
  authorization_expires_at: null,
  human_approvals: [],
  basis_record_digest_sha256: deletionAuthorization.record_digest_sha256,
})
const revocationApprovalScope = controlApprovalScope(deletionAuthorizationRevocation)
deletionAuthorizationRevocation.human_approvals = [
  approval('approval.revocation.records.synthetic.001', 'legal_records_authority', 'person.records.synthetic', revocationApprovalScope),
  approval('approval.revocation.deletion.synthetic.001', 'deletion_authority', 'person.deletion.approver.synthetic', revocationApprovalScope, 'binding.deletion.approver.synthetic'),
].map((entry) => {
  entry.decided_at = '2030-01-01T00:03:11.000Z'
  return addDigest(entry)
})
addDigest(deletionAuthorizationRevocation)

const tombstone = clone(deletionAuthorization)
Object.assign(tombstone, {
  record_kind_code: 'tombstone_applied',
  record_code: 'control.tombstone.synthetic.001',
  chain: { stream_code: deletionRequest.chain.stream_code, sequence: 3, predecessor_record_digest_sha256: deletionAuthorization.record_digest_sha256 },
  semantic_actor: actor('binding.custody.synthetic', 'service', 'custody_operator'),
  knowledge_boundary: knowledge('2030-01-01T00:03:12.000Z', 4),
  restriction_scope_code: 'all_access',
  basis_record_digest_sha256: deletionAuthorization.record_digest_sha256,
  human_approvals: [],
  backup_directive_code: 'tombstone_before_restore',
})
addDigest(tombstone)

function accessRecord(kind, code, streamCode, sequence, predecessor, time, receiptSequence) {
  const record = {
    format: 'jedi-atlas-access-revocation-record', format_version: '1.0.0', record_kind_code: kind,
    record_code: code, operation_id: deletionRequest.operation_id, operation_nonce: deletionRequest.operation_nonce,
    subject: clone(subject), chain: { stream_code: streamCode, sequence, predecessor_record_digest_sha256: predecessor },
    trigger_control_record_digest_sha256: validFixtures.records.restriction.record_digest_sha256,
    access_target_kind_code: null, access_target_identity_sha256: '',
    capability_record_digest_sha256: null, capability_leaf_record_digest_sha256: null, descriptor_lifecycle_record_digest_sha256: null,
    receiver_process_instance_code: null, sender_close_state_code: null, receiver_termination_state_code: null,
    descriptor_close_state_code: null, termination_disposition_code: null,
    semantic_actor: ['descriptor_termination_confirmed', 'descriptor_termination_failed'].includes(kind)
      ? actor('binding.filler.19', 'service', 'trusted_launcher')
      : actor('binding.custody.synthetic', 'service', 'custody_operator'),
    persistence_actor: clone(journalActor), knowledge_boundary: knowledge(time, receiptSequence), record_digest_sha256: '',
  }
  return record
}

const capabilityRevoked = accessRecord('capability_revoked', 'access.capability.synthetic.001', 'stream.access.capability.synthetic.001', 1, null, '2030-01-01T00:03:13.000Z', 5)
capabilityRevoked.access_target_kind_code = 'unconsumed_capability'
capabilityRevoked.capability_record_digest_sha256 = sourceCapability.record_digest_sha256
capabilityRevoked.capability_leaf_record_digest_sha256 = sourceCapability.record_digest_sha256
capabilityRevoked.access_target_identity_sha256 = accessTargetIdentity(capabilityRevoked)
addDigest(capabilityRevoked)

function descriptorShutdown(sourceDescriptor, ordinal, requestReceiptSequence) {
  const suffix = String(ordinal).padStart(3, '0')
  const stream = `stream.access.descriptor.synthetic.${suffix}`
  const request = accessRecord('descriptor_termination_requested', `access.termination-request.synthetic.${suffix}`, stream, 1, null, `2030-01-01T00:03:${String(requestReceiptSequence + 8).padStart(2, '0')}.000Z`, requestReceiptSequence)
  request.access_target_kind_code = 'issued_descriptor'
  request.descriptor_lifecycle_record_digest_sha256 = sourceDescriptor.record_digest_sha256
  request.receiver_process_instance_code = sourceDescriptor.receiver_process.process_instance_code
  request.access_target_identity_sha256 = accessTargetIdentity(request)
  addDigest(request)
  const confirmed = accessRecord('descriptor_termination_confirmed', `access.termination-confirmed.synthetic.${suffix}`, stream, 2, request.record_digest_sha256, `2030-01-01T00:03:${String(requestReceiptSequence + 9).padStart(2, '0')}.000Z`, requestReceiptSequence + 1)
  confirmed.access_target_kind_code = 'issued_descriptor'
  confirmed.descriptor_lifecycle_record_digest_sha256 = sourceDescriptor.record_digest_sha256
  confirmed.receiver_process_instance_code = sourceDescriptor.receiver_process.process_instance_code
  confirmed.access_target_identity_sha256 = request.access_target_identity_sha256
  confirmed.sender_close_state_code = 'confirmed'
  confirmed.receiver_termination_state_code = 'confirmed'
  confirmed.descriptor_close_state_code = 'confirmed'
  confirmed.termination_disposition_code = 'forced_kill_reaped'
  addDigest(confirmed)
  return [request, confirmed]
}

const [terminationRequested, terminationConfirmed] = descriptorShutdown(sourceDescriptorOne, 1, 6)
const [terminationRequestedTwo, terminationConfirmedTwo] = descriptorShutdown(sourceDescriptorTwo, 2, 8)

function journalReceiptFor(record, previousReceiptDigest) {
  const boundary = record.knowledge_boundary
  const semanticActor = record.semantic_actor ?? record.independent_verifier
  return addDigest({
    format: 'jedi-atlas-d940-journal-append-receipt', format_version: '1.0.0',
    record_code: `journal.receipt.synthetic.${String(boundary.receipt_sequence).padStart(3, '0')}`,
    journal_namespace_code: boundary.journal_namespace_code, receipt_sequence: boundary.receipt_sequence,
    previous_receipt_record_digest_sha256: previousReceiptDigest,
    target_format: record.format, target_record_code: record.record_code,
    target_record_digest_sha256: record.record_digest_sha256,
    target_subject_identity_sha256: record.subject.subject_identity_sha256,
    operation_id: record.operation_id, operation_nonce: record.operation_nonce,
    semantic_actor: clone(semanticActor), persistence_actor: clone(record.persistence_actor),
    semantic_recorded_at: boundary.recorded_at, persisted_at: boundary.persisted_at,
    durability_state_code: 'record_and_receipt_flushed_in_protected_d940_ledger', record_digest_sha256: '',
  })
}

function buildJournalReceipts(records) {
  const sorted = records.slice().sort((left, right) => left.knowledge_boundary.receipt_sequence - right.knowledge_boundary.receipt_sequence)
  const receipts = []
  let previous = null
  for (const record of sorted) {
    const receipt = journalReceiptFor(record, previous)
    receipts.push(receipt)
    previous = receipt.record_digest_sha256
  }
  return receipts
}

const accessShutdownRecords = [capabilityRevoked, terminationRequested, terminationConfirmed, terminationRequestedTwo, terminationConfirmedTwo]
function accessShutdownForTrigger(records, triggerDigest) {
  const predecessors = new Map()
  return records.map((source) => {
    const record = clone(source)
    record.trigger_control_record_digest_sha256 = triggerDigest
    record.chain.predecessor_record_digest_sha256 = predecessors.get(record.chain.stream_code) ?? null
    record.record_digest_sha256 = recordDigest(record)
    predecessors.set(record.chain.stream_code, record.record_digest_sha256)
    return record
  })
}
const preExecutionRecords = [validFixtures.records.restriction, deletionRequest, deletionAuthorization, tombstone, ...accessShutdownRecords]
const preExecutionJournalReceipts = buildJournalReceipts(preExecutionRecords)
const controlLedgerHeadReceiptDigest = preExecutionJournalReceipts.at(-1).record_digest_sha256
const executionControlProjectionSha256 = controlProjection([validFixtures.records.restriction, deletionRequest, deletionAuthorization, tombstone])
const executionAccessProjectionSha256 = resolveAccessShutdown(accessShutdownRecords)

const expectedPathIdentity = custodyPathIdentity(d930OperationalProfile, subject)
const presentInventory = {
  approved_primary_names_checked: 1, matching_primary_names: 1, open_descriptors: 0, hard_links: 0,
  unexpected_replicas: 0, temporary_objects: 0, backup_state_code: 'deletion_pending_d9_5', inventory_complete: true,
  target_file_type_code: 'regular_file', target_path_identity_sha256: expectedPathIdentity.target_path_identity_sha256,
  parent_directory_identity_sha256: expectedPathIdentity.parent_directory_identity_sha256, parent_directory_opened_no_follow: true,
  target_device: 11, target_inode: 22, parent_directory_device: 11, parent_directory_inode: 21,
  observed_target_sha256: subject.subject_payload.artifact.sha256, observed_target_byte_length: subject.subject_payload.artifact.byte_length,
  observed_target_link_count: 1, prior_target_observation_record_digest_sha256: null,
  target_opened_no_follow: true, symlink_observed: false,
}
const absentInventory = {
  ...clone(presentInventory), matching_primary_names: 0, target_file_type_code: 'absent', target_opened_no_follow: false,
  target_device: null, target_inode: null, observed_target_sha256: null, observed_target_byte_length: null,
  observed_target_link_count: null, prior_target_observation_record_digest_sha256: null,
}

function safetySnapshot(inventory, knownThroughReceiptSequence = 9, knownThroughPersistedAt = '2030-01-01T00:03:17.000Z', ledgerHeadReceiptDigest = controlLedgerHeadReceiptDigest) {
  const payload = {
    journal_namespace_code: 'd940.global.control-journal.v1', known_through_receipt_sequence: knownThroughReceiptSequence,
    known_through_persisted_at: knownThroughPersistedAt, control_ledger_head_receipt_digest_sha256: ledgerHeadReceiptDigest,
    control_head_projection_sha256: executionControlProjectionSha256,
    access_head_projection_sha256: executionAccessProjectionSha256,
    subject_lineage_projection_sha256: subjectLineageProjection().digest,
    custody_leaf_projection_sha256: authorizationScopePayload.custody_leaf_projection_sha256,
    inventory_snapshot_sha256: canonicalSha256(inventory), active_hold_count: 0, unknown_or_conflicting_control_count: 0,
  }
  return { snapshot_sha256: canonicalSha256(payload), ...payload }
}

function executionRecord(kind, code, sequence, predecessor, method, outcome, time, inventory = presentInventory, semanticRole = 'deletion_executor', snapshot = safetySnapshot(presentInventory)) {
  const didRemove = ['primary_name_removed', 'primary_absence_verified'].includes(outcome)
  return addDigest({
    format: 'jedi-atlas-deletion-execution-record', format_version: '1.0.0', record_kind_code: kind,
    record_code: code, operation_id: deletionRequest.operation_id, operation_nonce: deletionRequest.operation_nonce,
    subject: clone(subject), chain: { stream_code: 'stream.execution.synthetic.001', sequence, predecessor_record_digest_sha256: predecessor },
    deletion_authorization_record_digest_sha256: deletionAuthorization.record_digest_sha256,
    tombstone_record_digest_sha256: tombstone.record_digest_sha256,
    authorization_scope_sha256: authorizationScope,
    d930_operational_profile_record_digest_sha256: authorizationScopePayload.d930_operational_profile_record_digest_sha256,
    d930_primary_durability_receipt_sha256: authorizationScopePayload.d930_primary_durability_receipt_sha256,
    safety_snapshot: clone(snapshot), access_shutdown_state_code: 'confirmed', inventory: clone(inventory),
    execution: { method_code: method, target_name_removed: didRemove, directory_synced: didRemove,
      reopened_target_absent: outcome === 'primary_absence_verified', content_erase_claimed: false,
      complete_erasure_claimed: false, outcome_code: outcome },
    semantic_actor: actor(semanticRole === 'deletion_executor' ? 'binding.deletion.executor.synthetic' : 'binding.independent.verifier.synthetic', 'service', semanticRole),
    persistence_actor: clone(journalActor), knowledge_boundary: knowledge(time, 9 + sequence), record_digest_sha256: '',
  })
}

const executionStarted = executionRecord('execution_started', 'execution.started.synthetic.001', 1, null, 'none', 'not_attempted', '2030-01-01T00:03:18.000Z')
const inventoryObserved = executionRecord('inventory_observed', 'execution.inventory.synthetic.001', 2, executionStarted.record_digest_sha256, 'none', 'not_attempted', '2030-01-01T00:03:19.000Z')
const preUnlinkJournalReceipts = buildJournalReceipts([...preExecutionRecords, executionStarted, inventoryObserved])
const preUnlinkLedgerHead = preUnlinkJournalReceipts.at(-1)
const unlinkSafetySnapshot = safetySnapshot(presentInventory, preUnlinkLedgerHead.receipt_sequence, preUnlinkLedgerHead.persisted_at, preUnlinkLedgerHead.record_digest_sha256)
const unlinkAttempted = executionRecord('unlink_attempted', 'execution.unlink.synthetic.001', 3, inventoryObserved.record_digest_sha256, 'unlink_primary_name_no_follow', 'primary_name_removed', '2030-01-01T00:03:21.000Z', presentInventory, 'deletion_executor', unlinkSafetySnapshot)
absentInventory.prior_target_observation_record_digest_sha256 = unlinkAttempted.record_digest_sha256
const absenceVerified = executionRecord('primary_absence_verified', 'execution.verified.synthetic.001', 4, unlinkAttempted.record_digest_sha256, 'verify_primary_absence_no_follow', 'primary_absence_verified', '2030-01-01T00:03:22.000Z', absentInventory, 'independent_verifier', unlinkSafetySnapshot)

const deletionReceipt = addDigest({
  format: 'jedi-atlas-deletion-receipt', format_version: '1.0.0', record_code: 'receipt.deletion.synthetic.001',
  operation_id: deletionRequest.operation_id, operation_nonce: deletionRequest.operation_nonce, subject: clone(subject),
  deletion_request_record_digest_sha256: deletionRequest.record_digest_sha256,
  deletion_authorization_record_digest_sha256: deletionAuthorization.record_digest_sha256,
  tombstone_record_digest_sha256: tombstone.record_digest_sha256,
  execution_record_digest_sha256: unlinkAttempted.record_digest_sha256,
  verification_record_digest_sha256: absenceVerified.record_digest_sha256,
  authorization_scope_sha256: authorizationScope,
  d930_operational_profile_record_digest_sha256: authorizationScopePayload.d930_operational_profile_record_digest_sha256,
  d930_primary_durability_receipt_sha256: authorizationScopePayload.d930_primary_durability_receipt_sha256,
  safety_snapshot_sha256: absenceVerified.safety_snapshot.snapshot_sha256,
  control_ledger_head_receipt_digest_sha256: absenceVerified.safety_snapshot.control_ledger_head_receipt_digest_sha256,
  executor: actor('binding.deletion.executor.synthetic', 'service', 'deletion_executor'),
  independent_verifier: actor('binding.independent.verifier.synthetic', 'service', 'independent_verifier'),
  outcome_code: 'primary_copy_absence_verified', proof_scope_code: 'approved_primary_namespace_observation_only',
  remaining_copy_classes: ['backup', 'derived', 'open_descriptor', 'replica', 'temporary', 'unknown'], metadata_retention_code: 'restricted_audit_digest_retained',
  complete_erasure_claimed: false, backup_erasure_claimed: false, legal_compliance_claimed: false,
  limitations: ['no_complete_erasure_claim', 'no_backup_erasure_claim', 'no_derived_copy_erasure_claim', 'no_replica_erasure_claim',
    'no_open_descriptor_erasure_claim', 'no_storage_medium_overwrite_claim', 'no_legal_compliance_claim',
    'compromised_kernel_or_root_out_of_scope', 'observation_is_time_bounded'],
  completed_at: '2030-01-01T00:03:22.500Z', persistence_actor: clone(journalActor),
  knowledge_boundary: knowledge('2030-01-01T00:03:23.500Z', 14), record_digest_sha256: '',
})

const deletionReceiptHeadDigest = buildJournalReceipts([
  ...preExecutionRecords, executionStarted, inventoryObserved, unlinkAttempted, absenceVerified, deletionReceipt,
]).at(-1).record_digest_sha256

const backupDirective = addDigest({
  format: 'jedi-atlas-backup-coordination-record', format_version: '1.0.0', record_kind_code: 'deletion_pending',
  record_code: 'backup.directive.synthetic.001', operation_id: deletionRequest.operation_id,
  operation_nonce: deletionRequest.operation_nonce, subject: clone(subject),
  chain: { stream_code: 'stream.backup.synthetic.001', sequence: 1, predecessor_record_digest_sha256: null },
  basis_control_record_digest_sha256: tombstone.record_digest_sha256,
  control_ledger_head_receipt_digest_sha256: deletionReceiptHeadDigest,
  directive_code: 'delete_backup_copy_after_d9_5_authorization', backup_state_code: 'action_pending_d9_5',
  d95_execution_authority_code: 'unreachable_until_separately_approved_d9_5',
  d95_backup_receipt_record_digest_sha256: null,
  semantic_actor: actor('binding.records.synthetic', 'human', 'legal_records_authority', 'person.records.synthetic'),
  persistence_actor: clone(journalActor), knowledge_boundary: knowledge('2030-01-01T00:03:24.000Z', 15), record_digest_sha256: '',
})

const backupDirectiveHeadDigest = buildJournalReceipts([
  ...preExecutionRecords, executionStarted, inventoryObserved, unlinkAttempted, absenceVerified, deletionReceipt, backupDirective,
]).at(-1).record_digest_sha256

const recoveryAssessment = addDigest({
  format: 'jedi-atlas-d940-recovery-assessment', format_version: '1.0.0', record_code: 'recovery.assessment.synthetic.001',
  operation_id: deletionRequest.operation_id, operation_nonce: deletionRequest.operation_nonce, subject: clone(subject),
  snapshot: {
    journal_namespace_code: 'd940.global.control-journal.v1', known_through_receipt_sequence: 15,
    known_through_persisted_at: '2030-01-01T00:03:24.000Z', control_ledger_head_receipt_digest_sha256: backupDirectiveHeadDigest,
    control_head_projection_sha256: executionControlProjectionSha256, access_head_projection_sha256: executionAccessProjectionSha256,
    subject_lineage_projection_sha256: subjectLineageProjection().digest,
    inventory_snapshot_sha256: canonicalSha256(absentInventory), custody_leaf_projection_sha256: d930CustodyLeafProjectionSha256,
  },
  snapshot_digest_sha256: '', crash_boundary_code: 'after_unlink_before_directory_sync',
  inventory_state_code: 'incomplete', access_state_code: 'none_confirmed', control_state_code: 'linear_complete',
  classification_code: 'reconciliation_required', action_execution_code: 'none_classification_only',
  recovery_authority_present: false, semantic_actor: actor('binding.independent.verifier.synthetic', 'service', 'independent_verifier'),
  persistence_actor: clone(journalActor), knowledge_boundary: knowledge('2030-01-01T00:03:25.000Z', 16), record_digest_sha256: '',
})
recoveryAssessment.snapshot_digest_sha256 = canonicalSha256(recoveryAssessment.snapshot)
recoveryAssessment.record_digest_sha256 = recordDigest(recoveryAssessment)

const sampleRecords = {
  deletionRequest, deletionAuthorization, tombstone, capabilityRevoked, terminationRequested, terminationConfirmed, terminationRequestedTwo, terminationConfirmedTwo,
  executionStarted, inventoryObserved, unlinkAttempted, absenceVerified, deletionReceipt, backupDirective, recoveryAssessment,
}

const journalTargets = [
  validFixtures.records.restriction, deletionRequest, deletionAuthorization, tombstone,
  capabilityRevoked, terminationRequested, terminationConfirmed, terminationRequestedTwo, terminationConfirmedTwo, executionStarted,
  inventoryObserved, unlinkAttempted, absenceVerified, deletionReceipt, backupDirective, recoveryAssessment,
]
const journalReceipts = buildJournalReceipts(journalTargets)

function validateJournalLedger(records, receipts) {
  const sortedRecords = records.slice().sort((left, right) => left.knowledge_boundary.receipt_sequence - right.knowledge_boundary.receipt_sequence)
  const sortedReceipts = receipts.slice().sort((left, right) => left.receipt_sequence - right.receipt_sequence)
  if (sortedRecords.length !== sortedReceipts.length) fail('JOURNAL_RECEIPT_COVERAGE_MISMATCH')
  let previous = null
  let previousPersistedAt = null
  for (let index = 0; index < sortedRecords.length; index += 1) {
    const record = sortedRecords[index]
    const receipt = sortedReceipts[index]
    validateRecord(receipt)
    validateActor(receipt.semantic_actor, receipt.persisted_at)
    validateActor(receipt.persistence_actor, receipt.persisted_at)
    if (receipt.receipt_sequence !== index + 1 || record.knowledge_boundary.receipt_sequence !== receipt.receipt_sequence) fail('GLOBAL_RECEIPT_SEQUENCE_GAP')
    if (receipt.previous_receipt_record_digest_sha256 !== previous) fail('GLOBAL_RECEIPT_CHAIN_MISMATCH')
    if (previousPersistedAt !== null && receipt.persisted_at <= previousPersistedAt) fail('GLOBAL_RECEIPT_CHRONOLOGY_REJECTED')
    if (receipt.journal_namespace_code !== classifications.journal_rules.journal_namespace_code || record.knowledge_boundary.journal_namespace_code !== receipt.journal_namespace_code) fail('JOURNAL_NAMESPACE_MISMATCH')
    if (receipt.target_format !== record.format || receipt.target_record_code !== record.record_code || receipt.target_record_digest_sha256 !== record.record_digest_sha256 || receipt.target_subject_identity_sha256 !== record.subject.subject_identity_sha256) fail('JOURNAL_TARGET_MISMATCH')
    if (receipt.operation_id !== record.operation_id || receipt.operation_nonce !== record.operation_nonce || receipt.semantic_recorded_at !== record.knowledge_boundary.recorded_at || receipt.persisted_at !== record.knowledge_boundary.persisted_at) fail('JOURNAL_CONTEXT_MISMATCH')
    if (canonicalize(receipt.semantic_actor) !== canonicalize(record.semantic_actor ?? record.independent_verifier)) fail('JOURNAL_SEMANTIC_ACTOR_MISMATCH')
    if (bindingCode(receipt.persistence_actor) !== bindingCode(record.persistence_actor) || receipt.persistence_actor.role_code !== 'journal_broker') fail('JOURNAL_PERSISTENCE_ACTOR_MISMATCH')
    previous = receipt.record_digest_sha256
    previousPersistedAt = receipt.persisted_at
  }
  if (new Set(receipts.map((entry) => entry.target_record_digest_sha256)).size !== receipts.length) fail('JOURNAL_DUPLICATE_TARGET')
}

function validateSnapshotLedgerHead(snapshot, receipts) {
  const receipt = receipts.find((entry) => entry.receipt_sequence === snapshot.known_through_receipt_sequence)
  if (!receipt || receipt.record_digest_sha256 !== snapshot.control_ledger_head_receipt_digest_sha256 || receipt.persisted_at !== snapshot.known_through_persisted_at) fail('SNAPSHOT_LEDGER_HEAD_MISMATCH')
  return receipt
}

function validateDestructiveSnapshotFreshness(snapshot, destructiveRecord, profile = validFixtures.records.operational_profile) {
  const ageMs = Date.parse(destructiveRecord.knowledge_boundary.effective_at) - Date.parse(snapshot.known_through_persisted_at)
  if (ageMs < 0 || ageMs > profile.settings.maximum_destructive_snapshot_age_ms) fail('DESTRUCTIVE_SNAPSHOT_TOO_OLD')
}

function resolveDeletionGraph(overrides = {}) {
  const graph = {
    deletionRequest, deletionAuthorization, tombstone, executionStarted, inventoryObserved,
    unlinkAttempted, absenceVerified, deletionReceipt, backupDirective,
    d930OperationalProfile, d930PrimaryReceipt, d930PrimaryReceiptSha256, sourceAccessInventory, subjectLineageInventory,
    ...overrides,
  }
  const ledgerTargets = overrides.journalTargets ?? journalTargets
  const ledgerReceipts = overrides.journalReceipts ?? journalReceipts
  validateJournalLedger(ledgerTargets, ledgerReceipts)
  const requireJournaled = (record, code = 'DELETION_GRAPH_RECORD_NOT_JOURNALED') => {
    const target = ledgerTargets.find((entry) => entry.record_digest_sha256 === record.record_digest_sha256)
    const receipt = ledgerReceipts.find((entry) => entry.target_record_digest_sha256 === record.record_digest_sha256)
    if (!target || !receipt || target.record_code !== record.record_code || receipt.target_record_code !== record.record_code) fail(code)
    return receipt
  }
  const subjectDigest = graph.deletionRequest.subject.subject_identity_sha256
  const lineage = subjectLineageProjection(graph.subjectLineageInventory, subjectDigest)
  const unlinkBoundary = graph.unlinkAttempted.knowledge_boundary
  const knownBeforeUnlink = ledgerTargets
    .filter((record) => lineage.relevant_subject_identity_codes.has(record.subject.subject_identity_sha256))
    .filter((record) => record.knowledge_boundary.receipt_sequence < unlinkBoundary.receipt_sequence)
  const controlRecords = knownBeforeUnlink.filter((record) => record.format === 'jedi-atlas-custody-control-record')
  const accessRecords = knownBeforeUnlink.filter((record) => record.format === 'jedi-atlas-access-revocation-record')
  const controls = new Map(controlRecords.map((record) => [record.record_digest_sha256, record]))
  const executions = new Map([graph.executionStarted, graph.inventoryObserved, graph.unlinkAttempted, graph.absenceVerified].map((record) => [record.record_digest_sha256, record]))
  for (const record of controlRecords) validateControl(record)
  for (const record of accessRecords) validateAccess(record)
  for (const record of executions.values()) validateExecution(record)
  validateReceipt(graph.deletionReceipt)
  validateBackup(graph.backupDirective)
  validateChain(controlRecords)
  validateChain([graph.backupDirective])
  validateBackupBasis(graph.backupDirective, controlRecords)
  validatePropagationAssertions(controlRecords, graph.subjectLineageInventory, subjectDigest, graph.unlinkAttempted.knowledge_boundary.effective_at, graph.unlinkAttempted.knowledge_boundary.recorded_at, graph.unlinkAttempted.knowledge_boundary.receipt_sequence - 1)
  validateChain([graph.executionStarted, graph.inventoryObserved, graph.unlinkAttempted, graph.absenceVerified])
  const request = controls.get(graph.deletionAuthorization.basis_record_digest_sha256)
  if (!request || request.record_digest_sha256 !== graph.deletionRequest.record_digest_sha256 || request.record_kind_code !== 'deletion_requested') fail('DELETION_REQUEST_REFERENCE_MISMATCH')
  const scope = graph.deletionAuthorization.authorization_scope
  if (scope.deletion_request_record_digest_sha256 !== request.record_digest_sha256 || scope.subject_identity_sha256 !== request.subject.subject_identity_sha256 || scope.operation_id !== request.operation_id || scope.operation_nonce !== request.operation_nonce || scope.reason_category_code !== request.reason_category_code) fail('AUTHORIZATION_SCOPE_CONTEXT_MISMATCH')
  if (graph.deletionAuthorization.human_approvals.some((entry) => entry.actor.principal_code === request.semantic_actor.principal_code)) fail('SELF_APPROVAL_REJECTED')
  if (controlRecords.some((record) => record.record_kind_code === 'deletion_authorization_revoked' && record.basis_record_digest_sha256 === graph.deletionAuthorization.record_digest_sha256)) fail('DELETION_AUTHORIZATION_REVOKED')
  if (graph.deletionAuthorization.authorization_expires_at <= graph.unlinkAttempted.knowledge_boundary.recorded_at) fail('DELETION_AUTHORIZATION_EXPIRED')
  if (!controls.has(graph.deletionAuthorization.record_digest_sha256) || !controls.has(graph.tombstone.record_digest_sha256)) fail('DELETION_CONTROL_NOT_JOURNALED')
  if (graph.tombstone.basis_record_digest_sha256 !== graph.deletionAuthorization.record_digest_sha256 || graph.tombstone.authorization_scope_sha256 !== graph.deletionAuthorization.authorization_scope_sha256) fail('TOMBSTONE_AUTHORIZATION_MISMATCH')
  const custodyProjection = resolveD930Custody(graph.d930OperationalProfile, graph.d930PrimaryReceipt, graph.d930PrimaryReceiptSha256, request.subject)
  const pathIdentity = custodyPathIdentity(graph.d930OperationalProfile, request.subject)
  if (scope.d930_operational_profile_record_digest_sha256 !== graph.d930OperationalProfile.record_digest_sha256 || scope.d930_primary_durability_receipt_sha256 !== graph.d930PrimaryReceiptSha256 || scope.custody_leaf_projection_sha256 !== custodyProjection) fail('D930_CUSTODY_BINDING_MISMATCH')
  if (scope.subject_lineage_projection_sha256 !== lineage.digest) fail('SUBJECT_LINEAGE_PROJECTION_MISMATCH')
  const controlsBeforeAuthorization = controlRecords.filter((record) => record.knowledge_boundary.receipt_sequence < graph.deletionAuthorization.knowledge_boundary.receipt_sequence)
  if (scope.control_head_projection_sha256 !== controlProjection(controlsBeforeAuthorization) || scope.access_head_projection_sha256 !== sourceAccessInventoryProjection(graph.sourceAccessInventory)) fail('AUTHORIZATION_BASELINE_PROJECTION_MISMATCH')
  const allPriorJournalRecords = ledgerTargets
    .filter((record) => record.knowledge_boundary.receipt_sequence < unlinkBoundary.receipt_sequence)
    .sort((left, right) => left.knowledge_boundary.receipt_sequence - right.knowledge_boundary.receipt_sequence)
  const latestPrior = allPriorJournalRecords.at(-1)
  const expectedHead = ledgerReceipts.find((entry) => entry.target_record_digest_sha256 === latestPrior?.record_digest_sha256)
  const snapshot = graph.unlinkAttempted.safety_snapshot
  if (!latestPrior || latestPrior.knowledge_boundary.receipt_sequence !== snapshot.known_through_receipt_sequence || latestPrior.knowledge_boundary.persisted_at !== snapshot.known_through_persisted_at || !expectedHead || expectedHead.record_digest_sha256 !== snapshot.control_ledger_head_receipt_digest_sha256) fail('SAFETY_SNAPSHOT_STALE')
  validateDestructiveSnapshotFreshness(snapshot, graph.unlinkAttempted)
  const currentControlProjection = controlProjection(controlRecords)
  const currentAccessProjection = resolveAccessShutdown(accessRecords, graph.sourceAccessInventory, request.subject, custodyProjection, controlRecords)
  if (snapshot.control_head_projection_sha256 !== currentControlProjection || snapshot.access_head_projection_sha256 !== currentAccessProjection || snapshot.custody_leaf_projection_sha256 !== custodyProjection || snapshot.subject_lineage_projection_sha256 !== lineage.digest || snapshot.inventory_snapshot_sha256 !== canonicalSha256(graph.unlinkAttempted.inventory)) fail('SAFETY_SNAPSHOT_PROJECTION_MISMATCH')
  const active = activeControlLeaves(controlRecords, graph.unlinkAttempted.knowledge_boundary.effective_at, graph.unlinkAttempted.knowledge_boundary.recorded_at, graph.unlinkAttempted.knowledge_boundary.receipt_sequence - 1)
  if (active.some((record) => record.record_kind_code === 'hold_imposed')) fail('ACTIVE_HOLD_BLOCKS_DELETION')
  if (snapshot.active_hold_count !== 0 || snapshot.unknown_or_conflicting_control_count !== 0) fail('SAFETY_SNAPSHOT_BLOCKS_DELETION')
  for (const record of executions.values()) if (!ledgerTargets.some((entry) => entry.record_digest_sha256 === record.record_digest_sha256)) fail('DELETION_EXECUTION_NOT_JOURNALED')
  for (const record of executions.values()) {
    if (record.deletion_authorization_record_digest_sha256 !== graph.deletionAuthorization.record_digest_sha256 || record.tombstone_record_digest_sha256 !== graph.tombstone.record_digest_sha256 || record.authorization_scope_sha256 !== graph.deletionAuthorization.authorization_scope_sha256) fail('EXECUTION_AUTHORIZATION_MISMATCH')
    if (record.d930_operational_profile_record_digest_sha256 !== scope.d930_operational_profile_record_digest_sha256 || record.d930_primary_durability_receipt_sha256 !== scope.d930_primary_durability_receipt_sha256) fail('D930_CUSTODY_BINDING_MISMATCH')
    if (record.operation_id !== request.operation_id || record.operation_nonce !== request.operation_nonce || record.subject.subject_identity_sha256 !== request.subject.subject_identity_sha256) fail('DELETION_GRAPH_CONTEXT_MISMATCH')
    if (record.inventory.target_path_identity_sha256 !== pathIdentity.target_path_identity_sha256 || record.inventory.parent_directory_identity_sha256 !== pathIdentity.parent_directory_identity_sha256) fail('CUSTODY_PATH_IDENTITY_MISMATCH')
    validateObservedIdentityAgainstBaseline(record, graph.inventoryObserved.inventory)
    if (record.record_kind_code === 'primary_absence_verified' && record.inventory.prior_target_observation_record_digest_sha256 !== graph.unlinkAttempted.record_digest_sha256) fail('ABSENCE_PRIOR_OBSERVATION_MISMATCH')
    if (record.chain.sequence >= graph.unlinkAttempted.chain.sequence && record.safety_snapshot.snapshot_sha256 !== snapshot.snapshot_sha256) fail('EXECUTION_SAFETY_SNAPSHOT_DIVERGENCE')
  }
  if (graph.deletionReceipt.deletion_request_record_digest_sha256 !== request.record_digest_sha256 || graph.deletionReceipt.deletion_authorization_record_digest_sha256 !== graph.deletionAuthorization.record_digest_sha256 || graph.deletionReceipt.tombstone_record_digest_sha256 !== graph.tombstone.record_digest_sha256 || executions.get(graph.deletionReceipt.execution_record_digest_sha256) !== graph.unlinkAttempted || executions.get(graph.deletionReceipt.verification_record_digest_sha256) !== graph.absenceVerified) fail('DELETION_RECEIPT_REFERENCE_MISMATCH')
  if (graph.deletionReceipt.operation_id !== request.operation_id || graph.deletionReceipt.operation_nonce !== request.operation_nonce || graph.deletionReceipt.subject.subject_identity_sha256 !== request.subject.subject_identity_sha256) fail('DELETION_RECEIPT_CONTEXT_MISMATCH')
  if (bindingCode(graph.deletionReceipt.executor) !== bindingCode(graph.unlinkAttempted.semantic_actor) || bindingCode(graph.deletionReceipt.independent_verifier) !== bindingCode(graph.absenceVerified.semantic_actor)) fail('DELETION_RECEIPT_ACTOR_MISMATCH')
  if (!(graph.absenceVerified.knowledge_boundary.persisted_at <= graph.deletionReceipt.completed_at && graph.deletionReceipt.completed_at <= graph.deletionReceipt.knowledge_boundary.recorded_at)) fail('DELETION_RECEIPT_CHRONOLOGY_MISMATCH')
  if (graph.deletionReceipt.authorization_scope_sha256 !== graph.deletionAuthorization.authorization_scope_sha256 || graph.deletionReceipt.d930_operational_profile_record_digest_sha256 !== scope.d930_operational_profile_record_digest_sha256 || graph.deletionReceipt.d930_primary_durability_receipt_sha256 !== scope.d930_primary_durability_receipt_sha256 || graph.deletionReceipt.safety_snapshot_sha256 !== graph.absenceVerified.safety_snapshot.snapshot_sha256 || graph.deletionReceipt.control_ledger_head_receipt_digest_sha256 !== snapshot.control_ledger_head_receipt_digest_sha256) fail('DELETION_RECEIPT_PROOF_MISMATCH')
  const backupPriorReceipt = ledgerReceipts.find((entry) => entry.receipt_sequence === graph.backupDirective.knowledge_boundary.receipt_sequence - 1)
  if (graph.backupDirective.basis_control_record_digest_sha256 !== graph.tombstone.record_digest_sha256 || graph.backupDirective.subject.subject_identity_sha256 !== graph.tombstone.subject.subject_identity_sha256 || graph.backupDirective.operation_id !== request.operation_id || graph.backupDirective.operation_nonce !== request.operation_nonce || !backupPriorReceipt || graph.backupDirective.control_ledger_head_receipt_digest_sha256 !== backupPriorReceipt.record_digest_sha256) fail('BACKUP_DIRECTIVE_BASIS_MISMATCH')
  for (const record of [graph.deletionRequest, graph.deletionAuthorization, graph.tombstone, ...accessRecords, ...executions.values()]) requireJournaled(record)
  requireJournaled(graph.deletionReceipt, 'DELETION_RECEIPT_NOT_JOURNALED')
  requireJournaled(graph.backupDirective, 'BACKUP_DIRECTIVE_NOT_JOURNALED')
  if (!expectedHead || expectedHead.target_record_digest_sha256 !== latestPrior.record_digest_sha256) fail('CONTROL_LEDGER_HEAD_UNRESOLVED')
}

function assertFrozenInputs() {
  for (const [file, digest] of Object.entries(frozenMigrations)) assert.equal(rawSha(path.join(project, 'data/migrations', file)), digest, file)
  assert.equal(rawSha(path.join(frozenD90Root, 'contract-catalog-v1.json')), frozen.d901_catalog)
  assert.equal(rawSha(path.join(frozenD930Root, 'contract-catalog-v1.json')), frozen.d930_catalog)
  const d901Classifications = readJson(path.join(frozenD90Root, 'classifications-v1.json'))
  const d930Classifications = readJson(path.join(frozenD930Root, 'classifications-v1.json'))
  assert.equal(recordDigest(d901Classifications), frozen.d901_classification)
  assert.equal(recordDigest(d930Classifications), frozen.d930_classification)
  execFileSync('git', ['diff', '--quiet', 'HEAD', '--', 'd9/custody'], { cwd: project })
  assert.equal(execFileSync('git', ['rev-parse', 'HEAD:d9/custody'], { cwd: project, encoding: 'utf8' }).trim(), frozen.d931_tree)
}

function assertCatalogAndFingerprints() {
  assert.equal(catalog.status_code, 'design_only_contract_freeze')
  for (const forbidden of ['design_only_unapproved', 'approved', 'active']) assert.notEqual(catalog.status_code, forbidden)
  assert.equal(rawSha(path.join(root, 'contract-catalog-v1.json')), expected.catalog)
  assert.deepEqual(catalog.migration_sha256, frozenMigrations)
  assert.equal(catalog.base_contracts.d901_catalog_sha256, frozen.d901_catalog)
  assert.equal(catalog.base_contracts.d930_catalog_sha256, frozen.d930_catalog)
  assert.equal(catalog.base_contracts.d931_custody_runtime_git_tree, frozen.d931_tree)
  const catalogSchemas = new Map(catalog.schemas.map((entry) => [entry.schema_file, entry]))
  assert.deepEqual([...catalogSchemas.keys()].sort(), ['common-v1.schema.json', ...schemaFiles].sort())
  for (const [file, entry] of catalogSchemas) {
    assert.equal(rawSha(path.join(root, file)), entry.raw_sha256, file)
    assert.equal(readJson(path.join(root, file)).$id, entry.schema_id)
  }
  for (const [key, record, digest] of [
    ['classifications', classifications, expected.classification],
    ['digest_profiles', digestProfiles, expected.digest_profiles],
    ['field_registry', fieldRegistry, expected.field_registry],
  ]) {
    assert.equal(rawSha(path.join(root, catalog[key].file)), catalog[key].raw_sha256)
    assert.equal(recordDigest(record), digest)
    assert.equal(record.record_digest_sha256, digest)
    assert.equal(catalog[key].semantic_sha256, digest)
  }
  assert.equal(inventoryDigest(), expected.root_inventory)
}

function assertMatrixFingerprints() {
  const computed = {
    subject_rules_sha256: canonicalSha256(classifications.subject_rules),
    role_and_separation_sha256: canonicalSha256({ role_assignment_rules: classifications.role_assignment_rules, action_actor_rules: classifications.action_actor_rules, separation_of_duty_rules: classifications.separation_of_duty_rules, identity_binding_rules: classifications.identity_binding_rules, deletion_approval_rules: classifications.deletion_approval_rules }),
    restriction_projection_sha256: canonicalSha256({ control_record_rules: classifications.control_record_rules, control_transition_rules: classifications.control_transition_rules, correction_rules: classifications.correction_rules, control_projection_rules: classifications.control_projection_rules, restriction_precedence: classifications.restriction_precedence, propagation_rules: classifications.propagation_rules, access_revocation_rules: classifications.access_revocation_rules, journal_rules: classifications.journal_rules }),
    deletion_lifecycle_sha256: canonicalSha256({ deletion_transition_rules: classifications.deletion_transition_rules, deletion_execution_rules: classifications.deletion_execution_rules }),
    recovery_and_backup_sha256: canonicalSha256({ backup_coordination_rules: classifications.backup_coordination_rules, recovery_boundary_defaults: classifications.recovery_boundary_defaults, recovery_state_priority_rules: classifications.recovery_state_priority_rules, fail_closed_rules: classifications.fail_closed_rules, authority_boundary: classifications.authority_boundary }),
  }
  assert.deepEqual(computed, classifications.matrix_fingerprints)
  assert.deepEqual(Object.values(computed), [expected.subject_rules, expected.role_and_separation, expected.restriction_projection, expected.deletion_lifecycle, expected.recovery_and_backup])
  assert.ok(Object.values(classifications.authority_boundary).every((value) => value === false))
}

function assertFieldRegistry() {
  const registry = new Map(fieldRegistry.contracts.map((entry) => [entry.schema_file, entry]))
  assert.deepEqual([...registry.keys()].sort(), schemaFiles.slice().sort())
  for (const file of schemaFiles) {
    const entry = registry.get(file)
    assert.deepEqual(entry.field_codes.slice().sort(), Object.keys(schemas.get(file).properties).sort(), file)
    assert.ok(entry.producer_role_codes.length && entry.consumer_role_codes.length)
    assert.ok(entry.storage_code && entry.confidentiality_code && entry.state_code)
  }
  assert.equal(fieldRegistry.mapping_semantics.unmapped_field_code, 'reject')
  assert.equal(fieldRegistry.mapping_semantics.unknown_field_code, 'reject')
}

function assertGoldenVectors() {
  for (const vector of [...golden.vectors, ...golden.critical_payload_vectors, ...golden.projection_vectors]) {
    assert.equal(canonicalize(vector.input), vector.canonical_utf8)
    assert.equal(sha256Bytes(Buffer.from(vector.canonical_utf8, 'utf8')), vector.sha256)
  }
  const reversed = Object.fromEntries(Object.entries(golden.projection_vectors[1].input).reverse())
  assert.notEqual(JSON.stringify(reversed), golden.projection_vectors[1].canonical_utf8)
}

function assertProjectionContracts() {
  const profiles = new Map(digestProfiles.projection_profiles.map((entry) => [entry.profile_code, entry]))
  assert.deepEqual([...profiles.keys()].sort(), [
    'd940_access_shutdown_projection_v1', 'd940_control_head_projection_v1', 'd940_custody_leaf_projection_v1',
    'd940_custody_path_identity_v1', 'd940_source_access_inventory_projection_v1', 'd940_subject_lineage_projection_v1',
  ])
  const bindings = new Map(digestProfiles.field_bindings.map((entry) => [entry.field_code, entry]))
  for (const field of ['access_head_projection_sha256', 'control_head_projection_sha256', 'custody_leaf_projection_sha256', 'subject_lineage_projection_sha256', 'propagates_from_subject_identity_sha256', 'target_path_identity_sha256', 'parent_directory_identity_sha256']) assert.ok(bindings.has(field), field)
  const vector = new Map(golden.projection_vectors.map((entry) => [entry.vector_code, entry]))
  assert.equal(controlProjection(vector.get('control_head_projection').input.map((entry) => ({ knowledge_boundary: { receipt_sequence: entry.receipt_sequence }, record_kind_code: entry.record_kind_code, record_digest_sha256: entry.record_digest_sha256 }))), vector.get('control_head_projection').sha256)
  assert.equal(canonicalSha256(vector.get('source_access_inventory_projection').input), vector.get('source_access_inventory_projection').sha256)
  assert.equal(canonicalSha256(vector.get('access_shutdown_projection').input), vector.get('access_shutdown_projection').sha256)
  assert.equal(canonicalSha256(vector.get('custody_leaf_projection').input), vector.get('custody_leaf_projection').sha256)
  assert.equal(canonicalSha256(vector.get('custody_path_target_projection').input), vector.get('custody_path_target_projection').sha256)
  assert.equal(canonicalSha256(vector.get('subject_lineage_projection').input), vector.get('subject_lineage_projection').sha256)
}

function assertSchemasAndSemantics() {
  validateRecord(validFixtures.records.operational_profile)
  validateAuthorityRoster(validFixtures.records.authority_roster)
  validateAuthorityRosterAdoption(validFixtures.records.authority_roster_adoption)
  assert.equal(validFixtures.records.operational_profile.d940_catalog_sha256, expected.catalog)
  assert.equal(validFixtures.records.operational_profile.d940_classification_fingerprint_sha256, expected.classification)
  assert.equal(validFixtures.records.operational_profile.activation_state_code, 'design_only_unactivated')
  validateControl(validFixtures.records.restriction)
  validateControl(deletionRequest)
  validateControl(deletionAuthorization)
  validateControl(tombstone)
  for (const record of [capabilityRevoked, terminationRequested, terminationConfirmed]) validateAccess(record)
  for (const record of [executionStarted, unlinkAttempted, absenceVerified]) validateExecution(record)
  validateReceipt(deletionReceipt)
  validateBackup(backupDirective)
  validateRecovery(recoveryAssessment)
  validateChain([deletionRequest, deletionAuthorization, tombstone])
  validateChain([capabilityRevoked, terminationRequested, terminationConfirmed])
  validateExecution(inventoryObserved)
  validateChain([executionStarted, inventoryObserved, unlinkAttempted, absenceVerified])
  validateJournalLedger(journalTargets, journalReceipts)
  validateSnapshotLedgerHead(unlinkAttempted.safety_snapshot, journalReceipts)
  validateSnapshotLedgerHead(recoveryAssessment.snapshot, journalReceipts)
  resolveDeletionGraph()
  preflightNoReplace([...journalTargets, ...journalReceipts])
}

function accessProjection(records, effectiveAsOf, knownAt, knownThroughSequence) {
  let active
  try {
    active = activeControlLeaves(records, effectiveAsOf, knownAt, knownThroughSequence)
  } catch {
    return { access_eligibility_code: 'withheld', reason_code: 'unknown_gap_fork_collision_or_inventory' }
  }
  if (active.some((record) => record.record_kind_code === 'tombstone_applied')) return { access_eligibility_code: 'withheld', reason_code: 'active_tombstone' }
  if (active.some((record) => record.record_kind_code === 'hold_imposed')) return { access_eligibility_code: 'withheld', reason_code: 'active_legal_or_retention_hold' }
  if (active.some((record) => record.record_kind_code === 'deletion_authorization_revoked')) return { access_eligibility_code: 'withheld', reason_code: 'deletion_authorization_revoked' }
  if (active.some((record) => record.record_kind_code === 'quarantine_imposed')) return { access_eligibility_code: 'withheld', reason_code: 'active_quarantine' }
  if (active.some((record) => ['restriction_imposed', 'clearance_revoked'].includes(record.record_kind_code))) return { access_eligibility_code: 'withheld', reason_code: 'active_restriction_or_revoked_clearance' }
  return { access_eligibility_code: 'eligible_subject_to_d930_clearance', reason_code: 'no_active_control' }
}

function assertProjectionAndKnowledgeTime() {
  assert.deepEqual(accessProjection([validFixtures.records.restriction], '2030-01-01T00:03:05.000Z', '2030-01-01T00:03:05.000Z', 1), { access_eligibility_code: 'withheld', reason_code: 'active_restriction_or_revoked_clearance' })
  assert.equal(accessProjection([validFixtures.records.restriction], '2030-01-01T00:03:05.000Z', '2030-01-01T00:03:05.000Z', 0).access_eligibility_code, 'eligible_subject_to_d930_clearance')
  const laterBackdated = clone(validFixtures.records.restriction)
  laterBackdated.record_code = 'control.hold.synthetic.002'
  laterBackdated.record_kind_code = 'hold_imposed'
  laterBackdated.reason_category_code = 'legal_hold'
  laterBackdated.chain = { stream_code: 'stream.hold.synthetic.001', sequence: 1, predecessor_record_digest_sha256: null }
  laterBackdated.knowledge_boundary = { effective_at: '2025-12-01T00:00:00.000Z', recorded_at: '2030-01-02T00:00:00.000Z', persisted_at: '2030-01-02T00:00:01.000Z', journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: 2 }
  laterBackdated.semantic_actor = actor('binding.records.synthetic', 'human', 'legal_records_authority', 'person.records.synthetic')
  addDigest(laterBackdated)
  laterBackdated.human_approvals = [approval('approval.hold.synthetic.001', 'legal_records_authority', 'person.records.synthetic', controlApprovalScope(laterBackdated), 'binding.records.synthetic')]
  addDigest(laterBackdated)
  assert.equal(accessProjection([laterBackdated], '2030-01-01T00:02:00.000Z', '2030-01-02T00:00:01.000Z', 1).access_eligibility_code, 'eligible_subject_to_d930_clearance')
  assert.equal(accessProjection([laterBackdated], '2030-01-01T00:02:00.000Z', '2030-01-02T00:00:01.000Z', 2).reason_code, 'active_legal_or_retention_hold')
  assert.equal(firstBlockingKnownControl([validFixtures.records.restriction, laterBackdated]).record_digest_sha256, validFixtures.records.restriction.record_digest_sha256, 'operational access cutoff follows protected knowledge order, not a later-discovered backdated effective time')
  const broken = clone(laterBackdated)
  broken.chain.sequence = 2
  assert.equal(accessProjection([broken], '2030-01-01T00:02:00.000Z', '2030-01-02T00:00:01.000Z', 2).access_eligibility_code, 'withheld')
  const postTombstoneRevocation = clone(deletionAuthorizationRevocation)
  postTombstoneRevocation.chain = { stream_code: deletionRequest.chain.stream_code, sequence: 4, predecessor_record_digest_sha256: tombstone.record_digest_sha256 }
  postTombstoneRevocation.knowledge_boundary = knowledge('2030-01-01T00:05:02.000Z', 5)
  postTombstoneRevocation.record_digest_sha256 = recordDigest(postTombstoneRevocation)
  assert.equal(accessProjection([deletionRequest, deletionAuthorization, tombstone, postTombstoneRevocation], '2030-01-01T00:10:00.000Z', '2030-01-01T00:10:00.000Z', 999).reason_code, 'active_tombstone')
}

function assertNegativeFixturesAndMutations() {
  const bases = { restriction: validFixtures.records.restriction, deletion_request: deletionRequest, operational_profile: validFixtures.records.operational_profile }
  for (const mutation of invalidFixtures.mutations) {
    const changed = pointerSet(bases[mutation.base_record_code], mutation.json_pointer, mutation.replacement, mutation.mutation_code === 'unknown_field')
    if (Object.hasOwn(changed, 'record_digest_sha256')) changed.record_digest_sha256 = recordDigest(changed)
    expectCode(() => {
      if (changed.format === 'jedi-atlas-custody-control-record') validateControl(changed)
      else validateRecord(changed)
    }, mutation.expected_error_code)
  }

  const selfApproved = clone(deletionAuthorization)
  selfApproved.human_approvals[0].actor = clone(deletionRequest.semantic_actor)
  selfApproved.human_approvals[0].record_digest_sha256 = recordDigest(selfApproved.human_approvals[0])
  selfApproved.record_digest_sha256 = recordDigest(selfApproved)
  expectCode(() => validateControl(selfApproved), 'SELF_APPROVAL_REJECTED')

  const missingHuman = clone(deletionAuthorization)
  missingHuman.human_approvals.pop()
  missingHuman.record_digest_sha256 = recordDigest(missingHuman)
  expectCode(() => validateControl(missingHuman), 'HUMAN_GATE_REJECTED')

  const executorVerifier = clone(deletionReceipt)
  executorVerifier.independent_verifier = clone(executorVerifier.executor)
  executorVerifier.record_digest_sha256 = recordDigest(executorVerifier)
  expectCode(() => validateReceipt(executorVerifier), 'RECEIPT_ROLE_REJECTED')

  const overclaim = clone(deletionReceipt)
  overclaim.complete_erasure_claimed = true
  overclaim.record_digest_sha256 = recordDigest(overclaim)
  expectCode(() => validateReceipt(overclaim), 'SCHEMA_REJECTED')

  const openDescriptor = clone(unlinkAttempted)
  openDescriptor.inventory.open_descriptors = 1
  openDescriptor.record_digest_sha256 = recordDigest(openDescriptor)
  expectCode(() => validateExecution(openDescriptor), 'INVENTORY_BLOCKS_DELETION')

  const unconfirmed = clone(terminationConfirmed)
  unconfirmed.descriptor_close_state_code = 'unknown'
  unconfirmed.record_digest_sha256 = recordDigest(unconfirmed)
  expectCode(() => validateAccess(unconfirmed), 'DESCRIPTOR_TERMINATION_UNCONFIRMED')

  const inventedBackup = clone(backupDirective)
  inventedBackup.d95_execution_authority_code = 'active'
  inventedBackup.record_digest_sha256 = recordDigest(inventedBackup)
  expectCode(() => validateBackup(inventedBackup), 'SCHEMA_REJECTED')

  const inventedRecovery = clone(recoveryAssessment)
  inventedRecovery.recovery_authority_present = true
  inventedRecovery.record_digest_sha256 = recordDigest(inventedRecovery)
  expectCode(() => validateRecovery(inventedRecovery), 'SCHEMA_REJECTED')

  const gap = clone(tombstone)
  gap.chain.sequence = 4
  gap.record_digest_sha256 = recordDigest(gap)
  expectCode(() => validateChain([deletionRequest, deletionAuthorization, gap]), 'CHAIN_GAP')
  const fork = clone(tombstone)
  fork.chain.predecessor_record_digest_sha256 = 'ff'.repeat(32)
  fork.record_digest_sha256 = recordDigest(fork)
  expectCode(() => validateChain([deletionRequest, deletionAuthorization, fork]), 'CHAIN_FORK_OR_PREDECESSOR_MISMATCH')
  const backdated = clone(tombstone)
  backdated.knowledge_boundary.persisted_at = deletionAuthorization.knowledge_boundary.persisted_at
  backdated.record_digest_sha256 = recordDigest(backdated)
  expectCode(() => validateChain([deletionRequest, deletionAuthorization, backdated]), 'CHAIN_BACKDATING_REJECTED')

  const collision = clone(validFixtures.records.restriction)
  collision.reason_summary = 'Different bytes for the same stable record code.'
  collision.record_digest_sha256 = recordDigest(collision)
  assert.notEqual(collision.record_digest_sha256, validFixtures.records.restriction.record_digest_sha256)
  expectCode(() => preflightNoReplace([validFixtures.records.restriction, collision]), 'NO_REPLACE_COLLISION')

  const control = clone(validFixtures.records.restriction)
  control.reason_summary = 'bad\nvalue'
  control.record_digest_sha256 = recordDigest(control)
  expectCode(() => validateControl(control), 'UNSAFE_STRING_REJECTED')
}

function syntheticControl(kind) {
  if (kind === 'deletion_requested') return clone(deletionRequest)
  if (kind === 'deletion_authorized') return clone(deletionAuthorization)
  if (kind === 'tombstone_applied') return clone(tombstone)
  const record = clone(validFixtures.records.restriction)
  record.record_kind_code = kind
  record.record_code = `control.${kind.replaceAll('_', '-')}.matrix.001`
  record.operation_id = `operation.${kind.replaceAll('_', '-')}.matrix.001`
  record.operation_nonce = canonicalSha256({ kind })
  record.chain = { stream_code: `stream.${kind.replaceAll('_', '-')}.matrix.001`, sequence: 1, predecessor_record_digest_sha256: null }
  record.knowledge_boundary = knowledge('2030-01-01T00:03:02.000Z', 100 + classifications.control_record_rules.findIndex((entry) => entry.record_kind_code === kind))
  record.reason_category_code = kind.includes('hold') ? 'legal_hold' : kind.includes('quarantine') ? 'malware' : kind.includes('deletion') ? 'deletion_request' : 'security_incident'
  record.restriction_scope_code = ['deletion_requested', 'deletion_authorized', 'deletion_authorization_revoked', 'deletion_denied', 'control_corrected', 'control_withdrawn'].includes(kind) ? null : 'all_access'
  record.authorization_scope_sha256 = null
  record.authorization_scope = null
  record.authorization_expires_at = null
  record.human_approvals = []
  record.basis_record_digest_sha256 = ['restriction_released', 'quarantine_released', 'hold_released', 'deletion_authorization_revoked', 'deletion_denied', 'propagation_asserted'].includes(kind) ? 'a1'.repeat(32) : null
  record.clearance_reference = kind === 'clearance_revoked' ? {
    clearance_code: d901ClearanceDecision.clearance_code, clearance_decision_record_digest_sha256: d901ClearanceDecision.record_digest_sha256,
    clearance_transition_record_digest_sha256: d901ClearanceTransition.record_digest_sha256, clearance_scope_sha256: d901ClearanceDecision.clearance_scope_sha256,
  } : null
  record.corrects_record_digest_sha256 = ['control_corrected', 'control_withdrawn'].includes(kind) ? 'b1'.repeat(32) : null
  record.corrected_record_kind_code = ['control_corrected', 'control_withdrawn'].includes(kind) ? 'restriction_imposed' : null
  record.withdrawal_effect_code = kind === 'control_withdrawn' ? 'void_for_derived_projection_keep_history' : null
  record.propagates_from_subject_identity_sha256 = kind === 'propagation_asserted' ? 'd1'.repeat(32) : null
  record.backup_directive_code = kind.includes('quarantine') || kind.includes('restriction') ? 'restrict_before_restore' : 'none'
  const actorChoice = {
    restriction_released: ['binding.clearance.synthetic', 'human', 'clearance_authority', 'person.clearance.synthetic'],
    quarantine_imposed: ['binding.custody.synthetic', 'service', 'custody_operator', null],
    quarantine_released: ['binding.clearance.synthetic', 'human', 'clearance_authority', 'person.clearance.synthetic'],
    hold_imposed: ['binding.security.synthetic', 'human', 'security_authority', 'person.security.synthetic'],
    hold_released: ['binding.privacy.synthetic', 'human', 'privacy_authority', 'person.privacy.synthetic'],
    clearance_revoked: ['binding.security.synthetic', 'human', 'security_authority', 'person.security.synthetic'],
    deletion_denied: ['binding.records.synthetic', 'human', 'legal_records_authority', 'person.records.synthetic'],
    deletion_authorization_revoked: ['binding.privacy.synthetic', 'human', 'privacy_authority', 'person.privacy.synthetic'],
    control_corrected: ['binding.privacy.synthetic', 'human', 'privacy_authority', 'person.privacy.synthetic'],
    control_withdrawn: ['binding.privacy.synthetic', 'human', 'privacy_authority', 'person.privacy.synthetic'],
    propagation_asserted: ['binding.custody.synthetic', 'service', 'custody_operator', null],
  }[kind] ?? ['binding.security.synthetic', 'human', 'security_authority', 'person.security.synthetic']
  record.semantic_actor = actor(...actorChoice)
  const approvalRoles = {
    restriction_released: ['security_authority'], quarantine_released: ['security_authority'],
    hold_imposed: ['legal_records_authority'], hold_released: ['legal_records_authority', 'security_authority'],
    clearance_revoked: ['clearance_authority'], deletion_denied: ['deletion_authority'],
    deletion_authorization_revoked: ['legal_records_authority', 'deletion_authority'],
    control_corrected: ['legal_records_authority'], control_withdrawn: ['legal_records_authority'],
  }[kind] ?? []
  const scope = controlApprovalScope(record)
  record.human_approvals = approvalRoles.map((role, index) => approval(`approval.${kind}.${index + 1}`, role,
    role === 'legal_records_authority' ? 'person.records.synthetic' : role === 'security_authority' ? 'person.security.synthetic' : role === 'clearance_authority' ? 'person.clearance.synthetic' : 'person.deletion.approver.synthetic', scope))
  return addDigest(record)
}

function assertExhaustiveMatricesAndReviewMutants() {
  const preRuntimeBindings = clone(validFixtures.records.identity_bindings)
  preRuntimeBindings.issued_at = '2029-12-31T23:59:59.999Z'
  preRuntimeBindings.record_digest_sha256 = recordDigest(preRuntimeBindings)
  expectCode(() => validateD901IdentityGeneration(preRuntimeBindings), 'D901_IDENTITY_BINDING_CHRONOLOGY_REJECTED')
  const aliasedBindings = clone(validFixtures.records.identity_bindings)
  const executorBinding = aliasedBindings.bindings.find((entry) => entry.binding_code === 'binding.deletion.executor.synthetic')
  const verifierBinding = aliasedBindings.bindings.find((entry) => entry.binding_code === 'binding.independent.verifier.synthetic')
  executorBinding.unix_uid = verifierBinding.unix_uid
  aliasedBindings.record_digest_sha256 = recordDigest(aliasedBindings)
  expectCode(() => validateD901IdentityGeneration(aliasedBindings), 'D901_OS_SUBJECT_COLLISION')

  const controlKinds = schemas.get('custody-control-record-v1.schema.json').properties.record_kind_code.enum
  assert.deepEqual(controlKinds.slice().sort(), classifications.control_record_rules.map((entry) => entry.record_kind_code).sort())
  assert.deepEqual(controlKinds.slice().sort(), classifications.action_actor_rules.map((entry) => entry.record_kind_code).sort())
  for (const kind of controlKinds) validateControl(syntheticControl(kind))
  assert.deepEqual(classifications.reason_rules.map((entry) => entry.reason_category_code).sort(), classifications.deletion_approval_rules.map((entry) => entry.reason_category_code).sort())
  for (const approvalRule of classifications.deletion_approval_rules) {
    const record = clone(deletionAuthorization)
    record.reason_category_code = approvalRule.reason_category_code
    record.authorization_scope.reason_category_code = approvalRule.reason_category_code
    record.authorization_scope_sha256 = canonicalSha256(record.authorization_scope)
    record.human_approvals = approvalRule.required_human_role_codes.map((role, index) => approval(
      `approval.reason.${approvalRule.reason_category_code}.${index + 1}`, role,
      role === 'privacy_authority' ? 'person.privacy.synthetic' : role === 'security_authority' ? 'person.security.synthetic' : role === 'legal_records_authority' ? 'person.records.synthetic' : 'person.deletion.approver.synthetic',
      record.authorization_scope_sha256,
    )).map((entry) => { entry.decided_at = '2030-01-01T00:03:08.000Z'; return addDigest(entry) })
    record.record_digest_sha256 = recordDigest(record)
    if (approvalRule.authorization_code === 'blocked_while_hold_active') expectCode(() => validateControl(record), 'DELETION_AUTHORIZATION_BLOCKED')
    else validateControl(record)
  }

  const zeroApprovalHoldRelease = syntheticControl('hold_released')
  zeroApprovalHoldRelease.human_approvals = []
  zeroApprovalHoldRelease.record_digest_sha256 = recordDigest(zeroApprovalHoldRelease)
  expectCode(() => validateControl(zeroApprovalHoldRelease), 'HUMAN_GATE_REJECTED')

  const expiredAuthorization = clone(deletionAuthorization)
  expiredAuthorization.authorization_scope.valid_until = '2030-01-03T00:03:00.000Z'
  expiredAuthorization.authorization_expires_at = expiredAuthorization.authorization_scope.valid_until
  expiredAuthorization.authorization_scope_sha256 = canonicalSha256(expiredAuthorization.authorization_scope)
  expiredAuthorization.human_approvals = expiredAuthorization.human_approvals.map((item) => {
    const changed = clone(item); changed.scope_sha256 = expiredAuthorization.authorization_scope_sha256; changed.expires_at = expiredAuthorization.authorization_expires_at; return addDigest(changed)
  })
  expiredAuthorization.record_digest_sha256 = recordDigest(expiredAuthorization)
  expectCode(() => validateControl(expiredAuthorization), 'AUTHORIZATION_LIFETIME_EXCEEDED')

  const actorSpoof = clone(validFixtures.records.restriction)
  actorSpoof.semantic_actor.role_code = 'legal_records_authority'
  actorSpoof.record_digest_sha256 = recordDigest(actorSpoof)
  expectCode(() => validateControl(actorSpoof), 'ACTOR_CLAIM_MISMATCH')

  const badAdoptionDigest = clone(validFixtures.records.authority_roster_adoption)
  badAdoptionDigest.decisions[0].decision_digest_sha256 = 'ff'.repeat(32)
  badAdoptionDigest.record_digest_sha256 = recordDigest(badAdoptionDigest)
  expectCode(() => validateAuthorityRosterAdoption(badAdoptionDigest), 'ROSTER_ADOPTION_DECISION_DIGEST_MISMATCH')
  const spoofedAdoptionPrincipal = clone(validFixtures.records.authority_roster_adoption)
  spoofedAdoptionPrincipal.decisions[0].principal_code = 'person.spoofed.synthetic'
  spoofedAdoptionPrincipal.decisions[0].decision_digest_sha256 = canonicalSha256(Object.fromEntries(Object.entries(spoofedAdoptionPrincipal.decisions[0]).filter(([key]) => key !== 'decision_digest_sha256')))
  spoofedAdoptionPrincipal.record_digest_sha256 = recordDigest(spoofedAdoptionPrincipal)
  expectCode(() => validateAuthorityRosterAdoption(spoofedAdoptionPrincipal), 'ROSTER_ADOPTION_ACTOR_REJECTED')
  expectCode(() => validateActor(validFixtures.records.restriction.semantic_actor, '2030-01-01T00:00:05.000Z'), 'AUTHORITY_ROSTER_EXPIRED_OR_INACTIVE')
  expectCode(() => validateActor(validFixtures.records.restriction.semantic_actor, '2030-02-01T00:00:00.000Z'), 'AUTHORITY_ROSTER_EXPIRED_OR_INACTIVE')

  const clearance = syntheticControl('clearance_revoked')
  validateControl(clearance)
  const wrongDecisionReference = clone(clearance)
  wrongDecisionReference.clearance_reference.clearance_decision_record_digest_sha256 = 'c1'.repeat(32)
  wrongDecisionReference.record_digest_sha256 = recordDigest(wrongDecisionReference)
  expectCode(() => validateControl(wrongDecisionReference), 'CLEARANCE_REFERENCE_MISMATCH')
  const wrongTransitionReference = clone(clearance)
  wrongTransitionReference.clearance_reference.clearance_transition_record_digest_sha256 = 'c2'.repeat(32)
  wrongTransitionReference.record_digest_sha256 = recordDigest(wrongTransitionReference)
  expectCode(() => validateControl(wrongTransitionReference), 'CLEARANCE_REFERENCE_MISMATCH')
  const wrongClearanceArtifact = clone(d901ClearanceDecision)
  wrongClearanceArtifact.artifact.sha256 = 'c3'.repeat(32)
  wrongClearanceArtifact.clearance_scope_sha256 = clearanceScopeDigest(wrongClearanceArtifact)
  wrongClearanceArtifact.record_digest_sha256 = recordDigest(wrongClearanceArtifact)
  expectCode(() => validateControl(clearance, { decision: wrongClearanceArtifact, transitions: [d901ClearanceTransition] }), 'CLEARANCE_SCOPE_MISMATCH')
  const staleClearanceTransition = clone(d901ClearanceTransition)
  staleClearanceTransition.occurred_at = '2030-01-01T00:03:30.000Z'
  staleClearanceTransition.record_digest_sha256 = recordDigest(staleClearanceTransition)
  expectCode(() => validateControl(clearance, { decision: d901ClearanceDecision, transitions: [staleClearanceTransition] }), 'CLEARANCE_REFERENCE_MISMATCH')
  expectCode(() => validateControl(clearance, { decision: d901ClearanceDecision, transitions: [] }), 'CLEARANCE_CURRENT_LEAF_AMBIGUOUS')

  const releaseRoot = clone(validFixtures.records.restriction)
  const release = syntheticControl('restriction_released')
  release.operation_id = releaseRoot.operation_id; release.operation_nonce = releaseRoot.operation_nonce
  release.chain = { stream_code: releaseRoot.chain.stream_code, sequence: 2, predecessor_record_digest_sha256: releaseRoot.record_digest_sha256 }
  release.basis_record_digest_sha256 = releaseRoot.record_digest_sha256
  release.knowledge_boundary = knowledge('2030-01-01T00:03:05.000Z', 2)
  release.human_approvals = [approval('approval.release.chain.001', 'security_authority', 'person.security.synthetic', controlApprovalScope(release))].map((entry) => { entry.decided_at = '2030-01-01T00:03:04.000Z'; return addDigest(entry) })
  addDigest(release)
  for (const [field, value] of [['restriction_scope_code', 'projection_only'], ['reason_category_code', 'confidentiality']]) {
    const changed = clone(release)
    changed[field] = value
    changed.human_approvals = [approval(`approval.release.changed-${field}.001`, 'security_authority', 'person.security.synthetic', controlApprovalScope(changed))].map((entry) => { entry.decided_at = '2030-01-01T00:03:04.000Z'; return addDigest(entry) })
    changed.record_digest_sha256 = recordDigest(changed)
    expectCode(() => validateChain([releaseRoot, changed]), 'CONTROL_RELEASE_CONTEXT_MISMATCH')
  }
  const withdrawal = syntheticControl('control_withdrawn')
  withdrawal.operation_id = releaseRoot.operation_id; withdrawal.operation_nonce = releaseRoot.operation_nonce
  withdrawal.chain = { stream_code: releaseRoot.chain.stream_code, sequence: 3, predecessor_record_digest_sha256: release.record_digest_sha256 }
  withdrawal.knowledge_boundary = knowledge('2030-01-01T00:03:07.000Z', release.knowledge_boundary.receipt_sequence + 1)
  withdrawal.corrects_record_digest_sha256 = release.record_digest_sha256
  withdrawal.corrected_record_kind_code = 'restriction_released'
  withdrawal.human_approvals = [approval('approval.withdraw.chain.001', 'legal_records_authority', 'person.records.synthetic', controlApprovalScope(withdrawal))]
  addDigest(withdrawal)
  expectCode(() => validateChain([releaseRoot, release, withdrawal]), 'CORRECTION_TARGET_REJECTED')
  assert.equal(accessProjection([releaseRoot, release], '2030-01-01T00:10:00.000Z', '2030-01-01T00:10:00.000Z', 999).access_eligibility_code, 'eligible_subject_to_d930_clearance')
  assert.deepEqual(accessProjection([releaseRoot, release, withdrawal], '2030-01-01T00:10:00.000Z', '2030-01-01T00:10:00.000Z', 999), { access_eligibility_code: 'withheld', reason_code: 'unknown_gap_fork_collision_or_inventory' })
  const wrongSubject = clone(withdrawal)
  wrongSubject.subject.subject_identity_sha256 = 'ff'.repeat(32)
  wrongSubject.record_digest_sha256 = recordDigest(wrongSubject)
  expectCode(() => validateChain([releaseRoot, release, wrongSubject]), 'CHAIN_CONTEXT_MISMATCH')
  const tombstoneWithdrawal = clone(withdrawal)
  tombstoneWithdrawal.chain = { stream_code: deletionRequest.chain.stream_code, sequence: 4, predecessor_record_digest_sha256: tombstone.record_digest_sha256 }
  tombstoneWithdrawal.operation_id = tombstone.operation_id; tombstoneWithdrawal.operation_nonce = tombstone.operation_nonce
  tombstoneWithdrawal.knowledge_boundary = knowledge('2030-01-01T00:05:02.000Z', 5)
  tombstoneWithdrawal.corrects_record_digest_sha256 = tombstone.record_digest_sha256; tombstoneWithdrawal.corrected_record_kind_code = 'tombstone_applied'
  tombstoneWithdrawal.record_digest_sha256 = recordDigest(tombstoneWithdrawal)
  expectCode(() => validateChain([deletionRequest, deletionAuthorization, tombstone, tombstoneWithdrawal]), 'CORRECTION_TARGET_REJECTED')

  const movedCorrection = syntheticControl('control_corrected')
  movedCorrection.operation_id = releaseRoot.operation_id; movedCorrection.operation_nonce = releaseRoot.operation_nonce
  movedCorrection.chain = { stream_code: releaseRoot.chain.stream_code, sequence: 2, predecessor_record_digest_sha256: releaseRoot.record_digest_sha256 }
  movedCorrection.corrects_record_digest_sha256 = releaseRoot.record_digest_sha256; movedCorrection.corrected_record_kind_code = 'restriction_imposed'
  movedCorrection.knowledge_boundary = knowledge('2030-01-01T00:04:02.000Z', 4)
  movedCorrection.knowledge_boundary.effective_at = '2030-01-01T00:03:00.000Z'
  movedCorrection.human_approvals = [approval('approval.correction.moved.001', 'security_authority', 'person.security.synthetic', controlApprovalScope(movedCorrection), 'binding.security.synthetic')]
  addDigest(movedCorrection)
  expectCode(() => validateChain([releaseRoot, movedCorrection]), 'CORRECTION_TARGET_REJECTED')

  validateControl(deletionAuthorizationRevocation)
  validateChain([deletionRequest, deletionAuthorization, deletionAuthorizationRevocation])
  const revokedTargets = journalTargets.map((record) => record === tombstone ? deletionAuthorizationRevocation : record)
  expectCode(() => resolveDeletionGraph({
    journalTargets: revokedTargets,
    journalReceipts: buildJournalReceipts(revokedTargets),
  }), 'BACKUP_DIRECTIVE_BASIS_UNRESOLVED')
  const expiredGraphAuthorization = clone(deletionAuthorization)
  expiredGraphAuthorization.authorization_expires_at = '2030-01-01T00:03:18.500Z'
  expectCode(() => resolveDeletionGraph({ deletionAuthorization: expiredGraphAuthorization }), 'DELETION_AUTHORIZATION_EXPIRED')

  const shortApprovalAuthorization = clone(deletionAuthorization)
  shortApprovalAuthorization.human_approvals[0].expires_at = '2030-01-01T12:00:00.000Z'
  shortApprovalAuthorization.human_approvals[0].record_digest_sha256 = recordDigest(shortApprovalAuthorization.human_approvals[0])
  shortApprovalAuthorization.record_digest_sha256 = recordDigest(shortApprovalAuthorization)
  expectCode(() => validateControl(shortApprovalAuthorization), 'AUTHORIZATION_OUTLIVES_APPROVAL')

  const lateRevocation = clone(deletionAuthorizationRevocation)
  lateRevocation.chain = { stream_code: deletionRequest.chain.stream_code, sequence: 4, predecessor_record_digest_sha256: tombstone.record_digest_sha256 }
  lateRevocation.knowledge_boundary = knowledge('2030-01-01T00:03:19.000Z', 11)
  lateRevocation.human_approvals = lateRevocation.human_approvals.map((entry) => {
    entry.decided_at = '2030-01-01T00:03:18.000Z'
    entry.scope_sha256 = controlApprovalScope(lateRevocation)
    return addDigest(entry)
  })
  addDigest(lateRevocation)
  validateControl(lateRevocation)
  validateChain([deletionRequest, deletionAuthorization, tombstone, lateRevocation])
  const lateRevocationTargets = journalTargets.map((record) => record === inventoryObserved ? lateRevocation : record)
  expectCode(() => resolveDeletionGraph({
    journalTargets: lateRevocationTargets,
    journalReceipts: buildJournalReceipts(lateRevocationTargets),
  }), 'DELETION_AUTHORIZATION_REVOKED')

  const laterHold = syntheticControl('hold_imposed')
  laterHold.knowledge_boundary = knowledge('2030-01-01T00:03:18.000Z', 10)
  const laterHoldApprovalScope = controlApprovalScope(laterHold)
  laterHold.human_approvals = laterHold.human_approvals.map((entry) => {
    entry.decided_at = '2030-01-01T00:03:17.000Z'
    entry.scope_sha256 = laterHoldApprovalScope
    return addDigest(entry)
  })
  laterHold.record_digest_sha256 = recordDigest(laterHold)
  validateControl(laterHold)
  const heldTargets = journalTargets.map((record) => record === executionStarted ? laterHold : record)
  expectCode(() => resolveDeletionGraph({
    journalTargets: heldTargets,
    journalReceipts: buildJournalReceipts(heldTargets),
  }), 'SAFETY_SNAPSHOT_STALE')

  const stalePriorReceipt = journalReceipts.find((entry) => entry.receipt_sequence === executionStarted.knowledge_boundary.receipt_sequence)
  const staleUnlink = clone(unlinkAttempted)
  staleUnlink.safety_snapshot.known_through_receipt_sequence = stalePriorReceipt.receipt_sequence
  staleUnlink.safety_snapshot.known_through_persisted_at = stalePriorReceipt.persisted_at
  staleUnlink.safety_snapshot.control_ledger_head_receipt_digest_sha256 = stalePriorReceipt.record_digest_sha256
  staleUnlink.safety_snapshot.snapshot_sha256 = canonicalSha256(Object.fromEntries(Object.entries(staleUnlink.safety_snapshot).filter(([key]) => key !== 'snapshot_sha256')))
  staleUnlink.record_digest_sha256 = recordDigest(staleUnlink)
  const staleAbsence = clone(absenceVerified)
  staleAbsence.chain.predecessor_record_digest_sha256 = staleUnlink.record_digest_sha256
  staleAbsence.safety_snapshot = clone(staleUnlink.safety_snapshot)
  staleAbsence.inventory.prior_target_observation_record_digest_sha256 = staleUnlink.record_digest_sha256
  staleAbsence.record_digest_sha256 = recordDigest(staleAbsence)
  expectCode(() => resolveDeletionGraph({ unlinkAttempted: staleUnlink, absenceVerified: staleAbsence }), 'SAFETY_SNAPSHOT_STALE')
  const oldButOtherwiseCompleteSnapshot = clone(unlinkAttempted.safety_snapshot)
  oldButOtherwiseCompleteSnapshot.known_through_persisted_at = '2030-01-01T00:03:17.000Z'
  expectCode(() => validateDestructiveSnapshotFreshness(oldButOtherwiseCompleteSnapshot, unlinkAttempted), 'DESTRUCTIVE_SNAPSHOT_TOO_OLD')
  const postActionSnapshot = clone(unlinkAttempted.safety_snapshot)
  postActionSnapshot.known_through_persisted_at = '2030-01-01T00:03:19.001Z'
  expectCode(() => validateDestructiveSnapshotFreshness(postActionSnapshot, unlinkAttempted), 'DESTRUCTIVE_SNAPSHOT_TOO_OLD')

  const failedTermination = clone(terminationConfirmed)
  failedTermination.record_kind_code = 'descriptor_termination_failed'; failedTermination.record_code = 'access.termination-failed.synthetic.001'
  failedTermination.sender_close_state_code = 'confirmed'; failedTermination.receiver_termination_state_code = 'unknown'; failedTermination.descriptor_close_state_code = 'unknown'; failedTermination.termination_disposition_code = 'unknown'
  failedTermination.record_digest_sha256 = recordDigest(failedTermination)
  validateAccess(failedTermination)
  assert.equal(new Set([capabilityRevoked, terminationRequested, terminationConfirmed, failedTermination].map((entry) => entry.record_kind_code)).size, classifications.access_revocation_rules.length)
  assert.equal(resolveAccessShutdown(accessShutdownRecords), executionAccessProjectionSha256, 'all issued descriptors must be covered')
  const laterTriggerCapabilityRevocation = clone(capabilityRevoked)
  laterTriggerCapabilityRevocation.trigger_control_record_digest_sha256 = tombstone.record_digest_sha256
  laterTriggerCapabilityRevocation.record_digest_sha256 = recordDigest(laterTriggerCapabilityRevocation)
  expectCode(() => resolveAccessShutdown([laterTriggerCapabilityRevocation, ...accessShutdownRecords.slice(1)]), 'ACCESS_TRIGGER_NOT_EARLIEST')
  expectCode(() => resolveAccessShutdown(accessShutdownRecords.filter((entry) => entry !== terminationConfirmedTwo)), 'DESCRIPTOR_SHUTDOWN_INCOMPLETE')
  expectCode(() => resolveAccessShutdown([...accessShutdownRecords.filter((entry) => entry !== terminationConfirmed), failedTermination]), 'DESCRIPTOR_SHUTDOWN_INCOMPLETE')
  const substitutedCapability = clone(sourceCapability)
  substitutedCapability.record_code = 'capability.sealed.d940-substituted.001'
  substitutedCapability.record_digest_sha256 = recordDigest(substitutedCapability)
  expectCode(() => resolveAccessShutdown(accessShutdownRecords, {
    ...sourceAccessInventory,
    capabilities: [{ issuance: substitutedCapability, current_leaf: substitutedCapability, state_code: 'ready' }, ...sourceAccessInventory.capabilities.slice(1)],
  }), 'CAPABILITY_SHUTDOWN_INCOMPLETE')
  for (const [field, value, expectedCode] of [
    ['identity_bindings_record_digest_sha256', 'ef'.repeat(32), 'CAPABILITY_IDENTITY_GENERATION_MISMATCH'],
    ['requester_binding_code', 'binding.custody.synthetic', 'D901_IDENTITY_BINDING_UNRESOLVED'],
    ['issued_at', '2025-12-31T23:59:59.000Z', 'D901_IDENTITY_BINDING_EXPIRED_OR_INACTIVE'],
  ]) {
    const changed = clone(sourceCapability)
    changed[field] = value
    changed.record_digest_sha256 = recordDigest(changed)
    const changedInventory = accessInventoryWith({ capabilities: [{ issuance: changed, current_leaf: changed, state_code: 'ready' }, consumedCapabilityOne, consumedCapabilityTwo] })
    expectCode(() => resolveAccessShutdown(accessShutdownRecords, changedInventory), expectedCode)
  }
  for (const [mutate, expectedCode] of [
    [(entry) => { entry.expires_at = new Date(Date.parse(entry.issued_at) + 30001).toISOString() }, 'CAPABILITY_CHRONOLOGY_MISMATCH'],
    [(entry) => { entry.issued_at = '2030-01-01T00:00:30.000Z'; entry.grant_scope.custody_evaluated_at = entry.issued_at; entry.expires_at = '2030-01-01T00:01:00.000Z' }, 'CAPABILITY_CLEARANCE_MISMATCH'],
    [(entry) => { entry.issued_at = '2030-01-01T00:03:00.000Z'; entry.grant_scope.custody_evaluated_at = entry.issued_at; entry.expires_at = '2030-01-01T00:03:30.000Z' }, 'CAPABILITY_CLEARANCE_MISMATCH'],
    [(entry) => { entry.grant_scope.clearance_decision_record_digest_sha256 = 'ad'.repeat(32) }, 'CAPABILITY_CLEARANCE_MISMATCH'],
    [(entry) => { entry.grant_scope.clearance_scope_sha256 = 'ae'.repeat(32) }, 'CAPABILITY_CLEARANCE_MISMATCH'],
    [(entry) => { entry.grant_scope.custody_evaluated_at = '2030-01-01T00:02:51.000Z' }, 'CAPABILITY_CHRONOLOGY_MISMATCH'],
    [(entry) => { entry.issued_at = '2030-01-01T00:03:12.000Z'; entry.grant_scope.custody_evaluated_at = entry.issued_at; entry.expires_at = '2030-01-01T00:03:20.000Z' }, 'POST_RESTRICTION_ACCESS_CREATED'],
    [(entry) => { entry.expires_at = '2030-01-01T00:03:02.999Z' }, 'READY_CAPABILITY_NOT_ACTIVE_AT_RESTRICTION'],
  ]) {
    const changed = clone(sourceCapability)
    mutate(changed)
    changed.record_digest_sha256 = recordDigest(changed)
    const changedInventory = accessInventoryWith({ capabilities: [{ issuance: changed, current_leaf: changed, state_code: 'ready' }, consumedCapabilityOne, consumedCapabilityTwo] })
    expectCode(() => resolveAccessShutdown(accessShutdownRecords, changedInventory), expectedCode)
  }
  const substitutedDescriptor = clone(sourceDescriptorOne)
  substitutedDescriptor.record_code = 'descriptor.delivery.d940-substituted.001'
  substitutedDescriptor.record_digest_sha256 = recordDigest(substitutedDescriptor)
  expectCode(() => sourceAccessInventoryProjection({ ...sourceAccessInventory, descriptors: [substitutedDescriptor, sourceDescriptorTwo] }), 'SOURCE_ACCESS_STORE_SNAPSHOT_MISMATCH')
  expectCode(() => resolveAccessShutdown(accessShutdownRecords, { ...sourceAccessInventory, descriptors: [substitutedDescriptor, sourceDescriptorTwo] }), 'DESCRIPTOR_SHUTDOWN_INCOMPLETE')
  for (const [field, value, expectedCode] of [
    ['identity_bindings_record_digest_sha256', 'ef'.repeat(32), 'DESCRIPTOR_IDENTITY_GENERATION_MISMATCH'],
    ['producer_binding_code', 'binding.importer.synthetic', 'D901_IDENTITY_BINDING_UNRESOLVED'],
    ['verifier_executable_sha256', 'ef'.repeat(32), 'DESCRIPTOR_PROCESS_BINDING_MISMATCH'],
  ]) {
    const changed = clone(sourceDescriptorOne)
    changed[field] = value
    changed.record_digest_sha256 = recordDigest(changed)
    const changedInventory = accessInventoryWith({ descriptors: [changed, sourceDescriptorTwo] })
    expectCode(() => resolveAccessShutdown(accessShutdownRecords, changedInventory), expectedCode)
  }
  const wrongReceiverUid = clone(sourceDescriptorOne)
  wrongReceiverUid.receiver_process.uid = 62011
  wrongReceiverUid.record_digest_sha256 = recordDigest(wrongReceiverUid)
  expectCode(() => resolveAccessShutdown(accessShutdownRecords, accessInventoryWith({ descriptors: [wrongReceiverUid, sourceDescriptorTwo] })), 'DESCRIPTOR_PROCESS_BINDING_MISMATCH')
  const missingConsumedDescriptor = accessInventoryWith({ descriptors: [sourceDescriptorOne] })
  expectCode(() => resolveAccessShutdown(accessShutdownRecords.filter((record) => record.descriptor_lifecycle_record_digest_sha256 !== sourceDescriptorTwo.record_digest_sha256), missingConsumedDescriptor), 'DESCRIPTOR_CAPABILITY_BIJECTION_MISMATCH')
  const duplicateCapabilityDescriptor = clone(sourceDescriptorOne)
  duplicateCapabilityDescriptor.record_code = 'descriptor.delivery.d940-duplicate-capability.002'
  duplicateCapabilityDescriptor.receiver_process.process_instance_code = 'process.verifier.synthetic.duplicate.002'
  duplicateCapabilityDescriptor.receiver_process.pid = 41003
  duplicateCapabilityDescriptor.receiver_process.start_time_ticks = 42003
  duplicateCapabilityDescriptor.receiver_process.executable_inode = 43003
  duplicateCapabilityDescriptor.record_digest_sha256 = recordDigest(duplicateCapabilityDescriptor)
  const duplicateDescriptorInventory = accessInventoryWith({ descriptors: [sourceDescriptorOne, duplicateCapabilityDescriptor] })
  expectCode(() => resolveAccessShutdown(accessShutdownRecords, duplicateDescriptorInventory), 'DESCRIPTOR_CAPABILITY_BIJECTION_MISMATCH')
  for (const [messageIndex, mutate, expectedCode] of [
    [0, (message) => { message.record_code = 'custody.open-request.d940-substituted.001' }, 'DESCRIPTOR_ADAPTER_EXCHANGE_MISMATCH'],
    [1, (message) => { message.record_code = 'custody.open-response.d940-substituted.001' }, 'DESCRIPTOR_ADAPTER_EXCHANGE_MISMATCH'],
    [0, (message) => { message.created_at = '2030-01-01T00:02:54.000Z' }, 'DESCRIPTOR_ADAPTER_EXCHANGE_MISMATCH'],
  ]) {
    const messages = clone(sourceAccessInventory.adapter_messages)
    messages[messageIndex].record_digest_sha256 = ''
    mutate(messages[messageIndex])
    messages[messageIndex].record_digest_sha256 = recordDigest(messages[messageIndex])
    expectCode(() => resolveAccessShutdown(accessShutdownRecords, accessInventoryWith({ adapter_messages: messages })), expectedCode)
  }
  for (const mutate of [
    (token) => { token.issued_by_binding_code = 'binding.importer.synthetic' },
    (token) => { token.requester_binding_code = 'binding.custody.synthetic' },
    (token) => { token.adapter_binding_code = 'binding.importer.synthetic' },
    (token) => { token.operation_id = 'operation.substituted.synthetic' },
    (token) => { token.operation_nonce = 'fa'.repeat(32) },
    (token) => { token.allowed_consumer_operation_codes = [] },
    (token) => { token.replay_policy_code = 'substituted' },
  ]) {
    const request = clone(sourceOpenPairOne.request)
    mutate(request.payload.sealed_capability_token)
    expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, request, sourceOpenPairOne.response, sourceDescriptorOne), 'DESCRIPTOR_CAPABILITY_TOKEN_MISMATCH')
  }
  for (const mutate of [
    (payload) => { payload.custody_evaluated_at = '2030-01-01T00:02:54.000Z' },
    (payload) => { payload.known_through_bundle_sequence += 1 },
  ]) {
    const response = clone(sourceOpenPairOne.response)
    mutate(response.payload)
    expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, sourceOpenPairOne.request, response, sourceDescriptorOne), 'DESCRIPTOR_ADAPTER_RESPONSE_SCOPE_MISMATCH')
  }
  const alternateImporter = clone(validFixtures.records.identity_bindings.bindings.find((entry) => entry.binding_code === 'binding.importer.synthetic'))
  alternateImporter.binding_code = 'binding.importer.alternate.synthetic'
  alternateImporter.unix_uid = 62113
  alternateImporter.executable_sha256 = 'ab'.repeat(32)
  alternateImporter.ipc_endpoint_code = 'ipc.d940.importer.alternate'
  const alternateAdapter = clone(validFixtures.records.identity_bindings.bindings.find((entry) => entry.binding_code === 'binding.custody.synthetic'))
  alternateAdapter.binding_code = 'binding.custody.alternate.synthetic'
  alternateAdapter.unix_uid = 62108
  alternateAdapter.executable_sha256 = 'ac'.repeat(32)
  alternateAdapter.ipc_endpoint_code = 'ipc.d940.custody.alternate'
  validFixtures.records.identity_bindings.bindings.push(alternateImporter, alternateAdapter)
  try {
    resolveD901Binding(alternateImporter.binding_code, 'bundle_importer', sourceOpenPairOne.request.created_at, 'service')
    resolveD901Binding(alternateAdapter.binding_code, 'custody_adapter', sourceOpenPairOne.request.created_at, 'service')
    const alternateRequestSender = clone(sourceOpenPairOne.request)
    alternateRequestSender.sender_binding_code = alternateImporter.binding_code
    expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, alternateRequestSender, sourceOpenPairOne.response, sourceDescriptorOne), 'DESCRIPTOR_ADAPTER_REQUEST_SCOPE_MISMATCH')
    const alternateRequestRecipient = clone(sourceOpenPairOne.request)
    alternateRequestRecipient.recipient_binding_code = alternateAdapter.binding_code
    expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, alternateRequestRecipient, sourceOpenPairOne.response, sourceDescriptorOne), 'DESCRIPTOR_ADAPTER_REQUEST_SCOPE_MISMATCH')
    const alternateResponseSender = clone(sourceOpenPairOne.response)
    alternateResponseSender.sender_binding_code = alternateAdapter.binding_code
    expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, sourceOpenPairOne.request, alternateResponseSender, sourceDescriptorOne), 'DESCRIPTOR_ADAPTER_RESPONSE_SCOPE_MISMATCH')
    const alternateDescriptorSender = clone(sourceDescriptorOne)
    alternateDescriptorSender.sender_binding_code = alternateImporter.binding_code
    expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, sourceOpenPairOne.request, sourceOpenPairOne.response, alternateDescriptorSender), 'DESCRIPTOR_D930_CONTEXT_MISMATCH')
  } finally {
    validFixtures.records.identity_bindings.bindings.splice(-2)
  }
  const changedRequestPayload = clone(sourceOpenPairOne.request)
  changedRequestPayload.payload.purpose_code = 'processing'
  expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, changedRequestPayload, sourceOpenPairOne.response, sourceDescriptorOne), 'DESCRIPTOR_ADAPTER_REQUEST_SCOPE_MISMATCH')
  for (const mutate of [
    (transition) => { transition.capability_kind_code = 'sealed_custody_prepare' },
    (transition) => { transition.response_record_digest_sha256 = 'ad'.repeat(32) },
  ]) {
    const transition = clone(consumedCapabilityOne.current_leaf)
    mutate(transition)
    expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, transition, sourceOpenPairOne.request, sourceOpenPairOne.response, sourceDescriptorOne), 'CAPABILITY_LEAF_STATE_MISMATCH')
  }
  const wrongDescriptorProfile = clone(sourceDescriptorOne)
  wrongDescriptorProfile.d930_operational_profile_record_digest_sha256 = 'fb'.repeat(32)
  expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, sourceOpenPairOne.request, sourceOpenPairOne.response, wrongDescriptorProfile), 'DESCRIPTOR_D930_CONTEXT_MISMATCH')
  const wrongDescriptorBundle = clone(sourceDescriptorOne)
  wrongDescriptorBundle.bundle.bundle_code = 'bundle.substituted.synthetic'
  expectCode(() => validateExactOpenExchange(consumedCapabilityOne.issuance, consumedCapabilityOne.current_leaf, sourceOpenPairOne.request, sourceOpenPairOne.response, wrongDescriptorBundle), 'DESCRIPTOR_D930_CONTEXT_MISMATCH')
  const lateDescriptor = clone(sourceDescriptorOne)
  lateDescriptor.event_at = consumedCapabilityOne.issuance.expires_at
  lateDescriptor.record_digest_sha256 = recordDigest(lateDescriptor)
  expectCode(() => resolveAccessShutdown(accessShutdownRecords, accessInventoryWith({ descriptors: [lateDescriptor, sourceDescriptorTwo] })), 'POST_RESTRICTION_ACCESS_CREATED')
  const forgedLauncherConfirmation = clone(terminationConfirmed)
  forgedLauncherConfirmation.semantic_actor = actor('binding.custody.synthetic', 'service', 'custody_operator')
  forgedLauncherConfirmation.record_digest_sha256 = recordDigest(forgedLauncherConfirmation)
  expectCode(() => validateAccess(forgedLauncherConfirmation), 'ACCESS_ACTOR_REJECTED')

  const substitutedProfile = clone(d930OperationalProfile)
  substitutedProfile.record_code = 'profile.custody.d940-substituted.001'
  substitutedProfile.record_digest_sha256 = recordDigest(substitutedProfile)
  expectCode(() => resolveD930Custody(substitutedProfile, d930PrimaryReceipt, d930PrimaryReceiptSha256, subject), 'D930_PROFILE_REFERENCE_MISMATCH')
  const substitutedReceipt = clone(d930PrimaryReceipt)
  substitutedReceipt.semantic.copy_code = 'primary.substituted'
  substitutedReceipt.semantic_payload_sha256 = canonicalSha256(substitutedReceipt.semantic)
  expectCode(() => resolveD930Custody(d930OperationalProfile, substitutedReceipt, canonicalSha256(substitutedReceipt), subject, sealD930PrimaryReceiptStore([substitutedReceipt])), 'D930_CUSTODY_SUBJECT_MISMATCH')
  expectCode(() => resolveD930Custody(d930OperationalProfile, d930PrimaryReceipt, d930PrimaryReceiptSha256, subject, sealD930PrimaryReceiptStore([])), 'D930_PRIMARY_RECEIPT_STORE_MISMATCH')
  const foreignReceipt = clone(d930PrimaryReceipt)
  foreignReceipt.record_code = 'receipt.primary.d940-foreign.001'
  foreignReceipt.semantic_payload_sha256 = canonicalSha256(foreignReceipt.semantic)
  expectCode(() => resolveD930Custody(d930OperationalProfile, d930PrimaryReceipt, d930PrimaryReceiptSha256, subject, sealD930PrimaryReceiptStore([foreignReceipt])), 'D930_PRIMARY_RECEIPT_STORE_MISMATCH')
  const wrongCasSubject = clone(subject)
  wrongCasSubject.subject_payload.backend_reference = `objects/sha256/ff/${wrongCasSubject.subject_payload.artifact.sha256}`
  wrongCasSubject.subject_identity_sha256 = canonicalSha256({ subject_kind_code: wrongCasSubject.subject_kind_code, subject_payload: wrongCasSubject.subject_payload })
  expectCode(() => resolveD930Custody(d930OperationalProfile, d930PrimaryReceipt, d930PrimaryReceiptSha256, wrongCasSubject), 'D930_CAS_REFERENCE_MISMATCH')

  const verificationFailed = executionRecord('verification_failed', 'execution.verification-failed.synthetic.001', 4, unlinkAttempted.record_digest_sha256, 'verify_primary_absence_no_follow', 'failed', '2030-01-01T00:14:32.000Z', absentInventory, 'independent_verifier')
  const unlinkFailed = executionRecord('unlink_failed', 'execution.unlink-failed.synthetic.001', 3, inventoryObserved.record_digest_sha256, 'unlink_primary_name_no_follow', 'failed', '2030-01-01T00:12:32.000Z', presentInventory)
  const reconciliation = executionRecord('reconciliation_required', 'execution.reconciliation.synthetic.001', 2, executionStarted.record_digest_sha256, 'none', 'ambiguous', '2030-01-01T00:10:32.000Z', presentInventory, 'independent_verifier')
  reconciliation.access_shutdown_state_code = 'incomplete'; reconciliation.record_digest_sha256 = recordDigest(reconciliation)
  for (const record of [executionStarted, inventoryObserved, unlinkAttempted, unlinkFailed, absenceVerified, verificationFailed, reconciliation]) validateExecution(record)
  validateChain([executionStarted, inventoryObserved, unlinkAttempted, verificationFailed])
  validateChain([executionStarted, inventoryObserved, unlinkFailed])
  validateChain([executionStarted, reconciliation])
  assert.equal(new Set([executionStarted, inventoryObserved, unlinkAttempted, unlinkFailed, absenceVerified, verificationFailed, reconciliation].map((entry) => entry.record_kind_code)).size, classifications.deletion_execution_rules.length)

  const invalidReceiptOutcome = clone(deletionReceipt)
  invalidReceiptOutcome.outcome_code = 'failed'
  invalidReceiptOutcome.record_digest_sha256 = recordDigest(invalidReceiptOutcome)
  expectCode(() => validateReceipt(invalidReceiptOutcome), 'SCHEMA_REJECTED')
  const wrongReceiptActor = clone(deletionReceipt)
  wrongReceiptActor.executor = actor('binding.custody.synthetic', 'service', 'custody_operator')
  wrongReceiptActor.record_digest_sha256 = recordDigest(wrongReceiptActor)
  expectCode(() => resolveDeletionGraph({ deletionReceipt: wrongReceiptActor }), 'RECEIPT_ROLE_REJECTED')
  const earlyReceipt = clone(deletionReceipt)
  earlyReceipt.completed_at = '2030-01-01T00:03:20.000Z'
  earlyReceipt.record_digest_sha256 = recordDigest(earlyReceipt)
  expectCode(() => resolveDeletionGraph({ deletionReceipt: earlyReceipt }), 'DELETION_RECEIPT_CHRONOLOGY_MISMATCH')
  for (const copyClass of deletionReceipt.remaining_copy_classes) {
    const incomplete = clone(deletionReceipt)
    incomplete.remaining_copy_classes = incomplete.remaining_copy_classes.filter((entry) => entry !== copyClass)
    incomplete.record_digest_sha256 = recordDigest(incomplete)
    expectCode(() => validateReceipt(incomplete), 'SCHEMA_REJECTED')
  }
  const missingDerivedLimitation = clone(deletionReceipt)
  missingDerivedLimitation.limitations = missingDerivedLimitation.limitations.filter((entry) => entry !== 'no_derived_copy_erasure_claim')
  missingDerivedLimitation.record_digest_sha256 = recordDigest(missingDerivedLimitation)
  expectCode(() => validateReceipt(missingDerivedLimitation), 'SCHEMA_REJECTED')

  for (const rule of classifications.backup_coordination_rules) {
    const record = clone(backupDirective)
    record.record_kind_code = rule.record_kind_code; record.record_code = `backup.${rule.record_kind_code}.matrix.001`; record.directive_code = rule.directive_code
    const basis = rule.record_kind_code === 'restriction_directive' ? validFixtures.records.restriction : tombstone
    record.operation_id = basis.operation_id; record.operation_nonce = basis.operation_nonce; record.subject = clone(basis.subject)
    record.basis_control_record_digest_sha256 = basis.record_digest_sha256
    const role = rule.semantic_role_codes[0]
    record.semantic_actor = role === 'custody_operator' ? actor('binding.custody.synthetic', 'service', role) : actor('binding.records.synthetic', 'human', role, 'person.records.synthetic')
    record.record_digest_sha256 = recordDigest(record)
    validateBackup(record)
    validateBackupBasis(record, [validFixtures.records.restriction, deletionRequest, deletionAuthorization, tombstone])
  }
  const badBackupRoot = clone(backupDirective)
  badBackupRoot.chain.sequence = 99
  badBackupRoot.chain.predecessor_record_digest_sha256 = 'fc'.repeat(32)
  badBackupRoot.record_digest_sha256 = recordDigest(badBackupRoot)
  expectCode(() => validateChain([badBackupRoot]), 'CHAIN_GAP')
  const backupSuccessor = clone(backupDirective)
  backupSuccessor.record_code = 'backup.directive.synthetic.002'
  backupSuccessor.chain.sequence = 2
  backupSuccessor.chain.predecessor_record_digest_sha256 = backupDirective.record_digest_sha256
  backupSuccessor.knowledge_boundary = knowledge('2030-01-01T00:03:25.000Z', backupDirective.knowledge_boundary.receipt_sequence + 1)
  backupSuccessor.record_digest_sha256 = recordDigest(backupSuccessor)
  validateChain([backupDirective, backupSuccessor])
  for (const [mutate, expectedCode] of [
    [(entry) => { entry.chain.sequence = 3 }, 'CHAIN_GAP'],
    [(entry) => { entry.chain.predecessor_record_digest_sha256 = 'fd'.repeat(32) }, 'CHAIN_FORK_OR_PREDECESSOR_MISMATCH'],
    [(entry) => { entry.knowledge_boundary.persisted_at = backupDirective.knowledge_boundary.persisted_at }, 'CHAIN_BACKDATING_REJECTED'],
  ]) {
    const changed = clone(backupSuccessor)
    mutate(changed)
    changed.record_digest_sha256 = recordDigest(changed)
    expectCode(() => validateChain([backupDirective, changed]), expectedCode)
  }

  for (const boundary of classifications.recovery_boundary_defaults) {
    const record = clone(recoveryAssessment)
    record.record_code = `recovery.${boundary.crash_boundary_code}.matrix.001`; record.crash_boundary_code = boundary.crash_boundary_code
    record.inventory_state_code = 'complete'; record.access_state_code = 'none_confirmed'; record.control_state_code = 'linear_complete'; record.classification_code = boundary.classification_code
    record.record_digest_sha256 = recordDigest(record)
    validateRecovery(record)
  }
  for (const [field, value, expectedClass] of [
    ['control_state_code', 'gap', 'human_decision_required'], ['inventory_state_code', 'contradictory', 'human_decision_required'],
    ['access_state_code', 'termination_pending', 'retain_and_hold'], ['inventory_state_code', 'unavailable', 'reconciliation_required'],
  ]) {
    const record = clone(recoveryAssessment)
    record.inventory_state_code = 'complete'; record.access_state_code = 'none_confirmed'; record.control_state_code = 'linear_complete'; record[field] = value; record.classification_code = expectedClass; record.record_digest_sha256 = recordDigest(record)
    validateRecovery(record)
  }

  for (const rule of classifications.propagation_rules) {
    for (const target of rule.target_subject_kind_codes) assert.ok(rule.target_subject_kind_codes.includes(target))
  }
  assert.equal(classifications.propagation_rules.length, classifications.subject_rules.length)

  const lineageSubject = (subjectKindCode, subjectPayload) => ({
    subject_kind_code: subjectKindCode,
    subject_payload: clone(subjectPayload),
    subject_identity_sha256: canonicalSha256({ subject_kind_code: subjectKindCode, subject_payload: subjectPayload }),
  })
  const bundleSubject = lineageSubject('evidence_bundle', { bundle: clone(d930PrimaryReceipt.semantic.bundle) })
  const artifactSubject = lineageSubject('artifact', { artifact: clone(subject.subject_payload.artifact) })
  const bundleRestriction = clone(validFixtures.records.restriction)
  bundleRestriction.record_code = 'control.restriction.bundle.synthetic.001'
  bundleRestriction.operation_id = 'operation.restrict.bundle.synthetic.001'
  bundleRestriction.operation_nonce = 'd7'.repeat(32)
  bundleRestriction.subject = bundleSubject
  bundleRestriction.chain.stream_code = 'stream.restriction.bundle.synthetic.001'
  bundleRestriction.record_digest_sha256 = recordDigest(bundleRestriction)
  const propagation = syntheticControl('propagation_asserted')
  propagation.record_code = 'control.propagation.bundle-artifact.synthetic.001'
  propagation.operation_id = 'operation.propagation.bundle-artifact.synthetic.001'
  propagation.operation_nonce = 'd8'.repeat(32)
  propagation.subject = artifactSubject
  propagation.chain = { stream_code: 'stream.propagation.bundle-artifact.synthetic.001', sequence: 1, predecessor_record_digest_sha256: null }
  propagation.knowledge_boundary = knowledge('2030-01-01T00:03:04.000Z', 2)
  propagation.basis_record_digest_sha256 = bundleRestriction.record_digest_sha256
  propagation.propagates_from_subject_identity_sha256 = bundleSubject.subject_identity_sha256
  propagation.record_digest_sha256 = recordDigest(propagation)
  const lineage = sealSubjectLineage({
    nodes: [
      { subject_identity_sha256: bundleSubject.subject_identity_sha256, subject_kind_code: 'evidence_bundle' },
      { subject_identity_sha256: artifactSubject.subject_identity_sha256, subject_kind_code: 'artifact' },
    ],
    edges: [{ from_subject_identity_sha256: bundleSubject.subject_identity_sha256, to_subject_identity_sha256: artifactSubject.subject_identity_sha256 }],
  })
  validateControl(bundleRestriction)
  validateControl(propagation)
  validatePropagationAssertions([bundleRestriction, propagation], lineage, artifactSubject.subject_identity_sha256)
  expectCode(() => validatePropagationAssertions([bundleRestriction], lineage, artifactSubject.subject_identity_sha256), 'PROPAGATION_ASSERTION_MISSING')
  const wrongPropagationBasis = clone(propagation)
  wrongPropagationBasis.basis_record_digest_sha256 = 'd9'.repeat(32)
  wrongPropagationBasis.record_digest_sha256 = recordDigest(wrongPropagationBasis)
  expectCode(() => validatePropagationAssertions([bundleRestriction, wrongPropagationBasis], lineage, artifactSubject.subject_identity_sha256), 'PROPAGATION_ASSERTION_UNRESOLVED')
  for (const [basisSequence, basisPersistedAt] of [
    [propagation.knowledge_boundary.receipt_sequence + 1, '2030-01-01T00:03:05.000Z'],
    [propagation.knowledge_boundary.receipt_sequence, '2030-01-01T00:03:01.000Z'],
    [propagation.knowledge_boundary.receipt_sequence - 1, propagation.knowledge_boundary.persisted_at],
    [propagation.knowledge_boundary.receipt_sequence - 1, '2030-01-01T00:03:05.000Z'],
  ]) {
    const invalidBasis = clone(bundleRestriction)
    invalidBasis.knowledge_boundary = knowledge(basisPersistedAt, basisSequence)
    invalidBasis.record_digest_sha256 = recordDigest(invalidBasis)
    const invalidAssertion = clone(propagation)
    invalidAssertion.basis_record_digest_sha256 = invalidBasis.record_digest_sha256
    invalidAssertion.record_digest_sha256 = recordDigest(invalidAssertion)
    expectCode(() => validatePropagationAssertions([invalidBasis, invalidAssertion], lineage, artifactSubject.subject_identity_sha256), 'PROPAGATION_BASIS_CHRONOLOGY_REJECTED')
    expectCode(() => firstBlockingKnownControl([invalidBasis, invalidAssertion], artifactSubject, lineage), 'PROPAGATION_BASIS_CHRONOLOGY_REJECTED')
  }
  const incompleteLineage = sealSubjectLineage({ nodes: [{ subject_identity_sha256: artifactSubject.subject_identity_sha256, subject_kind_code: 'artifact' }], edges: lineage.edges })
  expectCode(() => validatePropagationAssertions([bundleRestriction, propagation], incompleteLineage, artifactSubject.subject_identity_sha256), 'SUBJECT_LINEAGE_EDGE_REJECTED')
  const cyclicLineage = sealSubjectLineage({ nodes: lineage.nodes, edges: [...lineage.edges, { from_subject_identity_sha256: artifactSubject.subject_identity_sha256, to_subject_identity_sha256: bundleSubject.subject_identity_sha256 }] })
  expectCode(() => validatePropagationAssertions([bundleRestriction, propagation], cyclicLineage, artifactSubject.subject_identity_sha256), 'SUBJECT_LINEAGE_CYCLE')
  const forbiddenSourceControl = clone(bundleRestriction)
  forbiddenSourceControl.subject = clone(subject)
  forbiddenSourceControl.record_digest_sha256 = recordDigest(forbiddenSourceControl)
  const forbiddenPropagation = clone(propagation)
  forbiddenPropagation.propagates_from_subject_identity_sha256 = subject.subject_identity_sha256
  forbiddenPropagation.basis_record_digest_sha256 = forbiddenSourceControl.record_digest_sha256
  forbiddenPropagation.record_digest_sha256 = recordDigest(forbiddenPropagation)
  const forbiddenLineage = sealSubjectLineage({
    nodes: [
      { subject_identity_sha256: subject.subject_identity_sha256, subject_kind_code: 'custody_copy' },
      { subject_identity_sha256: artifactSubject.subject_identity_sha256, subject_kind_code: 'artifact' },
    ],
    edges: [{ from_subject_identity_sha256: subject.subject_identity_sha256, to_subject_identity_sha256: artifactSubject.subject_identity_sha256 }],
  })
  expectCode(() => validatePropagationAssertions([forbiddenSourceControl, forbiddenPropagation], forbiddenLineage, artifactSubject.subject_identity_sha256), 'PROPAGATION_ASSERTION_UNRESOLVED')
  const withdrawnPropagation = syntheticControl('control_withdrawn')
  withdrawnPropagation.record_code = 'control.propagation-withdrawn.synthetic.001'
  withdrawnPropagation.operation_id = propagation.operation_id
  withdrawnPropagation.operation_nonce = propagation.operation_nonce
  withdrawnPropagation.subject = clone(propagation.subject)
  withdrawnPropagation.chain = { stream_code: propagation.chain.stream_code, sequence: 2, predecessor_record_digest_sha256: propagation.record_digest_sha256 }
  withdrawnPropagation.knowledge_boundary = knowledge('2030-01-01T00:04:02.000Z', propagation.knowledge_boundary.receipt_sequence + 1)
  withdrawnPropagation.knowledge_boundary.effective_at = propagation.knowledge_boundary.effective_at
  withdrawnPropagation.corrects_record_digest_sha256 = propagation.record_digest_sha256
  withdrawnPropagation.corrected_record_kind_code = 'propagation_asserted'
  withdrawnPropagation.basis_record_digest_sha256 = null
  withdrawnPropagation.propagates_from_subject_identity_sha256 = null
  withdrawnPropagation.human_approvals = [approval('approval.propagation-withdrawal.synthetic.001', 'legal_records_authority', 'person.records.synthetic', controlApprovalScope(withdrawnPropagation))].map((entry) => { entry.decided_at = '2030-01-01T00:04:01.000Z'; return addDigest(entry) })
  withdrawnPropagation.record_digest_sha256 = recordDigest(withdrawnPropagation)
  validateControl(withdrawnPropagation)
  expectCode(() => validatePropagationAssertions([bundleRestriction, propagation, withdrawnPropagation], lineage, artifactSubject.subject_identity_sha256), 'PROPAGATION_ASSERTION_MISSING')

  const artifactRestriction = clone(validFixtures.records.restriction)
  artifactRestriction.record_code = 'control.restriction.artifact-copy.synthetic.001'
  artifactRestriction.operation_id = 'operation.restrict.artifact-copy.synthetic.001'
  artifactRestriction.operation_nonce = 'da'.repeat(32)
  artifactRestriction.subject = artifactSubject
  artifactRestriction.chain.stream_code = 'stream.restriction.artifact-copy.synthetic.001'
  artifactRestriction.record_digest_sha256 = recordDigest(artifactRestriction)
  const copyPropagation = syntheticControl('propagation_asserted')
  copyPropagation.record_code = 'control.propagation.artifact-copy.synthetic.001'
  copyPropagation.operation_id = 'operation.propagation.artifact-copy.synthetic.001'
  copyPropagation.operation_nonce = 'db'.repeat(32)
  copyPropagation.subject = clone(subject)
  copyPropagation.chain = { stream_code: 'stream.propagation.artifact-copy.synthetic.001', sequence: 1, predecessor_record_digest_sha256: null }
  copyPropagation.knowledge_boundary = knowledge('2030-01-01T00:03:04.000Z', 2)
  copyPropagation.basis_record_digest_sha256 = artifactRestriction.record_digest_sha256
  copyPropagation.propagates_from_subject_identity_sha256 = artifactSubject.subject_identity_sha256
  copyPropagation.record_digest_sha256 = recordDigest(copyPropagation)
  const copyLineage = sealSubjectLineage({
    nodes: [
      { subject_identity_sha256: artifactSubject.subject_identity_sha256, subject_kind_code: 'artifact' },
      { subject_identity_sha256: subject.subject_identity_sha256, subject_kind_code: 'custody_copy' },
    ],
    edges: [{ from_subject_identity_sha256: artifactSubject.subject_identity_sha256, to_subject_identity_sha256: subject.subject_identity_sha256 }],
  })
  validateControl(artifactRestriction)
  validateControl(copyPropagation)
  validatePropagationAssertions([artifactRestriction, copyPropagation], copyLineage, subject.subject_identity_sha256)
  const propagatedShutdown = accessShutdownForTrigger(accessShutdownRecords, copyPropagation.record_digest_sha256)
  resolveAccessShutdown(propagatedShutdown, sourceAccessInventory, subject, d930CustodyLeafProjectionSha256, [artifactRestriction, copyPropagation], copyLineage)

  const copyPropagationWithdrawal = syntheticControl('control_withdrawn')
  copyPropagationWithdrawal.record_code = 'control.propagation-artifact-copy-withdrawn.synthetic.001'
  copyPropagationWithdrawal.operation_id = copyPropagation.operation_id
  copyPropagationWithdrawal.operation_nonce = copyPropagation.operation_nonce
  copyPropagationWithdrawal.subject = clone(copyPropagation.subject)
  copyPropagationWithdrawal.chain = { stream_code: copyPropagation.chain.stream_code, sequence: 2, predecessor_record_digest_sha256: copyPropagation.record_digest_sha256 }
  copyPropagationWithdrawal.knowledge_boundary = knowledge('2030-01-01T00:03:05.000Z', 3)
  copyPropagationWithdrawal.knowledge_boundary.effective_at = copyPropagation.knowledge_boundary.effective_at
  copyPropagationWithdrawal.corrects_record_digest_sha256 = copyPropagation.record_digest_sha256
  copyPropagationWithdrawal.corrected_record_kind_code = 'propagation_asserted'
  copyPropagationWithdrawal.basis_record_digest_sha256 = null
  copyPropagationWithdrawal.propagates_from_subject_identity_sha256 = null
  copyPropagationWithdrawal.human_approvals = [approval('approval.propagation-artifact-copy-withdrawal.synthetic.001', 'legal_records_authority', 'person.records.synthetic', controlApprovalScope(copyPropagationWithdrawal))].map((entry) => { entry.decided_at = '2030-01-01T00:03:04.000Z'; return addDigest(entry) })
  copyPropagationWithdrawal.record_digest_sha256 = recordDigest(copyPropagationWithdrawal)
  validateControl(copyPropagationWithdrawal)
  expectCode(() => resolveAccessShutdown(propagatedShutdown, sourceAccessInventory, subject, d930CustodyLeafProjectionSha256, [artifactRestriction, copyPropagation, copyPropagationWithdrawal], copyLineage), 'ACCESS_TRIGGER_UNRESOLVED')

  const artifactRelease = syntheticControl('restriction_released')
  artifactRelease.record_code = 'control.restriction-artifact-copy-released.synthetic.001'
  artifactRelease.operation_id = artifactRestriction.operation_id
  artifactRelease.operation_nonce = artifactRestriction.operation_nonce
  artifactRelease.subject = clone(artifactRestriction.subject)
  artifactRelease.chain = { stream_code: artifactRestriction.chain.stream_code, sequence: 2, predecessor_record_digest_sha256: artifactRestriction.record_digest_sha256 }
  artifactRelease.knowledge_boundary = knowledge('2030-01-01T00:03:04.000Z', 2)
  artifactRelease.reason_category_code = artifactRestriction.reason_category_code
  artifactRelease.restriction_scope_code = artifactRestriction.restriction_scope_code
  artifactRelease.basis_record_digest_sha256 = artifactRestriction.record_digest_sha256
  artifactRelease.human_approvals = [approval('approval.restriction-artifact-copy-release.synthetic.001', 'security_authority', 'person.security.synthetic', controlApprovalScope(artifactRelease))].map((entry) => { entry.decided_at = '2030-01-01T00:03:03.000Z'; return addDigest(entry) })
  artifactRelease.record_digest_sha256 = recordDigest(artifactRelease)
  const postReleasePropagation = clone(copyPropagation)
  postReleasePropagation.knowledge_boundary = knowledge('2030-01-01T00:03:06.000Z', 3)
  postReleasePropagation.record_digest_sha256 = recordDigest(postReleasePropagation)
  validateControl(artifactRelease)
  expectCode(() => resolveAccessShutdown(accessShutdownForTrigger(accessShutdownRecords, postReleasePropagation.record_digest_sha256), sourceAccessInventory, subject, d930CustodyLeafProjectionSha256, [artifactRestriction, artifactRelease, postReleasePropagation], copyLineage), 'PROPAGATION_ASSERTION_UNRESOLVED')

  const oldRestriction = clone(validFixtures.records.restriction)
  const releasedRestriction = syntheticControl('restriction_released')
  releasedRestriction.operation_id = oldRestriction.operation_id
  releasedRestriction.operation_nonce = oldRestriction.operation_nonce
  releasedRestriction.subject = clone(oldRestriction.subject)
  releasedRestriction.chain = { stream_code: oldRestriction.chain.stream_code, sequence: 2, predecessor_record_digest_sha256: oldRestriction.record_digest_sha256 }
  releasedRestriction.knowledge_boundary = knowledge('2030-01-01T00:03:04.000Z', 2)
  releasedRestriction.reason_category_code = oldRestriction.reason_category_code
  releasedRestriction.restriction_scope_code = oldRestriction.restriction_scope_code
  releasedRestriction.basis_record_digest_sha256 = oldRestriction.record_digest_sha256
  releasedRestriction.human_approvals = [approval('approval.old-restriction-release.synthetic.001', 'security_authority', 'person.security.synthetic', controlApprovalScope(releasedRestriction))].map((entry) => { entry.decided_at = '2030-01-01T00:03:03.000Z'; return addDigest(entry) })
  releasedRestriction.record_digest_sha256 = recordDigest(releasedRestriction)
  const newRestriction = clone(validFixtures.records.restriction)
  newRestriction.record_code = 'control.restriction.new-episode.synthetic.001'
  newRestriction.operation_id = 'operation.restriction.new-episode.synthetic.001'
  newRestriction.operation_nonce = 'dc'.repeat(32)
  newRestriction.chain.stream_code = 'stream.restriction.new-episode.synthetic.001'
  newRestriction.knowledge_boundary = knowledge('2030-01-01T00:03:06.000Z', 3)
  newRestriction.record_digest_sha256 = recordDigest(newRestriction)
  validateControl(releasedRestriction)
  const expiryBoundaryRelease = clone(releasedRestriction)
  expiryBoundaryRelease.human_approvals[0].expires_at = expiryBoundaryRelease.knowledge_boundary.persisted_at
  expiryBoundaryRelease.human_approvals[0].record_digest_sha256 = recordDigest(expiryBoundaryRelease.human_approvals[0])
  expiryBoundaryRelease.record_digest_sha256 = recordDigest(expiryBoundaryRelease)
  expectCode(() => validateControl(expiryBoundaryRelease), 'APPROVAL_EXPIRED')
  validateControl(newRestriction)
  const episodeControls = [oldRestriction, releasedRestriction, newRestriction]
  assert.equal(firstBlockingKnownControl(episodeControls, subject, subjectLineageInventory, '2030-01-01T00:03:11.000Z', '2030-01-01T00:03:12.000Z', 4).record_digest_sha256, newRestriction.record_digest_sha256)
  assert.doesNotThrow(() => assertAccessCreatedBeforeTrigger('2030-01-01T00:03:05.000Z', newRestriction))
  expectCode(() => assertAccessCreatedBeforeTrigger('2030-01-01T00:03:05.000Z', oldRestriction), 'POST_RESTRICTION_ACCESS_CREATED')
  resolveAccessShutdown(accessShutdownForTrigger(accessShutdownRecords, newRestriction.record_digest_sha256), sourceAccessInventory, subject, d930CustodyLeafProjectionSha256, episodeControls, subjectLineageInventory)
  expectCode(() => resolveAccessShutdown(accessShutdownForTrigger(accessShutdownRecords, oldRestriction.record_digest_sha256), sourceAccessInventory, subject, d930CustodyLeafProjectionSha256, episodeControls, subjectLineageInventory), 'ACCESS_TRIGGER_NOT_EARLIEST')

  const badContext = clone(inventoryObserved)
  badContext.operation_nonce = 'ee'.repeat(32); badContext.record_digest_sha256 = recordDigest(badContext)
  expectCode(() => validateChain([executionStarted, badContext]), 'CHAIN_CONTEXT_MISMATCH')
  const rootVerification = clone(absenceVerified)
  rootVerification.chain = { stream_code: 'stream.execution.bad-root', sequence: 1, predecessor_record_digest_sha256: null }; rootVerification.record_digest_sha256 = recordDigest(rootVerification)
  expectCode(() => validateChain([rootVerification]), 'EXECUTION_TRANSITION_REJECTED')
  const contradictoryUnlink = clone(unlinkAttempted)
  contradictoryUnlink.execution.target_name_removed = false; contradictoryUnlink.record_digest_sha256 = recordDigest(contradictoryUnlink)
  expectCode(() => validateExecution(contradictoryUnlink), 'UNLINK_RESULT_CONTRADICTORY')
  for (const [field, value] of [['target_inode', 999], ['observed_target_sha256', 'ef'.repeat(32)], ['observed_target_byte_length', 31], ['observed_target_link_count', 2]]) {
    const changed = clone(unlinkAttempted); changed.inventory[field] = value; changed.record_digest_sha256 = recordDigest(changed)
    expectCode(() => field === 'target_inode' ? validateObservedIdentityAgainstBaseline(changed, inventoryObserved.inventory) : validateExecution(changed), field === 'target_inode' ? 'CUSTODY_OBSERVED_IDENTITY_DIVERGENCE' : 'OBSERVED_TARGET_IDENTITY_MISMATCH')
  }
  const impossibleAbsent = clone(absenceVerified)
  impossibleAbsent.inventory.target_inode = 22; impossibleAbsent.inventory.target_opened_no_follow = true; impossibleAbsent.record_digest_sha256 = recordDigest(impossibleAbsent)
  expectCode(() => validateExecution(impossibleAbsent), 'ABSENCE_INVENTORY_STATE_MISMATCH')
  const falseAbsence = clone(absenceVerified)
  falseAbsence.inventory.approved_primary_names_checked = 0; falseAbsence.record_digest_sha256 = recordDigest(falseAbsence)
  expectCode(() => validateExecution(falseAbsence), 'PRIMARY_ABSENCE_NOT_VERIFIED')

  for (const field of ['deletion_request_record_digest_sha256', 'deletion_authorization_record_digest_sha256', 'tombstone_record_digest_sha256', 'execution_record_digest_sha256', 'verification_record_digest_sha256', 'authorization_scope_sha256', 'd930_primary_durability_receipt_sha256', 'safety_snapshot_sha256']) {
    const receipt = clone(deletionReceipt); receipt[field] = 'fe'.repeat(32); receipt.record_digest_sha256 = recordDigest(receipt)
    expectCode(() => resolveDeletionGraph({ deletionReceipt: receipt }), field.includes('scope') || field.startsWith('d930') || field.startsWith('safety') ? 'DELETION_RECEIPT_PROOF_MISMATCH' : 'DELETION_RECEIPT_REFERENCE_MISMATCH')
  }
  expectCode(() => resolveDeletionGraph({ journalTargets: journalTargets.filter((record) => record !== deletionReceipt), journalReceipts: buildJournalReceipts(journalTargets.filter((record) => record !== deletionReceipt)) }), 'GLOBAL_RECEIPT_SEQUENCE_GAP')
  expectCode(() => resolveDeletionGraph({ journalTargets: journalTargets.filter((record) => record !== backupDirective), journalReceipts: buildJournalReceipts(journalTargets.filter((record) => record !== backupDirective)) }), 'GLOBAL_RECEIPT_SEQUENCE_GAP')
  const wrongBackupBasis = clone(backupDirective); wrongBackupBasis.basis_control_record_digest_sha256 = validFixtures.records.restriction.record_digest_sha256; wrongBackupBasis.record_digest_sha256 = recordDigest(wrongBackupBasis)
  expectCode(() => validateBackupBasis(wrongBackupBasis, [validFixtures.records.restriction, tombstone]), 'BACKUP_DIRECTIVE_BASIS_UNRESOLVED')
  const staleRecoveryHead = clone(recoveryAssessment.snapshot); staleRecoveryHead.control_ledger_head_receipt_digest_sha256 = controlLedgerHeadReceiptDigest
  expectCode(() => validateSnapshotLedgerHead(staleRecoveryHead, journalReceipts), 'SNAPSHOT_LEDGER_HEAD_MISMATCH')
  const replay = clone(validFixtures.records.restriction)
  replay.record_code = 'control.restriction.replay.002'; replay.chain.stream_code = 'stream.restriction.replay.002'; replay.record_digest_sha256 = recordDigest(replay)
  expectCode(() => preflightNoReplace([validFixtures.records.restriction, replay]), 'SEMANTIC_ACTION_REPLAY')
  const journalFork = clone(journalReceipts[1]); journalFork.record_code = 'journal.receipt.fork.002'; journalFork.record_digest_sha256 = recordDigest(journalFork)
  expectCode(() => preflightNoReplace([...journalReceipts, journalFork]), 'GLOBAL_RECEIPT_SEQUENCE_COLLISION')
  for (const changedTime of [journalReceipts[0].persisted_at, '2030-01-01T00:00:30.000Z']) {
    const reversed = clone(journalReceipts)
    reversed[1].persisted_at = changedTime
    reversed[1].record_digest_sha256 = recordDigest(reversed[1])
    for (let index = 2; index < reversed.length; index += 1) {
      reversed[index].previous_receipt_record_digest_sha256 = reversed[index - 1].record_digest_sha256
      reversed[index].record_digest_sha256 = recordDigest(reversed[index])
    }
    expectCode(() => validateJournalLedger(journalTargets, reversed), 'GLOBAL_RECEIPT_CHRONOLOGY_REJECTED')
  }
}

function preflightNoReplace(records) {
  const seen = new Map()
  const nonces = new Map()
  const operations = new Map()
  const streamPositions = new Map()
  const semanticActions = new Map()
  const receiptSequences = new Map()
  const receiptTargets = new Map()
  for (const record of records) {
    const existing = seen.get(record.record_code)
    if (existing && existing !== record.record_digest_sha256) fail('NO_REPLACE_COLLISION')
    seen.set(record.record_code, record.record_digest_sha256)
    if (record.operation_nonce) {
      if (nonces.has(record.operation_nonce) && nonces.get(record.operation_nonce) !== record.operation_id) fail('NONCE_REPLAY_COLLISION')
      if (operations.has(record.operation_id) && operations.get(record.operation_id) !== record.operation_nonce) fail('OPERATION_REPLAY_COLLISION')
      nonces.set(record.operation_nonce, record.operation_id)
      operations.set(record.operation_id, record.operation_nonce)
    }
    if (record.chain) {
      const position = `${record.format}/${record.chain.stream_code}/${record.chain.sequence}`
      if (streamPositions.has(position) && streamPositions.get(position) !== record.record_digest_sha256) fail('STREAM_POSITION_COLLISION')
      streamPositions.set(position, record.record_digest_sha256)
      const target = record.format === 'jedi-atlas-access-revocation-record' ? `/${record.access_target_identity_sha256}` : ''
      const action = `${record.format}/${record.operation_id}/${record.operation_nonce}/${record.subject.subject_identity_sha256}/${record.record_kind_code}${target}`
      if (!['control_corrected', 'control_withdrawn'].includes(record.record_kind_code) && semanticActions.has(action) && semanticActions.get(action) !== record.record_digest_sha256) fail('SEMANTIC_ACTION_REPLAY')
      semanticActions.set(action, record.record_digest_sha256)
    }
    if (record.format === 'jedi-atlas-d940-journal-append-receipt') {
      if (receiptSequences.has(record.receipt_sequence) && receiptSequences.get(record.receipt_sequence) !== record.record_digest_sha256) fail('GLOBAL_RECEIPT_SEQUENCE_COLLISION')
      if (receiptTargets.has(record.target_record_digest_sha256) && receiptTargets.get(record.target_record_digest_sha256) !== record.record_digest_sha256) fail('JOURNAL_DUPLICATE_TARGET')
      receiptSequences.set(record.receipt_sequence, record.record_digest_sha256)
      receiptTargets.set(record.target_record_digest_sha256, record.record_digest_sha256)
    }
  }
}

function assertSchemaMutationDetection() {
  for (const file of schemaFiles) {
    const entry = catalog.schemas.find((item) => item.schema_file === file)
    const mutated = clone(schemas.get(file))
    mutated.title = `${mutated.title} changed`
    assert.notEqual(sha256Bytes(Buffer.from(JSON.stringify(mutated, null, 2))), entry.raw_sha256)
  }
  const weakened = clone(schemas.get('deletion-receipt-v1.schema.json'))
  weakened.properties.complete_erasure_claimed = { type: 'boolean' }
  const localAjv = new Ajv2020({ allErrors: true, strict: false })
  localAjv.addSchema(frozenCommon)
  localAjv.addSchema(common)
  const validator = localAjv.compile(weakened)
  const overclaim = clone(deletionReceipt)
  overclaim.complete_erasure_claimed = true
  overclaim.record_digest_sha256 = recordDigest(overclaim)
  assert.equal(validator(overclaim), true, 'weakened schema should expose the mutation test')
  expectCode(() => validateReceipt(overclaim), 'SCHEMA_REJECTED')
}

function assertDatabaseBoundary() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d940-design-'))
  const databasePath = path.join(temp, 'atlas.sqlite')
  try {
    applyMigrations({ databasePath, migrationsDirectory: path.join(project, 'data/migrations') })
    const database = new DatabaseSync(databasePath, { readOnly: true })
    try {
      assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
      assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])
      for (const table of atlasTables) assert.equal(database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count, 0, table)
    } finally {
      database.close()
    }
  } finally {
    fs.rmSync(temp, { recursive: true, force: true })
  }
}

assertFrozenInputs()
assertCatalogAndFingerprints()
assertMatrixFingerprints()
assertFieldRegistry()
assertGoldenVectors()
assertProjectionContracts()
assertSchemasAndSemantics()
assertProjectionAndKnowledgeTime()
assertNegativeFixturesAndMutations()
assertExhaustiveMatricesAndReviewMutants()
assertSchemaMutationDetection()
assertDatabaseBoundary()

console.log('D9.4.0 contract validation passed.')
console.log(`Schemas: ${schemaFiles.length + 1}; top-level contracts: ${schemaFiles.length}; contract-root files: ${fs.readdirSync(root, { recursive: true, withFileTypes: true }).filter((entry) => entry.isFile()).length}.`)
console.log(`Catalog: ${expected.catalog}`)
console.log(`Classification: ${expected.classification}`)
console.log(`Root inventory: ${expected.root_inventory}`)
console.log('Restriction, access shutdown, separation of duty, primary-copy deletion, D9.5 coordination, and classification-only recovery matrices passed.')
console.log('No runtime activation, physical deletion, evidence acceptance, legal authority, or publication behavior was exercised.')
