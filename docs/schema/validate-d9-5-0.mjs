import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync, spawnSync } from 'node:child_process'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { applyMigrations } from '../../data/lib/migrations.mjs'
import { canonicalize, canonicalSha256, parseStrictJson, sha256Bytes } from '../../d9/control-plane/canonical.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const project = path.resolve(here, '../..')
const root = path.join(here, 'd9-5-0')
const fixtureRoot = path.join(root, 'fixtures')
const ZERO = '0'.repeat(64)

const schemaFiles = [
  'common-v1.schema.json',
  'operational-profile-v1.schema.json',
  'backup-manifest-v1.schema.json',
  'backup-durability-receipt-v1.schema.json',
  'restore-authorization-v1.schema.json',
  'restore-plan-v1.schema.json',
  'restore-lifecycle-record-v1.schema.json',
  'deletion-aware-reconstruction-v1.schema.json',
  'restore-drill-record-v1.schema.json',
  'ipc-message-v1.schema.json',
  'journal-append-receipt-v1.schema.json',
  'retention-control-record-v1.schema.json',
  'retention-head-attestation-v1.schema.json',
]

const frozenFiles = {
  'data/migrations/001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  'data/migrations/002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  'data/migrations/003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
  'data/migrations/004_tranche_1a_foundations.sql': '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
  'data/migrations/005_tranche_2a_source_quarantine.sql': '1f83b484ca998be3bf5756492d4dffd958e2a6b37dbcc837e399226fdf41026b',
  'docs/schema/d9-0/contract-catalog-v1.json': 'e0a5663b378453a00626f02961465a60a474e145dd5160bf85a1797cd9316d2a',
  'docs/schema/d9-3-0/contract-catalog-v1.json': 'cd91f67c25941a472b89fe2fa6f19b012714dec96661b65b76ecfacf7f48e87c',
  'docs/schema/d9-4-0/contract-catalog-v1.json': '12da4237efade65cf6e2cc19d2df936e98caf505c8f6d30b38e7df8c4d349ad7',
  'docs/schema/d9-recovery-resolvers/contract-catalog-v1.json': 'df33cbf575f8f4b430ef22384f0d73350e521abed6443f07006d13bb3b968ba3',
  'docs/schema/d9-recovery-resolvers/root-inventory-v1.json': '93832dc8a6f12ae030515781169fd8ac9dd5431aa68f62699168469da3da6f31',
  'docs/schema/d9-recovery-resolvers-v1-1/contract-catalog-v1-1.json': 'aa846c01c5d055050c810249316d11eba7a48d1080681f9538be3e71d371bb26',
  'docs/schema/d9-recovery-resolvers-v1-1/root-inventory-v1-1.json': 'b3711db55ed73a1a74621a808014aae35b2e05319e5cf0aeba5df0d62b1933bf',
  'docs/schema/d9-recovery-resolvers-v1-2/contract-catalog-v1-2.json': 'b6fd085a5718fdccc51ae4cfbf10645aaa3a1f79929d9ebe896247350d3ddb3c',
  'docs/schema/d9-recovery-resolvers-v1-2/root-inventory-v1-2.json': '3bc242bbd7147597e9b34aad16293d8e397cb23d4b7b7a6ca3578b371403c1ad',
  'docs/schema/d9-recovery-resolvers-v1-3/contract-catalog-v1-3.json': '0aa40744517d595cafca368852771345f52db4c0b2bda36751912607183bcc9a',
  'docs/schema/d9-recovery-resolvers-v1-3/root-inventory-v1-3.json': '51d076dd244aa74c4fc7a433af6ab8121031f4b6194381477460c81ccd807fda',
  'docs/schema/validate-d9-0.mjs': 'a9046e8603842ac7fea210dab1a276e684456b49f9c702baeac4dcc7e8cd8684',
  'docs/schema/validate-d9-3-0.mjs': '494182b29e29b239bbec25ea6b012e163775d6a3195582514713766c3c6d8d0f',
  'docs/schema/validate-d9-4-0.mjs': '711f575425a1bffcbd09255f327b966df8dacc5ca58e10312bfa189a6a6f8ef6',
  'docs/schema/validate-d9-recovery-resolvers.mjs': 'bc36de4475ee6d8b9fd354f80163799f431496ae91765b5dd4903fdde9763ef5',
  'docs/schema/validate-d9-recovery-resolvers-v1-1.mjs': 'f6e8aa1f242198febd6e3b5bfa0a93ddf0f9829bc4850d920a1ca9be941235c5',
  'docs/schema/validate-d9-recovery-resolvers-v1-2.mjs': '4708ae4c43fe8bfd83e13e216b1d5fc8fc15077e6ec38e24eda78f0b859f5ad7',
  'docs/schema/validate-d9-recovery-resolvers-v1-3.mjs': '49a89a606a133f9778d2329972e94c1bc40cdee9c2a3225c4746cd29ed0f3e0f',
  'd9/control-plane/canonical.mjs': 'e0905b2e87991c67907b63d0a9b5db58c54cc982c2ab603501316ec26d648567',
  'd9/control-plane/contracts.mjs': 'c54a65f1033fd241a7da2728b568f5b92b79dc472810c9e9f6c85b943c0dbded',
  'tests/d9-1-support/runtime-fixture.mjs': '421ec225d07b835f1888975b09293941bace35cb12978ea49f8a7ac69002c3e9',
}

const pinnedCommits = {
  d901: '58a10d43ee5fcc3121a368301b4f5a925f26a9e3',
  d91: '79046c27dfa6923383be33a1d0aaa5a7641f5d1f',
  d92: '460547b7fe75a94f689dabc97fd91ee6f803934a',
  d930: '89433cf058ca8f52b658ea1ce2d0391aaf44f7fe',
  d931: 'd960a03f4b8ac8a78d3f6b40ba909eb24b5f3442',
  d940: '7db408fb0f9083f4a17c89cbaf1cb1a06bc44416',
  recoveryV1: 'd4f21787ebc4b99e032a9a2966cc828366159447',
  recoveryV11: '29157dd584c81ed421dfa52313f0763ce2e0b568',
  recoveryV12: 'ec83429ad3b9f77d655970f96d0be054f345a60a',
  recoveryV13: 'd9eddd21494f59e27b2b6365456b53ee2719db2c',
  d941: '08899d984c063743701c537a45e2ec015f168982',
}

const atlasTables = [
  'atlas_principals', 'atlas_languages', 'atlas_jurisdictions', 'atlas_jurisdiction_versions',
  'atlas_evidence_bundle_receipts', 'atlas_retrieval_locations', 'atlas_artifacts',
  'atlas_retrieval_events', 'atlas_retrieval_redirects', 'atlas_artifact_custody_events',
  'atlas_processing_runs', 'atlas_processing_outputs', 'atlas_unverified_candidate_occurrences',
]

function readJson(file) {
  return parseStrictJson(fs.readFileSync(file), {
    maximumBytes: 16 * 1024 * 1024,
    maximumDepth: 256,
    maximumMembers: 500_000,
    contractNumbers: true,
  })
}

function rawSha(file) { return sha256Bytes(fs.readFileSync(file)) }
function clone(value) { return structuredClone(value) }
function seal(value) { value.record_digest_sha256 = canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' }); return value }
function fail(code, detail = code) { const error = new Error(`${code}: ${detail}`); error.code = code; throw error }
function expectCode(fn, code) { assert.throws(fn, (error) => error?.code === code || String(error?.message).includes(code), `expected ${code}`) }
function ms(value) { const parsed = Date.parse(value); if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) fail('TIMESTAMP_INVALID', String(value)); return parsed }
function same(left, right) { return canonicalize(left) === canonicalize(right) }

function assertSafeStrings(value, pointer = '') {
  if (typeof value === 'string') {
    if (/\0|[\u0001-\u001f\u007f]/u.test(value)) fail('UNSAFE_STRING', pointer)
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+|(?:api|private|signing)[_-]?key\s*[:=]|password\s*[:=]/iu.test(value)) fail('SECRET_MATERIAL', pointer)
    return
  }
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (key.endsWith('_at') || key.endsWith('_from') || key.endsWith('_until') || key === 'scheduled_for' || key === 'retain_until' || key === 'expires_at') {
      if (typeof child === 'string') ms(child)
    }
    assertSafeStrings(child, `${pointer}/${key}`)
  }
}

const frozenD940Fixture = readJson(path.join(here, 'd9-4-0/fixtures/valid-contracts-v1.json')).records
const frozenD930Fixture = readJson(path.join(here, 'd9-3-0/fixtures/valid-contracts-v1.json')).records
const frozenBindings = new Map(frozenD940Fixture.identity_bindings.bindings.map((item) => [item.binding_code, item]))
const frozenRosterAssignments = new Map(frozenD940Fixture.authority_roster.assignments.map((item) => [`${item.role_code}/${item.binding_code}`, item]))
const authorityContext = {
  runtime_profile_record_digest_sha256: frozenD940Fixture.identity_bindings.runtime_profile_record_digest_sha256,
  identity_bindings_record_digest_sha256: frozenD940Fixture.identity_bindings.record_digest_sha256,
  authority_roster_record_digest_sha256: frozenD940Fixture.authority_roster.record_digest_sha256,
}

function actorMap(sourceFixture) {
  return new Map(sourceFixture.actor_processes.map((spec) => {
    const binding = frozenBindings.get(spec.binding_code)
    assert.ok(binding, `frozen binding ${spec.binding_code}`)
    const roster = spec.d940_role_code === null ? null : frozenRosterAssignments.get(`${spec.d940_role_code}/${spec.binding_code}`)
    assert.ok(spec.d940_role_code === null || roster, `frozen roster assignment ${spec.d940_role_code}/${spec.binding_code}`)
    const actorValue = {
      actor_kind_code: binding.principal_kind_code,
      semantic_role_code: spec.semantic_role_code,
      runtime_role_code: binding.runtime_role_code,
      binding_code: binding.binding_code,
      principal_code: roster?.principal_code ?? binding.atlas_principal_code,
      ipc_endpoint_code: binding.ipc_endpoint_code,
      executable_build_sha256: binding.executable_sha256,
      binding_generation: frozenD940Fixture.identity_bindings.binding_generation,
      ...authorityContext,
      process_instance_code: spec.process_instance_code,
    }
    return [spec.semantic_role_code, actorValue]
  }))
}
function actor(actors, code) { const value = actors.get(code); assert.ok(value, `actor ${code}`); return clone(value) }
function technicalClaims() {
  return {
    evidence_acceptance_claimed: false,
    officiality_claimed: false,
    legal_authority_claimed: false,
    legal_compliance_claimed: false,
    publication_eligibility_claimed: false,
    complete_erasure_claimed: false,
  }
}

const classifications = readJson(path.join(root, 'classifications-v1.json'))
const digestProfiles = readJson(path.join(root, 'digest-profiles-v1.json'))
const fieldRegistry = readJson(path.join(root, 'field-source-registry-v1.json'))
const storageProfiles = readJson(path.join(root, 'storage-profiles-v1.json'))
const fixture = readJson(path.join(fixtureRoot, 'valid-contracts-v1.json'))
const invalidFixture = readJson(path.join(fixtureRoot, 'invalid-contracts-v1.json'))
const golden = readJson(path.join(fixtureRoot, 'golden-vectors-v1.json'))

function buildRecords() {
  const actors = actorMap(fixture)
  const profile = seal({
    format: 'jedi-atlas-d950-operational-profile', format_version: '1.0.0', profile_code: 'profile.synthetic.d950.001',
    status_code: 'design_only_unactivated', authority_context: { ...authorityContext, binding_generation: 1, authority_roster_adoption_record_digest_sha256: frozenD940Fixture.authority_roster_adoption.record_digest_sha256, activation_state_code: 'design_only_unactivated' },
    base_contracts: {
      d901_catalog_sha256: frozenFiles['docs/schema/d9-0/contract-catalog-v1.json'], d930_catalog_sha256: frozenFiles['docs/schema/d9-3-0/contract-catalog-v1.json'],
      d940_catalog_sha256: frozenFiles['docs/schema/d9-4-0/contract-catalog-v1.json'], recovery_v13_catalog_sha256: frozenFiles['docs/schema/d9-recovery-resolvers-v1-3/contract-catalog-v1-3.json'],
      recovery_v13_root_inventory_sha256: frozenFiles['docs/schema/d9-recovery-resolvers-v1-3/root-inventory-v1-3.json'], d941_implementation_commit: pinnedCommits.d941,
    },
    allowed_operation_codes: classifications.operation_mode_rules.map((item) => item.operation_code),
    role_bindings: [...actors.values()].map(clone),
    ipc_routes: classifications.ipc_route_rules.map((route) => ({ ...route, endpoint_code: `ipc.d950.${route.route_code.split('.').slice(1).join('.')}`, request_format: 'jedi-atlas-d950-ipc-message', response_format: 'jedi-atlas-d950-ipc-message' })),
    limits: { manifest_bytes_max: 1048576, inventory_entries_max: 4096, backup_set_bytes_max: 1073741824, restore_files_max: 4096, operation_timeout_ms: 300000, response_age_ms_max: 5000, checkpoint_age_seconds_max: 86400, human_approval_age_seconds_max: 86400 },
    storage_policy: { append_only_records: true, no_replace: true, canonical_json: 'rfc8785-compatible-jcs-no-unicode-normalization', retention_expiry_deletes_automatically: false, backup_bytes_access_code: 'restricted_integrity_only', restore_staging_access_code: 'inaccessible_until_controls_applied' },
    authority_boundary: technicalClaims(), record_digest_sha256: ZERO,
  })
  const sourceInventory = clone(fixture.inventory_entries)
  const copies = clone(fixture.backup_copies)
  for (const copy of copies) {
    copy.copy_identity_sha256 = canonicalSha256({
      copy_code: copy.copy_code,
      copy_class_code: copy.copy_class_code,
      backend_code: copy.backend_code,
      backend_generation: copy.backend_generation,
      backend_reference: copy.backend_reference,
      artifact: copy.artifact,
    })
  }
  const sourceCopyCoverage = sourceInventory.map((entry, index) => ({ source_stable_identity_code: entry.stable_identity_code, copy_codes: [copies[index].copy_code] }))
  const manifest = seal({
    format: 'jedi-atlas-backup-set-manifest',
    format_version: '1.0.0',
    record_code: 'backup.manifest.synthetic.001',
    operation_id: fixture.operation_id,
    operation_nonce: fixture.operation_nonce,
    backup_set_code: fixture.backup_set_code,
    backup_chain_sequence: 1,
    previous_backup_manifest_record_digest_sha256: null,
    source_checkpoint: clone(fixture.source_checkpoint),
    source_inventory: sourceInventory,
    source_copy_coverage: sourceCopyCoverage,
    source_inventory_digest_sha256: canonicalSha256({ source_checkpoint: fixture.source_checkpoint, source_inventory: sourceInventory, source_copy_coverage: sourceCopyCoverage }),
    backup_copies: copies,
    backup_copy_inventory_digest_sha256: canonicalSha256([...copies].sort((a, b) => a.copy_code.localeCompare(b.copy_code))),
    retention: {
      retention_class_code: 'pilot_short_term',
      retain_until: '2030-02-01T00:00:00.000Z',
      hold_state_code: 'none_known',
      expiry_action_code: 'human_review_required_no_automatic_deletion',
    },
    producer: actor(actors, 'backup_producer'),
    persistence_broker: actor(actors, 'persistence_broker'),
    created_at: fixture.timeline.backup_created_at,
    persisted_at: '2030-01-01T00:01:01.000Z',
    technical_claims: technicalClaims(),
    record_digest_sha256: ZERO,
  })

  const bundle = { bundle_id: 'bundle.synthetic.001', bundle_sequence: 2, bundle_digest_sha256: '44'.repeat(32) }
  const logicalState = { state_seal_code: 'state.synthetic.001', state_seal_record_digest_sha256: fixture.source_checkpoint.logical_state_seal_record_digest_sha256, logical_state_sha256: fixture.source_checkpoint.source_state_head_digest_sha256 }
  const primaryReceiptRawSha256 = sha256Bytes(Buffer.from(canonicalize(frozenD930Fixture.primary_receipt)))
  const receiptSpecs = copies.map((copy) => copy.artifact.byte_layer_code === frozenD930Fixture.primary_receipt.semantic.artifact.byte_layer_code && copy.artifact.sha256 === frozenD930Fixture.primary_receipt.semantic.artifact.sha256 && copy.artifact.byte_length === frozenD930Fixture.primary_receipt.semantic.artifact.byte_length
    ? { kind: 'artifact_copy', scopeProfile: 'artifact_bundle_copy_primary_receipt_operation_nonce_v1', copy, scope: { bundle, artifact: clone(copy.artifact), copy_code: copy.copy_code, primary_receipt: { format: 'jedi-atlas-primary-durability-receipt', format_version: '1.0.0', record_code: frozenD930Fixture.primary_receipt.record_code, receipt_raw_sha256: primaryReceiptRawSha256 }, operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce } }
    : { kind: 'source_copy', scopeProfile: 'source_copy_operation_nonce_v1', copy, scope: { copy_code: copy.copy_code, artifact: clone(copy.artifact), operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce } })
  receiptSpecs.push({ kind: 'prior_database', scopeProfile: 'prior_logical_state_database_generation_operation_nonce_v1', copy: copies[0], scope: { bundle, prior_logical_state: logicalState, database_generation: 1, operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce } })
  const receipts = []
  for (const [index, spec] of receiptSpecs.entries()) {
    receipts.push(seal({
      format: 'jedi-atlas-backup-durability-receipt',
      format_version: '1.0.0',
      record_code: `backup.receipt.synthetic.${index + 1}`,
      receipt_kind_code: spec.kind,
      scope_profile_code: spec.scopeProfile,
      scope: spec.scope,
      scope_sha256: canonicalSha256(spec.scope),
      backup_profile_record_digest_sha256: profile.record_digest_sha256,
      operation_id: fixture.operation_id,
      operation_nonce: fixture.operation_nonce,
      backup_set_code: fixture.backup_set_code,
      backup_manifest_record_digest_sha256: manifest.record_digest_sha256,
      source_checkpoint_record_digest_sha256: fixture.source_checkpoint.checkpoint_record_digest_sha256,
      copy_identity: clone(spec.copy),
      verification: {
        outcome_code: 'passed',
        recomputed_sha256: spec.copy.artifact.sha256,
        recomputed_byte_length: spec.copy.artifact.byte_length,
        manifest_match: true,
        source_checkpoint_match: true,
      },
      durability: {
        no_replace_enforced: true,
        object_data_synchronized: true,
        parent_namespace_synchronized: true,
        final_reopen_rehash_passed: true,
        bounded_durability_code: 'component_observation_not_power_loss_guarantee',
      },
      producer: actor(actors, 'backup_producer'),
      independent_verifier: actor(actors, 'backup_verifier'),
      persistence_broker: actor(actors, 'persistence_broker'),
      completed_at: new Date(ms(fixture.timeline.backup_verified_at) + index * 1000).toISOString(),
      persisted_at: new Date(ms(fixture.timeline.backup_verified_at) + index * 1000 + 500).toISOString(),
      technical_claims: technicalClaims(),
      record_digest_sha256: ZERO,
    }))
  }
  const finalScope = { bundle, resulting_logical_state: logicalState, receipt_head: { journal_namespace_code: 'd940.global.journal.v1', receipt_sequence: fixture.source_checkpoint.checkpoint_sequence, receipt_record_digest_sha256: fixture.source_checkpoint.journal_tip_receipt_digest_sha256, receipt_persisted_at: fixture.source_checkpoint.captured_at }, constituent_receipt_record_digests: receipts.map((item) => item.record_digest_sha256), inventory_digest_sha256: manifest.source_inventory_digest_sha256, operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce }
  const finalIndex = receipts.length
  receipts.push(seal({
    format: 'jedi-atlas-backup-durability-receipt', format_version: '1.0.0', record_code: `backup.receipt.synthetic.${finalIndex + 1}`, receipt_kind_code: 'final_consistent_set', scope_profile_code: 'resulting_logical_state_receipt_head_inventory_operation_nonce_v1', scope: finalScope, scope_sha256: canonicalSha256(finalScope), backup_profile_record_digest_sha256: profile.record_digest_sha256, operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce, backup_set_code: fixture.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, source_checkpoint_record_digest_sha256: fixture.source_checkpoint.checkpoint_record_digest_sha256, copy_identity: clone(copies[0]), verification: { outcome_code: 'passed', recomputed_sha256: copies[0].artifact.sha256, recomputed_byte_length: copies[0].artifact.byte_length, manifest_match: true, source_checkpoint_match: true }, durability: { no_replace_enforced: true, object_data_synchronized: true, parent_namespace_synchronized: true, final_reopen_rehash_passed: true, bounded_durability_code: 'component_observation_not_power_loss_guarantee' }, producer: actor(actors, 'backup_producer'), independent_verifier: actor(actors, 'backup_verifier'), persistence_broker: actor(actors, 'persistence_broker'), completed_at: new Date(ms(fixture.timeline.backup_verified_at) + finalIndex * 1000).toISOString(), persisted_at: new Date(ms(fixture.timeline.backup_verified_at) + finalIndex * 1000 + 500).toISOString(), technical_claims: technicalClaims(), record_digest_sha256: ZERO,
  }))

  const boundary = {
    observed_at: '2030-01-01T00:03:00.000Z',
    known_at: '2030-01-01T00:03:01.000Z',
    known_through_d940_receipt_sequence: 7,
    d940_state_head_digest_sha256: fixture.source_checkpoint.source_state_head_digest_sha256,
    d940_journal_tip_receipt_digest_sha256: fixture.source_checkpoint.journal_tip_receipt_digest_sha256,
    d940_correspondence_record_digest_sha256: fixture.source_checkpoint.correspondence_record_digest_sha256,
  }
  const copyClassInventory = clone(fixture.copy_class_states)
  const controlEvidence = [
    { evidence_type_code: 'custody_control', source_format: 'jedi-atlas-custody-control-record', source_record_kind_code: 'restriction_imposed', record_code: 'd940.control.restriction.synthetic.001', record_digest_sha256: fixture.control_directives[0].basis_control_record_digest_sha256, journal_receipt_record_digest_sha256: '57'.repeat(32), subject_identity_sha256: fixture.subject_identity_sha256, basis_record_digest_sha256: null, directive_code: null, resolver_response_record_digest_sha256: '58'.repeat(32), current_leaf: true, applicability_code: 'applies_currently' },
    { evidence_type_code: 'deletion_receipt', source_format: 'jedi-atlas-deletion-receipt', source_record_kind_code: null, record_code: 'd940.deletion.receipt.synthetic.001', record_digest_sha256: '53'.repeat(32), journal_receipt_record_digest_sha256: '54'.repeat(32), subject_identity_sha256: fixture.subject_identity_sha256, basis_record_digest_sha256: null, directive_code: null, resolver_response_record_digest_sha256: '59'.repeat(32), current_leaf: true, applicability_code: 'historical_deletion_evidence' },
    { evidence_type_code: 'backup_coordination', source_format: 'jedi-atlas-backup-coordination-record', source_record_kind_code: 'restriction_directive', record_code: 'd940.backup.coordination.synthetic.001', record_digest_sha256: fixture.control_directives[0].d940_coordination_record_digest_sha256, journal_receipt_record_digest_sha256: '56'.repeat(32), subject_identity_sha256: fixture.subject_identity_sha256, basis_record_digest_sha256: fixture.control_directives[0].basis_control_record_digest_sha256, directive_code: fixture.control_directives[0].directive_code, resolver_response_record_digest_sha256: '5a'.repeat(32), current_leaf: true, applicability_code: 'applies_currently' },
  ]
  const deletionAware = seal({
    format: 'jedi-atlas-deletion-aware-reconstruction',
    format_version: '1.0.0',
    record_code: 'reconstruction.synthetic.001',
    operation_id: fixture.operation_id,
    operation_nonce: fixture.operation_nonce,
    backup_set_code: fixture.backup_set_code,
    subject_identity_sha256: fixture.subject_identity_sha256,
    source_checkpoint_record_digest_sha256: fixture.source_checkpoint.checkpoint_record_digest_sha256,
    control_snapshot: clone(boundary),
    control_evidence: controlEvidence,
    control_directives: clone(fixture.control_directives),
    copy_class_inventory: copyClassInventory,
    copy_class_inventory_digest_sha256: canonicalSha256(copyClassInventory),
    control_state_code: 'complete_current_consistent',
    restore_disposition_code: 'eligible_with_controls',
    bytes_accessible: false,
    bounded_copy_classes_complete: true,
    complete_erasure_claimed: false,
    limitations: [
      'bounded_registered_copy_classes_only',
      'hidden_or_unregistered_copies_not_excluded',
      'open_descriptor_inventory_is_runtime_bounded',
      'storage_media_remanence_not_assessed',
      'legal_compliance_not_assessed',
      'technical_recovery_evidence_only',
    ],
    semantic_verifier: actor(actors, 'control_state_verifier'),
    persistence_broker: actor(actors, 'persistence_broker'),
    evaluated_at: '2030-01-01T00:03:02.000Z',
    persisted_at: '2030-01-01T00:03:03.000Z',
    technical_claims: technicalClaims(),
    record_digest_sha256: ZERO,
  })

  const retentionControl = seal({
    format: 'jedi-atlas-backup-retention-control', format_version: '1.0.0', record_code: 'retention.control.synthetic.001',
    chain: { namespace_code: 'd950.retention.controls.v1', sequence: 1, previous_record_digest_sha256: null },
    backup_set_code: fixture.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256,
    decision_code: 'retain', retention_class_code: 'pilot_short_term', retain_until: '2030-02-01T00:00:00.000Z', hold_state_code: 'none_known', deletion_authority_present: false,
    reason_code: 'initial_retention', semantic_actor: actor(actors, 'legal_records_authority'), persistence_actor: actor(actors, 'persistence_broker'),
    effective_at: fixture.timeline.backup_created_at, recorded_at: '2030-01-01T00:03:02.000Z', persisted_at: '2030-01-01T00:03:03.000Z', technical_claims: technicalClaims(), record_digest_sha256: ZERO,
  })
  const retentionHistory = [retentionControl]
  const retentionReceipt = seal({
    format: 'jedi-atlas-d950-journal-append-receipt', format_version: '1.0.0', record_code: 'd950.retention.receipt.001',
    journal_namespace_code: 'd950.retention.journal.v1', receipt_sequence: 1, previous_receipt_record_digest_sha256: null,
    target_format: retentionControl.format, target_record_code: retentionControl.record_code, target_record_digest_sha256: retentionControl.record_digest_sha256,
    operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce, semantic_actor: actor(actors, 'legal_records_authority'),
    persistence_actor: actor(actors, 'persistence_broker'), semantic_recorded_at: retentionControl.recorded_at,
    persisted_at: '2030-01-01T00:03:03.500Z', durability_state_code: 'record_and_receipt_flushed_in_protected_d950_ledger', record_digest_sha256: ZERO,
  })
  const makeRetentionHeadAttestation = (recordCode, observedAt, knownAt) => seal({
    format: 'jedi-atlas-retention-head-attestation', format_version: '1.0.0', record_code: recordCode,
    operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce, backup_set_code: fixture.backup_set_code,
    backup_manifest_record_digest_sha256: manifest.record_digest_sha256, namespace_code: retentionControl.chain.namespace_code,
    head_sequence: retentionControl.chain.sequence, head_record_digest_sha256: retentionControl.record_digest_sha256,
    head_receipt_record_digest_sha256: retentionReceipt.record_digest_sha256, head_receipt_persisted_at: retentionReceipt.persisted_at,
    observed_by: actor(actors, 'persistence_broker'), observed_at: observedAt, known_at: knownAt,
    technical_claims: technicalClaims(), record_digest_sha256: ZERO,
  })
  const retentionHeadAttestation = makeRetentionHeadAttestation('retention.head.attestation.synthetic.plan', '2030-01-01T00:03:58.000Z', '2030-01-01T00:03:59.000Z')
  const retentionHeadAttestations = [retentionHeadAttestation]

  const targetEnvironment = {
    target_environment_code: 'target.synthetic.restore.001',
    target_kind_code: 'disposable_restore_candidate',
    runtime_profile_record_digest_sha256: '7171717171717171717171717171717171717171717171717171717171717171',
    identity_bindings_record_digest_sha256: '7272727272727272727272727272727272727272727272727272727272727272',
    binding_generation: 1,
    migration_set_digest_sha256: '7373737373737373737373737373737373737373737373737373737373737373',
    target_root_identity_sha256: '7474747474747474747474747474747474747474747474747474747474747474',
    preexisting_state_code: 'empty_verified',
  }
  const targetIdentity = canonicalSha256(targetEnvironment)
  const authorizationScope = canonicalSha256({
    operation_id: fixture.operation_id,
    operation_nonce: fixture.operation_nonce,
    backup_set_code: fixture.backup_set_code,
    backup_manifest_record_digest_sha256: manifest.record_digest_sha256,
    source_checkpoint_record_digest_sha256: fixture.source_checkpoint.checkpoint_record_digest_sha256,
    target_environment_identity_sha256: targetIdentity,
  })
  const approvalRoles = ['recovery_authority', 'legal_records_authority', 'privacy_authority']
  const approvalRouteCodes = ['route.restore.approve.recovery', 'route.restore.approve.records', 'route.restore.approve.privacy']
  const approvalRequests = []
  const approvalResponses = []
  const approvals = approvalRoles.map((role, index) => {
    const decidedAt = new Date(ms(fixture.timeline.authorization_from) + index * 1000).toISOString()
    const decisionPayload = { approval_code: `approval.synthetic.${index + 1}`, decision_code: 'approve_restore', scope_sha256: authorizationScope, actor: actor(actors, role), decided_at: decidedAt, valid_until: fixture.timeline.authorization_until }
    const decisionPayloadSha256 = canonicalSha256(decisionPayload)
    const request = seal({
      format: 'jedi-atlas-d950-ipc-message', format_version: '1.0.0', message_kind_code: 'request', route_code: approvalRouteCodes[index], request_code: `request.approval.${index + 1}`,
      operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce, request_sequence: index + 1, sender: actor(actors, role), recipient: actor(actors, 'persistence_broker'),
      payload_format: 'jedi-atlas-restore-approval-decision', payload_record_digest_sha256: decisionPayloadSha256, response_to_request_digest_sha256: null,
      outcome_code: 'submitted', error_code: 'none', retryability_code: 'not_retryable', sent_at: decidedAt, expires_at: fixture.timeline.authorization_until, record_digest_sha256: ZERO,
    })
    const response = seal({
      format: 'jedi-atlas-d950-ipc-message', format_version: '1.0.0', message_kind_code: 'response', route_code: approvalRouteCodes[index], request_code: request.request_code,
      operation_id: fixture.operation_id, operation_nonce: fixture.operation_nonce, request_sequence: request.request_sequence, sender: actor(actors, 'persistence_broker'), recipient: actor(actors, role),
      payload_format: 'jedi-atlas-restore-approval-acceptance', payload_record_digest_sha256: request.record_digest_sha256, response_to_request_digest_sha256: request.record_digest_sha256,
      outcome_code: 'accepted', error_code: 'none', retryability_code: 'not_retryable', sent_at: new Date(ms(decidedAt) + 250).toISOString(), expires_at: fixture.timeline.authorization_until, record_digest_sha256: ZERO,
    })
    approvalRequests.push(request); approvalResponses.push(response)
    return seal({ ...decisionPayload, decision_payload_sha256: decisionPayloadSha256, submission_request_record_digest_sha256: request.record_digest_sha256, broker_response_record_digest_sha256: response.record_digest_sha256, record_digest_sha256: ZERO })
  })
  const authorization = seal({
    format: 'jedi-atlas-restore-authorization',
    format_version: '1.0.0',
    record_code: 'restore.authorization.synthetic.001',
    operation_id: fixture.operation_id,
    operation_nonce: fixture.operation_nonce,
    requester: actor(actors, 'restore_requester'),
    backup_set_code: fixture.backup_set_code,
    backup_manifest_record_digest_sha256: manifest.record_digest_sha256,
    source_checkpoint_record_digest_sha256: fixture.source_checkpoint.checkpoint_record_digest_sha256,
    target_environment_identity_sha256: targetIdentity,
    authorization_scope_sha256: authorizationScope,
    approvals,
    valid_from: fixture.timeline.authorization_from,
    valid_until: fixture.timeline.authorization_until,
    persistence_broker: actor(actors, 'persistence_broker'),
    persisted_at: '2030-01-01T00:03:04.000Z',
    technical_claims: technicalClaims(),
    record_digest_sha256: ZERO,
  })

  const stages = classifications.restore_stage_rules.map((item) => item.stage_code)
  const plan = seal({
    format: 'jedi-atlas-restore-plan',
    format_version: '1.0.0',
    record_code: 'restore.plan.synthetic.001',
    operation_id: fixture.operation_id,
    operation_nonce: fixture.operation_nonce,
    restore_mode_code: 'authorized_reconstruction',
    backup_set_code: fixture.backup_set_code,
    backup_manifest_record_digest_sha256: manifest.record_digest_sha256,
    backup_receipt_record_digests: receipts.map((item) => item.record_digest_sha256),
    source_checkpoint: clone(fixture.source_checkpoint),
    authorization_record_digest_sha256: authorization.record_digest_sha256,
    target_environment: targetEnvironment,
    pre_restore_control_snapshot: clone(boundary),
    control_directives: clone(fixture.control_directives),
    deletion_aware_reconstruction_record_digests: [deletionAware.record_digest_sha256],
    retention_control_record_digest_sha256: retentionControl.record_digest_sha256,
    retention_control_chain_sequence: retentionControl.chain.sequence,
    retention_head: {
      namespace_code: retentionHeadAttestation.namespace_code,
      head_sequence: retentionHeadAttestation.head_sequence,
      head_record_digest_sha256: retentionHeadAttestation.head_record_digest_sha256,
      head_receipt_record_digest_sha256: retentionHeadAttestation.head_receipt_record_digest_sha256,
      head_receipt_persisted_at: retentionHeadAttestation.head_receipt_persisted_at,
      attestation_record_digest_sha256: retentionHeadAttestation.record_digest_sha256,
      known_at: retentionHeadAttestation.known_at,
    },
    ordered_stage_codes: stages,
    executor: actor(actors, 'restore_executor'),
    control_state_verifier: actor(actors, 'control_state_verifier'),
    restored_state_verifier: actor(actors, 'restored_state_verifier'),
    persistence_broker: actor(actors, 'persistence_broker'),
    planned_at: fixture.timeline.restore_planned_at,
    expires_at: fixture.timeline.restore_expires_at,
    technical_claims: technicalClaims(),
    record_digest_sha256: ZERO,
  })

  const lifecycle = []
  let previous = null
  for (const rule of classifications.restore_stage_rules) {
    const semanticActor = actor(actors, rule.semantic_role_code)
    const eventAt = new Date(ms(fixture.timeline.restore_started_at) + rule.ordinal * 20_000).toISOString()
    const stageRetentionAttestation = rule.control_revalidation_required ? makeRetentionHeadAttestation(`retention.head.attestation.synthetic.stage.${rule.ordinal}`, new Date(ms(eventAt) - 2000).toISOString(), new Date(ms(eventAt) - 1000).toISOString()) : null
    if (stageRetentionAttestation) retentionHeadAttestations.push(stageRetentionAttestation)
    const controlRevalidation = rule.control_revalidation_required ? {
      resolver_request_record_digest_sha256: crypto.createHash('sha256').update(`resolver-request-${rule.ordinal}`).digest('hex'),
      resolver_response_record_digest_sha256: crypto.createHash('sha256').update(`resolver-response-${rule.ordinal}`).digest('hex'),
      before: clone(boundary), after: { ...clone(boundary), observed_at: new Date(ms(eventAt) - 2000).toISOString(), known_at: new Date(ms(eventAt) - 1000).toISOString() }, retention_control_record_digest_sha256: retentionControl.record_digest_sha256, retention_chain_sequence: retentionControl.chain.sequence, retention_head_attestation_record_digest_sha256: stageRetentionAttestation.record_digest_sha256, retention_head_receipt_record_digest_sha256: retentionReceipt.record_digest_sha256, source_stable: true,
    } : null
    const record = seal({
      format: 'jedi-atlas-restore-lifecycle-record',
      format_version: '1.0.0',
      record_code: `restore.lifecycle.synthetic.${String(rule.ordinal).padStart(2, '0')}`,
      operation_id: fixture.operation_id,
      operation_nonce: fixture.operation_nonce,
      chain: { namespace_code: 'd950.restore.lifecycle.v1', sequence: rule.ordinal, previous_record_digest_sha256: previous },
      restore_plan_record_digest_sha256: plan.record_digest_sha256,
      authorization_record_digest_sha256: authorization.record_digest_sha256,
      stage_code: rule.stage_code,
      outcome_code: rule.outcome_code,
      error_code: rule.error_code,
      retryability_code: rule.retryability_code,
      bytes_accessible: rule.bytes_accessible,
      atomic_promotion_observed: rule.atomic_promotion_observed,
      source_checkpoint_record_digest_sha256: fixture.source_checkpoint.checkpoint_record_digest_sha256,
      backup_manifest_record_digest_sha256: manifest.record_digest_sha256,
      control_snapshot: clone(boundary),
      control_revalidation: controlRevalidation,
      restored_inventory_digest_sha256: rule.ordinal >= 6 ? manifest.source_inventory_digest_sha256 : null,
      semantic_actor: semanticActor,
      persistence_actor: actor(actors, 'persistence_broker'),
      event_at: eventAt,
      persisted_at: new Date(ms(eventAt) + 500).toISOString(),
      technical_claims: technicalClaims(),
      record_digest_sha256: ZERO,
    })
    lifecycle.push(record)
    previous = record.record_digest_sha256
  }

  const drill = seal({
    format: 'jedi-atlas-restore-drill-record',
    format_version: '1.0.0',
    record_code: 'restore.drill.synthetic.001',
    drill_code: 'drill.synthetic.001',
    chain: { namespace_code: 'd950.restore.drills.v1', sequence: 1, previous_record_digest_sha256: null },
    backup_set_code: fixture.backup_set_code,
    backup_manifest_record_digest_sha256: manifest.record_digest_sha256,
    restore_plan_record_digest_sha256: plan.record_digest_sha256,
    target_environment_identity_sha256: targetIdentity,
    expected_source_checkpoint: clone(fixture.source_checkpoint),
    observed_source_checkpoint_record_digest_sha256: fixture.source_checkpoint.checkpoint_record_digest_sha256,
    observed_source_state_head_digest_sha256: fixture.source_checkpoint.source_state_head_digest_sha256,
    observed_correspondence_record_digest_sha256: fixture.source_checkpoint.correspondence_record_digest_sha256,
    expected_backup_chain_leaf_record_digest_sha256: manifest.record_digest_sha256,
    expected_backup_chain_leaf_sequence: manifest.backup_chain_sequence,
    observed_backup_chain_leaf_record_digest_sha256: manifest.record_digest_sha256,
    observed_backup_chain_leaf_sequence: manifest.backup_chain_sequence,
    expected_inventory_digest_sha256: manifest.source_inventory_digest_sha256,
    restored_inventory_digest_sha256: manifest.source_inventory_digest_sha256,
    checkpoint_age_basis_code: 'started_at_minus_checkpoint_captured_at_floor_seconds',
    scheduled_for: fixture.timeline.drill_scheduled_for,
    started_at: fixture.timeline.drill_started_at,
    completed_at: fixture.timeline.drill_completed_at,
    checkpoint_age_seconds: 86400,
    checkpoint_age_limit_seconds: 86400,
    backup_chain_state_code: 'current_leaf',
    source_head_comparison_code: 'exact_checkpoint_match',
    restored_state_comparison_code: 'exact_match',
    outcome_code: 'passed',
    escalation_code: 'none',
    scheduler: actor(actors, 'drill_scheduler'),
    independent_verifier: actor(actors, 'restored_state_verifier'),
    persistence_broker: actor(actors, 'persistence_broker'),
    technical_claims: technicalClaims(),
    record_digest_sha256: ZERO,
  })

  const request = seal({
    format: 'jedi-atlas-d950-ipc-message', format_version: '1.0.0', message_kind_code: 'request',
    route_code: 'route.restore.execute', request_code: 'request.restore.001', operation_id: fixture.operation_id,
    operation_nonce: fixture.operation_nonce, request_sequence: 1, sender: actor(actors, 'trusted_launcher'),
    recipient: actor(actors, 'restore_executor'), payload_format: plan.format,
    payload_record_digest_sha256: plan.record_digest_sha256, response_to_request_digest_sha256: null,
    outcome_code: 'submitted', error_code: 'none', retryability_code: 'not_retryable',
    sent_at: '2030-01-01T00:04:01.000Z', expires_at: fixture.timeline.restore_expires_at, record_digest_sha256: ZERO,
  })
  const response = seal({
    format: 'jedi-atlas-d950-ipc-message', format_version: '1.0.0', message_kind_code: 'response',
    route_code: 'route.restore.execute', request_code: 'request.restore.001', operation_id: fixture.operation_id,
    operation_nonce: fixture.operation_nonce, request_sequence: 1, sender: actor(actors, 'restore_executor'),
    recipient: actor(actors, 'trusted_launcher'), payload_format: lifecycle.at(-1).format,
    payload_record_digest_sha256: lifecycle.at(-1).record_digest_sha256, response_to_request_digest_sha256: request.record_digest_sha256,
    outcome_code: 'accepted', error_code: 'none', retryability_code: 'not_retryable',
    sent_at: '2030-01-01T00:10:01.000Z', expires_at: '2030-01-01T00:10:06.000Z', record_digest_sha256: ZERO,
  })

  const journalTargets = [manifest, ...receipts, deletionAware, retentionControl, ...retentionHeadAttestations, authorization, plan, ...lifecycle, drill]
  const journalReceipts = []
  let journalPrevious = null
  for (const [index, target] of journalTargets.entries()) {
    const journalSemanticActor = target.producer ?? target.semantic_verifier ?? target.requester ?? target.executor ?? target.scheduler ?? target.semantic_actor ?? target.observed_by
    const journalSemanticTime = target.created_at ?? target.completed_at ?? target.evaluated_at ?? target.persisted_at ?? target.planned_at ?? target.event_at ?? target.known_at
    if (!journalSemanticActor || !journalSemanticTime) fail('JOURNAL_TARGET_METADATA_MISSING', target.record_code)
    const receipt = seal({
      format: 'jedi-atlas-d950-journal-append-receipt', format_version: '1.0.0',
      record_code: `d950.journal.receipt.${String(index + 1).padStart(3, '0')}`,
      journal_namespace_code: 'd950.global.journal.v1', receipt_sequence: index + 1,
      previous_receipt_record_digest_sha256: journalPrevious, target_format: target.format,
      target_record_code: target.record_code, target_record_digest_sha256: target.record_digest_sha256,
      operation_id: target.operation_id ?? fixture.operation_id, operation_nonce: target.operation_nonce ?? fixture.operation_nonce,
      semantic_actor: clone(journalSemanticActor),
      persistence_actor: actor(actors, 'persistence_broker'),
      semantic_recorded_at: journalSemanticTime,
      persisted_at: new Date(ms('2030-01-02T00:10:00.000Z') + index * 1000).toISOString(),
      durability_state_code: 'record_and_receipt_flushed_in_protected_d950_ledger', record_digest_sha256: ZERO,
    })
    journalReceipts.push(receipt)
    journalPrevious = receipt.record_digest_sha256
  }

  return { actors, profile, manifest, receipts, deletionAware, deletionAssessments: [deletionAware], retentionControl, retentionHistory, retentionReceipt, retentionReceipts: [retentionReceipt], retentionHeadAttestation, retentionHeadAttestations, targetEnvironment, targetIdentity, authorization, plan, lifecycle, drill, request, response, approvalRequests, approvalResponses, journalTargets, journalReceipts }
}

const d90Common = readJson(path.join(here, 'd9-0/common-v1.schema.json'))
const d930Common = readJson(path.join(here, 'd9-3-0/common-v1.schema.json'))
const d940Common = readJson(path.join(here, 'd9-4-0/common-v1.schema.json'))
const schemas = schemaFiles.map((file) => readJson(path.join(root, file)))
const ajv = new Ajv2020({ allErrors: true, strict: false })
ajv.addSchema(d90Common)
ajv.addSchema(d930Common)
ajv.addSchema(d940Common)
for (const schema of schemas) ajv.addSchema(schema)

function validateByFile(file, value) {
  const schema = schemas.find((candidate) => candidate.$id.endsWith(`/${file}`))
  const validate = ajv.getSchema(schema.$id)
  if (!validate(value)) fail('SCHEMA_REJECTED', `${file}: ${ajv.errorsText(validate.errors)}`)
  assertSafeStrings(value)
  if ('record_digest_sha256' in value) assert.equal(value.record_digest_sha256, canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' }), `${file} self digest`)
}

function assertActor(value, semanticRole) {
  const rule = classifications.role_assignment_rules.find((candidate) => candidate.semantic_role_code === semanticRole)
  if (!rule || value.semantic_role_code !== semanticRole || value.actor_kind_code !== rule.actor_kind_code || value.runtime_role_code !== rule.runtime_role_code) fail('ACTOR_UNAUTHORIZED', semanticRole)
  const expected = actorMap(fixture).get(semanticRole)
  if (!expected || !same(value, expected)) fail('ACTOR_UNAUTHORIZED', `${semanticRole}: not reachable from frozen identity generation and roster`)
  if (value.actor_kind_code === 'human' && (value.ipc_endpoint_code !== null || value.executable_build_sha256 !== null)) fail('ACTOR_UNAUTHORIZED', `${semanticRole}: human service claims`)
  if (value.actor_kind_code === 'service' && (!value.ipc_endpoint_code || !value.executable_build_sha256)) fail('ACTOR_UNAUTHORIZED', `${semanticRole}: missing service identity`)
}

function assertTechnicalClaims(value) {
  const claims = value.technical_claims
  if (!claims || Object.values(claims).some((item) => item !== false)) fail('AUTHORITY_OVERCLAIM')
}

function assertProfile(records) {
  validateByFile('operational-profile-v1.schema.json', records.profile)
  assert.deepEqual(records.profile.allowed_operation_codes, classifications.operation_mode_rules.map((rule) => rule.operation_code))
  assert.deepEqual(records.profile.role_bindings.map((item) => item.semantic_role_code), classifications.role_assignment_rules.map((rule) => rule.semantic_role_code))
  for (const item of records.profile.role_bindings) assertActor(item, item.semantic_role_code)
  assert.deepEqual(records.profile.authority_context, { ...authorityContext, binding_generation: 1, authority_roster_adoption_record_digest_sha256: frozenD940Fixture.authority_roster_adoption.record_digest_sha256, activation_state_code: 'design_only_unactivated' })
  if (!same(records.profile.ipc_routes.map(({ route_code, sender_role_code, recipient_role_code }) => ({ route_code, sender_role_code, recipient_role_code })), classifications.ipc_route_rules)) fail('IPC_ROUTE_MATRIX_INVALID')
  if (Object.values(records.profile.authority_boundary).some((item) => item !== false)) fail('AUTHORITY_OVERCLAIM')
}

function assertManifest(records, predecessors = []) {
  const manifest = records.manifest
  validateByFile('backup-manifest-v1.schema.json', manifest)
  assertActor(manifest.producer, 'backup_producer')
  assertActor(manifest.persistence_broker, 'persistence_broker')
  assert.notEqual(manifest.producer.binding_code, manifest.persistence_broker.binding_code)
  if (manifest.source_inventory_digest_sha256 !== canonicalSha256({ source_checkpoint: manifest.source_checkpoint, source_inventory: manifest.source_inventory, source_copy_coverage: manifest.source_copy_coverage })) fail('INVENTORY_INCOMPLETE')
  assert.deepEqual(manifest.source_inventory.map((item) => item.ordinal), manifest.source_inventory.map((_, index) => index + 1))
  assert.equal(new Set(manifest.source_inventory.map((item) => item.stable_identity_code)).size, manifest.source_inventory.length)
  if (new Set(manifest.backup_copies.map((item) => item.copy_code)).size !== manifest.backup_copies.length || new Set(manifest.backup_copies.map((item) => item.copy_identity_sha256)).size !== manifest.backup_copies.length) fail('COPY_IDENTITY_COLLISION')
  const byCopy = new Map(manifest.backup_copies.map((item) => [item.copy_code, item]))
  if (manifest.source_copy_coverage.length !== manifest.source_inventory.length) fail('SOURCE_COPY_COVERAGE_INCOMPLETE')
  for (const source of manifest.source_inventory) {
    const matches = manifest.source_copy_coverage.filter((item) => item.source_stable_identity_code === source.stable_identity_code)
    if (matches.length !== 1 || matches[0].copy_codes.length < 1) fail('SOURCE_COPY_COVERAGE_INCOMPLETE')
    for (const code of matches[0].copy_codes) {
      const copy = byCopy.get(code)
      if (!copy || copy.artifact.byte_layer_code !== source.byte_layer_code || copy.artifact.sha256 !== source.content_sha256 || copy.artifact.byte_length !== source.byte_length) fail('SOURCE_COPY_COVERAGE_CONFLICT')
    }
  }
  assert.equal(manifest.backup_copy_inventory_digest_sha256, canonicalSha256([...manifest.backup_copies].sort((a, b) => a.copy_code.localeCompare(b.copy_code))))
  for (const copy of manifest.backup_copies) {
    assert.equal(copy.copy_identity_sha256, canonicalSha256({ copy_code: copy.copy_code, copy_class_code: copy.copy_class_code, backend_code: copy.backend_code, backend_generation: copy.backend_generation, backend_reference: copy.backend_reference, artifact: copy.artifact }))
  }
  if (manifest.backup_chain_sequence === 1) {
    if (manifest.previous_backup_manifest_record_digest_sha256 !== null) fail('CHAIN_PREDECESSOR_INVALID')
  } else {
    const previous = predecessors.find((candidate) => candidate.record_digest_sha256 === manifest.previous_backup_manifest_record_digest_sha256)
    if (!previous) fail('PREDECESSOR_MISSING')
    if (previous.backup_chain_sequence + 1 !== manifest.backup_chain_sequence) fail('CHAIN_GAP')
  }
  if (ms(manifest.created_at) > ms(manifest.persisted_at)) fail('CHRONOLOGY_INVALID')
  assertTechnicalClaims(manifest)
}

function receiptScope(receipt) {
  return receipt.scope
}

function assertReceiptDurability(receipt) {
  if (!receipt.durability || !receipt.durability.no_replace_enforced || !receipt.durability.object_data_synchronized || !receipt.durability.parent_namespace_synchronized || !receipt.durability.final_reopen_rehash_passed) fail('DURABILITY_INCOMPLETE')
}

function assertReceipts(records) {
  const expectedProfiles = new Map(classifications.backup_receipt_rules.map((rule) => [rule.receipt_kind_code, rule.scope_profile_code]))
  assert.deepEqual(records.receipts.map((item) => item.receipt_kind_code), fixture.expected.backup_receipt_kinds)
  for (const receipt of records.receipts) {
    validateByFile('backup-durability-receipt-v1.schema.json', receipt)
    assertReceiptDurability(receipt)
    assert.equal(receipt.scope_profile_code, expectedProfiles.get(receipt.receipt_kind_code))
    const digestProfile = digestProfiles.payload_profiles.find((item) => item.profile_code === receipt.scope_profile_code)
    if (!digestProfile || !same(digestProfile.input_fields, Object.keys(receipt.scope))) fail('RECEIPT_SCOPE_PROFILE_MISMATCH')
    assert.equal(receipt.scope_sha256, canonicalSha256(receiptScope(receipt)))
    assert.equal(receipt.backup_profile_record_digest_sha256, records.profile.record_digest_sha256)
    if (receipt.scope.operation_id !== receipt.operation_id || receipt.scope.operation_nonce !== receipt.operation_nonce) fail('RECEIPT_SCOPE_INVALID')
    if (receipt.receipt_kind_code === 'source_copy') {
      assert.equal(receipt.scope.copy_code, receipt.copy_identity.copy_code)
      assert.deepEqual(receipt.scope.artifact, receipt.copy_identity.artifact)
    }
    if (receipt.receipt_kind_code === 'artifact_copy') {
      const ref = receipt.scope.primary_receipt
      assert.equal(ref.record_code, frozenD930Fixture.primary_receipt.record_code)
      assert.equal(ref.receipt_raw_sha256, sha256Bytes(Buffer.from(canonicalize(frozenD930Fixture.primary_receipt))))
      assert.equal(receipt.scope.copy_code, receipt.copy_identity.copy_code)
      assert.deepEqual(receipt.scope.artifact, receipt.copy_identity.artifact)
      if (!same(receipt.scope.bundle, frozenD930Fixture.primary_receipt.semantic.bundle) || !same(receipt.scope.artifact, { artifact_code: receipt.scope.artifact.artifact_code, ...frozenD930Fixture.primary_receipt.semantic.artifact }) || receipt.scope.operation_id !== frozenD930Fixture.primary_receipt.semantic.operation_id || receipt.scope.operation_nonce !== frozenD930Fixture.primary_receipt.semantic.operation_nonce) fail('D930_PRIMARY_RECEIPT_MISMATCH')
    }
    if (receipt.receipt_kind_code === 'prior_database') assert.equal(receipt.scope.prior_logical_state.state_seal_record_digest_sha256, records.manifest.source_checkpoint.logical_state_seal_record_digest_sha256)
    if (receipt.receipt_kind_code === 'final_consistent_set') {
      assert.equal(receipt.scope.resulting_logical_state.state_seal_record_digest_sha256, records.manifest.source_checkpoint.logical_state_seal_record_digest_sha256)
      assert.equal(receipt.scope.receipt_head.receipt_record_digest_sha256, records.manifest.source_checkpoint.journal_tip_receipt_digest_sha256)
      assert.equal(receipt.scope.inventory_digest_sha256, records.manifest.source_inventory_digest_sha256)
    }
    if (receipt.backup_manifest_record_digest_sha256 !== records.manifest.record_digest_sha256) fail('MANIFEST_SUBSTITUTED')
    assert.equal(receipt.source_checkpoint_record_digest_sha256, records.manifest.source_checkpoint.checkpoint_record_digest_sha256)
    if (receipt.verification.recomputed_sha256 !== receipt.copy_identity.artifact.sha256 || receipt.verification.recomputed_byte_length !== receipt.copy_identity.artifact.byte_length) fail('CORRUPT_BYTES')
    assertActor(receipt.producer, 'backup_producer')
    assertActor(receipt.independent_verifier, 'backup_verifier')
    assertActor(receipt.persistence_broker, 'persistence_broker')
    if (new Set([receipt.producer.binding_code, receipt.independent_verifier.binding_code, receipt.persistence_broker.binding_code]).size !== 3) fail('SEPARATION_OF_DUTY')
    if (ms(receipt.completed_at) > ms(receipt.persisted_at)) fail('CHRONOLOGY_INVALID')
    assertTechnicalClaims(receipt)
    if (receipt.receipt_kind_code !== 'source_copy') {
      const reference = {
      receipt_kind_code: receipt.receipt_kind_code,
      receipt_contract_format: receipt.format,
      receipt_contract_version: receipt.format_version,
      receipt_raw_sha256: sha256Bytes(Buffer.from(canonicalize(receipt))),
      scope_profile_code: receipt.scope_profile_code,
      scope_sha256: receipt.scope_sha256,
      backup_profile_record_digest_sha256: receipt.backup_profile_record_digest_sha256,
      produced_by_binding_code: receipt.producer.binding_code,
      completed_at: receipt.completed_at,
      persisted_at: receipt.persisted_at,
    }
      const defName = receipt.receipt_kind_code === 'artifact_copy' ? 'artifactBackupReceiptReference' : receipt.receipt_kind_code === 'prior_database' ? 'priorDatabaseBackupReceiptReference' : 'finalBackupReceiptReference'
      const validateReference = ajv.compile({ $ref: `${d930Common.$id}#/$defs/${defName}` })
      if (!validateReference(reference)) fail('D930_REFERENCE_INVALID', ajv.errorsText(validateReference.errors))
    }
  }
  const copyReceipts = records.receipts.filter((item) => ['source_copy', 'artifact_copy'].includes(item.receipt_kind_code))
  if (!same(copyReceipts.map((item) => item.copy_identity.copy_code).sort(), records.manifest.backup_copies.map((item) => item.copy_code).sort())) fail('UNVERIFIED_REQUIRED_COPY')
  const prior = records.receipts.filter((item) => item.receipt_kind_code === 'prior_database')
  const final = records.receipts.filter((item) => item.receipt_kind_code === 'final_consistent_set')
  if (prior.length !== 1 || final.length !== 1 || !same(final[0].scope.constituent_receipt_record_digests, [...copyReceipts, ...prior].map((item) => item.record_digest_sha256))) fail('FINAL_RECEIPT_INCOMPLETE')
}

function assertDeletionAware(records) {
  const value = records.deletionAware
  validateByFile('deletion-aware-reconstruction-v1.schema.json', value)
  const order = classifications.copy_class_rules.canonical_order
  assert.deepEqual(value.copy_class_inventory.map((item) => item.copy_class_code), order)
  assert.equal(value.copy_class_inventory_digest_sha256, canonicalSha256(value.copy_class_inventory))
  if (!value.bounded_copy_classes_complete && value.restore_disposition_code === 'eligible_with_controls') fail('COPY_INVENTORY_INCOMPLETE')
  for (const item of value.copy_class_inventory) {
    const stateRule = classifications.copy_class_rules.state_count_matrix.find((candidate) => candidate.state_code === item.state_code)
    if (!stateRule || (stateRule.bounded_count_exact !== undefined && item.bounded_count !== stateRule.bounded_count_exact) || (stateRule.bounded_count_min !== undefined && (item.bounded_count === null || item.bounded_count < stateRule.bounded_count_min))) fail('COPY_STATE_COUNT_INVALID')
  }
  for (const evidence of value.control_evidence) {
    if (evidence.subject_identity_sha256 !== value.subject_identity_sha256 || evidence.current_leaf !== true) fail('CONTROL_EVIDENCE_SUBJECT_MISMATCH')
  }
  for (const directive of value.control_directives) {
    const basis = value.control_evidence.find((item) => item.evidence_type_code === 'custody_control' && item.record_digest_sha256 === directive.basis_control_record_digest_sha256)
    const coordination = value.control_evidence.find((item) => item.evidence_type_code === 'backup_coordination' && item.record_digest_sha256 === directive.d940_coordination_record_digest_sha256)
    if (!basis || !coordination || coordination.basis_record_digest_sha256 !== basis.record_digest_sha256 || coordination.directive_code !== directive.directive_code) fail('CONTROL_EVIDENCE_MISSING')
  }
  for (const evidence of value.control_evidence.filter((item) => item.evidence_type_code === 'custody_control' && item.applicability_code === 'applies_currently')) {
    const mapping = classifications.control_application_rules.current_blocking_evidence_mapping.find((item) => item.source_record_kind_code === evidence.source_record_kind_code)
    const released = classifications.control_application_rules.released_evidence_requires_no_directive.includes(evidence.source_record_kind_code)
    const matching = value.control_directives.filter((item) => item.basis_control_record_digest_sha256 === evidence.record_digest_sha256)
    if (mapping) {
      if (matching.length !== 1 || matching[0].directive_code !== mapping.required_directive_code || matching[0].disposition_code !== mapping.required_disposition_code) fail('CONTROL_EVIDENCE_UNMAPPED')
    } else if (!released) fail('CONTROL_EVIDENCE_UNMAPPED')
    else if (matching.length !== 0) fail('CONTROL_EVIDENCE_CONTRADICTORY')
  }
  if (value.copy_class_inventory.some((item) => ['unknown', 'unverifiable'].includes(item.state_code)) && value.restore_disposition_code !== 'reconciliation_required') fail('COPY_INVENTORY_UNVERIFIABLE')
  if (value.control_state_code !== 'complete_current_consistent' && value.restore_disposition_code !== 'reconciliation_required') fail('CONTROL_STATE_INVALID')
  const directiveCodes = new Set(value.control_directives.map((item) => item.directive_code))
  if (directiveCodes.has('do_not_restore') && value.restore_disposition_code !== 'withheld_do_not_restore') fail('DO_NOT_RESTORE')
  if (directiveCodes.has('apply_tombstone_before_restore') && !['withheld_tombstoned', 'withheld_do_not_restore'].includes(value.restore_disposition_code)) fail('TOMBSTONED_CONTENT')
  if (value.complete_erasure_claimed) fail('COMPLETE_ERASURE_CLAIM_FORBIDDEN')
  if (value.bytes_accessible) fail('CONTROL_EXPOSURE_FORBIDDEN')
  assertActor(value.semantic_verifier, 'control_state_verifier')
  assertActor(value.persistence_broker, 'persistence_broker')
  assert.notEqual(value.semantic_verifier.binding_code, value.persistence_broker.binding_code)
  if (ms(value.evaluated_at) > ms(value.persisted_at)) fail('CHRONOLOGY_INVALID')
  assertTechnicalClaims(value)
}

function assertRetentionRecord(value, manifest) {
  validateByFile('retention-control-record-v1.schema.json', value)
  if (value.backup_set_code !== manifest.backup_set_code || value.backup_manifest_record_digest_sha256 !== manifest.record_digest_sha256) fail('RETENTION_CHAIN_SUBJECT_MISMATCH')
  assert.equal(value.deletion_authority_present, false)
  const matrix = classifications.retention_rules.decision_state_matrix.find((item) => item.decision_code === value.decision_code)
  if (!matrix || !matrix.allowed_reason_codes.includes(value.reason_code) || matrix.hold_state_code !== value.hold_state_code || matrix.deletion_authority_present !== value.deletion_authority_present) fail('RETENTION_STATE_INVALID')
  assertActor(value.semantic_actor, 'legal_records_authority')
  assertActor(value.persistence_actor, 'persistence_broker')
  if (!(ms(value.effective_at) <= ms(value.recorded_at) && ms(value.recorded_at) <= ms(value.persisted_at))) fail('RETENTION_CHRONOLOGY_INVALID')
  assertTechnicalClaims(value)
}

function assertRetention(records) {
  assertRetentionRecord(records.retentionControl, records.manifest)
  assert.equal(records.retentionControl.chain.sequence, 1)
  assert.equal(records.retentionControl.chain.previous_record_digest_sha256, null)
}

function successorRetention(previous, code) {
  const value = clone(previous)
  value.record_code = code
  value.chain = { namespace_code: previous.chain.namespace_code, sequence: previous.chain.sequence + 1, previous_record_digest_sha256: previous.record_digest_sha256 }
  value.decision_code = 'hold'; value.retention_class_code = 'legal_hold'; value.hold_state_code = 'hold_active'; value.reason_code = 'legal_hold_asserted'
  value.effective_at = '2030-01-01T00:03:04.000Z'; value.recorded_at = '2030-01-01T00:03:05.000Z'; value.persisted_at = '2030-01-01T00:03:06.000Z'
  return seal(value)
}

function assertRetentionGraph(records, manifest = null) {
  const ordered = [...records].sort((a, b) => a.chain.sequence - b.chain.sequence)
  const successors = new Map()
  const namespace = ordered[0]?.chain.namespace_code
  let previousPersisted = -Infinity
  let previousRecorded = -Infinity
  for (const [index, record] of ordered.entries()) {
    if (manifest) assertRetentionRecord(record, manifest)
    if (record.chain.namespace_code !== namespace) fail('RETENTION_CHAIN_SUBJECT_MISMATCH')
    if (record.chain.sequence !== index + 1) fail('RETENTION_CHAIN_GAP')
    if (ms(record.recorded_at) <= previousRecorded || ms(record.persisted_at) <= previousPersisted) fail('RETENTION_CHRONOLOGY_INVALID')
    previousRecorded = ms(record.recorded_at); previousPersisted = ms(record.persisted_at)
    if (index === 0) { if (record.chain.previous_record_digest_sha256 !== null) fail('RETENTION_CHAIN_GAP'); continue }
    const predecessor = ordered[index - 1]
    if (record.chain.previous_record_digest_sha256 !== predecessor.record_digest_sha256) fail('RETENTION_CHAIN_GAP')
    if (successors.has(predecessor.record_digest_sha256)) fail('RETENTION_CHAIN_FORK')
    successors.set(predecessor.record_digest_sha256, record.record_digest_sha256)
  }
  return ordered.at(-1)
}

function assertRetentionHead(records, value = records.retentionHeadAttestation) {
  validateByFile('retention-head-attestation-v1.schema.json', value)
  const expectedOperationId = records.plan?.operation_id ?? fixture.operation_id
  const expectedOperationNonce = records.plan?.operation_nonce ?? fixture.operation_nonce
  if (value.operation_id !== expectedOperationId || value.operation_nonce !== expectedOperationNonce) fail('RETENTION_HEAD_SCOPE_MISMATCH')
  if (value.backup_set_code !== records.manifest.backup_set_code || value.backup_manifest_record_digest_sha256 !== records.manifest.record_digest_sha256) fail('RETENTION_HEAD_SCOPE_MISMATCH')
  const leaf = assertRetentionGraph(records.retentionHistory, records.manifest)
  const receipt = records.retentionReceipts.find((item) => item.record_digest_sha256 === value.head_receipt_record_digest_sha256)
  if (!receipt || receipt.journal_namespace_code !== 'd950.retention.journal.v1' || receipt.receipt_sequence !== value.head_sequence || receipt.target_record_digest_sha256 !== value.head_record_digest_sha256) fail('RETENTION_HEAD_UNAUTHENTICATED')
  validateByFile('journal-append-receipt-v1.schema.json', receipt)
  assertActor(receipt.semantic_actor, 'legal_records_authority')
  assertActor(receipt.persistence_actor, 'persistence_broker')
  if (value.namespace_code !== leaf.chain.namespace_code || value.head_sequence !== leaf.chain.sequence || value.head_record_digest_sha256 !== leaf.record_digest_sha256 || value.head_receipt_persisted_at !== receipt.persisted_at) fail('RETENTION_LEAF_STALE')
  assertActor(value.observed_by, 'persistence_broker')
  if (ms(receipt.persisted_at) > ms(value.observed_at) || ms(value.observed_at) > ms(value.known_at)) fail('RETENTION_CHRONOLOGY_INVALID')
  assertTechnicalClaims(value)
  return leaf
}

function assertNoErasureOverclaim(value) {
  if (value.complete_erasure_claimed === true || value.technical_claims?.complete_erasure_claimed === true) fail('COMPLETE_ERASURE_CLAIM_FORBIDDEN')
}

function authorizationScope(value) {
  return canonicalSha256({
    operation_id: value.operation_id,
    operation_nonce: value.operation_nonce,
    backup_set_code: value.backup_set_code,
    backup_manifest_record_digest_sha256: value.backup_manifest_record_digest_sha256,
    source_checkpoint_record_digest_sha256: value.source_checkpoint_record_digest_sha256,
    target_environment_identity_sha256: value.target_environment_identity_sha256,
  })
}

function assertAuthorization(records) {
  const value = records.authorization
  validateByFile('restore-authorization-v1.schema.json', value)
  assertActor(value.requester, 'restore_requester')
  assert.equal(value.authorization_scope_sha256, authorizationScope(value))
  const required = classifications.restore_approval_rules.exact_required_semantic_roles
  assert.deepEqual(value.approvals.map((item) => item.actor.semantic_role_code), required)
  const principals = value.approvals.map((item) => item.actor.principal_code)
  if (new Set(principals).size !== 3 || principals.includes(value.requester.principal_code)) fail('APPROVAL_SEPARATION_INVALID')
  for (const approval of value.approvals) {
    assert.equal(approval.scope_sha256, value.authorization_scope_sha256)
    assertActor(approval.actor, approval.actor.semantic_role_code)
    assert.equal(approval.record_digest_sha256, canonicalSha256(approval, { excludedTopLevelField: 'record_digest_sha256' }))
    const decisionPayload = { approval_code: approval.approval_code, decision_code: approval.decision_code, scope_sha256: approval.scope_sha256, actor: approval.actor, decided_at: approval.decided_at, valid_until: approval.valid_until }
    assert.equal(approval.decision_payload_sha256, canonicalSha256(decisionPayload))
    const request = records.approvalRequests.find((item) => item.record_digest_sha256 === approval.submission_request_record_digest_sha256)
    const response = records.approvalResponses.find((item) => item.record_digest_sha256 === approval.broker_response_record_digest_sha256)
    if (!request || !response || request.payload_record_digest_sha256 !== approval.decision_payload_sha256 || response.response_to_request_digest_sha256 !== request.record_digest_sha256 || response.payload_record_digest_sha256 !== request.record_digest_sha256 || request.operation_id !== value.operation_id || response.operation_id !== value.operation_id || request.operation_nonce !== value.operation_nonce || response.operation_nonce !== value.operation_nonce) fail('APPROVAL_IPC_EVIDENCE_INVALID')
    if (!same(request.sender, approval.actor) || request.recipient.semantic_role_code !== 'persistence_broker' || response.sender.semantic_role_code !== 'persistence_broker' || !same(response.recipient, approval.actor)) fail('APPROVAL_IPC_EVIDENCE_INVALID')
    if (ms(approval.decided_at) < ms(value.valid_from) || ms(approval.decided_at) >= ms(value.valid_until) || ms(approval.valid_until) < ms(value.valid_until)) fail('APPROVAL_CHRONOLOGY_INVALID')
  }
  if (ms(value.valid_from) >= ms(value.valid_until) || ms(value.persisted_at) < ms(value.valid_from) || ms(value.persisted_at) >= ms(value.valid_until)) fail('AUTHORIZATION_CHRONOLOGY_INVALID')
  assertActor(value.persistence_broker, 'persistence_broker')
  assertTechnicalClaims(value)
}

function assertPlan(records) {
  const value = records.plan
  validateByFile('restore-plan-v1.schema.json', value)
  assert.equal(value.backup_manifest_record_digest_sha256, records.manifest.record_digest_sha256)
  if (!same(value.source_checkpoint, records.manifest.source_checkpoint)) fail('SOURCE_HEAD_MISMATCH')
  assert.deepEqual(value.backup_receipt_record_digests, records.receipts.map((item) => item.record_digest_sha256))
  assert.equal(value.authorization_record_digest_sha256, records.authorization.record_digest_sha256)
  assert.deepEqual(value.deletion_aware_reconstruction_record_digests, records.deletionAssessments.map((item) => item.record_digest_sha256))
  const sourceSubjects = [...new Set(records.manifest.source_inventory.map((item) => item.subject_identity_sha256))].sort()
  const assessedSubjects = records.deletionAssessments.map((item) => item.subject_identity_sha256).sort()
  if (!same(sourceSubjects, assessedSubjects) || new Set(assessedSubjects).size !== assessedSubjects.length) fail('SUBJECT_ASSESSMENT_INCOMPLETE')
  const currentRetention = assertRetentionHead(records)
  const expectedRetentionHead = {
    namespace_code: records.retentionHeadAttestation.namespace_code,
    head_sequence: records.retentionHeadAttestation.head_sequence,
    head_record_digest_sha256: records.retentionHeadAttestation.head_record_digest_sha256,
    head_receipt_record_digest_sha256: records.retentionHeadAttestation.head_receipt_record_digest_sha256,
    head_receipt_persisted_at: records.retentionHeadAttestation.head_receipt_persisted_at,
    attestation_record_digest_sha256: records.retentionHeadAttestation.record_digest_sha256,
    known_at: records.retentionHeadAttestation.known_at,
  }
  if (value.retention_control_record_digest_sha256 !== currentRetention.record_digest_sha256 || value.retention_control_chain_sequence !== currentRetention.chain.sequence || !same(value.retention_head, expectedRetentionHead)) fail('RETENTION_LEAF_STALE')
  if (ms(value.planned_at) < ms(value.retention_head.known_at) || ms(value.planned_at) - ms(value.retention_head.known_at) > records.profile.limits.response_age_ms_max) fail('RETENTION_HEAD_STALE')
  if (currentRetention.hold_state_code !== 'none_known' || currentRetention.decision_code === 'hold') fail('RESTORE_HELD')
  if (!same(value.pre_restore_control_snapshot, records.deletionAware.control_snapshot)) fail('CONTROL_SNAPSHOT_MISMATCH')
  if (records.deletionAware.restore_disposition_code !== 'eligible_with_controls') fail('RESTORE_WITHHELD')
  assert.deepEqual(value.ordered_stage_codes, classifications.restore_stage_rules.map((rule) => rule.stage_code))
  assert.equal(canonicalSha256(value.target_environment), records.targetIdentity)
  assertActor(value.executor, 'restore_executor')
  assertActor(value.control_state_verifier, 'control_state_verifier')
  assertActor(value.restored_state_verifier, 'restored_state_verifier')
  assertActor(value.persistence_broker, 'persistence_broker')
  if (value.executor.binding_code === value.restored_state_verifier.binding_code || value.executor.binding_code === value.persistence_broker.binding_code) fail('SEPARATION_OF_DUTY')
  if (value.control_state_verifier.process_instance_code === value.restored_state_verifier.process_instance_code) fail('VERIFIER_PROCESS_COLLISION')
  if (ms(value.planned_at) >= ms(value.expires_at)) fail('PLAN_EXPIRED')
  assertTechnicalClaims(value)
}

function assertLifecycle(records) {
  assert.equal(records.lifecycle.length, classifications.restore_stage_rules.length)
  let previous = null
  let previousPersisted = -Infinity
  let previousEvent = -Infinity
  for (const [index, value] of records.lifecycle.entries()) {
    validateByFile('restore-lifecycle-record-v1.schema.json', value)
    const rule = classifications.restore_stage_rules[index]
    if (value.stage_code !== rule.stage_code || value.outcome_code !== rule.outcome_code || value.error_code !== rule.error_code || value.retryability_code !== rule.retryability_code) fail('STAGE_SEMANTICS_INVALID')
    assert.equal(value.chain.sequence, index + 1)
    assert.equal(value.chain.previous_record_digest_sha256, previous)
    assert.equal(value.bytes_accessible, rule.bytes_accessible)
    assert.equal(value.atomic_promotion_observed, rule.atomic_promotion_observed)
    assert.equal(value.restore_plan_record_digest_sha256, records.plan.record_digest_sha256)
    assert.equal(value.authorization_record_digest_sha256, records.authorization.record_digest_sha256)
    assert.equal(value.source_checkpoint_record_digest_sha256, records.manifest.source_checkpoint.checkpoint_record_digest_sha256)
    assert.equal(value.backup_manifest_record_digest_sha256, records.manifest.record_digest_sha256)
    if (!same(value.control_snapshot, records.deletionAware.control_snapshot)) fail('CONTROL_HEAD_MOVED')
    if (rule.control_revalidation_required) {
      if (!value.control_revalidation) fail('CONTROL_REVALIDATION_MISSING')
      const { before, after } = value.control_revalidation
      if (before.d940_state_head_digest_sha256 !== after.d940_state_head_digest_sha256 || before.d940_journal_tip_receipt_digest_sha256 !== after.d940_journal_tip_receipt_digest_sha256 || before.d940_correspondence_record_digest_sha256 !== after.d940_correspondence_record_digest_sha256 || !value.control_revalidation.source_stable) fail('CONTROL_HEAD_MOVED')
      if (!same(before, records.plan.pre_restore_control_snapshot) || after.d940_state_head_digest_sha256 !== records.plan.pre_restore_control_snapshot.d940_state_head_digest_sha256 || after.d940_journal_tip_receipt_digest_sha256 !== records.plan.pre_restore_control_snapshot.d940_journal_tip_receipt_digest_sha256 || after.d940_correspondence_record_digest_sha256 !== records.plan.pre_restore_control_snapshot.d940_correspondence_record_digest_sha256) fail('CONTROL_HEAD_MOVED')
      const retentionAttestation = records.retentionHeadAttestations.find((item) => item.record_digest_sha256 === value.control_revalidation.retention_head_attestation_record_digest_sha256)
      if (!retentionAttestation) fail('RETENTION_HEAD_UNAUTHENTICATED')
      const retentionLeaf = assertRetentionHead(records, retentionAttestation)
      if (value.control_revalidation.retention_control_record_digest_sha256 !== retentionLeaf.record_digest_sha256 || value.control_revalidation.retention_chain_sequence !== retentionLeaf.chain.sequence || value.control_revalidation.retention_head_receipt_record_digest_sha256 !== retentionAttestation.head_receipt_record_digest_sha256) fail('RETENTION_LEAF_STALE')
      if (ms(value.event_at) < ms(retentionAttestation.known_at) || ms(value.event_at) - ms(retentionAttestation.known_at) > records.profile.limits.response_age_ms_max) fail('RETENTION_HEAD_STALE')
      if (ms(before.known_at) > ms(after.known_at) || ms(after.known_at) > ms(value.event_at)) fail('CONTROL_REVALIDATION_CHRONOLOGY_INVALID')
    } else if (value.control_revalidation !== null) fail('CONTROL_REVALIDATION_UNEXPECTED')
    if (rule.ordinal >= 6 && value.restored_inventory_digest_sha256 !== records.manifest.source_inventory_digest_sha256) fail('PARTIAL_RESTORE')
    if (ms(value.event_at) <= previousEvent || ms(value.event_at) > ms(value.persisted_at) || ms(value.persisted_at) <= previousPersisted || ms(value.event_at) < ms(records.authorization.valid_from) || ms(value.event_at) >= ms(records.authorization.valid_until) || ms(value.event_at) < ms(records.plan.planned_at) || ms(value.event_at) >= ms(records.plan.expires_at)) fail('LIFECYCLE_CHRONOLOGY_INVALID')
    previous = value.record_digest_sha256
    previousPersisted = ms(value.persisted_at)
    previousEvent = ms(value.event_at)
    assertActor(value.persistence_actor, 'persistence_broker')
    assertActor(value.semantic_actor, rule.semantic_role_code)
    assertTechnicalClaims(value)
  }
  assert.equal(records.lifecycle.at(-1).outcome_code, 'succeeded')
}

function assertDrill(records) {
  const value = records.drill
  validateByFile('restore-drill-record-v1.schema.json', value)
  assertActor(value.scheduler, 'drill_scheduler')
  assertActor(value.independent_verifier, 'restored_state_verifier')
  assertActor(value.persistence_broker, 'persistence_broker')
  if (ms(value.started_at) < ms(value.scheduled_for) || ms(value.completed_at) < ms(value.started_at)) fail('DRILL_CHRONOLOGY_INVALID')
  const computedAge = Math.floor((ms(value.started_at) - ms(value.expected_source_checkpoint.captured_at)) / 1000)
  if (value.checkpoint_age_basis_code !== classifications.drill_rules.checkpoint_age_basis_code || value.checkpoint_age_seconds !== computedAge) fail('DRILL_AGE_INVALID')
  const exactSource = value.observed_source_checkpoint_record_digest_sha256 === value.expected_source_checkpoint.checkpoint_record_digest_sha256 && value.observed_source_state_head_digest_sha256 === value.expected_source_checkpoint.source_state_head_digest_sha256 && value.observed_correspondence_record_digest_sha256 === value.expected_source_checkpoint.correspondence_record_digest_sha256
  const exactLeaf = value.observed_backup_chain_leaf_record_digest_sha256 === value.expected_backup_chain_leaf_record_digest_sha256
  const exactInventory = value.restored_inventory_digest_sha256 === value.expected_inventory_digest_sha256
  const expectedSourceComparison = exactSource ? 'exact_checkpoint_match' : 'mismatch'
  const expectedRestoredComparison = exactInventory ? 'exact_match' : 'mismatch'
  const expectedChainState = exactLeaf && value.observed_backup_chain_leaf_sequence === value.expected_backup_chain_leaf_sequence
    ? 'current_leaf'
    : !exactLeaf && value.observed_backup_chain_leaf_sequence > value.expected_backup_chain_leaf_sequence
      ? 'superseded'
      : null
  if (!expectedChainState) fail('DRILL_CHAIN_PROOF_INVALID')
  if (value.source_head_comparison_code !== expectedSourceComparison || value.restored_state_comparison_code !== expectedRestoredComparison || value.backup_chain_state_code !== expectedChainState) fail('DRILL_COMPARISON_INVALID')
  let expectedOutcome
  if (!exactSource || !exactInventory) expectedOutcome = { outcome_code: 'failed', escalation_code: 'security_review_required' }
  else if (value.checkpoint_age_seconds > value.checkpoint_age_limit_seconds || expectedChainState === 'superseded') expectedOutcome = { outcome_code: 'stale', escalation_code: 'new_backup_required' }
  else expectedOutcome = { outcome_code: 'passed', escalation_code: 'none' }
  if (value.outcome_code !== expectedOutcome.outcome_code || value.escalation_code !== expectedOutcome.escalation_code) fail('DRILL_CLASSIFICATION_INVALID')
  assertTechnicalClaims(value)
}

function assertDrillMatrixCoverage(records) {
  assertDrill(records)
  const superseded = clone(records); superseded.drill.observed_backup_chain_leaf_record_digest_sha256 = 'f'.repeat(64); superseded.drill.observed_backup_chain_leaf_sequence += 1; superseded.drill.backup_chain_state_code = 'superseded'; superseded.drill.outcome_code = 'stale'; superseded.drill.escalation_code = 'new_backup_required'; seal(superseded.drill); assertDrill(superseded)
  const sourceMismatch = clone(records); sourceMismatch.drill.observed_source_state_head_digest_sha256 = 'e'.repeat(64); sourceMismatch.drill.source_head_comparison_code = 'mismatch'; sourceMismatch.drill.outcome_code = 'failed'; sourceMismatch.drill.escalation_code = 'security_review_required'; seal(sourceMismatch.drill); assertDrill(sourceMismatch)
  const inventoryMismatch = clone(records); inventoryMismatch.drill.restored_inventory_digest_sha256 = 'd'.repeat(64); inventoryMismatch.drill.restored_state_comparison_code = 'mismatch'; inventoryMismatch.drill.outcome_code = 'failed'; inventoryMismatch.drill.escalation_code = 'security_review_required'; seal(inventoryMismatch.drill); assertDrill(inventoryMismatch)
  return 4
}

function assertDrillChain(drills) {
  let previous = null
  for (const [index, drill] of drills.entries()) {
    if (drill.chain.sequence !== index + 1 || drill.chain.previous_record_digest_sha256 !== previous) fail('DRILL_CHAIN_INVALID')
    previous = drill.record_digest_sha256
  }
}

function assertIpc(records) {
  const pairs = [[records.request, records.response], ...records.approvalRequests.map((request, index) => [request, records.approvalResponses[index]])]
  for (const [request, response] of pairs) {
    for (const value of [request, response]) validateByFile('ipc-message-v1.schema.json', value)
    assert.equal(request.response_to_request_digest_sha256, null)
    assert.equal(response.response_to_request_digest_sha256, request.record_digest_sha256)
    const route = classifications.ipc_route_rules.find((item) => item.route_code === request.route_code)
    if (!route || response.route_code !== request.route_code || response.request_code !== request.request_code || response.request_sequence !== request.request_sequence || route.sender_role_code !== request.sender.semantic_role_code || route.recipient_role_code !== request.recipient.semantic_role_code || response.sender.semantic_role_code !== route.recipient_role_code || response.recipient.semantic_role_code !== route.sender_role_code) fail('IPC_ROUTE_INVALID')
    assertActor(request.sender, route.sender_role_code); assertActor(request.recipient, route.recipient_role_code)
    assertActor(response.sender, route.recipient_role_code); assertActor(response.recipient, route.sender_role_code)
    if (request.message_kind_code !== 'request' || response.message_kind_code !== 'response' || request.outcome_code !== 'submitted' || request.error_code !== 'none' || request.retryability_code !== 'not_retryable' || response.outcome_code !== 'accepted' || response.error_code !== 'none' || response.retryability_code !== 'not_retryable' || request.operation_id !== response.operation_id || request.operation_nonce !== response.operation_nonce) fail('IPC_MESSAGE_SEMANTICS_INVALID')
    const approvalRoute = request.route_code.startsWith('route.restore.approve.')
    const expectedRequestFormat = approvalRoute ? 'jedi-atlas-restore-approval-decision' : 'jedi-atlas-restore-plan'
    const expectedResponseFormat = approvalRoute ? 'jedi-atlas-restore-approval-acceptance' : 'jedi-atlas-restore-lifecycle-record'
    if (request.payload_format !== expectedRequestFormat || response.payload_format !== expectedResponseFormat) fail('IPC_PAYLOAD_FORMAT_INVALID')
    if (ms(request.sent_at) >= ms(request.expires_at) || ms(response.sent_at) >= ms(response.expires_at)) fail('IPC_EXPIRED')
  }
}

function assertJournal(records) {
  assert.equal(records.journalTargets.length, records.journalReceipts.length)
  let previous = null
  let previousTime = -Infinity
  const targets = new Set()
  for (const [index, receipt] of records.journalReceipts.entries()) {
    validateByFile('journal-append-receipt-v1.schema.json', receipt)
    const target = records.journalTargets[index]
    assert.equal(receipt.receipt_sequence, index + 1)
    assert.equal(receipt.previous_receipt_record_digest_sha256, previous)
    assert.equal(receipt.target_format, target.format)
    assert.equal(receipt.target_record_code, target.record_code)
    assert.equal(receipt.target_record_digest_sha256, target.record_digest_sha256)
    if (targets.has(receipt.target_record_digest_sha256)) fail('JOURNAL_TARGET_REPLAY')
    targets.add(receipt.target_record_digest_sha256)
    if (ms(receipt.semantic_recorded_at) > ms(receipt.persisted_at) || ms(receipt.persisted_at) <= previousTime) fail('JOURNAL_CHRONOLOGY_INVALID')
    assertActor(receipt.persistence_actor, 'persistence_broker')
    previous = receipt.record_digest_sha256
    previousTime = ms(receipt.persisted_at)
  }
}

function assertValidRecords(records) {
  assertProfile(records)
  assertManifest(records)
  assertReceipts(records)
  assertDeletionAware(records)
  assertRetention(records)
  assertAuthorization(records)
  assertPlan(records)
  assertLifecycle(records)
  assertDrill(records)
  assertIpc(records)
  assertJournal(records)
}

function runMutation(caseCode, baseline) {
  const records = clone(baseline)
  switch (caseCode) {
    case 'wrong_source_head': {
      records.plan.source_checkpoint.source_state_head_digest_sha256 = 'f'.repeat(64)
      seal(records.plan)
      expectCode(() => assertPlan(records), 'SOURCE_HEAD_MISMATCH')
      return 'SOURCE_HEAD_MISMATCH'
    }
    case 'incomplete_inventory': {
      records.manifest.source_inventory.pop()
      seal(records.manifest)
      expectCode(() => assertManifest(records), 'INVENTORY_INCOMPLETE')
      return 'INVENTORY_INCOMPLETE'
    }
    case 'corrupt_bytes': {
      records.receipts[0].verification.recomputed_sha256 = 'f'.repeat(64)
      seal(records.receipts[0])
      expectCode(() => assertReceipts(records), 'CORRUPT_BYTES')
      return 'CORRUPT_BYTES'
    }
    case 'substituted_manifest': {
      records.receipts[0].backup_manifest_record_digest_sha256 = 'f'.repeat(64)
      records.receipts[0].scope_sha256 = canonicalSha256(receiptScope(records.receipts[0]))
      seal(records.receipts[0])
      expectCode(() => assertReceipts(records), 'MANIFEST_SUBSTITUTED')
      return 'MANIFEST_SUBSTITUTED'
    }
    case 'replay': {
      const changed = clone(records.manifest)
      changed.source_checkpoint.checkpoint_sequence += 1
      seal(changed)
      expectCode(() => assertNoReplace([records.manifest, changed]), 'REPLAY_CONFLICT')
      return 'REPLAY_CONFLICT'
    }
    case 'fork': {
      const successor = successorManifest(records.manifest, 2, 'backup.manifest.synthetic.002')
      const fork = successorManifest(records.manifest, 2, 'backup.manifest.synthetic.fork')
      expectCode(() => assertBackupGraph([records.manifest, successor, fork]), 'CHAIN_FORK')
      return 'CHAIN_FORK'
    }
    case 'rollback': {
      const successor = successorManifest(records.manifest, 1, 'backup.manifest.synthetic.rollback')
      expectCode(() => assertBackupGraph([records.manifest, successor]), 'ROLLBACK_DETECTED')
      return 'ROLLBACK_DETECTED'
    }
    case 'missing_predecessor': {
      const successor = successorManifest(records.manifest, 2, 'backup.manifest.synthetic.orphan')
      successor.previous_backup_manifest_record_digest_sha256 = 'f'.repeat(64)
      seal(successor)
      expectCode(() => assertBackupGraph([records.manifest, successor]), 'PREDECESSOR_MISSING')
      return 'PREDECESSOR_MISSING'
    }
    case 'stale_controls': {
      records.deletionAware.control_state_code = 'stale'
      seal(records.deletionAware)
      expectCode(() => assertDeletionAware(records), 'CONTROL_STATE_INVALID')
      return 'CONTROL_STATE_INVALID'
    }
    case 'tombstoned_content': {
      records.deletionAware.control_directives.push({
        directive_code: 'apply_tombstone_before_restore',
        d940_coordination_record_digest_sha256: 'f1'.repeat(32),
        basis_control_record_digest_sha256: 'f2'.repeat(32),
        disposition_code: 'restore_withheld',
      })
      records.deletionAware.control_evidence.push({ evidence_type_code: 'custody_control', source_format: 'jedi-atlas-custody-control-record', source_record_kind_code: 'tombstone_applied', record_code: 'd940.control.tombstone.synthetic.001', record_digest_sha256: 'f2'.repeat(32), journal_receipt_record_digest_sha256: 'f3'.repeat(32), subject_identity_sha256: fixture.subject_identity_sha256, basis_record_digest_sha256: null, directive_code: null, resolver_response_record_digest_sha256: 'f4'.repeat(32), current_leaf: true, applicability_code: 'applies_currently' })
      records.deletionAware.control_evidence.push({ evidence_type_code: 'backup_coordination', source_format: 'jedi-atlas-backup-coordination-record', source_record_kind_code: 'tombstone_directive', record_code: 'd940.coordination.tombstone.synthetic.001', record_digest_sha256: 'f1'.repeat(32), journal_receipt_record_digest_sha256: 'f5'.repeat(32), subject_identity_sha256: fixture.subject_identity_sha256, basis_record_digest_sha256: 'f2'.repeat(32), directive_code: 'apply_tombstone_before_restore', resolver_response_record_digest_sha256: 'f6'.repeat(32), current_leaf: true, applicability_code: 'applies_currently' })
      seal(records.deletionAware)
      expectCode(() => assertDeletionAware(records), 'TOMBSTONED_CONTENT')
      return 'TOMBSTONED_CONTENT'
    }
    case 'deletion_after_backup': {
      records.plan.pre_restore_control_snapshot.d940_state_head_digest_sha256 = 'f'.repeat(64)
      seal(records.plan)
      expectCode(() => assertPlan(records), 'CONTROL_SNAPSHOT_MISMATCH')
      return 'CONTROL_SNAPSHOT_MISMATCH'
    }
    case 'deletion_during_restore': {
      records.lifecycle[7].control_snapshot.d940_state_head_digest_sha256 = 'e'.repeat(64)
      seal(records.lifecycle[7])
      expectCode(() => assertLifecycle(records), 'CONTROL_HEAD_MOVED')
      return 'CONTROL_HEAD_MOVED'
    }
    case 'partial_restoration': {
      records.lifecycle.at(-1).restored_inventory_digest_sha256 = 'd'.repeat(64)
      seal(records.lifecycle.at(-1))
      expectCode(() => assertLifecycle(records), 'PARTIAL_RESTORE')
      return 'PARTIAL_RESTORE'
    }
    case 'response_loss': {
      const classification = classifyRestorePrefix(records.lifecycle.slice(0, -1), true)
      assert.equal(classification.error_code, 'response_loss_ambiguous')
      assert.equal(classification.automatic_action, false)
      return 'RESPONSE_LOSS_AMBIGUOUS'
    }
    case 'concurrent_restore': {
      const second = clone(records.plan)
      second.operation_id = 'operation.synthetic.restore.concurrent'
      second.operation_nonce = 'f'.repeat(64)
      seal(second)
      expectCode(() => assertExclusiveTargets([records.plan, second]), 'CONCURRENT_OPERATION')
      return 'CONCURRENT_OPERATION'
    }
    case 'wrong_actor': {
      records.plan.executor = clone(records.plan.persistence_broker)
      records.plan.executor.semantic_role_code = 'restore_executor'
      seal(records.plan)
      expectCode(() => assertPlan(records), 'ACTOR_UNAUTHORIZED')
      return 'ACTOR_UNAUTHORIZED'
    }
    case 'wrong_build': {
      records.plan.executor.executable_build_sha256 = 'f'.repeat(64)
      seal(records.plan)
      expectCode(() => assertBuildPins(records), 'BUILD_MISMATCH')
      return 'BUILD_MISMATCH'
    }
    case 'complete_erasure_overclaim': {
      records.deletionAware.complete_erasure_claimed = true
      records.deletionAware.technical_claims.complete_erasure_claimed = true
      seal(records.deletionAware)
      expectCode(() => validateByFile('deletion-aware-reconstruction-v1.schema.json', records.deletionAware), 'SCHEMA_REJECTED')
      return 'COMPLETE_ERASURE_CLAIM_FORBIDDEN'
    }
    case 'superseded_drill_chain': {
      records.drill.backup_chain_state_code = 'superseded'
      records.drill.observed_backup_chain_leaf_record_digest_sha256 = 'f'.repeat(64)
      records.drill.observed_backup_chain_leaf_sequence += 1
      seal(records.drill)
      expectCode(() => assertDrill(records), 'DRILL_CLASSIFICATION_INVALID')
      return 'DRILL_CLASSIFICATION_INVALID'
    }
    case 'unknown_copy_class': {
      records.deletionAware.copy_class_inventory.at(-1).state_code = 'unknown'
      records.deletionAware.copy_class_inventory_digest_sha256 = canonicalSha256(records.deletionAware.copy_class_inventory)
      seal(records.deletionAware)
      expectCode(() => assertDeletionAware(records), 'COPY_INVENTORY_UNVERIFIABLE')
      return 'COPY_INVENTORY_UNVERIFIABLE'
    }
    case 'missing_source_copy_coverage': {
      records.manifest.source_copy_coverage.pop(); records.manifest.source_inventory_digest_sha256 = canonicalSha256({ source_checkpoint: records.manifest.source_checkpoint, source_inventory: records.manifest.source_inventory, source_copy_coverage: records.manifest.source_copy_coverage }); seal(records.manifest)
      expectCode(() => assertManifest(records), 'SOURCE_COPY_COVERAGE_INCOMPLETE'); return 'SOURCE_COPY_COVERAGE_INCOMPLETE'
    }
    case 'conflicting_source_copy_coverage': {
      records.manifest.source_copy_coverage[1].copy_codes = [records.manifest.backup_copies[0].copy_code]; records.manifest.source_inventory_digest_sha256 = canonicalSha256({ source_checkpoint: records.manifest.source_checkpoint, source_inventory: records.manifest.source_inventory, source_copy_coverage: records.manifest.source_copy_coverage }); seal(records.manifest)
      expectCode(() => assertManifest(records), 'SOURCE_COPY_COVERAGE_CONFLICT'); return 'SOURCE_COPY_COVERAGE_CONFLICT'
    }
    case 'invalid_d930_receipt_scope': {
      const receipt = records.receipts.find((item) => item.receipt_kind_code === 'artifact_copy'); receipt.scope.operation_id = 'operation.synthetic.substituted'; receipt.scope_sha256 = canonicalSha256(receipt.scope); seal(receipt)
      expectCode(() => assertReceipts(records), 'RECEIPT_SCOPE_INVALID'); return 'RECEIPT_SCOPE_INVALID'
    }
    case 'fake_actor_context': {
      records.plan.executor.identity_bindings_record_digest_sha256 = 'f'.repeat(64); seal(records.plan)
      expectCode(() => assertPlan(records), 'ACTOR_UNAUTHORIZED'); return 'ACTOR_UNAUTHORIZED'
    }
    case 'wrong_subject_control_evidence': {
      records.deletionAware.control_evidence[0].subject_identity_sha256 = 'f'.repeat(64); seal(records.deletionAware)
      expectCode(() => assertDeletionAware(records), 'CONTROL_EVIDENCE_SUBJECT_MISMATCH'); return 'CONTROL_EVIDENCE_SUBJECT_MISMATCH'
    }
    case 'incomplete_copy_class_claim': {
      records.deletionAware.bounded_copy_classes_complete = false; seal(records.deletionAware)
      expectCode(() => assertDeletionAware(records), 'COPY_INVENTORY_INCOMPLETE'); return 'COPY_INVENTORY_INCOMPLETE'
    }
    case 'invalid_copy_state_count': {
      records.deletionAware.copy_class_inventory[0].bounded_count = 1; records.deletionAware.copy_class_inventory_digest_sha256 = canonicalSha256(records.deletionAware.copy_class_inventory); seal(records.deletionAware)
      expectCode(() => assertDeletionAware(records), 'COPY_STATE_COUNT_INVALID'); return 'COPY_STATE_COUNT_INVALID'
    }
    case 'control_revalidation_head_moved': {
      records.lifecycle[6].control_revalidation.after.d940_state_head_digest_sha256 = 'f'.repeat(64); seal(records.lifecycle[6])
      expectCode(() => assertLifecycle(records), 'CONTROL_HEAD_MOVED'); return 'CONTROL_HEAD_MOVED'
    }
    case 'expired_restore_authorization': {
      const lifecycle = records.lifecycle.at(-1); lifecycle.event_at = records.authorization.valid_until; lifecycle.persisted_at = new Date(ms(records.authorization.valid_until) + 1).toISOString(); const attestation = records.retentionHeadAttestations.find((item) => item.record_digest_sha256 === lifecycle.control_revalidation.retention_head_attestation_record_digest_sha256); attestation.observed_at = new Date(ms(lifecycle.event_at) - 2000).toISOString(); attestation.known_at = new Date(ms(lifecycle.event_at) - 1000).toISOString(); seal(attestation); lifecycle.control_revalidation.retention_head_attestation_record_digest_sha256 = attestation.record_digest_sha256; seal(lifecycle)
      expectCode(() => assertLifecycle(records), 'LIFECYCLE_CHRONOLOGY_INVALID'); return 'LIFECYCLE_CHRONOLOGY_INVALID'
    }
    case 'lifecycle_backdating': {
      const lifecycle = records.lifecycle.at(-1); lifecycle.event_at = new Date(ms(records.lifecycle.at(-2).event_at) - 1).toISOString(); lifecycle.control_revalidation.after.observed_at = new Date(ms(lifecycle.event_at) - 2000).toISOString(); lifecycle.control_revalidation.after.known_at = new Date(ms(lifecycle.event_at) - 1000).toISOString(); const attestation = records.retentionHeadAttestations.find((item) => item.record_digest_sha256 === lifecycle.control_revalidation.retention_head_attestation_record_digest_sha256); attestation.observed_at = new Date(ms(lifecycle.event_at) - 2000).toISOString(); attestation.known_at = new Date(ms(lifecycle.event_at) - 1000).toISOString(); seal(attestation); lifecycle.control_revalidation.retention_head_attestation_record_digest_sha256 = attestation.record_digest_sha256; seal(lifecycle)
      expectCode(() => assertLifecycle(records), 'LIFECYCLE_CHRONOLOGY_INVALID'); return 'LIFECYCLE_CHRONOLOGY_INVALID'
    }
    case 'wrong_stage_actor': {
      records.lifecycle[3].semantic_actor = actor(records.actors, 'restore_executor'); seal(records.lifecycle[3])
      expectCode(() => assertLifecycle(records), 'ACTOR_UNAUTHORIZED'); return 'ACTOR_UNAUTHORIZED'
    }
    case 'wrong_stage_outcome': {
      records.lifecycle[2].outcome_code = 'succeeded'; seal(records.lifecycle[2])
      expectCode(() => assertLifecycle(records), 'STAGE_SEMANTICS_INVALID'); return 'STAGE_SEMANTICS_INVALID'
    }
    case 'ipc_route_substitution': {
      records.request.route_code = 'route.backup.verify'; seal(records.request); records.response.route_code = 'route.backup.verify'; records.response.response_to_request_digest_sha256 = records.request.record_digest_sha256; seal(records.response)
      expectCode(() => assertIpc(records), 'IPC_ROUTE_INVALID'); return 'IPC_ROUTE_INVALID'
    }
    case 'false_pass_drill_mismatch': {
      records.drill.observed_source_state_head_digest_sha256 = 'f'.repeat(64); records.drill.source_head_comparison_code = 'mismatch'; seal(records.drill)
      expectCode(() => assertDrill(records), 'DRILL_CLASSIFICATION_INVALID'); return 'DRILL_CLASSIFICATION_INVALID'
    }
    case 'fabricated_checkpoint_age': {
      records.drill.checkpoint_age_seconds -= 1; seal(records.drill)
      expectCode(() => assertDrill(records), 'DRILL_AGE_INVALID'); return 'DRILL_AGE_INVALID'
    }
    case 'drill_chain_gap': {
      const next = clone(records.drill); next.record_code = 'restore.drill.synthetic.002'; next.chain = { namespace_code: 'd950.restore.drills.v1', sequence: 3, previous_record_digest_sha256: records.drill.record_digest_sha256 }; seal(next)
      expectCode(() => assertDrillChain([records.drill, next]), 'DRILL_CHAIN_INVALID'); return 'DRILL_CHAIN_INVALID'
    }
    case 'retention_chain_fork': {
      const first = successorRetention(records.retentionControl, 'retention.control.synthetic.002')
      const second = successorRetention(records.retentionControl, 'retention.control.synthetic.fork')
      expectCode(() => {
        const successors = new Map()
        for (const item of [first, second]) { const key = item.chain.previous_record_digest_sha256; if (successors.has(key)) fail('RETENTION_CHAIN_FORK'); successors.set(key, item.record_digest_sha256) }
      }, 'RETENTION_CHAIN_FORK'); return 'RETENTION_CHAIN_FORK'
    }
    case 'stale_retention_leaf': {
      records.retentionHistory.push(successorRetention(records.retentionControl, 'retention.control.synthetic.002'))
      expectCode(() => assertPlan(records), 'RETENTION_LEAF_STALE'); return 'RETENTION_LEAF_STALE'
    }
    case 'missing_subject_assessment': {
      records.manifest.source_inventory[1].subject_identity_sha256 = 'f'.repeat(64)
      expectCode(() => assertPlan(records), 'SUBJECT_ASSESSMENT_INCOMPLETE'); return 'SUBJECT_ASSESSMENT_INCOMPLETE'
    }
    case 'unverified_required_copy': {
      const verified = new Set(records.receipts.filter((item) => ['source_copy', 'artifact_copy'].includes(item.receipt_kind_code)).slice(0, -1).map((item) => item.copy_identity.copy_code))
      expectCode(() => { for (const copy of records.manifest.backup_copies) if (!verified.has(copy.copy_code)) fail('UNVERIFIED_REQUIRED_COPY') }, 'UNVERIFIED_REQUIRED_COPY'); return 'UNVERIFIED_REQUIRED_COPY'
    }
    case 'control_revalidation_substituted_stable': {
      const item = records.lifecycle[6].control_revalidation; item.before.d940_state_head_digest_sha256 = 'f'.repeat(64); item.after.d940_state_head_digest_sha256 = 'f'.repeat(64); seal(records.lifecycle[6])
      expectCode(() => assertLifecycle(records), 'CONTROL_HEAD_MOVED'); return 'CONTROL_HEAD_MOVED'
    }
    case 'approval_route_missing': {
      records.profile.ipc_routes.find((item) => item.route_code === 'route.restore.approve.privacy').sender_role_code = 'restore_requester'; seal(records.profile)
      expectCode(() => assertProfile(records), 'IPC_ROUTE_MATRIX_INVALID'); return 'IPC_ROUTE_MATRIX_INVALID'
    }
    case 'd930_primary_receipt_mismatch': {
      const receipt = records.receipts.find((item) => item.receipt_kind_code === 'artifact_copy'); receipt.scope.artifact.sha256 = 'f'.repeat(64); receipt.copy_identity.artifact.sha256 = 'f'.repeat(64); receipt.verification.recomputed_sha256 = 'f'.repeat(64); receipt.scope_sha256 = canonicalSha256(receipt.scope); seal(receipt)
      expectCode(() => assertReceipts(records), 'D930_PRIMARY_RECEIPT_MISMATCH'); return 'D930_PRIMARY_RECEIPT_MISMATCH'
    }
    case 'duplicate_copy_code': {
      records.manifest.backup_copies[1].copy_code = records.manifest.backup_copies[0].copy_code; records.manifest.backup_copies[1].copy_identity_sha256 = canonicalSha256({ copy_code: records.manifest.backup_copies[1].copy_code, copy_class_code: records.manifest.backup_copies[1].copy_class_code, backend_code: records.manifest.backup_copies[1].backend_code, backend_generation: records.manifest.backup_copies[1].backend_generation, backend_reference: records.manifest.backup_copies[1].backend_reference, artifact: records.manifest.backup_copies[1].artifact }); seal(records.manifest)
      expectCode(() => assertManifest(records), 'COPY_IDENTITY_COLLISION'); return 'COPY_IDENTITY_COLLISION'
    }
    case 'duplicate_copy_identity': {
      records.manifest.backup_copies[1].copy_identity_sha256 = records.manifest.backup_copies[0].copy_identity_sha256; seal(records.manifest)
      expectCode(() => assertManifest(records), 'COPY_IDENTITY_COLLISION'); return 'COPY_IDENTITY_COLLISION'
    }
    case 'unmapped_blocking_control': {
      records.deletionAware.control_evidence.push({ evidence_type_code: 'custody_control', source_format: 'jedi-atlas-custody-control-record', source_record_kind_code: 'hold_imposed', record_code: 'd940.control.hold.synthetic.002', record_digest_sha256: 'ab'.repeat(32), journal_receipt_record_digest_sha256: 'ac'.repeat(32), subject_identity_sha256: fixture.subject_identity_sha256, basis_record_digest_sha256: null, directive_code: null, resolver_response_record_digest_sha256: 'ad'.repeat(32), current_leaf: true, applicability_code: 'applies_currently' }); seal(records.deletionAware)
      expectCode(() => assertDeletionAware(records), 'CONTROL_EVIDENCE_UNMAPPED'); return 'CONTROL_EVIDENCE_UNMAPPED'
    }
    case 'approval_ipc_substitution': {
      records.authorization.approvals[0].submission_request_record_digest_sha256 = 'f'.repeat(64); seal(records.authorization.approvals[0]); seal(records.authorization)
      expectCode(() => assertAuthorization(records), 'APPROVAL_IPC_EVIDENCE_INVALID'); return 'APPROVAL_IPC_EVIDENCE_INVALID'
    }
    case 'retention_head_substitution': {
      records.retentionHeadAttestation.head_receipt_record_digest_sha256 = 'f'.repeat(64); seal(records.retentionHeadAttestation)
      expectCode(() => assertRetentionHead(records), 'RETENTION_HEAD_UNAUTHENTICATED'); return 'RETENTION_HEAD_UNAUTHENTICATED'
    }
    case 'retention_wrong_subject': {
      const successor = successorRetention(records.retentionControl, 'retention.control.synthetic.002'); successor.backup_set_code = 'backup.synthetic.other'; seal(successor)
      expectCode(() => assertRetentionGraph([records.retentionControl, successor], records.manifest), 'RETENTION_CHAIN_SUBJECT_MISMATCH'); return 'RETENTION_CHAIN_SUBJECT_MISMATCH'
    }
    case 'retention_successor_backdated': {
      const successor = successorRetention(records.retentionControl, 'retention.control.synthetic.002'); successor.recorded_at = records.retentionControl.recorded_at; successor.persisted_at = records.retentionControl.persisted_at; seal(successor)
      expectCode(() => assertRetentionGraph([records.retentionControl, successor], records.manifest), 'RETENTION_CHRONOLOGY_INVALID'); return 'RETENTION_CHRONOLOGY_INVALID'
    }
    case 'backup_operation_reuse': {
      const successor = successorManifest(records.manifest, 2, 'backup.manifest.synthetic.002'); successor.operation_id = records.manifest.operation_id; successor.operation_nonce = records.manifest.operation_nonce; seal(successor)
      expectCode(() => assertNoReplace([records.manifest, successor]), 'REPLAY_CONFLICT'); return 'REPLAY_CONFLICT'
    }
    case 'backup_successor_backdated': {
      const successor = successorManifest(records.manifest, 2, 'backup.manifest.synthetic.002'); successor.created_at = records.manifest.created_at; successor.persisted_at = records.manifest.persisted_at; seal(successor)
      expectCode(() => assertBackupGraph([records.manifest, successor]), 'CHAIN_CHRONOLOGY_INVALID'); return 'CHAIN_CHRONOLOGY_INVALID'
    }
    case 'drill_exact_labeled_failed': {
      records.drill.outcome_code = 'failed'; records.drill.escalation_code = 'security_review_required'; seal(records.drill)
      expectCode(() => assertDrill(records), 'DRILL_CLASSIFICATION_INVALID'); return 'DRILL_CLASSIFICATION_INVALID'
    }
    case 'drill_mismatch_labeled_stale': {
      records.drill.observed_source_state_head_digest_sha256 = 'f'.repeat(64); records.drill.source_head_comparison_code = 'mismatch'; records.drill.outcome_code = 'stale'; records.drill.escalation_code = 'new_backup_required'; seal(records.drill)
      expectCode(() => assertDrill(records), 'DRILL_CLASSIFICATION_INVALID'); return 'DRILL_CLASSIFICATION_INVALID'
    }
    case 'drill_comparison_inconsistent': {
      records.drill.source_head_comparison_code = 'mismatch'; seal(records.drill)
      expectCode(() => assertDrill(records), 'DRILL_COMPARISON_INVALID'); return 'DRILL_COMPARISON_INVALID'
    }
    case 'retention_revalidation_stale': {
      records.lifecycle[6].control_revalidation.retention_head_attestation_record_digest_sha256 = records.retentionHeadAttestation.record_digest_sha256; seal(records.lifecycle[6])
      expectCode(() => assertLifecycle(records), 'RETENTION_HEAD_STALE'); return 'RETENTION_HEAD_STALE'
    }
    case 'approval_ipc_rejected': {
      records.approvalResponses[0].outcome_code = 'rejected'; records.approvalResponses[0].error_code = 'authorization_failed'; seal(records.approvalResponses[0]); records.authorization.approvals[0].broker_response_record_digest_sha256 = records.approvalResponses[0].record_digest_sha256; seal(records.authorization.approvals[0]); seal(records.authorization)
      expectCode(() => assertIpc(records), 'IPC_MESSAGE_SEMANTICS_INVALID'); return 'IPC_MESSAGE_SEMANTICS_INVALID'
    }
    case 'approval_ipc_wrong_kind': {
      records.approvalResponses[0].message_kind_code = 'request'; seal(records.approvalResponses[0])
      expectCode(() => assertIpc(records), 'IPC_MESSAGE_SEMANTICS_INVALID'); return 'IPC_MESSAGE_SEMANTICS_INVALID'
    }
    case 'approval_ipc_wrong_operation': {
      records.approvalRequests[0].operation_id = 'operation.synthetic.other'; seal(records.approvalRequests[0]); records.approvalResponses[0].operation_id = 'operation.synthetic.other'; records.approvalResponses[0].response_to_request_digest_sha256 = records.approvalRequests[0].record_digest_sha256; records.approvalResponses[0].payload_record_digest_sha256 = records.approvalRequests[0].record_digest_sha256; seal(records.approvalResponses[0]); records.authorization.approvals[0].submission_request_record_digest_sha256 = records.approvalRequests[0].record_digest_sha256; records.authorization.approvals[0].broker_response_record_digest_sha256 = records.approvalResponses[0].record_digest_sha256; seal(records.authorization.approvals[0]); seal(records.authorization)
      expectCode(() => assertAuthorization(records), 'APPROVAL_IPC_EVIDENCE_INVALID'); return 'APPROVAL_IPC_EVIDENCE_INVALID'
    }
    case 'approval_ipc_wrong_payload': {
      records.approvalRequests[0].payload_format = 'jedi-atlas-restore-plan'; seal(records.approvalRequests[0]); records.approvalResponses[0].response_to_request_digest_sha256 = records.approvalRequests[0].record_digest_sha256; records.approvalResponses[0].payload_record_digest_sha256 = records.approvalRequests[0].record_digest_sha256; seal(records.approvalResponses[0])
      expectCode(() => assertIpc(records), 'IPC_PAYLOAD_FORMAT_INVALID'); return 'IPC_PAYLOAD_FORMAT_INVALID'
    }
    case 'retention_head_scope_substitution': {
      records.retentionHeadAttestation.backup_set_code = 'backup.synthetic.other'; seal(records.retentionHeadAttestation)
      expectCode(() => assertRetentionHead(records), 'RETENTION_HEAD_SCOPE_MISMATCH'); return 'RETENTION_HEAD_SCOPE_MISMATCH'
    }
    case 'drill_chain_relabel': {
      records.drill.backup_chain_state_code = 'superseded'; seal(records.drill)
      expectCode(() => assertDrill(records), 'DRILL_COMPARISON_INVALID'); return 'DRILL_COMPARISON_INVALID'
    }
    default:
      fail('UNTESTED_MUTATION', caseCode)
  }
}

function successorManifest(previous, sequence, code) {
  const value = clone(previous)
  value.record_code = code
  value.operation_id = `operation.synthetic.backup.${sequence}`
  value.operation_nonce = crypto.createHash('sha256').update(value.operation_id).digest('hex')
  value.backup_chain_sequence = sequence
  value.previous_backup_manifest_record_digest_sha256 = previous.record_digest_sha256
  value.created_at = new Date(ms(previous.created_at) + sequence * 1000).toISOString()
  value.persisted_at = new Date(ms(previous.persisted_at) + sequence * 1000).toISOString()
  return seal(value)
}

function assertNoReplace(records) {
  const identities = new Map()
  const operations = new Map()
  for (const record of records) {
    for (const identity of [record.record_code, `${record.operation_id}/${record.operation_nonce}`]) {
      const prior = identities.get(identity)
      if (prior && prior !== record.record_digest_sha256) fail('REPLAY_CONFLICT', identity)
      identities.set(identity, record.record_digest_sha256)
    }
    const priorNonce = operations.get(record.operation_id)
    if (priorNonce && priorNonce !== record.operation_nonce) fail('REPLAY_CONFLICT', record.operation_id)
    operations.set(record.operation_id, record.operation_nonce)
  }
}

function assertBackupGraph(manifests) {
  const byDigest = new Map(manifests.map((item) => [item.record_digest_sha256, item]))
  const successorByPredecessor = new Map()
  const sequences = new Map()
  let rootDigest = null
  let backupSetCode = null
  for (const manifest of manifests) {
    if (manifest.backup_chain_sequence === 1 && manifest.previous_backup_manifest_record_digest_sha256 !== null) fail('ROLLBACK_DETECTED')
    const predecessors = manifests.filter((candidate) => candidate.record_digest_sha256 !== manifest.record_digest_sha256)
    assertManifest({ manifest }, predecessors)
    if (backupSetCode === null) backupSetCode = manifest.backup_set_code
    if (manifest.backup_set_code !== backupSetCode) fail('CHAIN_SUBJECT_MISMATCH')
    if (manifest.backup_chain_sequence === 1) {
      if (manifest.previous_backup_manifest_record_digest_sha256 !== null) fail('ROLLBACK_DETECTED')
      if (rootDigest !== null && rootDigest !== manifest.record_digest_sha256) fail('ROLLBACK_DETECTED')
      rootDigest = manifest.record_digest_sha256
    }
    if (sequences.has(manifest.backup_chain_sequence)) {
      const prior = sequences.get(manifest.backup_chain_sequence)
      if (prior !== manifest.record_digest_sha256) fail('CHAIN_FORK')
    }
    sequences.set(manifest.backup_chain_sequence, manifest.record_digest_sha256)
    if (manifest.backup_chain_sequence === 1) continue
    const predecessor = byDigest.get(manifest.previous_backup_manifest_record_digest_sha256)
    if (!predecessor) fail('PREDECESSOR_MISSING')
    if (manifest.backup_chain_sequence <= predecessor.backup_chain_sequence) fail('ROLLBACK_DETECTED')
    if (manifest.backup_chain_sequence !== predecessor.backup_chain_sequence + 1) fail('CHAIN_GAP')
    if (ms(manifest.created_at) <= ms(predecessor.created_at) || ms(manifest.persisted_at) <= ms(predecessor.persisted_at)) fail('CHAIN_CHRONOLOGY_INVALID')
    const priorSuccessor = successorByPredecessor.get(predecessor.record_digest_sha256)
    if (priorSuccessor && priorSuccessor !== manifest.record_digest_sha256) fail('CHAIN_FORK')
    successorByPredecessor.set(predecessor.record_digest_sha256, manifest.record_digest_sha256)
  }
}

function classifyRestorePrefix(records, responseLost = false) {
  const expected = classifications.restore_stage_rules.map((rule) => rule.stage_code)
  for (const [index, record] of records.entries()) if (record.stage_code !== expected[index]) return { outcome_code: 'recovery_required', error_code: 'chain_gap', automatic_action: false }
  if (records.length === expected.length) return { outcome_code: 'succeeded', error_code: 'none', automatic_action: false }
  return { outcome_code: 'recovery_required', error_code: responseLost ? 'response_loss_ambiguous' : 'partial_restore', automatic_action: false }
}

function assertExclusiveTargets(plans) {
  const active = new Map()
  for (const plan of plans) {
    const identity = canonicalSha256(plan.target_environment)
    const previous = active.get(identity)
    if (previous && previous !== `${plan.operation_id}/${plan.operation_nonce}`) fail('CONCURRENT_OPERATION')
    active.set(identity, `${plan.operation_id}/${plan.operation_nonce}`)
  }
}

function assertBuildPins(records) {
  const fixtureActors = actorMap(fixture)
  for (const value of [records.plan.executor, records.plan.control_state_verifier, records.plan.restored_state_verifier, records.plan.persistence_broker]) {
    const expected = fixtureActors.get(value.semantic_role_code)
    if (!expected || value.executable_build_sha256 !== expected.executable_build_sha256 || value.binding_code !== expected.binding_code || value.ipc_endpoint_code !== expected.ipc_endpoint_code) fail('BUILD_MISMATCH')
  }
}

function assertFrozenBoundaries() {
  for (const [relative, digest] of Object.entries(frozenFiles)) assert.equal(rawSha(path.join(project, relative)), digest, `${relative} frozen`)
  for (const commit of Object.values(pinnedCommits)) {
    const result = spawnSync('git', ['merge-base', '--is-ancestor', commit, 'HEAD'], { cwd: project })
    assert.equal(result.status, 0, `approved commit ${commit} is an ancestor`)
  }
  const d941Tree = execFileSync('git', ['show', '-s', '--format=%T', pinnedCommits.d941], { cwd: project, encoding: 'utf8' }).trim()
  assert.equal(d941Tree, '70bf23ad29722f18d7d970013864bc147c0c154b')
}

function runFrozenValidators() {
  const validators = [
    'docs/schema/validate-d9-0.mjs',
    'docs/schema/validate-d9-3-0.mjs',
    'docs/schema/validate-d9-4-0.mjs',
    'docs/schema/validate-d9-recovery-resolvers.mjs',
    'docs/schema/validate-d9-recovery-resolvers-v1-1.mjs',
    'docs/schema/validate-d9-recovery-resolvers-v1-2.mjs',
    'docs/schema/validate-d9-recovery-resolvers-v1-3.mjs',
  ]
  for (const validator of validators) execFileSync(process.execPath, ['--disable-warning=ExperimentalWarning', validator], { cwd: project, stdio: 'pipe' })
  return validators.length
}

function assertRegistries() {
  for (const value of [classifications, digestProfiles, fieldRegistry, storageProfiles]) {
    assert.equal(value.status_code ?? 'design_only_contract_freeze', 'design_only_contract_freeze')
    assert.equal(value.record_digest_sha256, canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' }))
    assertSafeStrings(value)
  }
  assert.deepEqual(classifications.copy_class_rules.canonical_order, ['primary', 'backup', 'derived', 'temporary', 'replica', 'open_descriptor', 'unknown'])
  assert.equal(classifications.copy_class_rules.complete_erasure_claim_permitted, false)
  for (const partition of [classifications.error_retryability_partition, classifications.error_outcome_partition]) {
    const members = Object.values(partition).flat()
    assert.equal(new Set(members).size, members.length, 'closed error partition has no duplicates')
    assert.deepEqual([...members].sort(), [...classifications.closed_error_codes].sort(), 'closed error partition is exhaustive')
  }
  assert.equal(classifications.authority_boundary.runtime_implementation_authorized, false)
  assert.equal(storageProfiles.restore_staging.separate_inaccessible_namespace_required, true)
  assert.equal(storageProfiles.reconstruction_rules.deletion_receipts_and_tombstones_precede_exposure, true)
  assert.equal(new Set(fieldRegistry.field_families.map((item) => item.field_family_code)).size, fieldRegistry.field_families.length)
  assert.ok(fieldRegistry.caller_claim_prohibitions.includes('complete_erasure'))
}

function assertCatalogAndInventory() {
  const catalog = readJson(path.join(root, 'contract-catalog-v1.json'))
  const inventory = readJson(path.join(root, 'root-inventory-v1.json'))
  assert.equal(catalog.status_code, 'design_only_contract_freeze')
  assert.deepEqual(catalog.approved_commits, {
    d901: pinnedCommits.d901, d91: pinnedCommits.d91, d92: pinnedCommits.d92, d930: pinnedCommits.d930,
    d931: pinnedCommits.d931, d940: pinnedCommits.d940, recovery_v1: pinnedCommits.recoveryV1,
    recovery_v11: pinnedCommits.recoveryV11, recovery_v12: pinnedCommits.recoveryV12,
    recovery_v13: pinnedCommits.recoveryV13, d941: pinnedCommits.d941,
  })
  for (const entry of [...catalog.schemas, ...catalog.registries, ...catalog.fixtures, ...catalog.validators]) {
    const absolute = path.resolve(root, entry.file)
    assert.equal(rawSha(absolute), entry.raw_sha256, `catalog raw hash ${entry.file}`)
    if (entry.semantic_sha256) {
      const value = readJson(absolute)
      assert.equal(value.record_digest_sha256, entry.semantic_sha256, `catalog semantic hash ${entry.file}`)
    }
  }
  for (const [file, digest] of Object.entries(catalog.migration_sha256)) assert.equal(frozenFiles[`data/migrations/${file}`], digest)
  for (const value of Object.values(catalog.instance_policy)) assert.equal(value, false)

  const disk = []
  const walk = (directory, prefix = '') => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const relative = path.posix.join(prefix, entry.name)
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) walk(absolute, relative)
      else if (entry.isFile() && relative !== inventory.self_excluded_path) disk.push(relative)
      else if (!entry.isFile()) fail('SPECIAL_FILE_IN_CONTRACT_ROOT', relative)
    }
  }
  walk(root)
  disk.sort()
  assert.deepEqual(inventory.files.map((item) => item.path), disk)
  for (const item of inventory.files) assert.equal(rawSha(path.join(root, item.path)), item.raw_sha256, `root inventory ${item.path}`)
  return { catalog: rawSha(path.join(root, 'contract-catalog-v1.json')), root_inventory: rawSha(path.join(root, 'root-inventory-v1.json')) }
}

function assertGoldenVectors(records) {
  const vectors = new Map(golden.vectors.map((item) => [item.vector_code, item]))
  for (const item of golden.vectors) assert.equal(crypto.createHash('sha256').update(Buffer.from(item.canonical_utf8)).digest('hex'), item.sha256, `${item.vector_code} independent SHA-256`)
  assert.equal(vectors.get('object_key_order_and_null').canonical_utf8, canonicalize({ b: [2, 1], a: null }))
  assert.equal(vectors.get('unicode_non_normalization').canonical_utf8, canonicalize({ value: 'e\u0301' }))
  for (const [code, record] of [['complete_backup_manifest', records.manifest], ['complete_deletion_aware_reconstruction', records.deletionAware]]) {
    const item = vectors.get(code)
    assert.equal(item.canonical_utf8, canonicalize(record), `${code} canonical string`)
    assert.equal(item.canonical_byte_length, Buffer.byteLength(item.canonical_utf8), `${code} byte length`)
  }
  const reversed = JSON.stringify({ b: [2, 1], a: null })
  assert.notEqual(crypto.createHash('sha256').update(Buffer.from(reversed)).digest('hex'), vectors.get('object_key_order_and_null').sha256)
}

function leafPaths(value, prefix = []) {
  if (value === null || typeof value !== 'object') return [prefix]
  const result = []
  if (Array.isArray(value)) for (let index = 0; index < value.length; index += 1) result.push(...leafPaths(value[index], [...prefix, index]))
  else for (const key of Object.keys(value)) if (key !== 'record_digest_sha256') result.push(...leafPaths(value[key], [...prefix, key]))
  return result
}

function setAt(value, pointer, replacement) {
  let cursor = value
  for (const key of pointer.slice(0, -1)) cursor = cursor[key]
  cursor[pointer.at(-1)] = replacement
}

function assertDigestCoverage(records) {
  let mutations = 0
  for (const record of [records.profile, records.manifest, ...records.receipts, records.deletionAware, records.retentionControl, records.retentionReceipt, ...records.retentionHeadAttestations, records.authorization, records.plan, ...records.lifecycle, records.drill, records.request, records.response, ...records.approvalRequests, ...records.approvalResponses, ...records.journalReceipts]) {
    for (const pointer of leafPaths(record)) {
      const changed = clone(record)
      let value = changed
      for (const key of pointer) value = value[key]
      const replacement = typeof value === 'boolean' ? !value : typeof value === 'number' ? value + 1 : value === null ? 'x' : `${value}x`
      setAt(changed, pointer, replacement)
      assert.notEqual(canonicalSha256(changed, { excludedTopLevelField: 'record_digest_sha256' }), record.record_digest_sha256, `digest-covered ${pointer.join('/')}`)
      mutations += 1
    }
  }
  return mutations
}

function assertSchemaMutations(records) {
  const catalog = readJson(path.join(root, 'contract-catalog-v1.json'))
  let count = 0
  for (const file of schemaFiles) {
    const original = schemas.find((schema) => schema.$id.endsWith(`/${file}`))
    const changed = clone(original)
    changed.title = `${changed.title} weakened`
    assert.notEqual(sha256Bytes(Buffer.from(`${JSON.stringify(changed, null, 2)}\n`)), catalog.schemas.find((item) => item.file === file).raw_sha256)
    count += 1
  }
  const receiptSchema = clone(schemas.find((schema) => schema.$id.endsWith('/backup-durability-receipt-v1.schema.json')))
  receiptSchema.properties.durability.properties.no_replace_enforced = { type: 'boolean' }
  const localAjv = new Ajv2020({ allErrors: true, strict: false })
  localAjv.addSchema(d90Common); localAjv.addSchema(d940Common); localAjv.addSchema(schemas.find((schema) => schema.$id.endsWith('/common-v1.schema.json')))
  const receiptValidator = localAjv.compile(receiptSchema)
  const weakenedReceipt = clone(records.receipts[0]); weakenedReceipt.durability.no_replace_enforced = false; seal(weakenedReceipt)
  assert.equal(receiptValidator(weakenedReceipt), true)
  expectCode(() => assertReceiptDurability(weakenedReceipt), 'DURABILITY_INCOMPLETE')

  const reconstructionSchema = clone(schemas.find((schema) => schema.$id.endsWith('/deletion-aware-reconstruction-v1.schema.json')))
  reconstructionSchema.properties.complete_erasure_claimed = { type: 'boolean' }
  const localAjv2 = new Ajv2020({ allErrors: true, strict: false }); localAjv2.addSchema(d90Common); localAjv2.addSchema(d940Common); localAjv2.addSchema(schemas.find((schema) => schema.$id.endsWith('/common-v1.schema.json')))
  const reconstructionValidator = localAjv2.compile(reconstructionSchema)
  const overclaim = clone(records.deletionAware); overclaim.complete_erasure_claimed = true; seal(overclaim)
  assert.equal(reconstructionValidator(overclaim), true)
  expectCode(() => assertNoErasureOverclaim(overclaim), 'COMPLETE_ERASURE_CLAIM_FORBIDDEN')
  return count + 2
}

function assertDatabaseBoundary() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d950-design-'))
  try {
    const databasePath = path.join(temp, 'atlas.sqlite')
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

function emitDerived() {
  const records = buildRecords()
  const vectors = {
    object_key_order_and_null: canonicalize({ b: [2, 1], a: null }),
    unicode_non_normalization: canonicalize({ value: 'e\u0301' }),
    complete_backup_manifest: canonicalize(records.manifest),
    complete_deletion_aware_reconstruction: canonicalize(records.deletionAware),
  }
  console.log(JSON.stringify(Object.fromEntries(Object.entries(vectors).map(([key, value]) => [key, { canonical_utf8: value, sha256: crypto.createHash('sha256').update(Buffer.from(value)).digest('hex'), canonical_byte_length: Buffer.byteLength(value) }])), null, 2))
}

if (process.argv.includes('--emit-derived')) {
  emitDerived()
  process.exit(0)
}

const records = buildRecords()
assertFrozenBoundaries()
assertRegistries()
assertValidRecords(records)
const drillMatrixCases = assertDrillMatrixCoverage(records)
assertBuildPins(records)
const successorBackup = successorManifest(records.manifest, 2, 'backup.manifest.synthetic.002')
assertBackupGraph([records.manifest, successorBackup])
assertRetentionGraph([records.retentionControl, successorRetention(records.retentionControl, 'retention.control.synthetic.002')], records.manifest)
assertNoReplace([records.manifest, successorBackup])
assertExclusiveTargets([records.plan])

const executedMutations = new Map()
for (const item of invalidFixture.mutations) {
  const result = runMutation(item.case_code, records)
  assert.equal(result.toLowerCase(), item.expected_error_code, `${item.case_code} closed error code`)
  executedMutations.set(item.case_code, result)
}
assert.deepEqual([...executedMutations.keys()], invalidFixture.mutations.map((item) => item.case_code))
assert.deepEqual(classifications.adversarial_case_codes, ['valid_backup_restore', ...invalidFixture.mutations.map((item) => item.case_code)])

assertGoldenVectors(records)
const leafMutations = assertDigestCoverage(records)
const schemaMutations = assertSchemaMutations(records)
const fingerprints = assertCatalogAndInventory()
assertDatabaseBoundary()
const frozenValidators = runFrozenValidators()

console.log(JSON.stringify({
  status: 'D9.5.0 design-only backup, restore, and deletion-aware reconstruction contracts validated offline; no runtime authority claimed.',
  schemas: schemaFiles.length,
  registries: 4,
  valid_synthetic_contract_records: [records.profile, records.manifest, ...records.receipts, records.deletionAware, records.retentionControl, records.retentionReceipt, ...records.retentionHeadAttestations, records.authorization, records.plan, ...records.lifecycle, records.drill, records.request, records.response, ...records.approvalRequests, ...records.approvalResponses, ...records.journalReceipts].length,
  invalid_adversarial_cases: executedMutations.size,
  digest_leaf_mutations: leafMutations,
  schema_mutations: schemaMutations,
  backup_chain: 'linear_gapless_unforked',
  restore_stages: records.lifecycle.length,
  drill_matrix_positive_cases: drillMatrixCases,
  copy_classes: classifications.copy_class_rules.canonical_order,
  technical_non_authority_boundary: 'passed',
  frozen_validators_executed: frozenValidators,
  frozen_migrations: 5,
  atlas_tables_empty: atlasTables.length,
  integrity_check: 'ok',
  foreign_key_check: 'clean',
  fingerprints: {
    catalog: fingerprints.catalog,
    classifications: classifications.record_digest_sha256,
    digest_profiles: digestProfiles.record_digest_sha256,
    field_registry: fieldRegistry.record_digest_sha256,
    storage_profiles: storageProfiles.record_digest_sha256,
    validator: rawSha(fileURLToPath(import.meta.url)),
    root_inventory: fingerprints.root_inventory,
  },
}, null, 2))
