import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { canonicalSha256, canonicalize, sha256Bytes } from '../../d9/control-plane/canonical.mjs'
import { loadApprovedContractSet } from '../../d9/control-plane/contracts.mjs'
import { compileLinuxEnforcement, SYNTHETIC_DESCRIPTOR_BYTES } from '../../d9/control-plane/platform.mjs'
import { loadApprovedD930ContractSet } from '../../d9/custody/contracts.mjs'
import { createDurableNamespaceStore } from '../../d9/custody/durable-store.mjs'
import { createD941AdministrativeLauncher } from '../../d9/restriction/admin-launcher.mjs'
import { createD941AuthorityRegistry } from '../../d9/restriction/authority.mjs'
import { loadApprovedD940ContractSet, sealD940Record, verifyD940AuthorityContext } from '../../d9/restriction/contracts.mjs'
import { createD941LedgerBroker, D941_STORE_NAMESPACES } from '../../d9/restriction/ledger.mjs'
import { compileD941PrimaryDeleteRuntime } from '../../d9/restriction/primary-delete.mjs'
import { createD941SyntheticCustodyEvidence } from '../../d9/restriction/custody-evidence.mjs'
import { createD941ResolverDurabilityStore, createD941SyntheticResolverClock } from '../../d9/restriction/recovery-resolvers.mjs'
import { createGenerationFixture, reseal, verifyFixture } from '../d9-1-support/runtime-fixture.mjs'

const templates = JSON.parse(fs.readFileSync('docs/schema/d9-4-0/fixtures/valid-contracts-v1.json', 'utf8')).records
const d930Templates = JSON.parse(fs.readFileSync('docs/schema/d9-3-0/fixtures/valid-contracts-v1.json', 'utf8')).records

export function d940Template(code) { return structuredClone(templates[code]) }

function actorScope(roster, identity, extension) {
  return canonicalSha256({
    authority_roster_record_digest_sha256: roster.record_digest_sha256,
    identity_bindings_record_digest_sha256: identity.record_digest_sha256,
    binding_set_code: identity.binding_set_code,
    binding_generation: identity.binding_generation,
    authority_identity_extension_record_digest_sha256: extension.record_digest_sha256,
    authority_identity_extension_generation: extension.extension_generation,
    roster_generation: roster.roster_generation,
  })
}

export function makeClock(start = '2030-01-01T00:10:00.000Z') {
  let current = Date.parse(start)
  const reserved = []
  return {
    reserve(step = 1_000) { current += step; const value = new Date(current).toISOString(); reserved.push(value); return value },
    clock() { if (!reserved.length) throw new Error('No reserved persistence time'); return reserved.shift() },
  }
}

export async function createD941Fixture(t, { resolverFaultInjector = null, brokerFaultInjector = null } = {}) {
  const linux = await compileLinuxEnforcement(); t.after(() => linux.dispose())
  const deleteRuntime = compileD941PrimaryDeleteRuntime(); t.after(() => deleteRuntime.dispose())
  const base = loadApprovedContractSet()
  const generationFixture = createGenerationFixture(t, { serviceExecutablePath: linux.syntheticExecutablePath })
  fs.copyFileSync(linux.syntheticExecutablePath, generationFixture.options.componentFiles.trusted_launcher.executable)
  fs.chmodSync(generationFixture.options.componentFiles.trusted_launcher.executable, 0o755)
  const releases = new Map(generationFixture.runtime.component_releases.map((release) => [release.runtime_role_code, release]))
  releases.get('trusted_launcher').executable_sha256 = sha256Bytes(fs.readFileSync(generationFixture.options.componentFiles.trusted_launcher.executable))
  reseal(generationFixture.runtime)
  for (const binding of generationFixture.identity.bindings) {
    if (binding.principal_kind_code === 'service') binding.executable_sha256 = releases.get(binding.runtime_role_code).executable_sha256
  }
  generationFixture.identity.runtime_profile_record_digest_sha256 = generationFixture.runtime.record_digest_sha256
  reseal(generationFixture.identity)
  generationFixture.selection.runtime_profile_record_digest_sha256 = generationFixture.runtime.record_digest_sha256
  generationFixture.selection.identity_bindings_record_digest_sha256 = generationFixture.identity.record_digest_sha256
  const generation = verifyFixture(base, generationFixture)
  const d930 = loadApprovedD930ContractSet({ baseContractSet: base })
  const d940 = loadApprovedD940ContractSet({ baseContractSet: base, d930ContractSet: d930 })

  const profile = d940Template('operational_profile')
  const extension = d940Template('authority_identity_extension')
  const roster = d940Template('authority_roster')
  const adoption = d940Template('authority_roster_adoption')
  const identity = generation.identityBindings
  extension.identity_bindings_record_digest_sha256 = identity.record_digest_sha256
  extension.binding_set_code = identity.binding_set_code; extension.binding_generation = identity.binding_generation
  extension.issued_at = '2030-01-01T00:01:01.000Z'; extension.bindings[0].valid_from = extension.issued_at
  extension.expires_at = identity.expires_at; extension.bindings[0].valid_until = identity.expires_at
  reseal(extension)
  const humanPrincipalByRole = new Map([
    ['bootstrap_authority', 'person.deletion.synthetic'], ['clearance_checker', 'person.records.synthetic'],
    ['clearance_decider', 'person.privacy.synthetic'], ['human_submitter', 'synthetic.human'],
    ['operational_witness', 'person.witness.synthetic'], ['recovery_authority', 'person.deletion.approver.synthetic'],
    ['recovery_operator', 'person.security.synthetic'],
  ])
  const byRole = new Map(identity.bindings.map((binding) => [binding.runtime_role_code, binding]))
  roster.identity_bindings_record_digest_sha256 = identity.record_digest_sha256
  roster.binding_set_code = identity.binding_set_code; roster.binding_generation = identity.binding_generation
  roster.authority_identity_extension_record_digest_sha256 = extension.record_digest_sha256
  roster.valid_until = identity.expires_at
  for (const mapping of roster.human_identity_mappings) {
    const binding = byRole.get(mapping.d901_runtime_role_code); mapping.binding_code = binding.binding_code; mapping.principal_code = humanPrincipalByRole.get(mapping.d901_runtime_role_code)
  }
  const counters = new Map()
  for (const assignment of roster.assignments) {
    let role = assignment.d901_runtime_role_code
    const count = counters.get(assignment.role_code) ?? 0; counters.set(assignment.role_code, count + 1)
    if (assignment.role_code === 'deletion_authority') role = count === 0 ? 'bootstrap_authority' : 'recovery_authority'
    const binding = byRole.get(role)
    assignment.binding_code = binding.binding_code; assignment.d901_runtime_role_code = role
    assignment.principal_code = binding.principal_kind_code === 'human' ? humanPrincipalByRole.get(role) : null
  }
  reseal(roster)
  adoption.authority_roster_record_digest_sha256 = roster.record_digest_sha256
  adoption.identity_bindings_record_digest_sha256 = identity.record_digest_sha256
  adoption.binding_set_code = identity.binding_set_code; adoption.binding_generation = identity.binding_generation
  adoption.authority_identity_extension_record_digest_sha256 = extension.record_digest_sha256
  const scope = actorScope(roster, identity, extension); adoption.scope_sha256 = scope
  adoption.decisions[0].binding_code = byRole.get('operational_witness').binding_code
  adoption.decisions[0].principal_code = humanPrincipalByRole.get('operational_witness'); adoption.decisions[0].scope_sha256 = scope
  adoption.decisions[0].decision_digest_sha256 = canonicalSha256(adoption.decisions[0], { excludedTopLevelField: 'decision_digest_sha256' })
  adoption.decisions[1].binding_code = extension.bindings[0].binding_code; adoption.decisions[1].principal_code = extension.bindings[0].principal_code; adoption.decisions[1].scope_sha256 = scope
  adoption.decisions[1].decision_digest_sha256 = canonicalSha256(adoption.decisions[1], { excludedTopLevelField: 'decision_digest_sha256' })
  reseal(adoption)
  const authorityContext = verifyD940AuthorityContext({ contractSet: d940, verifiedGeneration: generation, operationalProfile: profile, authorityIdentityExtension: extension, authorityRoster: roster, authorityRosterAdoption: adoption, asOf: '2030-01-01T00:10:00.000Z' })

  const roots = {}
  for (const code of ['store', 'handle', 'lock', 'resolver']) { roots[code] = fs.mkdtempSync(path.join(os.tmpdir(), `jedi-d941-${code}-`)); fs.chmodSync(roots[code], 0o700) }
  roots.cas = deleteRuntime.createSyntheticRoot()
  t.after(() => { for (const root of Object.values(roots)) fs.rmSync(root, { recursive: true, force: true }) })
  fs.writeFileSync(path.join(roots.handle, 'synthetic.handle'), SYNTHETIC_DESCRIPTOR_BYTES, { mode: 0o600 })
  const store = createDurableNamespaceStore({ rootPath: roots.store, namespaceCodes: D941_STORE_NAMESPACES }); t.after(() => store.close())
  const resolverStore = createD941ResolverDurabilityStore({ rootPath: roots.resolver, faultInjector: resolverFaultInjector }); t.after(() => resolverStore.close())
  const time = makeClock()
  const registry = createD941AuthorityRegistry({ store, authorityContext, clock: () => '2030-01-01T00:10:03.000Z', linuxEnforcement: linux, operationLockRootPath: roots.lock })
  const launcher = createD941AdministrativeLauncher({ authorityRegistry: registry, linuxEnforcement: linux, handleRootPath: roots.handle, trustedClock: () => '2030-01-01T00:10:00.000Z', maxFutureSkewMs: 5_000 })
  const selectionSession = await launcher.authenticateAuthorityTransition({ roleCode: 'operational_witness', bindingCode: byRole.get('operational_witness').binding_code, at: '2030-01-01T00:10:00.000Z' })
  registry.selectSynthetic({ actorSession: selectionSession, persistedAt: '2030-01-01T00:10:00.000Z' })
  const resolverPersistenceSession = await launcher.authenticateService({ scopeCode: 'recovery_classification', bindingCode: byRole.get('journal_broker').binding_code, at: '2030-01-01T00:10:00.000Z' })
  const resolverVerifierSession = await launcher.authenticateService({ scopeCode: 'recovery_projection', bindingCode: byRole.get('independent_verifier').binding_code, at: '2030-01-01T00:10:00.000Z' })
  const resolverFinalizerSession = await launcher.authenticateService({ scopeCode: 'recovery_progression', bindingCode: byRole.get('trusted_launcher').binding_code, at: '2030-01-01T00:10:00.000Z' })
  const broker = createD941LedgerBroker({ store, authorityContext, authorityRegistry: registry, clock: time.clock, linuxEnforcement: linux, operationLockRootPath: roots.lock, faultInjector: brokerFaultInjector })
  return { base, d930, d940, generationFixture, generation, authorityContext, profile, extension, roster, adoption, byRole, linux, deleteRuntime, roots, store, resolverStore, resolverPersistenceSession, resolverVerifierSession, resolverFinalizerSession, createResolverClock: (clock) => createD941SyntheticResolverClock({ authorityRegistry: registry, launcherSession: resolverFinalizerSession, clock }), time, registry, launcher, broker }
}

export async function serviceSession(fixture, scopeCode, runtimeRoleCode, at = '2030-01-01T00:10:00.000Z', extra = {}) {
  return fixture.launcher.authenticateService({ scopeCode, bindingCode: fixture.byRole.get(runtimeRoleCode).binding_code, at, ...extra })
}

export async function humanSession(fixture, roleCode, runtimeRoleCode, at = '2030-01-01T00:10:00.000Z', extra = {}) {
  return fixture.launcher.authenticateHumanSubmission({ roleCode, bindingCode: fixture.byRole.get(runtimeRoleCode).binding_code, at, ...extra })
}

export function subjectFor(bytes = Buffer.from('synthetic deletion artifact\n')) {
  const artifact = { byte_layer_code: 'retrieved_body', hash_algorithm_code: 'sha256', sha256: sha256Bytes(bytes), byte_length: bytes.length }
  const subject = { subject_kind_code: 'custody_copy', subject_payload: { artifact, copy_code: 'copy.synthetic.primary', backend_code: 'pilot_local_cas_v1', backend_reference: `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}` }, subject_identity_sha256: null }
  subject.subject_identity_sha256 = canonicalSha256({ subject_kind_code: subject.subject_kind_code, subject_payload: subject.subject_payload })
  return { bytes, artifact, subject, backendReference: subject.subject_payload.backend_reference }
}

export function custodyEvidenceForSubject(fixture, subject) {
  const profile = structuredClone(d930Templates.custody_profile)
  const receipt = structuredClone(d930Templates.primary_receipt)
  receipt.d930_operational_profile_record_digest_sha256 = profile.record_digest_sha256
  receipt.semantic.artifact = structuredClone(subject.subject_payload.artifact)
  receipt.semantic.copy_code = subject.subject_payload.copy_code
  receipt.semantic.backend_code = subject.subject_payload.backend_code
  receipt.semantic.backend_reference = subject.subject_payload.backend_reference
  receipt.semantic_payload_sha256 = canonicalSha256(receipt.semantic)
  return createD941SyntheticCustodyEvidence({ contractSet: fixture.d930, operationalProfile: profile, primaryReceipt: receipt, subject })
}

export function prepareCas(root, artifact, bytes) {
  const target = path.join(root, `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}`)
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 }); fs.chmodSync(path.join(root, 'objects'), 0o700); fs.chmodSync(path.join(root, 'objects/sha256'), 0o700); fs.chmodSync(path.dirname(target), 0o700)
  fs.writeFileSync(target, bytes, { mode: 0o600 }); return target
}

export function makeControlRecord({ fixture, kind, code, operationId, nonce, subject, semanticActor, persistenceActor, sequence, predecessor = null, effectiveAt, recordedAt, persistedAt, reason = 'security_incident', approvals = [], basis = null, authorization = null }) {
  const template = d940Template('restriction')
  Object.assign(template, { record_kind_code: kind, record_code: code, operation_id: operationId, operation_nonce: nonce, subject: structuredClone(subject), reason_category_code: reason, reason_summary: `Synthetic ${kind}.`, semantic_actor: semanticActor, persistence_actor: persistenceActor })
  template.chain = { stream_code: `stream.${operationId}`, sequence, predecessor_record_digest_sha256: predecessor }
  template.knowledge_boundary = { effective_at: effectiveAt, recorded_at: recordedAt, persisted_at: persistedAt, journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: fixture.broker.head().sequence + 1 }
  template.restriction_scope_code = ['restriction_imposed', 'restriction_released', 'quarantine_imposed', 'quarantine_released', 'hold_imposed', 'hold_released', 'clearance_revoked', 'tombstone_applied'].includes(kind) ? 'all_access' : null
  template.human_approvals = approvals
  template.basis_record_digest_sha256 = basis
  template.authorization_scope = authorization
  template.authorization_scope_sha256 = authorization ? canonicalSha256(authorization) : null
  template.authorization_expires_at = authorization?.valid_until ?? null
  template.backup_directive_code = kind === 'restriction_imposed' ? 'restrict_before_restore' : kind === 'tombstone_applied' ? 'tombstone_before_restore' : 'none'
  return sealD940Record(template)
}

export function makeApproval({ code, actor, scopeSha256, decidedAt, expiresAt }) {
  const approval = { approval_code: code, actor, decision_code: 'approve', scope_sha256: scopeSha256, decided_at: decidedAt, expires_at: expiresAt, record_digest_sha256: null }
  approval.record_digest_sha256 = canonicalSha256(approval, { excludedTopLevelField: 'record_digest_sha256' }); return approval
}

export function controlApprovalScope(record) {
  return canonicalSha256({
    record_kind_code: record.record_kind_code, subject_identity_sha256: record.subject.subject_identity_sha256,
    operation_id: record.operation_id, operation_nonce: record.operation_nonce, reason_category_code: record.reason_category_code,
    restriction_scope_code: record.restriction_scope_code, basis_record_digest_sha256: record.basis_record_digest_sha256,
    corrects_record_digest_sha256: record.corrects_record_digest_sha256, effective_at: record.knowledge_boundary.effective_at,
  })
}

export function replaceApprovals(record, approvals) {
  const next = structuredClone(record); next.human_approvals = approvals; return sealD940Record(next)
}

export function makeAccessRecord({ fixture, kind, code, operationId, nonce, subject, semanticActor, persistenceActor, sequence, predecessor = null, targetKind, targetIdentity, triggerDigest }) {
  const persistedAt = fixture.time.reserve()
  const descriptor = targetKind === 'issued_descriptor'
  const accessTargetIdentity = canonicalSha256(descriptor
    ? { access_target_kind_code: targetKind, descriptor_lifecycle_record_digest_sha256: '3'.repeat(64), receiver_process_instance_code: 'receiver.synthetic.001' }
    : { access_target_kind_code: targetKind, capability_record_digest_sha256: '1'.repeat(64), capability_leaf_record_digest_sha256: '2'.repeat(64) })
  return sealD940Record({
    format: 'jedi-atlas-access-revocation-record', format_version: '1.0.0', record_kind_code: kind, record_code: code,
    operation_id: operationId, operation_nonce: nonce, subject,
    chain: { stream_code: `stream.access.${accessTargetIdentity.slice(0, 12)}`, sequence, predecessor_record_digest_sha256: predecessor },
    trigger_control_record_digest_sha256: triggerDigest, access_target_kind_code: targetKind, access_target_identity_sha256: accessTargetIdentity,
    capability_record_digest_sha256: descriptor ? null : '1'.repeat(64), capability_leaf_record_digest_sha256: descriptor ? null : '2'.repeat(64),
    descriptor_lifecycle_record_digest_sha256: descriptor ? '3'.repeat(64) : null,
    receiver_process_instance_code: descriptor ? 'receiver.synthetic.001' : null,
    sender_close_state_code: descriptor && kind !== 'descriptor_termination_requested' ? 'confirmed' : null,
    receiver_termination_state_code: descriptor && kind === 'descriptor_termination_confirmed' ? 'confirmed' : descriptor && kind === 'descriptor_termination_failed' ? 'unknown' : null,
    descriptor_close_state_code: descriptor && kind === 'descriptor_termination_confirmed' ? 'confirmed' : descriptor && kind === 'descriptor_termination_failed' ? 'unknown' : null,
    termination_disposition_code: descriptor && kind === 'descriptor_termination_confirmed' ? 'clean_exit_reaped' : descriptor && kind === 'descriptor_termination_failed' ? 'unknown' : null,
    semantic_actor: semanticActor, persistence_actor: persistenceActor,
    knowledge_boundary: { effective_at: new Date(Date.parse(persistedAt) - 2).toISOString(), recorded_at: new Date(Date.parse(persistedAt) - 1).toISOString(), persisted_at: persistedAt, journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: fixture.broker.head().sequence + 1 },
    record_digest_sha256: null,
  })
}

function inventoryFor(observed, artifact, { absent = false } = {}) {
  return {
    approved_primary_names_checked: 1, matching_primary_names: absent ? 0 : 1, open_descriptors: 0, hard_links: 0, unexpected_replicas: 0, temporary_objects: 0,
    backup_state_code: 'not_implemented', inventory_complete: true, target_file_type_code: absent ? 'absent' : 'regular_file',
    target_path_identity_sha256: canonicalSha256({ device: observed.targetDevice, inode: observed.targetInode, sha256: artifact.sha256 }),
    parent_directory_identity_sha256: canonicalSha256({ device: observed.parentDevice, inode: observed.parentInode }),
    target_device: absent ? null : observed.targetDevice, target_inode: absent ? null : observed.targetInode,
    parent_directory_device: observed.parentDevice, parent_directory_inode: observed.parentInode,
    observed_target_sha256: absent ? null : artifact.sha256, observed_target_byte_length: absent ? null : artifact.byte_length,
    observed_target_link_count: absent ? null : 1, prior_target_observation_record_digest_sha256: null,
    parent_directory_opened_no_follow: true, target_opened_no_follow: !absent, symlink_observed: false,
  }
}

export function makeExecutionRecord({ fixture, kind, code, operationId, nonce, subject, semanticActor, persistenceActor, sequence, predecessor = null, authorizationDigest, tombstoneDigest, authorizationScopeSha256, observed, artifact, head, projection, custodyEvidence, inventory = null, priorTargetObservationRecordDigest = null, effectiveAt = null }) {
  const persistedAt = fixture.time.reserve()
  const actualInventory = inventory ?? inventoryFor(observed, artifact, { absent: kind === 'primary_absence_verified' })
  if (kind === 'primary_absence_verified') actualInventory.prior_target_observation_record_digest_sha256 = priorTargetObservationRecordDigest
  const inventorySha256 = canonicalSha256(actualInventory)
  const snapshotMaterial = {
    journal_namespace_code: 'd940.global.control-journal.v1', known_through_receipt_sequence: head.sequence, known_through_persisted_at: head.persistedAt,
    control_ledger_head_receipt_digest_sha256: head.digest, control_head_projection_sha256: projection.projection_sha256,
    access_head_projection_sha256: projection.projection_sha256, subject_lineage_projection_sha256: custodyEvidence.subjectLineageProjectionSha256, custody_leaf_projection_sha256: custodyEvidence.custodyLeafProjectionSha256,
    inventory_snapshot_sha256: inventorySha256, active_hold_count: projection.active_hold ? 1 : 0, unknown_or_conflicting_control_count: 0,
  }
  const method = kind === 'unlink_attempted' ? 'unlink_primary_name_no_follow' : kind === 'primary_absence_verified' ? 'verify_primary_absence_no_follow' : 'none'
  const outcome = kind === 'unlink_attempted' ? 'primary_name_removed' : kind === 'primary_absence_verified' ? 'primary_absence_verified' : 'not_attempted'
  return sealD940Record({
    format: 'jedi-atlas-deletion-execution-record', format_version: '1.0.0', record_kind_code: kind, record_code: code,
    operation_id: operationId, operation_nonce: nonce, subject,
    chain: { stream_code: `stream.execution.${operationId}`, sequence, predecessor_record_digest_sha256: predecessor },
    deletion_authorization_record_digest_sha256: authorizationDigest, tombstone_record_digest_sha256: tombstoneDigest,
    authorization_scope_sha256: authorizationScopeSha256, d930_operational_profile_record_digest_sha256: custodyEvidence.d930OperationalProfileSha256, d930_primary_durability_receipt_sha256: custodyEvidence.d930PrimaryDurabilityReceiptSha256,
    safety_snapshot: { snapshot_sha256: canonicalSha256(snapshotMaterial), ...snapshotMaterial }, access_shutdown_state_code: 'confirmed', inventory: actualInventory,
    execution: { method_code: method, target_name_removed: kind === 'unlink_attempted' || kind === 'primary_absence_verified', directory_synced: kind === 'unlink_attempted' || kind === 'primary_absence_verified', reopened_target_absent: kind === 'unlink_attempted' || kind === 'primary_absence_verified', content_erase_claimed: false, complete_erasure_claimed: false, outcome_code: outcome },
    semantic_actor: semanticActor, persistence_actor: persistenceActor,
    knowledge_boundary: { effective_at: effectiveAt ?? new Date(Date.parse(persistedAt) - 1).toISOString(), recorded_at: new Date(Date.parse(persistedAt) - 1).toISOString(), persisted_at: persistedAt, journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: fixture.broker.head().sequence + 1 },
    record_digest_sha256: null,
  })
}

export function makeDeletionReceipt({ fixture, operationId, nonce, subject, requestDigest, authorizationDigest, tombstoneDigest, unlinkRecord, verificationRecord, authorizationScopeSha256, executor, verifier, persistenceActor, safetySnapshotSha256, custodyEvidence }) {
  const persistedAt = fixture.time.reserve()
  return sealD940Record({
    format: 'jedi-atlas-deletion-receipt', format_version: '1.0.0', record_code: `receipt.${operationId}`, operation_id: operationId, operation_nonce: nonce, subject,
    deletion_request_record_digest_sha256: requestDigest, deletion_authorization_record_digest_sha256: authorizationDigest, tombstone_record_digest_sha256: tombstoneDigest,
    execution_record_digest_sha256: unlinkRecord.record_digest_sha256, verification_record_digest_sha256: verificationRecord.record_digest_sha256,
    authorization_scope_sha256: authorizationScopeSha256, d930_operational_profile_record_digest_sha256: custodyEvidence.d930OperationalProfileSha256, d930_primary_durability_receipt_sha256: custodyEvidence.d930PrimaryDurabilityReceiptSha256,
    safety_snapshot_sha256: safetySnapshotSha256, control_ledger_head_receipt_digest_sha256: unlinkRecord.safety_snapshot.control_ledger_head_receipt_digest_sha256,
    executor, independent_verifier: verifier, outcome_code: 'primary_copy_absence_verified', proof_scope_code: 'approved_primary_namespace_observation_only',
    remaining_copy_classes: ['backup', 'derived', 'open_descriptor', 'replica', 'temporary', 'unknown'], metadata_retention_code: 'restricted_audit_digest_retained',
    complete_erasure_claimed: false, backup_erasure_claimed: false, legal_compliance_claimed: false,
    limitations: ['no_complete_erasure_claim', 'no_backup_erasure_claim', 'no_derived_copy_erasure_claim', 'no_replica_erasure_claim', 'no_open_descriptor_erasure_claim', 'no_storage_medium_overwrite_claim', 'no_legal_compliance_claim', 'compromised_kernel_or_root_out_of_scope', 'observation_is_time_bounded'],
    completed_at: new Date(Date.parse(persistedAt) - 1).toISOString(), persistence_actor: persistenceActor,
    knowledge_boundary: { effective_at: new Date(Date.parse(persistedAt) - 1).toISOString(), recorded_at: new Date(Date.parse(persistedAt) - 1).toISOString(), persisted_at: persistedAt, journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: fixture.broker.head().sequence + 1 },
    record_digest_sha256: null,
  })
}

export function recordBytes(record) { return Buffer.from(canonicalize(record), 'utf8') }
