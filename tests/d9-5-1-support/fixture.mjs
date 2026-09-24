import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { canonicalSha256, sha256Bytes } from '../../d9/control-plane/canonical.mjs'
import { createDurableNamespaceStore } from '../../d9/custody/durable-store.mjs'
import { loadD950ContractSet } from '../../d9/backup-restore/contracts.mjs'
import { createD951SyntheticAuthority } from '../../d9/backup-restore/session.mjs'
import { createD951BackupStore } from '../../d9/backup-restore/storage.mjs'
import { createD951History, D951_NAMESPACES } from '../../d9/backup-restore/history.mjs'
import { createD951Runtime, createD951SyntheticCheckpointResolver, createD951SyntheticControlResolver } from '../../d9/backup-restore/runtime.mjs'
import { createD941Fixture } from '../d9-4-1-support/fixture.mjs'

const ROLE_TO_RUNTIME = Object.freeze({
  backup_producer: 'backup_adapter', backup_verifier: 'independent_verifier', restore_requester: 'human_submitter',
  recovery_authority: 'recovery_operator', legal_records_authority: 'clearance_checker', privacy_authority: 'clearance_decider',
  restore_executor: 'cloner_promoter', control_state_verifier: 'independent_verifier', restored_state_verifier: 'independent_verifier',
  persistence_broker: 'journal_broker', trusted_launcher: 'trusted_launcher', drill_scheduler: 'trusted_launcher',
})

export async function createD951Fixture(t, { storeFault = null, runtimeFault = null } = {}) {
  const predecessor = await createD941Fixture(t)
  const contractSet = loadD950ContractSet()
  const roots = {}
  for (const code of ['backup', 'history', 'staging', 'promotion', 'sources']) {
    roots[code] = fs.mkdtempSync(path.join(os.tmpdir(), `jedi-d951-${code}-`)); fs.chmodSync(roots[code], 0o700)
  }
  t.after(() => { for (const root of Object.values(roots)) fs.rmSync(root, { recursive: true, force: true }) })
  let tick = Date.parse('2030-01-01T00:11:00.000Z')
  const clock = () => { const value = new Date(tick).toISOString(); tick += 1; return value }
  const authority = createD951SyntheticAuthority({ contractSet, authorityContext: predecessor.authorityContext, authorityRegistry: predecessor.registry, linuxEnforcement: predecessor.linux, handleRootPath: predecessor.roots.handle, trustedClock: clock })
  const sessions = new Map()
  for (const rule of contractSet.classifications.role_assignment_rules) {
    const binding = predecessor.byRole.get(ROLE_TO_RUNTIME[rule.semantic_role_code])
    const suffix = rule.semantic_role_code === 'restored_state_verifier' ? '02' : '01'
    sessions.set(rule.semantic_role_code, await authority.authenticate({ semanticRoleCode: rule.semantic_role_code, bindingCode: binding.binding_code, processInstanceCode: `process.${rule.semantic_role_code}.${suffix}`, authenticatedAt: clock() }))
  }
  const store = createDurableNamespaceStore({ rootPath: roots.history, namespaceCodes: D951_NAMESPACES, faultInjector: storeFault }); t.after(() => store.close())
  const backupStore = createD951BackupStore({ rootPath: roots.backup }); t.after(() => backupStore.close())
  const history = createD951History({ store, clock })
  const boundary = { observed_at: '2030-01-01T00:10:58.000Z', known_at: '2030-01-01T00:10:59.000Z', known_through_d940_receipt_sequence: 1, d940_state_head_digest_sha256: 'a'.repeat(64), d940_journal_tip_receipt_digest_sha256: 'b'.repeat(64), d940_correspondence_record_digest_sha256: 'c'.repeat(64) }
  const custodyEvidence = { evidence_type_code: 'custody_control', source_format: 'jedi-atlas-custody-control-record', source_record_kind_code: 'restriction_released', record_code: 'custody.control.synthetic.001', record_digest_sha256: 'f'.repeat(64), journal_receipt_record_digest_sha256: '3'.repeat(64), subject_identity_sha256: '1'.repeat(64), basis_record_digest_sha256: null, directive_code: null, resolver_response_record_digest_sha256: '4'.repeat(64), current_leaf: true, applicability_code: 'applies_currently' }
  const coordinationEvidence = { evidence_type_code: 'backup_coordination', source_format: 'jedi-atlas-backup-coordination-record', source_record_kind_code: 'restriction_directive', record_code: 'control.synthetic.001', record_digest_sha256: 'd'.repeat(64), journal_receipt_record_digest_sha256: 'e'.repeat(64), subject_identity_sha256: '1'.repeat(64), basis_record_digest_sha256: 'f'.repeat(64), directive_code: 'apply_restriction_before_restore', resolver_response_record_digest_sha256: '2'.repeat(64), current_leaf: true, applicability_code: 'applies_currently' }
  const evidence = [custodyEvidence]
  const directives = []
  const controlResolver = createD951SyntheticControlResolver({ subject_identity_sha256: '1'.repeat(64), boundary, evidence, directives })
  const source = (code, bytes, kind = 'evidence_artifact', layer = 'retrieved_body') => {
    const file = path.join(roots.sources, code); fs.writeFileSync(file, bytes, { mode: 0o600, flag: 'wx' })
    const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC); t.after(() => { try { fs.closeSync(descriptor) } catch {} })
    return { entry_kind_code: kind, stable_identity_code: code, byte_layer_code: layer, subject_identity_sha256: '1'.repeat(64), content_sha256: sha256Bytes(bytes), byte_length: bytes.length, source_record_digest_sha256: canonicalSha256({ code, hash: sha256Bytes(bytes) }), source_descriptor: descriptor }
  }
  const checkpoint = { checkpoint_code: 'checkpoint.synthetic.001', checkpoint_sequence: 1, checkpoint_record_digest_sha256: '3'.repeat(64), checkpoint_cas_sha256: '4'.repeat(64), source_state_head_digest_sha256: '5'.repeat(64), journal_tip_receipt_digest_sha256: '6'.repeat(64), correspondence_record_digest_sha256: '7'.repeat(64), logical_state_seal_record_digest_sha256: '8'.repeat(64), atlas_schema_digest_sha256: '9'.repeat(64), migration_ledger_digest_sha256: 'a'.repeat(64), captured_at: '2030-01-01T00:10:59.000Z' }
  const checkpointResolver = createD951SyntheticCheckpointResolver(checkpoint)
  const runtime = createD951Runtime({ contractSet, authority, backupStore, history, controlResolver, checkpointResolver, stagingRootPath: roots.staging, promotionRootPath: roots.promotion, clock, faultInjector: runtimeFault })
  t.after(() => runtime.close())
  const controlState = (directiveCode, sequence = 2) => {
    const custodyDigest = String(sequence + 2).repeat(64); const coordinationDigest = String(sequence + 3).repeat(64)
    const sourceKind = directiveCode === 'apply_tombstone_before_restore' ? 'tombstone_applied' : directiveCode === 'do_not_restore' ? 'hold_imposed' : 'restriction_imposed'
    const coordinationKind = directiveCode === 'apply_tombstone_before_restore' ? 'tombstone_directive' : directiveCode === 'do_not_restore' ? 'restore_guard' : 'restriction_directive'
    return { subject_identity_sha256: '1'.repeat(64), boundary: { ...boundary, known_through_d940_receipt_sequence: sequence, d940_state_head_digest_sha256: String(sequence).repeat(64) }, evidence: [{ ...custodyEvidence, record_digest_sha256: custodyDigest, journal_receipt_record_digest_sha256: String(sequence + 4).repeat(64), source_record_kind_code: sourceKind }, { ...coordinationEvidence, record_digest_sha256: coordinationDigest, journal_receipt_record_digest_sha256: String(sequence + 5).repeat(64), source_record_kind_code: coordinationKind, basis_record_digest_sha256: custodyDigest, directive_code: directiveCode }], directives: [{ directive_code: directiveCode, d940_coordination_record_digest_sha256: coordinationDigest, basis_control_record_digest_sha256: custodyDigest, disposition_code: directiveCode === 'apply_restriction_before_restore' ? 'applied_before_exposure' : 'restore_withheld' }] }
  }
  return { ...predecessor, contractSet, roots, clock, authority, sessions, store, backupStore, history, controlResolver, checkpointResolver, controlState, runtime, source, checkpoint }
}

export function backupArgs(fixture, suffix = '001') {
  return { operationId: `backup.operation.${suffix}`, operationNonce: String(Number(suffix) + 1).padStart(64, '0'), backupSetCode: `backup.set.${suffix}`, checkpoint: fixture.checkpoint, sources: [fixture.source(`database_${suffix}`, Buffer.from(`synthetic database ${suffix}\n`), 'atlas_database', 'sqlite_database'), fixture.source(`source_${suffix}`, Buffer.from(`synthetic source ${suffix}\n`)), fixture.source(`control_${suffix}`, Buffer.from(`synthetic control ${suffix}\n`), 'protected_control_record', 'protected_record_bytes')], producerSession: fixture.sessions.get('backup_producer'), verifierSession: fixture.sessions.get('backup_verifier'), persistenceSession: fixture.sessions.get('persistence_broker') }
}

export function authorizationArgs(fixture, manifest, suffix = '001') {
  const operationId = `restore.operation.${suffix}`
  const targetEnvironment = targetFor(fixture, operationId)
  const base = { operationId, operationNonce: `f${suffix}`.padEnd(64, '0'), manifest, targetEnvironmentIdentitySha256: canonicalSha256(targetEnvironment), persistenceSession: fixture.sessions.get('persistence_broker'), validUntil: '2030-01-01T01:00:00.000Z' }
  const approvalRecords = ['recovery_authority', 'legal_records_authority', 'privacy_authority'].map((role) => fixture.runtime.submitRestoreApproval({ ...base, approverSession: fixture.sessions.get(role) }))
  return { ...base, requesterSession: fixture.sessions.get('restore_requester'), approvalRecords }
}

export function restoreArgs(fixture, manifest, authorization) {
  if (!fixture.history.records('retention-controls').some((item) => item.backup_set_code === manifest.backup_set_code)) {
    fixture.runtime.recordRetention({ manifest, decisionCode: 'retain', retainUntil: '2031-01-01T00:00:00.000Z', holdStateCode: 'none_known', reasonCode: 'initial_retention', authoritySession: fixture.sessions.get('legal_records_authority'), persistenceSession: fixture.sessions.get('persistence_broker') })
    fixture.runtime.attestRetentionHead({ manifest, operationId: `retention.${authorization.operation_id}`, operationNonce: authorization.operation_nonce, verifierSession: fixture.sessions.get('control_state_verifier'), persistenceSession: fixture.sessions.get('persistence_broker') })
    const states = ['primary', 'backup', 'derived', 'temporary', 'replica', 'open_descriptor', 'unknown'].map((copy_class_code) => ({ copy_class_code, state_code: copy_class_code === 'backup' ? 'present' : 'absent_verified' }))
    fixture.runtime.assessDeletionAware({ operationId: `assessment.${authorization.operation_id}`, operationNonce: authorization.operation_nonce, manifest, copyClassStates: states, verifierSession: fixture.sessions.get('control_state_verifier'), persistenceSession: fixture.sessions.get('persistence_broker') })
  }
  return { authorization, manifest, requesterSession: fixture.sessions.get('restore_requester'), executorSession: fixture.sessions.get('restore_executor'), controlVerifierSession: fixture.sessions.get('control_state_verifier'), restoredVerifierSession: fixture.sessions.get('restored_state_verifier'), persistenceSession: fixture.sessions.get('persistence_broker'), targetEnvironment: targetFor(fixture, authorization.operation_id) }
}

function targetFor(fixture, code) {
  return { target_environment_code: `target.synthetic.${code}`, target_kind_code: 'disposable_restore_candidate', runtime_profile_record_digest_sha256: fixture.generation.runtimeProfile.record_digest_sha256, identity_bindings_record_digest_sha256: fixture.generation.identityBindings.record_digest_sha256, binding_generation: fixture.generation.identityBindings.binding_generation, migration_set_digest_sha256: '7'.repeat(64), target_root_identity_sha256: canonicalSha256({ code }), preexisting_state_code: 'empty_verified' }
}
