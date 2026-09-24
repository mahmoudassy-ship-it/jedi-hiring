import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { canonicalSha256, sha256Bytes } from '../../d9/control-plane/canonical.mjs'
import { createDurableNamespaceStore } from '../../d9/custody/durable-store.mjs'
import { loadD950ContractSet } from '../../d9/backup-restore/contracts.mjs'
import { createD951SyntheticAuthority } from '../../d9/backup-restore/session.mjs'
import { createD951BackupStore } from '../../d9/backup-restore/storage.mjs'
import { createD951History, D951_NAMESPACES } from '../../d9/backup-restore/history.mjs'
import { createD951Runtime, createD951SyntheticControlResolver } from '../../d9/backup-restore/runtime.mjs'
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
  const controlResolver = createD951SyntheticControlResolver({ head_sequence: 1, head_digest_sha256: 'a'.repeat(64), directives: [{ directive_code: 'apply_restriction_before_restore', basis_record_digest_sha256: 'b'.repeat(64) }] })
  const runtime = createD951Runtime({ contractSet, authority, backupStore, history, controlResolver, stagingRootPath: roots.staging, promotionRootPath: roots.promotion, clock, faultInjector: runtimeFault })
  t.after(() => runtime.close())
  const source = (code, bytes, kind = 'evidence_artifact', layer = 'retrieved_body') => {
    const file = path.join(roots.sources, code); fs.writeFileSync(file, bytes, { mode: 0o600, flag: 'wx' })
    const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC); t.after(() => { try { fs.closeSync(descriptor) } catch {} })
    return { entry_kind_code: kind, stable_identity_code: code, byte_layer_code: layer, subject_identity_sha256: '1'.repeat(64), content_sha256: sha256Bytes(bytes), byte_length: bytes.length, source_record_digest_sha256: canonicalSha256({ code, hash: sha256Bytes(bytes) }), source_descriptor: descriptor }
  }
  const checkpoint = { record_digest_sha256: '3'.repeat(64), source_state_head_digest_sha256: '4'.repeat(64), journal_tip_receipt_digest_sha256: '5'.repeat(64), captured_at: '2030-01-01T00:10:59.000Z' }
  return { ...predecessor, contractSet, roots, clock, authority, sessions, store, backupStore, history, controlResolver, runtime, source, checkpoint }
}

export function backupArgs(fixture, suffix = '001') {
  return { operationId: `backup.operation.${suffix}`, operationNonce: String(Number(suffix) + 1).padStart(64, '0'), backupSetCode: `backup.set.${suffix}`, checkpoint: fixture.checkpoint, sources: [fixture.source(`source_${suffix}`, Buffer.from(`synthetic source ${suffix}\n`))], producerSession: fixture.sessions.get('backup_producer'), verifierSession: fixture.sessions.get('backup_verifier'), persistenceSession: fixture.sessions.get('persistence_broker') }
}

export function authorizationArgs(fixture, manifest, suffix = '001') {
  return { operationId: `restore.operation.${suffix}`, operationNonce: `f${suffix}`.padEnd(64, '0'), manifest, targetEnvironmentIdentitySha256: '9'.repeat(64), requesterSession: fixture.sessions.get('restore_requester'), approvalSessions: [fixture.sessions.get('recovery_authority'), fixture.sessions.get('legal_records_authority'), fixture.sessions.get('privacy_authority')], persistenceSession: fixture.sessions.get('persistence_broker'), validUntil: '2030-01-01T01:00:00.000Z' }
}

export function restoreArgs(fixture, manifest, authorization) {
  return { authorization, manifest, executorSession: fixture.sessions.get('restore_executor'), controlVerifierSession: fixture.sessions.get('control_state_verifier'), restoredVerifierSession: fixture.sessions.get('restored_state_verifier'), persistenceSession: fixture.sessions.get('persistence_broker'), expectedTargetIdentitySha256: authorization.target_environment_identity_sha256 }
}
