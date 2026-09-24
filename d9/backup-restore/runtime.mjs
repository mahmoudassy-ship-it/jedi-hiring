import fs from 'node:fs'
import path from 'node:path'
import { canonicalSha256, sha256Bytes } from '../control-plane/canonical.mjs'
import { assertD951Authority } from './session.mjs'
import { assertD951BackupStore } from './storage.mjs'
import { assertSha, assertTimestamp, sealD951 } from './contracts.mjs'
import { failD951 } from './errors.mjs'

const runtimes = new WeakSet()
const resolvers = new WeakSet()
const COPY_CLASSES = Object.freeze(['primary', 'backup', 'derived', 'temporary', 'replica', 'open_descriptor', 'unknown'])
const STAGES = Object.freeze(['authorized', 'staging_started', 'bytes_reconstructed_inaccessible', 'controls_revalidated', 'controls_applied', 'staged_state_verified', 'promotion_started', 'promoted', 'post_promotion_verified', 'completed'])

function assertCode(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(value)) failD951('D951_CODE_INVALID', `${label} is outside the closed code shape`)
  return value
}

function ensurePrivateRoot(rootPath) {
  if (!path.isAbsolute(rootPath) || rootPath.includes('\0')) failD951('D951_ROOT_INVALID', 'root must be a configured absolute path')
  const status = fs.lstatSync(rootPath, { bigint: true })
  if (!status.isDirectory() || status.isSymbolicLink() || (status.mode & 0o077n) !== 0n || status.uid !== BigInt(process.getuid())) failD951('D951_ROOT_INVALID', 'root must be owned, private, and not a symlink')
  const descriptor = fs.openSync(rootPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  const opened = fs.fstatSync(descriptor, { bigint: true })
  if (opened.dev !== status.dev || opened.ino !== status.ino) { fs.closeSync(descriptor); failD951('D951_ROOT_INVALID', 'root changed while it was opened') }
  return { dev: status.dev, ino: status.ino, descriptor }
}

function exactSource(entry) {
  assertCode(entry.stable_identity_code, 'source identity')
  assertSha(entry.content_sha256, 'source content')
  if (!Number.isSafeInteger(entry.byte_length) || entry.byte_length < 0 || !Number.isInteger(entry.source_descriptor) || entry.source_descriptor < 0) failD951('D951_SOURCE_INVALID', 'source length and descriptor must be exact')
  const before = fs.fstatSync(entry.source_descriptor, { bigint: true })
  if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(entry.byte_length)) failD951('D951_SOURCE_INVALID', 'source is not a single-link regular file of exact length')
  const bytes = Buffer.alloc(entry.byte_length)
  let offset = 0
  while (offset < bytes.length) {
    const count = fs.readSync(entry.source_descriptor, bytes, offset, bytes.length - offset, offset)
    if (count <= 0) failD951('D951_SOURCE_INVALID', 'source ended before its declared length')
    offset += count
  }
  const after = fs.fstatSync(entry.source_descriptor, { bigint: true })
  for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) if (before[key] !== after[key]) failD951('D951_SOURCE_CHANGED', 'source changed during collection')
  if (sha256Bytes(bytes) !== entry.content_sha256) failD951('D951_SOURCE_MISMATCH', 'source bytes do not match the declared hash')
  return bytes
}

export function createD951SyntheticControlResolver(initialSnapshot) {
  let snapshot = structuredClone(initialSnapshot)
  function validate(value) {
    if (!value || !Number.isSafeInteger(value.head_sequence) || value.head_sequence < 0 || typeof value.head_digest_sha256 !== 'string' || !Array.isArray(value.directives)) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'control resolver returned incomplete state')
    assertSha(value.head_digest_sha256, 'control head')
    for (const directive of value.directives) if (!['apply_restriction_before_restore', 'do_not_restore', 'apply_tombstone_before_restore'].includes(directive.directive_code)) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'unknown control directive')
    return Object.freeze(structuredClone(value))
  }
  validate(snapshot)
  const resolver = Object.freeze({
    resolve() { return validate(snapshot) },
    replaceForSyntheticTest(next) { snapshot = structuredClone(validate(next)) },
  })
  resolvers.add(resolver)
  return resolver
}

export function createD951Runtime({ contractSet, authority, backupStore, history, controlResolver, stagingRootPath, promotionRootPath, clock, faultInjector = null }) {
  assertD951Authority(authority); assertD951BackupStore(backupStore)
  if (!contractSet?.classifications || !history?.append || !resolvers.has(controlResolver) || typeof clock !== 'function') failD951('D951_RUNTIME_INVALID', 'runtime dependencies are not trusted')
  const stagingRootIdentity = ensurePrivateRoot(stagingRootPath)
  const promotionRootIdentity = ensurePrivateRoot(promotionRootPath)
  if (stagingRootIdentity.dev === promotionRootIdentity.dev && stagingRootIdentity.ino === promotionRootIdentity.ino) { fs.closeSync(stagingRootIdentity.descriptor); fs.closeSync(promotionRootIdentity.descriptor); failD951('D951_ROOT_INVALID', 'staging and promotion roots must be distinct') }
  const stagingRoot = `/proc/self/fd/${stagingRootIdentity.descriptor}`
  const promotionRoot = `/proc/self/fd/${promotionRootIdentity.descriptor}`
  let closed = false
  const usedOperations = new Map()

  function now() { return assertTimestamp(clock(), 'trusted runtime time') }
  function assertOpen() {
    if (closed) failD951('D951_RUNTIME_CLOSED', 'runtime is closed')
    for (const identity of [stagingRootIdentity, promotionRootIdentity]) {
      const current = fs.fstatSync(identity.descriptor, { bigint: true })
      if (!current.isDirectory() || current.dev !== identity.dev || current.ino !== identity.ino || current.uid !== BigInt(process.getuid()) || (current.mode & 0o077n) !== 0n) failD951('D951_ROOT_INVALID', 'opened runtime root is no longer private and stable')
    }
  }
  function session(value, role) { return authority.revalidate(value, role, now()) }
  function operationKey(id, nonce) { assertCode(id, 'operation id'); assertSha(nonce, 'operation nonce'); return `${id}/${nonce}` }
  function priorOperation(id, nonce, requestDigest) {
    const prior = usedOperations.get(operationKey(id, nonce))
    if (prior && prior.requestDigest !== requestDigest) failD951('D951_OPERATION_REPLAY', 'operation identity was reused with different content')
    return prior
  }
  function rememberOperation(id, nonce, requestDigest, result) {
    usedOperations.set(operationKey(id, nonce), { requestDigest, result })
    return result
  }
  function manifests() { return history.records('backup-manifests').toSorted((a, b) => a.backup_chain_sequence - b.backup_chain_sequence) }

  const runtime = Object.freeze({
    createBackup({ operationId, operationNonce, backupSetCode, checkpoint, sources, producerSession, verifierSession, persistenceSession }) {
      assertOpen()
      session(producerSession, 'backup_producer'); session(verifierSession, 'backup_verifier'); session(persistenceSession, 'persistence_broker')
      if (producerSession.bindingCode === verifierSession.bindingCode) failD951('D951_SEPARATION_VIOLATION', 'backup producer and verifier must differ')
      assertCode(backupSetCode, 'backup set'); assertSha(checkpoint.record_digest_sha256, 'checkpoint')
      if (!Array.isArray(sources) || sources.length === 0 || new Set(sources.map((item) => item.stable_identity_code)).size !== sources.length) failD951('D951_INVENTORY_INVALID', 'source inventory must be nonempty and unique')
      const requestDigest = canonicalSha256({ operation_id: operationId, operation_nonce: operationNonce, backup_set_code: backupSetCode, checkpoint, sources: sources.map(({ source_descriptor: ignored, ...source }) => source) })
      const priorOperationResult = priorOperation(operationId, operationNonce, requestDigest)
      if (priorOperationResult) {
        for (const source of sources) exactSource(source)
        return Object.freeze({ ...priorOperationResult.result, replay: true })
      }
      const inventory = []; const copies = []
      for (const [index, source] of sources.entries()) {
        exactSource(source)
        const identity = { hash_algorithm_code: 'sha256', sha256: source.content_sha256, byte_length: source.byte_length }
        const stored = backupStore.put({ identity, sourceDescriptor: source.source_descriptor })
        const copy = { copy_code: `copy.${backupSetCode}.${String(index + 1).padStart(4, '0')}`, copy_class_code: 'backup', backend_code: stored.backend_code, backend_reference: stored.backend_reference, artifact: { artifact_code: source.stable_identity_code, byte_layer_code: source.byte_layer_code, ...identity }, copy_identity_sha256: canonicalSha256({ backend_code: stored.backend_code, backend_reference: stored.backend_reference, identity }) }
        inventory.push({ ordinal: index + 1, entry_kind_code: source.entry_kind_code, stable_identity_code: source.stable_identity_code, byte_layer_code: source.byte_layer_code, subject_identity_sha256: source.subject_identity_sha256, content_sha256: source.content_sha256, byte_length: source.byte_length, source_record_digest_sha256: source.source_record_digest_sha256 })
        copies.push(copy)
      }
      const prior = manifests().at(-1) ?? null
      const createdAt = now()
      const manifest = sealD951({ format: 'jedi-atlas-backup-manifest', format_version: '1.0.0', record_code: `backup-manifest-${String((prior?.backup_chain_sequence ?? 0) + 1).padStart(8, '0')}`, operation_id: operationId, operation_nonce: operationNonce, backup_set_code: backupSetCode, backup_chain_sequence: (prior?.backup_chain_sequence ?? 0) + 1, previous_backup_manifest_record_digest_sha256: prior?.record_digest_sha256 ?? null, source_checkpoint: checkpoint, source_inventory: inventory, source_inventory_digest_sha256: canonicalSha256(inventory), backup_copies: copies, backup_copy_inventory_digest_sha256: canonicalSha256(copies), producer_binding_code: producerSession.bindingCode, verifier_binding_code: verifierSession.bindingCode, created_at: createdAt, persisted_at: createdAt, technical_claims: { evidence_accepted: false, legal_authority_verified: false, publication_authorized: false, complete_erasure_claimed: false }, record_digest_sha256: null })
      const persisted = history.append({ namespaceCode: 'backup-manifests', record: manifest, semanticSession: producerSession, persistenceSession })
      const receipts = []
      for (const copy of copies) {
        const receipt = sealD951({ format: 'jedi-atlas-backup-durability-receipt', format_version: '1.0.0', record_code: `backup-receipt-${copy.copy_code}`, receipt_kind_code: copy.artifact.byte_layer_code === 'sqlite_database' ? 'prior_database' : 'source_copy', operation_id: operationId, operation_nonce: operationNonce, backup_set_code: backupSetCode, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, source_checkpoint_record_digest_sha256: checkpoint.record_digest_sha256, copy_identity: copy, verification: { exact_hash_and_length: true, independently_reopened: true }, durability: { no_replace_enforced: true, file_data_synced: true, parent_directory_synced: true }, completed_at: createdAt, persisted_at: createdAt, technical_claims: manifest.technical_claims, record_digest_sha256: null })
        receipts.push(history.append({ namespaceCode: 'backup-receipts', record: receipt, semanticSession: verifierSession, persistenceSession }).record)
      }
      const result = Object.freeze({ manifest: persisted.record, manifestReceipt: persisted.receipt, durabilityReceipts: Object.freeze(receipts), replay: false })
      return rememberOperation(operationId, operationNonce, requestDigest, result)
    },

    authorizeRestore({ operationId, operationNonce, manifest, targetEnvironmentIdentitySha256, requesterSession, approvalSessions, persistenceSession, validUntil }) {
      assertOpen()
      session(requesterSession, 'restore_requester'); session(persistenceSession, 'persistence_broker')
      const required = ['recovery_authority', 'legal_records_authority', 'privacy_authority']
      if (!Array.isArray(approvalSessions) || approvalSessions.length !== 3) failD951('D951_APPROVALS_INVALID', 'restore needs exactly three human approvals')
      required.forEach((role, index) => session(approvalSessions[index], role))
      const bindings = [requesterSession, ...approvalSessions].map((item) => item.bindingCode)
      if (new Set(bindings).size !== bindings.length || approvalSessions.some((item) => item.actorKindCode !== 'human')) failD951('D951_APPROVALS_INVALID', 'requester and approvals must be four distinct humans')
      const persistedAt = now(); assertTimestamp(validUntil, 'authorization expiry')
      if (persistedAt >= validUntil) failD951('D951_APPROVALS_EXPIRED', 'restore authorization must be current')
      const scope = { operation_id: operationId, operation_nonce: operationNonce, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, target_environment_identity_sha256: targetEnvironmentIdentitySha256 }
      const requestDigest = canonicalSha256({ ...scope, approval_binding_codes: approvalSessions.map((item) => item.bindingCode), valid_until: validUntil })
      const prior = priorOperation(operationId, operationNonce, requestDigest)
      if (prior) return prior.result
      const record = sealD951({ format: 'jedi-atlas-restore-authorization', format_version: '1.0.0', record_code: `restore-authorization-${operationId}`, operation_id: operationId, operation_nonce: operationNonce, requester_binding_code: requesterSession.bindingCode, backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, source_checkpoint_record_digest_sha256: manifest.source_checkpoint.record_digest_sha256, target_environment_identity_sha256: targetEnvironmentIdentitySha256, authorization_scope_sha256: canonicalSha256(scope), approvals: required.map((role, index) => ({ role_code: role, binding_code: approvalSessions[index].bindingCode })), valid_from: persistedAt, valid_until: validUntil, persisted_at: persistedAt, technical_claims: manifest.technical_claims, record_digest_sha256: null })
      const result = history.append({ namespaceCode: 'restore-authorizations', record, semanticSession: requesterSession, persistenceSession }).record
      return rememberOperation(operationId, operationNonce, requestDigest, result)
    },

    recordRetention({ manifest, decisionCode, retainUntil, holdStateCode, reasonCode, authoritySession, persistenceSession }) {
      assertOpen()
      session(authoritySession, 'legal_records_authority'); session(persistenceSession, 'persistence_broker')
      if (!['retain', 'hold', 'release'].includes(decisionCode) || !['none', 'active', 'released'].includes(holdStateCode)) failD951('D951_RETENTION_INVALID', 'retention decision is outside the frozen vocabulary')
      assertTimestamp(retainUntil, 'retention end')
      const prior = history.records('retention-controls').filter((item) => item.backup_set_code === manifest.backup_set_code).toSorted((a, b) => a.chain.sequence - b.chain.sequence).at(-1) ?? null
      const persistedAt = now()
      const record = sealD951({ format: 'jedi-atlas-retention-control-record', format_version: '1.0.0', record_code: `retention-${manifest.backup_set_code}-${String((prior?.chain.sequence ?? 0) + 1).padStart(4, '0')}`, chain: { stream_code: `retention.${manifest.backup_set_code}`, sequence: (prior?.chain.sequence ?? 0) + 1, predecessor_record_digest_sha256: prior?.record_digest_sha256 ?? null }, backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, decision_code: decisionCode, retention_class_code: 'synthetic_pilot', retain_until: retainUntil, hold_state_code: holdStateCode, deletion_authority_present: false, reason_code: reasonCode, semantic_actor_binding_code: authoritySession.bindingCode, persistence_actor_binding_code: persistenceSession.bindingCode, effective_at: persistedAt, recorded_at: persistedAt, persisted_at: persistedAt, technical_claims: manifest.technical_claims, record_digest_sha256: null })
      return history.append({ namespaceCode: 'retention-controls', record, semanticSession: authoritySession, persistenceSession }).record
    },

    attestRetentionHead({ manifest, operationId, operationNonce, verifierSession, persistenceSession }) {
      assertOpen()
      session(verifierSession, 'control_state_verifier'); session(persistenceSession, 'persistence_broker')
      const controls = history.records('retention-controls').filter((item) => item.backup_set_code === manifest.backup_set_code).toSorted((a, b) => a.chain.sequence - b.chain.sequence)
      const leaf = controls.at(-1)
      if (!leaf) failD951('D951_RETENTION_HEAD_MISSING', 'retention head cannot be attested without a control record')
      const observedAt = now()
      const record = sealD951({ format: 'jedi-atlas-retention-head-attestation', format_version: '1.0.0', record_code: `retention-head-${operationId}`, operation_id: operationId, operation_nonce: operationNonce, backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, namespace_code: 'd950.retention.controls.v1', head_sequence: leaf.chain.sequence, head_record_digest_sha256: leaf.record_digest_sha256, head_receipt_record_digest_sha256: history.head().record_digest_sha256, head_receipt_persisted_at: history.head().persisted_at, observed_by_binding_code: verifierSession.bindingCode, observed_at: observedAt, known_at: observedAt, technical_claims: manifest.technical_claims, record_digest_sha256: null })
      return history.append({ namespaceCode: 'retention-heads', record, semanticSession: verifierSession, persistenceSession }).record
    },

    assessDeletionAware({ operationId, operationNonce, manifest, copyClassStates, verifierSession, persistenceSession }) {
      assertOpen()
      session(verifierSession, 'control_state_verifier'); session(persistenceSession, 'persistence_broker')
      const inventory = runtime.inventoryCopyClasses(copyClassStates)
      const controls = controlResolver.resolve(); const blocked = controls.directives.some((item) => ['do_not_restore', 'apply_tombstone_before_restore'].includes(item.directive_code))
      const evaluatedAt = now()
      const record = sealD951({ format: 'jedi-atlas-deletion-aware-reconstruction', format_version: '1.0.0', record_code: `deletion-aware-${operationId}`, operation_id: operationId, operation_nonce: operationNonce, backup_set_code: manifest.backup_set_code, subject_identity_sha256: manifest.source_inventory[0].subject_identity_sha256, source_checkpoint_record_digest_sha256: manifest.source_checkpoint.record_digest_sha256, control_snapshot: controls, control_directives: controls.directives, copy_class_inventory: inventory.states, copy_class_inventory_digest_sha256: inventory.digest, control_state_code: blocked ? 'restore_blocked' : 'controls_current', restore_disposition_code: blocked ? 'restore_withheld' : 'eligible_for_inaccessible_reconstruction', bytes_accessible: false, bounded_copy_classes_complete: true, complete_erasure_claimed: false, limitations: ['bounded_inventory_only', 'no_complete_erasure_claim', 'technical_evidence_only'], semantic_verifier_binding_code: verifierSession.bindingCode, persistence_broker_binding_code: persistenceSession.bindingCode, evaluated_at: evaluatedAt, persisted_at: evaluatedAt, technical_claims: manifest.technical_claims, record_digest_sha256: null })
      return history.append({ namespaceCode: 'deletion-aware', record, semanticSession: verifierSession, persistenceSession }).record
    },

    recordDrill({ drillCode, manifest, expectedInventoryDigestSha256, observedInventoryDigestSha256, schedulerSession, verifierSession, persistenceSession }) {
      assertOpen()
      session(schedulerSession, 'drill_scheduler'); session(verifierSession, 'restored_state_verifier'); session(persistenceSession, 'persistence_broker')
      assertCode(drillCode, 'drill code'); assertSha(expectedInventoryDigestSha256, 'expected inventory'); assertSha(observedInventoryDigestSha256, 'observed inventory')
      const completedAt = now(); const passed = expectedInventoryDigestSha256 === observedInventoryDigestSha256
      const record = sealD951({ format: 'jedi-atlas-restore-drill-record', format_version: '1.0.0', record_code: `drill-${drillCode}`, drill_code: drillCode, backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, expected_inventory_digest_sha256: expectedInventoryDigestSha256, restored_inventory_digest_sha256: observedInventoryDigestSha256, outcome_code: passed ? 'passed' : 'failed', escalation_code: passed ? 'none' : 'reconciliation_required', scheduler_binding_code: schedulerSession.bindingCode, independent_verifier_binding_code: verifierSession.bindingCode, persistence_broker_binding_code: persistenceSession.bindingCode, started_at: completedAt, completed_at: completedAt, technical_claims: manifest.technical_claims, record_digest_sha256: null })
      return history.append({ namespaceCode: 'restore-drills', record, semanticSession: verifierSession, persistenceSession }).record
    },

    restore({ authorization, manifest, executorSession, controlVerifierSession, restoredVerifierSession, persistenceSession, expectedTargetIdentitySha256 }) {
      assertOpen()
      session(executorSession, 'restore_executor'); session(controlVerifierSession, 'control_state_verifier'); session(restoredVerifierSession, 'restored_state_verifier'); session(persistenceSession, 'persistence_broker')
      if (executorSession.bindingCode === restoredVerifierSession.bindingCode || controlVerifierSession.processInstanceCode === restoredVerifierSession.processInstanceCode) failD951('D951_SEPARATION_VIOLATION', 'executor and verifier or verifier processes are not distinct')
      const at = now()
      if (authorization.valid_from > at || at >= authorization.valid_until || authorization.backup_manifest_record_digest_sha256 !== manifest.record_digest_sha256 || authorization.target_environment_identity_sha256 !== expectedTargetIdentitySha256) failD951('D951_AUTHORIZATION_INVALID', 'authorization is expired or bound to different inputs')
      const initialControls = controlResolver.resolve()
      if (initialControls.directives.some((item) => item.directive_code === 'do_not_restore')) return Object.freeze({ outcomeCode: 'withheld', recoveryCode: 'safe_no_effect', stages: Object.freeze([]) })
      const stageName = `restore-${authorization.operation_id}`
      if (!SAFE_STAGE.test(stageName)) failD951('D951_STAGE_INVALID', 'staging name is invalid')
      const stagePath = path.join(stagingRoot, stageName)
      const promotedPath = path.join(promotionRoot, stageName)
      if (fs.existsSync(stagePath) || fs.existsSync(promotedPath)) failD951('D951_REPLAY_COLLISION', 'restore target already exists')
      fs.mkdirSync(stagePath, { mode: 0o700 }); const lifecycle = []
      const appendStage = (stageCode, roleSession, bytesAccessible = false, promoted = false) => {
        const record = sealD951({ format: 'jedi-atlas-restore-lifecycle-record', format_version: '1.0.0', record_code: `restore-${authorization.operation_id}-${String(lifecycle.length + 1).padStart(2, '0')}`, operation_id: authorization.operation_id, operation_nonce: authorization.operation_nonce, chain: { sequence: lifecycle.length + 1, predecessor_record_digest_sha256: lifecycle.at(-1)?.record_digest_sha256 ?? null }, restore_plan_record_digest_sha256: authorization.record_digest_sha256, authorization_record_digest_sha256: authorization.record_digest_sha256, stage_code: stageCode, outcome_code: stageCode === 'completed' ? 'succeeded' : 'progress', error_code: 'none', retryability_code: 'not_retryable', bytes_accessible: bytesAccessible, atomic_promotion_observed: promoted, source_checkpoint_record_digest_sha256: manifest.source_checkpoint.record_digest_sha256, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, control_snapshot: { head_sequence: initialControls.head_sequence, head_digest_sha256: initialControls.head_digest_sha256 }, restored_inventory_digest_sha256: stageCode === 'staged_state_verified' || promoted ? manifest.source_inventory_digest_sha256 : null, semantic_actor_binding_code: roleSession.bindingCode, event_at: now(), persisted_at: now(), technical_claims: manifest.technical_claims, record_digest_sha256: null })
        lifecycle.push(history.append({ namespaceCode: 'restore-lifecycle', record, semanticSession: roleSession, persistenceSession }).record)
        faultInjector?.(`after_${stageCode}`, { stagePath, promotedPath })
      }
      appendStage('authorized', executorSession); appendStage('staging_started', executorSession)
      for (const copy of manifest.backup_copies) {
        const bytes = backupStore.read({ identity: copy.artifact, backendReference: copy.backend_reference })
        const file = path.join(stagePath, `${String(copy.artifact.artifact_code).replaceAll('.', '_')}.bin`)
        fs.writeFileSync(file, bytes, { mode: 0o600, flag: 'wx' }); const fd = fs.openSync(file, 'r'); try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
      }
      appendStage('bytes_reconstructed_inaccessible', executorSession)
      const revalidated = controlResolver.resolve()
      if (canonicalSha256(revalidated) !== canonicalSha256(initialControls)) failD951('D951_CONTROL_MOVED', 'control head moved during restore')
      appendStage('controls_revalidated', controlVerifierSession)
      fs.writeFileSync(path.join(stagePath, '.controls.json'), JSON.stringify(revalidated), { mode: 0o600, flag: 'wx' })
      appendStage('controls_applied', executorSession)
      const files = fs.readdirSync(stagePath).toSorted(); const stagedDigest = canonicalSha256(files.map((name) => ({ name, sha256: sha256Bytes(fs.readFileSync(path.join(stagePath, name))) })))
      if (files.length !== manifest.backup_copies.length + 1) failD951('D951_RESTORE_MISMATCH', 'staged inventory is incomplete')
      appendStage('staged_state_verified', restoredVerifierSession); appendStage('promotion_started', executorSession)
      const finalControls = controlResolver.resolve()
      if (canonicalSha256(finalControls) !== canonicalSha256(initialControls)) failD951('D951_CONTROL_MOVED', 'control head moved before promotion')
      fs.renameSync(stagePath, promotedPath); fs.fsyncSync(promotionRootIdentity.descriptor)
      appendStage('promoted', executorSession, true, true)
      const promotedFiles = fs.readdirSync(promotedPath).toSorted(); const promotedDigest = canonicalSha256(promotedFiles.map((name) => ({ name, sha256: sha256Bytes(fs.readFileSync(path.join(promotedPath, name))) })))
      if (promotedDigest !== stagedDigest) failD951('D951_PROMOTION_MISMATCH', 'promoted generation differs from independently verified staging')
      appendStage('post_promotion_verified', restoredVerifierSession, true, true); appendStage('completed', restoredVerifierSession, true, true)
      return Object.freeze({ outcomeCode: 'succeeded', recoveryCode: 'complete', lifecycle: Object.freeze(lifecycle), promotedPath, inventoryDigestSha256: promotedDigest })
    },

    classifyCrash(boundaryCode) {
      const map = { before_staging: 'safe_no_effect', after_staging_before_controls: 'retain_inaccessible_and_reconcile', after_controls_before_verification: 'retain_inaccessible_and_reconcile', after_verification_before_promotion: 'retain_inaccessible_and_reconcile', after_promotion_before_post_verification: 'recovery_required_no_automatic_rollback', after_verification_before_receipt: 'recovery_required_exact_replay_only', after_receipt_before_response: 'exact_replay_no_op_after_full_revalidation' }
      if (!map[boundaryCode]) failD951('D951_CRASH_BOUNDARY_UNKNOWN', 'crash boundary is not closed')
      return Object.freeze({ boundaryCode, classificationCode: map[boundaryCode], actionAuthorized: false })
    },

    inventoryCopyClasses(states) {
      assertOpen()
      if (!Array.isArray(states) || states.length !== COPY_CLASSES.length || states.map((item) => item.copy_class_code).join('|') !== COPY_CLASSES.join('|')) failD951('D951_COPY_INVENTORY_INCOMPLETE', 'all seven copy classes are required in canonical order')
      if (states.some((item) => !['present', 'absent_verified', 'unknown'].includes(item.state_code))) failD951('D951_COPY_INVENTORY_INVALID', 'copy class state is outside the closed vocabulary')
      return Object.freeze({ states: structuredClone(states), completeErasureClaimed: false, digest: canonicalSha256(states) })
    },
    close() {
      if (!closed) { closed = true; runtimes.delete(runtime); fs.closeSync(stagingRootIdentity.descriptor); fs.closeSync(promotionRootIdentity.descriptor) }
    },
  })
  runtimes.add(runtime)
  return runtime
}

const SAFE_STAGE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u
