import fs from 'node:fs'
import path from 'node:path'
import { canonicalSha256, sha256Bytes } from '../control-plane/canonical.mjs'
import { assertD951Authority } from './session.mjs'
import { assertD951BackupStore } from './storage.mjs'
import { assertSha, assertTimestamp, deepFreeze, sealD951, validateD950Record } from './contracts.mjs'
import { failD951 } from './errors.mjs'

const runtimes = new WeakSet()
const resolvers = new WeakSet()
const checkpointResolvers = new WeakSet()
const approvalDecisions = new WeakSet()
const approvalDecisionSessions = new WeakMap()
const COPY_CLASSES = Object.freeze(['primary', 'backup', 'derived', 'temporary', 'replica', 'open_descriptor', 'unknown'])
const STAGES = Object.freeze(['authorized', 'staging_started', 'bytes_reconstructed_inaccessible', 'controls_revalidated', 'controls_applied', 'staged_state_verified', 'promotion_started', 'promoted', 'post_promotion_verified', 'completed'])
const TECHNICAL_CLAIMS = Object.freeze({ evidence_acceptance_claimed: false, officiality_claimed: false, legal_authority_claimed: false, legal_compliance_claimed: false, publication_eligibility_claimed: false, complete_erasure_claimed: false })

function claims() { return { ...TECHNICAL_CLAIMS } }
function actor(session) { return structuredClone(session.actor) }

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

function readPrivateDirectoryInventory(directory) {
  const status = fs.lstatSync(directory, { bigint: true })
  if (!status.isDirectory() || status.isSymbolicLink() || status.uid !== BigInt(process.getuid()) || (status.mode & 0o077n) !== 0n) failD951('D951_RESTORE_MISMATCH', 'restore generation is not an exact private directory')
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try {
    const pinned = `/proc/self/fd/${descriptor}`
    const files = fs.readdirSync(pinned).toSorted()
    return deepFreeze({ files, digest: canonicalSha256(files.map((name) => ({ name, sha256: sha256Bytes(fs.readFileSync(path.join(pinned, name))) }))) })
  } finally { fs.closeSync(descriptor) }
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
    if (!value || !value.boundary || !Array.isArray(value.evidence) || value.evidence.length === 0 || !Array.isArray(value.directives) || !value.subject_identity_sha256) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'control resolver returned incomplete subject-bound state')
    for (const key of ['d940_state_head_digest_sha256', 'd940_correspondence_record_digest_sha256']) assertSha(value.boundary[key], `control boundary ${key}`)
    if (!Number.isSafeInteger(value.boundary.known_through_d940_receipt_sequence) || value.boundary.known_through_d940_receipt_sequence < 0) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'control receipt boundary is invalid')
    const evidenceByDigest = new Map()
    for (const item of value.evidence) {
      if (item.subject_identity_sha256 !== value.subject_identity_sha256 || item.current_leaf !== true || evidenceByDigest.has(item.record_digest_sha256)) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'control evidence is not a unique current leaf for the subject')
      evidenceByDigest.set(item.record_digest_sha256, item)
    }
    const mapping = new Map([['restriction_imposed', ['apply_restriction_before_restore', 'applied_before_exposure']], ['hold_imposed', ['do_not_restore', 'restore_withheld']], ['tombstone_applied', ['apply_tombstone_before_restore', 'restore_withheld']]])
    const coordinationKinds = new Map([['restriction_directive', 'apply_restriction_before_restore'], ['restore_guard', 'do_not_restore'], ['tombstone_directive', 'apply_tombstone_before_restore']])
    const used = new Set()
    for (const directive of value.directives) {
      if (!['apply_restriction_before_restore', 'do_not_restore', 'apply_tombstone_before_restore'].includes(directive.directive_code)) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'unknown control directive')
      const coordination = evidenceByDigest.get(directive.d940_coordination_record_digest_sha256)
      const basis = evidenceByDigest.get(directive.basis_control_record_digest_sha256)
      const expected = basis && mapping.get(basis.source_record_kind_code)
      if (!coordination || coordination.evidence_type_code !== 'backup_coordination' || coordinationKinds.get(coordination.source_record_kind_code) !== directive.directive_code || coordination.directive_code !== directive.directive_code || coordination.basis_record_digest_sha256 !== directive.basis_control_record_digest_sha256 || !expected || expected[0] !== directive.directive_code || expected[1] !== directive.disposition_code || basis.evidence_type_code !== 'custody_control' || used.has(basis.record_digest_sha256)) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'control directive does not exactly satisfy its current evidence')
      used.add(basis.record_digest_sha256); used.add(coordination.record_digest_sha256)
    }
    for (const item of value.evidence) {
      const required = mapping.has(item.source_record_kind_code) || coordinationKinds.has(item.source_record_kind_code)
      if (required !== used.has(item.record_digest_sha256)) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'blocking evidence and directives are not reverse-complete')
    }
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

export function createD951SyntheticCheckpointResolver(initialCheckpoint) {
  let checkpoint = structuredClone(initialCheckpoint)
  const resolver = Object.freeze({
    resolve() { return deepFreeze(structuredClone(checkpoint)) },
    replaceForSyntheticTest(next) { checkpoint = structuredClone(next) },
  })
  checkpointResolvers.add(resolver)
  return resolver
}

export function createD951Runtime({ contractSet, authority, backupStore, history, controlResolver, checkpointResolver, stagingRootPath, promotionRootPath, clock, faultInjector = null }) {
  assertD951Authority(authority); assertD951BackupStore(backupStore)
  if (!contractSet?.classifications || !history?.append || !resolvers.has(controlResolver) || !checkpointResolvers.has(checkpointResolver) || typeof clock !== 'function') failD951('D951_RUNTIME_INVALID', 'runtime dependencies are not trusted')
  const stagingRootIdentity = ensurePrivateRoot(stagingRootPath)
  const promotionRootIdentity = ensurePrivateRoot(promotionRootPath)
  if (stagingRootIdentity.dev === promotionRootIdentity.dev && stagingRootIdentity.ino === promotionRootIdentity.ino) { fs.closeSync(stagingRootIdentity.descriptor); fs.closeSync(promotionRootIdentity.descriptor); failD951('D951_ROOT_INVALID', 'staging and promotion roots must be distinct') }
  if (stagingRootIdentity.dev !== promotionRootIdentity.dev) { fs.closeSync(stagingRootIdentity.descriptor); fs.closeSync(promotionRootIdentity.descriptor); failD951('D951_ROOT_INVALID', 'staging and promotion roots must share one filesystem for atomic generation rename') }
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
  function manifests() {
    history.verifyComplete()
    const values = history.records('backup-manifests').toSorted((a, b) => a.backup_chain_sequence - b.backup_chain_sequence)
    let previous = null
    for (const [index, value] of values.entries()) {
      validateD950Record('backup-manifest-v1.schema.json', value)
      if (value.backup_chain_sequence !== index + 1 || value.previous_backup_manifest_record_digest_sha256 !== previous) failD951('D951_BACKUP_CHAIN_INVALID', 'backup manifest chain is gapped, forked, or rolled back')
      previous = value.record_digest_sha256
    }
    return values
  }
  function persistedExact(namespace, candidate, schema) {
    validateD950Record(schema, candidate)
    const stored = history.records(namespace).find((item) => item.record_code === candidate.record_code && item.record_digest_sha256 === candidate.record_digest_sha256)
    if (!stored || canonicalSha256(stored) !== canonicalSha256(candidate)) failD951('D951_PERSISTED_RECORD_MISMATCH', `${namespace} input is not the exact protected record`)
    return stored
  }
  function verifyBackupProjection(manifest) {
    history.verifyComplete(); validateD950Record('backup-manifest-v1.schema.json', manifest)
    const coverage = manifest.source_inventory.map((item, index) => ({ source_stable_identity_code: item.stable_identity_code, copy_codes: [manifest.backup_copies[index]?.copy_code] }))
    if (canonicalSha256({ source_checkpoint: manifest.source_checkpoint, source_inventory: manifest.source_inventory, source_copy_coverage: coverage }) !== manifest.source_inventory_digest_sha256 || canonicalSha256(coverage) !== canonicalSha256(manifest.source_copy_coverage) || canonicalSha256([...manifest.backup_copies].sort((a, b) => a.copy_code.localeCompare(b.copy_code))) !== manifest.backup_copy_inventory_digest_sha256) failD951('D951_BACKUP_PROJECTION_MISMATCH', 'manifest inventory or coverage projection differs')
    for (const [index, copy] of manifest.backup_copies.entries()) {
      const source = manifest.source_inventory[index]
      if (!source || copy.artifact.artifact_code !== source.stable_identity_code || copy.artifact.sha256 !== source.content_sha256 || copy.artifact.byte_length !== source.byte_length || copy.artifact.byte_layer_code !== source.byte_layer_code) failD951('D951_BACKUP_PROJECTION_MISMATCH', 'copy identity differs from source inventory')
      backupStore.read({ identity: copy.artifact, backendReference: copy.backend_reference })
    }
    const receipts = history.records('backup-receipts').filter((item) => item.backup_manifest_record_digest_sha256 === manifest.record_digest_sha256)
    for (const receipt of receipts) validateD950Record('backup-durability-receipt-v1.schema.json', receipt)
    const sources = receipts.filter((item) => item.receipt_kind_code === 'source_copy')
    const prior = receipts.filter((item) => item.receipt_kind_code === 'prior_database')
    const final = receipts.filter((item) => item.receipt_kind_code === 'final_consistent_set')
    if (sources.length !== manifest.backup_copies.length || prior.length !== 1 || final.length !== 1 || receipts.length !== manifest.backup_copies.length + 2) failD951('D951_BACKUP_PROJECTION_MISMATCH', 'durability receipt projection is incomplete or ambiguous')
    for (const copy of manifest.backup_copies) {
      const receipt = sources.find((item) => item.copy_identity.copy_code === copy.copy_code)
      const scope = { copy_code: copy.copy_code, artifact: copy.artifact, operation_id: manifest.operation_id, operation_nonce: manifest.operation_nonce }
      if (!receipt || canonicalSha256(receipt.copy_identity) !== canonicalSha256(copy) || receipt.scope_sha256 !== canonicalSha256(scope) || canonicalSha256(receipt.scope) !== canonicalSha256(scope)) failD951('D951_BACKUP_PROJECTION_MISMATCH', 'source-copy receipt does not bind the exact copy')
    }
    const databaseCopy = manifest.backup_copies.find((copy) => copy.artifact.byte_layer_code === 'sqlite_database')
    if (!databaseCopy || canonicalSha256(prior[0].copy_identity) !== canonicalSha256(databaseCopy)) failD951('D951_BACKUP_PROJECTION_MISMATCH', 'prior-database receipt does not bind the database copy')
    const constituent = [...sources, prior[0]].map((item) => item.record_digest_sha256)
    if (canonicalSha256(final[0].scope.constituent_receipt_record_digests) !== canonicalSha256(constituent) || final[0].scope.inventory_digest_sha256 !== manifest.source_inventory_digest_sha256) failD951('D951_BACKUP_PROJECTION_MISMATCH', 'final consistent-set receipt is not complete')
    const manifestReceipt = history.records('global-journal').find((item) => item.target_record_digest_sha256 === manifest.record_digest_sha256 && item.target_record_code === manifest.record_code)
    if (!manifestReceipt) failD951('D951_BACKUP_PROJECTION_MISMATCH', 'manifest journal receipt is missing')
    return deepFreeze({ manifest, manifestReceipt, durabilityReceipts: receipts })
  }
  function currentRetention(manifest) {
    const retention = history.records('retention-controls').filter((item) => item.backup_set_code === manifest.backup_set_code).toSorted((a, b) => a.chain.sequence - b.chain.sequence).at(-1)
    const retentionHead = history.records('retention-heads').filter((item) => item.backup_set_code === manifest.backup_set_code).toSorted((a, b) => a.head_sequence - b.head_sequence).at(-1)
    if (!retention || !retentionHead || retentionHead.head_record_digest_sha256 !== retention.record_digest_sha256 || retentionHead.head_sequence !== retention.chain.sequence || retention.decision_code !== 'retain' || retention.hold_state_code !== 'none_known') failD951('D951_RESTORE_PREREQUISITE_MISSING', 'current retention leaf is not affirmatively retained and attested')
    return deepFreeze({ retention, retentionHead })
  }

  const runtime = Object.freeze({
    createBackup({ operationId, operationNonce, backupSetCode, checkpoint, sources, producerSession, verifierSession, persistenceSession }) {
      assertOpen()
      session(producerSession, 'backup_producer'); session(verifierSession, 'backup_verifier'); session(persistenceSession, 'persistence_broker')
      if (producerSession.bindingCode === verifierSession.bindingCode) failD951('D951_SEPARATION_VIOLATION', 'backup producer and verifier must differ')
      assertCode(backupSetCode, 'backup set')
      const resolvedCheckpoint = checkpointResolver.resolve()
      if (canonicalSha256(resolvedCheckpoint) !== canonicalSha256(checkpoint)) failD951('D951_CHECKPOINT_INVALID', 'checkpoint differs from the trusted resolver output')
      for (const key of ['checkpoint_record_digest_sha256', 'checkpoint_cas_sha256', 'source_state_head_digest_sha256', 'correspondence_record_digest_sha256', 'logical_state_seal_record_digest_sha256', 'atlas_schema_digest_sha256', 'migration_ledger_digest_sha256']) assertSha(checkpoint[key], `checkpoint ${key}`)
      if (!Number.isSafeInteger(checkpoint.checkpoint_sequence) || checkpoint.checkpoint_sequence < 1 || !checkpoint.checkpoint_code) failD951('D951_CHECKPOINT_INVALID', 'v1.3 checkpoint identity is incomplete')
      assertTimestamp(checkpoint.captured_at, 'checkpoint capture')
      if (!Array.isArray(sources) || sources.length < 3 || !sources.some((item) => item.entry_kind_code === 'atlas_database') || new Set(sources.map((item) => item.stable_identity_code)).size !== sources.length) failD951('D951_INVENTORY_INVALID', 'complete source inventory requires unique entries and an Atlas database')
      const requestDigest = canonicalSha256({ operation_id: operationId, operation_nonce: operationNonce, backup_set_code: backupSetCode, checkpoint, sources: sources.map(({ source_descriptor: ignored, ...source }) => source) })
      const priorOperationResult = priorOperation(operationId, operationNonce, requestDigest)
      if (priorOperationResult) {
        for (const source of sources) exactSource(source)
        const verified = verifyBackupProjection(priorOperationResult.result.manifest)
        return deepFreeze({ ...verified, replay: true })
      }
      const expectedInventory = sources.map((source, index) => ({ ordinal: index + 1, entry_kind_code: source.entry_kind_code, stable_identity_code: source.stable_identity_code, byte_layer_code: source.byte_layer_code, subject_identity_sha256: source.subject_identity_sha256, content_sha256: source.content_sha256, byte_length: source.byte_length, source_record_digest_sha256: source.source_record_digest_sha256 }))
      const persistedOperation = manifests().find((item) => item.operation_id === operationId || item.operation_nonce === operationNonce)
      if (persistedOperation) {
        for (const source of sources) exactSource(source)
        if (persistedOperation.operation_id !== operationId || persistedOperation.operation_nonce !== operationNonce || persistedOperation.backup_set_code !== backupSetCode || canonicalSha256(persistedOperation.source_checkpoint) !== canonicalSha256(checkpoint) || canonicalSha256(persistedOperation.source_inventory) !== canonicalSha256(expectedInventory)) failD951('D951_OPERATION_REPLAY', 'persisted operation identity maps to different backup inputs')
        const result = deepFreeze({ ...verifyBackupProjection(persistedOperation), replay: true })
        return rememberOperation(operationId, operationNonce, requestDigest, result)
      }
      const inventory = []; const copies = []
      for (const [index, source] of sources.entries()) {
        exactSource(source)
        const identity = { hash_algorithm_code: 'sha256', sha256: source.content_sha256, byte_length: source.byte_length }
        const stored = backupStore.put({ identity, sourceDescriptor: source.source_descriptor })
        const copyBase = { copy_code: `copy.${backupSetCode}.${String(index + 1).padStart(4, '0')}`, copy_class_code: 'backup', backend_code: stored.backend_code, backend_generation: 1, backend_reference: stored.backend_reference, artifact: { artifact_code: source.stable_identity_code, byte_layer_code: source.byte_layer_code, ...identity } }
        const copy = { ...copyBase, copy_identity_sha256: canonicalSha256(copyBase) }
        inventory.push({ ordinal: index + 1, entry_kind_code: source.entry_kind_code, stable_identity_code: source.stable_identity_code, byte_layer_code: source.byte_layer_code, subject_identity_sha256: source.subject_identity_sha256, content_sha256: source.content_sha256, byte_length: source.byte_length, source_record_digest_sha256: source.source_record_digest_sha256 })
        copies.push(copy)
      }
      const prior = manifests().at(-1) ?? null
      const createdAt = now()
      const coverage = inventory.map((item, index) => ({ source_stable_identity_code: item.stable_identity_code, copy_codes: [copies[index].copy_code] }))
      const manifest = sealD951({ format: 'jedi-atlas-backup-set-manifest', format_version: '1.0.0', record_code: `backup-manifest-${String((prior?.backup_chain_sequence ?? 0) + 1).padStart(8, '0')}`, operation_id: operationId, operation_nonce: operationNonce, backup_set_code: backupSetCode, backup_chain_sequence: (prior?.backup_chain_sequence ?? 0) + 1, previous_backup_manifest_record_digest_sha256: prior?.record_digest_sha256 ?? null, source_checkpoint: checkpoint, source_inventory: inventory, source_inventory_digest_sha256: canonicalSha256({ source_checkpoint: checkpoint, source_inventory: inventory, source_copy_coverage: coverage }), backup_copies: copies, source_copy_coverage: coverage, backup_copy_inventory_digest_sha256: canonicalSha256([...copies].sort((a, b) => a.copy_code.localeCompare(b.copy_code))), retention: { retention_class_code: 'pilot_short_term', retain_until: '2031-01-01T00:00:00.000Z', hold_state_code: 'none_known', expiry_action_code: 'human_review_required_no_automatic_deletion' }, producer: actor(producerSession), persistence_broker: actor(persistenceSession), created_at: createdAt, persisted_at: createdAt, technical_claims: claims(), record_digest_sha256: null })
      validateD950Record('backup-manifest-v1.schema.json', manifest)
      const persisted = history.append({ namespaceCode: 'backup-manifests', record: manifest, semanticSession: producerSession, persistenceSession })
      const receipts = []
      for (const copy of copies) {
        const scope = { copy_code: copy.copy_code, artifact: copy.artifact, operation_id: operationId, operation_nonce: operationNonce }
        const receipt = sealD951({ format: 'jedi-atlas-backup-durability-receipt', format_version: '1.0.0', record_code: `backup-receipt-${copy.copy_code}`, receipt_kind_code: 'source_copy', scope_profile_code: 'source_copy_operation_nonce_v1', scope, scope_sha256: canonicalSha256(scope), backup_profile_record_digest_sha256: canonicalSha256({ contract: contractSet.catalog, generation: producerSession.generationDigest }), operation_id: operationId, operation_nonce: operationNonce, backup_set_code: backupSetCode, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, source_checkpoint_record_digest_sha256: checkpoint.checkpoint_record_digest_sha256, copy_identity: copy, verification: { outcome_code: 'passed', recomputed_sha256: copy.artifact.sha256, recomputed_byte_length: copy.artifact.byte_length, manifest_match: true, source_checkpoint_match: true }, durability: { no_replace_enforced: true, object_data_synchronized: true, parent_namespace_synchronized: true, final_reopen_rehash_passed: true, bounded_durability_code: 'component_observation_not_power_loss_guarantee' }, producer: actor(producerSession), independent_verifier: actor(verifierSession), persistence_broker: actor(persistenceSession), completed_at: createdAt, persisted_at: createdAt, technical_claims: claims(), record_digest_sha256: null })
        validateD950Record('backup-durability-receipt-v1.schema.json', receipt)
        receipts.push(history.append({ namespaceCode: 'backup-receipts', record: receipt, semanticSession: verifierSession, persistenceSession }).record)
      }
      const databaseCopy = copies.find((copy) => copy.artifact.byte_layer_code === 'sqlite_database')
      const priorScope = { bundle: { bundle_id: `bundle.${backupSetCode}`, bundle_sequence: manifest.backup_chain_sequence, bundle_digest_sha256: manifest.record_digest_sha256 }, prior_logical_state: { state_seal_code: checkpoint.checkpoint_code, state_seal_record_digest_sha256: checkpoint.logical_state_seal_record_digest_sha256, logical_state_sha256: checkpoint.source_state_head_digest_sha256 }, database_generation: manifest.backup_chain_sequence, operation_id: operationId, operation_nonce: operationNonce }
      const priorReceipt = sealD951({ format: 'jedi-atlas-backup-durability-receipt', format_version: '1.0.0', record_code: `backup-receipt-prior-${manifest.backup_chain_sequence}`, receipt_kind_code: 'prior_database', scope_profile_code: 'prior_logical_state_database_generation_operation_nonce_v1', scope: priorScope, scope_sha256: canonicalSha256(priorScope), backup_profile_record_digest_sha256: canonicalSha256({ contract: contractSet.catalog, generation: producerSession.generationDigest }), operation_id: operationId, operation_nonce: operationNonce, backup_set_code: backupSetCode, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, source_checkpoint_record_digest_sha256: checkpoint.checkpoint_record_digest_sha256, copy_identity: databaseCopy, verification: { outcome_code: 'passed', recomputed_sha256: databaseCopy.artifact.sha256, recomputed_byte_length: databaseCopy.artifact.byte_length, manifest_match: true, source_checkpoint_match: true }, durability: { no_replace_enforced: true, object_data_synchronized: true, parent_namespace_synchronized: true, final_reopen_rehash_passed: true, bounded_durability_code: 'component_observation_not_power_loss_guarantee' }, producer: actor(producerSession), independent_verifier: actor(verifierSession), persistence_broker: actor(persistenceSession), completed_at: createdAt, persisted_at: createdAt, technical_claims: claims(), record_digest_sha256: null })
      validateD950Record('backup-durability-receipt-v1.schema.json', priorReceipt); receipts.push(history.append({ namespaceCode: 'backup-receipts', record: priorReceipt, semanticSession: verifierSession, persistenceSession }).record)
      const h = history.head(); const finalScope = { bundle: priorScope.bundle, resulting_logical_state: priorScope.prior_logical_state, receipt_head: { journal_namespace_code: 'd950.global.journal.v1', receipt_sequence: h.receipt_sequence, receipt_record_digest_sha256: h.record_digest_sha256, receipt_persisted_at: h.persisted_at }, constituent_receipt_record_digests: receipts.map((item) => item.record_digest_sha256), inventory_digest_sha256: manifest.source_inventory_digest_sha256, operation_id: operationId, operation_nonce: operationNonce }
      const finalReceipt = sealD951({ ...structuredClone(priorReceipt), record_code: `backup-receipt-final-${manifest.backup_chain_sequence}`, receipt_kind_code: 'final_consistent_set', scope_profile_code: 'resulting_logical_state_receipt_head_inventory_operation_nonce_v1', scope: finalScope, scope_sha256: canonicalSha256(finalScope), record_digest_sha256: null })
      validateD950Record('backup-durability-receipt-v1.schema.json', finalReceipt); receipts.push(history.append({ namespaceCode: 'backup-receipts', record: finalReceipt, semanticSession: verifierSession, persistenceSession }).record)
      const verified = verifyBackupProjection(persisted.record)
      const result = deepFreeze({ ...verified, replay: false })
      return rememberOperation(operationId, operationNonce, requestDigest, result)
    },

    submitRestoreApproval({ operationId, operationNonce, manifest, targetEnvironmentIdentitySha256, approverSession, persistenceSession, validUntil }) {
      assertOpen(); session(persistenceSession, 'persistence_broker')
      const persistedManifest = persistedExact('backup-manifests', manifest, 'backup-manifest-v1.schema.json')
      const role = approverSession?.semanticRoleCode
      if (!['recovery_authority', 'legal_records_authority', 'privacy_authority'].includes(role)) failD951('D951_APPROVALS_INVALID', 'approval must be submitted by one exact required human role')
      session(approverSession, role)
      if (approverSession.actorKindCode !== 'human' || approverSession.bindingCode === persistenceSession.bindingCode) failD951('D951_APPROVALS_INVALID', 'approval needs a distinct authenticated human')
      const decidedAt = now(); assertTimestamp(validUntil, 'approval expiry')
      if (decidedAt >= validUntil) failD951('D951_APPROVALS_EXPIRED', 'approval must be current')
      const scope = { operation_id: operationId, operation_nonce: operationNonce, backup_manifest_record_digest_sha256: persistedManifest.record_digest_sha256, target_environment_identity_sha256: targetEnvironmentIdentitySha256 }
      const scopeSha256 = canonicalSha256(scope)
      const decisionPayload = { approval_code: `approval.${operationId}.${role}`, decision_code: 'approve_restore', scope_sha256: scopeSha256, actor: actor(approverSession), decided_at: decidedAt, valid_until: validUntil }
      const decisionPayloadSha256 = canonicalSha256(decisionPayload)
      const requestSha256 = canonicalSha256({ format: 'jedi-atlas-d951-approval-submission', operation_id: operationId, operation_nonce: operationNonce, sender: approverSession.actor, recipient: persistenceSession.actor, payload_record_digest_sha256: decisionPayloadSha256 })
      const responseSha256 = canonicalSha256({ format: 'jedi-atlas-d951-approval-broker-response', request_digest_sha256: requestSha256, outcome_code: 'accepted', persistence_actor: persistenceSession.actor })
      const decision = sealD951({ ...decisionPayload, decision_payload_sha256: decisionPayloadSha256, submission_request_record_digest_sha256: requestSha256, broker_response_record_digest_sha256: responseSha256, record_digest_sha256: null })
      approvalDecisions.add(decision); approvalDecisionSessions.set(decision, approverSession)
      return decision
    },

    authorizeRestore({ operationId, operationNonce, manifest, targetEnvironmentIdentitySha256, requesterSession, approvalRecords, persistenceSession, validUntil }) {
      assertOpen()
      session(requesterSession, 'restore_requester'); session(persistenceSession, 'persistence_broker')
      manifest = persistedExact('backup-manifests', manifest, 'backup-manifest-v1.schema.json')
      const required = ['recovery_authority', 'legal_records_authority', 'privacy_authority']
      if (!Array.isArray(approvalRecords) || approvalRecords.length !== 3 || approvalRecords.some((item) => !approvalDecisions.has(item))) failD951('D951_APPROVALS_INVALID', 'restore needs three exact decisions from the fixed approval broker')
      const approvalSessions = approvalRecords.map((item) => approvalDecisionSessions.get(item))
      required.forEach((role, index) => { if (approvalSessions[index]?.semanticRoleCode !== role) failD951('D951_APPROVALS_INVALID', 'approval roles are missing or reordered'); session(approvalSessions[index], role) })
      const bindings = [requesterSession, ...approvalSessions].map((item) => item.bindingCode)
      if (new Set(bindings).size !== bindings.length || approvalSessions.some((item) => item.actorKindCode !== 'human')) failD951('D951_APPROVALS_INVALID', 'requester and approvals must be four distinct humans')
      const persistedAt = now(); assertTimestamp(validUntil, 'authorization expiry')
      if (persistedAt >= validUntil) failD951('D951_APPROVALS_EXPIRED', 'restore authorization must be current')
      const scope = { operation_id: operationId, operation_nonce: operationNonce, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, target_environment_identity_sha256: targetEnvironmentIdentitySha256 }
      const scopeSha256 = canonicalSha256(scope)
      if (approvalRecords.some((item) => item.scope_sha256 !== scopeSha256 || item.valid_until !== validUntil || item.decided_at > persistedAt)) failD951('D951_APPROVALS_INVALID', 'approval does not bind the exact authorization scope and validity')
      const requestDigest = canonicalSha256({ ...scope, approval_record_digests: approvalRecords.map((item) => item.record_digest_sha256), valid_until: validUntil })
      const prior = priorOperation(operationId, operationNonce, requestDigest)
      if (prior) return prior.result
      const record = sealD951({ format: 'jedi-atlas-restore-authorization', format_version: '1.0.0', record_code: `restore-authorization-${operationId}`, operation_id: operationId, operation_nonce: operationNonce, requester: actor(requesterSession), backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, source_checkpoint_record_digest_sha256: manifest.source_checkpoint.checkpoint_record_digest_sha256, target_environment_identity_sha256: targetEnvironmentIdentitySha256, authorization_scope_sha256: scopeSha256, approvals: approvalRecords, valid_from: persistedAt, valid_until: validUntil, persistence_broker: actor(persistenceSession), persisted_at: persistedAt, technical_claims: claims(), record_digest_sha256: null })
      validateD950Record('restore-authorization-v1.schema.json', record)
      const result = history.append({ namespaceCode: 'restore-authorizations', record, semanticSession: requesterSession, persistenceSession }).record
      return rememberOperation(operationId, operationNonce, requestDigest, result)
    },

    recordRetention({ manifest, decisionCode, retainUntil, holdStateCode, reasonCode, authoritySession, persistenceSession }) {
      assertOpen()
      session(authoritySession, 'legal_records_authority'); session(persistenceSession, 'persistence_broker')
      const retentionRule = contractSet.classifications.retention_rules.decision_state_matrix.find((item) => item.decision_code === decisionCode)
      if (!retentionRule || retentionRule.hold_state_code !== holdStateCode || !retentionRule.allowed_reason_codes.includes(reasonCode)) failD951('D951_RETENTION_INVALID', 'retention decision/state/reason is outside the frozen matrix')
      assertTimestamp(retainUntil, 'retention end')
      const prior = history.records('retention-controls').filter((item) => item.backup_set_code === manifest.backup_set_code).toSorted((a, b) => a.chain.sequence - b.chain.sequence).at(-1) ?? null
      const persistedAt = now()
      const record = sealD951({ format: 'jedi-atlas-backup-retention-control', format_version: '1.0.0', record_code: `retention-${manifest.backup_set_code}-${String((prior?.chain.sequence ?? 0) + 1).padStart(4, '0')}`, chain: { namespace_code: 'd950.retention.controls.v1', sequence: (prior?.chain.sequence ?? 0) + 1, previous_record_digest_sha256: prior?.record_digest_sha256 ?? null }, backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, decision_code: decisionCode, retention_class_code: decisionCode === 'hold' ? 'legal_hold' : 'pilot_short_term', retain_until: retainUntil, hold_state_code: holdStateCode, deletion_authority_present: false, reason_code: reasonCode, semantic_actor: actor(authoritySession), persistence_actor: actor(persistenceSession), effective_at: persistedAt, recorded_at: persistedAt, persisted_at: persistedAt, technical_claims: claims(), record_digest_sha256: null })
      validateD950Record('retention-control-record-v1.schema.json', record)
      return history.append({ namespaceCode: 'retention-controls', record, semanticSession: authoritySession, persistenceSession }).record
    },

    attestRetentionHead({ manifest, operationId, operationNonce, verifierSession, persistenceSession }) {
      assertOpen()
      session(verifierSession, 'control_state_verifier'); session(persistenceSession, 'persistence_broker')
      const controls = history.records('retention-controls').filter((item) => item.backup_set_code === manifest.backup_set_code).toSorted((a, b) => a.chain.sequence - b.chain.sequence)
      const leaf = controls.at(-1)
      if (!leaf) failD951('D951_RETENTION_HEAD_MISSING', 'retention head cannot be attested without a control record')
      const observedAt = now()
      const receiptHead = history.head()
      const record = sealD951({ format: 'jedi-atlas-retention-head-attestation', format_version: '1.0.0', record_code: `retention-head-${operationId}`, operation_id: operationId, operation_nonce: operationNonce, backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, namespace_code: 'd950.retention.controls.v1', head_sequence: leaf.chain.sequence, head_record_digest_sha256: leaf.record_digest_sha256, head_receipt_record_digest_sha256: receiptHead.record_digest_sha256, head_receipt_persisted_at: receiptHead.persisted_at, observed_by: actor(verifierSession), observed_at: observedAt, known_at: observedAt, technical_claims: claims(), record_digest_sha256: null })
      validateD950Record('retention-head-attestation-v1.schema.json', record)
      return history.append({ namespaceCode: 'retention-heads', record, semanticSession: verifierSession, persistenceSession }).record
    },

    assessDeletionAware({ operationId, operationNonce, manifest, copyClassStates, verifierSession, persistenceSession }) {
      assertOpen()
      session(verifierSession, 'control_state_verifier'); session(persistenceSession, 'persistence_broker')
      const inventory = runtime.inventoryCopyClasses(copyClassStates)
      const controls = controlResolver.resolve(); const blockedDirective = controls.directives.find((item) => ['do_not_restore', 'apply_tombstone_before_restore'].includes(item.directive_code))
      const evaluatedAt = now()
      const disposition = blockedDirective?.directive_code === 'apply_tombstone_before_restore' ? 'withheld_tombstoned' : blockedDirective ? 'withheld_do_not_restore' : controls.directives.length === 0 || controls.directives.some((item) => item.directive_code === 'apply_restriction_before_restore') ? 'eligible_with_controls' : 'reconciliation_required'
      const record = sealD951({ format: 'jedi-atlas-deletion-aware-reconstruction', format_version: '1.0.0', record_code: `deletion-aware-${operationId}`, operation_id: operationId, operation_nonce: operationNonce, backup_set_code: manifest.backup_set_code, subject_identity_sha256: manifest.source_inventory[0].subject_identity_sha256, source_checkpoint_record_digest_sha256: manifest.source_checkpoint.checkpoint_record_digest_sha256, control_snapshot: controls.boundary, control_evidence: controls.evidence, control_directives: controls.directives, copy_class_inventory: inventory.states, copy_class_inventory_digest_sha256: inventory.digest, control_state_code: 'complete_current_consistent', restore_disposition_code: disposition, bytes_accessible: false, bounded_copy_classes_complete: true, complete_erasure_claimed: false, limitations: ['bounded_registered_copy_classes_only', 'hidden_or_unregistered_copies_not_excluded', 'open_descriptor_inventory_is_runtime_bounded', 'storage_media_remanence_not_assessed', 'legal_compliance_not_assessed', 'technical_recovery_evidence_only'], semantic_verifier: actor(verifierSession), persistence_broker: actor(persistenceSession), evaluated_at: evaluatedAt, persisted_at: evaluatedAt, technical_claims: claims(), record_digest_sha256: null })
      validateD950Record('deletion-aware-reconstruction-v1.schema.json', record)
      return history.append({ namespaceCode: 'deletion-aware', record, semanticSession: verifierSession, persistenceSession }).record
    },

    recordDrill({ drillCode, manifest, schedulerSession, verifierSession, persistenceSession }) {
      assertOpen()
      session(schedulerSession, 'drill_scheduler'); session(verifierSession, 'restored_state_verifier'); session(persistenceSession, 'persistence_broker')
      assertCode(drillCode, 'drill code'); manifest = persistedExact('backup-manifests', manifest, 'backup-manifest-v1.schema.json'); verifyBackupProjection(manifest)
      const plan = history.records('restore-plans').filter((item) => item.backup_manifest_record_digest_sha256 === manifest.record_digest_sha256).at(-1)
      const leaf = manifests().at(-1); if (!plan || leaf.record_digest_sha256 !== manifest.record_digest_sha256) failD951('D951_DRILL_UNPROVEN', 'drill requires the current backup leaf and a verified restore plan')
      const promotedPath = path.join(promotionRoot, `generation-${canonicalSha256(plan.target_environment)}`)
      const observedInventoryDigestSha256 = readPrivateDirectoryInventory(promotedPath).digest
      const controls = controlResolver.resolve()
      const expectedFiles = manifest.backup_copies.map((copy) => ({ name: `${String(copy.artifact.artifact_code).replaceAll('.', '_')}.bin`, sha256: copy.artifact.sha256 }))
      expectedFiles.push({ name: '.controls.json', sha256: sha256Bytes(Buffer.from(JSON.stringify(controls))) })
      const expectedInventoryDigestSha256 = canonicalSha256(expectedFiles.toSorted((a, b) => a.name.localeCompare(b.name)))
      const resolvedCheckpoint = checkpointResolver.resolve()
      const completedAt = now()
      const prior = history.records('restore-drills').toSorted((a, b) => a.chain.sequence - b.chain.sequence).at(-1)
      const age = Math.floor((Date.parse(completedAt) - Date.parse(manifest.source_checkpoint.captured_at)) / 1000)
      const sourceMatches = canonicalSha256(resolvedCheckpoint) === canonicalSha256(manifest.source_checkpoint)
      const passed = sourceMatches && age <= 86400 && expectedInventoryDigestSha256 === observedInventoryDigestSha256
      const record = sealD951({ format: 'jedi-atlas-restore-drill-record', format_version: '1.0.0', record_code: `drill-${drillCode}`, drill_code: drillCode, chain: { namespace_code: 'd950.restore.drills.v1', sequence: (prior?.chain.sequence ?? 0) + 1, previous_record_digest_sha256: prior?.record_digest_sha256 ?? null }, backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, restore_plan_record_digest_sha256: plan.record_digest_sha256, target_environment_identity_sha256: canonicalSha256(plan.target_environment), expected_source_checkpoint: manifest.source_checkpoint, observed_source_checkpoint_record_digest_sha256: resolvedCheckpoint.checkpoint_record_digest_sha256, observed_source_state_head_digest_sha256: resolvedCheckpoint.source_state_head_digest_sha256, observed_correspondence_record_digest_sha256: resolvedCheckpoint.correspondence_record_digest_sha256, expected_backup_chain_leaf_record_digest_sha256: manifest.record_digest_sha256, expected_backup_chain_leaf_sequence: manifest.backup_chain_sequence, observed_backup_chain_leaf_record_digest_sha256: leaf.record_digest_sha256, observed_backup_chain_leaf_sequence: leaf.backup_chain_sequence, expected_inventory_digest_sha256: expectedInventoryDigestSha256, restored_inventory_digest_sha256: observedInventoryDigestSha256, checkpoint_age_basis_code: 'started_at_minus_checkpoint_captured_at_floor_seconds', scheduled_for: completedAt, started_at: completedAt, completed_at: completedAt, checkpoint_age_seconds: age, checkpoint_age_limit_seconds: 86400, backup_chain_state_code: 'current_leaf', source_head_comparison_code: sourceMatches ? 'exact_checkpoint_match' : 'mismatch', restored_state_comparison_code: expectedInventoryDigestSha256 === observedInventoryDigestSha256 ? 'exact_match' : 'mismatch', outcome_code: passed ? 'passed' : age > 86400 ? 'stale' : 'failed', escalation_code: passed ? 'none' : age > 86400 ? 'new_backup_required' : 'security_review_required', scheduler: actor(schedulerSession), independent_verifier: actor(verifierSession), persistence_broker: actor(persistenceSession), technical_claims: claims(), record_digest_sha256: null })
      validateD950Record('restore-drill-record-v1.schema.json', record)
      return history.append({ namespaceCode: 'restore-drills', record, semanticSession: verifierSession, persistenceSession }).record
    },

    restore({ authorization, manifest, requesterSession, executorSession, controlVerifierSession, restoredVerifierSession, persistenceSession, targetEnvironment }) {
      assertOpen()
      session(requesterSession, 'restore_requester'); session(executorSession, 'restore_executor'); session(controlVerifierSession, 'control_state_verifier'); session(restoredVerifierSession, 'restored_state_verifier'); session(persistenceSession, 'persistence_broker')
      if (executorSession.bindingCode === restoredVerifierSession.bindingCode || controlVerifierSession.processInstanceCode === restoredVerifierSession.processInstanceCode) failD951('D951_SEPARATION_VIOLATION', 'executor and verifier or verifier processes are not distinct')
      manifest = persistedExact('backup-manifests', manifest, 'backup-manifest-v1.schema.json')
      authorization = persistedExact('restore-authorizations', authorization, 'restore-authorization-v1.schema.json')
      verifyBackupProjection(manifest)
      const at = now()
      const expectedTargetIdentitySha256 = canonicalSha256(targetEnvironment)
      if (authorization.valid_from > at || at >= authorization.valid_until || authorization.backup_manifest_record_digest_sha256 !== manifest.record_digest_sha256 || authorization.target_environment_identity_sha256 !== expectedTargetIdentitySha256) failD951('D951_AUTHORIZATION_INVALID', 'authorization is expired or bound to different inputs')
      if (canonicalSha256(checkpointResolver.resolve()) !== canonicalSha256(manifest.source_checkpoint)) failD951('D951_SOURCE_HEAD_MOVED', 'trusted source checkpoint no longer matches the backup')
      const initialControls = controlResolver.resolve()
      const subjects = new Set(manifest.source_inventory.map((item) => item.subject_identity_sha256))
      if (subjects.size !== 1 || !subjects.has(initialControls.subject_identity_sha256) || initialControls.evidence.some((item) => item.subject_identity_sha256 !== initialControls.subject_identity_sha256 || item.current_leaf !== true)) failD951('D951_CONTROL_SNAPSHOT_INVALID', 'control projection is not complete for the restored subject')
      if (initialControls.directives.some((item) => ['do_not_restore', 'apply_tombstone_before_restore'].includes(item.directive_code))) return Object.freeze({ outcomeCode: 'withheld', recoveryCode: 'safe_no_effect', stages: Object.freeze([]) })
      if (initialControls.directives.some((item) => item.directive_code === 'apply_restriction_before_restore')) return Object.freeze({ outcomeCode: 'withheld', recoveryCode: 'restriction_enforcement_unimplemented_fail_closed', stages: Object.freeze([]) })
      const initialRetention = currentRetention(manifest)
      const { retention, retentionHead } = initialRetention
      const assessment = history.records('deletion-aware').filter((item) => item.backup_set_code === manifest.backup_set_code).at(-1)
      if (!assessment || assessment.restore_disposition_code !== 'eligible_with_controls') failD951('D951_RESTORE_PREREQUISITE_MISSING', 'current deletion-aware evidence is required')
      const receiptDigests = history.records('backup-receipts').filter((item) => item.backup_manifest_record_digest_sha256 === manifest.record_digest_sha256).map((item) => item.record_digest_sha256)
      if (!history.records('backup-receipts').some((item) => item.backup_manifest_record_digest_sha256 === manifest.record_digest_sha256 && item.receipt_kind_code === 'final_consistent_set')) failD951('D951_RESTORE_PREREQUISITE_MISSING', 'final consistent-set receipt is required')
      const priorPlan = history.records('restore-plans').find((item) => item.operation_id === authorization.operation_id)
      if (priorPlan) {
        if (priorPlan.operation_nonce !== authorization.operation_nonce || priorPlan.authorization_record_digest_sha256 !== authorization.record_digest_sha256 || priorPlan.backup_manifest_record_digest_sha256 !== manifest.record_digest_sha256 || canonicalSha256(priorPlan.target_environment) !== expectedTargetIdentitySha256) failD951('D951_REPLAY_COLLISION', 'restore operation identity is bound to different inputs')
        const priorLifecycle = history.records('restore-lifecycle').filter((item) => item.restore_plan_record_digest_sha256 === priorPlan.record_digest_sha256).toSorted((a, b) => a.chain.sequence - b.chain.sequence)
        if (priorLifecycle.length !== STAGES.length || priorLifecycle.map((item) => item.stage_code).join('|') !== STAGES.join('|') || priorLifecycle.at(-1).outcome_code !== 'succeeded') failD951('D951_RECOVERY_REQUIRED', 'restore history is incomplete and requires classification')
        const priorPromotedPath = path.join(promotionRoot, `generation-${expectedTargetIdentitySha256}`)
        const priorLockPath = path.join(promotionRoot, `lock-${expectedTargetIdentitySha256}`)
        const priorStagePath = path.join(stagingRoot, `restore-${authorization.operation_id}`)
        const priorStatus = fs.lstatSync(priorPromotedPath, { bigint: true })
        if (fs.existsSync(priorLockPath) || fs.existsSync(priorStagePath) || (priorStatus.mode & 0o777n) !== 0o700n) failD951('D951_RECOVERY_REQUIRED', 'completed history has unresolved lock, staging, or inaccessible promotion state')
        const observed = readPrivateDirectoryInventory(priorPromotedPath)
        const expectedFiles = manifest.backup_copies.map((copy) => ({ name: `${String(copy.artifact.artifact_code).replaceAll('.', '_')}.bin`, sha256: copy.artifact.sha256 }))
        expectedFiles.push({ name: '.controls.json', sha256: sha256Bytes(Buffer.from(JSON.stringify(initialControls))) })
        const expectedDigest = canonicalSha256(expectedFiles.toSorted((a, b) => a.name.localeCompare(b.name)))
        if (observed.digest !== expectedDigest) failD951('D951_PROMOTION_MISMATCH', 'completed restore bytes no longer match the accepted bundle')
        return deepFreeze({ outcomeCode: 'succeeded', recoveryCode: 'exact_replay_no_op_after_full_revalidation', lifecycle: priorLifecycle, promotedPath: priorPromotedPath, inventoryDigestSha256: observed.digest, replay: true })
      }
      const plannedAt = now()
      const plan = sealD951({ format: 'jedi-atlas-restore-plan', format_version: '1.0.0', record_code: `restore-plan-${authorization.operation_id}`, operation_id: authorization.operation_id, operation_nonce: authorization.operation_nonce, restore_mode_code: 'authorized_reconstruction', backup_set_code: manifest.backup_set_code, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, backup_receipt_record_digests: receiptDigests, source_checkpoint: manifest.source_checkpoint, authorization_record_digest_sha256: authorization.record_digest_sha256, target_environment: targetEnvironment, pre_restore_control_snapshot: initialControls.boundary, control_directives: initialControls.directives, deletion_aware_reconstruction_record_digests: [assessment.record_digest_sha256], retention_control_record_digest_sha256: retention.record_digest_sha256, retention_control_chain_sequence: retention.chain.sequence, retention_head: { namespace_code: retentionHead.namespace_code, head_sequence: retentionHead.head_sequence, head_record_digest_sha256: retentionHead.head_record_digest_sha256, head_receipt_record_digest_sha256: retentionHead.head_receipt_record_digest_sha256, head_receipt_persisted_at: retentionHead.head_receipt_persisted_at, attestation_record_digest_sha256: retentionHead.record_digest_sha256, known_at: retentionHead.known_at }, ordered_stage_codes: STAGES, executor: actor(executorSession), control_state_verifier: actor(controlVerifierSession), restored_state_verifier: actor(restoredVerifierSession), persistence_broker: actor(persistenceSession), planned_at: plannedAt, expires_at: authorization.valid_until, technical_claims: claims(), record_digest_sha256: null })
      validateD950Record('restore-plan-v1.schema.json', plan)
      history.append({ namespaceCode: 'restore-plans', record: plan, semanticSession: executorSession, persistenceSession })
      const stageName = `restore-${authorization.operation_id}`
      if (!SAFE_STAGE.test(stageName)) failD951('D951_STAGE_INVALID', 'staging name is invalid')
      const stagePath = path.join(stagingRoot, stageName)
      const promotedPath = path.join(promotionRoot, `generation-${expectedTargetIdentitySha256}`)
      if (fs.existsSync(stagePath) || fs.existsSync(promotedPath)) failD951('D951_REPLAY_COLLISION', 'restore target already exists')
      const lockPath = path.join(promotionRoot, `lock-${expectedTargetIdentitySha256}`); const lockFd = fs.openSync(lockPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC, 0o600)
      fs.mkdirSync(stagePath, { mode: 0o700 }); const stageFd = fs.openSync(stagePath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); const stageDirectory = `/proc/self/fd/${stageFd}`; const lifecycle = []
      let promoted = false; let accessible = false; let successful = false
      const observeCurrent = () => {
        const observedControls = controlResolver.resolve()
        const observedRetention = currentRetention(manifest)
        if (canonicalSha256(observedControls) !== canonicalSha256(initialControls) || observedRetention.retention.record_digest_sha256 !== retention.record_digest_sha256 || observedRetention.retentionHead.record_digest_sha256 !== retentionHead.record_digest_sha256 || canonicalSha256(checkpointResolver.resolve()) !== canonicalSha256(manifest.source_checkpoint)) failD951('D951_CONTROL_MOVED', 'control, retention, or source checkpoint moved during restore')
        return { observedControls, observedRetention }
      }
      const appendStage = (stageCode, roleSession, bytesAccessible = false, promoted = false) => {
        const rule = contractSet.classifications.restore_stage_rules.find((item) => item.stage_code === stageCode)
        const eventAt = now()
        const observed = rule.control_revalidation_required ? observeCurrent() : null
        const controlRevalidation = observed ? { resolver_request_record_digest_sha256: canonicalSha256({ operation: authorization.operation_id, stageCode, kind: 'request' }), resolver_response_record_digest_sha256: canonicalSha256({ controls: observed.observedControls, stageCode }), before: initialControls.boundary, after: observed.observedControls.boundary, retention_control_record_digest_sha256: observed.observedRetention.retention.record_digest_sha256, retention_chain_sequence: observed.observedRetention.retention.chain.sequence, retention_head_attestation_record_digest_sha256: observed.observedRetention.retentionHead.record_digest_sha256, retention_head_receipt_record_digest_sha256: observed.observedRetention.retentionHead.head_receipt_record_digest_sha256, source_stable: true } : null
        const record = sealD951({ format: 'jedi-atlas-restore-lifecycle-record', format_version: '1.0.0', record_code: `restore-${authorization.operation_id}-${String(lifecycle.length + 1).padStart(2, '0')}`, operation_id: authorization.operation_id, operation_nonce: authorization.operation_nonce, chain: { namespace_code: 'd950.restore.lifecycle.v1', sequence: lifecycle.length + 1, previous_record_digest_sha256: lifecycle.at(-1)?.record_digest_sha256 ?? null }, restore_plan_record_digest_sha256: plan.record_digest_sha256, authorization_record_digest_sha256: authorization.record_digest_sha256, stage_code: stageCode, outcome_code: rule.outcome_code, error_code: rule.error_code, retryability_code: rule.retryability_code, bytes_accessible: rule.bytes_accessible, atomic_promotion_observed: rule.atomic_promotion_observed, source_checkpoint_record_digest_sha256: manifest.source_checkpoint.checkpoint_record_digest_sha256, backup_manifest_record_digest_sha256: manifest.record_digest_sha256, control_snapshot: initialControls.boundary, control_revalidation: controlRevalidation, restored_inventory_digest_sha256: rule.ordinal >= 6 ? manifest.source_inventory_digest_sha256 : null, semantic_actor: actor(roleSession), persistence_actor: actor(persistenceSession), event_at: eventAt, persisted_at: eventAt, technical_claims: claims(), record_digest_sha256: null })
        validateD950Record('restore-lifecycle-record-v1.schema.json', record)
        lifecycle.push(history.append({ namespaceCode: 'restore-lifecycle', record, semanticSession: roleSession, persistenceSession }).record)
        faultInjector?.(`after_${stageCode}`, { stagePath, promotedPath })
      }
      try {
        appendStage('authorized', requesterSession); appendStage('staging_started', executorSession)
        for (const copy of manifest.backup_copies) {
          const bytes = backupStore.read({ identity: copy.artifact, backendReference: copy.backend_reference })
          const file = path.join(stageDirectory, `${String(copy.artifact.artifact_code).replaceAll('.', '_')}.bin`)
          fs.writeFileSync(file, bytes, { mode: 0o600, flag: 'wx' }); const fd = fs.openSync(file, 'r'); try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
        }
        appendStage('bytes_reconstructed_inaccessible', executorSession)
        const revalidated = observeCurrent().observedControls
        appendStage('controls_revalidated', controlVerifierSession)
        fs.writeFileSync(path.join(stageDirectory, '.controls.json'), JSON.stringify(revalidated), { mode: 0o600, flag: 'wx' })
        const controlsFd = fs.openSync(path.join(stageDirectory, '.controls.json'), 'r'); try { fs.fsyncSync(controlsFd) } finally { fs.closeSync(controlsFd) }
        appendStage('controls_applied', executorSession)
        const files = fs.readdirSync(stageDirectory).toSorted(); const stagedDigest = canonicalSha256(files.map((name) => ({ name, sha256: sha256Bytes(fs.readFileSync(path.join(stageDirectory, name))) })))
        if (files.length !== manifest.backup_copies.length + 1) failD951('D951_RESTORE_MISMATCH', 'staged inventory is incomplete')
        fs.fchmodSync(stageFd, 0o000); fs.fsyncSync(stageFd)
        appendStage('staged_state_verified', restoredVerifierSession); appendStage('promotion_started', executorSession)
        observeCurrent()
        fs.renameSync(stagePath, promotedPath); promoted = true; fs.fsyncSync(stagingRootIdentity.descriptor); fs.fsyncSync(promotionRootIdentity.descriptor)
        const promotedFiles = fs.readdirSync(stageDirectory).toSorted(); const promotedDigest = canonicalSha256(promotedFiles.map((name) => ({ name, sha256: sha256Bytes(fs.readFileSync(path.join(stageDirectory, name))) })))
        if (promotedDigest !== stagedDigest) failD951('D951_PROMOTION_MISMATCH', 'atomically promoted generation differs from independently verified staging')
        observeCurrent(); fs.fchmodSync(stageFd, 0o700); accessible = true; fs.fsyncSync(stageFd); fs.fsyncSync(promotionRootIdentity.descriptor)
        appendStage('promoted', executorSession, true, true)
        appendStage('post_promotion_verified', restoredVerifierSession, true, true); appendStage('completed', executorSession, true, true)
        successful = true; fs.unlinkSync(lockPath); fs.fsyncSync(promotionRootIdentity.descriptor)
        return Object.freeze({ outcomeCode: 'succeeded', recoveryCode: 'complete', lifecycle: Object.freeze(lifecycle), promotedPath, inventoryDigestSha256: promotedDigest })
      } finally {
        if (!successful) { try { fs.fchmodSync(stageFd, 0o000) } catch {} }
        try { fs.closeSync(stageFd) } catch {}
        try { fs.closeSync(lockFd) } catch {}
      }
    },

    classifyCrash(boundaryCode) {
      const map = { before_staging: 'safe_no_effect', after_staging_before_controls: 'retain_inaccessible_and_reconcile', after_controls_before_verification: 'retain_inaccessible_and_reconcile', after_verification_before_promotion: 'retain_inaccessible_and_reconcile', after_promotion_before_post_verification: 'recovery_required_no_automatic_rollback', after_verification_before_receipt: 'recovery_required_exact_replay_only', after_receipt_before_response: 'exact_replay_no_op_after_full_revalidation' }
      if (!map[boundaryCode]) failD951('D951_CRASH_BOUNDARY_UNKNOWN', 'crash boundary is not closed')
      return Object.freeze({ boundaryCode, classificationCode: map[boundaryCode], actionAuthorized: false })
    },

    inspectRestoreRecovery(operationId) {
      assertOpen(); assertCode(operationId, 'operation id'); history.verifyComplete()
      const plan = history.records('restore-plans').find((item) => item.operation_id === operationId)
      if (!plan) return Object.freeze({ operationId, classificationCode: 'safe_no_effect', lastStageCode: null, lockPresent: false, stagingPresent: false, promotionPresent: false, actionAuthorized: false })
      const lifecycle = history.records('restore-lifecycle').filter((item) => item.restore_plan_record_digest_sha256 === plan.record_digest_sha256).toSorted((a, b) => a.chain.sequence - b.chain.sequence)
      for (const [index, item] of lifecycle.entries()) if (item.chain.sequence !== index + 1 || item.stage_code !== STAGES[index] || item.chain.previous_record_digest_sha256 !== lifecycle[index - 1]?.record_digest_sha256 && index > 0) failD951('D951_RECOVERY_REQUIRED', 'restore lifecycle is gapped, forked, or reordered')
      const targetIdentity = canonicalSha256(plan.target_environment)
      const lockPresent = fs.existsSync(path.join(promotionRoot, `lock-${targetIdentity}`))
      const stagingPresent = fs.existsSync(path.join(stagingRoot, `restore-${operationId}`))
      const promotionPresent = fs.existsSync(path.join(promotionRoot, `generation-${targetIdentity}`))
      const last = lifecycle.at(-1)?.stage_code ?? null
      let classificationCode = 'retain_inaccessible_and_reconcile'
      if (last === 'completed' && promotionPresent && !lockPresent && !stagingPresent) classificationCode = 'exact_replay_no_op_after_full_revalidation'
      else if (promotionPresent) classificationCode = 'recovery_required_no_automatic_rollback'
      else if (!stagingPresent && !lockPresent) classificationCode = 'safe_no_effect'
      return Object.freeze({ operationId, classificationCode, lastStageCode: last, lockPresent, stagingPresent, promotionPresent, actionAuthorized: false })
    },

    inventoryCopyClasses(states) {
      assertOpen()
      if (!Array.isArray(states) || states.length !== COPY_CLASSES.length || states.map((item) => item.copy_class_code).join('|') !== COPY_CLASSES.join('|')) failD951('D951_COPY_INVENTORY_INCOMPLETE', 'all seven copy classes are required in canonical order')
      if (states.some((item) => !['present', 'absent_verified', 'restricted', 'tombstoned', 'unknown', 'unverifiable'].includes(item.state_code))) failD951('D951_COPY_INVENTORY_INVALID', 'copy class state is outside the closed vocabulary')
      const observations = states.map((item) => ({ copy_class_code: item.copy_class_code, state_code: item.state_code, bounded_count: item.bounded_count ?? (item.state_code === 'present' ? 1 : item.state_code === 'absent_verified' ? 0 : null), inventory_digest_sha256: item.inventory_digest_sha256 ?? canonicalSha256(item), evidence_record_digests: item.evidence_record_digests ?? [canonicalSha256({ copy_class_code: item.copy_class_code, state_code: item.state_code })] }))
      return Object.freeze({ states: observations, completeErasureClaimed: false, digest: canonicalSha256(observations) })
    },
    close() {
      if (!closed) { closed = true; runtimes.delete(runtime); fs.closeSync(stagingRootIdentity.descriptor); fs.closeSync(promotionRootIdentity.descriptor) }
    },
  })
  runtimes.add(runtime)
  return runtime
}

const SAFE_STAGE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u
