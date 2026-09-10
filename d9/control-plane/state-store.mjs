import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { TextDecoder } from 'node:util'

const protectedStateStores = new WeakSet()

const STATE_FORMAT = 'jedi-atlas-d9-1-protected-state'
const STATE_VERSION = '1.0.0'
const HEAD_FILE = 'HEAD.json'
const COMMIT_DIRECTORY = 'commits'
const PENDING_DIRECTORY = 'pending'
const LOCK_DIRECTORY = 'operation.lock'
const APPEND_LOCK_DIRECTORY = 'append.lock'
const RECOVERY_INTENT_FILE = 'RECOVERY.json'
const HASH_PATTERN = /^[0-9a-f]{64}$/
const CODE_PATTERN = /^[a-z0-9][a-z0-9._-]{1,94}[a-z0-9]$/
const TIMESTAMP_PATTERN = /^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/
const COMMIT_NAME_PATTERN = /^(\d{12})-([0-9a-f]{64})\.json$/
const TERMINAL_PERMIT_STATES = new Set([
  'revoked',
  'spent',
  'recovery_required',
  'terminal_expired_unused',
  'terminal_recovery_hold',
])
const REGISTRY_KINDS = new Set(['collector_handoff', 'bundle_seal'])
const OPERATION_MODES = new Set(['bootstrap', 'document_import', 'dry_run', 'no_op_verification', 'recovery'])
const HISTORICAL_OPERATION_RECOVERY = Symbol('historical-operation-recovery')
const RUNTIME_ROLE_CODES = Object.freeze([
  'backup_adapter',
  'bootstrap_authority',
  'bundle_importer',
  'clearance_broker',
  'clearance_checker',
  'clearance_decider',
  'cloner_promoter',
  'collector',
  'custody_adapter',
  'database_writer',
  'handoff_broker',
  'human_submitter',
  'independent_verifier',
  'journal_broker',
  'operational_witness',
  'recovery_authority',
  'recovery_operator',
  'scanner',
  'trusted_launcher',
])
const utf8Decoder = new TextDecoder('utf-8', { fatal: true })

export class StateStoreError extends Error {
  constructor(code, message, details = undefined) {
    super(`${code}: ${message}`)
    this.name = 'StateStoreError'
    this.code = code
    this.details = details
  }
}

export class SimulatedStateCrash extends Error {
  constructor(stage) {
    super(`simulated protected-state crash at ${stage}`)
    this.name = 'SimulatedStateCrash'
    this.stage = stage
  }
}

function fail(code, message, details) {
  throw new StateStoreError(code, message, details)
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
}

function assertPlainObject(value, label) {
  if (!isPlainObject(value)) fail('STATE_INPUT_INVALID', `${label} must be a plain object`)
}

function assertExactKeys(value, keys, label) {
  assertPlainObject(value, label)
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('STATE_RECORD_SHAPE_INVALID', `${label} has unexpected or missing fields`, { actual, expected })
  }
}

function assertCode(value, label) {
  if (typeof value !== 'string' || !CODE_PATTERN.test(value)) fail('STATE_CODE_INVALID', `${label} is not a stable code`)
  return value
}

function assertHash(value, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) fail('STATE_HASH_INVALID', `${label} must be lowercase SHA-256 hex`)
  return value
}

function assertTimestamp(value, label) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) fail('STATE_TIMESTAMP_INVALID', `${label} is not a canonical UTC timestamp`)
  const milliseconds = Date.parse(value)
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail('STATE_TIMESTAMP_INVALID', `${label} is not a real canonical UTC timestamp`)
  }
  return milliseconds
}

function assertPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) fail('STATE_INTEGER_INVALID', `${label} must be a positive safe integer`)
  return value
}

function clone(value) {
  return structuredClone(value)
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const child of Object.values(value)) deepFreeze(child)
  }
  return value
}

function canonicalizeValue(value, location = '$') {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail('STATE_CANONICAL_VALUE_INVALID', `${location} contains a noncanonical number`)
    return String(value)
  }
  if (Array.isArray(value)) return `[${value.map((item, index) => canonicalizeValue(item, `${location}/${index}`)).join(',')}]`
  if (isPlainObject(value)) {
    const entries = Object.keys(value).sort().map((key) => {
      if (value[key] === undefined) fail('STATE_CANONICAL_VALUE_INVALID', `${location}/${key} is undefined`)
      return `${JSON.stringify(key)}:${canonicalizeValue(value[key], `${location}/${key}`)}`
    })
    return `{${entries.join(',')}}`
  }
  fail('STATE_CANONICAL_VALUE_INVALID', `${location} contains an unsupported value`)
}

export function canonicalizeStateRecord(value) {
  return canonicalizeValue(value)
}

export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function stateRecordDigest(record) {
  const unsigned = clone(record)
  delete unsigned.commit_sha256
  return sha256Hex(Buffer.from(canonicalizeStateRecord(unsigned), 'utf8'))
}

function assertCanonicalRecordDigest(record, label) {
  assertHash(record.record_digest_sha256, `${label} record digest`)
  const unsigned = clone(record)
  delete unsigned.record_digest_sha256
  const computed = sha256Hex(Buffer.from(canonicalizeStateRecord(unsigned), 'utf8'))
  if (computed !== record.record_digest_sha256) fail('STATE_RECORD_DIGEST_MISMATCH', `${label} digest does not bind its complete canonical content`)
}

function recoveryIntentDigest(record) {
  const unsigned = clone(record)
  delete unsigned.intent_sha256
  return sha256Hex(Buffer.from(canonicalizeStateRecord(unsigned), 'utf8'))
}

function validateRecoveryIntent(intent) {
  assertExactKeys(intent, ['format', 'format_version', 'action_code', 'recovered_at', 'recovered_by_binding_code', 'affected_sequence', 'affected_commit_sha256', 'append_lock_state_code', 'append_lock_lease_sha256', 'pending_names', 'audit_commit', 'intent_sha256'], 'publish recovery intent')
  if (intent.format !== STATE_FORMAT || intent.format_version !== STATE_VERSION) fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery intent has an unsupported format')
  if (!['discarded_uncommitted_pending', 'finalized_durable_unanchored_commit', 'completed_durable_head_commit_cleanup', 'discarded_abandoned_append_lock'].includes(intent.action_code)) fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery intent has an invalid action')
  assertTimestamp(intent.recovered_at, 'publish recovery intent recovered_at')
  assertCode(intent.recovered_by_binding_code, 'publish recovery intent binding')
  if ((intent.affected_sequence === null) !== (intent.affected_commit_sha256 === null)) fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery affected commit fields must be paired')
  if (intent.affected_sequence !== null) assertPositiveInteger(intent.affected_sequence, 'publish recovery affected sequence')
  if (intent.affected_commit_sha256 !== null) assertHash(intent.affected_commit_sha256, 'publish recovery affected digest')
  if (!['none', 'complete_abandoned', 'incomplete'].includes(intent.append_lock_state_code)) fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery append-lock state is invalid')
  if (intent.append_lock_state_code === 'complete_abandoned') assertHash(intent.append_lock_lease_sha256, 'publish recovery append-lock digest')
  else if (intent.append_lock_lease_sha256 !== null) fail('STATE_RECOVERY_INTENT_INVALID', 'only a complete abandoned append lock has a digest')
  if (!Array.isArray(intent.pending_names) || new Set(intent.pending_names).size !== intent.pending_names.length || canonicalizeStateRecord([...intent.pending_names].sort()) !== canonicalizeStateRecord(intent.pending_names)) fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery pending names must be unique and sorted')
  for (const name of intent.pending_names) {
    if (typeof name !== 'string' || (!/^\d{12}-[0-9a-f]{64}\.commit\.pending$/.test(name) && !/^head-\d{12}-(?:[0-9a-f]{64}|genesis)-[0-9a-f]{16}\.pending$/.test(name))) fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery intent has an invalid pending name')
  }
  assertPlainObject(intent.audit_commit, 'publish recovery audit commit')
  validateCommit(intent.audit_commit, intent.audit_commit.sequence, intent.audit_commit.previous_commit_sha256, intent.audit_commit.commit_sha256)
  if (intent.audit_commit.transaction_code !== 'recovery.publish' || intent.audit_commit.events.length !== 1) fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery intent has the wrong audit commit')
  const audit = intent.audit_commit.events[0]
  const expectedIncidentSha256 = publishRecoveryIncidentSha256({
    actionCode: intent.action_code,
    affectedSequence: intent.affected_sequence,
    affectedCommitSha256: intent.affected_commit_sha256,
    appendLockStateCode: intent.append_lock_state_code,
    appendLockLeaseSha256: intent.append_lock_lease_sha256,
    pendingNames: intent.pending_names,
  })
  if (audit.event_kind_code !== 'recovery_action_recorded' || audit.recovery_action_code !== intent.action_code || audit.recovered_at !== intent.recovered_at || audit.recovered_by_binding_code !== intent.recovered_by_binding_code || audit.affected_sequence !== intent.affected_sequence || audit.affected_commit_sha256 !== intent.affected_commit_sha256 || audit.operation_id !== null || audit.operation_nonce !== null || audit.incident_sha256 !== expectedIncidentSha256) {
    fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery audit event differs from the recovery intent')
  }
  assertHash(intent.intent_sha256, 'publish recovery intent digest')
  if (recoveryIntentDigest(intent) !== intent.intent_sha256) fail('STATE_RECOVERY_INTENT_INVALID', 'publish recovery intent digest does not match content')
  return intent
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalizeStateRecord(value)}\n`, 'utf8')
}

function parseCanonicalBytes(bytes, label) {
  let text
  try {
    text = utf8Decoder.decode(bytes)
  } catch {
    fail('STATE_FILE_INVALID_UTF8', `${label} is not valid UTF-8`)
  }
  let value
  try {
    value = JSON.parse(text)
  } catch {
    fail('STATE_FILE_INVALID_JSON', `${label} is not valid JSON`)
  }
  if (!canonicalBytes(value).equals(bytes)) fail('STATE_FILE_NOT_CANONICAL', `${label} is not canonical JSON plus one LF`)
  return value
}

function assertRegularNoSymlink(targetPath, label, expectedUid = undefined) {
  const stat = fs.lstatSync(targetPath)
  if (stat.isSymbolicLink() || !stat.isFile()) fail('STATE_PATH_UNSAFE', `${label} must be a regular file, not a symlink`)
  if ((stat.mode & 0o077) !== 0) fail('STATE_FILE_PERMISSIONS_INVALID', `${label} must deny group and other access`)
  if (expectedUid !== undefined && stat.uid !== expectedUid) fail('STATE_ROOT_OWNER_INVALID', `${label} has the wrong owner`)
  return stat
}

function assertDirectoryNoSymlink(targetPath, label, expectedUid) {
  const stat = fs.lstatSync(targetPath)
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail('STATE_PATH_UNSAFE', `${label} must be a directory, not a symlink`)
  if ((stat.mode & 0o077) !== 0) fail('STATE_ROOT_PERMISSIONS_INVALID', `${label} must deny group and other access`)
  if (expectedUid !== undefined && stat.uid !== expectedUid) fail('STATE_ROOT_OWNER_INVALID', `${label} has the wrong owner`)
  return stat
}

function fsyncDirectory(directoryPath) {
  const descriptor = fs.openSync(directoryPath, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0))
  try {
    fs.fsyncSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
}

function processStartTicks(pid) {
  try {
    const value = fs.readFileSync(`/proc/${pid}/stat`, 'utf8')
    const close = value.lastIndexOf(')')
    if (close < 0) return null
    const fields = value.slice(close + 2).trim().split(/\s+/)
    const startTicks = fields[19]
    return /^\d+$/.test(startTicks ?? '') ? startTicks : null
  } catch {
    return null
  }
}

function appendLockDigest(lease) {
  const unsigned = clone(lease)
  delete unsigned.lease_sha256
  return sha256Hex(Buffer.from(canonicalizeStateRecord(unsigned), 'utf8'))
}

function validateAppendLockLease(lease) {
  assertExactKeys(lease, ['format', 'format_version', 'transaction_code', 'owner_pid', 'owner_start_ticks', 'acquired_at', 'base_sequence', 'base_commit_sha256', 'intended_sequence', 'intended_commit_sha256', 'lease_sha256'], 'append mutex lease')
  if (lease.format !== STATE_FORMAT || lease.format_version !== STATE_VERSION) fail('STATE_APPEND_LOCK_CORRUPT', 'append mutex lease format is invalid')
  assertCode(lease.transaction_code, 'append mutex transaction_code')
  assertPositiveInteger(lease.owner_pid, 'append mutex owner_pid')
  if (typeof lease.owner_start_ticks !== 'string' || !/^\d+$/.test(lease.owner_start_ticks)) fail('STATE_APPEND_LOCK_CORRUPT', 'append mutex owner start time is invalid')
  assertTimestamp(lease.acquired_at, 'append mutex acquired_at')
  if (!Number.isSafeInteger(lease.base_sequence) || lease.base_sequence < 0 || lease.intended_sequence !== lease.base_sequence + 1) fail('STATE_APPEND_LOCK_CORRUPT', 'append mutex sequence commitment is invalid')
  if (lease.base_sequence === 0 ? lease.base_commit_sha256 !== null : !HASH_PATTERN.test(lease.base_commit_sha256 ?? '')) fail('STATE_APPEND_LOCK_CORRUPT', 'append mutex base-HEAD commitment is invalid')
  assertHash(lease.intended_commit_sha256, 'append mutex intended commit digest')
  assertHash(lease.lease_sha256, 'append mutex digest')
  if (appendLockDigest(lease) !== lease.lease_sha256) fail('STATE_APPEND_LOCK_CORRUPT', 'append mutex digest does not match content')
  return lease
}

function appendLockOwnerIsAlive(lease) {
  return processStartTicks(lease.owner_pid) === lease.owner_start_ticks
}

function recoveryIncidentSha256(value) {
  return sha256Hex(Buffer.from(canonicalizeStateRecord(value), 'utf8'))
}

function operationLockIncidentSha256(rootPath, lock) {
  if (lock) {
    return recoveryIncidentSha256({
      incident_kind_code: 'complete_operation_lock',
      lease_token_sha256: lock.lease_token_sha256,
    })
  }
  const stat = fs.lstatSync(path.join(rootPath, LOCK_DIRECTORY), { bigint: true })
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('STATE_PATH_UNSAFE', 'incomplete operation lock must remain a real directory')
  return recoveryIncidentSha256({
    incident_kind_code: 'incomplete_operation_lock',
    device: String(stat.dev),
    inode: String(stat.ino),
    changed_at_nanoseconds: String(stat.ctimeNs),
  })
}

function publishRecoveryIncidentSha256({ actionCode, affectedSequence, affectedCommitSha256, appendLockStateCode, appendLockLeaseSha256, pendingNames }) {
  return recoveryIncidentSha256({
    incident_kind_code: 'interrupted_publish',
    action_code: actionCode,
    affected_sequence: affectedSequence,
    affected_commit_sha256: affectedCommitSha256,
    append_lock_state_code: appendLockStateCode,
    append_lock_lease_sha256: appendLockLeaseSha256,
    pending_names: pendingNames,
  })
}

function writeExclusiveDurable(targetPath, bytes, mode = 0o400) {
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0)
  const descriptor = fs.openSync(targetPath, flags, mode)
  try {
    fs.writeFileSync(descriptor, bytes)
    fs.fsyncSync(descriptor)
    fs.fchmodSync(descriptor, mode)
  } finally {
    fs.closeSync(descriptor)
  }
}

function replaceHeadDurably(rootPath, head) {
  const pendingDirectory = path.join(rootPath, PENDING_DIRECTORY)
  const suffix = crypto.randomBytes(8).toString('hex')
  const temporaryPath = path.join(pendingDirectory, `head-${String(head.sequence).padStart(12, '0')}-${head.commit_sha256 ?? 'genesis'}-${suffix}.pending`)
  const destinationPath = path.join(rootPath, HEAD_FILE)
  writeExclusiveDurable(temporaryPath, canonicalBytes(head))
  fsyncDirectory(pendingDirectory)
  fs.renameSync(temporaryPath, destinationPath)
  fsyncDirectory(rootPath)
}

function readCanonicalFile(filePath, label, expectedUid = undefined) {
  assertRegularNoSymlink(filePath, label, expectedUid)
  return parseCanonicalBytes(fs.readFileSync(filePath), label)
}

function makeEmptyProjection() {
  return {
    generationPairs: [],
    generationPairRevocations: new Map(),
    registryRecords: new Map(),
    registryRevocations: new Map(),
    permits: new Map(),
    permitRecordCodes: new Set(),
    permitRecordDigests: new Set(),
    operationsByNonce: new Map(),
    operationsById: new Map(),
    recoveryActions: [],
  }
}

function selectGenerationPairFromProjection(projection, asOf, { runtimeProfileRecordDigestSha256, identityBindingsRecordDigestSha256 } = {}) {
  const asOfMs = assertTimestamp(asOf, 'asOf')
  const eligible = projection.generationPairs.filter((entry) => (
    assertTimestamp(entry.activated_at, 'generation pair activated_at') <= asOfMs
    &&
    assertTimestamp(entry.runtime_profile.valid_from, 'runtime profile valid_from') <= asOfMs
    && assertTimestamp(entry.identity_bindings.valid_from, 'identity bindings valid_from') <= asOfMs
  )).sort((left, right) => left.pair_generation - right.pair_generation)
  const candidate = eligible.at(-1)
  if (!candidate) fail('STATE_ACTIVE_GENERATION_MISSING', 'no runtime/binding generation pair is valid as of the requested time')
  const revoked = projection.generationPairRevocations.get(candidate.pair_code)
  if (revoked && assertTimestamp(revoked.revoked_at, 'generation pair revoked_at') <= asOfMs) fail('STATE_ACTIVE_GENERATION_REVOKED', 'latest pair is revoked; older pairs do not resurrect')
  if (asOfMs >= assertTimestamp(candidate.runtime_profile.expires_at, 'runtime profile expires_at') || asOfMs >= assertTimestamp(candidate.identity_bindings.expires_at, 'identity bindings expires_at')) fail('STATE_ACTIVE_GENERATION_EXPIRED', 'latest pair is expired; older pairs do not resurrect')
  if (runtimeProfileRecordDigestSha256 !== undefined && candidate.runtime_profile.record_digest_sha256 !== runtimeProfileRecordDigestSha256) fail('STATE_ACTIVE_GENERATION_SUBSTITUTED', 'active runtime profile does not have the expected digest')
  if (identityBindingsRecordDigestSha256 !== undefined && candidate.identity_bindings.record_digest_sha256 !== identityBindingsRecordDigestSha256) fail('STATE_ACTIVE_GENERATION_SUBSTITUTED', 'active identity bindings do not have the expected digest')
  return candidate
}

function registryKey(kind, code) {
  return `${kind}\0${code}`
}

function bootstrapSealMatchesPermit(seal, permit) {
  return seal.bundle_kind_code === 'principal_bootstrap'
    && canonicalizeStateRecord(seal.bundle) === canonicalizeStateRecord(permit.bootstrap_bundle)
    && seal.manifest_path === permit.manifest_path
    && seal.reviewed_git_commit === permit.reviewed_git_commit
    && seal.runtime_profile_record_digest_sha256 === permit.runtime_profile_record_digest_sha256
    && seal.identity_bindings_record_digest_sha256 === permit.identity_bindings_record_digest_sha256
    && seal.operation_nonce === permit.operation_nonce
    && seal.submitter_binding_code === permit.submitter_binding_code
    && seal.importer_binding_code === permit.importer_binding_code
    && canonicalizeStateRecord(seal.target_logical_state) === canonicalizeStateRecord(permit.target_empty_logical_state)
}

function permitStateAt(permitEntry, asOf) {
  const asOfMs = assertTimestamp(asOf, 'as_of')
  const issuance = permitEntry.record
  if (asOfMs < assertTimestamp(issuance.issued_at, 'permit issued_at')) return null
  let state = 'ready'
  for (const transition of permitEntry.transitions) {
    if (assertTimestamp(transition.persisted_at, 'transition persisted_at') <= asOfMs) state = transition.to_state_code
  }
  if (TERMINAL_PERMIT_STATES.has(state)) return state
  if (asOfMs >= assertTimestamp(issuance.expires_at, 'permit expires_at')) {
    return state === 'ready' ? 'terminal_expired_unused' : 'terminal_recovery_hold'
  }
  return state
}

function validateBindingFacts(bindingFacts, label) {
  if (!Array.isArray(bindingFacts) || bindingFacts.length !== RUNTIME_ROLE_CODES.length) {
    fail('STATE_BINDING_FACTS_INVALID', `${label} must contain every runtime role exactly once`)
  }
  const normalized = bindingFacts.map((fact, index) => {
    assertExactKeys(fact, ['binding_code', 'runtime_role_code', 'valid_from', 'valid_until'], `${label}[${index}]`)
    assertCode(fact.binding_code, `${label}[${index}].binding_code`)
    if (!RUNTIME_ROLE_CODES.includes(fact.runtime_role_code)) fail('STATE_BINDING_FACTS_INVALID', `${label}[${index}] has an unknown runtime role`)
    const validFrom = assertTimestamp(fact.valid_from, `${label}[${index}].valid_from`)
    const validUntil = assertTimestamp(fact.valid_until, `${label}[${index}].valid_until`)
    if (validFrom >= validUntil) fail('STATE_BINDING_FACTS_INVALID', `${label}[${index}] has an empty or reversed interval`)
    return clone(fact)
  }).sort((left, right) => left.runtime_role_code < right.runtime_role_code ? -1 : left.runtime_role_code > right.runtime_role_code ? 1 : 0)
  if (canonicalizeStateRecord(normalized.map((fact) => fact.runtime_role_code)) !== canonicalizeStateRecord(RUNTIME_ROLE_CODES)) {
    fail('STATE_BINDING_FACTS_INVALID', `${label} has missing or duplicate runtime roles`)
  }
  if (new Set(normalized.map((fact) => fact.binding_code)).size !== normalized.length) {
    fail('STATE_BINDING_COLLISION', `${label} must use a distinct binding for every runtime role`)
  }
  return Object.freeze(normalized.map((fact) => Object.freeze(fact)))
}

function validateIdentityBindingsRecord(record, label) {
  assertPlainObject(record, label)
  assertHash(record.record_digest_sha256, `${label}.record_digest_sha256`)
  const unsigned = clone(record)
  delete unsigned.record_digest_sha256
  const computed = sha256Hex(Buffer.from(canonicalizeStateRecord(unsigned), 'utf8'))
  if (computed !== record.record_digest_sha256) fail('STATE_IDENTITY_BINDINGS_DIGEST_MISMATCH', `${label} digest does not bind its complete content`)
  if (!Array.isArray(record.bindings)) fail('STATE_BINDING_FACTS_INVALID', `${label}.bindings must be an array`)
  const facts = validateBindingFacts(record.bindings.map((binding) => ({
    binding_code: binding.binding_code,
    runtime_role_code: binding.runtime_role_code,
    valid_from: binding.valid_from,
    valid_until: binding.valid_until,
  })), `${label}.bindings projection`)
  return { record: clone(record), facts }
}

function bindingFact(bindingFacts, runtimeRoleCode) {
  return bindingFacts.find((fact) => fact.runtime_role_code === runtimeRoleCode)
}

function requiredTrustedBinding(bindingFacts, runtimeRoleCode, bindingCode, label, at) {
  const expected = bindingFact(bindingFacts, runtimeRoleCode)
  if (!expected || expected.binding_code !== bindingCode) fail('STATE_AUTHENTICATED_BINDING_MISMATCH', `${label} is not the verified ${runtimeRoleCode} binding`)
  const atMs = assertTimestamp(at, `${label} binding time`)
  if (atMs < assertTimestamp(expected.valid_from, `${label} binding valid_from`) || atMs >= assertTimestamp(expected.valid_until, `${label} binding valid_until`)) {
    fail('STATE_AUTHENTICATED_BINDING_EXPIRED', `${label} binding is not valid at the persistence boundary`)
  }
  return expected
}

function generationContext(pair) {
  return {
    pair_code: pair.pair_code,
    pair_generation: pair.pair_generation,
    runtime_profile_record_digest_sha256: pair.runtime_profile.record_digest_sha256,
    identity_bindings_record_digest_sha256: pair.identity_bindings.record_digest_sha256,
  }
}

function assertGenerationContext(actual, expected) {
  assertExactKeys(actual, ['pair_code', 'pair_generation', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256'], 'commit generation context')
  assertCode(actual.pair_code, 'commit generation pair code')
  assertPositiveInteger(actual.pair_generation, 'commit generation pair generation')
  assertHash(actual.runtime_profile_record_digest_sha256, 'commit runtime profile digest')
  assertHash(actual.identity_bindings_record_digest_sha256, 'commit identity bindings digest')
  if (canonicalizeStateRecord(actual) !== canonicalizeStateRecord(expected)) {
    fail('STATE_COMMIT_GENERATION_MISMATCH', 'commit does not bind the generation active at persistence time')
  }
}

function assertPermitTiming(record) {
  const issued = assertTimestamp(record.issued_at, 'permit issued_at')
  const notBefore = assertTimestamp(record.not_before, 'permit not_before')
  const expires = assertTimestamp(record.expires_at, 'permit expires_at')
  if (!(issued <= notBefore && notBefore < expires)) fail('STATE_PERMIT_INTERVAL_INVALID', 'permit timing is not causal')
  const maximum = record.permit_kind_code === 'bootstrap' ? 3_600_000 : 900_000
  if (expires - issued > maximum) fail('STATE_PERMIT_INTERVAL_INVALID', 'permit exceeds its maximum lifetime')
}

const transitionRules = new Map([
  ['bootstrap|ready|in_progress|operation_claimed|operation_claimed', 'trusted_launcher'],
  ['bootstrap|ready|revoked|authority_withdrawal|authority_withdrawal', 'bootstrap_authority'],
  ['bootstrap|in_progress|spent|verified_effect|canonical_receipt_verified', 'trusted_launcher'],
  ['bootstrap|in_progress|recovery_required|state_ambiguous|state_ambiguous', 'trusted_launcher'],
  ['recovery|ready|in_progress|operation_claimed|operation_claimed', 'trusted_launcher'],
  ['recovery|ready|revoked|authority_withdrawal|authority_withdrawal', 'recovery_authority'],
  ['recovery|in_progress|spent|verified_effect|canonical_receipt_verified', 'trusted_launcher'],
  ['recovery|in_progress|recovery_required|state_ambiguous|state_ambiguous', 'trusted_launcher'],
  ['post_promotion_completion|ready|in_progress|operation_claimed|operation_claimed', 'trusted_launcher'],
  ['post_promotion_completion|ready|revoked|authority_withdrawal|authority_withdrawal', 'recovery_authority'],
  ['post_promotion_completion|in_progress|spent|no_effect_verified|no_effect_verified', 'independent_verifier'],
  ['post_promotion_completion|in_progress|recovery_required|state_ambiguous|state_ambiguous', 'independent_verifier'],
])

function assertTransitionAgainstPermit(projection, transition, trustedBindings, { allowClaim = true } = {}) {
  assertPlainObject(transition, 'permit transition')
  if (transition.record_kind_code !== 'permit_transition') fail('STATE_PERMIT_TRANSITION_INVALID', 'record is not a permit transition')
  assertCode(transition.record_code, 'transition record_code')
  assertCode(transition.permit_code, 'transition permit_code')
  assertCanonicalRecordDigest(transition, 'transition')
  assertHash(transition.permit_issuance_record_digest_sha256, 'permit issuance digest')
  assertHash(transition.operation_nonce, 'transition operation_nonce')
  assertPositiveInteger(transition.transition_sequence, 'transition sequence')
  const entry = projection.permits.get(transition.permit_code)
  if (!entry) fail('STATE_PERMIT_UNKNOWN', 'transition references an unknown permit')
  const issuance = entry.record
  if (transition.permit_kind_code !== issuance.permit_kind_code || transition.permit_issuance_record_digest_sha256 !== issuance.record_digest_sha256) {
    fail('STATE_PERMIT_SUBSTITUTION', 'transition does not identify its exact permit issuance')
  }
  if (transition.operation_nonce !== issuance.operation_nonce) fail('STATE_PERMIT_NONCE_MISMATCH', 'transition nonce differs from the permit')
  if (!allowClaim && transition.transition_code === 'operation_claimed') fail('STATE_CLAIM_NOT_ATOMIC', 'claim transitions must be registered atomically with operation start')
  const prior = entry.transitions.at(-1)
  const expectedSequence = prior ? prior.transition_sequence + 1 : 1
  const expectedPrevious = prior ? prior.record_digest_sha256 : null
  const expectedFrom = prior ? prior.to_state_code : 'ready'
  if (transition.transition_sequence !== expectedSequence || transition.previous_transition_record_digest_sha256 !== expectedPrevious) {
    fail('STATE_PERMIT_FORK_OR_GAP', 'transition does not extend the current permit leaf')
  }
  if (transition.from_state_code !== expectedFrom) fail('STATE_PERMIT_FROM_STATE_INVALID', 'transition from_state is not current')
  if (TERMINAL_PERMIT_STATES.has(expectedFrom)) fail('STATE_PERMIT_TERMINAL', 'terminal permit state cannot be extended')
  const ruleKey = [transition.permit_kind_code, transition.from_state_code, transition.to_state_code, transition.transition_code, transition.reason_code].join('|')
  const requiredRole = transitionRules.get(ruleKey)
  if (!requiredRole || transition.recorded_by_runtime_role_code !== requiredRole) fail('STATE_PERMIT_TRANSITION_INVALID', 'transition is not in the closed transition matrix')
  const expectedLogicalState = issuance.target_empty_logical_state ?? issuance.target_logical_state
  if (transition.transition_code === 'state_ambiguous') {
    if (transition.observed_logical_state !== null) assertPlainObject(transition.observed_logical_state, 'optional last-known logical state')
  } else if (['operation_claimed', 'authority_withdrawal'].includes(transition.transition_code) && canonicalizeStateRecord(transition.observed_logical_state) !== canonicalizeStateRecord(expectedLogicalState)) {
    fail('STATE_PERMIT_OBSERVED_STATE_MISMATCH', 'transition does not carry the exact permit-scoped expected state')
  } else if (!['operation_claimed', 'authority_withdrawal'].includes(transition.transition_code) && !isPlainObject(transition.observed_logical_state)) {
    fail('STATE_PERMIT_OBSERVED_STATE_MISMATCH', 'verified terminal transition requires one exact observed state reference')
  }
  const occurred = assertTimestamp(transition.occurred_at, 'transition occurred_at')
  const persisted = assertTimestamp(transition.persisted_at, 'transition persisted_at')
  requiredTrustedBinding(trustedBindings, requiredRole, transition.recorded_by_binding_code, 'semantic recorder', transition.occurred_at)
  requiredTrustedBinding(trustedBindings, 'trusted_launcher', transition.persisted_by_binding_code, 'transition persistence broker', transition.persisted_at)
  const issued = assertTimestamp(issuance.issued_at, 'permit issued_at')
  const notBefore = assertTimestamp(issuance.not_before, 'permit not_before')
  const expires = assertTimestamp(issuance.expires_at, 'permit expires_at')
  if (occurred > persisted) fail('STATE_PERMIT_BACKDATED_PERSISTENCE', 'transition occurred_at exceeds persisted_at')
  if (persisted >= expires || occurred >= expires) fail('STATE_PERMIT_EXPIRED', 'transition was not persisted before exclusive expiry')
  if (prior && persisted <= assertTimestamp(prior.persisted_at, 'prior transition persisted_at')) fail('STATE_PERMIT_CHRONOLOGY_INVALID', 'transition persistence is not strictly increasing')
  if (prior && occurred <= assertTimestamp(prior.occurred_at, 'prior transition occurred_at')) fail('STATE_PERMIT_CHRONOLOGY_INVALID', 'transition occurrence time is not strictly increasing')
  if (requiredRole.endsWith('_authority')) {
    if (occurred < issued) fail('STATE_PERMIT_CHRONOLOGY_INVALID', 'authority withdrawal predates issuance')
    if (transition.recorded_by_binding_code !== issuance.issuer_binding_code) fail('STATE_PERMIT_AUTHORITY_MISMATCH', 'withdrawal was not recorded by the issuing authority')
  } else if (occurred < notBefore || persisted < notBefore) {
    fail('STATE_PERMIT_NOT_YET_VALID', 'operational transition predates not_before')
  }
  if (transition.transition_code === 'operation_claimed' && expires - persisted < 60_000) {
    fail('STATE_PERMIT_CLAIM_LIFETIME_INSUFFICIENT', 'permit has less than 60 seconds remaining')
  }
  selectGenerationPairFromProjection(projection, transition.persisted_at, {
    runtimeProfileRecordDigestSha256: issuance.runtime_profile_record_digest_sha256,
    identityBindingsRecordDigestSha256: issuance.identity_bindings_record_digest_sha256,
  })
  if (transition.transition_code === 'operation_claimed' && issuance.permit_kind_code === 'bootstrap') {
    const matchedSeal = projection.registryRecords.get(entry.matched_seal_registry_key)
    const revocation = projection.registryRevocations.get(entry.matched_seal_registry_key)
    if (
      !matchedSeal
      || matchedSeal.record_digest_sha256 !== entry.matched_seal_record_digest_sha256
      || !bootstrapSealMatchesPermit(matchedSeal.record, issuance)
      || assertTimestamp(matchedSeal.recorded_at, 'bootstrap seal recorded_at') > persisted
      || assertTimestamp(matchedSeal.record.sealed_at, 'bootstrap seal sealed_at') > persisted
      || assertTimestamp(matchedSeal.record.expires_at, 'bootstrap seal expires_at') <= persisted
      || (revocation && assertTimestamp(revocation.revoked_at, 'bootstrap seal revoked_at') <= persisted)
    ) fail('STATE_BOOTSTRAP_SEAL_MISMATCH', 'bootstrap claim requires the exact issuance-matched seal to remain current and nonrevoked')
    if (entry.matched_seal_operation_id === null || matchedSeal.record.operation_id !== entry.matched_seal_operation_id || transition.operation_id !== entry.matched_seal_operation_id) {
      fail('STATE_BOOTSTRAP_OPERATION_MISMATCH', 'bootstrap claim operation differs from the exactly matched bundle seal')
    }
  }
  if (prior && (transition.operation_id !== prior.operation_id || transition.operation_nonce !== prior.operation_nonce)) {
    fail('STATE_PERMIT_OPERATION_MISMATCH', 'permit transition changed operation identity')
  }
  if (projection.permitRecordCodes.has(transition.record_code) || projection.permitRecordDigests.has(transition.record_digest_sha256)) {
    fail('STATE_PERMIT_TRANSITION_COLLISION', 'transition record identity already exists')
  }
}

function applyEvent(projection, event, trustedBindings, { allowClaim = true, recoveryBindingAt = undefined, historicalBindingAt = undefined } = {}) {
  assertPlainObject(event, 'protected-state event')
  const kind = event.event_kind_code
  switch (kind) {
    case 'generation_pair_activated': {
      assertExactKeys(event, ['event_kind_code', 'pair_code', 'pair_generation', 'runtime_profile', 'identity_bindings', 'identity_bindings_record', 'trusted_role_bindings', 'activated_at', 'activated_by_binding_code'], kind)
      assertCode(event.pair_code, 'pair_code')
      assertPositiveInteger(event.pair_generation, 'pair_generation')
      assertExactKeys(event.runtime_profile, ['generation_number', 'generation_code', 'record_digest_sha256', 'valid_from', 'expires_at'], 'runtime profile')
      assertExactKeys(event.identity_bindings, ['generation_number', 'generation_code', 'record_digest_sha256', 'bound_runtime_profile_record_digest_sha256', 'valid_from', 'expires_at'], 'identity bindings')
      assertHash(event.identity_bindings.bound_runtime_profile_record_digest_sha256, 'identity bindings runtime profile commitment')
      if (event.identity_bindings.bound_runtime_profile_record_digest_sha256 !== event.runtime_profile.record_digest_sha256) fail('STATE_GENERATION_PAIR_MISMATCH', 'identity bindings do not pin the paired runtime profile')
      for (const [label, generation] of [['runtime profile', event.runtime_profile], ['identity bindings', event.identity_bindings]]) {
        assertPositiveInteger(generation.generation_number, `${label} generation_number`)
        assertCode(generation.generation_code, `${label} generation_code`)
        assertHash(generation.record_digest_sha256, `${label} record digest`)
        const validFrom = assertTimestamp(generation.valid_from, `${label} valid_from`)
        const expires = assertTimestamp(generation.expires_at, `${label} expires_at`)
        const activated = assertTimestamp(event.activated_at, 'generation pair activated_at')
        if (!(validFrom <= activated && activated < expires)) fail('STATE_GENERATION_INTERVAL_INVALID', `${label} activation is outside its validity interval`)
      }
      const activated = assertTimestamp(event.activated_at, 'generation activated_at')
      const sealedBindings = validateIdentityBindingsRecord(event.identity_bindings_record, 'generation identity_bindings_record')
      if (event.identity_bindings_record.binding_generation !== event.identity_bindings.generation_number ||
          event.identity_bindings_record.binding_set_code !== event.identity_bindings.generation_code ||
          event.identity_bindings_record.record_digest_sha256 !== event.identity_bindings.record_digest_sha256 ||
          event.identity_bindings_record.runtime_profile_record_digest_sha256 !== event.identity_bindings.bound_runtime_profile_record_digest_sha256 ||
          event.identity_bindings_record.issued_at !== event.identity_bindings.valid_from ||
          event.identity_bindings_record.expires_at !== event.identity_bindings.expires_at) {
        fail('STATE_IDENTITY_BINDINGS_SUBSTITUTION', 'generation summary differs from its exact sealed identity-binding record')
      }
      const nextBindingFacts = validateBindingFacts(event.trusted_role_bindings, 'generation trusted_role_bindings')
      if (canonicalizeStateRecord(nextBindingFacts) !== canonicalizeStateRecord(sealedBindings.facts)) fail('STATE_IDENTITY_BINDINGS_SUBSTITUTION', 'persisted role-binding facts differ from the exact identity-binding record')
      const identityExpires = assertTimestamp(event.identity_bindings.expires_at, 'identity bindings expires_at')
      for (const fact of nextBindingFacts) {
        if (activated < assertTimestamp(fact.valid_from, `${fact.runtime_role_code} valid_from`) || activated >= assertTimestamp(fact.valid_until, `${fact.runtime_role_code} valid_until`) || assertTimestamp(fact.valid_until, `${fact.runtime_role_code} valid_until`) > identityExpires) {
          fail('STATE_BINDING_FACTS_INVALID', 'every persisted role binding must be active at generation activation and end no later than the identity generation')
        }
      }
      requiredTrustedBinding(trustedBindings, 'trusted_launcher', event.activated_by_binding_code, 'generation activator', event.activated_at)
      const prior = projection.generationPairs.at(-1)
      const expected = prior ? prior.pair_generation + 1 : 1
      if (event.pair_generation !== expected) fail('STATE_GENERATION_GAP_OR_STALE', 'pair generations must be contiguous and increasing')
      if (prior && activated <= assertTimestamp(prior.activated_at, 'prior generation pair activated_at')) fail('STATE_GENERATION_CHRONOLOGY_INVALID', 'replacement pair must advance activation time')
      if (prior) {
        const runtimeAdvanced = event.runtime_profile.generation_number > prior.runtime_profile.generation_number
        const bindingsAdvanced = event.identity_bindings.generation_number > prior.identity_bindings.generation_number
        if (event.runtime_profile.generation_number < prior.runtime_profile.generation_number ||
            event.identity_bindings.generation_number < prior.identity_bindings.generation_number ||
            (!runtimeAdvanced && !bindingsAdvanced)) {
          fail('STATE_GENERATION_GAP_OR_STALE', 'a replacement pair must advance at least one inner generation and may not move either backwards')
        }
      }
      for (const existing of projection.generationPairs) {
        for (const field of ['runtime_profile', 'identity_bindings']) {
          const incoming = event[field]
          const known = existing[field]
          const sameNumber = incoming.generation_number === known.generation_number
          if ((sameNumber && canonicalizeStateRecord(incoming) !== canonicalizeStateRecord(known)) ||
              (!sameNumber && incoming.record_digest_sha256 === known.record_digest_sha256)) {
            fail('STATE_GENERATION_SUBSTITUTION', `${field} stable generation identity was repurposed`)
          }
        }
      }
      if (projection.generationPairs.some((entry) => entry.pair_code === event.pair_code)) fail('STATE_GENERATION_COLLISION', 'generation pair code was reused')
      projection.generationPairs.push(clone(event))
      return
    }
    case 'generation_pair_revoked': {
      assertExactKeys(event, ['event_kind_code', 'pair_code', 'pair_generation', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'revoked_at', 'reason_code', 'revoked_by_binding_code'], kind)
      assertCode(event.pair_code, 'pair_code')
      assertPositiveInteger(event.pair_generation, 'pair_generation')
      assertHash(event.runtime_profile_record_digest_sha256, 'runtime profile record digest')
      assertHash(event.identity_bindings_record_digest_sha256, 'identity bindings record digest')
      assertCode(event.reason_code, 'generation revocation reason')
      requiredTrustedBinding(trustedBindings, 'trusted_launcher', event.revoked_by_binding_code, 'generation revoker', event.revoked_at)
      const target = projection.generationPairs.find((entry) => entry.pair_generation === event.pair_generation)
      if (!target || target.pair_code !== event.pair_code || target.runtime_profile.record_digest_sha256 !== event.runtime_profile_record_digest_sha256 || target.identity_bindings.record_digest_sha256 !== event.identity_bindings_record_digest_sha256) fail('STATE_GENERATION_SUBSTITUTION', 'pair revocation target does not exist exactly')
      if (assertTimestamp(event.revoked_at, 'generation revoked_at') < assertTimestamp(target.activated_at, 'generation activated_at')) fail('STATE_GENERATION_CHRONOLOGY_INVALID', 'revocation predates activation')
      if (projection.generationPairRevocations.has(event.pair_code)) fail('STATE_GENERATION_ALREADY_REVOKED', 'generation pair already has a revocation')
      projection.generationPairRevocations.set(event.pair_code, clone(event))
      return
    }
    case 'registry_recorded': {
      assertExactKeys(event, ['event_kind_code', 'registry_kind_code', 'record_code', 'record_digest_sha256', 'recorded_at', 'recorded_by_runtime_role_code', 'recorded_by_binding_code', 'record'], kind)
      if (!REGISTRY_KINDS.has(event.registry_kind_code) || event.record.record_kind_code !== event.registry_kind_code) fail('STATE_REGISTRY_KIND_INVALID', 'unsupported or mismatched registry kind')
      assertCode(event.record_code, 'registry record_code')
      assertCanonicalRecordDigest(event.record, 'registry record')
      if (event.record.record_code !== event.record_code || event.record.record_digest_sha256 !== event.record_digest_sha256) fail('STATE_REGISTRY_SUBSTITUTION', 'registry wrapper differs from its immutable record')
      const requiredRole = event.registry_kind_code === 'collector_handoff' ? 'handoff_broker' : 'trusted_launcher'
      if (event.recorded_by_runtime_role_code !== requiredRole) fail('STATE_REGISTRY_WRITER_INVALID', 'registry kind has the wrong fixed writer role')
      requiredTrustedBinding(trustedBindings, requiredRole, event.recorded_by_binding_code, 'registry writer', event.recorded_at)
      const recorded = assertTimestamp(event.recorded_at, 'registry recorded_at')
      const semanticRecordedAt = event.registry_kind_code === 'collector_handoff' ? event.record.handoff_recorded_at : event.record.sealed_at
      if (recorded < assertTimestamp(semanticRecordedAt, 'registry semantic recorded time')) fail('STATE_REGISTRY_CHRONOLOGY_INVALID', 'registry persistence predates record creation')
      if (recorded >= assertTimestamp(event.record.expires_at, 'registry record expiry')) fail('STATE_REGISTRY_EXPIRED', 'expired registry records cannot be introduced')
      selectGenerationPairFromProjection(projection, event.recorded_at, {
        runtimeProfileRecordDigestSha256: event.record.runtime_profile_record_digest_sha256,
        identityBindingsRecordDigestSha256: event.record.identity_bindings_record_digest_sha256,
      })
      const key = registryKey(event.registry_kind_code, event.record_code)
      const existing = projection.registryRecords.get(key)
      if (existing) {
        if (existing.record_digest_sha256 === event.record_digest_sha256 && canonicalizeStateRecord(existing.record) === canonicalizeStateRecord(event.record)) fail('STATE_REGISTRY_REPLAY', 'identical registry replay is not a new append')
        fail('STATE_REGISTRY_COLLISION', 'registry record code collides with different content')
      }
      for (const candidate of projection.registryRecords.values()) {
        if (candidate.record_digest_sha256 === event.record_digest_sha256) fail('STATE_REGISTRY_COLLISION', 'registry digest is already bound to another code')
      }
      projection.registryRecords.set(key, clone(event))
      return
    }
    case 'registry_record_revoked': {
      assertExactKeys(event, ['event_kind_code', 'registry_kind_code', 'record_code', 'record_digest_sha256', 'revoked_at', 'reason_code', 'revoked_by_runtime_role_code', 'revoked_by_binding_code'], kind)
      const key = registryKey(event.registry_kind_code, event.record_code)
      const target = projection.registryRecords.get(key)
      if (!target || target.record_digest_sha256 !== event.record_digest_sha256) fail('STATE_REGISTRY_SUBSTITUTION', 'registry revocation target does not exist exactly')
      const requiredRole = event.registry_kind_code === 'collector_handoff' ? 'handoff_broker' : 'trusted_launcher'
      if (event.revoked_by_runtime_role_code !== requiredRole) fail('STATE_REGISTRY_WRITER_INVALID', 'registry revocation has the wrong fixed role')
      requiredTrustedBinding(trustedBindings, requiredRole, event.revoked_by_binding_code, 'registry revoker', event.revoked_at)
      if (assertTimestamp(event.revoked_at, 'registry revoked_at') < assertTimestamp(target.recorded_at, 'registry recorded_at')) fail('STATE_REGISTRY_CHRONOLOGY_INVALID', 'registry revocation predates recording')
      assertCode(event.reason_code, 'registry revocation reason')
      if (projection.registryRevocations.has(key)) fail('STATE_REGISTRY_ALREADY_REVOKED', 'registry record already revoked')
      projection.registryRevocations.set(key, clone(event))
      return
    }
    case 'permit_issued': {
      assertExactKeys(event, ['event_kind_code', 'record_code', 'record_digest_sha256', 'issued_by_runtime_role_code', 'issued_by_binding_code', 'persisted_by_binding_code', 'persisted_at', 'record'], kind)
      const record = event.record
      assertPlainObject(record, 'permit issuance')
      if (!['permit_issuance', 'recovery_permit', 'post_promotion_completion_permit'].includes(record.record_kind_code)) fail('STATE_PERMIT_KIND_INVALID', 'record is not a supported permit issuance')
      if (!['bootstrap', 'recovery', 'post_promotion_completion'].includes(record.permit_kind_code)) fail('STATE_PERMIT_KIND_INVALID', 'unsupported permit kind')
      if (record.permit_kind_code !== 'bootstrap') fail('STATE_PERMIT_KIND_UNIMPLEMENTED', 'D9.1 persists bootstrap permits only; later permit kinds require their implementation tranche')
      assertCode(record.permit_code, 'permit_code')
      assertCode(record.record_code, 'permit record_code')
      assertCanonicalRecordDigest(record, 'permit')
      assertHash(record.operation_nonce, 'permit operation_nonce')
      if (event.record_code !== record.record_code || event.record_digest_sha256 !== record.record_digest_sha256) fail('STATE_PERMIT_SUBSTITUTION', 'permit wrapper differs from immutable record')
      const issuerRole = record.permit_kind_code === 'bootstrap' ? 'bootstrap_authority' : 'recovery_authority'
      if (event.issued_by_runtime_role_code !== issuerRole || event.issued_by_binding_code !== record.issuer_binding_code) fail('STATE_PERMIT_AUTHORITY_MISMATCH', 'permit issuer fields disagree')
      requiredTrustedBinding(trustedBindings, issuerRole, event.issued_by_binding_code, 'permit issuer', record.issued_at)
      requiredTrustedBinding(trustedBindings, 'trusted_launcher', event.persisted_by_binding_code, 'permit persistence broker', event.persisted_at)
      if (event.issued_by_binding_code === event.persisted_by_binding_code) fail('STATE_SEPARATION_OF_DUTY', 'permit issuer and persistence broker must be distinct')
      assertPermitTiming(record)
      const persisted = assertTimestamp(event.persisted_at, 'permit persisted_at')
      if (persisted < assertTimestamp(record.issued_at, 'permit issued_at') || persisted >= assertTimestamp(record.expires_at, 'permit expires_at')) fail('STATE_PERMIT_CHRONOLOGY_INVALID', 'permit persistence is outside issuance lifetime')
      const permitGeneration = selectGenerationPairFromProjection(projection, event.persisted_at, {
        runtimeProfileRecordDigestSha256: record.runtime_profile_record_digest_sha256,
        identityBindingsRecordDigestSha256: record.identity_bindings_record_digest_sha256,
      })
      const expires = assertTimestamp(record.expires_at, 'permit expires_at')
      if (expires > assertTimestamp(permitGeneration.runtime_profile.expires_at, 'permit runtime profile expiry') || expires > assertTimestamp(permitGeneration.identity_bindings.expires_at, 'permit identity binding expiry')) {
        fail('STATE_PERMIT_BINDING_LIFETIME_INVALID', 'permit outlives its pinned runtime or identity generation')
      }
      for (const [role, code] of [
        [issuerRole, record.issuer_binding_code],
        ['bundle_importer', record.importer_binding_code],
        ['human_submitter', record.submitter_binding_code],
        ['operational_witness', record.witness_binding_code],
      ]) {
        const fact = requiredTrustedBinding(permitGeneration.trusted_role_bindings, role, code, `permit ${role}`, record.issued_at)
        if (expires > assertTimestamp(fact.valid_until, `permit ${role} valid_until`)) {
          fail('STATE_PERMIT_BINDING_LIFETIME_INVALID', `permit outlives the ${role} binding`)
        }
      }
      let matchedSealOperationId = null
      let matchedSealRegistryKey = null
      let matchedSealRecordDigestSha256 = null
      if (record.permit_kind_code === 'bootstrap') {
        const matchingSeals = [...projection.registryRecords.entries()].filter(([key, candidate]) => {
          if (!key.startsWith('bundle_seal\0')) return false
          const seal = candidate.record
          const revoked = projection.registryRevocations.get(key)
          return bootstrapSealMatchesPermit(seal, record)
            && candidate.recorded_at <= event.persisted_at
            && assertTimestamp(seal.sealed_at, 'bootstrap seal sealed_at') <= assertTimestamp(record.issued_at, 'bootstrap permit issued_at')
            && (!revoked || revoked.revoked_at > event.persisted_at)
            && seal.expires_at > event.persisted_at
        })
        if (matchingSeals.length !== 1) fail('STATE_BOOTSTRAP_SEAL_MISMATCH', 'bootstrap permit requires exactly one active matching bootstrap bundle seal')
        matchedSealRegistryKey = matchingSeals[0][0]
        matchedSealOperationId = matchingSeals[0][1].record.operation_id
        matchedSealRecordDigestSha256 = matchingSeals[0][1].record.record_digest_sha256
      }
      if (projection.permits.has(record.permit_code) || projection.permitRecordCodes.has(record.record_code) || projection.permitRecordDigests.has(record.record_digest_sha256)) fail('STATE_PERMIT_COLLISION', 'permit identity already exists')
      if (projection.operationsByNonce.has(record.operation_nonce)) fail('STATE_NONCE_REPLAY', 'operation nonce was already consumed by an operation')
      for (const entry of projection.permits.values()) if (entry.record.operation_nonce === record.operation_nonce) fail('STATE_NONCE_REPLAY', 'operation nonce is already reserved by another permit')
      projection.permits.set(record.permit_code, {
        record: clone(record),
        event: clone(event),
        transitions: [],
        matched_seal_operation_id: matchedSealOperationId,
        matched_seal_registry_key: matchedSealRegistryKey,
        matched_seal_record_digest_sha256: matchedSealRecordDigestSha256,
      })
      projection.permitRecordCodes.add(record.record_code)
      projection.permitRecordDigests.add(record.record_digest_sha256)
      return
    }
    case 'permit_transition_recorded': {
      assertExactKeys(event, ['event_kind_code', 'record'], kind)
      const transition = event.record
      assertTransitionAgainstPermit(projection, transition, trustedBindings, { allowClaim })
      const entry = projection.permits.get(transition.permit_code)
      entry.transitions.push(clone(transition))
      projection.permitRecordCodes.add(transition.record_code)
      projection.permitRecordDigests.add(transition.record_digest_sha256)
      return
    }
    case 'operation_started': {
      assertExactKeys(event, ['event_kind_code', 'operation_id', 'operation_nonce', 'operation_mode_code', 'started_at', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'permit_code', 'permit_claim_record_digest_sha256', 'started_by_binding_code'], kind)
      assertCode(event.operation_id, 'operation_id')
      assertHash(event.operation_nonce, 'operation_nonce')
      assertHash(event.runtime_profile_record_digest_sha256, 'runtime profile digest')
      assertHash(event.identity_bindings_record_digest_sha256, 'identity bindings digest')
      assertTimestamp(event.started_at, 'operation started_at')
      if (!OPERATION_MODES.has(event.operation_mode_code)) fail('STATE_OPERATION_MODE_INVALID', 'unsupported operation mode')
      requiredTrustedBinding(trustedBindings, 'trusted_launcher', event.started_by_binding_code, 'operation starter', event.started_at)
      selectGenerationPairFromProjection(projection, event.started_at, {
        runtimeProfileRecordDigestSha256: event.runtime_profile_record_digest_sha256,
        identityBindingsRecordDigestSha256: event.identity_bindings_record_digest_sha256,
      })
      if (projection.operationsByNonce.has(event.operation_nonce) || projection.operationsById.has(event.operation_id)) fail('STATE_NONCE_REPLAY', 'operation ID or nonce has already been used')
      if ((event.permit_code === null) !== (event.permit_claim_record_digest_sha256 === null)) fail('STATE_OPERATION_PERMIT_INVALID', 'permit code and claim digest must be paired')
      if (event.permit_code !== null) {
        assertCode(event.permit_code, 'operation permit_code')
        assertHash(event.permit_claim_record_digest_sha256, 'operation permit claim digest')
        const permit = projection.permits.get(event.permit_code)
        const claim = permit?.transitions.at(-1)
        if (!claim || claim.transition_code !== 'operation_claimed' || claim.record_digest_sha256 !== event.permit_claim_record_digest_sha256 || claim.operation_id !== event.operation_id || claim.operation_nonce !== event.operation_nonce) fail('STATE_OPERATION_PERMIT_INVALID', 'operation does not match the current atomic permit claim')
        if (assertTimestamp(event.started_at, 'operation started_at') !== assertTimestamp(claim.persisted_at, 'claim persisted_at')) fail('STATE_OPERATION_PERMIT_INVALID', 'operation start must equal claim persistence time')
        const expectedMode = permit.record.permit_kind_code === 'bootstrap' ? 'bootstrap' : 'recovery'
        if (event.operation_mode_code !== expectedMode) fail('STATE_OPERATION_PERMIT_INVALID', 'operation mode is incompatible with permit kind')
        if (permit.record.operation_id !== undefined && permit.record.operation_id !== event.operation_id) fail('STATE_OPERATION_PERMIT_INVALID', 'operation ID differs from the exact permit scope')
        if (permit.record.runtime_profile_record_digest_sha256 !== event.runtime_profile_record_digest_sha256 || permit.record.identity_bindings_record_digest_sha256 !== event.identity_bindings_record_digest_sha256) fail('STATE_OPERATION_PERMIT_INVALID', 'operation generation pins differ from the permit')
      } else {
        for (const permit of projection.permits.values()) if (permit.record.operation_nonce === event.operation_nonce) fail('STATE_OPERATION_PERMIT_INVALID', 'permit-reserved nonce requires its exact atomic claim')
      }
      const operation = { ...clone(event), state_code: 'in_progress', terminal_event: null }
      projection.operationsByNonce.set(event.operation_nonce, operation)
      projection.operationsById.set(event.operation_id, operation)
      return
    }
    case 'operation_no_effect_verified':
    case 'operation_recovery_required': {
      const common = ['event_kind_code', 'operation_id', 'operation_nonce', 'recorded_at', 'recorded_by_runtime_role_code', 'recorded_by_binding_code', 'reason_code']
      const keys = kind === 'operation_no_effect_verified' ? [...common, 'before_logical_state_sha256', 'after_logical_state_sha256'] : [...common, 'last_known_logical_state_sha256']
      assertExactKeys(event, keys, kind)
      const operation = projection.operationsByNonce.get(event.operation_nonce)
      if (!operation || operation.operation_id !== event.operation_id || operation.state_code !== 'in_progress') fail('STATE_OPERATION_NOT_ACTIVE', 'terminal event does not target one current operation')
      const recorded = assertTimestamp(event.recorded_at, 'operation terminal recorded_at')
      if (recorded < assertTimestamp(operation.started_at, 'operation started_at')) fail('STATE_OPERATION_CHRONOLOGY_INVALID', 'terminal event predates operation')
      if (kind === 'operation_no_effect_verified') {
        if (event.recorded_by_runtime_role_code !== 'independent_verifier') fail('STATE_OPERATION_VERIFIER_INVALID', 'no-effect result requires independent verifier')
        requiredTrustedBinding(trustedBindings, 'independent_verifier', event.recorded_by_binding_code, 'no-effect verifier', historicalBindingAt ?? event.recorded_at)
        assertHash(event.before_logical_state_sha256, 'before logical state')
        assertHash(event.after_logical_state_sha256, 'after logical state')
        if (event.before_logical_state_sha256 !== event.after_logical_state_sha256) fail('STATE_OPERATION_EFFECT_DETECTED', 'no-effect result has different before and after states')
        operation.state_code = 'no_effect_verified'
      } else {
        if (event.recorded_by_runtime_role_code !== 'trusted_launcher') fail('STATE_OPERATION_RECORDER_INVALID', 'recovery-required result requires trusted launcher')
        requiredTrustedBinding(trustedBindings, 'trusted_launcher', event.recorded_by_binding_code, 'recovery recorder', historicalBindingAt ?? event.recorded_at)
        if (event.last_known_logical_state_sha256 !== null) assertHash(event.last_known_logical_state_sha256, 'last known logical state')
        operation.state_code = 'recovery_required'
      }
      assertCode(event.reason_code, 'operation terminal reason')
      operation.terminal_event = clone(event)
      return
    }
    case 'recovery_action_recorded': {
      assertExactKeys(event, ['event_kind_code', 'recovery_action_code', 'recovered_at', 'recovered_by_binding_code', 'affected_sequence', 'affected_commit_sha256', 'operation_id', 'operation_nonce', 'incident_sha256'], kind)
      if (!['discarded_uncommitted_pending', 'discarded_incomplete_lock', 'discarded_abandoned_append_lock', 'finalized_durable_unanchored_commit', 'completed_durable_head_commit_cleanup', 'removed_terminal_operation_lock'].includes(event.recovery_action_code)) fail('STATE_RECOVERY_ACTION_INVALID', 'unsupported recovery action')
      assertTimestamp(event.recovered_at, 'recovery action time')
      assertCode(event.recovered_by_binding_code, 'recovery binding')
      requiredTrustedBinding(trustedBindings, 'recovery_authority', event.recovered_by_binding_code, 'recovery action recorder', recoveryBindingAt ?? event.recovered_at)
      if (event.affected_sequence !== null) assertPositiveInteger(event.affected_sequence, 'affected sequence')
      if (event.affected_commit_sha256 !== null) assertHash(event.affected_commit_sha256, 'affected commit digest')
      assertHash(event.incident_sha256, 'recovery incident digest')
      if ((event.operation_id === null) !== (event.operation_nonce === null)) fail('STATE_RECOVERY_ACTION_INVALID', 'recovery operation ID and nonce must be paired')
      if (event.operation_id !== null) {
        assertCode(event.operation_id, 'recovery operation_id')
        assertHash(event.operation_nonce, 'recovery operation_nonce')
      }
      projection.recoveryActions.push(clone(event))
      return
    }
    default:
      fail('STATE_EVENT_KIND_UNKNOWN', `unknown protected-state event ${String(kind)}`)
  }
}

function pairForGenerationContext(projection, context, authorityAt) {
  const matches = projection.generationPairs.filter((pair) => canonicalizeStateRecord(generationContext(pair)) === canonicalizeStateRecord(context))
  if (matches.length !== 1) fail('STATE_COMMIT_GENERATION_MISMATCH', 'historical recovery context does not identify exactly one generation pair')
  const pair = matches[0]
  const atMs = assertTimestamp(authorityAt, 'historical recovery authority time')
  if (
    atMs < assertTimestamp(pair.activated_at, 'historical pair activation')
    || atMs < assertTimestamp(pair.runtime_profile.valid_from, 'historical runtime valid_from')
    || atMs >= assertTimestamp(pair.runtime_profile.expires_at, 'historical runtime expires_at')
    || atMs < assertTimestamp(pair.identity_bindings.valid_from, 'historical bindings valid_from')
    || atMs >= assertTimestamp(pair.identity_bindings.expires_at, 'historical bindings expires_at')
  ) fail('STATE_COMMIT_GENERATION_MISMATCH', 'historical recovery context was not valid at its authority boundary')
  const revocation = projection.generationPairRevocations.get(pair.pair_code)
  if (revocation && assertTimestamp(revocation.revoked_at, 'historical pair revocation') < atMs) {
    fail('STATE_COMMIT_GENERATION_MISMATCH', 'historical recovery context was already revoked before its authority boundary')
  }
  return pair
}

function pairForOperationFromProjection(projection, operation) {
  const matches = projection.generationPairs.filter((pair) => (
    pair.runtime_profile.record_digest_sha256 === operation.runtime_profile_record_digest_sha256
    && pair.identity_bindings.record_digest_sha256 === operation.identity_bindings_record_digest_sha256
  ))
  if (matches.length !== 1) fail('STATE_COMMIT_GENERATION_MISMATCH', 'operation pins do not identify exactly one historical generation pair')
  return pairForGenerationContext(projection, generationContext(matches[0]), operation.started_at)
}

function historicalRecoveryAuthority(projection, events, transactionCode) {
  if (!['recovery.lock', 'recovery.operation-no-effect', 'recovery.terminal-lock'].includes(transactionCode)) return null
  const operationReference = events.find((event) => event.operation_id !== null && event.operation_id !== undefined && event.operation_nonce !== null && event.operation_nonce !== undefined)
  const operation = operationReference ? projection.operationsByNonce.get(operationReference.operation_nonce) : null
  if (operation && operation.operation_id !== operationReference.operation_id) fail('STATE_OPERATION_NOT_ACTIVE', 'recovery event operation identity is inconsistent')
  if (operation) {
    const pair = pairForOperationFromProjection(projection, operation)
    return { pair, authorityAt: operation.started_at }
  }
  const pair = projection.generationPairs.at(-1)
  if (!pair) fail('STATE_ACTIVE_GENERATION_MISSING', 'recovery append has no historical generation context')
  return { pair: pairForGenerationContext(projection, generationContext(pair), pair.activated_at), authorityAt: pair.activated_at }
}

function validateOperationTerminalTransaction(projection, events, transactionCode) {
  const expectedTerminalKind = ['operation.no-effect', 'recovery.operation-no-effect'].includes(transactionCode)
    ? 'operation_no_effect_verified'
    : transactionCode === 'operation.recovery-required'
      ? 'operation_recovery_required'
      : null
  if (expectedTerminalKind === null) return
  if (![1, 2].includes(events.length) || events.at(-1)?.event_kind_code !== expectedTerminalKind) {
    fail('STATE_OPERATION_TERMINAL_TRANSACTION_INVALID', 'operation terminal commit has the wrong atomic event shape')
  }
  const terminal = events.at(-1)
  const operation = projection.operationsByNonce.get(terminal.operation_nonce)
  if (!operation || operation.operation_id !== terminal.operation_id || operation.state_code !== 'in_progress') fail('STATE_OPERATION_NOT_ACTIVE', 'operation terminal commit does not target one current operation')
  const transition = events.length === 2 && events[0]?.event_kind_code === 'permit_transition_recorded' ? events[0].record : null
  if ((operation.permit_code === null) !== (transition === null)) fail('STATE_OPERATION_PERMIT_INVALID', 'permitted operations require one atomic terminal transition and unpermitted operations forbid one')
  if (!transition) return
  if (transition.operation_id !== terminal.operation_id || transition.operation_nonce !== terminal.operation_nonce || transition.persisted_at !== terminal.recorded_at) {
    fail('STATE_OPERATION_PERMIT_INVALID', 'terminal permit transition differs from operation result')
  }
  if (expectedTerminalKind === 'operation_no_effect_verified') {
    if (transition.to_state_code !== 'spent' || transition.transition_code !== 'no_effect_verified' || transition.reason_code !== 'no_effect_verified') fail('STATE_OPERATION_PERMIT_OUTCOME_MISMATCH', 'a no-effect operation requires the exact no-effect permit transition')
  } else if (transition.to_state_code !== 'recovery_required' || transition.transition_code !== 'state_ambiguous' || transition.reason_code !== 'state_ambiguous') {
    fail('STATE_OPERATION_PERMIT_OUTCOME_MISMATCH', 'a recovery-required operation requires the exact ambiguous-state permit transition')
  }
}

function authorityForCommit(projection, commit, bootstrapIdentityBindings, priorCommits = []) {
  if (projection.generationPairs.length === 0) {
    if (commit.sequence !== 1 || commit.events.length !== 1 || commit.events[0].event_kind_code !== 'generation_pair_activated' || commit.events[0].pair_generation !== 1) {
      fail('STATE_GENESIS_ACTIVATION_REQUIRED', 'the first protected commit must activate generation pair 1 only')
    }
    const event = commit.events[0]
    const persistedFacts = validateBindingFacts(event.trusted_role_bindings, 'genesis trusted_role_bindings')
    if (canonicalizeStateRecord(persistedFacts) !== canonicalizeStateRecord(bootstrapIdentityBindings.facts) || canonicalizeStateRecord(event.identity_bindings_record) !== canonicalizeStateRecord(bootstrapIdentityBindings.record)) {
      fail('STATE_BOOTSTRAP_BINDING_MISMATCH', 'genesis identity bindings do not match the explicit bootstrap trust anchor')
    }
    return { context: generationContext(event), bindingFacts: bootstrapIdentityBindings.facts, persistenceBindingAt: commit.written_at, recoveryBindingAt: undefined }
  }
  if (commit.transaction_code === 'recovery.publish') {
    if (commit.events.length !== 1 || commit.events[0].event_kind_code !== 'recovery_action_recorded') {
      fail('STATE_RECOVERY_ACTION_INVALID', 'publish recovery commit must contain exactly one recovery action')
    }
    const recovery = commit.events[0]
    let authorityAt
    if (recovery.affected_sequence !== null) {
      const affected = priorCommits[recovery.affected_sequence - 1]
      if (!affected || affected.commit_sha256 !== recovery.affected_commit_sha256 || recovery.affected_sequence !== commit.sequence - 1) {
        fail('STATE_RECOVERY_ACTION_INVALID', 'publish recovery does not identify its immediately preceding recovered commit')
      }
      assertGenerationContext(commit.generation_context, affected.generation_context)
      authorityAt = affected.written_at
    } else {
      const pair = pairForGenerationContext(projection, commit.generation_context, projection.generationPairs.find((candidate) => canonicalizeStateRecord(generationContext(candidate)) === canonicalizeStateRecord(commit.generation_context))?.activated_at)
      authorityAt = pair.activated_at
    }
    const pair = pairForGenerationContext(projection, commit.generation_context, authorityAt)
    return { context: generationContext(pair), bindingFacts: pair.trusted_role_bindings, persistenceBindingAt: authorityAt, recoveryBindingAt: authorityAt }
  }
  const historicalRecovery = historicalRecoveryAuthority(projection, commit.events, commit.transaction_code)
  if (historicalRecovery) {
    assertGenerationContext(commit.generation_context, generationContext(historicalRecovery.pair))
    return {
      context: generationContext(historicalRecovery.pair),
      bindingFacts: historicalRecovery.pair.trusted_role_bindings,
      persistenceBindingAt: historicalRecovery.authorityAt,
      recoveryBindingAt: historicalRecovery.authorityAt,
      historicalBindingAt: historicalRecovery.authorityAt,
    }
  }
  const pair = selectGenerationPairFromProjection(projection, commit.written_at)
  return { context: generationContext(pair), bindingFacts: pair.trusted_role_bindings, persistenceBindingAt: commit.written_at, recoveryBindingAt: undefined }
}

function replayCommits(commits, bootstrapIdentityBindings) {
  const projection = makeEmptyProjection()
  for (const [index, commit] of commits.entries()) {
    const authority = authorityForCommit(projection, commit, bootstrapIdentityBindings, commits.slice(0, index))
    assertGenerationContext(commit.generation_context, authority.context)
    requiredTrustedBinding(authority.bindingFacts, 'trusted_launcher', commit.persisted_by_binding_code, 'commit persistence broker', authority.persistenceBindingAt)
    validateOperationTerminalTransaction(projection, commit.events, commit.transaction_code)
    for (const event of commit.events) {
      const eventPersistenceTime = (() => {
        switch (event.event_kind_code) {
          case 'generation_pair_activated': return event.activated_at
          case 'generation_pair_revoked': return event.revoked_at
          case 'registry_recorded': return event.recorded_at
          case 'registry_record_revoked': return event.revoked_at
          case 'permit_issued': return event.persisted_at
          case 'permit_transition_recorded': return event.record?.persisted_at
          case 'operation_started': return event.started_at
          case 'operation_no_effect_verified':
          case 'operation_recovery_required': return event.recorded_at
          case 'recovery_action_recorded': return event.recovered_at
          default: return undefined
        }
      })()
      if (eventPersistenceTime !== commit.written_at) fail('STATE_EVENT_COMMIT_CHRONOLOGY_INVALID', 'event persistence time must equal its atomic commit time')
      applyEvent(projection, event, authority.bindingFacts, {
        recoveryBindingAt: authority.recoveryBindingAt,
        historicalBindingAt: authority.historicalBindingAt,
      })
    }
  }
  return projection
}

function validateCommit(commit, expectedSequence, expectedPrevious, fileDigest) {
  assertExactKeys(commit, ['format', 'format_version', 'sequence', 'previous_commit_sha256', 'transaction_code', 'written_at', 'generation_context', 'persisted_by_binding_code', 'events', 'commit_sha256'], 'protected-state commit')
  if (commit.format !== STATE_FORMAT || commit.format_version !== STATE_VERSION) fail('STATE_COMMIT_VERSION_INVALID', 'protected-state commit format is unsupported')
  if (commit.sequence !== expectedSequence || commit.previous_commit_sha256 !== expectedPrevious) fail('STATE_COMMIT_CHAIN_INVALID', 'commit sequence or predecessor is invalid')
  assertCode(commit.transaction_code, 'commit transaction_code')
  assertTimestamp(commit.written_at, 'commit written_at')
  assertCode(commit.persisted_by_binding_code, 'commit persistence binding')
  if (!Array.isArray(commit.events) || commit.events.length < 1 || commit.events.length > 8) fail('STATE_COMMIT_EVENTS_INVALID', 'commit must contain one to eight events')
  assertHash(commit.commit_sha256, 'commit digest')
  const computed = stateRecordDigest(commit)
  if (computed !== commit.commit_sha256 || computed !== fileDigest) fail('STATE_COMMIT_DIGEST_MISMATCH', 'commit digest or filename does not match content')
}

class ProtectedStateStore {
  constructor({ rootPath, expectedUid, trustedIdentityBindingsRecord, faultInjector }) {
    this.rootPath = path.resolve(rootPath)
    this.expectedUid = expectedUid
    // This anchor authenticates genesis only. Operational role attribution is
    // always resolved from the generation-scoped facts persisted in the ledger.
    this.bootstrapIdentityBindings = validateIdentityBindingsRecord(trustedIdentityBindingsRecord, 'trustedIdentityBindingsRecord bootstrap anchor')
    this.faultInjector = faultInjector ?? (() => {})
    this.ownedLease = null
    this.ownedAppendLock = false
    this._refresh()
  }

  _fault(stage, context = {}) {
    this.faultInjector(stage, Object.freeze({ ...context }))
  }

  _refresh() {
    assertDirectoryNoSymlink(this.rootPath, 'protected state root', this.expectedUid)
    const commitDirectory = path.join(this.rootPath, COMMIT_DIRECTORY)
    const pendingDirectory = path.join(this.rootPath, PENDING_DIRECTORY)
    assertDirectoryNoSymlink(commitDirectory, 'commit directory', this.expectedUid)
    assertDirectoryNoSymlink(pendingDirectory, 'pending directory', this.expectedUid)
    const head = readCanonicalFile(path.join(this.rootPath, HEAD_FILE), 'protected state HEAD', this.expectedUid)
    assertExactKeys(head, ['format', 'format_version', 'sequence', 'commit_sha256'], 'protected state HEAD')
    if (head.format !== STATE_FORMAT || head.format_version !== STATE_VERSION || !Number.isSafeInteger(head.sequence) || head.sequence < 0 || (head.sequence === 0 ? head.commit_sha256 !== null : !HASH_PATTERN.test(head.commit_sha256))) fail('STATE_HEAD_INVALID', 'protected state HEAD is invalid')
    const names = fs.readdirSync(commitDirectory).sort()
    const commits = []
    let expectedPrevious = null
    for (const [index, name] of names.entries()) {
      const match = COMMIT_NAME_PATTERN.exec(name)
      if (!match) fail('STATE_COMMIT_NAME_INVALID', `unexpected commit file ${name}`)
      const sequence = Number(match[1])
      const expectedSequence = index + 1
      if (sequence !== expectedSequence) fail('STATE_COMMIT_GAP_OR_FORK', 'commit files do not form one ordered prefix')
      const commit = readCanonicalFile(path.join(commitDirectory, name), `commit ${name}`, this.expectedUid)
      validateCommit(commit, expectedSequence, expectedPrevious, match[2])
      if (commits.length && assertTimestamp(commit.written_at, 'commit written_at') <= assertTimestamp(commits.at(-1).written_at, 'prior commit written_at')) fail('STATE_COMMIT_CHRONOLOGY_INVALID', 'commit persistence time must strictly increase')
      commits.push(commit)
      expectedPrevious = commit.commit_sha256
    }
    if (head.sequence > commits.length) fail('STATE_HEAD_DANGLING', 'HEAD references a missing commit')
    if (head.sequence > 0 && commits[head.sequence - 1].commit_sha256 !== head.commit_sha256) fail('STATE_HEAD_MISMATCH', 'HEAD digest does not match its commit')
    if (head.sequence === 0 && head.commit_sha256 !== null) fail('STATE_HEAD_INVALID', 'genesis HEAD must have null digest')
    this.head = head
    this.allCommits = commits
    replayCommits(commits, this.bootstrapIdentityBindings)
    this.commits = commits.slice(0, head.sequence)
    this.projection = replayCommits(this.commits, this.bootstrapIdentityBindings)
    this.pendingNames = fs.readdirSync(pendingDirectory).sort()
    const recoveryIntentPath = path.join(this.rootPath, RECOVERY_INTENT_FILE)
    this.recoveryIntent = fs.existsSync(recoveryIntentPath)
      ? validateRecoveryIntent(readCanonicalFile(recoveryIntentPath, 'publish recovery intent', this.expectedUid))
      : null
    const lockPath = path.join(this.rootPath, LOCK_DIRECTORY)
    this.lock = null
    this.lockAnomaly = null
    if (fs.existsSync(lockPath)) {
      assertDirectoryNoSymlink(lockPath, 'operation lock', this.expectedUid)
      const contents = fs.readdirSync(lockPath)
      if (contents.length === 0) {
        this.lockAnomaly = 'incomplete_operation_lock'
      } else if (contents.length === 1 && contents[0] === 'lease.json') {
        try {
          this.lock = readCanonicalFile(path.join(lockPath, 'lease.json'), 'operation lock lease', this.expectedUid)
          assertExactKeys(this.lock, ['format', 'format_version', 'operation_id', 'operation_nonce', 'lease_token_sha256', 'owner_pid', 'acquired_at'], 'operation lock lease')
          if (this.lock.format !== STATE_FORMAT || this.lock.format_version !== STATE_VERSION || !Number.isSafeInteger(this.lock.owner_pid) || this.lock.owner_pid <= 0) fail('STATE_LOCK_CORRUPT', 'operation lock lease is invalid')
          assertCode(this.lock.operation_id, 'lock operation_id')
          assertHash(this.lock.operation_nonce, 'lock operation_nonce')
          assertHash(this.lock.lease_token_sha256, 'lock lease token')
          assertTimestamp(this.lock.acquired_at, 'lock acquired_at')
        } catch (error) {
          if (error instanceof StateStoreError && ['STATE_FILE_INVALID_UTF8', 'STATE_FILE_INVALID_JSON', 'STATE_FILE_NOT_CANONICAL'].includes(error.code)) {
            this.lock = null
            this.lockAnomaly = 'incomplete_operation_lock'
          } else {
            throw error
          }
        }
      } else {
        fail('STATE_LOCK_CORRUPT', 'operation lock has unexpected contents')
      }
    }
    const appendLockPath = path.join(this.rootPath, APPEND_LOCK_DIRECTORY)
    this.appendLock = null
    this.appendLockAnomaly = null
    if (fs.existsSync(appendLockPath)) {
      assertDirectoryNoSymlink(appendLockPath, 'append mutex directory', this.expectedUid)
      const appendContents = fs.readdirSync(appendLockPath)
      if (appendContents.length === 0) {
        this.appendLockAnomaly = 'incomplete_append_lock'
      } else if (appendContents.length === 1 && appendContents[0] === 'lease.json') {
        try {
          this.appendLock = validateAppendLockLease(readCanonicalFile(path.join(appendLockPath, 'lease.json'), 'append mutex lease', this.expectedUid))
        } catch (error) {
          if (error instanceof StateStoreError && ['STATE_FILE_INVALID_UTF8', 'STATE_FILE_INVALID_JSON', 'STATE_FILE_NOT_CANONICAL'].includes(error.code)) this.appendLockAnomaly = 'incomplete_append_lock'
          else throw error
        }
      } else {
        fail('STATE_APPEND_LOCK_CORRUPT', 'append mutex has unexpected contents')
      }
    }
    this.recoveryReasons = []
    if (this.pendingNames.length) this.recoveryReasons.push('pending_publish')
    if (this.recoveryIntent) this.recoveryReasons.push('recovery_audit_pending')
    if (this.appendLock && !this.ownedAppendLock) this.recoveryReasons.push('append_lock_present')
    if (this.appendLockAnomaly) this.recoveryReasons.push(this.appendLockAnomaly)
    if (this.allCommits.length > this.head.sequence) this.recoveryReasons.push('unanchored_commit')
    if (this.lockAnomaly) this.recoveryReasons.push(this.lockAnomaly)
    if (this.lock) {
      const operation = this.projection.operationsByNonce.get(this.lock.operation_nonce)
      if (!operation) this.recoveryReasons.push('lock_without_operation')
      else if (operation.state_code === 'in_progress' && this.ownedLease?.lease_token_sha256 !== this.lock.lease_token_sha256) this.recoveryReasons.push('unfinished_operation')
      else if (operation.state_code !== 'in_progress') this.recoveryReasons.push('terminal_operation_lock')
    }
    for (const operation of this.projection.operationsByNonce.values()) {
      if (operation.state_code === 'in_progress' && (!this.lock || this.lock.operation_nonce !== operation.operation_nonce)) this.recoveryReasons.push('operation_without_lock')
      if (operation.state_code === 'recovery_required') this.recoveryReasons.push('operation_recovery_hold')
    }
    this.recoveryReasons = [...new Set(this.recoveryReasons)].sort()
  }

  inspect() {
    this._refresh()
    return Object.freeze({
      sequence: this.head.sequence,
      headCommitSha256: this.head.commit_sha256,
      recoveryRequired: this.recoveryReasons.length > 0,
      recoveryReasons: Object.freeze([...this.recoveryReasons]),
      activeOperation: this.lock ? Object.freeze({ operationId: this.lock.operation_id, operationNonce: this.lock.operation_nonce }) : null,
    })
  }

  _assertWritable({ allowOwnedOperation = false } = {}) {
    this._refresh()
    const reasons = this.recoveryReasons.filter((reason) => allowOwnedOperation && reason === 'unfinished_operation' && this.ownedLease?.lease_token_sha256 === this.lock?.lease_token_sha256 ? false : true)
    if (reasons.length) fail('STATE_RECOVERY_REQUIRED', 'protected state is not safe for ordinary mutation', reasons)
  }

  _bindingFactsAt(at) {
    return selectGenerationPairFromProjection(this.projection, at).trusted_role_bindings
  }

  _authorityForAppend(events, writtenAt, transactionCode) {
    if (this.projection.generationPairs.length === 0) {
      if (events.length !== 1 || events[0].event_kind_code !== 'generation_pair_activated' || events[0].pair_generation !== 1) {
        fail('STATE_GENESIS_ACTIVATION_REQUIRED', 'the first protected commit must activate generation pair 1 only')
      }
      const facts = validateBindingFacts(events[0].trusted_role_bindings, 'genesis trusted_role_bindings')
      if (canonicalizeStateRecord(facts) !== canonicalizeStateRecord(this.bootstrapIdentityBindings.facts) || canonicalizeStateRecord(events[0].identity_bindings_record) !== canonicalizeStateRecord(this.bootstrapIdentityBindings.record)) {
        fail('STATE_BOOTSTRAP_BINDING_MISMATCH', 'genesis identity bindings do not match the explicit bootstrap trust anchor')
      }
      return { context: generationContext(events[0]), bindingFacts: facts }
    }
    const historicalRecovery = historicalRecoveryAuthority(this.projection, events, transactionCode)
    if (historicalRecovery) {
      return {
        context: generationContext(historicalRecovery.pair),
        bindingFacts: historicalRecovery.pair.trusted_role_bindings,
        bindingValidationAt: historicalRecovery.authorityAt,
        historicalBindingAt: historicalRecovery.authorityAt,
      }
    }
    const pair = selectGenerationPairFromProjection(this.projection, writtenAt)
    return { context: generationContext(pair), bindingFacts: pair.trusted_role_bindings, bindingValidationAt: writtenAt }
  }

  _acquireAppendLock({ transactionCode, acquiredAt, intendedCommitSha256 }) {
    const lockPath = path.join(this.rootPath, APPEND_LOCK_DIRECTORY)
    try {
      fs.mkdirSync(lockPath, { mode: 0o700 })
    } catch (error) {
      if (error.code === 'EEXIST') fail('STATE_APPEND_LOCKED', 'another protected-state writer holds the append mutex')
      fail('STATE_APPEND_LOCK_FAILED', `could not create append mutex: ${error.code ?? error.message}`)
    }
    try {
      this._fault('after_append_lock_directory', { transactionCode })
      const ownerStartTicks = processStartTicks(process.pid)
      if (ownerStartTicks === null) fail('STATE_PLATFORM_UNSUPPORTED', 'Linux process start identity is required for the append mutex')
      const unsignedLease = {
        format: STATE_FORMAT,
        format_version: STATE_VERSION,
        transaction_code: transactionCode,
        owner_pid: process.pid,
        owner_start_ticks: ownerStartTicks,
        acquired_at: acquiredAt,
        base_sequence: this.head.sequence,
        base_commit_sha256: this.head.commit_sha256,
        intended_sequence: this.head.sequence + 1,
        intended_commit_sha256: intendedCommitSha256,
      }
      const lease = { ...unsignedLease, lease_sha256: appendLockDigest(unsignedLease) }
      const leaseBytes = canonicalBytes(lease)
      const leasePath = path.join(lockPath, 'lease.json')
      const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0)
      const descriptor = fs.openSync(leasePath, flags, 0o400)
      try {
        const split = Math.ceil(leaseBytes.length / 2)
        fs.writeSync(descriptor, leaseBytes, 0, split)
        this._fault('after_append_lock_partial_write', { transactionCode })
        fs.writeSync(descriptor, leaseBytes, split, leaseBytes.length - split)
        fs.fsyncSync(descriptor)
        fs.fchmodSync(descriptor, 0o400)
      } finally {
        fs.closeSync(descriptor)
      }
      fsyncDirectory(lockPath)
      fsyncDirectory(this.rootPath)
      this.ownedAppendLock = true
      this._fault('after_append_lock_fsync', { transactionCode })
    } catch (error) {
      if (!this.ownedAppendLock) fs.rmSync(lockPath, { recursive: true, force: true })
      throw error
    }
  }

  _releaseAppendLock() {
    if (!this.ownedAppendLock) return
    fs.rmSync(path.join(this.rootPath, APPEND_LOCK_DIRECTORY), { recursive: true })
    fsyncDirectory(this.rootPath)
    this.ownedAppendLock = false
  }

  _appendEvents(events, { transactionCode, writtenAt }) {
    assertCode(transactionCode, 'transactionCode')
    const initialAuthority = this._authorityForAppend(events, writtenAt, transactionCode)
    requiredTrustedBinding(
      initialAuthority.bindingFacts,
      'trusted_launcher',
      bindingFact(initialAuthority.bindingFacts, 'trusted_launcher').binding_code,
      'commit persistence broker',
      initialAuthority.bindingValidationAt ?? writtenAt,
    )
    const initialUnsignedCommit = {
      format: STATE_FORMAT,
      format_version: STATE_VERSION,
      sequence: this.head.sequence + 1,
      previous_commit_sha256: this.head.commit_sha256,
      transaction_code: transactionCode,
      written_at: writtenAt,
      generation_context: initialAuthority.context,
      persisted_by_binding_code: bindingFact(initialAuthority.bindingFacts, 'trusted_launcher').binding_code,
      events: clone(events),
    }
    const intendedCommitSha256 = stateRecordDigest(initialUnsignedCommit)
    try {
      this._fault('before_append_lock_acquire', { transactionCode })
      this._acquireAppendLock({ transactionCode, acquiredAt: writtenAt, intendedCommitSha256 })
      this._refresh()
      const allowedRecoveryReasons = (() => {
        if (transactionCode === 'operation.begin') return new Set(['lock_without_operation'])
        if (['operation.no-effect', 'operation.recovery-required', 'recovery.operation-no-effect'].includes(transactionCode)) return new Set(['unfinished_operation'])
        if (transactionCode === 'recovery.lock') return new Set(['incomplete_operation_lock', 'lock_without_operation'])
        if (transactionCode === 'recovery.terminal-lock') return new Set(['operation_recovery_hold', 'terminal_operation_lock'])
        return new Set()
      })()
      const newlyBlockingReasons = this.recoveryReasons.filter((reason) => !allowedRecoveryReasons.has(reason))
      if (newlyBlockingReasons.length) fail('STATE_RECOVERY_REQUIRED', 'protected state became recovery-required before serialized append', newlyBlockingReasons)
      if (
        this.appendLock?.base_sequence !== this.head.sequence
        || this.appendLock?.base_commit_sha256 !== this.head.commit_sha256
        || this.appendLock?.intended_sequence !== this.head.sequence + 1
      ) fail('STATE_APPEND_BASE_CHANGED', 'protected HEAD changed before the append mutex was acquired')
      const writtenMs = assertTimestamp(writtenAt, 'writtenAt')
      const authority = this._authorityForAppend(events, writtenAt, transactionCode)
      requiredTrustedBinding(
        authority.bindingFacts,
        'trusted_launcher',
        bindingFact(authority.bindingFacts, 'trusted_launcher').binding_code,
        'commit persistence broker',
        authority.bindingValidationAt ?? writtenAt,
      )
      const simulated = structuredClone(this.projection)
      validateOperationTerminalTransaction(this.projection, events, transactionCode)
      for (const event of events) applyEvent(simulated, event, authority.bindingFacts, {
        recoveryBindingAt: authority.historicalBindingAt,
        historicalBindingAt: authority.historicalBindingAt,
      })
      if (this.commits.length && writtenMs <= assertTimestamp(this.commits.at(-1).written_at, 'prior commit written_at')) fail('STATE_COMMIT_CHRONOLOGY_INVALID', 'new commit time must be strictly later than current HEAD')
      const sequence = this.head.sequence + 1
      const unsigned = {
        format: STATE_FORMAT,
        format_version: STATE_VERSION,
        sequence,
        previous_commit_sha256: this.head.commit_sha256,
        transaction_code: transactionCode,
        written_at: writtenAt,
        generation_context: authority.context,
        persisted_by_binding_code: bindingFact(authority.bindingFacts, 'trusted_launcher').binding_code,
        events: clone(events),
      }
      const commit = { ...unsigned, commit_sha256: sha256Hex(Buffer.from(canonicalizeStateRecord(unsigned), 'utf8')) }
      if (commit.commit_sha256 !== this.appendLock.intended_commit_sha256) fail('STATE_APPEND_INTENT_CHANGED', 'serialized commit differs from the append-mutex intent commitment')
      const prefix = `${String(sequence).padStart(12, '0')}-${commit.commit_sha256}`
      const pendingPath = path.join(this.rootPath, PENDING_DIRECTORY, `${prefix}.commit.pending`)
      const commitPath = path.join(this.rootPath, COMMIT_DIRECTORY, `${prefix}.json`)
      this._fault('before_pending_write', { sequence })
      writeExclusiveDurable(pendingPath, canonicalBytes(commit))
      this._fault('after_pending_fsync', { sequence })
      try {
        fs.linkSync(pendingPath, commitPath)
      } catch (error) {
        fail('STATE_COMMIT_COLLISION', `could not publish immutable commit: ${error.code ?? error.message}`)
      }
      this._fault('after_commit_link', { sequence })
      fsyncDirectory(path.join(this.rootPath, COMMIT_DIRECTORY))
      this._fault('after_commit_directory_fsync', { sequence })
      replaceHeadDurably(this.rootPath, {
        format: STATE_FORMAT,
        format_version: STATE_VERSION,
        sequence,
        commit_sha256: commit.commit_sha256,
      })
      this._fault('after_head_replace', { sequence })
      if (fs.existsSync(pendingPath)) fs.unlinkSync(pendingPath)
      fsyncDirectory(path.join(this.rootPath, PENDING_DIRECTORY))
      this._fault('after_pending_cleanup', { sequence })
      this._refresh()
      return Object.freeze({ sequence, commitSha256: commit.commit_sha256 })
    } finally {
      this._releaseAppendLock()
      this._refresh()
    }
  }

  activateGenerationPair(input) {
    this._assertWritable()
    const currentFacts = this.projection.generationPairs.length === 0
      ? this.bootstrapIdentityBindings.facts
      : this._bindingFactsAt(input.activatedAt)
    const sealedBindings = validateIdentityBindingsRecord(input.identityBindingsRecord, 'identityBindingsRecord activation')
    const nextFacts = sealedBindings.facts
    const event = {
      event_kind_code: 'generation_pair_activated',
      pair_code: input.pairCode,
      pair_generation: input.pairGeneration,
      runtime_profile: {
        generation_number: input.runtimeProfile.generationNumber,
        generation_code: input.runtimeProfile.generationCode,
        record_digest_sha256: input.runtimeProfile.recordDigestSha256,
        valid_from: input.runtimeProfile.validFrom,
        expires_at: input.runtimeProfile.expiresAt,
      },
      identity_bindings: {
        generation_number: input.identityBindings.generationNumber,
        generation_code: input.identityBindings.generationCode,
        record_digest_sha256: input.identityBindings.recordDigestSha256,
        bound_runtime_profile_record_digest_sha256: input.identityBindings.boundRuntimeProfileRecordDigestSha256,
        valid_from: input.identityBindings.validFrom,
        expires_at: input.identityBindings.expiresAt,
      },
      identity_bindings_record: sealedBindings.record,
      trusted_role_bindings: clone(nextFacts),
      activated_at: input.activatedAt,
      activated_by_binding_code: input.authenticatedLauncherBindingCode,
    }
    if (input.identityBindings.boundRuntimeProfileRecordDigestSha256 !== input.runtimeProfile.recordDigestSha256) fail('STATE_GENERATION_PAIR_MISMATCH', 'identity bindings do not pin the paired runtime profile')
    requiredTrustedBinding(currentFacts, 'trusted_launcher', input.authenticatedLauncherBindingCode, 'generation activator', input.activatedAt)
    return this._appendEvents([event], { transactionCode: 'generation-pair.activation', writtenAt: input.activatedAt })
  }

  revokeGenerationPair(input) {
    this._assertWritable()
    if (this.projection.generationPairRevocations.has(input.pairCode)) fail('STATE_GENERATION_ALREADY_REVOKED', 'generation pair already has a revocation')
    const event = {
      event_kind_code: 'generation_pair_revoked',
      pair_code: input.pairCode,
      pair_generation: input.pairGeneration,
      runtime_profile_record_digest_sha256: input.runtimeProfileRecordDigestSha256,
      identity_bindings_record_digest_sha256: input.identityBindingsRecordDigestSha256,
      revoked_at: input.revokedAt,
      reason_code: input.reasonCode,
      revoked_by_binding_code: input.authenticatedLauncherBindingCode,
    }
    return this._appendEvents([event], { transactionCode: 'generation-pair.revocation', writtenAt: input.revokedAt })
  }

  projectGenerationPairRevocation({ pairCode }) {
    this._refresh()
    assertCode(pairCode, 'pairCode')
    const revocation = this.projection.generationPairRevocations.get(pairCode)
    if (!revocation) fail('STATE_GENERATION_REVOCATION_UNKNOWN', 'generation pair has no revocation')
    return deepFreeze(clone(revocation))
  }

  selectActiveGenerationPair({ asOf, runtimeProfileRecordDigestSha256, identityBindingsRecordDigestSha256 }) {
    this._refresh()
    if (this.recoveryReasons.length) fail('STATE_RECOVERY_REQUIRED', 'active generation cannot be selected during recovery-required state', this.recoveryReasons)
    const candidate = selectGenerationPairFromProjection(this.projection, asOf, { runtimeProfileRecordDigestSha256, identityBindingsRecordDigestSha256 })
    return deepFreeze(clone(candidate))
  }

  selectGenerationPairForActiveOperation({ asOf, operationId, operationNonce, runtimeProfileRecordDigestSha256, identityBindingsRecordDigestSha256 }) {
    this._refresh()
    assertCode(operationId, 'operationId')
    assertHash(operationNonce, 'operationNonce')
    const ownedExactOperation = this.recoveryReasons.length === 0
      && this.ownedLease?.operation_id === operationId
      && this.ownedLease?.operation_nonce === operationNonce
      && this.ownedLease?.lease_token_sha256 === this.lock?.lease_token_sha256
    if (!ownedExactOperation && canonicalizeStateRecord(this.recoveryReasons) !== canonicalizeStateRecord(['unfinished_operation'])) {
      fail('STATE_RECOVERY_REQUIRED', 'only the exact currently owned unfinished operation may revalidate its generation', this.recoveryReasons)
    }
    const operation = this.projection.operationsByNonce.get(operationNonce)
    if (
      !operation
      || operation.operation_id !== operationId
      || operation.state_code !== 'in_progress'
      || this.lock?.operation_id !== operationId
      || this.lock?.operation_nonce !== operationNonce
      || operation.runtime_profile_record_digest_sha256 !== runtimeProfileRecordDigestSha256
      || operation.identity_bindings_record_digest_sha256 !== identityBindingsRecordDigestSha256
    ) fail('STATE_OPERATION_NOT_ACTIVE', 'generation revalidation does not identify the exact active operation')
    return deepFreeze(clone(selectGenerationPairFromProjection(this.projection, asOf, {
      runtimeProfileRecordDigestSha256,
      identityBindingsRecordDigestSha256,
    })))
  }

  selectActiveGeneration({ generationKindCode, asOf, expectedRecordDigestSha256 = undefined }) {
    if (!['runtime_profile', 'identity_bindings'].includes(generationKindCode)) fail('STATE_GENERATION_KIND_INVALID', 'unsupported generation kind')
    const pair = this.selectActiveGenerationPair({
      asOf,
      runtimeProfileRecordDigestSha256: generationKindCode === 'runtime_profile' ? expectedRecordDigestSha256 : undefined,
      identityBindingsRecordDigestSha256: generationKindCode === 'identity_bindings' ? expectedRecordDigestSha256 : undefined,
    })
    return deepFreeze(clone(pair[generationKindCode]))
  }

  registerFixedRecord({ record, recordedAt, authenticatedRuntimeRoleCode, authenticatedBindingCode }) {
    this._assertWritable()
    const event = {
      event_kind_code: 'registry_recorded',
      registry_kind_code: record.record_kind_code,
      record_code: record.record_code,
      record_digest_sha256: record.record_digest_sha256,
      recorded_at: recordedAt,
      recorded_by_runtime_role_code: authenticatedRuntimeRoleCode,
      recorded_by_binding_code: authenticatedBindingCode,
      record: clone(record),
    }
    return this._appendEvents([event], { transactionCode: `registry.${record.record_kind_code}`, writtenAt: recordedAt })
  }

  revokeFixedRecord({ registryKindCode, recordCode, recordDigestSha256, revokedAt, reasonCode, authenticatedRuntimeRoleCode, authenticatedBindingCode }) {
    this._assertWritable()
    const event = {
      event_kind_code: 'registry_record_revoked',
      registry_kind_code: registryKindCode,
      record_code: recordCode,
      record_digest_sha256: recordDigestSha256,
      revoked_at: revokedAt,
      reason_code: reasonCode,
      revoked_by_runtime_role_code: authenticatedRuntimeRoleCode,
      revoked_by_binding_code: authenticatedBindingCode,
    }
    return this._appendEvents([event], { transactionCode: 'registry.revocation', writtenAt: revokedAt })
  }

  projectFixedRecordRevocation({ registryKindCode, recordCode }) {
    this._refresh()
    if (!REGISTRY_KINDS.has(registryKindCode)) fail('STATE_REGISTRY_KIND_INVALID', 'unsupported registry kind')
    assertCode(recordCode, 'recordCode')
    const revocation = this.projection.registryRevocations.get(registryKey(registryKindCode, recordCode))
    if (!revocation) fail('STATE_REGISTRY_REVOCATION_UNKNOWN', 'registry record has no revocation')
    return deepFreeze(clone(revocation))
  }

  resolveFixedRecord({ registryKindCode, recordCode, recordDigestSha256, asOf }) {
    this._refresh()
    if (this.recoveryReasons.length) fail('STATE_RECOVERY_REQUIRED', 'registry cannot be resolved during recovery-required state', this.recoveryReasons)
    const key = registryKey(registryKindCode, recordCode)
    const entry = this.projection.registryRecords.get(key)
    if (!entry || entry.record_digest_sha256 !== recordDigestSha256) fail('STATE_REGISTRY_RECORD_MISSING', 'exact registry record is absent')
    const asOfMs = assertTimestamp(asOf, 'asOf')
    if (asOfMs < assertTimestamp(entry.recorded_at, 'registry recorded_at')) fail('STATE_REGISTRY_NOT_YET_KNOWN', 'registry record was not yet known')
    const revocation = this.projection.registryRevocations.get(key)
    if (revocation && assertTimestamp(revocation.revoked_at, 'registry revoked_at') <= asOfMs) fail('STATE_REGISTRY_RECORD_REVOKED', 'registry record was revoked')
    if (asOfMs >= assertTimestamp(entry.record.expires_at, 'registry record expires_at')) fail('STATE_REGISTRY_RECORD_EXPIRED', 'registry record has expired')
    selectGenerationPairFromProjection(this.projection, asOf, {
      runtimeProfileRecordDigestSha256: entry.record.runtime_profile_record_digest_sha256,
      identityBindingsRecordDigestSha256: entry.record.identity_bindings_record_digest_sha256,
    })
    return deepFreeze(clone(entry.record))
  }

  resolveBootstrapBundleSealForPermit({ permit, asOf }) {
    this._refresh()
    if (this.recoveryReasons.length) fail('STATE_RECOVERY_REQUIRED', 'bootstrap seal cannot be resolved during recovery-required state', this.recoveryReasons)
    assertPlainObject(permit, 'bootstrap permit')
    if (permit.record_kind_code !== 'permit_issuance' || permit.permit_kind_code !== 'bootstrap') {
      fail('STATE_PERMIT_KIND_INVALID', 'bootstrap seal resolution requires a bootstrap permit issuance')
    }
    const asOfMs = assertTimestamp(asOf, 'asOf')
    const permitEntry = this.projection.permits.get(permit.permit_code)
    if (permitEntry && permitEntry.record.record_digest_sha256 !== permit.record_digest_sha256) fail('STATE_PERMIT_SUBSTITUTION', 'bootstrap seal resolution received a different record for a persisted permit code')
    if (!permitEntry) {
      const issuedAtMs = assertTimestamp(permit.issued_at, 'permit issued_at')
      const candidates = [...this.projection.registryRecords.entries()].filter(([key, candidate]) => {
        if (!key.startsWith('bundle_seal\0')) return false
        const revocation = this.projection.registryRevocations.get(key)
        return bootstrapSealMatchesPermit(candidate.record, permit)
          && assertTimestamp(candidate.recorded_at, 'bootstrap seal recorded_at') <= asOfMs
          && assertTimestamp(candidate.record.sealed_at, 'bootstrap seal sealed_at') <= issuedAtMs
          && (!revocation || assertTimestamp(revocation.revoked_at, 'bootstrap seal revoked_at') > asOfMs)
          && asOfMs < assertTimestamp(candidate.record.expires_at, 'bootstrap seal expires_at')
      })
      if (candidates.length !== 1) fail('STATE_BOOTSTRAP_SEAL_MISMATCH', 'unpersisted permit requires exactly one current matching bootstrap bundle seal')
      return deepFreeze(clone(candidates[0][1].record))
    }
    const matched = this.projection.registryRecords.get(permitEntry.matched_seal_registry_key)
    const revocation = this.projection.registryRevocations.get(permitEntry.matched_seal_registry_key)
    if (
      !matched
      || matched.record_digest_sha256 !== permitEntry.matched_seal_record_digest_sha256
      || !bootstrapSealMatchesPermit(matched.record, permit)
      || assertTimestamp(matched.recorded_at, 'bootstrap seal recorded_at') > asOfMs
      || (revocation && assertTimestamp(revocation.revoked_at, 'bootstrap seal revoked_at') <= asOfMs)
      || asOfMs >= assertTimestamp(matched.record.expires_at, 'bootstrap seal expires_at')
    ) fail('STATE_BOOTSTRAP_SEAL_MISMATCH', 'the exact issuance-matched bootstrap bundle seal is unavailable')
    const seal = matched.record
    selectGenerationPairFromProjection(this.projection, asOf, {
      runtimeProfileRecordDigestSha256: seal.runtime_profile_record_digest_sha256,
      identityBindingsRecordDigestSha256: seal.identity_bindings_record_digest_sha256,
    })
    return deepFreeze(clone(seal))
  }

  issuePermit({ record, persistedAt, authenticatedIssuerRuntimeRoleCode, authenticatedIssuerBindingCode, authenticatedPersistenceBindingCode }) {
    this._assertWritable()
    const event = {
      event_kind_code: 'permit_issued',
      record_code: record.record_code,
      record_digest_sha256: record.record_digest_sha256,
      issued_by_runtime_role_code: authenticatedIssuerRuntimeRoleCode,
      issued_by_binding_code: authenticatedIssuerBindingCode,
      persisted_by_binding_code: authenticatedPersistenceBindingCode,
      persisted_at: persistedAt,
      record: clone(record),
    }
    return this._appendEvents([event], { transactionCode: 'permit.issuance', writtenAt: persistedAt })
  }

  appendPermitTransition({ record, authenticatedSemanticRuntimeRoleCode, authenticatedSemanticBindingCode, authenticatedPersistenceBindingCode }) {
    this._assertWritable()
    if (record.transition_code === 'operation_claimed') fail('STATE_CLAIM_NOT_ATOMIC', 'use claimPermitAndBeginOperation for claim transitions')
    if (record.transition_code !== 'authority_withdrawal') fail('STATE_TERMINAL_NOT_ATOMIC', 'operational terminal transitions must be registered with their operation result')
    if (record.recorded_by_runtime_role_code !== authenticatedSemanticRuntimeRoleCode || record.recorded_by_binding_code !== authenticatedSemanticBindingCode || record.persisted_by_binding_code !== authenticatedPersistenceBindingCode) fail('STATE_AUTHENTICATED_BINDING_MISMATCH', 'authenticated transition actors differ from record')
    return this._appendEvents([{ event_kind_code: 'permit_transition_recorded', record: clone(record) }], { transactionCode: 'permit.transition', writtenAt: record.persisted_at })
  }

  projectPermit({ permitCode, asOf }) {
    this._refresh()
    const entry = this.projection.permits.get(permitCode)
    if (!entry) fail('STATE_PERMIT_UNKNOWN', 'permit is unknown')
    const asOfMs = assertTimestamp(asOf, 'asOf')
    if (asOfMs < assertTimestamp(entry.event.persisted_at, 'permit persisted_at')) return Object.freeze({ permitCode, stateCode: null, transitionCount: 0, currentTransition: null })
    const boundedTransitions = entry.transitions.filter((transition) => assertTimestamp(transition.persisted_at, 'transition persisted_at') <= asOfMs)
    return deepFreeze({ permitCode, stateCode: permitStateAt(entry, asOf), transitionCount: boundedTransitions.length, currentTransition: boundedTransitions.length ? clone(boundedTransitions.at(-1)) : null })
  }

  resolvePermit({ permitCode, recordDigestSha256, asOf, requiredStateCode = undefined }) {
    this._refresh()
    if (this.recoveryReasons.length) fail('STATE_RECOVERY_REQUIRED', 'permit cannot be resolved during recovery-required state', this.recoveryReasons)
    assertCode(permitCode, 'permitCode')
    assertHash(recordDigestSha256, 'permit record digest')
    const entry = this.projection.permits.get(permitCode)
    if (!entry) fail('STATE_PERMIT_UNKNOWN', 'permit is unknown')
    if (entry.record.record_digest_sha256 !== recordDigestSha256) fail('STATE_PERMIT_SUBSTITUTION', 'permit digest does not match its immutable issuance')
    const asOfMs = assertTimestamp(asOf, 'asOf')
    if (asOfMs < assertTimestamp(entry.event.persisted_at, 'permit persisted_at')) fail('STATE_PERMIT_NOT_YET_KNOWN', 'permit had not been persisted as of the requested time')
    selectGenerationPairFromProjection(this.projection, asOf, {
      runtimeProfileRecordDigestSha256: entry.record.runtime_profile_record_digest_sha256,
      identityBindingsRecordDigestSha256: entry.record.identity_bindings_record_digest_sha256,
    })
    const stateCode = permitStateAt(entry, asOf)
    if (requiredStateCode !== undefined && stateCode !== requiredStateCode) fail('STATE_PERMIT_STATE_MISMATCH', `permit is ${stateCode}, not ${requiredStateCode}`)
    const boundedTransition = entry.transitions.filter((transition) => assertTimestamp(transition.persisted_at, 'transition persisted_at') <= asOfMs).at(-1)
    return deepFreeze({
      record: clone(entry.record),
      stateCode,
      currentTransition: boundedTransition ? clone(boundedTransition) : null,
    })
  }

  resolvePermitForActiveOperation({
    asOf,
    operationId,
    operationNonce,
    permitCode,
    permitRecordDigestSha256,
    permitClaimRecordDigestSha256,
    runtimeProfileRecordDigestSha256,
    identityBindingsRecordDigestSha256,
  }) {
    this._refresh()
    assertCode(operationId, 'operationId')
    assertHash(operationNonce, 'operationNonce')
    assertCode(permitCode, 'permitCode')
    assertHash(permitRecordDigestSha256, 'permit record digest')
    assertHash(permitClaimRecordDigestSha256, 'permit claim record digest')
    const ownedExactOperation = this.recoveryReasons.length === 0
      && this.ownedLease?.operation_id === operationId
      && this.ownedLease?.operation_nonce === operationNonce
      && this.ownedLease?.lease_token_sha256 === this.lock?.lease_token_sha256
    if (!ownedExactOperation && canonicalizeStateRecord(this.recoveryReasons) !== canonicalizeStateRecord(['unfinished_operation'])) {
      fail('STATE_RECOVERY_REQUIRED', 'only the exact currently owned unfinished operation may revalidate permit authority', this.recoveryReasons)
    }
    const operation = this.projection.operationsByNonce.get(operationNonce)
    const entry = this.projection.permits.get(permitCode)
    const currentClaim = entry?.transitions.at(-1)
    if (
      !operation
      || !entry
      || operation.operation_id !== operationId
      || operation.state_code !== 'in_progress'
      || operation.permit_code !== permitCode
      || operation.permit_claim_record_digest_sha256 !== permitClaimRecordDigestSha256
      || entry.record.record_digest_sha256 !== permitRecordDigestSha256
      || currentClaim?.record_digest_sha256 !== permitClaimRecordDigestSha256
      || currentClaim?.transition_code !== 'operation_claimed'
      || currentClaim?.operation_id !== operationId
      || currentClaim?.operation_nonce !== operationNonce
      || this.lock?.operation_id !== operationId
      || this.lock?.operation_nonce !== operationNonce
      || operation.runtime_profile_record_digest_sha256 !== runtimeProfileRecordDigestSha256
      || operation.identity_bindings_record_digest_sha256 !== identityBindingsRecordDigestSha256
    ) fail('STATE_OPERATION_NOT_ACTIVE', 'permit revalidation does not identify the exact active claimed operation')
    const asOfMs = assertTimestamp(asOf, 'asOf')
    if (asOfMs < assertTimestamp(entry.event.persisted_at, 'permit persisted_at')) fail('STATE_PERMIT_NOT_YET_KNOWN', 'permit had not been persisted as of the requested time')
    const stateCode = permitStateAt(entry, asOf)
    if (stateCode !== 'in_progress') fail('STATE_PERMIT_STATE_MISMATCH', `permit is ${stateCode}, not in_progress`)
    const pair = selectGenerationPairFromProjection(this.projection, asOf, {
      runtimeProfileRecordDigestSha256,
      identityBindingsRecordDigestSha256,
    })
    const matchedSeal = this.projection.registryRecords.get(entry.matched_seal_registry_key)
    const revocation = this.projection.registryRevocations.get(entry.matched_seal_registry_key)
    if (
      !matchedSeal
      || matchedSeal.record_digest_sha256 !== entry.matched_seal_record_digest_sha256
      || !bootstrapSealMatchesPermit(matchedSeal.record, entry.record)
      || matchedSeal.record.operation_id !== operationId
      || assertTimestamp(matchedSeal.recorded_at, 'bootstrap seal recorded_at') > asOfMs
      || assertTimestamp(matchedSeal.record.sealed_at, 'bootstrap seal sealed_at') > asOfMs
      || asOfMs >= assertTimestamp(matchedSeal.record.expires_at, 'bootstrap seal expires_at')
      || (revocation && assertTimestamp(revocation.revoked_at, 'bootstrap seal revoked_at') <= asOfMs)
    ) fail('STATE_BOOTSTRAP_SEAL_MISMATCH', 'active bootstrap operation requires its exact issuance-matched seal to remain current and nonrevoked')
    return deepFreeze({
      currentClaim: clone(currentClaim),
      generationPair: clone(pair),
      permit: clone(entry.record),
      seal: clone(matchedSeal.record),
      stateCode,
    })
  }

  projectOperation({ operationId, operationNonce }) {
    this._refresh()
    assertCode(operationId, 'operationId')
    assertHash(operationNonce, 'operationNonce')
    const operation = this.projection.operationsByNonce.get(operationNonce)
    if (!operation || operation.operation_id !== operationId) fail('STATE_OPERATION_UNKNOWN', 'exact operation is unknown')
    return deepFreeze(clone(operation))
  }

  _acquireLock({ operationId, operationNonce, acquiredAt }) {
    const lockPath = path.join(this.rootPath, LOCK_DIRECTORY)
    try {
      fs.mkdirSync(lockPath, { mode: 0o700 })
    } catch (error) {
      if (error.code === 'EEXIST') fail('STATE_OPERATION_LOCKED', 'another operation lock exists')
      fail('STATE_OPERATION_LOCK_FAILED', `could not create operation lock: ${error.code ?? error.message}`)
    }
    const rawToken = crypto.randomBytes(32).toString('hex')
    const lease = {
      format: STATE_FORMAT,
      format_version: STATE_VERSION,
      operation_id: operationId,
      operation_nonce: operationNonce,
      lease_token_sha256: sha256Hex(rawToken),
      owner_pid: process.pid,
      acquired_at: acquiredAt,
    }
    try {
      this._fault('after_lock_directory', { operationId })
      writeExclusiveDurable(path.join(lockPath, 'lease.json'), canonicalBytes(lease), 0o400)
      fsyncDirectory(lockPath)
      fsyncDirectory(this.rootPath)
      this._fault('after_lock_fsync', { operationId })
    } catch (error) {
      if (!(error instanceof SimulatedStateCrash)) fs.rmSync(lockPath, { recursive: true, force: true })
      throw error
    }
    this.ownedLease = { ...lease, raw_token: rawToken, recovery_override: false }
    return this.ownedLease
  }

  _releaseOwnedLock() {
    if (!this.ownedLease) fail('STATE_OPERATION_LEASE_REQUIRED', 'this process does not own the operation lease')
    const lockPath = path.join(this.rootPath, LOCK_DIRECTORY)
    const persisted = readCanonicalFile(path.join(lockPath, 'lease.json'), 'operation lock lease')
    if (persisted.lease_token_sha256 !== this.ownedLease.lease_token_sha256) fail('STATE_OPERATION_LEASE_MISMATCH', 'operation lease changed')
    if (!this.ownedLease.recovery_override && sha256Hex(this.ownedLease.raw_token) !== persisted.lease_token_sha256) fail('STATE_OPERATION_LEASE_MISMATCH', 'process-held lease token does not authenticate the lock')
    fs.rmSync(lockPath, { recursive: true })
    fsyncDirectory(this.rootPath)
    this.ownedLease = null
    this._refresh()
  }

  beginOperation({ operation, claimTransition = null, authenticatedLauncherBindingCode }) {
    this._assertWritable()
    assertPlainObject(operation, 'operation')
    const operationBindingFacts = this._bindingFactsAt(operation.startedAt)
    requiredTrustedBinding(operationBindingFacts, 'trusted_launcher', authenticatedLauncherBindingCode, 'operation launcher', operation.startedAt)
    const startedEvent = {
      event_kind_code: 'operation_started',
      operation_id: operation.operationId,
      operation_nonce: operation.operationNonce,
      operation_mode_code: operation.operationModeCode,
      started_at: operation.startedAt,
      runtime_profile_record_digest_sha256: operation.runtimeProfileRecordDigestSha256,
      identity_bindings_record_digest_sha256: operation.identityBindingsRecordDigestSha256,
      permit_code: claimTransition?.permit_code ?? null,
      permit_claim_record_digest_sha256: claimTransition?.record_digest_sha256 ?? null,
      started_by_binding_code: authenticatedLauncherBindingCode,
    }
    const events = []
    if (claimTransition) {
      if (claimTransition.recorded_by_runtime_role_code !== 'trusted_launcher' || claimTransition.recorded_by_binding_code !== authenticatedLauncherBindingCode || claimTransition.persisted_by_binding_code !== authenticatedLauncherBindingCode) fail('STATE_AUTHENTICATED_BINDING_MISMATCH', 'permit claim is not attributed to the authenticated launcher')
      if (claimTransition.persisted_at !== operation.startedAt) fail('STATE_OPERATION_PERMIT_INVALID', 'claim persistence and operation start must be identical')
      events.push({ event_kind_code: 'permit_transition_recorded', record: clone(claimTransition) })
    }
    events.push(startedEvent)
    const preflightProjection = structuredClone(this.projection)
    for (const event of events) applyEvent(preflightProjection, event, operationBindingFacts)
    this._acquireLock({ operationId: operation.operationId, operationNonce: operation.operationNonce, acquiredAt: operation.startedAt })
    try {
      const commit = this._appendEvents(events, { transactionCode: 'operation.begin', writtenAt: operation.startedAt })
      return Object.freeze({ ...commit, operationId: operation.operationId, operationNonce: operation.operationNonce })
    } catch (error) {
      if (!(error instanceof SimulatedStateCrash)) {
        this._refresh()
        const persistedOperation = this.projection.operationsByNonce.get(operation.operationNonce)
        const durableOrInterrupted = (persistedOperation?.operation_id === operation.operationId && persistedOperation?.started_at === operation.startedAt)
          || this.pendingNames.length > 0
          || this.allCommits.length > this.head.sequence
        if (!durableOrInterrupted) this._releaseOwnedLock()
      }
      throw error
    }
  }

  _finishNoEffect({ operationId, operationNonce, recordedAt, beforeLogicalStateSha256, afterLogicalStateSha256, reasonCode = 'synthetic_control_plane_no_effect', authenticatedVerifierBindingCode, terminalPermitTransition = null }, recoveryToken = null) {
    this._assertWritable({ allowOwnedOperation: true })
    if (!this.ownedLease || this.ownedLease.operation_id !== operationId || this.ownedLease.operation_nonce !== operationNonce) fail('STATE_OPERATION_LEASE_REQUIRED', 'exact process-held lease is required')
    const operation = this.projection.operationsByNonce.get(operationNonce)
    if (!operation || operation.operation_id !== operationId) fail('STATE_OPERATION_NOT_ACTIVE', 'operation is not active')
    if ((operation.permit_code === null) !== (terminalPermitTransition === null)) fail('STATE_OPERATION_PERMIT_INVALID', 'permitted operations require one atomic terminal transition and unpermitted operations forbid one')
    const events = []
    if (terminalPermitTransition) {
      if (terminalPermitTransition.persisted_at !== recordedAt || terminalPermitTransition.operation_id !== operationId || terminalPermitTransition.operation_nonce !== operationNonce) fail('STATE_OPERATION_PERMIT_INVALID', 'terminal permit transition differs from operation result')
      if (terminalPermitTransition.to_state_code !== 'spent' || terminalPermitTransition.transition_code !== 'no_effect_verified' || terminalPermitTransition.reason_code !== 'no_effect_verified') fail('STATE_OPERATION_PERMIT_OUTCOME_MISMATCH', 'a no-effect operation requires the exact no-effect permit transition')
      events.push({ event_kind_code: 'permit_transition_recorded', record: clone(terminalPermitTransition) })
    }
    events.push({
      event_kind_code: 'operation_no_effect_verified',
      operation_id: operationId,
      operation_nonce: operationNonce,
      before_logical_state_sha256: beforeLogicalStateSha256,
      after_logical_state_sha256: afterLogicalStateSha256,
      recorded_at: recordedAt,
      recorded_by_runtime_role_code: 'independent_verifier',
      recorded_by_binding_code: authenticatedVerifierBindingCode,
      reason_code: reasonCode,
    })
    try {
      const transactionCode = recoveryToken === HISTORICAL_OPERATION_RECOVERY ? 'recovery.operation-no-effect' : 'operation.no-effect'
      const result = this._appendEvents(events, { transactionCode, writtenAt: recordedAt })
      this._fault('after_terminal_commit_before_unlock', { operationId })
      this._releaseOwnedLock()
      return result
    } catch (error) {
      if (!(error instanceof SimulatedStateCrash) && this.projection.operationsByNonce.get(operationNonce)?.state_code !== 'in_progress') this._releaseOwnedLock()
      throw error
    }
  }

  finishNoEffect(input) {
    return this._finishNoEffect(input)
  }

  markRecoveryRequired({ operationId, operationNonce, recordedAt, reasonCode, lastKnownLogicalStateSha256 = null, authenticatedLauncherBindingCode, terminalPermitTransition = null }) {
    this._assertWritable({ allowOwnedOperation: true })
    if (!this.ownedLease || this.ownedLease.operation_id !== operationId || this.ownedLease.operation_nonce !== operationNonce) fail('STATE_OPERATION_LEASE_REQUIRED', 'exact process-held lease is required')
    const operation = this.projection.operationsByNonce.get(operationNonce)
    if (!operation || operation.operation_id !== operationId) fail('STATE_OPERATION_NOT_ACTIVE', 'operation is not active')
    if ((operation.permit_code === null) !== (terminalPermitTransition === null)) fail('STATE_OPERATION_PERMIT_INVALID', 'permitted operations require one atomic terminal transition and unpermitted operations forbid one')
    const events = []
    if (terminalPermitTransition) {
      if (terminalPermitTransition.persisted_at !== recordedAt || terminalPermitTransition.operation_id !== operationId || terminalPermitTransition.operation_nonce !== operationNonce) fail('STATE_OPERATION_PERMIT_INVALID', 'terminal permit transition differs from operation result')
      if (terminalPermitTransition.to_state_code !== 'recovery_required' || terminalPermitTransition.transition_code !== 'state_ambiguous' || terminalPermitTransition.reason_code !== 'state_ambiguous') fail('STATE_OPERATION_PERMIT_OUTCOME_MISMATCH', 'a recovery-required operation requires the exact ambiguous-state permit transition')
      events.push({ event_kind_code: 'permit_transition_recorded', record: clone(terminalPermitTransition) })
    }
    events.push({
      event_kind_code: 'operation_recovery_required',
      operation_id: operationId,
      operation_nonce: operationNonce,
      last_known_logical_state_sha256: lastKnownLogicalStateSha256,
      recorded_at: recordedAt,
      recorded_by_runtime_role_code: 'trusted_launcher',
      recorded_by_binding_code: authenticatedLauncherBindingCode,
      reason_code: reasonCode,
    })
    const result = this._appendEvents(events, { transactionCode: 'operation.recovery-required', writtenAt: recordedAt })
    this._fault('after_recovery_required_commit_before_unlock', { operationId })
    this._releaseOwnedLock()
    return result
  }

  recoverInterruptedPublish({ recoveredAt, authenticatedRecoveryBindingCode }) {
    this._refresh()
    const recoveredMs = assertTimestamp(recoveredAt, 'recoveredAt')
    const pendingDirectory = path.join(this.rootPath, PENDING_DIRECTORY)
    const inspectPending = () => fs.readdirSync(pendingDirectory).sort().map((name) => {
      const recognizedCommit = /^\d{12}-[0-9a-f]{64}\.commit\.pending$/.test(name)
      const recognizedHead = /^head-\d{12}-(?:[0-9a-f]{64}|genesis)-[0-9a-f]{16}\.pending$/.test(name)
      if (!recognizedCommit && !recognizedHead) fail('STATE_RECOVERY_AMBIGUOUS', `unrecognized pending entry ${name}`)
      const target = path.join(pendingDirectory, name)
      const stat = fs.lstatSync(target)
      if (!stat.isFile() || stat.isSymbolicLink()) fail('STATE_PATH_UNSAFE', 'pending recovery encountered a non-regular entry')
      return { name, target }
    })

    // Before genesis there is no protected generation that can authorize an
    // append-only recovery audit commit. Remnants that never became a linked
    // commit are therefore validated against the explicit bootstrap anchor,
    // discarded as unaccepted bytes, and genesis remains retryable. A linked
    // sequence-one commit takes the ordinary durable recovery path below.
    if (this.head.sequence === 0 && this.allCommits.length === 0 && this.projection.generationPairs.length === 0) {
      if (this.recoveryIntent) fail('STATE_RECOVERY_AMBIGUOUS', 'pre-genesis state cannot contain a publish recovery intent')
      const pendingEntries = inspectPending()
      if (!pendingEntries.length && !this.appendLock && !this.appendLockAnomaly) fail('STATE_RECOVERY_NOT_NEEDED', 'there is no interrupted pre-genesis publish to recover')
      if (this.appendLockAnomaly && !pendingEntries.length) fail('STATE_PRE_GENESIS_INCIDENT_TIME_UNAVAILABLE', 'an incomplete pre-genesis append mutex without a sealed timestamp requires controlled out-of-band incident recovery')
      if (this.appendLock && appendLockOwnerIsAlive(this.appendLock)) fail('STATE_APPEND_LOCK_ACTIVE', 'append mutex owner is still alive')
      if (this.appendLock && recoveredMs <= assertTimestamp(this.appendLock.acquired_at, 'pre-genesis append-lock acquisition')) {
        fail('STATE_RECOVERY_CHRONOLOGY_INVALID', 'pre-genesis recovery must follow append-lock acquisition')
      }
      const authorityAnchors = this.appendLock ? [this.appendLock.acquired_at] : []
      for (const { name, target } of pendingEntries) {
        const match = /^(\d{12})-([0-9a-f]{64})\.commit\.pending$/.exec(name)
        if (!match) fail('STATE_RECOVERY_AMBIGUOUS', 'pre-genesis recovery encountered a non-commit pending object')
        const pendingCommit = readCanonicalFile(target, 'pre-genesis pending commit', this.expectedUid)
        validateCommit(pendingCommit, 1, null, match[2])
        replayCommits([pendingCommit], this.bootstrapIdentityBindings)
        authorityAnchors.push(pendingCommit.written_at)
        if (recoveredMs <= assertTimestamp(pendingCommit.written_at, 'pre-genesis pending commit time')) {
          fail('STATE_RECOVERY_CHRONOLOGY_INVALID', 'pre-genesis recovery must follow pending commit persistence')
        }
      }
      if (new Set(authorityAnchors).size > 1) fail('STATE_RECOVERY_AMBIGUOUS', 'pre-genesis lock and pending activation disagree on their authority boundary')
      const recoveryAuthorityAt = authorityAnchors.length ? authorityAnchors[0] : recoveredAt
      requiredTrustedBinding(this.bootstrapIdentityBindings.facts, 'recovery_authority', authenticatedRecoveryBindingCode, 'pre-genesis recovery authority', recoveryAuthorityAt)
      if (fs.existsSync(path.join(this.rootPath, APPEND_LOCK_DIRECTORY))) fs.rmSync(path.join(this.rootPath, APPEND_LOCK_DIRECTORY), { recursive: true })
      for (const { target } of pendingEntries) fs.unlinkSync(target)
      fsyncDirectory(pendingDirectory)
      fsyncDirectory(this.rootPath)
      this._refresh()
      return Object.freeze({
        actionCode: 'discarded_pre_genesis_interruption',
        bootstrapTrustAnchorUsed: true,
        durableAuditRecorded: false,
        recoveryReasons: [...this.recoveryReasons],
      })
    }

    let intent = this.recoveryIntent
    if (intent) {
      if (intent.recovered_at !== recoveredAt || intent.recovered_by_binding_code !== authenticatedRecoveryBindingCode) {
        fail('STATE_RECOVERY_INTENT_MISMATCH', 'publish recovery retry must exactly match the durable recovery intent')
      }
    } else {
      if (!this.pendingNames.length && this.allCommits.length === this.head.sequence && !this.appendLock && !this.appendLockAnomaly) fail('STATE_RECOVERY_NOT_NEEDED', 'there is no interrupted publish to recover')
      if (this.appendLock && appendLockOwnerIsAlive(this.appendLock)) fail('STATE_APPEND_LOCK_ACTIVE', 'append mutex owner is still alive')
      const latestKnownCommit = this.allCommits.at(-1)
      if (latestKnownCommit && recoveredMs <= assertTimestamp(latestKnownCommit.written_at, 'latest known commit written_at')) {
        fail('STATE_COMMIT_CHRONOLOGY_INVALID', 'publish recovery time must advance all durable commit times')
      }
      const unanchored = this.allCommits.slice(this.head.sequence)
      if (unanchored.length > 1) fail('STATE_RECOVERY_AMBIGUOUS', 'more than one unanchored commit requires an external incident procedure')
      const pendingEntries = inspectPending()
      const affected = unanchored.at(0) ?? null
      if (affected && this.appendLockAnomaly) fail('STATE_RECOVERY_AMBIGUOUS', 'an unanchored commit cannot be correlated with an incomplete append mutex')
      if (affected && this.appendLock && (
        this.appendLock.intended_sequence !== affected.sequence
        || this.appendLock.base_sequence !== affected.sequence - 1
        || this.appendLock.base_commit_sha256 !== affected.previous_commit_sha256
        || this.appendLock.intended_commit_sha256 !== affected.commit_sha256
        || this.appendLock.acquired_at !== affected.written_at
        || this.appendLock.transaction_code !== affected.transaction_code
      )) fail('STATE_RECOVERY_AMBIGUOUS', 'the append mutex does not bind the exact unanchored commit')
      if (this.appendLock && recoveredMs <= assertTimestamp(this.appendLock.acquired_at, 'append-lock acquisition')) {
        fail('STATE_RECOVERY_CHRONOLOGY_INVALID', 'publish recovery must follow append-lock acquisition')
      }
      for (const { name, target } of pendingEntries) {
        const match = /^(\d{12})-([0-9a-f]{64})\.commit\.pending$/.exec(name)
        if (!match) continue
        const sequence = Number(match[1])
        const previous = sequence === 1 ? null : this.allCommits[sequence - 2]
        if (sequence > 1 && !previous) fail('STATE_RECOVERY_AMBIGUOUS', 'pending commit does not extend a known predecessor')
        const pendingCommit = readCanonicalFile(target, 'pending publish commit', this.expectedUid)
        validateCommit(pendingCommit, sequence, previous?.commit_sha256 ?? null, match[2])
        if (recoveredMs <= assertTimestamp(pendingCommit.written_at, 'pending commit written_at')) {
          fail('STATE_RECOVERY_CHRONOLOGY_INVALID', 'publish recovery must follow every pending commit persistence time')
        }
      }
      const linkedHead = this.commits.at(-1) ?? null
      const headAnchoredAffected = !affected
        && this.appendLock
        && linkedHead
        && this.appendLock.intended_sequence === linkedHead.sequence
        && this.appendLock.base_sequence === linkedHead.sequence - 1
        && this.appendLock.base_commit_sha256 === linkedHead.previous_commit_sha256
        && this.appendLock.intended_commit_sha256 === linkedHead.commit_sha256
        && this.appendLock.acquired_at === linkedHead.written_at
        && this.appendLock.transaction_code === linkedHead.transaction_code
        ? linkedHead
        : null
      const recoveredCommit = affected ?? headAnchoredAffected
      const targetCommits = recoveredCommit ? this.allCommits.slice(0, recoveredCommit.sequence) : this.commits
      const targetProjection = replayCommits(targetCommits, this.bootstrapIdentityBindings)
      let recoveryAuthorityAt
      let targetPair
      if (recoveredCommit) {
        if (recoveredCommit.sequence === 1) {
          targetPair = targetProjection.generationPairs[0]
          if (!targetPair || recoveredCommit.events.length !== 1 || recoveredCommit.events[0].event_kind_code !== 'generation_pair_activated') {
            fail('STATE_GENESIS_ACTIVATION_REQUIRED', 'sequence-one recovery requires the exact validated genesis activation')
          }
        } else {
          const preAffectedProjection = replayCommits(this.allCommits.slice(0, recoveredCommit.sequence - 1), this.bootstrapIdentityBindings)
          targetPair = selectGenerationPairFromProjection(preAffectedProjection, recoveredCommit.written_at)
        }
        assertGenerationContext(recoveredCommit.generation_context, generationContext(targetPair))
        recoveryAuthorityAt = recoveredCommit.written_at
      } else if (this.appendLock) {
        recoveryAuthorityAt = this.appendLock.acquired_at
        targetPair = selectGenerationPairFromProjection(targetProjection, recoveryAuthorityAt)
      } else {
        targetPair = targetProjection.generationPairs.at(-1)
        if (!targetPair) fail('STATE_ACTIVE_GENERATION_MISSING', 'publish recovery has no historical generation context')
        recoveryAuthorityAt = targetPair.activated_at
        targetPair = pairForGenerationContext(targetProjection, generationContext(targetPair), recoveryAuthorityAt)
      }
      requiredTrustedBinding(targetPair.trusted_role_bindings, 'recovery_authority', authenticatedRecoveryBindingCode, 'protected-state recovery authority', recoveryAuthorityAt)
      requiredTrustedBinding(targetPair.trusted_role_bindings, 'trusted_launcher', bindingFact(targetPair.trusted_role_bindings, 'trusted_launcher').binding_code, 'publish recovery persistence broker', recoveryAuthorityAt)
      const recoveryActionCode = affected
        ? 'finalized_durable_unanchored_commit'
        : headAnchoredAffected
          ? 'completed_durable_head_commit_cleanup'
          : pendingEntries.length
            ? 'discarded_uncommitted_pending'
            : 'discarded_abandoned_append_lock'
      const appendLockStateCode = this.appendLock ? 'complete_abandoned' : this.appendLockAnomaly ? 'incomplete' : 'none'
      const appendLockLeaseSha256 = this.appendLock?.lease_sha256 ?? null
      const pendingNames = pendingEntries.map(({ name }) => name)
      const recoveryEvent = {
        event_kind_code: 'recovery_action_recorded',
        recovery_action_code: recoveryActionCode,
        recovered_at: recoveredAt,
        recovered_by_binding_code: authenticatedRecoveryBindingCode,
        affected_sequence: recoveredCommit?.sequence ?? null,
        affected_commit_sha256: recoveredCommit?.commit_sha256 ?? null,
        operation_id: null,
        operation_nonce: null,
        incident_sha256: publishRecoveryIncidentSha256({
          actionCode: recoveryActionCode,
          affectedSequence: recoveredCommit?.sequence ?? null,
          affectedCommitSha256: recoveredCommit?.commit_sha256 ?? null,
          appendLockStateCode,
          appendLockLeaseSha256,
          pendingNames,
        }),
      }
      const simulated = structuredClone(targetProjection)
      applyEvent(simulated, recoveryEvent, targetPair.trusted_role_bindings, { recoveryBindingAt: recoveryAuthorityAt })
      const unsignedAuditCommit = {
        format: STATE_FORMAT,
        format_version: STATE_VERSION,
        sequence: targetCommits.length + 1,
        previous_commit_sha256: targetCommits.at(-1)?.commit_sha256 ?? null,
        transaction_code: 'recovery.publish',
        written_at: recoveredAt,
        generation_context: generationContext(targetPair),
        persisted_by_binding_code: bindingFact(targetPair.trusted_role_bindings, 'trusted_launcher').binding_code,
        events: [recoveryEvent],
      }
      const auditCommit = { ...unsignedAuditCommit, commit_sha256: sha256Hex(Buffer.from(canonicalizeStateRecord(unsignedAuditCommit), 'utf8')) }
      const unsignedIntent = {
        format: STATE_FORMAT,
        format_version: STATE_VERSION,
        action_code: recoveryEvent.recovery_action_code,
        recovered_at: recoveredAt,
        recovered_by_binding_code: authenticatedRecoveryBindingCode,
        affected_sequence: recoveredCommit?.sequence ?? null,
        affected_commit_sha256: recoveredCommit?.commit_sha256 ?? null,
        append_lock_state_code: appendLockStateCode,
        append_lock_lease_sha256: appendLockLeaseSha256,
        pending_names: pendingNames,
        audit_commit: auditCommit,
      }
      intent = { ...unsignedIntent, intent_sha256: recoveryIntentDigest(unsignedIntent) }
      writeExclusiveDurable(path.join(this.rootPath, RECOVERY_INTENT_FILE), canonicalBytes(intent), 0o400)
      fsyncDirectory(this.rootPath)
      this._fault('after_recovery_intent_fsync', { actionCode: intent.action_code })
    }

    const currentPending = inspectPending()
    const intendedNames = new Set(intent.pending_names)
    const auditPrefix = `${String(intent.audit_commit.sequence).padStart(12, '0')}-${intent.audit_commit.commit_sha256}`
    const auditPendingName = `${auditPrefix}.commit.pending`
    if (currentPending.some(({ name }) => !intendedNames.has(name) && name !== auditPendingName)) fail('STATE_RECOVERY_AMBIGUOUS', 'publish recovery found pending material outside its durable intent')
    if (intent.append_lock_state_code === 'complete_abandoned' && this.appendLock) {
      if (this.appendLock.lease_sha256 !== intent.append_lock_lease_sha256 || appendLockOwnerIsAlive(this.appendLock)) fail('STATE_RECOVERY_AMBIGUOUS', 'append mutex no longer matches the abandoned lock sealed by the recovery intent')
      fs.rmSync(path.join(this.rootPath, APPEND_LOCK_DIRECTORY), { recursive: true })
      fsyncDirectory(this.rootPath)
    } else if (intent.append_lock_state_code === 'incomplete' && this.appendLockAnomaly === 'incomplete_append_lock') {
      fs.rmSync(path.join(this.rootPath, APPEND_LOCK_DIRECTORY), { recursive: true })
      fsyncDirectory(this.rootPath)
    } else if ((intent.append_lock_state_code === 'complete_abandoned' && !this.appendLock && this.appendLockAnomaly) ||
        (intent.append_lock_state_code === 'incomplete' && (this.appendLock || (!this.appendLockAnomaly && fs.existsSync(path.join(this.rootPath, APPEND_LOCK_DIRECTORY))))) ||
        (intent.append_lock_state_code === 'none' && (this.appendLock || this.appendLockAnomaly))) {
      fail('STATE_RECOVERY_AMBIGUOUS', 'an append mutex appeared after the recovery intent was sealed')
    }
    this._fault('after_recovery_append_lock_cleanup', { actionCode: intent.action_code })
    if (intent.affected_sequence !== null) {
      const affected = this.allCommits[intent.affected_sequence - 1]
      if (!affected || affected.commit_sha256 !== intent.affected_commit_sha256) fail('STATE_RECOVERY_INTENT_INVALID', 'durable recovery intent no longer identifies the exact commit')
      if (this.head.sequence < intent.affected_sequence) {
        fsyncDirectory(path.join(this.rootPath, COMMIT_DIRECTORY))
        replaceHeadDurably(this.rootPath, { format: STATE_FORMAT, format_version: STATE_VERSION, sequence: intent.affected_sequence, commit_sha256: intent.affected_commit_sha256 })
      } else if (this.head.sequence === intent.affected_sequence && this.head.commit_sha256 !== intent.affected_commit_sha256) {
        fail('STATE_RECOVERY_AMBIGUOUS', 'HEAD advanced outside the durable recovery intent')
      }
    }
    this._fault('after_recovery_head_replace', { actionCode: intent.action_code })
    for (const { name, target } of currentPending) if (intendedNames.has(name)) fs.unlinkSync(target)
    fsyncDirectory(pendingDirectory)
    this._fault('after_recovery_pending_cleanup', { actionCode: intent.action_code })

    const auditCommitPath = path.join(this.rootPath, COMMIT_DIRECTORY, `${auditPrefix}.json`)
    const auditPendingPath = path.join(pendingDirectory, auditPendingName)
    if (fs.existsSync(auditCommitPath)) {
      const persisted = readCanonicalFile(auditCommitPath, 'publish recovery audit commit', this.expectedUid)
      if (canonicalizeStateRecord(persisted) !== canonicalizeStateRecord(intent.audit_commit)) fail('STATE_RECOVERY_AMBIGUOUS', 'published recovery audit commit differs from its durable intent')
    } else {
      if (fs.existsSync(auditPendingPath)) {
        const pendingAudit = readCanonicalFile(auditPendingPath, 'pending publish recovery audit commit', this.expectedUid)
        if (canonicalizeStateRecord(pendingAudit) !== canonicalizeStateRecord(intent.audit_commit)) fail('STATE_RECOVERY_AMBIGUOUS', 'pending recovery audit commit differs from its durable intent')
      } else {
        writeExclusiveDurable(auditPendingPath, canonicalBytes(intent.audit_commit))
        fsyncDirectory(pendingDirectory)
      }
      this._fault('after_recovery_audit_pending_fsync', { actionCode: intent.action_code })
      fs.linkSync(auditPendingPath, auditCommitPath)
      fsyncDirectory(path.join(this.rootPath, COMMIT_DIRECTORY))
    }
    this._fault('after_recovery_audit_commit_link', { actionCode: intent.action_code })
    if (this.head.sequence < intent.audit_commit.sequence) {
      replaceHeadDurably(this.rootPath, { format: STATE_FORMAT, format_version: STATE_VERSION, sequence: intent.audit_commit.sequence, commit_sha256: intent.audit_commit.commit_sha256 })
    } else if (this.head.sequence !== intent.audit_commit.sequence || this.head.commit_sha256 !== intent.audit_commit.commit_sha256) {
      fail('STATE_RECOVERY_AMBIGUOUS', 'HEAD differs from the exact recovery audit commit')
    }
    this._fault('after_recovery_audit_commit', { actionCode: intent.action_code })
    if (fs.existsSync(auditPendingPath)) fs.unlinkSync(auditPendingPath)
    fsyncDirectory(pendingDirectory)
    fs.unlinkSync(path.join(this.rootPath, RECOVERY_INTENT_FILE))
    fsyncDirectory(this.rootPath)
    this._refresh()
    return Object.freeze({ actionCode: intent.action_code, affectedSequence: intent.affected_sequence, affectedCommitSha256: intent.affected_commit_sha256, recoveryReasons: [...this.recoveryReasons] })
  }

  discardUnregisteredLock({ recoveredAt, authenticatedRecoveryBindingCode }) {
    this._refresh()
    const recoveredMs = assertTimestamp(recoveredAt, 'lock recovery time')
    const incomplete = this.lockAnomaly === 'incomplete_operation_lock'
    if ((!this.lock && !incomplete) || (this.lock && this.projection.operationsByNonce.has(this.lock.operation_nonce)) ||
        (incomplete && [...this.projection.operationsByNonce.values()].some((operation) => operation.state_code === 'in_progress'))) {
      fail('STATE_LOCK_RECOVERY_FORBIDDEN', 'only an incomplete or unregistered lock with no committed operation may be discarded')
    }
    const historicalPair = this.projection.generationPairs.at(-1)
    if (!historicalPair) fail('STATE_ACTIVE_GENERATION_MISSING', 'lock recovery has no historical generation context')
    const recoveryAuthorityAt = historicalPair.activated_at
    requiredTrustedBinding(historicalPair.trusted_role_bindings, 'recovery_authority', authenticatedRecoveryBindingCode, 'lock recovery authority', recoveryAuthorityAt)
    const operationId = this.lock?.operation_id ?? null
    const operationNonce = this.lock?.operation_nonce ?? null
    const actionCode = incomplete ? 'discarded_incomplete_lock' : 'discarded_uncommitted_pending'
    const incidentSha256 = operationLockIncidentSha256(this.rootPath, this.lock)
    const recordedRecovery = this.projection.recoveryActions.find((event) => event.recovery_action_code === actionCode && event.incident_sha256 === incidentSha256)
    if (recordedRecovery) {
      if (recordedRecovery.recovered_at !== recoveredAt || recordedRecovery.recovered_by_binding_code !== authenticatedRecoveryBindingCode) fail('STATE_RECOVERY_RETRY_MISMATCH', 'lock recovery retry differs from its exact durable audit')
    } else {
      const latestCommit = this.commits.at(-1)
      if (latestCommit && recoveredMs <= assertTimestamp(latestCommit.written_at, 'latest commit time')) {
        fail('STATE_RECOVERY_CHRONOLOGY_INVALID', 'lock recovery must advance the protected commit chronology')
      }
      if (this.lock && recoveredMs <= assertTimestamp(this.lock.acquired_at, 'lock acquisition time')) {
        fail('STATE_RECOVERY_CHRONOLOGY_INVALID', 'lock recovery must occur after the recorded lock acquisition')
      }
      this._appendEvents([{
        event_kind_code: 'recovery_action_recorded',
        recovery_action_code: actionCode,
        recovered_at: recoveredAt,
        recovered_by_binding_code: authenticatedRecoveryBindingCode,
        affected_sequence: null,
        affected_commit_sha256: null,
        operation_id: operationId,
        operation_nonce: operationNonce,
        incident_sha256: incidentSha256,
      }], { transactionCode: 'recovery.lock', writtenAt: recoveredAt })
      this._fault('after_lock_recovery_commit_before_unlock', { operationId })
    }
    fs.rmSync(path.join(this.rootPath, LOCK_DIRECTORY), { recursive: true })
    fsyncDirectory(this.rootPath)
    this._refresh()
  }

  recoverNoEffectAfterCrash({ operationId, operationNonce, recordedAt, beforeLogicalStateSha256, afterLogicalStateSha256, reasonCode = 'synthetic_control_plane_no_effect', authenticatedVerifierBindingCode, authenticatedRecoveryBindingCode, terminalPermitTransition = null }) {
    this._refresh()
    if (this.pendingNames.length || this.allCommits.length > this.head.sequence) fail('STATE_RECOVERY_ORDER_INVALID', 'interrupted publish must be reconciled before operation recovery')
    if (!this.lock || this.lock.operation_id !== operationId || this.lock.operation_nonce !== operationNonce) fail('STATE_OPERATION_LOCK_MISMATCH', 'crash recovery does not match the protected lock')
    const operation = this.projection.operationsByNonce.get(operationNonce)
    if (!operation || operation.operation_id !== operationId || operation.state_code !== 'in_progress') fail('STATE_OPERATION_NOT_ACTIVE', 'crash recovery requires one committed in-progress operation')
    const historicalPair = pairForOperationFromProjection(this.projection, operation)
    requiredTrustedBinding(historicalPair.trusted_role_bindings, 'recovery_authority', authenticatedRecoveryBindingCode, 'operation recovery authority', operation.started_at)
    this.ownedLease = { ...this.lock, raw_token: null, recovery_override: true }
    return this._finishNoEffect({ operationId, operationNonce, recordedAt, beforeLogicalStateSha256, afterLogicalStateSha256, reasonCode, authenticatedVerifierBindingCode, terminalPermitTransition }, HISTORICAL_OPERATION_RECOVERY)
  }

  reconcileTerminalLock({ recoveredAt, authenticatedRecoveryBindingCode }) {
    this._refresh()
    const recoveredMs = assertTimestamp(recoveredAt, 'terminal-lock recovery time')
    if (!this.lock) fail('STATE_LOCK_RECOVERY_FORBIDDEN', 'there is no lock')
    const operation = this.projection.operationsByNonce.get(this.lock.operation_nonce)
    if (!operation || operation.state_code === 'in_progress') fail('STATE_LOCK_RECOVERY_FORBIDDEN', 'lock is not backed by a terminal operation')
    const historicalPair = pairForOperationFromProjection(this.projection, operation)
    requiredTrustedBinding(historicalPair.trusted_role_bindings, 'recovery_authority', authenticatedRecoveryBindingCode, 'terminal-lock recovery authority', operation.started_at)
    const incidentSha256 = operationLockIncidentSha256(this.rootPath, this.lock)
    const recordedRecovery = this.projection.recoveryActions.find((event) => event.recovery_action_code === 'removed_terminal_operation_lock' && event.incident_sha256 === incidentSha256)
    let result = null
    if (recordedRecovery) {
      if (recordedRecovery.recovered_at !== recoveredAt || recordedRecovery.recovered_by_binding_code !== authenticatedRecoveryBindingCode) fail('STATE_RECOVERY_RETRY_MISMATCH', 'terminal-lock recovery retry differs from its exact durable audit')
    } else {
      const latestCommit = this.commits.at(-1)
      if (latestCommit && recoveredMs <= assertTimestamp(latestCommit.written_at, 'latest commit time')) fail('STATE_RECOVERY_CHRONOLOGY_INVALID', 'terminal-lock recovery must advance the protected commit chronology')
      if (recoveredMs <= assertTimestamp(this.lock.acquired_at, 'terminal lock acquisition time')) fail('STATE_RECOVERY_CHRONOLOGY_INVALID', 'terminal-lock recovery must follow lock acquisition')
      result = this._appendEvents([{
        event_kind_code: 'recovery_action_recorded',
        recovery_action_code: 'removed_terminal_operation_lock',
        recovered_at: recoveredAt,
        recovered_by_binding_code: authenticatedRecoveryBindingCode,
        affected_sequence: null,
        affected_commit_sha256: null,
        operation_id: this.lock.operation_id,
        operation_nonce: this.lock.operation_nonce,
        incident_sha256: incidentSha256,
      }], { transactionCode: 'recovery.terminal-lock', writtenAt: recoveredAt })
      this._fault('after_terminal_lock_recovery_commit_before_unlock', { operationId: this.lock.operation_id })
    }
    fs.rmSync(path.join(this.rootPath, LOCK_DIRECTORY), { recursive: true })
    fsyncDirectory(this.rootPath)
    this._refresh()
    return result ?? Object.freeze({ sequence: this.head.sequence, commitSha256: this.head.commit_sha256 })
  }
}

function normalizeExpectedUid(expectedUid) {
  const uid = expectedUid ?? (typeof process.getuid === 'function' ? process.getuid() : undefined)
  if (!Number.isSafeInteger(uid) || uid < 0) fail('STATE_PLATFORM_UNSUPPORTED', 'a verified numeric Unix UID is required')
  return uid
}

export function createProtectedStateStore({ rootPath, trustedIdentityBindingsRecord, expectedUid, faultInjector } = {}) {
  if (typeof rootPath !== 'string' || !path.isAbsolute(rootPath)) fail('STATE_ROOT_INVALID', 'protected root must be an absolute trusted path')
  const uid = normalizeExpectedUid(expectedUid)
  const resolved = path.resolve(rootPath)
  if (fs.existsSync(resolved)) fail('STATE_ROOT_ALREADY_EXISTS', 'protected state root already exists')
  fs.mkdirSync(resolved, { mode: 0o700 })
  try {
    fs.mkdirSync(path.join(resolved, COMMIT_DIRECTORY), { mode: 0o700 })
    fs.mkdirSync(path.join(resolved, PENDING_DIRECTORY), { mode: 0o700 })
    const head = { format: STATE_FORMAT, format_version: STATE_VERSION, sequence: 0, commit_sha256: null }
    writeExclusiveDurable(path.join(resolved, HEAD_FILE), canonicalBytes(head), 0o400)
    fsyncDirectory(path.join(resolved, COMMIT_DIRECTORY))
    fsyncDirectory(path.join(resolved, PENDING_DIRECTORY))
    fsyncDirectory(resolved)
  } catch (error) {
    fs.rmSync(resolved, { recursive: true, force: true })
    throw error
  }
  const store = new ProtectedStateStore({ rootPath: resolved, expectedUid: uid, trustedIdentityBindingsRecord, faultInjector })
  protectedStateStores.add(store)
  return store
}

export function openProtectedStateStore({ rootPath, trustedIdentityBindingsRecord, expectedUid, faultInjector } = {}) {
  if (typeof rootPath !== 'string' || !path.isAbsolute(rootPath)) fail('STATE_ROOT_INVALID', 'protected root must be an absolute trusted path')
  const store = new ProtectedStateStore({ rootPath, expectedUid: normalizeExpectedUid(expectedUid), trustedIdentityBindingsRecord, faultInjector })
  protectedStateStores.add(store)
  return store
}

export function assertProtectedStateStore(value) {
  if (!protectedStateStores.has(value)) fail('STATE_TRUST_BOUNDARY_INVALID', 'protected state store was not created by the fixed-function factory')
  return value
}
