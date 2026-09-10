import fs from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { canonicalize, parseStrictJson, sha256Bytes, sha256File } from './canonical.mjs'
import { openProtectedStateStore } from './state-store.mjs'

const modulePath = fileURLToPath(import.meta.url)
const brokerInstances = new WeakSet()
const OPERATION_METHODS = Object.freeze({
  append_permit_transition: 'appendPermitTransition',
  begin_synthetic_bootstrap_scope_audit: 'beginOperation',
  begin_synthetic_dry_run: 'beginOperation',
  finish_synthetic_no_effect: 'finishNoEffect',
  issue_permit: 'issuePermit',
  mark_synthetic_recovery_required: 'markRecoveryRequired',
  mark_synthetic_bootstrap_scope_recovery: 'markRecoveryRequired',
  register_fixed_record: 'registerFixedRecord',
  revoke_fixed_record: 'revokeFixedRecord',
  revoke_generation_pair: 'revokeGenerationPair',
})
const SOURCE_FILES = Object.freeze({
  canonical: 'canonical.mjs',
  state_append_broker: 'state-append-broker.mjs',
  state_store: 'state-store.mjs',
})
const TIMESTAMP_PATTERN = /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u
const TERMINAL_WORKER_CODES = new Set([
  'STATE_ACTIVE_GENERATION_EXPIRED',
  'STATE_ACTIVE_GENERATION_MISSING',
  'STATE_ACTIVE_GENERATION_REVOKED',
  'STATE_ACTIVE_GENERATION_SUBSTITUTED',
  'STATE_BROKER_BUILD_MISMATCH',
  'STATE_BROKER_GENERATION_REVOKED',
  'STATE_BROKER_REPLAY',
])

export class D9StateAppendBrokerError extends Error {
  constructor(code, message, details = undefined) {
    super(`${code}: ${message}`)
    this.name = 'D9StateAppendBrokerError'
    this.code = code
    if (details !== undefined) this.details = details
  }
}

function fail(code, message, details) {
  throw new D9StateAppendBrokerError(code, message, details)
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('STATE_BROKER_INPUT_INVALID', `${label} must be an object`)
  const actual = Object.keys(value).toSorted()
  const wanted = [...expected].toSorted()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail('STATE_BROKER_INPUT_INVALID', `${label} has unknown or missing fields`)
}

function timestamp(value, label) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value) || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail('STATE_BROKER_INPUT_INVALID', `${label} is not a canonical UTC timestamp`)
  }
}

function brokerUid(value) {
  if (!Number.isSafeInteger(value) || value < 1_000 || value > 0xffff_fffe) fail('STATE_BROKER_CONFIGURATION_INVALID', 'broker UID is outside the frozen identity-binding domain')
  return value
}

function hash(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) fail('STATE_BROKER_CONFIGURATION_INVALID', `${label} is not lowercase SHA-256 hex`)
  return value
}

function assertProtectedRoot(rootPath, expectedUid) {
  if (typeof rootPath !== 'string' || !path.isAbsolute(rootPath) || rootPath.includes('\0')) fail('STATE_BROKER_CONFIGURATION_INVALID', 'protected root must be absolute and NUL-free')
  const stat = fs.lstatSync(rootPath, { bigint: true })
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o077n) !== 0n) {
    fail('STATE_BROKER_CONFIGURATION_INVALID', 'protected root must be an owner-only directory owned by the broker UID')
  }
  return path.resolve(rootPath)
}

function assertRuntime(workerModulePath, sourceHashes, nodeExecutableSha256) {
  if (typeof workerModulePath !== 'string' || !path.isAbsolute(workerModulePath) || workerModulePath.includes('\0') || path.basename(workerModulePath) !== SOURCE_FILES.state_append_broker) {
    fail('STATE_BROKER_CONFIGURATION_INVALID', 'worker module path is invalid')
  }
  exactKeys(sourceHashes, Object.keys(SOURCE_FILES), 'source hashes')
  const directory = path.dirname(workerModulePath)
  const directoryStat = fs.lstatSync(directory, { bigint: true })
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink() || directoryStat.uid !== 0n || (directoryStat.mode & 0o022n) !== 0n) {
    fail('STATE_BROKER_CONFIGURATION_INVALID', 'worker runtime must be root-owned and non-writable')
  }
  for (const [code, leaf] of Object.entries(SOURCE_FILES)) {
    const target = path.join(directory, leaf)
    const stat = fs.lstatSync(target, { bigint: true })
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0n || (stat.mode & 0o022n) !== 0n) fail('STATE_BROKER_CONFIGURATION_INVALID', `${leaf} is not a protected source file`)
    if (sha256File(target) !== hash(sourceHashes[code], `${code} source digest`)) fail('STATE_BROKER_BUILD_MISMATCH', `${leaf} differs from the pinned source`)
  }
  if (sha256Bytes(fs.readFileSync('/proc/self/exe')) !== hash(nodeExecutableSha256, 'Node executable digest')) fail('STATE_BROKER_BUILD_MISMATCH', 'Node executable differs from the pinned build')
  return path.resolve(workerModulePath)
}

function assertInput(operationCode, input) {
  switch (operationCode) {
    case 'register_fixed_record':
      exactKeys(input, ['authenticatedBindingCode', 'authenticatedRuntimeRoleCode', 'record', 'recordedAt'], 'register input')
      timestamp(input.recordedAt, 'recordedAt')
      break
    case 'issue_permit':
      exactKeys(input, ['authenticatedIssuerBindingCode', 'authenticatedIssuerRuntimeRoleCode', 'authenticatedPersistenceBindingCode', 'persistedAt', 'record'], 'permit input')
      timestamp(input.persistedAt, 'persistedAt')
      break
    case 'append_permit_transition':
      exactKeys(input, ['authenticatedPersistenceBindingCode', 'authenticatedSemanticBindingCode', 'authenticatedSemanticRuntimeRoleCode', 'record'], 'transition input')
      timestamp(input.record?.persisted_at, 'record.persisted_at')
      break
    case 'begin_synthetic_dry_run':
      exactKeys(input, ['authenticatedLauncherBindingCode', 'operation'], 'begin input')
      timestamp(input.operation?.startedAt, 'operation.startedAt')
      if (input.operation?.operationModeCode !== 'dry_run') fail('STATE_BROKER_INPUT_INVALID', 'D9.1 broker can begin only an unpermitted synthetic dry run')
      break
    case 'begin_synthetic_bootstrap_scope_audit':
      exactKeys(input, ['authenticatedLauncherBindingCode', 'claimTransition', 'operation'], 'synthetic permitted begin input')
      timestamp(input.operation?.startedAt, 'operation.startedAt')
      if (
        input.operation?.operationModeCode !== 'bootstrap'
        || input.claimTransition?.permit_kind_code !== 'bootstrap'
        || input.claimTransition?.transition_code !== 'operation_claimed'
      ) fail('STATE_BROKER_INPUT_INVALID', 'synthetic permitted begin requires one bootstrap claim')
      break
    case 'finish_synthetic_no_effect':
      exactKeys(input, ['afterLogicalStateSha256', 'authenticatedVerifierBindingCode', 'beforeLogicalStateSha256', 'operationId', 'operationNonce', 'reasonCode', 'recordedAt'], 'finish input')
      timestamp(input.recordedAt, 'recordedAt')
      break
    case 'mark_synthetic_recovery_required':
      exactKeys(input, ['authenticatedLauncherBindingCode', 'lastKnownLogicalStateSha256', 'operationId', 'operationNonce', 'reasonCode', 'recordedAt'], 'recovery input')
      timestamp(input.recordedAt, 'recordedAt')
      break
    case 'mark_synthetic_bootstrap_scope_recovery':
      exactKeys(input, ['authenticatedLauncherBindingCode', 'lastKnownLogicalStateSha256', 'operationId', 'operationNonce', 'reasonCode', 'recordedAt', 'terminalPermitTransition'], 'synthetic permitted recovery input')
      timestamp(input.recordedAt, 'recordedAt')
      if (
        input.terminalPermitTransition?.permit_kind_code !== 'bootstrap'
        || input.terminalPermitTransition?.transition_code !== 'state_ambiguous'
        || input.terminalPermitTransition?.to_state_code !== 'recovery_required'
      ) fail('STATE_BROKER_INPUT_INVALID', 'synthetic permitted recovery requires one bootstrap recovery transition')
      break
    case 'revoke_fixed_record':
      exactKeys(input, ['authenticatedBindingCode', 'authenticatedRuntimeRoleCode', 'reasonCode', 'recordCode', 'recordDigestSha256', 'registryKindCode', 'revokedAt'], 'registry revocation input')
      timestamp(input.revokedAt, 'revokedAt')
      break
    case 'revoke_generation_pair':
      exactKeys(input, ['authenticatedLauncherBindingCode', 'identityBindingsRecordDigestSha256', 'pairCode', 'pairGeneration', 'reasonCode', 'revokedAt', 'runtimeProfileRecordDigestSha256'], 'generation revocation input')
      timestamp(input.revokedAt, 'revokedAt')
      break
    default:
      fail('STATE_BROKER_INPUT_INVALID', 'operation is outside the fixed append interface')
  }
}

function requestTime(operationCode, input) {
  if (operationCode === 'register_fixed_record') return input.recordedAt
  if (operationCode === 'issue_permit') return input.persistedAt
  if (operationCode === 'append_permit_transition') return input.record.persisted_at
  if (operationCode === 'begin_synthetic_dry_run' || operationCode === 'begin_synthetic_bootstrap_scope_audit') return input.operation.startedAt
  if (operationCode === 'revoke_fixed_record' || operationCode === 'revoke_generation_pair') return input.revokedAt
  return input.recordedAt
}

function rootFromDescriptor(expectedUid) {
  const descriptor = fs.fstatSync(3, { bigint: true })
  if (!descriptor.isDirectory() || descriptor.uid !== BigInt(expectedUid) || (descriptor.mode & 0o077n) !== 0n) fail('STATE_BROKER_ROOT_SUBSTITUTED', 'inherited descriptor is not the protected root')
  const resolved = fs.realpathSync('/proc/self/fd/3')
  const observed = fs.lstatSync(resolved, { bigint: true })
  for (const field of ['dev', 'ino', 'uid', 'mode']) if (descriptor[field] !== observed[field]) fail('STATE_BROKER_ROOT_SUBSTITUTED', 'protected root changed after descriptor handoff')
  return resolved
}

function writeMessage(value) {
  process.stdout.write(`${canonicalize(value)}\n`)
}

function stateInput(operationCode, input) {
  if (operationCode === 'begin_synthetic_dry_run') return { ...input, claimTransition: null }
  if (operationCode === 'finish_synthetic_no_effect' || operationCode === 'mark_synthetic_recovery_required') return { ...input, terminalPermitTransition: null }
  return input
}

function parseLine(line) {
  const parsed = parseStrictJson(Buffer.from(line, 'utf8'), { contractNumbers: true, maximumBytes: 65_536, maximumDepth: 32, maximumMembers: 4_096 })
  if (canonicalize(parsed) !== line) fail('STATE_BROKER_PROTOCOL_INVALID', 'broker frame is not canonical UTF-8 JSON')
  return parsed
}

async function workerMain() {
  let configuration
  try {
    configuration = parseStrictJson(fs.readFileSync(4), { contractNumbers: true, maximumBytes: 262_144, maximumDepth: 32, maximumMembers: 4_096 })
    exactKeys(configuration, ['broker_binding_code', 'broker_gid', 'broker_uid', 'identity_bindings_record_digest_sha256', 'node_executable_sha256', 'runtime_profile_record_digest_sha256', 'source_hashes', 'synthetic_crash_after_operation_code', 'synthetic_crash_before_operation_code', 'trusted_genesis_identity_bindings_record'], 'worker configuration')
    if (configuration.synthetic_crash_after_operation_code !== null && !Object.hasOwn(OPERATION_METHODS, configuration.synthetic_crash_after_operation_code)) fail('STATE_BROKER_CONFIGURATION_INVALID', 'synthetic crash operation is invalid')
    if (configuration.synthetic_crash_before_operation_code !== null && !Object.hasOwn(OPERATION_METHODS, configuration.synthetic_crash_before_operation_code)) fail('STATE_BROKER_CONFIGURATION_INVALID', 'synthetic pre-append crash operation is invalid')
    const expectedUid = brokerUid(configuration.broker_uid)
    if (configuration.broker_gid !== expectedUid || process.getuid?.() !== expectedUid || process.getgid?.() !== expectedUid || canonicalize(process.getgroups?.() ?? []) !== canonicalize([expectedUid])) {
      fail('STATE_BROKER_IDENTITY_MISMATCH', 'worker UID, GID, or supplementary groups differ from the dedicated trusted_launcher identity')
    }
    assertRuntime(modulePath, configuration.source_hashes, configuration.node_executable_sha256)
    const store = openProtectedStateStore({ rootPath: rootFromDescriptor(expectedUid), expectedUid, trustedIdentityBindingsRecord: configuration.trusted_genesis_identity_bindings_record })
    writeMessage({
      broker_binding_code: configuration.broker_binding_code,
      broker_pid: process.pid,
      broker_uid: process.getuid(),
      identity_bindings_record_digest_sha256: configuration.identity_bindings_record_digest_sha256,
      node_executable_sha256: configuration.node_executable_sha256,
      runtime_profile_record_digest_sha256: configuration.runtime_profile_record_digest_sha256,
      source_hashes: configuration.source_hashes,
      status: 'ready',
    })
    let buffered = ''
    let lastRequestId = 0
    const nonces = new Set()
    process.stdin.setEncoding('utf8')
    for await (const chunk of process.stdin) {
      buffered += chunk
      if (Buffer.byteLength(buffered, 'utf8') > 65_536) fail('STATE_BROKER_PROTOCOL_INVALID', 'request frame exceeds the frozen IPC limit')
      for (;;) {
        const newline = buffered.indexOf('\n')
        if (newline === -1) break
        const line = buffered.slice(0, newline)
        buffered = buffered.slice(newline + 1)
        let requestId = null
        try {
          const request = parseLine(line)
          exactKeys(request, ['input', 'operation_code', 'request_digest_sha256', 'request_id', 'request_nonce'], 'append request')
          requestId = request.request_id
          if (!Number.isSafeInteger(requestId) || requestId !== lastRequestId + 1) fail('STATE_BROKER_REPLAY', 'request IDs must form one increasing sequence')
          hash(request.request_nonce, 'request nonce')
          if (nonces.has(request.request_nonce)) fail('STATE_BROKER_REPLAY', 'request nonce was reused')
          assertInput(request.operation_code, request.input)
          const digestPayload = { input: request.input, operation_code: request.operation_code, request_id: requestId, request_nonce: request.request_nonce }
          if (sha256Bytes(Buffer.from(canonicalize(digestPayload), 'utf8')) !== request.request_digest_sha256) fail('STATE_BROKER_REQUEST_SUBSTITUTED', 'request digest is invalid')
          nonces.add(request.request_nonce)
          lastRequestId = requestId
          assertRuntime(modulePath, configuration.source_hashes, configuration.node_executable_sha256)
          const pair = store.selectActiveGenerationPair({
            asOf: requestTime(request.operation_code, request.input),
            runtimeProfileRecordDigestSha256: configuration.runtime_profile_record_digest_sha256,
            identityBindingsRecordDigestSha256: configuration.identity_bindings_record_digest_sha256,
          })
          const activeLauncher = pair.trusted_role_bindings.find((binding) => binding.runtime_role_code === 'trusted_launcher')
          if (activeLauncher?.binding_code !== configuration.broker_binding_code) fail('STATE_BROKER_GENERATION_REVOKED', 'broker binding is no longer the active trusted_launcher identity')
          const method = OPERATION_METHODS[request.operation_code]
          if (configuration.synthetic_crash_before_operation_code === request.operation_code) process.kill(process.pid, 'SIGKILL')
          const result = store[method](stateInput(request.operation_code, request.input))
          if (configuration.synthetic_crash_after_operation_code === request.operation_code) process.kill(process.pid, 'SIGKILL')
          writeMessage({ request_digest_sha256: request.request_digest_sha256, request_id: requestId, result, status: 'persisted' })
        } catch (error) {
          const code = typeof error?.code === 'string' ? error.code : 'STATE_BROKER_WORKER_FAILED'
          writeMessage({ code, message: String(error?.message ?? error), request_id: requestId, status: 'rejected' })
          if (TERMINAL_WORKER_CODES.has(code)) return
        }
      }
    }
    if (buffered.length !== 0) fail('STATE_BROKER_PROTOCOL_INVALID', 'worker input ended with an incomplete frame')
  } catch (error) {
    writeMessage({ code: typeof error?.code === 'string' ? error.code : 'STATE_BROKER_WORKER_FAILED', message: String(error?.message ?? error), status: 'startup_rejected' })
    process.exitCode = 1
  }
}

function createLineChannel(child, maximumBytes = 65_536) {
  let buffered = ''
  const queue = []
  const waiters = []
  let terminalError = null
  let stderr = ''
  const deliver = (value) => {
    const waiter = waiters.shift()
    if (waiter) waiter.resolve(value)
    else queue.push(value)
  }
  child.stdout.setEncoding('utf8')
  child.stdout.on('error', (error) => {
    terminalError = new D9StateAppendBrokerError('STATE_BROKER_PROTOCOL_INVALID', 'broker output pipe failed', { cause: error.code ?? error.message })
    while (waiters.length) waiters.shift().reject(terminalError)
  })
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', (chunk) => { if (stderr.length < 65_536) stderr += chunk })
  child.stdout.on('data', (chunk) => {
    buffered += chunk
    if (Buffer.byteLength(buffered, 'utf8') > maximumBytes) {
      child.kill('SIGKILL')
      terminalError = new D9StateAppendBrokerError('STATE_BROKER_PROTOCOL_INVALID', 'broker response frame exceeded the fixed limit')
      while (waiters.length) waiters.shift().reject(terminalError)
      return
    }
    for (;;) {
      const newline = buffered.indexOf('\n')
      if (newline === -1) break
      const line = buffered.slice(0, newline)
      buffered = buffered.slice(newline + 1)
      try { deliver(parseLine(line)) } catch (error) { terminalError = error; child.kill('SIGKILL'); while (waiters.length) waiters.shift().reject(error) }
    }
  })
  child.once('exit', (code, signal) => {
    terminalError ??= new D9StateAppendBrokerError('STATE_BROKER_TERMINATED', 'state broker terminated', { code, signal, stderr })
    while (waiters.length) waiters.shift().reject(terminalError)
  })
  return {
    next() {
      if (queue.length) return Promise.resolve(queue.shift())
      if (terminalError) return Promise.reject(terminalError)
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }))
    },
  }
}

async function withTimeout(promise, timeoutMs) {
  let timer
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new D9StateAppendBrokerError('STATE_BROKER_TIMEOUT', 'broker request exceeded its fixed deadline')), timeoutMs)
      timer.unref?.()
    })])
  } finally {
    clearTimeout(timer)
  }
}

function sameInspection(left, right) {
  return canonicalize(left) === canonicalize(right)
}

function expectedTerminalEvent(operationCode, input) {
  if (operationCode === 'finish_synthetic_no_effect') {
    return {
      event_kind_code: 'operation_no_effect_verified',
      operation_id: input.operationId,
      operation_nonce: input.operationNonce,
      before_logical_state_sha256: input.beforeLogicalStateSha256,
      after_logical_state_sha256: input.afterLogicalStateSha256,
      recorded_at: input.recordedAt,
      recorded_by_runtime_role_code: 'independent_verifier',
      recorded_by_binding_code: input.authenticatedVerifierBindingCode,
      reason_code: input.reasonCode,
    }
  }
  if (operationCode === 'mark_synthetic_recovery_required' || operationCode === 'mark_synthetic_bootstrap_scope_recovery') {
    return {
      event_kind_code: 'operation_recovery_required',
      operation_id: input.operationId,
      operation_nonce: input.operationNonce,
      last_known_logical_state_sha256: input.lastKnownLogicalStateSha256,
      recorded_at: input.recordedAt,
      recorded_by_runtime_role_code: 'trusted_launcher',
      recorded_by_binding_code: input.authenticatedLauncherBindingCode,
      reason_code: input.reasonCode,
    }
  }
  return null
}

function reconcileAfterResponseLoss({ brokerUid: uid, input, operationCode, prior, rootPath, trustedIdentityBindingsRecord }) {
  let store
  let after
  try {
    store = openProtectedStateStore({ rootPath, expectedUid: uid, trustedIdentityBindingsRecord })
    after = store.inspect()
  } catch (error) {
    return { status: 'ambiguous', reason: 'protected state could not be reopened', errorCode: error?.code }
  }
  if (after.sequence === prior.sequence && after.headCommitSha256 === prior.headCommitSha256 && sameInspection(after, prior)) {
    if (operationCode === 'finish_synthetic_no_effect' || operationCode === 'mark_synthetic_recovery_required' || operationCode === 'mark_synthetic_bootstrap_scope_recovery') {
      return { status: 'ambiguous', reason: 'operation lease owner died before a terminal commit' }
    }
    return { status: 'absent', sequence: after.sequence, headCommitSha256: after.headCommitSha256 }
  }
  if (after.sequence !== prior.sequence + 1) return { status: 'ambiguous', reason: 'state advanced unexpectedly', inspection: after }
  try {
    if (operationCode === 'register_fixed_record') {
      const record = store.resolveFixedRecord({ registryKindCode: input.record.record_kind_code, recordCode: input.record.record_code, recordDigestSha256: input.record.record_digest_sha256, asOf: input.recordedAt })
      if (canonicalize(record) !== canonicalize(input.record)) return { status: 'ambiguous', reason: 'registry projection differs from request' }
    } else if (operationCode === 'issue_permit') {
      const permit = store.resolvePermit({ permitCode: input.record.permit_code, recordDigestSha256: input.record.record_digest_sha256, asOf: input.persistedAt, requiredStateCode: 'ready' })
      if (canonicalize(permit.record) !== canonicalize(input.record)) return { status: 'ambiguous', reason: 'permit projection differs from request' }
    } else if (operationCode === 'append_permit_transition') {
      const permit = store.projectPermit({ permitCode: input.record.permit_code, asOf: input.record.persisted_at })
      if (permit.currentTransition?.record_digest_sha256 !== input.record.record_digest_sha256) return { status: 'ambiguous', reason: 'transition projection differs from request' }
    } else if (operationCode === 'revoke_fixed_record') {
      const expected = {
        event_kind_code: 'registry_record_revoked',
        registry_kind_code: input.registryKindCode,
        record_code: input.recordCode,
        record_digest_sha256: input.recordDigestSha256,
        revoked_at: input.revokedAt,
        reason_code: input.reasonCode,
        revoked_by_runtime_role_code: input.authenticatedRuntimeRoleCode,
        revoked_by_binding_code: input.authenticatedBindingCode,
      }
      const observed = store.projectFixedRecordRevocation({ registryKindCode: input.registryKindCode, recordCode: input.recordCode })
      if (canonicalize(observed) !== canonicalize(expected)) return { status: 'ambiguous', reason: 'registry revocation projection differs from request' }
    } else if (operationCode === 'revoke_generation_pair') {
      const expected = {
        event_kind_code: 'generation_pair_revoked',
        pair_code: input.pairCode,
        pair_generation: input.pairGeneration,
        runtime_profile_record_digest_sha256: input.runtimeProfileRecordDigestSha256,
        identity_bindings_record_digest_sha256: input.identityBindingsRecordDigestSha256,
        revoked_at: input.revokedAt,
        reason_code: input.reasonCode,
        revoked_by_binding_code: input.authenticatedLauncherBindingCode,
      }
      const observed = store.projectGenerationPairRevocation({ pairCode: input.pairCode })
      if (canonicalize(observed) !== canonicalize(expected)) return { status: 'ambiguous', reason: 'generation revocation projection differs from request' }
    } else if (operationCode === 'begin_synthetic_dry_run' || operationCode === 'begin_synthetic_bootstrap_scope_audit') {
      return { status: 'ambiguous', reason: 'durable begin lost its process-held lease and requires recovery', inspection: after }
    } else if (operationCode === 'finish_synthetic_no_effect' || operationCode === 'mark_synthetic_recovery_required' || operationCode === 'mark_synthetic_bootstrap_scope_recovery') {
      const operation = store.projectOperation({ operationId: input.operationId, operationNonce: input.operationNonce })
      const expected = expectedTerminalEvent(operationCode, input)
      const expectedStateCode = operationCode === 'finish_synthetic_no_effect' ? 'no_effect_verified' : 'recovery_required'
      const expectedRecoveryRequired = operationCode !== 'finish_synthetic_no_effect'
      const terminalPermitMatches = input.terminalPermitTransition === undefined || canonicalize(
        store.projectPermit({ permitCode: input.terminalPermitTransition.permit_code, asOf: input.recordedAt }).currentTransition,
      ) === canonicalize(input.terminalPermitTransition)
      if (
        operation.state_code !== expectedStateCode
        || canonicalize(operation.terminal_event) !== canonicalize(expected)
        || !terminalPermitMatches
        || after.activeOperation !== null
        || after.recoveryRequired !== expectedRecoveryRequired
      ) return { status: 'ambiguous', reason: 'terminal operation projection differs from the exact request', inspection: after }
    }
  } catch (error) {
    return { status: 'ambiguous', reason: 'exact requested effect could not be projected', errorCode: error?.code }
  }
  return { status: 'persisted', sequence: after.sequence, headCommitSha256: after.headCommitSha256 }
}

class ProtectedStateAppendBroker {
  #attestation
  #brokerUid
  #channel
  #child
  #closed = false
  #nextRequestId = 1
  #nonceSource
  #pending = Promise.resolve()
  #poisonedError = null
  #rootPath
  #timeoutMs
  #trustedGenesisIdentityBindingsRecord
  #usedNonces = new Set()

  constructor({ attestation, brokerUid: uid, child, channel, nonceSource, rootPath, timeoutMs, trustedGenesisIdentityBindingsRecord }) {
    this.#attestation = Object.freeze(structuredClone(attestation))
    this.#brokerUid = uid
    this.#child = child
    this.#channel = channel
    this.#nonceSource = nonceSource
    this.#rootPath = rootPath
    this.#timeoutMs = timeoutMs
    this.#trustedGenesisIdentityBindingsRecord = structuredClone(trustedGenesisIdentityBindingsRecord)
  }

  attestation() { return this.#attestation }

  #dispatch(operationCode, input) {
    const perform = async () => {
      if (this.#closed || this.#poisonedError) throw this.#poisonedError ?? new D9StateAppendBrokerError('STATE_BROKER_TERMINATED', 'state broker is closed')
      const cloned = structuredClone(input)
      assertInput(operationCode, cloned)
      const prior = openProtectedStateStore({ rootPath: this.#rootPath, expectedUid: this.#brokerUid, trustedIdentityBindingsRecord: this.#trustedGenesisIdentityBindingsRecord }).inspect()
      const requestNonce = hash(this.#nonceSource(), 'request nonce')
      if (this.#usedNonces.has(requestNonce)) fail('STATE_BROKER_REPLAY', 'request nonce was reused before dispatch')
      const requestId = this.#nextRequestId
      const digestPayload = { input: cloned, operation_code: operationCode, request_id: requestId, request_nonce: requestNonce }
      const requestDigestSha256 = sha256Bytes(Buffer.from(canonicalize(digestPayload), 'utf8'))
      const wire = `${canonicalize({ ...digestPayload, request_digest_sha256: requestDigestSha256 })}\n`
      this.#usedNonces.add(requestNonce)
      this.#nextRequestId += 1
      try {
        await new Promise((resolve, reject) => this.#child.stdin.write(wire, (error) => error ? reject(error) : resolve()))
      } catch (error) {
        return this.#handleResponseLoss({ cause: error, input: cloned, operationCode, prior })
      }
      let response
      try {
        response = await withTimeout(this.#channel.next(), this.#timeoutMs)
      } catch (error) {
        return this.#handleResponseLoss({ cause: error, input: cloned, operationCode, prior })
      }
      if (response.status !== 'persisted') {
        const rejected = new D9StateAppendBrokerError('STATE_BROKER_APPEND_REJECTED', 'fixed-function append was rejected', { workerCode: response.code, workerMessage: response.message })
        if (TERMINAL_WORKER_CODES.has(response.code)) {
          this.#closed = true
          this.#poisonedError = rejected
          this.#child.kill('SIGKILL')
        }
        throw rejected
      }
      try {
        exactKeys(response, ['request_digest_sha256', 'request_id', 'result', 'status'], 'broker result')
        if (response.request_id !== requestId || response.request_digest_sha256 !== requestDigestSha256) fail('STATE_BROKER_RESPONSE_SUBSTITUTED', 'broker result does not bind the exact request')
        return Object.freeze({ ...response.result, brokerGid: this.#brokerUid, brokerPid: this.#child.pid, brokerUid: this.#brokerUid, requestDigestSha256 })
      } catch (error) {
        return this.#handleResponseLoss({ cause: error, input: cloned, operationCode, prior })
      }
    }
    const result = this.#pending.then(perform, perform)
    this.#pending = result.catch(() => {})
    return result
  }

  async #handleResponseLoss({ cause, input, operationCode, prior }) {
    this.#closed = true
    const exit = this.#child.exitCode === null && this.#child.signalCode === null
      ? new Promise((resolve) => this.#child.once('exit', resolve))
      : null
    this.#child.kill('SIGKILL')
    if (exit) await exit
    const reconciliation = reconcileAfterResponseLoss({ brokerUid: this.#brokerUid, input, operationCode, prior, rootPath: this.#rootPath, trustedIdentityBindingsRecord: this.#trustedGenesisIdentityBindingsRecord })
    if (reconciliation.status === 'persisted') return Object.freeze({ brokerGid: this.#brokerUid, brokerPid: this.#child.pid, brokerUid: this.#brokerUid, persistenceStatus: 'persisted_after_response_loss', reconciliation })
    if (reconciliation.status === 'absent') {
      this.#poisonedError = new D9StateAppendBrokerError('STATE_BROKER_APPEND_NOT_PERSISTED', 'state append was not persisted before broker failure', { cause: cause?.code ?? cause?.message, reconciliation })
      throw this.#poisonedError
    }
    this.#poisonedError = new D9StateAppendBrokerError('STATE_BROKER_RECOVERY_REQUIRED', 'state append outcome is ambiguous after broker failure', { cause: cause?.code ?? cause?.message, reconciliation })
    throw this.#poisonedError
  }

  registerFixedRecord(input) { return this.#dispatch('register_fixed_record', input) }
  issuePermit(input) { return this.#dispatch('issue_permit', input) }
  appendPermitTransition(input) { return this.#dispatch('append_permit_transition', input) }
  beginSyntheticBootstrapScopeAudit(input) { return this.#dispatch('begin_synthetic_bootstrap_scope_audit', input) }
  beginSyntheticDryRun(input) { return this.#dispatch('begin_synthetic_dry_run', input) }
  finishSyntheticNoEffect(input) { return this.#dispatch('finish_synthetic_no_effect', input) }
  markSyntheticRecoveryRequired(input) { return this.#dispatch('mark_synthetic_recovery_required', input) }
  markSyntheticBootstrapScopeRecovery(input) { return this.#dispatch('mark_synthetic_bootstrap_scope_recovery', input) }
  revokeFixedRecord(input) { return this.#dispatch('revoke_fixed_record', input) }
  async revokeGenerationPair(input) {
    const result = await this.#dispatch('revoke_generation_pair', input)
    await this.close()
    return result
  }

  async close() {
    if (this.#closed) return
    this.#closed = true
    const exit = this.#child.exitCode === null && this.#child.signalCode === null
      ? new Promise((resolve) => this.#child.once('exit', resolve))
      : null
    this.#child.stdin.end()
    if (exit) await withTimeout(exit, this.#timeoutMs)
  }
}

async function startProtectedStateAppendBroker({
  nonceSource = () => randomBytes(32).toString('hex'),
  rootPath,
  timeoutMs = 5_000,
  trustedGenesisIdentityBindingsRecord,
  verifiedControlPlaneBuild,
  verifiedGeneration,
  workerModulePath,
} = {}, { afterOperationCode = null, beforeOperationCode = null } = {}) {
  const [{ assertVerifiedControlPlaneBuild }, { assertVerifiedRuntimeGeneration }] = await Promise.all([
    import('./build-integrity.mjs'),
    import('./contracts.mjs'),
  ])
  const generation = assertVerifiedRuntimeGeneration(verifiedGeneration)
  const build = assertVerifiedControlPlaneBuild(verifiedControlPlaneBuild)
  if (build.runtimeProfileRecordDigestSha256 !== generation.runtimeProfile.record_digest_sha256 || build.identityBindingsRecordDigestSha256 !== generation.identityBindings.record_digest_sha256) {
    fail('STATE_BROKER_BUILD_MISMATCH', 'verified control-plane build belongs to a different runtime generation')
  }
  const launcherBindings = generation.identityBindings.bindings.filter((binding) => binding.runtime_role_code === 'trusted_launcher' && binding.principal_kind_code === 'service')
  if (launcherBindings.length !== 1) fail('STATE_BROKER_CONFIGURATION_INVALID', 'verified generation lacks one dedicated trusted_launcher binding')
  const uid = brokerUid(launcherBindings[0].unix_uid)
  const nodeExecutableSha256 = build.nodeExecutableSha256
  const launcherRelease = generation.runtimeProfile.component_releases.find((release) => release.runtime_role_code === 'trusted_launcher')
  if (launcherBindings[0].executable_sha256 !== nodeExecutableSha256 || launcherRelease?.executable_sha256 !== nodeExecutableSha256) {
    fail('STATE_BROKER_BUILD_MISMATCH', 'trusted_launcher binding and component release must pin the verified Node executable')
  }
  const sourceHashes = {
    canonical: build.sourceFiles['d9/control-plane/canonical.mjs'],
    state_append_broker: build.sourceFiles['d9/control-plane/state-append-broker.mjs'],
    state_store: build.sourceFiles['d9/control-plane/state-store.mjs'],
  }
  const root = assertProtectedRoot(rootPath, uid)
  // Genesis authentication is deliberately independent of the currently
  // selected operational binding generation. A broker restart after rotation
  // must replay sequence one against the original protected trust anchor.
  openProtectedStateStore({
    rootPath: root,
    expectedUid: uid,
    trustedIdentityBindingsRecord: trustedGenesisIdentityBindingsRecord,
  })
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000 || typeof nonceSource !== 'function') fail('STATE_BROKER_CONFIGURATION_INVALID', 'broker timeout or nonce source is invalid')
  if (afterOperationCode !== null && !Object.hasOwn(OPERATION_METHODS, afterOperationCode)) fail('STATE_BROKER_CONFIGURATION_INVALID', 'synthetic crash operation is invalid')
  if (beforeOperationCode !== null && !Object.hasOwn(OPERATION_METHODS, beforeOperationCode)) fail('STATE_BROKER_CONFIGURATION_INVALID', 'synthetic pre-append crash operation is invalid')
  const moduleFile = assertRuntime(workerModulePath, sourceHashes, nodeExecutableSha256)
  const rootFd = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW)
  const nodeFd = fs.openSync('/proc/self/exe', fs.constants.O_RDONLY | fs.constants.O_CLOEXEC)
  const configuration = canonicalize({
    broker_binding_code: launcherBindings[0].binding_code,
    broker_gid: uid,
    broker_uid: uid,
    identity_bindings_record_digest_sha256: generation.identityBindings.record_digest_sha256,
    node_executable_sha256: nodeExecutableSha256,
    runtime_profile_record_digest_sha256: generation.runtimeProfile.record_digest_sha256,
    source_hashes: sourceHashes,
    synthetic_crash_after_operation_code: afterOperationCode,
    synthetic_crash_before_operation_code: beforeOperationCode,
    trusted_genesis_identity_bindings_record: trustedGenesisIdentityBindingsRecord,
  })
  let child
  try {
    child = spawn('/proc/self/fd/5', ['--disable-warning=ExperimentalWarning', moduleFile, '--state-append-worker'], {
      env: Object.freeze({ LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin', TZ: 'UTC' }),
      gid: uid,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe', rootFd, 'pipe', nodeFd],
      uid,
    })
  } finally {
    fs.closeSync(rootFd)
    fs.closeSync(nodeFd)
  }
  child.stdin.on('error', () => {})
  child.stdio[4].on('error', () => {})
  const channel = createLineChannel(child)
  child.stdio[4].end(Buffer.from(configuration, 'utf8'))
  let ready
  try {
    ready = await withTimeout(channel.next(), timeoutMs)
    if (ready.status !== 'ready') fail('STATE_BROKER_STARTUP_REJECTED', 'state broker failed closed during startup', { workerCode: ready.code, workerMessage: ready.message })
    exactKeys(ready, ['broker_binding_code', 'broker_pid', 'broker_uid', 'identity_bindings_record_digest_sha256', 'node_executable_sha256', 'runtime_profile_record_digest_sha256', 'source_hashes', 'status'], 'broker ready message')
    if (ready.broker_pid !== child.pid || ready.broker_uid !== uid || ready.broker_binding_code !== launcherBindings[0].binding_code || ready.node_executable_sha256 !== nodeExecutableSha256 || ready.runtime_profile_record_digest_sha256 !== generation.runtimeProfile.record_digest_sha256 || ready.identity_bindings_record_digest_sha256 !== generation.identityBindings.record_digest_sha256 || canonicalize(ready.source_hashes) !== canonicalize(sourceHashes)) {
      fail('STATE_BROKER_IDENTITY_MISMATCH', 'broker ready message does not bind the spawned UID/build')
    }
  } catch (error) {
    const exit = child.exitCode === null && child.signalCode === null
      ? new Promise((resolve) => child.once('exit', resolve))
      : null
    child.kill('SIGKILL')
    if (exit) await exit
    throw error
  }
  const broker = new ProtectedStateAppendBroker({
    attestation: {
      brokerBindingCode: launcherBindings[0].binding_code,
      brokerGid: uid,
      brokerPid: child.pid,
      brokerUid: uid,
      identityBindingsRecordDigestSha256: generation.identityBindings.record_digest_sha256,
      nodeExecutableSha256,
      runtimeProfileRecordDigestSha256: generation.runtimeProfile.record_digest_sha256,
      syntheticPrivatePipeHarness: true,
    },
    brokerUid: uid,
    child,
    channel,
    nonceSource,
    rootPath: root,
    timeoutMs,
    trustedGenesisIdentityBindingsRecord,
  })
  brokerInstances.add(broker)
  return broker
}

export function createProtectedStateAppendBroker(options) {
  return startProtectedStateAppendBroker(options)
}

// Test-only fault injector; it does not weaken production broker construction.
export function createSyntheticCrashStateAppendBroker(options, operationCode, phase = 'after_commit_before_response') {
  if (phase === 'after_commit_before_response') return startProtectedStateAppendBroker(options, { afterOperationCode: operationCode })
  if (phase === 'before_append') return startProtectedStateAppendBroker(options, { beforeOperationCode: operationCode })
  fail('STATE_BROKER_CONFIGURATION_INVALID', 'synthetic crash phase is invalid')
}

export function assertProtectedStateAppendBroker(value) {
  if (!brokerInstances.has(value)) fail('STATE_BROKER_CONFIGURATION_INVALID', 'broker was not created by the protected factory')
  return value
}

if (process.argv[1] && path.resolve(process.argv[1]) === modulePath && process.argv[2] === '--state-append-worker') await workerMain()
