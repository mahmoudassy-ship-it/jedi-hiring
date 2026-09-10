import { createHash, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { closeSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs'
import { access, chmod, mkdtemp, readFile, rm } from 'node:fs/promises'
import { constants as fsConstants } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn, spawnSync } from 'node:child_process'

export const D9_MAX_PACKET_BYTES = 65_536
export const D9_MAX_ANCILLARY_FDS = 8
export const SYNTHETIC_DESCRIPTOR_BYTES = 'synthetic-d9-handle\n'

const REQUIRED_FEATURES = Object.freeze([
  'linux',
  'seqpacket',
  'peer_credentials',
  'peer_pidfd',
  'scm_rights',
  'msg_cmsg_cloexec',
  'openat2',
  'flock',
])
const SYNTHETIC_SCENARIOS = new Set([
  'normal',
  'replay',
  'oversize',
  'too_many_fds',
  'spoof_uid',
  'spoof_gid',
  'spoof_pid',
  'build_substitution',
  'malformed_packet',
  'noncanonical_packet',
  'wrong_nonce',
  'wrong_request_digest',
  'wrong_descriptor_metadata',
  'ignore_sigterm',
  'fork_escape',
  'fd_transfer_escape',
])
const nativeSource = fileURLToPath(new URL('./native/d9_linux.c', import.meta.url))
const fixedEnvironment = Object.freeze({ LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' })
const constructionToken = Symbol('LinuxEnforcement construction')
const verifiedLinuxEnforcements = new WeakSet()

export class D9PlatformError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`)
    this.name = 'D9PlatformError'
    this.code = code
    this.details = details
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function fsOpenNoFollow(filePath) {
  return openSync(
    filePath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_CLOEXEC ?? 0),
  )
}

function fstatBigInt(descriptor) {
  return fstatSync(descriptor, { bigint: true })
}

function closeDescriptor(descriptor) {
  try {
    closeSync(descriptor)
  } catch {
    // Closing an already-closed temporary descriptor is harmless during cleanup.
  }
}

function parseJsonLine(line, label) {
  try {
    const parsed = JSON.parse(line)
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('not an object')
    return parsed
  } catch (error) {
    throw new D9PlatformError('NATIVE_PROTOCOL_INVALID', `${label} emitted invalid JSON`, {
      cause: error.message,
      line,
    })
  }
}

function parseLastJsonLine(output, label) {
  const lines = output.trim().split('\n').filter(Boolean)
  if (lines.length === 0) {
    throw new D9PlatformError('NATIVE_PROTOCOL_INVALID', `${label} emitted no result`)
  }
  return parseJsonLine(lines.at(-1), label)
}

function assertClosedString(value, label, pattern, maximum = 240) {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value) > maximum || !pattern.test(value)) {
    throw new D9PlatformError('PLATFORM_INPUT_INVALID', `${label} is outside its closed shape`)
  }
}

function assertAbsolutePath(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    throw new D9PlatformError('PLATFORM_INPUT_INVALID', `${label} must be an absolute NUL-free path`)
  }
}

function assertRelativeLeaf(value, label) {
  assertClosedString(value, label, /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u, 120)
  if (value === '.' || value === '..') throw new D9PlatformError('PLATFORM_INPUT_INVALID', `${label} is not a safe leaf`)
}

function createEventReader(child, label) {
  let buffered = ''
  const events = []
  const waiters = []
  let stderr = ''
  let ended = false

  const dispatch = (event) => {
    const waiterIndex = waiters.findIndex(({ predicate }) => predicate(event))
    if (waiterIndex === -1) events.push(event)
    else {
      const [{ resolve, timer }] = waiters.splice(waiterIndex, 1)
      clearTimeout(timer)
      resolve(event)
    }
  }

  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', (chunk) => {
    buffered += chunk
    for (;;) {
      const newline = buffered.indexOf('\n')
      if (newline === -1) break
      const line = buffered.slice(0, newline)
      buffered = buffered.slice(newline + 1)
      if (line.length > 0) dispatch(parseJsonLine(line, label))
    }
  })
  child.stderr.on('data', (chunk) => { stderr += chunk })
  child.on('close', () => {
    ended = true
    if (buffered.length > 0) {
      dispatch(parseJsonLine(buffered, label))
      buffered = ''
    }
    for (const { reject, timer } of waiters.splice(0)) {
      clearTimeout(timer)
      reject(new D9PlatformError('NATIVE_PROCESS_EXITED', `${label} exited before the expected event`, { stderr }))
    }
  })

  return {
    async next(predicate, timeoutMs = 5_000) {
      const index = events.findIndex(predicate)
      if (index !== -1) return events.splice(index, 1)[0]
      if (ended) throw new D9PlatformError('NATIVE_PROCESS_EXITED', `${label} already exited`, { stderr })
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const waiterIndex = waiters.findIndex((waiter) => waiter.timer === timer)
          if (waiterIndex !== -1) waiters.splice(waiterIndex, 1)
          reject(new D9PlatformError('NATIVE_PROCESS_TIMEOUT', `${label} timed out`, { stderr }))
        }, timeoutMs)
        timer.unref()
        waiters.push({ predicate, reject, resolve, timer })
      })
    },
    stderr: () => stderr,
  }
}

async function waitForExit(child, timeoutMs = 7_000) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode }
  }
  let timer
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new D9PlatformError('NATIVE_PROCESS_TIMEOUT', 'native helper did not exit')), timeoutMs)
    timer.unref()
  })
  try {
    const [code, signal] = await Promise.race([once(child, 'exit'), timeout])
    return { code, signal }
  } finally {
    clearTimeout(timer)
  }
}

async function stopChildAndConfirm(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return
  child.kill('SIGKILL')
  await waitForExit(child)
}

export async function compileLinuxEnforcement() {
  if (process.platform !== 'linux') {
    throw new D9PlatformError('D9_PLATFORM_UNAVAILABLE', 'the D9.1 platform boundary requires Linux')
  }
  const compiler = '/usr/bin/cc'
  try {
    await access(compiler, fsConstants.X_OK)
    await access(nativeSource, fsConstants.R_OK)
  } catch (error) {
    throw new D9PlatformError('D9_PLATFORM_UNAVAILABLE', 'the pinned native helper cannot be compiled', { cause: error.message })
  }

  const buildDirectory = await mkdtemp(path.join(tmpdir(), 'jedi-d9-linux-'))
  await chmod(buildDirectory, 0o755)
  const executablePath = path.join(buildDirectory, 'd9-linux')
  const substituteExecutablePath = path.join(buildDirectory, 'd9-linux-substitute')
  const sourceBytes = await readFile(nativeSource)
  const compile = spawnSync(compiler, [
    '-std=c11',
    '-O2',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-pedantic',
    nativeSource,
    '-o',
    executablePath,
  ], {
    encoding: 'utf8',
    env: fixedEnvironment,
    shell: false,
  })
  if (compile.error || compile.status !== 0) {
    await rm(buildDirectory, { force: true, recursive: true })
    throw new D9PlatformError('NATIVE_BUILD_FAILED', 'the D9 Linux helper failed to compile', {
      cause: compile.error?.message ?? null,
      stderr: compile.stderr,
      status: compile.status,
    })
  }
  const substituteCompile = spawnSync(compiler, [
    '-std=c11',
    '-O2',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-pedantic',
    '-DD9_SYNTHETIC_BUILD_VARIANT=1',
    nativeSource,
    '-o',
    substituteExecutablePath,
  ], {
    encoding: 'utf8',
    env: fixedEnvironment,
    shell: false,
  })
  if (substituteCompile.error || substituteCompile.status !== 0) {
    await rm(buildDirectory, { force: true, recursive: true })
    throw new D9PlatformError('NATIVE_BUILD_FAILED', 'the synthetic substituted peer failed to compile', {
      cause: substituteCompile.error?.message ?? null,
      stderr: substituteCompile.stderr,
      status: substituteCompile.status,
    })
  }
  const executableBytes = await readFile(executablePath)
  const substituteExecutableBytes = await readFile(substituteExecutablePath)
  return new LinuxEnforcement({
    buildDirectory,
    executablePath,
    executableSha256: sha256(executableBytes),
    sourceSha256: sha256(sourceBytes),
    substituteExecutablePath,
    substituteExecutableSha256: sha256(substituteExecutableBytes),
  }, constructionToken)
}

export class LinuxEnforcement {
  #buildDirectory
  #disposed = false
  #executablePath
  #substituteExecutablePath
  #executableSha256
  #substituteExecutableSha256

  constructor({ buildDirectory, executablePath, executableSha256, sourceSha256, substituteExecutablePath, substituteExecutableSha256 }, token) {
    if (token !== constructionToken) {
      throw new D9PlatformError('PLATFORM_INPUT_INVALID', 'Linux enforcement must be created by the verified compiler path')
    }
    this.#buildDirectory = buildDirectory
    this.#executablePath = executablePath
    this.#substituteExecutablePath = substituteExecutablePath
    this.#executableSha256 = executableSha256
    this.#substituteExecutableSha256 = substituteExecutableSha256
    Object.defineProperties(this, {
      executableSha256: { enumerable: true, value: executableSha256 },
      sourceSha256: { enumerable: true, value: sourceSha256 },
      substituteExecutableSha256: { enumerable: true, value: substituteExecutableSha256 },
      syntheticExecutablePath: { enumerable: true, value: executablePath },
    })
    verifiedLinuxEnforcements.add(this)
  }

  #assertLive() {
    if (this.#disposed) throw new D9PlatformError('PLATFORM_DISPOSED', 'the native enforcement helper was disposed')
  }

  #openVerifiedExecutable(executablePath, expectedSha256, label) {
    let descriptor
    try {
      const before = lstatSync(executablePath, { bigint: true })
      if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o022n) !== 0n) {
        throw new Error('executable is not a protected regular file')
      }
      descriptor = fsOpenNoFollow(executablePath)
      const openedBefore = fstatBigInt(descriptor)
      const bytes = readFileSync(descriptor)
      const openedAfter = fstatBigInt(descriptor)
      const after = lstatSync(executablePath, { bigint: true })
      for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
        if (before[field] !== openedBefore[field] || openedBefore[field] !== openedAfter[field] || openedAfter[field] !== after[field]) {
          throw new Error('executable identity changed while it was opened')
        }
      }
      if (sha256(bytes) !== expectedSha256) throw new Error('executable bytes differ from pinned digest')
      return descriptor
    } catch (error) {
      if (descriptor !== undefined) closeDescriptor(descriptor)
      throw new D9PlatformError('EXECUTABLE_BUILD_MISMATCH', `${label} is unavailable or unprotected`, { cause: error.message })
    }
  }

  #assertExecutableIntegrity(executablePath, expectedSha256, label) {
    const descriptor = this.#openVerifiedExecutable(executablePath, expectedSha256, label)
    closeDescriptor(descriptor)
  }

  #assertRunningExecutable(pid, expectedSha256, label) {
    if (!Number.isSafeInteger(pid) || pid < 1) {
      throw new D9PlatformError('EXECUTABLE_BUILD_MISMATCH', `${label} PID is invalid`)
    }
    let bytes
    try {
      bytes = readFileSync(`/proc/${pid}/exe`)
    } catch (error) {
      throw new D9PlatformError('EXECUTABLE_BUILD_MISMATCH', `${label} executable cannot be inspected`, { cause: error.message })
    }
    if (sha256(bytes) !== expectedSha256) {
      throw new D9PlatformError('EXECUTABLE_BUILD_MISMATCH', `${label} executed bytes differ from the pinned build`)
    }
  }

  probe({ unavailable = [] } = {}) {
    this.#assertLive()
    const executableFd = this.#openVerifiedExecutable(this.#executablePath, this.#executableSha256, 'native enforcement helper')
    if (!Array.isArray(unavailable) || unavailable.some((name) => !REQUIRED_FEATURES.includes(name))) {
      throw new D9PlatformError('PLATFORM_INPUT_INVALID', 'unavailable may only remove known required guarantees')
    }
    let probe
    try {
      probe = spawnSync('/proc/self/fd/3', ['probe'], {
        encoding: 'utf8',
        env: fixedEnvironment,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe', executableFd],
      })
    } finally {
      closeDescriptor(executableFd)
    }
    if (probe.error) {
      throw new D9PlatformError('D9_PLATFORM_UNAVAILABLE', 'the native feature probe could not execute', { cause: probe.error.message })
    }
    const result = parseLastJsonLine(probe.stdout, 'native feature probe')
    const effective = { ...result }
    for (const feature of unavailable) effective[feature] = false
    const missing = REQUIRED_FEATURES.filter((feature) => effective[feature] !== true)
    if (probe.status !== 0 || result.event !== 'probe' || missing.length > 0) {
      throw new D9PlatformError('D9_PLATFORM_UNAVAILABLE', 'required Linux guarantees are unavailable', {
        missing,
        nativeStatus: probe.status,
        probe: effective,
        stderr: probe.stderr,
      })
    }
    this.#assertExecutableIntegrity(this.#executablePath, this.#executableSha256, 'native enforcement helper')
    return Object.freeze(effective)
  }

  async runSyntheticPeerExchange({
    descriptorGrants = Object.freeze([Object.freeze({
      access_code: 'attestation_only',
      runtime_role_code: 'synthetic_peer',
      slot_code: 'synthetic_attestation',
    })]),
    expectedEndpointCode = 'ipc.synthetic-peer',
    expectedPeerGid = process.getgid(),
    expectedPeerUid = process.getuid(),
    nonce = randomBytes(32).toString('hex'),
    relativePath,
    requestDigestSha256 = sha256(Buffer.from('d9.synthetic.peer-attestation', 'utf8')),
    rootPath,
    scenario = 'normal',
    syntheticPeerGid = expectedPeerGid,
    syntheticPeerUid = expectedPeerUid,
    token = randomBytes(32).toString('hex'),
  }) {
    this.#assertLive()
    this.probe()
    assertAbsolutePath(rootPath, 'rootPath')
    assertRelativeLeaf(relativePath, 'relativePath')
    assertClosedString(nonce, 'nonce', /^[0-9a-f]{64}$/u, 64)
    assertClosedString(token, 'token', /^[0-9a-f]{64}$/u, 64)
    assertClosedString(requestDigestSha256, 'requestDigestSha256', /^[0-9a-f]{64}$/u, 64)
    assertClosedString(expectedEndpointCode, 'expectedEndpointCode', /^[a-z0-9][a-z0-9._-]{1,94}[a-z0-9]$/u, 96)
    if (!Array.isArray(descriptorGrants) || descriptorGrants.length < 1 || descriptorGrants.length > D9_MAX_ANCILLARY_FDS) {
      throw new D9PlatformError('PLATFORM_INPUT_INVALID', 'descriptorGrants must contain between one and eight grants')
    }
    const grantKeys = new Set()
    for (const [index, descriptorGrant] of descriptorGrants.entries()) {
      if (!descriptorGrant || Array.isArray(descriptorGrant) || typeof descriptorGrant !== 'object' ||
          JSON.stringify(Object.keys(descriptorGrant).toSorted()) !==
            JSON.stringify(['access_code', 'runtime_role_code', 'slot_code'])) {
        throw new D9PlatformError('PLATFORM_INPUT_INVALID', `descriptorGrants[${index}] must contain only the closed grant triple`)
      }
      for (const field of ['access_code', 'runtime_role_code', 'slot_code']) {
        assertClosedString(descriptorGrant[field], `descriptorGrants[${index}].${field}`, /^[a-z0-9][a-z0-9._-]{1,94}[a-z0-9]$/u, 96)
      }
      const grantKey = `${descriptorGrant.slot_code}|${descriptorGrant.runtime_role_code}|${descriptorGrant.access_code}`
      if (grantKeys.has(grantKey)) throw new D9PlatformError('PLATFORM_INPUT_INVALID', 'descriptorGrants contains a duplicate')
      grantKeys.add(grantKey)
    }
    if (!SYNTHETIC_SCENARIOS.has(scenario)) {
      throw new D9PlatformError('PLATFORM_INPUT_INVALID', 'unknown synthetic peer scenario')
    }
    if (!Number.isInteger(expectedPeerUid) || expectedPeerUid < 0 || expectedPeerUid > 0xffff_ffff ||
        !Number.isInteger(expectedPeerGid) || expectedPeerGid < 0 || expectedPeerGid > 0xffff_ffff ||
        !Number.isInteger(syntheticPeerUid) || syntheticPeerUid < 0 || syntheticPeerUid > 0xffff_ffff ||
        !Number.isInteger(syntheticPeerGid) || syntheticPeerGid < 0 || syntheticPeerGid > 0xffff_ffff) {
      throw new D9PlatformError('PLATFORM_INPUT_INVALID', 'expected peer UID/GID is invalid')
    }

    const socketDirectory = await mkdtemp(path.join(tmpdir(), 'jedi-d9-ipc-'))
    await chmod(socketDirectory, 0o711)
    const socketPath = path.join(socketDirectory, `${sha256(Buffer.from(expectedEndpointCode, 'utf8')).slice(0, 32)}.sock`)
    let broker
    let peer
    try {
      const operationMaterial = [
        nonce,
        token,
        requestDigestSha256,
        String(descriptorGrants.length),
        ...descriptorGrants.flatMap((grant) => [grant.slot_code, grant.runtime_role_code, grant.access_code]),
        '',
      ].join('\n')
      const brokerExecutableFd = this.#openVerifiedExecutable(this.#executablePath, this.#executableSha256, 'native descriptor broker')
      try {
        broker = spawn('/proc/self/fd/4', [
        'broker',
        socketPath,
        rootPath,
        relativePath,
        String(expectedPeerUid),
        String(expectedPeerGid),
        scenario,
        ], { env: fixedEnvironment, shell: false, stdio: ['ignore', 'pipe', 'pipe', 'pipe', brokerExecutableFd] })
      } finally {
        closeDescriptor(brokerExecutableFd)
      }
      broker.stdio[3].end(operationMaterial)
      const brokerEvents = createEventReader(broker, 'native descriptor broker')
      const ready = await brokerEvents.next((event) => event.event === 'ready')
      if (!Number.isInteger(ready.pid) || ready.pid < 1) {
        throw new D9PlatformError('NATIVE_PROTOCOL_INVALID', 'descriptor broker returned an invalid PID')
      }
      this.#assertRunningExecutable(ready.pid, this.#executableSha256, 'native descriptor broker')

      const peerExecutable = scenario === 'build_substitution' ? this.#substituteExecutablePath : this.#executablePath
      const peerSha256 = scenario === 'build_substitution' ? this.#substituteExecutableSha256 : this.#executableSha256
      const peerExecutableFd = this.#openVerifiedExecutable(peerExecutable, peerSha256, 'native synthetic peer')
      try {
        peer = spawn('/proc/self/fd/4', ['synthetic-peer', socketPath, scenario], {
          env: fixedEnvironment,
          gid: syntheticPeerGid,
          shell: false,
          stdio: ['ignore', 'pipe', 'pipe', 'pipe', peerExecutableFd],
          uid: syntheticPeerUid,
        })
      } finally {
        closeDescriptor(peerExecutableFd)
      }
      peer.stdio[3].end(operationMaterial)
      const result = await brokerEvents.next((event) => event.event === 'result')
      const [brokerExit, peerExit] = await Promise.all([waitForExit(broker), waitForExit(peer)])
      return Object.freeze({
        ...result,
        brokerExit,
        peerExit,
        receiverExitConfirmed: peerExit.code !== null || peerExit.signal !== null,
        authenticatedEndpointCode: expectedEndpointCode,
        syntheticPeer: true,
      })
    } finally {
      await Promise.allSettled([stopChildAndConfirm(peer), stopChildAndConfirm(broker)])
      await rm(socketDirectory, { force: true, recursive: true })
    }
  }

  async holdOperationLock({ relativePath, rootPath }) {
    this.#assertLive()
    this.probe()
    assertAbsolutePath(rootPath, 'rootPath')
    assertRelativeLeaf(relativePath, 'relativePath')
    const executableFd = this.#openVerifiedExecutable(this.#executablePath, this.#executableSha256, 'native lock holder')
    let child
    try {
      child = spawn('/proc/self/fd/3', ['lock-hold', rootPath, relativePath], {
        env: fixedEnvironment,
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe', executableFd],
      })
    } finally {
      closeDescriptor(executableFd)
    }
    const events = createEventReader(child, 'native operation lock holder')
    const acquired = await events.next((event) => event.event === 'lock')
    if (acquired.status !== 'acquired') {
      await stopChildAndConfirm(child)
      throw new D9PlatformError('OPERATION_LOCK_UNAVAILABLE', 'the operation lock is already held', acquired)
    }
    let released = false
    return Object.freeze({
      pid: acquired.pid,
      async release() {
        if (released) return
        released = true
        child.stdin.end()
        const exit = await waitForExit(child)
        if (exit.code !== 0) {
          throw new D9PlatformError('OPERATION_LOCK_RELEASE_FAILED', 'the lock holder exited abnormally', exit)
        }
      },
    })
  }

  tryOperationLock({ relativePath, rootPath }) {
    this.#assertLive()
    this.probe()
    assertAbsolutePath(rootPath, 'rootPath')
    assertRelativeLeaf(relativePath, 'relativePath')
    const executableFd = this.#openVerifiedExecutable(this.#executablePath, this.#executableSha256, 'native lock probe')
    let attempt
    try {
      attempt = spawnSync('/proc/self/fd/3', ['lock-try', rootPath, relativePath], {
        encoding: 'utf8',
        env: fixedEnvironment,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe', executableFd],
      })
    } finally {
      closeDescriptor(executableFd)
    }
    if (attempt.error) {
      throw new D9PlatformError('OPERATION_LOCK_UNAVAILABLE', 'the native lock attempt could not execute', { cause: attempt.error.message })
    }
    const result = parseLastJsonLine(attempt.stdout, 'native operation lock attempt')
    if (result.event !== 'lock' || !['acquired', 'busy'].includes(result.status) ||
        (result.status === 'acquired' && attempt.status !== 0) ||
        (result.status === 'busy' && attempt.status !== 3)) {
      throw new D9PlatformError('NATIVE_PROTOCOL_INVALID', 'the native lock attempt returned an inconsistent result', {
        result,
        status: attempt.status,
        stderr: attempt.stderr,
      })
    }
    return Object.freeze(result)
  }

  async dispose() {
    if (this.#disposed) return
    this.#disposed = true
    await rm(this.#buildDirectory, { force: true, recursive: true })
  }
}

export function assertLinuxEnforcement(value) {
  if (!verifiedLinuxEnforcements.has(value)) {
    throw new D9PlatformError('PLATFORM_INPUT_INVALID', 'platform object was not created by the verified Linux compiler path')
  }
  return value
}
