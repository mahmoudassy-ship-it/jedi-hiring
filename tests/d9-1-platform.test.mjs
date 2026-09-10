import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { appendFile, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import {
  D9_MAX_ANCILLARY_FDS,
  D9_MAX_PACKET_BYTES,
  D9PlatformError,
  SYNTHETIC_DESCRIPTOR_BYTES,
  compileLinuxEnforcement,
} from '../d9/control-plane/platform.mjs'

let platform
let syntheticRoot

before(async () => {
  platform = await compileLinuxEnforcement()
  syntheticRoot = await mkdtemp(path.join(tmpdir(), 'jedi-d9-platform-test-'))
  await writeFile(path.join(syntheticRoot, 'source.bin'), SYNTHETIC_DESCRIPTOR_BYTES, { mode: 0o600 })
  await symlink('source.bin', path.join(syntheticRoot, 'source-link'))
})

after(async () => {
  await platform?.dispose()
  if (syntheticRoot) await rm(syntheticRoot, { force: true, recursive: true })
})

test('D9.1 Linux helper proves every required kernel primitive and fails closed when one is unavailable', () => {
  const probe = platform.probe()
  for (const feature of [
    'linux',
    'seqpacket',
    'peer_credentials',
    'peer_pidfd',
    'scm_rights',
    'msg_cmsg_cloexec',
    'openat2',
    'flock',
  ]) assert.equal(probe[feature], true, feature)
  assert.match(platform.sourceSha256, /^[0-9a-f]{64}$/u)
  assert.match(platform.executableSha256, /^[0-9a-f]{64}$/u)
  assert.match(platform.substituteExecutableSha256, /^[0-9a-f]{64}$/u)
  assert.notEqual(platform.executableSha256, platform.substituteExecutableSha256)

  assert.throws(
    () => platform.probe({ unavailable: ['peer_pidfd', 'openat2'] }),
    (error) => error instanceof D9PlatformError &&
      error.code === 'D9_PLATFORM_UNAVAILABLE' &&
      assert.deepEqual(error.details.missing, ['peer_pidfd', 'openat2']) === undefined,
  )
  assert.throws(
    () => platform.probe({ unavailable: ['invented-bypass'] }),
    (error) => error instanceof D9PlatformError && error.code === 'PLATFORM_INPUT_INVALID',
  )
})

test('synthetic peer receives one CLOEXEC descriptor over authenticated SOCK_SEQPACKET and is then confirmed dead', async () => {
  const result = await platform.runSyntheticPeerExchange({
    relativePath: 'source.bin',
    rootPath: syntheticRoot,
  })
  assert.equal(result.syntheticPeer, true)
  assert.equal(result.status, 'ok')
  assert.equal(result.ack_same_channel, true)
  assert.equal(result.descriptor_cloexec, true)
  assert.equal(result.descriptor_metadata_verified, true)
  assert.equal(result.termination_confirmed, true)
  assert.equal(result.termination_escalated, false)
  assert.equal(result.peer_uid, process.getuid())
  assert.equal(result.peer_gid, process.getgid())
  assert.ok(Number.isInteger(result.peer_pid) && result.peer_pid > 1)
  assert.deepEqual(result.brokerExit, { code: 0, signal: null })
  assert.deepEqual(result.peerExit, { code: null, signal: 'SIGTERM' })
})

test('descriptor packets bind an ordered role-scoped grant set and every descriptor ordinal', async () => {
  const descriptorGrants = [
    {
      access_code: 'append_only',
      runtime_role_code: 'journal_broker',
      slot_code: 'operation_journal',
    },
    {
      access_code: 'read_only',
      runtime_role_code: 'journal_broker',
      slot_code: 'runtime_profile',
    },
  ]
  const result = await platform.runSyntheticPeerExchange({
    descriptorGrants,
    relativePath: 'source.bin',
    rootPath: syntheticRoot,
  })
  assert.equal(result.status, 'ok')
  assert.equal(result.descriptor_count, 2)
  assert.equal(result.descriptor_metadata_verified, true)

  await assert.rejects(
    platform.runSyntheticPeerExchange({
      descriptorGrants: [{ ...descriptorGrants[0], extra: 'not_allowed' }],
      relativePath: 'source.bin',
      rootPath: syntheticRoot,
    }),
    (error) => error instanceof D9PlatformError && error.code === 'PLATFORM_INPUT_INVALID',
  )
})

test('descriptor token replay on the authenticated channel is recognized and rejected', async () => {
  const result = await platform.runSyntheticPeerExchange({
    relativePath: 'source.bin',
    rootPath: syntheticRoot,
    scenario: 'replay',
  })
  assert.equal(result.status, 'ok')
  assert.equal(result.replay_rejected, true)
  assert.equal(result.ack_same_channel, true)
  assert.equal(result.termination_confirmed, true)
})

test('kernel peer identity rejects allowlist mismatch and claimed UID/GID/PID spoofing before descriptor delivery', async (context) => {
  const actualUid = process.getuid()
  const mismatchedUid = actualUid === 0xffff_ffff ? actualUid - 1 : actualUid + 1
  const cases = [
    ['allowlist mismatch', { expectedPeerUid: mismatchedUid, syntheticPeerUid: actualUid }, 'PEER_MISMATCH'],
    ['claimed UID spoof', { scenario: 'spoof_uid' }, 'PEER_CLAIM_MISMATCH'],
    ['claimed GID spoof', { scenario: 'spoof_gid' }, 'PEER_CLAIM_MISMATCH'],
    ['claimed PID spoof', { scenario: 'spoof_pid' }, 'PEER_CLAIM_MISMATCH'],
  ]
  for (const [label, options, errorCode] of cases) {
    await context.test(label, async () => {
      const result = await platform.runSyntheticPeerExchange({
        relativePath: 'source.bin',
        rootPath: syntheticRoot,
        ...options,
      })
      assert.equal(result.status, 'rejected')
      assert.equal(result.error_code, errorCode)
      assert.deepEqual(result.brokerExit, { code: 2, signal: null })
    })
  }
})

test('peer executable substitution is rejected against the pre-hashed native build inode', async () => {
  const result = await platform.runSyntheticPeerExchange({
    relativePath: 'source.bin',
    rootPath: syntheticRoot,
    scenario: 'build_substitution',
  })
  assert.equal(result.status, 'rejected')
  assert.equal(result.error_code, 'PEER_EXECUTABLE_MISMATCH')
  assert.deepEqual(result.brokerExit, { code: 2, signal: null })
})

test('use-time build verification rejects mutation of the executable selected for launch', async (context) => {
  const isolated = await compileLinuxEnforcement()
  context.after(async () => { await isolated.dispose() })
  await appendFile(isolated.syntheticExecutablePath, Buffer.from([0]))
  assert.throws(
    () => isolated.probe(),
    (error) => error instanceof D9PlatformError && error.code === 'EXECUTABLE_BUILD_MISMATCH',
  )
  await assert.rejects(
    isolated.runSyntheticPeerExchange({ relativePath: 'source.bin', rootPath: syntheticRoot }),
    (error) => error instanceof D9PlatformError && error.code === 'EXECUTABLE_BUILD_MISMATCH',
  )
})

test('packet and ancillary descriptor ceilings reject oversize and ninth-FD packets', async (context) => {
  assert.equal(D9_MAX_PACKET_BYTES, 65_536)
  assert.equal(D9_MAX_ANCILLARY_FDS, 8)
  for (const [scenario, errorCode] of [
    ['oversize', 'PACKET_TOO_LARGE'],
    ['too_many_fds', 'DESCRIPTOR_LIMIT'],
  ]) {
    await context.test(scenario, async () => {
      const result = await platform.runSyntheticPeerExchange({
        relativePath: 'source.bin',
        rootPath: syntheticRoot,
        scenario,
      })
      assert.equal(result.status, 'rejected')
      assert.equal(result.error_code, errorCode)
      assert.deepEqual(result.brokerExit, { code: 2, signal: null })
    })
  }
})

test('malformed, noncanonical, and wrong-nonce packets fail on the authenticated native channel', async (context) => {
  for (const [scenario, errorCode] of [
    ['malformed_packet', 'PACKET_INVALID'],
    ['noncanonical_packet', 'PACKET_NOT_CANONICAL'],
    ['wrong_nonce', 'NONCE_MISMATCH'],
    ['wrong_request_digest', 'REQUEST_DIGEST_MISMATCH'],
    ['wrong_descriptor_metadata', 'ACK_INVALID'],
  ]) {
    await context.test(scenario, async () => {
      const result = await platform.runSyntheticPeerExchange({
        relativePath: 'source.bin',
        rootPath: syntheticRoot,
        scenario,
      })
      assert.equal(result.status, 'rejected')
      assert.equal(result.error_code, errorCode)
      assert.deepEqual(result.brokerExit, { code: 2, signal: null })
    })
  }
})

test('descriptor receiver that ignores SIGTERM is killed through its pidfd and confirmed dead', async () => {
  const result = await platform.runSyntheticPeerExchange({
    relativePath: 'source.bin',
    rootPath: syntheticRoot,
    scenario: 'ignore_sigterm',
  })
  assert.equal(result.status, 'ok')
  assert.equal(result.termination_confirmed, true)
  assert.equal(result.termination_escalated, true)
  assert.deepEqual(result.peerExit, { code: null, signal: 'SIGKILL' })
})

test('kernel-visible confinement kills attempted fork and descriptor transfer before acknowledgement', async (context) => {
  for (const scenario of ['fork_escape', 'fd_transfer_escape']) {
    await context.test(scenario, async () => {
      const result = await platform.runSyntheticPeerExchange({
        relativePath: 'source.bin',
        rootPath: syntheticRoot,
        scenario,
      })
      assert.equal(result.status, 'rejected')
      assert.equal(result.error_code, 'ACK_INVALID')
      assert.equal(result.receiverExitConfirmed, true)
      assert.equal(result.peerExit.signal, 'SIGSYS')
    })
  }
})

test('openat2 confinement rejects symlinks and the wrapper rejects traversal before native invocation', async () => {
  const symlinkResult = await platform.runSyntheticPeerExchange({
    relativePath: 'source-link',
    rootPath: syntheticRoot,
  })
  assert.equal(symlinkResult.status, 'rejected')
  assert.equal(symlinkResult.error_code, 'SAFE_OPEN_FAILED')

  await assert.rejects(
    platform.runSyntheticPeerExchange({
      relativePath: '../source.bin',
      rootPath: syntheticRoot,
    }),
    (error) => error instanceof D9PlatformError && error.code === 'PLATFORM_INPUT_INVALID',
  )
})

test('operation lock is held by the kernel and excludes a second process until release', async (context) => {
  const lease = await platform.holdOperationLock({
    relativePath: 'operation.lock',
    rootPath: syntheticRoot,
  })
  context.after(async () => { await lease.release() })
  assert.ok(Number.isInteger(lease.pid) && lease.pid > 1)
  assert.deepEqual(platform.tryOperationLock({
    relativePath: 'operation.lock',
    rootPath: syntheticRoot,
  }), { event: 'lock', status: 'busy' })

  await lease.release()
  const reacquired = platform.tryOperationLock({
    relativePath: 'operation.lock',
    rootPath: syntheticRoot,
  })
  assert.equal(reacquired.event, 'lock')
  assert.equal(reacquired.status, 'acquired')
  assert.ok(Number.isInteger(reacquired.pid) && reacquired.pid > 1)
})
