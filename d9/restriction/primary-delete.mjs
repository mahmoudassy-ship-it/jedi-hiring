import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

import { canonicalSha256, sha256Bytes } from '../control-plane/canonical.mjs'
import { failD941 } from './errors.mjs'

const source = fileURLToPath(new URL('./native/d9_primary_delete.c', import.meta.url))
const runtimes = new WeakSet()
const effectProofs = new WeakSet()
const syncProofs = new WeakSet()

function protectedTempRoot(rootPath) {
  const resolved = path.resolve(rootPath)
  const relative = path.relative(os.tmpdir(), resolved)
  if (!relative.startsWith('jedi-d941-') || relative.includes(path.sep + '..') || relative === '..') failD941('D941_DELETE_ROOT_FORBIDDEN', 'deletion root must be a newly created D9.4.1 temporary test directory')
  const status = fs.lstatSync(resolved, { bigint: true })
  if (!status.isDirectory() || status.isSymbolicLink() || (status.mode & 0o077n) !== 0n || status.uid !== BigInt(process.getuid())) failD941('D941_DELETE_ROOT_UNPROTECTED', 'deletion root must be owned mode-0700 and not a symlink')
  return { resolved, status }
}

function exactReference(artifact) { return `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}` }

function inspect(rootPath, artifact) {
  const target = path.join(rootPath, exactReference(artifact))
  const parent = path.dirname(target)
  for (const current of [path.join(rootPath, 'objects'), path.join(rootPath, 'objects/sha256'), parent]) {
    const status = fs.lstatSync(current, { bigint: true })
    if (!status.isDirectory() || status.isSymbolicLink() || (status.mode & 0o022n) !== 0n) failD941('D941_DELETE_NAMESPACE_UNSAFE', 'CAS namespace contains an unsafe directory')
  }
  const unexpected = fs.readdirSync(parent).filter((name) => name !== artifact.sha256)
  if (unexpected.length) failD941('D941_DELETE_INVENTORY_UNEXPECTED', 'primary hash directory contains unexpected names')
  const objectsEntries = fs.readdirSync(path.join(rootPath, 'objects'))
  if (objectsEntries.length !== 1 || objectsEntries[0] !== 'sha256') failD941('D941_DELETE_INVENTORY_UNEXPECTED', 'CAS object namespace contains an unexpected entry')
  const fanoutRoot = path.join(rootPath, 'objects', 'sha256')
  const fanouts = fs.readdirSync(fanoutRoot, { withFileTypes: true })
  if (fanouts.length !== 1 || !fanouts[0].isDirectory() || fanouts[0].name !== artifact.sha256.slice(0, 2)) failD941('D941_DELETE_INVENTORY_UNEXPECTED', 'CAS fanout contains an unexpected replica or namespace')
  const status = fs.lstatSync(target, { bigint: true })
  if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1n || status.size !== BigInt(artifact.byte_length)) failD941('D941_DELETE_TARGET_UNSAFE', 'target is not the exact single-link regular artifact')
  const descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try {
    const before = fs.fstatSync(descriptor, { bigint: true }); const bytes = fs.readFileSync(descriptor); const after = fs.fstatSync(descriptor, { bigint: true })
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || sha256Bytes(bytes) !== artifact.sha256) failD941('D941_DELETE_TARGET_CHANGED', 'target identity or bytes changed during inventory')
    const parentDescriptor = fs.openSync(parent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
    try {
      const parentStatus = fs.fstatSync(parentDescriptor, { bigint: true })
      return Object.freeze({ targetPath: target, targetDevice: Number(before.dev), targetInode: Number(before.ino), targetSize: Number(before.size), targetLinkCount: Number(before.nlink), parentDevice: Number(parentStatus.dev), parentInode: Number(parentStatus.ino) })
    } finally { fs.closeSync(parentDescriptor) }
  } finally { fs.closeSync(descriptor) }
}

export function compileD941PrimaryDeleteRuntime() {
  if (process.platform !== 'linux') failD941('D941_PLATFORM_UNAVAILABLE', 'synthetic deletion requires Linux')
  const buildRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d941-build-')); fs.chmodSync(buildRoot, 0o700)
  const executable = path.join(buildRoot, 'd9-primary-delete')
  const result = spawnSync('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic', source, '-o', executable], { encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }, shell: false })
  if (result.error || result.status !== 0) { fs.rmSync(buildRoot, { recursive: true, force: true }); failD941('D941_NATIVE_BUILD_FAILED', 'primary deletion helper did not compile', { stderr: result.stderr }) }
  const executableSha256 = sha256Bytes(fs.readFileSync(executable))
  const executableDescriptor = fs.openSync(executable, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  const readPinnedExecutable = () => {
    const size = Number(fs.fstatSync(executableDescriptor, { bigint: true }).size)
    const bytes = Buffer.alloc(size); let offset = 0
    while (offset < size) offset += fs.readSync(executableDescriptor, bytes, offset, size - offset, offset)
    return bytes
  }
  let pinnedRoot = null
  const ownedRoots = new Map()
  function createSyntheticRoot() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d941-cas-'))
    fs.chmodSync(root, 0o700)
    const status = fs.lstatSync(root, { bigint: true })
    ownedRoots.set(path.resolve(root), Object.freeze({ device: status.dev, inode: status.ino }))
    return root
  }
  function rootFor(rootPath) {
    const checked = protectedTempRoot(rootPath)
    const provenance = ownedRoots.get(checked.resolved)
    const isPinnedPath = pinnedRoot !== null && checked.resolved === pinnedRoot.resolved
    if ((!provenance && !isPinnedPath) || (provenance && (provenance.device !== checked.status.dev || provenance.inode !== checked.status.ino) && !isPinnedPath)) failD941('D941_DELETE_ROOT_FORBIDDEN', 'root was not created and registered by this synthetic deletion runtime')
    if (pinnedRoot === null) {
      const descriptor = fs.openSync(checked.resolved, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
      const opened = fs.fstatSync(descriptor, { bigint: true })
      if (opened.dev !== checked.status.dev || opened.ino !== checked.status.ino) { fs.closeSync(descriptor); failD941('D941_DELETE_ROOT_SUBSTITUTED', 'root changed during descriptor pinning') }
      pinnedRoot = Object.freeze({ descriptor, resolved: checked.resolved, device: Number(opened.dev), inode: Number(opened.ino) })
    }
    const current = fs.lstatSync(checked.resolved, { bigint: true })
    const opened = fs.fstatSync(pinnedRoot.descriptor, { bigint: true })
    if (checked.resolved !== pinnedRoot.resolved || current.dev !== opened.dev || current.ino !== opened.ino || Number(opened.dev) !== pinnedRoot.device || Number(opened.ino) !== pinnedRoot.inode) failD941('D941_DELETE_ROOT_SUBSTITUTED', 'configured root no longer resolves to the pinned descriptor')
    return `/proc/self/fd/${pinnedRoot.descriptor}`
  }
  function execute(mode, root, artifact, inventory, operationNonce) {
    if (sha256Bytes(readPinnedExecutable()) !== executableSha256) failD941('D941_NATIVE_BUILD_SUBSTITUTED', 'native helper bytes changed after attestation')
    const args = [mode, '4', artifact.sha256, String(inventory.targetDevice ?? 0), String(inventory.targetInode ?? 0), String(artifact.byte_length), String(pinnedRoot.device), String(pinnedRoot.inode), String(inventory.parentDevice), String(inventory.parentInode), operationNonce]
    const result = spawnSync('/proc/self/fd/3', args, { encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }, shell: false, stdio: ['ignore', 'pipe', 'pipe', executableDescriptor, pinnedRoot.descriptor] })
    if (result.error || result.status !== 0) failD941(mode === 'verify-absent' ? 'D941_ABSENCE_UNVERIFIED' : 'D941_UNLINK_FAILED', `native ${mode} failed with status ${result.status}: ${result.stderr?.trim() ?? ''}`, { details: { status: result.status, stderr: result.stderr } })
    return JSON.parse(result.stdout.trim())
  }
  const runtime = Object.freeze({
    executableSha256,
    createSyntheticRoot,
    inspect({ rootPath, artifact, backendReference }) {
      rootPath = rootFor(rootPath)
      if (backendReference !== exactReference(artifact)) failD941('D941_DELETE_REFERENCE_MISMATCH', 'backend reference is not the exact approved primary CAS name')
      return inspect(rootPath, artifact)
    },
    unlinkPrimary({ rootPath, artifact, backendReference, inventory, recordInventory = inventory, recordDigestSha256 = null, operationNonce }) {
      rootPath = rootFor(rootPath)
      if (backendReference !== exactReference(artifact) || !/^[0-9a-f]{64}$/u.test(operationNonce)) failD941('D941_DELETE_INPUT_INVALID', 'delete input is outside the closed interface')
      const output = execute('unlink', rootPath, artifact, inventory, operationNonce)
      if (!output.removed || output.directory_synced || !output.reopened_absent || output.target_device !== inventory.targetDevice || output.target_inode !== inventory.targetInode) failD941('D941_UNLINK_RESULT_INVALID', 'native unlink result differs from the safety inventory')
      const result = Object.freeze(output)
      const proof = Object.freeze({ effect_kind_code: 'primary_name_unlinked_pending_sync', operation_nonce: operationNonce, record_digest_sha256: recordDigestSha256, target_device: result.target_device, target_inode: result.target_inode, inventory_digest_sha256: canonicalSha256(recordInventory), result_digest_sha256: canonicalSha256(result) })
      effectProofs.add(proof)
      return Object.freeze({ ...result, effectProof: proof })
    },
    syncParent({ rootPath, artifact, inventory, operationNonce }) {
      rootPath = rootFor(rootPath)
      const output = execute('sync-parent', rootPath, artifact, inventory, operationNonce)
      if (!output.directory_synced || !output.reopened_absent || output.parent_device !== inventory.parentDevice || output.parent_inode !== inventory.parentInode) failD941('D941_DIRECTORY_SYNC_FAILED', 'parent synchronization differs from the pinned inventory')
      const result = Object.freeze(output)
      const syncProof = Object.freeze({ parent_device: result.parent_device, parent_inode: result.parent_inode, reopened_absent: result.reopened_absent, result_digest_sha256: canonicalSha256(result) })
      syncProofs.add(syncProof)
      return Object.freeze({ ...result, syncProof })
    },
    verifyAbsent({ rootPath, artifact, inventory, recordInventory = inventory, recordDigestSha256 = null, operationNonce }) {
      rootPath = rootFor(rootPath)
      const output = execute('verify-absent', rootPath, artifact, inventory, operationNonce)
      if (!output.absent || output.parent_device !== inventory.parentDevice || output.parent_inode !== inventory.parentInode) failD941('D941_ABSENCE_UNVERIFIED', 'parent identity changed or target remains')
      const result = Object.freeze(output)
      const proof = Object.freeze({ effect_kind_code: 'primary_absence_observed', operation_nonce: operationNonce, record_digest_sha256: recordDigestSha256, parent_device: result.parent_device, parent_inode: result.parent_inode, inventory_digest_sha256: canonicalSha256(recordInventory), result_digest_sha256: canonicalSha256(result) })
      effectProofs.add(proof)
      return Object.freeze({ ...result, effectProof: proof })
    },
    finalizeUnlinkEffect({ unlinkResult, syncResult, recordInventory, recordDigestSha256, operationNonce }) {
      if (!unlinkResult?.effectProof || !effectProofs.has(unlinkResult.effectProof) || !syncResult?.syncProof || !syncProofs.has(syncResult.syncProof) ||
          unlinkResult.effectProof.effect_kind_code !== 'primary_name_unlinked_pending_sync' || syncResult.syncProof.reopened_absent !== true) {
        failD941('D941_DELETE_EFFECT_UNPROVEN', 'unlink effect was not followed by the fixed parent synchronization boundary')
      }
      const proof = Object.freeze({ effect_kind_code: 'primary_name_unlinked_and_synced', operation_nonce: operationNonce, record_digest_sha256: recordDigestSha256, inventory_digest_sha256: canonicalSha256(recordInventory), target_device: unlinkResult.effectProof.target_device, target_inode: unlinkResult.effectProof.target_inode, parent_device: syncResult.syncProof.parent_device, parent_inode: syncResult.syncProof.parent_inode, reopened_absent: true, unlink_result_digest_sha256: unlinkResult.effectProof.result_digest_sha256, sync_result_digest_sha256: syncResult.syncProof.result_digest_sha256 })
      effectProofs.add(proof)
      return proof
    },
    dispose() { if (pinnedRoot) fs.closeSync(pinnedRoot.descriptor); fs.closeSync(executableDescriptor); for (const root of ownedRoots.keys()) fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(buildRoot, { recursive: true, force: true }); runtimes.delete(runtime) },
  })
  runtimes.add(runtime); return runtime
}

export function assertD941PrimaryDeleteRuntime(value) {
  if (!runtimes.has(value)) failD941('D941_DELETE_RUNTIME_UNTRUSTED', 'primary deletion runtime was not compiled by the fixed factory')
  return value
}

export function assertD941PrimaryEffectProof(proof, record) {
  if (!proof || !effectProofs.has(proof) || proof.operation_nonce !== record.operation_nonce || proof.record_digest_sha256 !== record.record_digest_sha256 ||
      proof.inventory_digest_sha256 !== canonicalSha256(record.inventory) ||
      (record.record_kind_code === 'unlink_attempted' && (proof.target_device !== record.inventory.target_device || proof.target_inode !== record.inventory.target_inode)) ||
      (record.record_kind_code === 'primary_absence_verified' && (proof.parent_device !== record.inventory.parent_directory_device || proof.parent_inode !== record.inventory.parent_directory_inode)) ||
      (record.record_kind_code === 'unlink_attempted' && (proof.effect_kind_code !== 'primary_name_unlinked_and_synced' || proof.parent_device !== record.inventory.parent_directory_device || proof.parent_inode !== record.inventory.parent_directory_inode || proof.reopened_absent !== true)) ||
      (record.record_kind_code === 'primary_absence_verified' && proof.effect_kind_code !== 'primary_absence_observed')) {
    failD941('D941_DELETE_EFFECT_UNPROVEN', 'deletion fact lacks the fixed native effect attestation')
  }
  return true
}
