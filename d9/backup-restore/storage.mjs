import fs from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { sha256Bytes } from '../control-plane/canonical.mjs'
import { assertSha } from './contracts.mjs'
import { failD951 } from './errors.mjs'

const stores = new WeakSet()
const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u

function syncDirectory(directory) {
  const procDescriptor = /^\/proc\/self\/fd\/(\d+)$/u.exec(directory)
  if (procDescriptor) { fs.fsyncSync(Number(procDescriptor[1])); return }
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try { fs.fsyncSync(descriptor) } finally { fs.closeSync(descriptor) }
}

function protectedDirectory(directory, expectedUid, create = false) {
  if (create) { try { fs.mkdirSync(directory, { mode: 0o700 }) } catch (error) { if (error.code !== 'EEXIST') throw error } }
  const status = fs.lstatSync(directory, { bigint: true })
  if (!status.isDirectory() || status.isSymbolicLink() || status.uid !== BigInt(expectedUid) || (status.mode & 0o077n) !== 0n) failD951('D951_STORAGE_ROOT_UNSAFE', 'storage directory must be owned, private, and not a symlink')
  return status
}

function readExact(file, identity, expectedUid) {
  const before = fs.lstatSync(file, { bigint: true })
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o177n) !== 0n || before.size !== BigInt(identity.byte_length)) failD951('D951_COPY_UNSAFE', 'backup object is not the expected private single-link file')
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try {
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor, { bigint: true })
    for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) if (before[key] !== after[key]) failD951('D951_COPY_CHANGED', 'backup object changed during verification')
    if (bytes.length !== identity.byte_length || sha256Bytes(bytes) !== identity.sha256) failD951('D951_COPY_MISMATCH', 'backup bytes differ from their exact identity')
    return bytes
  } finally { fs.closeSync(descriptor) }
}

function assertIdentity(identity) {
  if (!identity || identity.hash_algorithm_code !== 'sha256' || !Number.isSafeInteger(identity.byte_length) || identity.byte_length < 0 || identity.byte_length > 64 * 1024 * 1024) failD951('D951_COPY_IDENTITY_INVALID', 'copy identity is outside the synthetic profile')
  assertSha(identity.sha256, 'copy identity')
  return identity
}

function descriptorBytes(descriptor, length) {
  const bytes = Buffer.alloc(length)
  let offset = 0
  while (offset < length) {
    const count = fs.readSync(descriptor, bytes, offset, length - offset, offset)
    if (count <= 0) failD951('D951_SOURCE_INVALID', 'descriptor ended before its declared length')
    offset += count
  }
  return bytes
}

export function createD951BackupStore({ rootPath, expectedUid = process.getuid(), backendCode = 'synthetic.restricted.backup.v1', faultInjector = null }) {
  if (!path.isAbsolute(rootPath) || rootPath.includes('\0')) failD951('D951_STORAGE_ROOT_UNSAFE', 'backup root must be an absolute NUL-free configured path')
  const original = protectedDirectory(rootPath, expectedUid)
  const rootDescriptor = fs.openSync(rootPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  const opened = fs.fstatSync(rootDescriptor, { bigint: true })
  if (opened.dev !== original.dev || opened.ino !== original.ino) failD951('D951_STORAGE_ROOT_UNSAFE', 'backup root changed while opening')
  const root = `/proc/self/fd/${rootDescriptor}`
  let objects = path.join(root, 'objects')
  let pending = path.join(root, 'pending')
  let objectsDescriptor
  let pendingDescriptor
  try {
    protectedDirectory(objects, expectedUid, true); protectedDirectory(pending, expectedUid, true)
    if (fs.readdirSync(pending).length !== 0) failD951('D951_RECOVERY_REQUIRED', 'unresolved staged backup object exists')
    const exact = fs.readdirSync(root).toSorted()
    if (exact.join('\0') !== ['objects', 'pending'].join('\0')) failD951('D951_STORAGE_LAYOUT_INVALID', 'backup root has an unexpected namespace')
    objectsDescriptor = fs.openSync(objects, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
    pendingDescriptor = fs.openSync(pending, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
    objects = `/proc/self/fd/${objectsDescriptor}`; pending = `/proc/self/fd/${pendingDescriptor}`
  } catch (error) { fs.closeSync(rootDescriptor); throw error }
  let closed = false
  const store = Object.freeze({
    backendCode,
    put({ identity, sourceDescriptor }) {
      if (closed) failD951('D951_STORAGE_CLOSED', 'backup store is closed')
      assertIdentity(identity)
      if (!Number.isInteger(sourceDescriptor) || sourceDescriptor < 0) failD951('D951_SOURCE_INVALID', 'source must be an already-open descriptor')
      const before = fs.fstatSync(sourceDescriptor, { bigint: true })
      if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(identity.byte_length)) failD951('D951_SOURCE_INVALID', 'source descriptor is not an exact single-link regular file')
      const bytes = descriptorBytes(sourceDescriptor, identity.byte_length)
      const after = fs.fstatSync(sourceDescriptor, { bigint: true })
      for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) if (before[key] !== after[key]) failD951('D951_SOURCE_CHANGED', 'source changed during backup')
      if (sha256Bytes(bytes) !== identity.sha256) failD951('D951_SOURCE_MISMATCH', 'source bytes differ from declared identity')
      const final = path.join(objects, identity.sha256)
      const temporary = path.join(pending, `${identity.sha256}.${randomBytes(8).toString('hex')}`)
      let created = false
      try {
        const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC, 0o600)
        try { fs.writeFileSync(fd, bytes); faultInjector?.('after_write'); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
        syncDirectory(pending); faultInjector?.('after_stage_sync')
        try { fs.linkSync(temporary, final); created = true } catch (error) { if (error.code !== 'EEXIST') throw error }
        const finalFd = fs.openSync(final, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
        try { fs.fsyncSync(finalFd) } finally { fs.closeSync(finalFd) }
        syncDirectory(objects)
        fs.unlinkSync(temporary); syncDirectory(pending)
        readExact(final, identity, expectedUid); faultInjector?.('after_publish')
        return Object.freeze({ backend_code: backendCode, backend_reference: `objects/${identity.sha256}`, disposition_code: created ? 'created_new' : 'existing_exact', file_data_synced: true, parent_directory_synced: true, reopened_and_rehashed: true, no_replace_enforced: true })
      } catch (error) {
        try { if (fs.existsSync(temporary)) { fs.unlinkSync(temporary); syncDirectory(pending) } } catch {}
        throw error
      }
    },
    read({ identity, backendReference }) {
      if (closed) failD951('D951_STORAGE_CLOSED', 'backup store is closed')
      assertIdentity(identity)
      if (backendReference !== `objects/${identity.sha256}`) failD951('D951_REFERENCE_MISMATCH', 'backup reference is not content-addressed')
      return readExact(path.join(objects, identity.sha256), identity, expectedUid)
    },
    inventory() {
      return fs.readdirSync(objects).toSorted().map((name) => {
        if (!/^[0-9a-f]{64}$/u.test(name)) failD951('D951_STORAGE_LAYOUT_INVALID', 'backup object name is not a SHA-256 identity')
        const bytes = fs.readFileSync(path.join(objects, name)); return { sha256: name, byte_length: bytes.length }
      })
    },
    close() { if (!closed) { closed = true; stores.delete(store); fs.closeSync(objectsDescriptor); fs.closeSync(pendingDescriptor); fs.closeSync(rootDescriptor) } },
  })
  stores.add(store)
  return store
}

export function assertD951BackupStore(value) {
  if (!stores.has(value)) failD951('D951_STORAGE_UNTRUSTED', 'backup store is not trusted')
  return value
}
