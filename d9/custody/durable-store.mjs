import fs from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { canonicalize, sha256Bytes } from '../control-plane/canonical.mjs'
import { failD931 } from './errors.mjs'

const stores = new WeakSet()
const SAFE_PART = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u

function assertRoot(rootPath, expectedUid) {
  if (typeof rootPath !== 'string' || !path.isAbsolute(rootPath) || rootPath.includes('\0')) failD931('D931_ROOT_INVALID', 'protected root must be an absolute NUL-free path selected by configuration')
  const before = fs.lstatSync(rootPath, { bigint: true })
  if (!before.isDirectory() || before.isSymbolicLink() || before.nlink < 2n || (before.mode & 0o077n) !== 0n || before.uid !== BigInt(expectedUid)) {
    failD931('D931_ROOT_UNPROTECTED', 'protected root must be an owned mode-0700 single directory')
  }
  const descriptor = fs.openSync(rootPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true })
    if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink < 2n || (opened.mode & 0o077n) !== 0n || opened.uid !== BigInt(expectedUid)) failD931('D931_ROOT_UNPROTECTED', 'opened protected root identity or permissions differ from the validated path')
  } catch (error) {
    fs.closeSync(descriptor)
    throw error
  }
  return descriptor
}

function assertPart(part) {
  if (typeof part !== 'string' || !SAFE_PART.test(part) || part === '.' || part === '..') failD931('D931_PATH_REJECTED', `internal path component is outside the closed shape: ${String(part)}`)
}

function descriptorRoot(descriptor) {
  return `/proc/self/fd/${descriptor}`
}

function inspectDirectory(parent, part, { create = false, expectedUid = process.getuid() } = {}) {
  assertPart(part)
  const target = path.join(parent, part)
  if (create) {
    try { fs.mkdirSync(target, { mode: 0o700 }) } catch (error) { if (error.code !== 'EEXIST') throw error }
  }
  const status = fs.lstatSync(target, { bigint: true })
  if (!status.isDirectory() || status.isSymbolicLink() || status.nlink < 2n || status.uid !== BigInt(expectedUid) || (status.mode & 0o077n) !== 0n) {
    failD931('D931_PATH_SUBSTITUTION', `directory is not protected: ${part}`)
  }
  return target
}

function fsyncDirectory(directory) {
  const procDescriptor = /^\/proc\/self\/fd\/(\d+)$/u.exec(directory)
  if (procDescriptor) {
    fs.fsyncSync(Number(procDescriptor[1]))
    return
  }
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try { fs.fsyncSync(descriptor) } finally { fs.closeSync(descriptor) }
}

function immutableRegularFile(file, { expectedLength = null, expectedUid = process.getuid() } = {}) {
  const before = fs.lstatSync(file, { bigint: true })
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o177n) !== 0n ||
      (expectedLength !== null && before.size !== BigInt(expectedLength))) {
    failD931('D931_OBJECT_UNPROTECTED', 'object is not a private single-link regular file of the expected length')
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true })
    for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
      if (before[key] !== opened[key]) failD931('D931_PATH_SUBSTITUTION', 'object identity changed while opening')
    }
  } catch (error) {
    fs.closeSync(descriptor)
    throw error
  }
  return descriptor
}

function readExactFile(file, expectedLength, expectedSha256, expectedUid) {
  const descriptor = immutableRegularFile(file, { expectedLength, expectedUid })
  try {
    const before = fs.fstatSync(descriptor, { bigint: true })
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor, { bigint: true })
    for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) if (before[key] !== after[key]) failD931('D931_OBJECT_CHANGED', 'object changed while it was hashed')
    if (bytes.length !== expectedLength || sha256Bytes(bytes) !== expectedSha256) failD931('D931_OBJECT_COLLISION', 'object bytes do not match their identity')
    return bytes
  } finally { fs.closeSync(descriptor) }
}

function safeInternalPath(rootDescriptor, parts, options = {}) {
  let current = descriptorRoot(rootDescriptor)
  for (const part of parts) current = inspectDirectory(current, part, options)
  return current
}

export function createDurableNamespaceStore({ rootPath, expectedUid = process.getuid(), namespaceCodes, faultInjector = null }) {
  if (!Array.isArray(namespaceCodes) || namespaceCodes.length === 0 || namespaceCodes.includes('pending') || new Set(namespaceCodes).size !== namespaceCodes.length) failD931('D931_NAMESPACE_INVALID', 'namespace inventory must be a nonempty unique array outside the reserved pending namespace')
  namespaceCodes.forEach(assertPart)
  const rootDescriptor = assertRoot(rootPath, expectedUid)
  const base = descriptorRoot(rootDescriptor)
  let pending
  try {
    const existingRootEntries = fs.readdirSync(base).toSorted()
    const expectedRootEntries = ['pending', ...namespaceCodes].toSorted()
    if (existingRootEntries.length > 0 && canonicalize(existingRootEntries) !== canonicalize(expectedRootEntries)) failD931('D931_NAMESPACE_INVALID', 'initialized protected store root is not the exact closed namespace inventory')
    const pendingWasPresent = fs.existsSync(path.join(base, 'pending'))
    pending = inspectDirectory(base, 'pending', { create: true, expectedUid })
    if (!pendingWasPresent) { fsyncDirectory(pending); fsyncDirectory(base) }
    if (fs.readdirSync(pending).length !== 0) failD931('D931_STORE_RECOVERY_REQUIRED', 'protected store contains an unresolved incomplete append')
    const created = []
    for (const code of namespaceCodes) {
      const target = path.join(base, code)
      if (!fs.existsSync(target)) created.push(target)
      inspectDirectory(base, code, { create: true, expectedUid })
    }
    for (const directory of created) fsyncDirectory(directory)
    if (created.length > 0) fsyncDirectory(base)
    const actualRootEntries = fs.readdirSync(base).toSorted()
    if (canonicalize(actualRootEntries) !== canonicalize(expectedRootEntries)) failD931('D931_NAMESPACE_INVALID', 'protected store root is not the exact closed namespace inventory')
  } catch (error) {
    fs.closeSync(rootDescriptor)
    throw error
  }
  let disposed = false
  let recoveryRequired = false
  const replay = new Map()

  function assertOperational() {
    if (disposed || !stores.has(store)) failD931('D931_STORE_CLOSED', 'durable namespace store is closed')
    if (recoveryRequired) failD931('D931_STORE_RECOVERY_REQUIRED', 'protected store has an unresolved in-process append boundary')
    const rootStatus = fs.fstatSync(rootDescriptor, { bigint: true })
    if (!rootStatus.isDirectory() || rootStatus.nlink < 2n || rootStatus.uid !== BigInt(expectedUid) || (rootStatus.mode & 0o077n) !== 0n) failD931('D931_ROOT_UNPROTECTED', 'live protected root descriptor is no longer owned and private')
    const actualRootEntries = fs.readdirSync(base).toSorted()
    const expectedRootEntries = ['pending', ...namespaceCodes].toSorted()
    if (canonicalize(actualRootEntries) !== canonicalize(expectedRootEntries)) failD931('D931_NAMESPACE_INVALID', 'live protected store root is not the exact closed namespace inventory')
    inspectDirectory(base, 'pending', { expectedUid })
    if (fs.readdirSync(pending).length !== 0) failD931('D931_STORE_RECOVERY_REQUIRED', 'live protected store contains an unresolved pending record')
  }

  const store = Object.freeze({
    namespaceCodes: Object.freeze([...namespaceCodes]),
    append({ namespaceCode, recordCode, bytes, replayKey = recordCode }) {
      assertOperational()
      if (!namespaceCodes.includes(namespaceCode)) failD931('D931_NAMESPACE_INVALID', 'namespace is outside the fixed inventory')
      assertPart(recordCode)
      assertPart(replayKey)
      if (!Buffer.isBuffer(bytes) || bytes.length === 0) failD931('D931_RECORD_INVALID', 'persisted record bytes must be a nonempty Buffer')
      const digest = sha256Bytes(bytes)
      const prior = replay.get(`${namespaceCode}/${replayKey}`)
      if (prior) {
        if (prior.digest !== digest || !prior.bytes.equals(bytes)) failD931('D931_REPLAY_COLLISION', 'same replay identity has different bytes')
        return Object.freeze({ created: false, digest, bytes: Buffer.from(prior.bytes), recordCode })
      }
      const directory = safeInternalPath(rootDescriptor, [namespaceCode], { expectedUid })
      const file = path.join(directory, recordCode)
      const pendingCode = `${namespaceCode}-${recordCode}-${randomBytes(12).toString('hex')}`
      const pendingFile = path.join(pending, pendingCode)
      let linked = false
      try {
        const descriptor = fs.openSync(pendingFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC, 0o600)
        try {
          fs.writeFileSync(descriptor, bytes)
          faultInjector?.('after_record_write', { namespaceCode, recordCode })
          fs.fsyncSync(descriptor)
          faultInjector?.('after_record_sync', { namespaceCode, recordCode })
        } finally { fs.closeSync(descriptor) }
        fsyncDirectory(pending)
        fs.linkSync(pendingFile, file)
        linked = true
        faultInjector?.('after_record_publish_before_directory_sync', { namespaceCode, recordCode })
        fsyncDirectory(directory)
        faultInjector?.('after_directory_sync', { namespaceCode, recordCode })
        fs.unlinkSync(pendingFile)
        fsyncDirectory(pending)
      } catch (error) {
        if (error.code === 'EEXIST') {
          recoveryRequired = true
          try {
            if (fs.existsSync(pendingFile)) fs.unlinkSync(pendingFile)
            fsyncDirectory(pending)
            const current = readExactFile(file, bytes.length, digest, expectedUid)
            const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
            try { fs.fsyncSync(descriptor) } finally { fs.closeSync(descriptor) }
            fsyncDirectory(directory)
            replay.set(`${namespaceCode}/${replayKey}`, { digest, bytes: current })
            recoveryRequired = false
            return Object.freeze({ created: false, digest, bytes: Buffer.from(current), recordCode })
          } catch (recoveryError) {
            throw recoveryError
          }
        }
        if (!linked && fs.existsSync(pendingFile)) {
          try {
            fs.unlinkSync(pendingFile)
            fsyncDirectory(pending)
          } catch (cleanupError) {
            recoveryRequired = true
            throw cleanupError
          }
        }
        if (linked || fs.existsSync(pendingFile)) recoveryRequired = true
        throw error
      }
      replay.set(`${namespaceCode}/${replayKey}`, { digest, bytes: Buffer.from(bytes) })
      return Object.freeze({ created: true, digest, bytes: Buffer.from(bytes), recordCode })
    },
    read({ namespaceCode, recordCode }) {
      assertOperational()
      if (!namespaceCodes.includes(namespaceCode)) failD931('D931_NAMESPACE_INVALID', 'namespace is outside the fixed inventory')
      assertPart(recordCode)
      const directory = safeInternalPath(rootDescriptor, [namespaceCode], { expectedUid })
      const file = path.join(directory, recordCode)
      const descriptor = immutableRegularFile(file, { expectedUid })
      try { return fs.readFileSync(descriptor) } finally { fs.closeSync(descriptor) }
    },
    inventory() {
      assertOperational()
      const result = {}
      for (const namespaceCode of namespaceCodes) {
        const directory = safeInternalPath(rootDescriptor, [namespaceCode], { expectedUid })
        result[namespaceCode] = fs.readdirSync(directory).toSorted().map((recordCode) => {
          assertPart(recordCode)
          const file = path.join(directory, recordCode)
          const descriptor = immutableRegularFile(file, { expectedUid })
          try {
            const bytes = fs.readFileSync(descriptor)
            return { record_code: recordCode, raw_sha256: sha256Bytes(bytes), byte_length: bytes.length }
          } finally { fs.closeSync(descriptor) }
        })
      }
      return Object.freeze({ projection: result, digest: sha256Bytes(Buffer.from(canonicalize(result), 'utf8')) })
    },
    close() {
      if (disposed) return
      disposed = true
      stores.delete(store)
      fs.closeSync(rootDescriptor)
    },
  })
  stores.add(store)
  return store
}

export function assertDurableNamespaceStore(value) {
  if (!stores.has(value)) failD931('D931_STORE_UNTRUSTED', 'store was not produced by the protected constructor')
  return value
}

export function durableJsonBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8')
}
