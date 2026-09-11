import fs from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { sha256Bytes } from '../control-plane/canonical.mjs'
import { failD931 } from './errors.mjs'

const instances = new WeakSet()
const SHA = /^[0-9a-f]{64}$/u
const LAYER_CODES = new Set(['retrieved_body', 'decoded_body', 'extracted_text', 'derived_binary'])

function fsyncDirectory(directory) {
  const procDescriptor = /^\/proc\/self\/fd\/(\d+)$/u.exec(directory)
  if (procDescriptor) {
    fs.fsyncSync(Number(procDescriptor[1]))
    return
  }
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
}

function protectedDirectory(directory, expectedUid, label) {
  const procDescriptor = /^\/proc\/self\/fd\/(\d+)$/u.exec(directory)
  const status = procDescriptor ? fs.fstatSync(Number(procDescriptor[1]), { bigint: true }) : fs.lstatSync(directory, { bigint: true })
  if (!status.isDirectory() || (!procDescriptor && status.isSymbolicLink()) || status.nlink < 2n || status.uid !== BigInt(expectedUid) || (status.mode & 0o077n) !== 0n) {
    failD931('D931_CAS_PATH_REJECTED', `${label} is not a protected directory`)
  }
  return status
}

function verifyArtifact(artifact) {
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact) ||
      artifact.hash_algorithm_code !== 'sha256' || !SHA.test(artifact.sha256) ||
      !LAYER_CODES.has(artifact.byte_layer_code) || !Number.isSafeInteger(artifact.byte_length) || artifact.byte_length < 0 || artifact.byte_length > 25 * 1024 * 1024) {
    failD931('D931_ARTIFACT_INVALID', 'artifact identity is outside the approved pilot shape')
  }
  return artifact
}

function referenceFor(artifact) {
  return `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}`
}

function readDescriptorExact(descriptor, artifact) {
  if (!Number.isInteger(descriptor) || descriptor < 0) failD931('D931_DESCRIPTOR_INVALID', 'source descriptor is invalid')
  const before = fs.fstatSync(descriptor, { bigint: true })
  if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(artifact.byte_length)) failD931('D931_SOURCE_REJECTED', 'source must be a single-link regular file of exact length')
  const bytes = Buffer.alloc(artifact.byte_length)
  let offset = 0
  while (offset < bytes.length) {
    const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset)
    if (count <= 0) failD931('D931_SOURCE_READ_FAILED', 'source ended before its declared length')
    offset += count
  }
  const after = fs.fstatSync(descriptor, { bigint: true })
  for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) if (before[key] !== after[key]) failD931('D931_SOURCE_CHANGED', 'source changed while it was read')
  if (sha256Bytes(bytes) !== artifact.sha256) failD931('D931_SOURCE_HASH_MISMATCH', 'source bytes do not match the artifact identity')
  return bytes
}

function readPathExact(file, artifact) {
  const before = fs.lstatSync(file, { bigint: true })
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size !== BigInt(artifact.byte_length) || (before.mode & 0o177n) !== 0n) {
    failD931('D931_CAS_OBJECT_REJECTED', 'CAS object is not a private single-link regular file')
  }
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try {
    const bytes = readDescriptorExact(fd, artifact)
    const opened = fs.fstatSync(fd, { bigint: true })
    if (before.dev !== opened.dev || before.ino !== opened.ino) failD931('D931_CAS_PATH_SUBSTITUTION', 'CAS object changed during open')
    return bytes
  } finally { fs.closeSync(fd) }
}

export function createRestrictedLocalCas({ protectedRootPath, expectedUid = process.getuid(), faultInjector = null }) {
  if (typeof protectedRootPath !== 'string' || !path.isAbsolute(protectedRootPath) || protectedRootPath.includes('\0')) failD931('D931_CAS_ROOT_INVALID', 'CAS root is not a fixed absolute protected path')
  const beforeRoot = protectedDirectory(protectedRootPath, expectedUid, 'CAS root')
  const rootDescriptor = fs.openSync(protectedRootPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try {
    const openedRoot = fs.fstatSync(rootDescriptor, { bigint: true })
    if (!openedRoot.isDirectory() || openedRoot.dev !== beforeRoot.dev || openedRoot.ino !== beforeRoot.ino || openedRoot.nlink < 2n || openedRoot.uid !== BigInt(expectedUid) || (openedRoot.mode & 0o077n) !== 0n) failD931('D931_CAS_PATH_REJECTED', 'opened CAS root identity or permissions differ from the validated path')
  } catch (error) {
    fs.closeSync(rootDescriptor)
    throw error
  }
  const root = `/proc/self/fd/${rootDescriptor}`
  const exactEntries = (directory, expected, label, { allowEmpty = false } = {}) => {
    const actual = fs.readdirSync(directory).toSorted()
    const exact = [...expected].toSorted()
    if (!(allowEmpty && actual.length === 0) && actual.join('\0') !== exact.join('\0')) failD931('D931_CAS_INVENTORY_CORRUPT', `${label} is not the exact fixed CAS layout`)
    return actual
  }
  const createDirectory = (parent, leaf) => {
    const target = path.join(parent, leaf)
    let created = false
    try { fs.mkdirSync(target, { mode: 0o700 }); created = true } catch (error) { if (error.code !== 'EEXIST') throw error }
    protectedDirectory(target, expectedUid, leaf)
    if (created) { fsyncDirectory(target); fsyncDirectory(parent) }
    return target
  }
  let tempDirectory
  let objectsDirectory
  let shaDirectory
  let recoveryRequired
  const fanoutNames = Array.from({ length: 256 }, (_, value) => value.toString(16).padStart(2, '0'))
  try {
    const initializing = exactEntries(root, ['private-temp', 'objects'], 'CAS root', { allowEmpty: true }).length === 0
    tempDirectory = createDirectory(root, 'private-temp')
    objectsDirectory = createDirectory(root, 'objects')
    exactEntries(objectsDirectory, ['sha256'], 'CAS objects directory', { allowEmpty: initializing })
    shaDirectory = createDirectory(objectsDirectory, 'sha256')
    exactEntries(shaDirectory, fanoutNames, 'CAS SHA directory', { allowEmpty: initializing })
    for (let value = 0; value < 256; value += 1) createDirectory(shaDirectory, value.toString(16).padStart(2, '0'))
    fsyncDirectory(shaDirectory)
    fsyncDirectory(objectsDirectory)
    fsyncDirectory(root)
    exactEntries(root, ['private-temp', 'objects'], 'CAS root')
    exactEntries(objectsDirectory, ['sha256'], 'CAS objects directory')
    exactEntries(shaDirectory, fanoutNames, 'CAS SHA directory')
    recoveryRequired = fs.readdirSync(tempDirectory).length !== 0
  } catch (error) {
    fs.closeSync(rootDescriptor)
    throw error
  }
  const preparations = new Map()
  let closed = false

  function assertLive() {
    if (closed || !instances.has(cas)) failD931('D931_CAS_CLOSED', 'CAS is closed')
  }

  function assertFixedLayout() {
    protectedDirectory(root, expectedUid, 'CAS root descriptor')
    protectedDirectory(tempDirectory, expectedUid, 'CAS private temporary directory')
    protectedDirectory(objectsDirectory, expectedUid, 'CAS objects directory')
    protectedDirectory(shaDirectory, expectedUid, 'CAS SHA directory')
    exactEntries(root, ['private-temp', 'objects'], 'CAS root')
    exactEntries(objectsDirectory, ['sha256'], 'CAS objects directory')
    exactEntries(shaDirectory, fanoutNames, 'CAS SHA directory')
  }

  function assertOperational() {
    assertLive()
    if (recoveryRequired) failD931('D931_CAS_RECOVERY_REQUIRED', 'CAS has unresolved temporary state; D9.3.1 is classification-only')
    try {
      assertFixedLayout()
    } catch (error) {
      if (preparations.size > 0) recoveryRequired = true
      throw error
    }
  }

  function paths(artifact) {
    verifyArtifact(artifact)
    protectedDirectory(root, expectedUid, 'CAS root descriptor')
    protectedDirectory(tempDirectory, expectedUid, 'CAS private temporary directory')
    protectedDirectory(objectsDirectory, expectedUid, 'CAS objects directory')
    protectedDirectory(shaDirectory, expectedUid, 'CAS SHA directory')
    const fanout = path.join(shaDirectory, artifact.sha256.slice(0, 2))
    protectedDirectory(fanout, expectedUid, 'CAS fanout directory')
    return { final: path.join(fanout, artifact.sha256), fanout }
  }

  const cas = Object.freeze({
    backendCode: 'pilot_local_cas_v1',
    prepare({ operationId, operationNonce, artifact, sourceDescriptor }) {
      assertOperational()
      if (typeof operationId !== 'string' || !/^[a-z0-9][a-z0-9._-]{1,94}[a-z0-9]$/u.test(operationId) || !SHA.test(operationNonce)) failD931('D931_OPERATION_INVALID', 'operation identity is invalid')
      verifyArtifact(artifact)
      const key = `${operationId}/${operationNonce}/${artifact.sha256}`
      if (preparations.has(key)) failD931('D931_PREPARATION_REPLAY', 'preparation already exists for this operation and artifact')
      const bytes = readDescriptorExact(sourceDescriptor, artifact)
      const leaf = `${operationNonce.slice(0, 24)}-${randomBytes(8).toString('hex')}.tmp`
      const file = path.join(tempDirectory, leaf)
      const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC, 0o600)
      try {
        try {
          fs.writeFileSync(fd, bytes)
          faultInjector?.('after_temporary_write')
          fs.fsyncSync(fd)
          faultInjector?.('after_temporary_sync')
        } finally { fs.closeSync(fd) }
        fsyncDirectory(tempDirectory)
      } catch (error) {
        recoveryRequired = true
        throw error
      }
      const handle = Object.freeze({ key, leaf, artifact: Object.freeze(structuredClone(artifact)), verified: false, consumed: false })
      preparations.set(key, handle)
      return handle
    },
    verifyPrepared(handle) {
      assertOperational()
      const current = preparations.get(handle?.key)
      if (current !== handle || handle.consumed) failD931('D931_PREPARATION_INVALID', 'preparation handle is not current')
      try { readPathExact(path.join(tempDirectory, handle.leaf), handle.artifact) } catch (error) { recoveryRequired = true; throw error }
      const verified = Object.freeze({ ...handle, verified: true })
      preparations.set(handle.key, verified)
      return verified
    },
    publishNoReplace(handle) {
      assertOperational()
      const current = preparations.get(handle?.key)
      if (current !== handle || !handle.verified || handle.consumed) failD931('D931_PREPARATION_INVALID', 'only the current verified preparation may publish')
      const temporary = path.join(tempDirectory, handle.leaf)
      let disposition
      try {
        const { final, fanout } = paths(handle.artifact)
        readPathExact(temporary, handle.artifact)
        faultInjector?.('before_publish')
        try {
          fs.linkSync(temporary, final)
          disposition = 'created_new'
          faultInjector?.('after_no_replace_publish')
        } catch (error) {
          if (error.code !== 'EEXIST') throw error
          disposition = 'existing_exact'
        }
        if (disposition === 'existing_exact') readPathExact(final, handle.artifact)
        const finalFd = fs.openSync(final, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
        try { fs.fsyncSync(finalFd) } finally { fs.closeSync(finalFd) }
        faultInjector?.('after_file_sync')
        fsyncDirectory(fanout)
        faultInjector?.('after_parent_sync')
        fs.unlinkSync(temporary)
        fsyncDirectory(tempDirectory)
        readPathExact(final, handle.artifact)
      } catch (error) {
        recoveryRequired = true
        throw error
      }
      preparations.delete(handle.key)
      return Object.freeze({
        backendCode: 'pilot_local_cas_v1',
        backendReference: referenceFor(handle.artifact),
        dispositionCode: disposition,
        outcomeCode: disposition === 'created_new' ? 'published' : 'reused_verified',
        fileDataSynced: true,
        parentDirectorySynced: true,
        fanoutAncestorsPreprovisionedAndSynced: true,
        noReplaceEnforced: true,
        reopenedAndRehashed: true,
      })
    },
    openIntegrity({ artifact, backendReference }) {
      assertOperational()
      const { final } = paths(artifact)
      if (backendReference !== referenceFor(artifact)) failD931('D931_BACKEND_REFERENCE_MISMATCH', 'reference is not the exact SHA-256 fanout path')
      readPathExact(final, artifact)
      return fs.openSync(final, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
    },
    verifyExisting({ artifact, backendReference }) {
      assertOperational()
      const { final } = paths(artifact)
      if (backendReference !== referenceFor(artifact)) failD931('D931_BACKEND_REFERENCE_MISMATCH', 'reference is not exact')
      readPathExact(final, artifact)
      return true
    },
    inventory() {
      assertOperational()
      const result = []
      for (let value = 0; value < 256; value += 1) {
        const fanout = path.join(shaDirectory, value.toString(16).padStart(2, '0'))
        protectedDirectory(fanout, expectedUid, 'CAS fanout directory')
        for (const leaf of fs.readdirSync(fanout).toSorted()) {
          if (!SHA.test(leaf) || !leaf.startsWith(value.toString(16).padStart(2, '0'))) failD931('D931_CAS_INVENTORY_CORRUPT', 'unexpected CAS key')
          const status = fs.lstatSync(path.join(fanout, leaf), { bigint: true })
          if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1n) failD931('D931_CAS_INVENTORY_CORRUPT', 'CAS inventory contains unsafe object')
          const descriptor = fs.openSync(path.join(fanout, leaf), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
          let digest
          try {
            const before = fs.fstatSync(descriptor, { bigint: true })
            const bytes = fs.readFileSync(descriptor)
            const after = fs.fstatSync(descriptor, { bigint: true })
            for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) if (before[key] !== after[key]) failD931('D931_CAS_INVENTORY_CORRUPT', 'CAS object changed during inventory')
            digest = sha256Bytes(bytes)
          } finally { fs.closeSync(descriptor) }
          if (digest !== leaf) failD931('D931_CAS_INVENTORY_CORRUPT', 'CAS filename does not match the rehashed bytes')
          result.push({ sha256: leaf, byte_length: Number(status.size), backend_reference: `objects/sha256/${leaf.slice(0, 2)}/${leaf}` })
        }
      }
      return Object.freeze(result)
    },
    inspectCrashState() {
      assertLive()
      assertFixedLayout()
      protectedDirectory(root, expectedUid, 'CAS root descriptor')
      protectedDirectory(tempDirectory, expectedUid, 'CAS private temporary directory')
      protectedDirectory(objectsDirectory, expectedUid, 'CAS objects directory')
      protectedDirectory(shaDirectory, expectedUid, 'CAS SHA directory')
      const temporaries = fs.readdirSync(tempDirectory).toSorted().map((leaf) => {
        const file = path.join(tempDirectory, leaf)
        const status = fs.lstatSync(file, { bigint: true })
        if (!/^[0-9a-f]{24}-[0-9a-f]{16}\.tmp$/u.test(leaf) || !status.isFile() || status.isSymbolicLink() || (status.mode & 0o177n) !== 0n) failD931('D931_CAS_INVENTORY_CORRUPT', 'private temporary inventory contains an unsafe object')
        const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
        try {
          const bytes = fs.readFileSync(descriptor)
          return { leaf, sha256: sha256Bytes(bytes), byte_length: bytes.length, device: String(status.dev), inode: String(status.ino), link_count: Number(status.nlink) }
        } finally { fs.closeSync(descriptor) }
      })
      const published = []
      for (let value = 0; value < 256; value += 1) {
        const fanout = path.join(shaDirectory, value.toString(16).padStart(2, '0'))
        protectedDirectory(fanout, expectedUid, 'CAS fanout directory')
        for (const leaf of fs.readdirSync(fanout).toSorted()) {
          if (!SHA.test(leaf) || !leaf.startsWith(value.toString(16).padStart(2, '0'))) failD931('D931_CAS_INVENTORY_CORRUPT', 'published inventory key is invalid or in the wrong fanout')
          const file = path.join(fanout, leaf)
          const status = fs.lstatSync(file, { bigint: true })
          if (!status.isFile() || status.isSymbolicLink() || status.uid !== BigInt(expectedUid) || (status.mode & 0o177n) !== 0n || ![1n, 2n].includes(status.nlink)) failD931('D931_CAS_INVENTORY_CORRUPT', 'published inventory object is unsafe')
          const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
          try {
            const bytes = fs.readFileSync(descriptor)
            const observedSha256 = sha256Bytes(bytes)
            if (observedSha256 !== leaf) failD931('D931_CAS_INVENTORY_CORRUPT', 'published object bytes do not match their content-addressed key')
            published.push({ sha256: leaf, observed_sha256: observedSha256, byte_length: bytes.length, device: String(status.dev), inode: String(status.ino), link_count: Number(status.nlink), backend_reference: `objects/sha256/${leaf.slice(0, 2)}/${leaf}` })
          } finally { fs.closeSync(descriptor) }
        }
      }
      const linked = temporaries.some((temporary) => published.some((object) => object.device === temporary.device && object.inode === temporary.inode))
      const unmatchedMultiplyLinked = published.some((object) => object.link_count !== 1 && !temporaries.some((temporary) => object.device === temporary.device && object.inode === temporary.inode))
      if (unmatchedMultiplyLinked) {
        recoveryRequired = true
        failD931('D931_CAS_INVENTORY_CORRUPT', 'published object has an unexplained additional hard link')
      }
      const stateCode = linked ? 'ambiguous_published_with_linked_temporary' : temporaries.length ? 'temporary_present' : 'stable'
      if (stateCode !== 'stable') recoveryRequired = true
      return Object.freeze({ stateCode, actionExecutionCode: 'none_classification_only', temporaries: Object.freeze(temporaries), published: Object.freeze(published) })
    },
    close() {
      if (closed) return
      closed = true
      instances.delete(cas)
      fs.closeSync(rootDescriptor)
    },
  })
  instances.add(cas)
  return cas
}

export function assertRestrictedLocalCas(value) {
  if (!instances.has(value)) failD931('D931_CAS_UNTRUSTED', 'CAS was not produced by the restricted constructor')
  return value
}

export { referenceFor as custodyReferenceFor }
