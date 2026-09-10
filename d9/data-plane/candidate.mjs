import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { backup, DatabaseSync } from 'node:sqlite'
import { logicalStateDigest, verifyDatabaseHealth } from './projection.mjs'
import { failD92 } from './errors.mjs'

const sources = new WeakMap()
const candidates = new WeakMap()
const generations = new WeakMap()

function sameIdentity(left, right) {
  return ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs'].every((field) => left[field] === right[field])
}

function sameStableIdentity(left, right) {
  return ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid'].every((field) => left[field] === right[field])
}

function assertSingleRegularFile(stat, code, label) {
  if (!stat.isFile() || stat.nlink !== 1n) failD92(code, `${label} must be a single-link regular file`)
}

function openBoundPath(filePath, expected, flags, code, label, { mutableContent = false } = {}) {
  let pathStat
  try { pathStat = fs.lstatSync(filePath, { bigint: true }) } catch (error) {
    failD92(code, `${label} path is unavailable`, { cause: error })
  }
  if (pathStat.isSymbolicLink()) failD92(code, `${label} path must not be a symbolic link`)
  assertSingleRegularFile(pathStat, code, label)
  const expectedMatches = mutableContent ? sameStableIdentity : sameIdentity
  if (expected && !expectedMatches(pathStat, expected)) failD92(code, `${label} path identity changed`)
  const descriptor = fs.openSync(filePath, flags | fs.constants.O_CLOEXEC | (fs.constants.O_NOFOLLOW ?? 0))
  const held = fs.fstatSync(descriptor, { bigint: true })
  if (!sameIdentity(pathStat, held)) {
    fs.closeSync(descriptor)
    failD92(code, `${label} identity changed while opening`)
  }
  return { descriptor, identity: held }
}

function assertSourceIdentity(source) {
  const details = sources.get(source)
  if (!details) failD92('DATABASE_SOURCE_UNTRUSTED', 'database source is not a live D9.2 descriptor-bound source')
  let current
  try { current = fs.fstatSync(details.descriptor, { bigint: true }) } catch (error) {
    failD92('DATABASE_SOURCE_CHANGED', 'source database descriptor is unavailable', { cause: error })
  }
  if (!sameIdentity(current, details.identity)) failD92('DATABASE_SOURCE_CHANGED', 'source database descriptor identity changed')
  return details
}

export function openSyntheticReadOnlyDatabaseDescriptor(descriptor) {
  if (!Number.isInteger(descriptor) || descriptor < 0) failD92('DATABASE_DESCRIPTOR_INVALID', 'database descriptor must be nonnegative')
  const before = fs.fstatSync(descriptor, { bigint: true })
  assertSingleRegularFile(before, 'DATABASE_DESCRIPTOR_INVALID', 'database descriptor')
  const database = new DatabaseSync(`/proc/self/fd/${descriptor}`, { readOnly: true })
  database.exec('PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON')
  verifyDatabaseHealth(database)
  const after = fs.fstatSync(descriptor, { bigint: true })
  if (!sameIdentity(before, after)) {
    database.close()
    failD92('DATABASE_SOURCE_CHANGED', 'source database identity changed while opening')
  }
  const source = Object.freeze({
    syntheticTestDouble: true,
    database,
    identity: Object.freeze({ device: before.dev.toString(), inode: before.ino.toString(), size: before.size.toString() }),
    close() {
      if (!sources.has(source)) return
      sources.delete(source)
      database.close()
    },
  })
  sources.set(source, { descriptor, identity: before })
  return source
}

export function assertSyntheticReadOnlySource(source) {
  assertSourceIdentity(source)
  return source
}

export async function cloneDisposableCandidate({ source }) {
  assertSourceIdentity(source)
  const before = logicalStateDigest(source.database)
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-candidate-'))
  fs.chmodSync(root, 0o700)
  const candidateDatabasePath = path.join(root, 'candidate.sqlite')
  try {
    await backup(source.database, candidateDatabasePath)
    assertSourceIdentity(source)
    const after = logicalStateDigest(source.database)
    if (after !== before) failD92('DATABASE_SOURCE_CHANGED', 'source database changed during clone')
    const stat = fs.lstatSync(candidateDatabasePath, { bigint: true })
    assertSingleRegularFile(stat, 'CANDIDATE_INVALID', 'candidate backup')
    const database = new DatabaseSync(candidateDatabasePath, { readOnly: true })
    try {
      verifyDatabaseHealth(database)
      if (logicalStateDigest(database) !== before) failD92('CANDIDATE_CLONE_MISMATCH', 'candidate clone differs from its source')
    } finally { database.close() }
    const candidate = Object.freeze({
      candidateDatabasePath,
      root,
      sourceLogicalStateSha256: before,
      syntheticTestDouble: true,
      dispose() {
        if (!candidates.has(candidate)) return
        candidates.delete(candidate)
        fs.rmSync(root, { recursive: true, force: true })
      },
    })
    candidates.set(candidate, { identity: stat })
    return candidate
  } catch (error) {
    fs.rmSync(root, { recursive: true, force: true })
    throw error
  }
}

export function assertDisposableCandidate(candidate) {
  const details = candidates.get(candidate)
  if (!details) failD92('CANDIDATE_UNTRUSTED', 'candidate is not a live D9.2 disposable clone')
  const current = fs.lstatSync(candidate.candidateDatabasePath, { bigint: true })
  if (current.isSymbolicLink() || !sameStableIdentity(current, details.identity)) failD92('CANDIDATE_CHANGED', 'candidate path identity changed')
  return candidate
}

export function openDisposableCandidateDescriptor(candidate, { writable = false } = {}) {
  assertDisposableCandidate(candidate)
  const details = candidates.get(candidate)
  return openBoundPath(
    candidate.candidateDatabasePath,
    details.identity,
    writable ? fs.constants.O_RDWR : fs.constants.O_RDONLY,
    'CANDIDATE_CHANGED',
    'candidate',
    { mutableContent: true },
  ).descriptor
}

export function withCandidateReadOnly(candidate, callback) {
  if (typeof callback !== 'function') failD92('CANDIDATE_UNTRUSTED', 'candidate reader callback is required')
  const descriptor = openDisposableCandidateDescriptor(candidate)
  const database = new DatabaseSync(`/proc/self/fd/${descriptor}`, { readOnly: true })
  try {
    database.exec('PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON')
    verifyDatabaseHealth(database)
    return callback(database)
  } finally {
    database.close()
    fs.closeSync(descriptor)
  }
}

export function copySyntheticTestGeneration(candidate) {
  const descriptor = openDisposableCandidateDescriptor(candidate)
  const generationPath = path.join(candidate.root, 'synthetic-post-copy-generation.sqlite')
  try {
    fs.copyFileSync(`/proc/self/fd/${descriptor}`, generationPath, fs.constants.COPYFILE_EXCL)
  } finally { fs.closeSync(descriptor) }
  fs.chmodSync(generationPath, 0o400)
  const stat = fs.lstatSync(generationPath, { bigint: true })
  assertSingleRegularFile(stat, 'SYNTHETIC_COPY_INVALID', 'synthetic post-copy generation')
  const generation = Object.freeze({ generationPath, syntheticTestDouble: true })
  generations.set(generation, { identity: stat })
  return generation
}

export function withSyntheticGenerationReadOnly(generation, callback) {
  const details = generations.get(generation)
  if (!details) failD92('SYNTHETIC_COPY_INVALID', 'post-copy generation is not a live D9.2 synthetic copy')
  const { descriptor } = openBoundPath(generation.generationPath, details.identity, fs.constants.O_RDONLY, 'SYNTHETIC_COPY_CHANGED', 'synthetic post-copy generation')
  const database = new DatabaseSync(`/proc/self/fd/${descriptor}`, { readOnly: true })
  try {
    database.exec('PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON')
    verifyDatabaseHealth(database)
    return callback(database)
  } finally {
    database.close()
    fs.closeSync(descriptor)
  }
}
