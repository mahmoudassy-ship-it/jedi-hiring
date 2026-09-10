import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256Bytes } from '../control-plane/canonical.mjs'
import { failD92 } from './errors.mjs'

export const D9_ARTIFACT_BYTES_MAX = 25 * 1024 * 1024
const nativeSource = fileURLToPath(new URL('./native/d9_artifact_reader.c', import.meta.url))
const readers = new WeakSet()
const adapters = new WeakSet()

function duplicateDirectoryDescriptor(descriptor, label) {
  if (!Number.isInteger(descriptor) || descriptor < 0) failD92('BYTE_ROOT_INVALID', `${label} descriptor is invalid`)
  let before
  try { before = fs.fstatSync(descriptor) } catch (error) {
    failD92('BYTE_ROOT_INVALID', `${label} descriptor is unavailable`, { cause: error })
  }
  if (!before.isDirectory()) failD92('BYTE_ROOT_INVALID', `${label} descriptor is not a directory`)
  let duplicate
  try {
    duplicate = fs.openSync(`/proc/self/fd/${descriptor}`, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_CLOEXEC)
    const after = fs.fstatSync(duplicate)
    if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino) {
      failD92('BYTE_ROOT_INVALID', `${label} descriptor changed while it was bound`)
    }
    return duplicate
  } catch (error) {
    if (duplicate !== undefined) fs.closeSync(duplicate)
    if (error?.code?.startsWith?.('BYTE_')) throw error
    failD92('BYTE_ROOT_INVALID', `${label} descriptor could not be pinned`, { cause: error })
  }
}

function safeReference(value) {
  return typeof value === 'string' && Buffer.byteLength(value) >= 1 && Buffer.byteLength(value) <= 512
    && /^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/u.test(value)
    && value.split('/').every((part) => part !== '.' && part !== '..' && Buffer.byteLength(part) <= 180)
}

function compile() {
  if (process.platform !== 'linux') failD92('BYTE_PLATFORM_UNAVAILABLE', 'artifact reader requires Linux openat2')
  const buildDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-artifact-reader-'))
  const executable = path.join(buildDirectory, 'reader')
  const result = spawnSync('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic', nativeSource, '-o', executable], {
    encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }, shell: false,
  })
  if (result.error || result.status !== 0) {
    fs.rmSync(buildDirectory, { recursive: true, force: true })
    failD92('BYTE_PLATFORM_UNAVAILABLE', 'artifact reader compilation failed', { cause: result.error, stderr: result.stderr })
  }
  const executableSha256 = sha256Bytes(fs.readFileSync(executable))
  const reader = Object.freeze({
    read({ rootDescriptor, relativePath, expectedByteLength }) {
      if (!readers.has(reader)) failD92('BYTE_READER_UNTRUSTED', 'artifact reader is not verified')
      if (!Number.isInteger(rootDescriptor) || rootDescriptor < 0 || !fs.fstatSync(rootDescriptor).isDirectory()) failD92('BYTE_ROOT_INVALID', 'artifact root descriptor is invalid')
      if (!safeReference(relativePath)) failD92('BYTE_PATH_INVALID', 'artifact reference is not a safe relative path')
      if (!Number.isSafeInteger(expectedByteLength) || expectedByteLength < 0 || expectedByteLength > D9_ARTIFACT_BYTES_MAX) failD92('BYTE_SIZE_INVALID', 'artifact byte length is outside the pilot limit')
      const currentDigest = sha256Bytes(fs.readFileSync(executable))
      if (currentDigest !== executableSha256) failD92('BYTE_READER_CHANGED', 'artifact reader binary changed')
      const descriptor = fs.openSync(executable, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
      try {
        const child = spawnSync('/proc/self/fd/4', [relativePath, String(expectedByteLength)], {
          encoding: null, env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }, maxBuffer: expectedByteLength + 4096,
          shell: false, stdio: ['ignore', 'pipe', 'pipe', rootDescriptor, descriptor], timeout: 10_000,
        })
        if (child.error || child.status !== 0 || child.signal) failD92('BYTE_OPEN_FAILED', 'artifact could not be opened and verified beneath its root', { cause: child.error, stderr: child.stderr?.toString('utf8') })
        if (!Buffer.isBuffer(child.stdout) || child.stdout.length !== expectedByteLength) failD92('BYTE_SIZE_MISMATCH', 'artifact bytes differ in length')
        return Buffer.from(child.stdout)
      } finally { fs.closeSync(descriptor) }
    },
    dispose() { readers.delete(reader); fs.rmSync(buildDirectory, { recursive: true, force: true }) },
  })
  readers.add(reader)
  return reader
}

export function createSyntheticReadOnlyByteAdapter({ stagingRootDescriptor, backendRootDescriptors }) {
  if (!(backendRootDescriptors instanceof Map)) failD92('BYTE_ROOT_INVALID', 'backend descriptors must be a Map')
  const pinnedDescriptors = []
  let pinnedStagingRootDescriptor
  const pinnedBackendRootDescriptors = new Map()
  try {
    pinnedStagingRootDescriptor = duplicateDirectoryDescriptor(stagingRootDescriptor, 'staging root')
    pinnedDescriptors.push(pinnedStagingRootDescriptor)
    for (const [code, descriptor] of backendRootDescriptors) {
      if (typeof code !== 'string' || code.length === 0 || pinnedBackendRootDescriptors.has(code)) failD92('BYTE_ROOT_INVALID', 'backend descriptor binding is invalid')
      const pinned = duplicateDirectoryDescriptor(descriptor, `backend ${code}`)
      pinnedDescriptors.push(pinned)
      pinnedBackendRootDescriptors.set(code, pinned)
    }
  } catch (error) {
    for (const descriptor of pinnedDescriptors) fs.closeSync(descriptor)
    throw error
  }
  let reader
  try { reader = compile() } catch (error) {
    for (const descriptor of pinnedDescriptors) fs.closeSync(descriptor)
    throw error
  }
  let disposed = false
  const adapter = Object.freeze({
    syntheticTestDouble: true,
    readStaged(artifact) { return reader.read({ rootDescriptor: pinnedStagingRootDescriptor, relativePath: artifact.staged_path, expectedByteLength: artifact.byte_length }) },
    readCustody({ artifact, backendCode, backendReference }) {
      const descriptor = pinnedBackendRootDescriptors.get(backendCode)
      if (descriptor === undefined) failD92('CUSTODY_ADAPTER_UNAVAILABLE', `synthetic backend is unavailable: ${backendCode}`)
      return reader.read({ rootDescriptor: descriptor, relativePath: backendReference, expectedByteLength: artifact.byte_length })
    },
    dispose() {
      if (disposed) return
      disposed = true
      adapters.delete(adapter)
      reader.dispose()
      for (const descriptor of pinnedDescriptors) fs.closeSync(descriptor)
    },
  })
  adapters.add(adapter)
  return adapter
}

export function assertSyntheticByteAdapter(adapter) {
  if (!adapters.has(adapter) || adapter.syntheticTestDouble !== true) failD92('CUSTODY_ADAPTER_UNAVAILABLE', 'D9.2 requires the explicit synthetic read-only byte test double')
  return adapter
}

function assertBytes(artifact, bytes, label) {
  if (bytes.length !== artifact.byte_length || sha256Bytes(bytes) !== artifact.sha256) failD92('ARTIFACT_INTEGRITY_MISMATCH', `${label} bytes do not match ${artifact.record_code}`)
}

function artifactResolver(database, manifest) {
  const result = new Map(database.prepare('SELECT artifact_code,byte_layer_code,sha256,byte_length FROM atlas_artifacts').all().map((row) => [row.artifact_code, { ...row, record_code: row.artifact_code }]))
  for (const artifact of manifest.artifacts) result.set(artifact.record_code, artifact)
  return result
}

function readCurrentArtifactBytes({ artifact, byteAdapter, database }) {
  const events = database.prepare(`SELECT c.* FROM atlas_artifact_custody_events c
    JOIN atlas_artifacts a ON a.id=c.artifact_id WHERE a.artifact_code=?
    ORDER BY c.custody_event_code COLLATE BINARY ASC`).all(artifact.record_code)
  const predecessors = new Set(events.filter((row) => row.predecessor_custody_event_id !== null).map((row) => row.predecessor_custody_event_id))
  const leaf = events.find((row) => !predecessors.has(row.id) && ['placed', 'relocated', 'restored'].includes(row.event_kind_code))
  if (!leaf) failD92('CUSTODY_UNAVAILABLE', `candidate locator bytes are unavailable: ${artifact.record_code}`)
  const bytes = byteAdapter.readCustody({ artifact, backendCode: leaf.backend_code, backendReference: leaf.backend_reference })
  assertBytes(artifact, bytes, 'custody')
  return bytes
}

export function verifyStagedManifestArtifacts({ manifest, byteAdapter, database }) {
  assertSyntheticByteAdapter(byteAdapter)
  const artifacts = artifactResolver(database, manifest)
  let occurrenceCount = 0
  for (const artifact of manifest.artifacts) {
    assertBytes(artifact, byteAdapter.readStaged(artifact), 'artifact declaration')
    occurrenceCount += 1
  }
  for (const event of manifest.retrieval_events.filter((row) => row.outcome_code === 'retrieved_retained')) {
    const artifact = artifacts.get(event.artifact_code)
    if (!artifact) failD92('ARTIFACT_REFERENCE_INVALID', `retrieval artifact is unavailable: ${event.artifact_code}`)
    assertBytes(artifact, byteAdapter.readStaged({ ...artifact, staged_path: event.artifact_staged_path }), 'retained retrieval occurrence')
    occurrenceCount += 1
  }
  const outputBytes = new Map()
  for (const run of manifest.processing_runs) {
    for (const output of run.outputs) {
      const artifact = artifacts.get(output.artifact_code)
      if (!artifact) failD92('ARTIFACT_REFERENCE_INVALID', `processing output artifact is unavailable: ${output.artifact_code}`)
      const bytes = byteAdapter.readStaged({ ...artifact, staged_path: output.staged_path })
      assertBytes(artifact, bytes, 'processing output occurrence')
      outputBytes.set(output.record_code, bytes)
      occurrenceCount += 1
    }
  }
  for (const candidate of manifest.candidate_occurrences) {
    if (candidate.locator_kind_code !== 'text_span') continue
    let bytes = outputBytes.get(candidate.processing_output_code)
    if (!bytes) {
      const output = database.prepare(`SELECT a.artifact_code,a.byte_layer_code,a.sha256,a.byte_length
        FROM atlas_processing_outputs o JOIN atlas_artifacts a ON a.id=o.artifact_id
        WHERE o.processing_output_code=?`).get(candidate.processing_output_code)
      if (!output) failD92('ARTIFACT_REFERENCE_INVALID', `candidate output is unavailable: ${candidate.processing_output_code}`)
      const artifact = { ...output, record_code: output.artifact_code }
      bytes = readCurrentArtifactBytes({ artifact, byteAdapter, database })
    }
    let text
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes) } catch (error) {
      failD92('CANDIDATE_TEXT_INVALID', 'text_span requires valid UTF-8 output bytes', { cause: error })
    }
    if (candidate.span_end > Array.from(text).length) failD92('CANDIDATE_SPAN_INVALID', 'text_span exceeds the output Unicode-scalar length')
  }
  return Object.freeze({ artifactIdentityOccurrences: manifest.artifacts.length, byteOccurrencesChecked: occurrenceCount })
}

export function verifyCurrentCustodyBytes({ database, byteAdapter, throughBundleSequence = null }) {
  assertSyntheticByteAdapter(byteAdapter)
  if (throughBundleSequence !== null && (!Number.isSafeInteger(throughBundleSequence) || throughBundleSequence <= 0)) {
    failD92('CUSTODY_PROJECTION_INVALID', 'custody bundle-sequence bound is invalid')
  }
  const boundPredicate = throughBundleSequence === null
    ? ''
    : ' WHERE evidence_bundle_receipt_id IN (SELECT id FROM atlas_evidence_bundle_receipts WHERE bundle_sequence <= ?)'
  const parameters = throughBundleSequence === null ? [] : [throughBundleSequence]
  const artifacts = new Map(database.prepare(`SELECT id,artifact_code,sha256,byte_length FROM atlas_artifacts${boundPredicate}`).all(...parameters)
    .map((row) => [row.id, { ...row, record_code: row.artifact_code }]))
  const events = database.prepare(`SELECT c.*,r.bundle_sequence FROM atlas_artifact_custody_events c
    JOIN atlas_evidence_bundle_receipts r ON r.id=c.evidence_bundle_receipt_id
    ${throughBundleSequence === null ? '' : 'WHERE r.bundle_sequence <= ?'}
    ORDER BY r.bundle_sequence,c.recorded_at,c.id`).all(...parameters)
  const successors = new Set(events.filter((row) => row.predecessor_custody_event_id !== null).map((row) => row.predecessor_custody_event_id))
  let checked = 0
  for (const event of events.filter((row) => !successors.has(row.id))) {
    if (event.event_kind_code === 'tombstoned') continue
    if (!['placed', 'relocated', 'restored'].includes(event.event_kind_code)) failD92('CUSTODY_UNAVAILABLE', `current custody leaf is not readable: ${event.custody_event_code}`)
    const artifact = artifacts.get(event.artifact_id)
    if (!artifact) failD92('CUSTODY_REFERENCE_INVALID', 'custody artifact is absent')
    assertBytes(artifact, byteAdapter.readCustody({ artifact, backendCode: event.backend_code, backendReference: event.backend_reference }), 'custody')
    checked += 1
  }
  return checked
}
