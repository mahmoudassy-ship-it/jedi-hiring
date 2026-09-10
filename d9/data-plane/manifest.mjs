import { spawnSync } from 'node:child_process'
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
} from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  canonicalSha256,
  canonicalize,
  parseStrictJson,
  sha256Bytes,
} from '../control-plane/canonical.mjs'

export const D9_EVIDENCE_MANIFEST_FORMAT = 'jedi-atlas-evidence-bundle'
export const D9_EVIDENCE_MANIFEST_VERSION = '1.0.0'
export const D9_EVIDENCE_MANIFEST_BYTES_MAX = 2 * 1024 * 1024
export const D9_EVIDENCE_MANIFEST_SCHEMA_SHA256 = '60c832c45498db04638b0dc769b64efffe3fe2a2fccc2f352bf29d78d15f07a1'

const nativeSource = fileURLToPath(new URL('./native/d9_manifest_reader.c', import.meta.url))
const schemaPath = fileURLToPath(new URL('../../docs/schema/tranche-2a-evidence-bundle-v1.schema.json', import.meta.url))
const fixedEnvironment = Object.freeze({ LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' })
const constructionToken = Symbol('D9 reviewed-manifest reader construction')
const verifiedReaders = new WeakSet()

export class D9ManifestError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`)
    this.name = 'D9ManifestError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = {}) {
  throw new D9ManifestError(code, message, details)
}

function safeRelativePath(value) {
  return typeof value === 'string'
    && Buffer.byteLength(value) >= 1
    && Buffer.byteLength(value) <= 240
    && /^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/u.test(value)
    && value.split('/').every((component) => component !== '.' && component !== '..' && Buffer.byteLength(component) <= 120)
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  if (ArrayBuffer.isView(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function closeDescriptor(descriptor) {
  try {
    closeSync(descriptor)
  } catch {
    // Cleanup is best-effort after a prior failure.
  }
}

function schemaTypeMatches(value, type) {
  if (type === 'null') return value === null
  if (type === 'array') return Array.isArray(value)
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value)
  if (type === 'integer') return typeof value === 'number' && Number.isSafeInteger(value)
  return typeof value === type
}

function resolveSchemaReference(root, reference) {
  if (typeof reference !== 'string' || !reference.startsWith('#/')) {
    fail('MANIFEST_SCHEMA_INVALID', 'the approved evidence schema contains an unsupported reference')
  }
  let node = root
  for (const encodedSegment of reference.slice(2).split('/')) {
    const segment = encodedSegment.replaceAll('~1', '/').replaceAll('~0', '~')
    if (!node || typeof node !== 'object' || !Object.hasOwn(node, segment)) {
      fail('MANIFEST_SCHEMA_INVALID', 'the approved evidence schema contains an unresolved reference')
    }
    node = node[segment]
  }
  return node
}

function schemaFailure(pointer, message) {
  fail('MANIFEST_SCHEMA_INVALID', `${pointer} ${message}`)
}

function matchesSchema(root, schema, value, pointer) {
  try {
    validateSchemaValue(root, schema, value, pointer)
    return true
  } catch (error) {
    if (error instanceof D9ManifestError && error.code === 'MANIFEST_SCHEMA_INVALID') return false
    throw error
  }
}

function validateSchemaValue(root, schema, value, pointer = '$') {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    schemaFailure(pointer, 'has an invalid approved-schema node')
  }
  if (schema.$ref) return validateSchemaValue(root, resolveSchemaReference(root, schema.$ref), value, pointer)

  for (const branch of schema.allOf ?? []) validateSchemaValue(root, branch, value, pointer)
  if (schema.if) {
    const conditionMatches = matchesSchema(root, schema.if, value, pointer)
    if (conditionMatches && schema.then) validateSchemaValue(root, schema.then, value, pointer)
    if (!conditionMatches && schema.else) validateSchemaValue(root, schema.else, value, pointer)
  }
  if (schema.anyOf) {
    if (!schema.anyOf.some((branch) => matchesSchema(root, branch, value, pointer))) {
      schemaFailure(pointer, 'must match at least one approved anyOf branch')
    }
    return
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((branch) => matchesSchema(root, branch, value, pointer))
    if (matches.length !== 1) schemaFailure(pointer, 'must match exactly one approved oneOf branch')
    return
  }

  if (Object.hasOwn(schema, 'const') && !Object.is(value, schema.const)) schemaFailure(pointer, 'does not match its constant')
  if (schema.enum && !schema.enum.some((item) => Object.is(item, value))) schemaFailure(pointer, 'is outside its closed values')
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    if (!types.some((type) => schemaTypeMatches(value, type))) schemaFailure(pointer, 'has the wrong type')
  }

  if (typeof value === 'string') {
    const scalarLength = Array.from(value).length
    if (schema.minLength !== undefined && scalarLength < schema.minLength) schemaFailure(pointer, 'is shorter than its minimum')
    if (schema.maxLength !== undefined && scalarLength > schema.maxLength) schemaFailure(pointer, 'is longer than its maximum')
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) schemaFailure(pointer, 'does not match its required shape')
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) schemaFailure(pointer, 'is below its minimum')
    if (schema.maximum !== undefined && value > schema.maximum) schemaFailure(pointer, 'is above its maximum')
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) schemaFailure(pointer, 'has too few items')
    if (schema.maxItems !== undefined && value.length > schema.maxItems) schemaFailure(pointer, 'has too many items')
    if (schema.uniqueItems) {
      const identities = value.map((item) => canonicalize(item))
      if (new Set(identities).size !== identities.length) schemaFailure(pointer, 'contains duplicate items')
    }
    if (schema.items) value.forEach((item, index) => validateSchemaValue(root, schema.items, item, `${pointer}/${index}`))
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value)
    if (schema.minProperties !== undefined && keys.length < schema.minProperties) schemaFailure(pointer, 'has too few members')
    if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) schemaFailure(pointer, 'has too many members')
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) schemaFailure(pointer, `is missing required member ${required}`)
    }
    for (const key of keys) {
      if (schema.propertyNames) validateSchemaValue(root, schema.propertyNames, key, `${pointer}/<key>`)
      if (schema.properties?.[key]) validateSchemaValue(root, schema.properties[key], value[key], `${pointer}/${key}`)
      else if (schema.additionalProperties === false) schemaFailure(pointer, `contains unknown member ${key}`)
      else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        validateSchemaValue(root, schema.additionalProperties, value[key], `${pointer}/${key}`)
      }
    }
  }
}

function approvedEvidenceSchema() {
  const bytes = readFileSync(schemaPath)
  const actualDigest = sha256Bytes(bytes)
  if (actualDigest !== D9_EVIDENCE_MANIFEST_SCHEMA_SHA256) {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'the approved evidence-manifest schema bytes changed', {
      actualDigest,
      expectedDigest: D9_EVIDENCE_MANIFEST_SCHEMA_SHA256,
    })
  }
  let schema
  try {
    schema = JSON.parse(bytes.toString('utf8'))
  } catch {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'the approved evidence-manifest schema is not valid JSON')
  }
  if (schema.$id !== 'https://jedi-hiring.invalid/schema/tranche-2a-evidence-bundle-v1.schema.json') {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'the approved evidence-manifest schema identity changed')
  }
  return schema
}

function mapNativeFailure(stderr, status, signal) {
  const line = stderr.toString('utf8').trim().split('\n')[0] ?? ''
  const [nativeCode, detail] = line.split(':', 2)
  const errno = Number.parseInt(detail ?? '', 10)
  if (nativeCode === 'OPENAT2_UNAVAILABLE') {
    fail('D9_PLATFORM_UNAVAILABLE', 'Linux openat2 confinement is unavailable', { errno, status, signal })
  }
  if (nativeCode === 'INPUT_OPEN_REJECTED') {
    if (errno === 40) fail('INPUT_SYMLINK_REJECTED', 'the reviewed manifest path contains a symbolic link')
    if (errno === 18) fail('INPUT_ROOT_ESCAPE', 'the reviewed manifest path escapes or crosses the reviewed root')
    if (errno === 2) fail('INPUT_NOT_FOUND', 'the reviewed manifest does not exist')
    fail('INPUT_PATH_INVALID', 'the reviewed manifest cannot be opened beneath its root', { errno })
  }
  const mapped = new Map([
    ['INPUT_PATH_INVALID', 'INPUT_PATH_INVALID'],
    ['INPUT_ROOT_INVALID', 'INPUT_PATH_INVALID'],
    ['INPUT_TYPE_REJECTED', 'INPUT_TYPE_REJECTED'],
    ['INPUT_SIZE_REJECTED', 'MANIFEST_TOO_LARGE'],
    ['INPUT_SHORT_READ', 'INPUT_CHANGED'],
    ['INPUT_CHANGED', 'INPUT_CHANGED'],
  ])
  fail(mapped.get(nativeCode) ?? 'INPUT_CHANGED', 'the reviewed manifest reader failed closed', {
    nativeCode: nativeCode || null,
    errno: Number.isNaN(errno) ? null : errno,
    status,
    signal,
  })
}

export class ReviewedManifestReader {
  #buildDirectory
  #disposed = false
  #executablePath
  #executableSha256

  constructor({ buildDirectory, executablePath, executableSha256, sourceSha256 }, token) {
    if (token !== constructionToken) fail('D9_PLATFORM_UNAVAILABLE', 'reviewed-manifest readers must come from the pinned compiler path')
    this.#buildDirectory = buildDirectory
    this.#executablePath = executablePath
    this.#executableSha256 = executableSha256
    this.sourceSha256 = sourceSha256
    verifiedReaders.add(this)
    Object.freeze(this)
  }

  #assertLive() {
    if (this.#disposed) fail('D9_PLATFORM_UNAVAILABLE', 'the reviewed-manifest reader has been disposed')
  }

  read({ reviewedRootDescriptor, manifestRelativePath, maximumBytes = D9_EVIDENCE_MANIFEST_BYTES_MAX }) {
    this.#assertLive()
    if (!Number.isInteger(reviewedRootDescriptor) || reviewedRootDescriptor < 0) {
      fail('INPUT_PATH_INVALID', 'reviewedRootDescriptor must be an open directory descriptor')
    }
    if (!safeRelativePath(manifestRelativePath)) fail('INPUT_PATH_INVALID', 'manifestRelativePath is outside the closed relative-path shape')
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > D9_EVIDENCE_MANIFEST_BYTES_MAX) {
      fail('MANIFEST_TOO_LARGE', 'maximumBytes exceeds the approved manifest ceiling')
    }
    let rootStats
    try {
      rootStats = fstatSync(reviewedRootDescriptor)
    } catch (error) {
      fail('INPUT_PATH_INVALID', 'the reviewed-root descriptor is unavailable', { cause: error.message })
    }
    if (!rootStats.isDirectory()) fail('INPUT_PATH_INVALID', 'the reviewed-root descriptor is not a directory')

    let executableDescriptor
    try {
      executableDescriptor = openSync(this.#executablePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_CLOEXEC ?? 0))
      const executableBytes = readFileSync(executableDescriptor)
      if (sha256Bytes(executableBytes) !== this.#executableSha256) {
        fail('D9_PLATFORM_UNAVAILABLE', 'the native manifest reader build changed after verification')
      }
      const result = spawnSync('/proc/self/fd/4', [manifestRelativePath, String(maximumBytes)], {
        encoding: null,
        env: fixedEnvironment,
        maxBuffer: maximumBytes + 4096,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe', reviewedRootDescriptor, executableDescriptor],
        timeout: 10_000,
      })
      if (result.error) fail('D9_PLATFORM_UNAVAILABLE', 'the native manifest reader could not execute', { cause: result.error.message })
      if (result.status !== 0 || result.signal !== null) mapNativeFailure(result.stderr ?? Buffer.alloc(0), result.status, result.signal)
      if ((result.stderr?.length ?? 0) !== 0) fail('D9_PLATFORM_UNAVAILABLE', 'the native manifest reader emitted unexpected diagnostic bytes')
      if (!Buffer.isBuffer(result.stdout) || result.stdout.length < 1 || result.stdout.length > maximumBytes) {
        fail('MANIFEST_TOO_LARGE', 'the native manifest reader returned an invalid byte count')
      }
      return Buffer.from(result.stdout)
    } finally {
      if (executableDescriptor !== undefined) closeDescriptor(executableDescriptor)
    }
  }

  dispose() {
    if (this.#disposed) return
    this.#disposed = true
    rmSync(this.#buildDirectory, { force: true, recursive: true })
  }
}

export function compileReviewedManifestReader({ forceOpenat2Unavailable = false } = {}) {
  if (process.platform !== 'linux') fail('D9_PLATFORM_UNAVAILABLE', 'the reviewed-manifest boundary requires Linux openat2')
  if (typeof forceOpenat2Unavailable !== 'boolean') fail('D9_PLATFORM_UNAVAILABLE', 'forceOpenat2Unavailable must be boolean')
  const compiler = '/usr/bin/cc'
  const buildDirectory = mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-manifest-reader-'))
  const executablePath = path.join(buildDirectory, 'd9-manifest-reader')
  try {
    const sourceBytes = readFileSync(nativeSource)
    const compile = spawnSync(compiler, [
      '-std=c11',
      '-O2',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-pedantic',
      forceOpenat2Unavailable ? '-DD9_FORCE_OPENAT2_UNAVAILABLE=1' : '-DD9_FORCE_OPENAT2_UNAVAILABLE=0',
      nativeSource,
      '-o',
      executablePath,
    ], {
      encoding: 'utf8',
      env: fixedEnvironment,
      shell: false,
    })
    if (compile.error || compile.status !== 0) {
      fail('D9_PLATFORM_UNAVAILABLE', 'the native reviewed-manifest reader failed to compile', {
        cause: compile.error?.message ?? null,
        status: compile.status,
        stderr: compile.stderr,
      })
    }
    return new ReviewedManifestReader({
      buildDirectory,
      executablePath,
      executableSha256: sha256Bytes(readFileSync(executablePath)),
      sourceSha256: sha256Bytes(sourceBytes),
    }, constructionToken)
  } catch (error) {
    rmSync(buildDirectory, { force: true, recursive: true })
    if (error instanceof D9ManifestError) throw error
    fail('D9_PLATFORM_UNAVAILABLE', 'the native reviewed-manifest reader could not be prepared', { cause: error.message })
  }
}

export function parseApprovedEvidenceManifest(manifestBytes) {
  let manifest
  try {
    manifest = parseStrictJson(manifestBytes, {
      contractNumbers: true,
      maximumBytes: D9_EVIDENCE_MANIFEST_BYTES_MAX,
      maximumDepth: 32,
      maximumMembers: 4096,
    })
  } catch (error) {
    if (error?.code === 'INVALID_SIZE') fail('MANIFEST_TOO_LARGE', 'manifest bytes are outside the approved limit')
    if (error?.code === 'INVALID_ENCODING') fail('MANIFEST_ENCODING_INVALID', 'manifest bytes are not approved UTF-8')
    fail('MANIFEST_SCHEMA_INVALID', 'manifest bytes are not valid strict contract JSON', { cause: error.message })
  }
  if (manifest.format !== D9_EVIDENCE_MANIFEST_FORMAT || manifest.format_version !== D9_EVIDENCE_MANIFEST_VERSION) {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'manifest format or version is not approved')
  }
  const schema = approvedEvidenceSchema()
  validateSchemaValue(schema, schema, manifest)
  const actualDigest = canonicalSha256(manifest, { excludedTopLevelField: 'bundle_digest_sha256' })
  if (manifest.bundle_digest_sha256 !== actualDigest) {
    fail('MANIFEST_DIGEST_MISMATCH', 'the canonical bundle digest does not match the manifest', {
      actualDigest,
      declaredDigest: manifest.bundle_digest_sha256,
    })
  }
  return Object.freeze({
    bundleDigestSha256: actualDigest,
    canonicalPayloadBytes: Buffer.from(canonicalize(Object.fromEntries(
      Object.entries(manifest).filter(([key]) => key !== 'bundle_digest_sha256'),
    )), 'utf8'),
    manifest: deepFreeze(manifest),
  })
}

export function openApprovedEvidenceManifest({
  manifestRelativePath,
  reader,
  reviewedRootDescriptor,
}) {
  if (!verifiedReaders.has(reader)) fail('D9_PLATFORM_UNAVAILABLE', 'reader is not a verified reviewed-manifest reader')
  const manifestBytes = reader.read({ reviewedRootDescriptor, manifestRelativePath })
  const parsed = parseApprovedEvidenceManifest(manifestBytes)
  if (parsed.manifest.manifest_path !== manifestRelativePath) {
    fail('MANIFEST_PATH_MISMATCH', 'the opened reviewed path differs from the manifest declaration')
  }
  return Object.freeze({
    ...parsed,
    manifestBytes,
    manifestBytesSha256: sha256Bytes(manifestBytes),
    manifestRelativePath,
  })
}
