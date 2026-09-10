import fs from 'node:fs'
import path from 'node:path'
import { canonicalSha256, canonicalize, parseStrictJson, sha256Bytes } from './canonical.mjs'
import { assertVerifiedRuntimeGeneration } from './contracts.mjs'

export const CONTROL_PLANE_SOURCE_FILES = Object.freeze([
  'd9/control-plane/build-integrity.mjs',
  'd9/control-plane/canonical.mjs',
  'd9/control-plane/ceremony-semantics.mjs',
  'd9/control-plane/contracts.mjs',
  'd9/control-plane/empty-state.mjs',
  'd9/control-plane/identity.mjs',
  'd9/control-plane/launcher.mjs',
  'd9/control-plane/native/d9_linux.c',
  'd9/control-plane/platform.mjs',
  'd9/control-plane/scopes.mjs',
  'd9/control-plane/state-append-broker.mjs',
  'd9/control-plane/state-store.mjs',
  'package-lock.json',
  'package.json',
])

const verifiedBuilds = new WeakSet()
const HASH_PATTERN = /^[0-9a-f]{64}$/u

export class D9BuildIntegrityError extends Error {
  constructor(code, message, options) {
    super(`${code}: ${message}`, options)
    this.name = 'D9BuildIntegrityError'
    this.code = code
  }
}

function fail(code, message, options) {
  throw new D9BuildIntegrityError(code, message, options)
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('CONTROL_PLANE_BUILD_INVALID', `${label} must be an object`)
  const actual = Object.keys(value).toSorted()
  const wanted = [...expected].toSorted()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail('CONTROL_PLANE_BUILD_INVALID', `${label} has unknown or missing fields`)
  }
}

function stableRegularFile(filePath, label) {
  let before
  let bytes
  let after
  try {
    before = fs.lstatSync(filePath, { bigint: true })
    if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o022n) !== 0n) {
      fail('CONTROL_PLANE_BUILD_UNPROTECTED', `${label} must be a protected regular non-symlink file`)
    }
    bytes = fs.readFileSync(filePath)
    after = fs.lstatSync(filePath, { bigint: true })
  } catch (error) {
    if (error instanceof D9BuildIntegrityError) throw error
    fail('CONTROL_PLANE_BUILD_UNAVAILABLE', `${label} could not be read`, { cause: error })
  }
  for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
    if (before[field] !== after[field]) fail('CONTROL_PLANE_BUILD_CHANGED', `${label} changed while it was hashed`)
  }
  return bytes
}

function resolvedBeneath(root, relativePath) {
  if (typeof relativePath !== 'string' || relativePath.length === 0 || relativePath.includes('\0') || path.isAbsolute(relativePath)) {
    fail('CONTROL_PLANE_BUILD_INVALID', 'source path must be a safe relative path')
  }
  const resolved = path.resolve(root, relativePath)
  const relative = path.relative(root, resolved)
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    fail('CONTROL_PLANE_BUILD_INVALID', `source path escapes the protected project root: ${relativePath}`)
  }
  return resolved
}

export function runningExecutableSha256() {
  let descriptor
  try {
    descriptor = fs.openSync('/proc/self/exe', fs.constants.O_RDONLY | fs.constants.O_CLOEXEC)
    const before = fs.fstatSync(descriptor, { bigint: true })
    if (!before.isFile()) fail('CONTROL_PLANE_BUILD_UNAVAILABLE', 'running executable is not a regular file')
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor, { bigint: true })
    for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
      if (before[field] !== after[field]) fail('CONTROL_PLANE_BUILD_CHANGED', 'running executable changed while it was hashed')
    }
    return sha256Bytes(bytes)
  } catch (error) {
    if (error instanceof D9BuildIntegrityError) throw error
    fail('CONTROL_PLANE_BUILD_UNAVAILABLE', 'running executable could not be inspected through /proc/self/exe', { cause: error })
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

export function verifyControlPlaneBuild({ manifestPath, projectRoot, verifiedGeneration }) {
  assertVerifiedRuntimeGeneration(verifiedGeneration)
  const resolvedRoot = path.resolve(projectRoot)
  const manifestBytes = stableRegularFile(path.resolve(manifestPath), 'control-plane build manifest')
  let manifest
  try {
    manifest = parseStrictJson(manifestBytes, {
      contractNumbers: true,
      maximumBytes: 262_144,
      maximumDepth: 8,
      maximumMembers: 256,
    })
  } catch (error) {
    fail('CONTROL_PLANE_BUILD_INVALID', 'control-plane build manifest is not strict JSON', { cause: error })
  }
  exactKeys(manifest, [
    'format',
    'format_version',
    'manifest_digest_sha256',
    'node_executable_sha256',
    'source_files',
  ], 'control-plane build manifest')
  if (manifest.format !== 'jedi-atlas-d91-control-plane-build' || manifest.format_version !== '1.0.0') {
    fail('CONTROL_PLANE_BUILD_INVALID', 'control-plane build manifest version is unsupported')
  }
  if (!HASH_PATTERN.test(manifest.manifest_digest_sha256) ||
      manifest.manifest_digest_sha256 !== canonicalSha256(manifest, { excludedTopLevelField: 'manifest_digest_sha256' })) {
    fail('CONTROL_PLANE_BUILD_INVALID', 'control-plane build manifest digest is invalid')
  }
  if (canonicalize(manifest) !== manifestBytes.toString('utf8')) {
    fail('CONTROL_PLANE_BUILD_INVALID', 'control-plane build manifest bytes are not canonical UTF-8')
  }
  if (!Array.isArray(manifest.source_files) || manifest.source_files.length !== CONTROL_PLANE_SOURCE_FILES.length) {
    fail('CONTROL_PLANE_BUILD_INVALID', 'control-plane source inventory has the wrong cardinality')
  }
  const paths = manifest.source_files.map((entry) => {
    exactKeys(entry, ['relative_path', 'sha256'], 'control-plane source entry')
    if (!HASH_PATTERN.test(entry.sha256)) fail('CONTROL_PLANE_BUILD_INVALID', 'control-plane source digest is invalid')
    return entry.relative_path
  })
  if (canonicalize(paths) !== canonicalize(CONTROL_PLANE_SOURCE_FILES)) {
    fail('CONTROL_PLANE_BUILD_INVALID', 'control-plane source inventory or ordering differs from D9.1')
  }

  const release = verifiedGeneration.runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === 'trusted_launcher')
  if (!release || sha256Bytes(manifestBytes) !== release.dependency_lock_sha256) {
    fail('CONTROL_PLANE_BUILD_MISMATCH', 'runtime profile does not pin the exact control-plane build manifest')
  }
  if (!HASH_PATTERN.test(manifest.node_executable_sha256) || runningExecutableSha256() !== manifest.node_executable_sha256) {
    fail('CONTROL_PLANE_BUILD_MISMATCH', 'running Node executable differs from the dependency-locked control-plane build')
  }
  for (const entry of manifest.source_files) {
    const bytes = stableRegularFile(resolvedBeneath(resolvedRoot, entry.relative_path), `control-plane source ${entry.relative_path}`)
    if (sha256Bytes(bytes) !== entry.sha256) fail('CONTROL_PLANE_BUILD_MISMATCH', `control-plane source changed: ${entry.relative_path}`)
  }

  const result = Object.freeze({
    manifestDigestSha256: manifest.manifest_digest_sha256,
    manifestFileSha256: sha256Bytes(manifestBytes),
    identityBindingsRecordDigestSha256: verifiedGeneration.identityBindings.record_digest_sha256,
    nodeExecutableSha256: manifest.node_executable_sha256,
    runtimeProfileRecordDigestSha256: verifiedGeneration.runtimeProfile.record_digest_sha256,
    sourceFiles: Object.freeze(Object.fromEntries(manifest.source_files.map((entry) => [entry.relative_path, entry.sha256]))),
    sourceFileCount: manifest.source_files.length,
  })
  verifiedBuilds.add(result)
  return result
}

export function assertVerifiedControlPlaneBuild(value) {
  if (!verifiedBuilds.has(value)) fail('CONTROL_PLANE_BUILD_INVALID', 'control-plane build was not verified from protected bytes')
  return value
}
