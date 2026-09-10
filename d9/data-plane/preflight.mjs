import {
  canonicalSha256,
  sha256Bytes,
} from '../control-plane/canonical.mjs'
import { assertD92PreflightRuntime } from './runtime.mjs'

const preflightResults = new WeakMap()

const PROCESSING_OUTPUT_KINDS = Object.freeze({
  content_decoding: new Set(['decoded_body']),
  parser: new Set(['extracted_text', 'structured_data', 'diagnostic']),
  ocr: new Set(['ocr_text', 'diagnostic']),
  normalization: new Set(['normalized_text', 'diagnostic']),
  manual_transcription: new Set(['manual_transcript', 'diagnostic']),
})

const AVAILABLE_CUSTODY_KINDS = new Set(['placed', 'relocated', 'restored'])
const SUPPORTED_VARY = new Set([
  undefined,
  'accept',
  'accept-encoding',
  'accept-language',
  'accept, accept-encoding',
  'accept, accept-language',
  'accept-encoding, accept-language',
  'accept, accept-encoding, accept-language',
])

const FROZEN_PILOT_SHAPE = Object.freeze({
  bootstrap_principals_exact: 4,
  bootstrap_artifacts_exact: 0,
  document_artifacts_exact: 1,
  document_retrieval_events_exact: 1,
  document_http_200_retained_exact: 1,
  document_redirects_max: 5,
  document_custody_placements_exact: 1,
  processing_runs_exact: 0,
  processing_outputs_exact: 0,
  candidate_occurrences_exact: 0,
  required_dependencies_for_document_exact: 1,
})

const FROZEN_PILOT_LIMITS = Object.freeze({
  manifest_bytes_max: 2_097_152,
  artifact_bytes_max: 26_214_400,
  bundle_artifact_bytes_max: 26_214_400,
})

export class D9PreflightError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`)
    this.name = 'D9PreflightError'
    this.code = code
  }
}

function fail(code, message) {
  throw new D9PreflightError(code, message)
}

function check(condition, code, message) {
  if (!condition) fail(code, message)
}

function same(left, right, code, message) {
  check(left === right, code, message)
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value
  seen.add(value)
  for (const child of Object.values(value)) deepFreeze(child, seen)
  return Object.freeze(value)
}

function immutableSnapshot(value, label) {
  try {
    return deepFreeze(structuredClone(value))
  } catch {
    fail('INVALID_PREFLIGHT_INPUT', `${label} must be structured data`)
  }
}

function requiredObject(value, label) {
  check(value && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype, 'INVALID_MANIFEST_SHAPE', `${label} must be an object`)
  return value
}

function requiredArray(value, label) {
  check(Array.isArray(value), 'INVALID_MANIFEST_SHAPE', `${label} must be an array`)
  return value
}

function canonicalTimestamp(value) {
  return typeof value === 'string'
    && /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u.test(value)
    && !Number.isNaN(Date.parse(value))
    && new Date(value).toISOString() === value
}

function validCode(value, maximum = 160, minimum = 3) {
  return typeof value === 'string'
    && Buffer.byteLength(value, 'utf8') >= minimum
    && Buffer.byteLength(value, 'utf8') <= maximum
    && /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/u.test(value)
}

function boundedText(value, maximum, { nullable = false, nonblank = true } = {}) {
  if (value === null && nullable) return true
  return typeof value === 'string'
    && !value.includes('\0')
    && Buffer.byteLength(value, 'utf8') <= maximum
    && (!nonblank || (Buffer.byteLength(value, 'utf8') > 0 && value.trim() !== ''))
}

function boundedTrimmedText(value, maximum) {
  return boundedText(value, maximum) && value === value.trim()
}

function safePath(value, maximum = 240) {
  return boundedText(value, maximum)
    && !value.startsWith('/')
    && !value.includes('\\')
    && !value.includes('?')
    && !value.includes('//')
    && value.split('/').every((segment) => segment !== '.' && segment !== '..' && /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/u.test(segment))
}

function safeUrl(value) {
  if (!boundedText(value, 2048) || /[\u0000-\u0020\u007f\\]/u.test(value)) return false
  try {
    const parsed = new URL(value)
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) return false
    return !Array.from(parsed.searchParams.keys()).some((key) => /^(?:x-amz-.+|x-goog-.+|sv|se|sp|sig)$|(?:^|[_-])(?:access|auth|authorization|credential|key|password|secret|signature|token)(?:$|[_-])/iu.test(key))
  } catch {
    return false
  }
}

function safeHttpFieldValue(value, maximum = 512) {
  return typeof value === 'string'
    && Buffer.byteLength(value, 'utf8') >= 1
    && Buffer.byteLength(value, 'utf8') <= maximum
    && value === value.trim()
    && !/[\u0000-\u001f\u007f]/u.test(value)
}

function validEtag(value) {
  return safeHttpFieldValue(value, 512) && /^(?:W\/)?"[!#-~]*"$/u.test(value)
}

function validHttpDate(value) {
  if (!safeHttpFieldValue(value, 29)) return false
  const match = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), (0[1-9]|[12][0-9]|3[01]) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) ([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]) GMT$/u.exec(value)
  if (!match) return false
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
  const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
  const date = new Date(Date.UTC(Number(match[4]), months.indexOf(match[3]), Number(match[2]), Number(match[5]), Number(match[6]), Number(match[7])))
  return date.getUTCFullYear() === Number(match[4])
    && date.getUTCMonth() === months.indexOf(match[3])
    && date.getUTCDate() === Number(match[2])
    && weekdays[date.getUTCDay()] === match[1]
}

function canonicalVary(value) {
  if (value === '*') return true
  if (!boundedTrimmedText(value, 512) || value !== value.toLowerCase()) return false
  const tokens = value.split(', ')
  return tokens.length > 0
    && tokens.every((token) => /^[a-z0-9!#$%&'*+.^_`|~-]+$/u.test(token))
    && new Set(tokens).size === tokens.length
    && value === [...tokens].sort().join(', ')
}

function canonicalContentCoding(value) {
  return safeHttpFieldValue(value, 255)
    && value === value.toLowerCase()
    && value.split(', ').every((token) => /^[a-z0-9!#$%&'*+.^_`|~-]+$/u.test(token))
}

function isForbiddenConfigurationKey(value) {
  const lower = value.toLowerCase()
  const parts = lower.split(/[._-]+/u).filter(Boolean)
  const singleton = new Set(['authorization', 'cookie', 'credential', 'credentials', 'password', 'passwd', 'secret', 'secrets', 'token', 'tokens'])
  if (parts.some((part) => singleton.has(part))) return true
  const pairs = new Set(['api:key', 'private:key', 'signing:key', 'access:key', 'client:secret', 'refresh:token', 'bearer:token', 'session:cookie', 'auth:token'])
  for (let index = 0; index < parts.length - 1; index += 1) {
    if (pairs.has(`${parts[index]}:${parts[index + 1]}`)) return true
  }
  return ['apikey', 'privatekey', 'signingkey', 'accesskey'].includes(lower)
}

function assertNoForbiddenMaterial(value, key = '') {
  if (Array.isArray(value)) {
    for (const item of value) assertNoForbiddenMaterial(item, key)
    return
  }
  if (value && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value)) {
      if (childKey !== 'contains_credentials') check(!isForbiddenConfigurationKey(childKey), 'FORBIDDEN_MATERIAL', `forbidden credential-like key: ${childKey}`)
      assertNoForbiddenMaterial(child, childKey)
    }
    return
  }
  if (typeof value !== 'string') return
  if (key.endsWith('url') || key.includes('reference') || key.includes('path')) {
    check(!/(?:bearer%20|x-(?:amz|goog)-signature|[?#&](?:token|key|api[_-]?key|signature|sig)=)/iu.test(value), 'FORBIDDEN_MATERIAL', 'credential-shaped URL, reference, or path')
  }
  check(!/-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]+=*|\bAKIA[0-9A-Z]{16}\b/iu.test(value), 'FORBIDDEN_MATERIAL', 'credential-shaped value')
}

function unique(values, label) {
  check(new Set(values).size === values.length, 'DUPLICATE_IDENTITY', `duplicate ${label}`)
}

function compareCode(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function artifactCode(layer, digest, length) {
  return `artifact.${layer}.sha256.${digest}.${length}`
}

function locationCode(url) {
  return `location.${sha256Bytes(Buffer.from(url, 'utf8'))}`
}

function custodyReference(artifact) {
  return `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}`
}

function rowMap(database, sql, key) {
  return new Map(database.prepare(sql).all().map((row) => [row[key], { ...row }]))
}

function databaseContext(database, { beforeBundleSequence = null } = {}) {
  check(database && typeof database.prepare === 'function', 'INVALID_DATABASE', 'database must provide the fixed read-only query interface')
  if (beforeBundleSequence !== null) check(Number.isSafeInteger(beforeBundleSequence) && beforeBundleSequence > 0, 'INVALID_DATABASE', 'preflight sequence bound is invalid')
  const allReceipts = rowMap(database, 'SELECT * FROM atlas_evidence_bundle_receipts', 'bundle_code')
  const receipts = new Map([...allReceipts].filter(([, row]) => beforeBundleSequence === null || row.bundle_sequence < beforeBundleSequence))
  const receiptById = new Map([...receipts.values()].map((row) => [row.id, row]))
  const withBundle = (sql, key) => {
    const rows = rowMap(database, sql, key)
    for (const [code, row] of rows) {
      const receipt = receiptById.get(row.evidence_bundle_receipt_id)
      if (!receipt) rows.delete(code)
      else {
        row.bundle_code = receipt.bundle_code
        row.bundle_sequence = receipt.bundle_sequence
      }
    }
    return rows
  }
  const principals = beforeBundleSequence === 1
    ? new Map()
    : rowMap(database, 'SELECT id,principal_code,principal_kind_code,created_by_principal_id,created_at FROM atlas_principals', 'principal_code')
  return {
    receipts,
    receiptById,
    principals,
    locations: withBundle('SELECT * FROM atlas_retrieval_locations', 'location_code'),
    artifacts: withBundle('SELECT * FROM atlas_artifacts', 'artifact_code'),
    retrievalEvents: withBundle('SELECT * FROM atlas_retrieval_events', 'retrieval_event_code'),
    redirects: withBundle('SELECT * FROM atlas_retrieval_redirects', 'redirect_code'),
    custodyEvents: withBundle('SELECT * FROM atlas_artifact_custody_events', 'custody_event_code'),
    processingRuns: withBundle('SELECT * FROM atlas_processing_runs', 'processing_run_code'),
    processingOutputs: withBundle('SELECT * FROM atlas_processing_outputs', 'processing_output_code'),
    candidates: withBundle('SELECT * FROM atlas_unverified_candidate_occurrences', 'candidate_record_code'),
  }
}

function valueById(map, id) {
  return [...map.values()].find((row) => row.id === id)
}

function codeById(map, id, column) {
  return valueById(map, id)?.[column]
}

function responseMetadata(row) {
  if (row.response_metadata) return row.response_metadata
  return {
    ...(row.response_etag === null ? {} : { etag: row.response_etag }),
    ...(row.response_last_modified === null ? {} : { last_modified: row.response_last_modified }),
    ...(row.response_content_type === null ? {} : { content_type: row.response_content_type }),
    ...(row.response_content_length === null ? {} : { content_length: row.response_content_length }),
    ...(row.response_content_encoding === null ? {} : { content_encoding: row.response_content_encoding }),
    ...(row.response_vary === null ? {} : { vary: row.response_vary }),
  }
}

function requestHeaders(row) {
  if (row.request_headers) return row.request_headers
  return {
    accept: row.request_accept,
    accept_language: row.request_accept_language,
    accept_encoding: row.request_accept_encoding,
  }
}

function runtimeValue(runtime, ...keys) {
  for (const key of keys) {
    if (runtime[key] !== undefined) return runtime[key]
  }
  return undefined
}

function validateRuntime(runtime, manifest) {
  assertD92PreflightRuntime(runtime)
  requiredObject(runtime, 'runtime')
  const submitterCode = runtimeValue(runtime, 'authenticatedSubmitterPrincipalCode', 'submitterPrincipalCode')
  const importerCode = runtimeValue(runtime, 'authenticatedImporterPrincipalCode', 'importerPrincipalCode')
  const importerSoftwareCode = runtimeValue(runtime, 'importerSoftwareCode')
  const importerVersion = runtimeValue(runtime, 'importerVersion')
  same(submitterCode, manifest.submitter_principal_code, 'ATTRIBUTION_MISMATCH', 'authenticated submitter does not match manifest attribution')
  same(importerCode, manifest.expected_importer_principal_code, 'ATTRIBUTION_MISMATCH', 'authenticated importer does not match manifest attribution')
  same(importerSoftwareCode, manifest.expected_importer_software_code, 'RUNTIME_MISMATCH', 'importer software identity does not match manifest')
  same(importerVersion, manifest.expected_importer_version, 'RUNTIME_MISMATCH', 'importer version does not match manifest')

  const profile = runtimeValue(runtime, 'policy', 'runtimeProfile')
  if (profile !== undefined && profile !== null) validatePilotProfile(profile, manifest, runtime.manifestByteLength)
}

function validatePilotProfile(profile, manifest, manifestByteLength) {
  requiredObject(profile, 'runtime policy')
  same(profile.profile_code ?? profile.profileCode, 'pilot_local_restricted_v1', 'PROFILE_MISMATCH', 'only the frozen pilot profile is recognized')
  same(profile.processor_policy_code ?? profile.processorPolicyCode, 'disabled', 'PROFILE_MISMATCH', 'frozen pilot processing policy must remain disabled')
  const limits = profile.limits ?? profile
  for (const [key, expected] of Object.entries(FROZEN_PILOT_LIMITS)) {
    const camel = key.replace(/_([a-z])/gu, (_, character) => character.toUpperCase())
    same(limits[key] ?? limits[camel], expected, 'PROFILE_MISMATCH', `frozen pilot limit changed: ${key}`)
  }
  const shape = profile.pilot_bundle_shape ?? profile.pilotBundleShape
  requiredObject(shape, 'pilot bundle shape')
  for (const [key, expected] of Object.entries(FROZEN_PILOT_SHAPE)) {
    const camel = key.replace(/_([a-z])/gu, (_, character) => character.toUpperCase())
    same(shape[key] ?? shape[camel], expected, 'PROFILE_MISMATCH', `frozen pilot bundle shape changed: ${key}`)
  }
  if (manifestByteLength !== undefined) {
    check(Number.isSafeInteger(manifestByteLength) && manifestByteLength > 0 && manifestByteLength <= FROZEN_PILOT_LIMITS.manifest_bytes_max, 'RESOURCE_LIMIT_EXCEEDED', 'manifest byte length exceeds frozen pilot limit')
  }
  for (const artifact of manifest.artifacts) {
    check(artifact.byte_length <= FROZEN_PILOT_LIMITS.artifact_bytes_max, 'RESOURCE_LIMIT_EXCEEDED', 'artifact exceeds frozen pilot byte limit')
  }
  const totalArtifactBytes = manifest.artifacts.reduce((total, artifact) => total + artifact.byte_length, 0)
  check(Number.isSafeInteger(totalArtifactBytes) && totalArtifactBytes <= FROZEN_PILOT_LIMITS.bundle_artifact_bytes_max, 'RESOURCE_LIMIT_EXCEEDED', 'bundle artifacts exceed frozen pilot byte limit')

  const outputCount = manifest.processing_runs.reduce((total, run) => total + run.outputs.length, 0)
  same(manifest.processing_runs.length, 0, 'PILOT_SHAPE_MISMATCH', 'frozen pilot rejects processing runs')
  same(outputCount, 0, 'PILOT_SHAPE_MISMATCH', 'frozen pilot rejects processing outputs')
  same(manifest.candidate_occurrences.length, 0, 'PILOT_SHAPE_MISMATCH', 'frozen pilot rejects candidate occurrences')
  if (manifest.principal_bootstrap) {
    same(1 + manifest.principal_bootstrap.principals.length, 4, 'PILOT_SHAPE_MISMATCH', 'bootstrap roster must contain exactly four principals')
    same(manifest.artifacts.length, 0, 'PILOT_SHAPE_MISMATCH', 'bootstrap bundle must contain no artifact')
    for (const field of ['retrieval_locations', 'retrieval_events', 'custody_events']) same(manifest[field].length, 0, 'PILOT_SHAPE_MISMATCH', `bootstrap bundle must contain no ${field}`)
  } else {
    same(manifest.artifacts.length, 1, 'PILOT_SHAPE_MISMATCH', 'document bundle must contain exactly one artifact')
    same(manifest.retrieval_events.length, 1, 'PILOT_SHAPE_MISMATCH', 'document bundle must contain exactly one retrieval event')
    same(manifest.retrieval_events.filter((event) => event.outcome_code === 'retrieved_retained' && event.http_status_code === 200).length, 1, 'PILOT_SHAPE_MISMATCH', 'document bundle must contain exactly one retained HTTP-200 event')
    check(manifest.retrieval_events[0].redirects.length <= 5, 'PILOT_SHAPE_MISMATCH', 'document retrieval exceeds redirect limit')
    same(manifest.custody_events.length, 1, 'PILOT_SHAPE_MISMATCH', 'document bundle must contain exactly one custody placement')
    const custody = manifest.custody_events[0]
    const retrieval = manifest.retrieval_events[0]
    const artifact = manifest.artifacts[0]
    const custodyPolicy = profile.custody_policy ?? profile.custodyPolicy
    requiredObject(custodyPolicy, 'pilot custody policy')
    check(custody.event_kind_code === 'placed'
      && custody.custody_class_code === custodyPolicy.custody_class_code
      && custody.backend_code === custodyPolicy.backend_code
      && custody.artifact_code === artifact.record_code
      && custody.backend_reference === artifact.staged_path
      && custody.repository_eligibility_declaration === null,
    'PILOT_SHAPE_MISMATCH', 'document custody differs from the frozen restricted-store profile')
    check(retrieval.artifact_code === artifact.record_code
      && retrieval.artifact_staged_path === artifact.staged_path
      && retrieval.request_method_code === 'GET'
      && retrieval.request_profile_code === 'http_get_representation_v1'
      && retrieval.request_headers.accept_encoding === 'identity'
      && retrieval.response_metadata.content_encoding === undefined,
    'PILOT_SHAPE_MISMATCH', 'document response differs from the frozen identity-coded representation profile')
    const usedLocationCodes = new Set([
      retrieval.requested_location_code,
      retrieval.last_attempted_location_code,
      retrieval.resolved_location_code,
      ...retrieval.redirects.flatMap((redirect) => [redirect.from_location_code, redirect.to_location_code]),
    ])
    usedLocationCodes.delete(null)
    const declaredLocationCodes = new Set(manifest.retrieval_locations.map((location) => location.record_code))
    check(canonicalSha256([...declaredLocationCodes].toSorted()) === canonicalSha256([...usedLocationCodes].toSorted()), 'PILOT_SHAPE_MISMATCH', 'document bundle contains an unused or missing retrieval location')
    same(manifest.required_bundles.length, 1, 'PILOT_SHAPE_MISMATCH', 'document bundle must pin exactly one dependency')
  }
}

function validateBootstrap(manifest, context, principals) {
  const bootstrap = manifest.principal_bootstrap
  if (context.principals.size === 0) {
    same(context.receipts.size, 0, 'INCONSISTENT_BOOTSTRAP_STATE', 'receipt history exists without principals')
    same(manifest.bundle_sequence, 1, 'INVALID_BOOTSTRAP', 'empty Atlas starts at bundle sequence 1')
    check(bootstrap, 'INVALID_BOOTSTRAP', 'empty Atlas requires explicit principal bootstrap')
    const root = requiredObject(bootstrap.trust_root, 'bootstrap trust root')
    same(root.id, 1, 'INVALID_BOOTSTRAP', 'trust root ID must be 1')
    same(root.principal_code, 'system.bootstrap', 'INVALID_BOOTSTRAP', 'trust root code mismatch')
    same(root.principal_kind_code, 'service', 'INVALID_BOOTSTRAP', 'trust root kind mismatch')
    same(root.created_by_principal_code, 'system.bootstrap', 'INVALID_BOOTSTRAP', 'trust root must be self-created')
    check(canonicalTimestamp(root.created_at), 'INVALID_BOOTSTRAP', 'trust root creation timestamp is invalid')
    const ids = new Set([1])
    const available = new Map([['system.bootstrap', { ...root }]])
    unique(bootstrap.principals.map((principal) => principal.principal_code), 'bootstrap principal code')
    for (const principal of bootstrap.principals) {
      check(Number.isSafeInteger(principal.id) && principal.id > 1 && !ids.has(principal.id), 'INVALID_BOOTSTRAP', 'duplicate or reserved bootstrap principal ID')
      check(validCode(principal.principal_code, 80, 1) && !available.has(principal.principal_code), 'INVALID_BOOTSTRAP', 'bootstrap principal code collides or is invalid')
      const creator = available.get(principal.created_by_principal_code)
      check(creator, 'INVALID_BOOTSTRAP', `bootstrap creator must precede ${principal.principal_code}`)
      check(['human', 'service'].includes(principal.principal_kind_code), 'INVALID_BOOTSTRAP', 'invalid bootstrap principal kind')
      check(canonicalTimestamp(principal.created_at) && creator.created_at <= principal.created_at, 'INVALID_BOOTSTRAP', 'noncausal principal creation')
      ids.add(principal.id)
      available.set(principal.principal_code, { ...principal })
    }
    const submitter = available.get(manifest.submitter_principal_code)
    const importer = available.get(manifest.expected_importer_principal_code)
    check(submitter?.principal_kind_code === 'human' && submitter.runtime_role_code === 'manifest_submitter', 'INVALID_BOOTSTRAP', 'submitter role must bind a human')
    check(importer?.principal_kind_code === 'service' && importer.runtime_role_code === 'bundle_importer', 'INVALID_BOOTSTRAP', 'importer role must bind a service')
    check([...available.values()].some((principal) => principal.runtime_role_code === 'collector' && principal.principal_kind_code === 'service'), 'INVALID_BOOTSTRAP', 'bootstrap requires a service collector')
    for (const [principalCode, principal] of available) principals.set(principalCode, principal)
  } else {
    check(context.receipts.size > 0, 'INCONSISTENT_BOOTSTRAP_STATE', 'principal state exists without an accepted receipt')
    same(bootstrap, undefined, 'INVALID_BOOTSTRAP', 'principal bootstrap is a one-time ceremony')
  }
}

function assertDependency(manifest, context, bundleCode, usedDependencies) {
  if (!bundleCode || bundleCode === manifest.bundle_id) return
  const dependency = manifest.required_bundles.find((item) => item.bundle_id === bundleCode)
  const receipt = context.receipts.get(bundleCode)
  check(receipt && dependency, 'UNPINNED_DEPENDENCY', `unpinned cross-bundle reference: ${bundleCode}`)
  same(dependency.bundle_digest_sha256, receipt.bundle_digest_sha256, 'DEPENDENCY_MISMATCH', `dependency digest mismatch: ${bundleCode}`)
  check(receipt.bundle_sequence < manifest.bundle_sequence, 'DEPENDENCY_MISMATCH', `dependency is not earlier: ${bundleCode}`)
  usedDependencies.add(bundleCode)
}

function validateManifestHeader(manifest, context) {
  same(manifest.format, 'jedi-atlas-evidence-bundle', 'INVALID_MANIFEST', 'manifest format mismatch')
  same(manifest.format_version, '1.0.0', 'INVALID_MANIFEST', 'manifest version mismatch')
  check(validCode(manifest.bundle_id, 80), 'INVALID_MANIFEST', 'invalid bundle identity')
  check(Number.isSafeInteger(manifest.bundle_sequence) && manifest.bundle_sequence > 0, 'INVALID_MANIFEST', 'invalid bundle sequence')
  check(canonicalTimestamp(manifest.bundle_created_at), 'INVALID_MANIFEST', 'invalid bundle creation timestamp')
  check(safePath(manifest.manifest_path), 'INVALID_MANIFEST', 'invalid manifest path')
  same(manifest.bundle_digest_sha256, canonicalSha256(manifest, { excludedTopLevelField: 'bundle_digest_sha256' }), 'DIGEST_MISMATCH', 'bundle digest mismatch')
  check(validCode(manifest.submitter_principal_code, 80, 1) && manifest.submitter_principal_code !== 'system.bootstrap', 'INVALID_ATTRIBUTION', 'invalid submitter principal')
  check(validCode(manifest.expected_importer_principal_code, 80, 1) && manifest.expected_importer_principal_code !== 'system.bootstrap', 'INVALID_ATTRIBUTION', 'invalid importer principal')
  check(boundedTrimmedText(manifest.expected_importer_software_code, 80), 'INVALID_RUNTIME_IDENTITY', 'invalid importer software code')
  check(boundedTrimmedText(manifest.expected_importer_version, 80), 'INVALID_RUNTIME_IDENTITY', 'invalid importer version')
  const declarations = requiredObject(manifest.bundle_declarations, 'bundle declarations')
  check(declarations.contains_credentials === false && declarations.contains_personal_data === false && declarations.hostile_input_acknowledged === true, 'INVALID_DECLARATION', 'bundle declarations must fail closed')
  for (const field of ['required_bundles', 'retrieval_locations', 'artifacts', 'retrieval_events', 'custody_events', 'processing_runs', 'candidate_occurrences']) requiredArray(manifest[field], field)
  const dependencies = manifest.required_bundles
  unique(dependencies.map((dependency) => dependency.bundle_id), 'required bundle')
  same(dependencies.map((item) => item.bundle_id).join('\0'), [...dependencies].sort((left, right) => compareCode(left.bundle_id, right.bundle_id)).map((item) => item.bundle_id).join('\0'), 'INVALID_DEPENDENCY_ORDER', 'required bundles must be sorted')
  for (const dependency of dependencies) {
    check(validCode(dependency.bundle_id, 80) && /^[0-9a-f]{64}$/u.test(dependency.bundle_digest_sha256), 'INVALID_DEPENDENCY', 'invalid required bundle identity')
    check(dependency.bundle_id !== manifest.bundle_id, 'DEPENDENCY_CYCLE', 'bundle cannot depend on itself')
    const receipt = context.receipts.get(dependency.bundle_id)
    check(receipt, 'MISSING_DEPENDENCY', `missing required bundle: ${dependency.bundle_id}`)
    same(receipt.bundle_digest_sha256, dependency.bundle_digest_sha256, 'DEPENDENCY_MISMATCH', `required bundle digest mismatch: ${dependency.bundle_id}`)
    check(receipt.bundle_sequence < manifest.bundle_sequence, 'DEPENDENCY_CYCLE', 'required bundle must be earlier')
  }
}

function acceptedReceiptFor(manifest, context) {
  const byCode = context.receipts.get(manifest.bundle_id)
  const byDigest = [...context.receipts.values()].find((receipt) => receipt.bundle_digest_sha256 === manifest.bundle_digest_sha256)
  if (!byCode && !byDigest) return null
  check(byCode && byDigest && byCode.id === byDigest.id, 'REPLAY_DRIFT', 'bundle code or digest is paired with another accepted bundle')
  for (const [stored, expected, label] of [
    [byCode.bundle_sequence, manifest.bundle_sequence, 'sequence'],
    [byCode.manifest_path, manifest.manifest_path, 'manifest path'],
    [byCode.bundle_created_at, manifest.bundle_created_at, 'creation timestamp'],
    [byCode.format_version_code, manifest.format_version, 'format version'],
    [byCode.importer_software_code, manifest.expected_importer_software_code, 'importer software'],
    [byCode.importer_version, manifest.expected_importer_version, 'importer version'],
  ]) same(stored, expected, 'REPLAY_DRIFT', `accepted bundle ${label} drift`)
  return byCode
}

function receiptAndIdentitySnapshot(context) {
  const mapRows = (map, codeColumn) => Object.fromEntries([...map].map(([code, row]) => [code, row.id]))
  return {
    receipts: mapRows(context.receipts),
    principals: mapRows(context.principals),
    locations: mapRows(context.locations),
    artifacts: mapRows(context.artifacts),
    retrievalEvents: mapRows(context.retrievalEvents),
    redirects: mapRows(context.redirects),
    custodyEvents: mapRows(context.custodyEvents),
    processingRuns: mapRows(context.processingRuns),
    processingOutputs: mapRows(context.processingOutputs),
    candidates: mapRows(context.candidates),
  }
}

function finalizeResult({ manifest, runtime, context, mode, usedDependencies = [] }) {
  const manifestSnapshot = immutableSnapshot(manifest, 'manifest')
  const runtimeSnapshot = immutableSnapshot(runtime, 'runtime')
  const result = deepFreeze({
    preflightVersion: '1.0.0',
    mode,
    bundleId: manifest.bundle_id,
    bundleSequence: manifest.bundle_sequence,
    bundleDigestSha256: manifest.bundle_digest_sha256,
    usedDependencyBundleIds: [...usedDependencies].sort(),
  })
  const metadata = deepFreeze({
    manifest: manifestSnapshot,
    runtime: runtimeSnapshot,
    mode,
    context: receiptAndIdentitySnapshot(context),
  })
  preflightResults.set(result, metadata)
  return result
}

export function assertPreflightResult(value) {
  const metadata = value && typeof value === 'object' ? preflightResults.get(value) : undefined
  check(metadata, 'UNVERIFIED_PREFLIGHT_RESULT', 'value was not produced by this preflight module')
  return metadata
}

export function preflightEvidenceBundle({ database, manifest, runtime, verifyAcceptedReplay = false }) {
  check(!database?.isTransaction, 'PREFLIGHT_TRANSACTION_ACTIVE', 'semantic preflight must run before a transaction begins')
  requiredObject(manifest, 'manifest')
  check(typeof verifyAcceptedReplay === 'boolean', 'INVALID_PREFLIGHT_INPUT', 'verifyAcceptedReplay must be boolean')
  const acceptedContext = databaseContext(database)
  const context = verifyAcceptedReplay ? databaseContext(database, { beforeBundleSequence: manifest.bundle_sequence }) : acceptedContext
  validateManifestHeader(manifest, context)
  validateRuntime(runtime, manifest)
  assertNoForbiddenMaterial(manifest)

  if (verifyAcceptedReplay) {
    check(acceptedReceiptFor(manifest, acceptedContext), 'REPLAY_DRIFT', 'full replay validation requires an accepted receipt')
  } else {
    const acceptedReceipt = acceptedReceiptFor(manifest, context)
    if (acceptedReceipt) return finalizeResult({ manifest, runtime, context, mode: 'no_op' })
  }

  const existingSequences = [...context.receipts.values()].map((receipt) => receipt.bundle_sequence)
  const expectedSequence = Math.max(0, ...existingSequences) + 1
  same(manifest.bundle_sequence, expectedSequence, 'INVALID_BUNDLE_SEQUENCE', 'bundle sequence must be contiguous')
  check(![...context.receipts.values()].some((receipt) => receipt.manifest_path === manifest.manifest_path), 'IDENTITY_COLLISION', 'manifest path collision')
  if (expectedSequence === 1) same(manifest.required_bundles.length, 0, 'INVALID_DEPENDENCY', 'first bundle has no dependencies')
  else {
    const predecessor = [...context.receipts.values()].find((receipt) => receipt.bundle_sequence === expectedSequence - 1)
    check(manifest.required_bundles.some((dependency) => dependency.bundle_id === predecessor.bundle_code), 'UNPINNED_DEPENDENCY', 'immediate predecessor must be pinned')
    check(predecessor.bundle_created_at <= manifest.bundle_created_at, 'NONCAUSAL_RECORD', 'bundle creation chronology must be monotonic')
  }

  const principals = new Map(context.principals)
  validateBootstrap(manifest, context, principals)
  const submitter = principals.get(manifest.submitter_principal_code)
  const importer = principals.get(manifest.expected_importer_principal_code)
  check(submitter?.principal_kind_code === 'human', 'INVALID_ATTRIBUTION', 'submitter must resolve to a human')
  check(importer?.principal_kind_code === 'service', 'INVALID_ATTRIBUTION', 'importer must resolve to a service')
  check(submitter.created_at <= manifest.bundle_created_at && importer.created_at <= manifest.bundle_created_at, 'NONCAUSAL_RECORD', 'bundle predates a principal')

  const prefix = `${manifest.bundle_id}.`
  const allNewCodes = []
  const usedDependencies = new Set()
  const locations = new Map(context.locations)
  const artifacts = new Map(context.artifacts)
  const retrievalEvents = new Map(context.retrievalEvents)
  const custodyEvents = new Map(context.custodyEvents)
  const processingRuns = new Map(context.processingRuns)
  const processingOutputs = new Map(context.processingOutputs)
  const candidates = new Map(context.candidates)

  for (const location of manifest.retrieval_locations) {
    same(location.record_code, locationCode(location.url), 'IDENTITY_MISMATCH', 'location code mismatch')
    check(safeUrl(location.url), 'UNSAFE_URL', 'unsafe retrieval URL')
    check(canonicalTimestamp(location.recorded_at) && location.recorded_at <= manifest.bundle_created_at, 'NONCAUSAL_RECORD', 'invalid retrieval-location chronology')
    same(location.recorded_by_principal_code, manifest.submitter_principal_code, 'ATTRIBUTION_MISMATCH', 'retrieval location recorder mismatch')
    check(submitter.created_at <= location.recorded_at, 'NONCAUSAL_RECORD', 'retrieval location predates submitter')
    check(!locations.has(location.record_code), 'IDENTITY_COLLISION', 'retrieval location code collision')
    check(![...locations.values()].some((row) => row.location_url === location.url || row.url === location.url), 'IDENTITY_COLLISION', 'retrieval URL collision')
    locations.set(location.record_code, { ...location, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(location.record_code)
  }

  for (const artifact of manifest.artifacts) {
    check(['retrieved_body', 'derived_output'].includes(artifact.byte_layer_code), 'INVALID_ARTIFACT', 'invalid artifact byte layer')
    same(artifact.hash_algorithm_code, 'sha256', 'INVALID_ARTIFACT', 'invalid artifact hash algorithm')
    check(/^[0-9a-f]{64}$/u.test(artifact.sha256) && Number.isSafeInteger(artifact.byte_length) && artifact.byte_length >= 0, 'INVALID_ARTIFACT', 'invalid artifact identity')
    same(artifact.record_code, artifactCode(artifact.byte_layer_code, artifact.sha256, artifact.byte_length), 'IDENTITY_MISMATCH', 'artifact code mismatch')
    check(safePath(artifact.staged_path), 'UNSAFE_PATH', 'unsafe artifact staged path')
    same(artifact.staged_path, custodyReference(artifact), 'IDENTITY_MISMATCH', 'artifact staged path is not content addressed')
    check(canonicalTimestamp(artifact.recorded_at) && artifact.recorded_at <= manifest.bundle_created_at, 'NONCAUSAL_RECORD', 'invalid artifact chronology')
    same(artifact.recorded_by_principal_code, manifest.submitter_principal_code, 'ATTRIBUTION_MISMATCH', 'artifact recorder mismatch')
    check(submitter.created_at <= artifact.recorded_at, 'NONCAUSAL_RECORD', 'artifact predates submitter')
    check(!artifacts.has(artifact.record_code), 'IDENTITY_COLLISION', 'artifact code collision')
    check(![...artifacts.values()].some((row) => row.byte_layer_code === artifact.byte_layer_code && row.sha256 === artifact.sha256 && row.byte_length === artifact.byte_length), 'IDENTITY_COLLISION', 'artifact natural-identity collision')
    artifacts.set(artifact.record_code, { ...artifact, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(artifact.record_code)
  }

  for (const event of manifest.retrieval_events) {
    check(validCode(event.record_code) && event.record_code.startsWith(prefix), 'INVALID_RECORD_CODE', 'invalid retrieval event code')
    check(!retrievalEvents.has(event.record_code), 'IDENTITY_COLLISION', 'retrieval event collision')
    const requested = locations.get(event.requested_location_code)
    const lastAttempted = locations.get(event.last_attempted_location_code)
    const resolved = event.resolved_location_code === null ? null : locations.get(event.resolved_location_code)
    check(requested && lastAttempted, 'MISSING_REFERENCE', 'unknown requested or last-attempted location')
    if (event.resolved_location_code !== null) check(resolved, 'MISSING_REFERENCE', 'unknown resolved location')
    assertDependency(manifest, context, requested.bundle_code, usedDependencies)
    assertDependency(manifest, context, lastAttempted.bundle_code, usedDependencies)
    assertDependency(manifest, context, resolved?.bundle_code, usedDependencies)
    check(canonicalTimestamp(event.started_at) && canonicalTimestamp(event.completed_at) && canonicalTimestamp(event.recorded_at), 'INVALID_TIMESTAMP', 'invalid retrieval event timestamp')
    check(event.started_at <= event.completed_at && event.completed_at <= event.recorded_at && event.recorded_at <= manifest.bundle_created_at, 'NONCAUSAL_RECORD', 'invalid retrieval event chronology')
    check((requested.recorded_at ?? requested.recorded_at) <= event.started_at, 'NONCAUSAL_RECORD', 'requested location was recorded after attempt start')
    check(lastAttempted.recorded_at <= event.completed_at, 'NONCAUSAL_RECORD', 'last attempted location was recorded after attempt completion')
    if (resolved) check(resolved.recorded_at <= event.completed_at, 'NONCAUSAL_RECORD', 'resolved location was recorded after attempt completion')
    same(event.recorded_by_principal_code, manifest.submitter_principal_code, 'ATTRIBUTION_MISMATCH', 'retrieval recorder mismatch')
    check(submitter.created_at <= event.recorded_at, 'NONCAUSAL_RECORD', 'retrieval event predates submitter')
    const collector = principals.get(event.collector_principal_code)
    check(collector?.principal_kind_code === 'service', 'INVALID_ATTRIBUTION', 'collector must resolve to a service')
    same(event.collector_principal_code, runtime.authenticatedCollectorPrincipalCode, 'ATTRIBUTION_MISMATCH', 'collector does not match the verified synthetic runtime binding')
    check(event.collector_principal_code !== manifest.expected_importer_principal_code, 'SEPARATION_VIOLATION', 'collector and importer must differ')
    check(collector.created_at <= event.started_at, 'NONCAUSAL_RECORD', 'retrieval predates collector')
    check(boundedTrimmedText(event.collector_software_code, 80) && boundedTrimmedText(event.collector_version, 80), 'INVALID_RUNTIME_IDENTITY', 'invalid collector identity')
    same(event.request_method_code, 'GET', 'INVALID_HTTP_PROFILE', 'manifest v1 is GET-only')
    same(event.request_profile_code, 'http_get_representation_v1', 'INVALID_HTTP_PROFILE', 'request profile mismatch')
    requiredObject(event.request_headers, 'request headers')
    same(Object.keys(event.request_headers).sort().join('\0'), ['accept', 'accept_encoding', 'accept_language'].join('\0'), 'INVALID_HTTP_PROFILE', 'request header set mismatch')
    for (const value of Object.values(event.request_headers)) if (value !== null) check(safeHttpFieldValue(value), 'INVALID_HTTP_FIELD', 'invalid request header value')
    requiredObject(event.response_metadata, 'response metadata')
    if (event.response_metadata.etag !== undefined) check(validEtag(event.response_metadata.etag), 'INVALID_HTTP_FIELD', 'invalid ETag')
    if (event.response_metadata.last_modified !== undefined) check(validHttpDate(event.response_metadata.last_modified), 'INVALID_HTTP_FIELD', 'invalid Last-Modified')
    if (event.response_metadata.content_type !== undefined) check(safeHttpFieldValue(event.response_metadata.content_type, 255), 'INVALID_HTTP_FIELD', 'invalid Content-Type')
    if (event.response_metadata.content_length !== undefined) check(Number.isSafeInteger(event.response_metadata.content_length) && event.response_metadata.content_length >= 0, 'INVALID_HTTP_FIELD', 'invalid Content-Length')
    if (event.response_metadata.content_encoding !== undefined) check(canonicalContentCoding(event.response_metadata.content_encoding), 'INVALID_HTTP_FIELD', 'invalid Content-Encoding')
    if (event.response_metadata.vary !== undefined) check(canonicalVary(event.response_metadata.vary), 'INVALID_HTTP_FIELD', 'noncanonical Vary')
    const artifact = event.artifact_code === null ? null : artifacts.get(event.artifact_code)
    if (event.artifact_code !== null) check(artifact, 'MISSING_REFERENCE', 'unknown retrieval artifact')
    assertDependency(manifest, context, artifact?.bundle_code, usedDependencies)
    if (artifact) check(artifact.recorded_at <= event.recorded_at, 'NONCAUSAL_RECORD', 'retrieval artifact recorded after event')
    const hasConditional = event.conditional_basis_retrieval_event_code !== null || event.conditional_validator_kind_code !== null || event.conditional_validator_value !== null
    if (hasConditional) {
      check(event.conditional_basis_retrieval_event_code !== null && ['etag', 'last_modified'].includes(event.conditional_validator_kind_code) && safeHttpFieldValue(event.conditional_validator_value), 'INVALID_CONDITIONAL', 'incomplete conditional request')
      check(event.conditional_validator_kind_code === 'etag' ? validEtag(event.conditional_validator_value) : validHttpDate(event.conditional_validator_value), 'INVALID_CONDITIONAL', 'invalid conditional validator')
      const basis = retrievalEvents.get(event.conditional_basis_retrieval_event_code)
      check(basis?.outcome_code === 'retrieved_retained' && basis.http_status_code === 200, 'INVALID_CONDITIONAL', 'conditional basis is not a retained HTTP-200 event')
      const basisRequested = basis.requested_location_code ?? codeById(context.locations, basis.requested_location_id, 'location_code')
      const basisResolved = basis.resolved_location_code ?? codeById(context.locations, basis.resolved_location_id, 'location_code')
      same(basisRequested, event.requested_location_code, 'INVALID_CONDITIONAL', 'conditional requested location differs from basis')
      same(basisResolved, event.last_attempted_location_code, 'INVALID_CONDITIONAL', 'conditional attempt target differs from basis')
      check(basis.completed_at < event.started_at, 'NONCAUSAL_RECORD', 'conditional attempt does not follow basis')
      same(basis.request_method_code, event.request_method_code, 'INVALID_CONDITIONAL', 'conditional method differs from basis')
      same(basis.request_profile_code, event.request_profile_code, 'INVALID_CONDITIONAL', 'conditional request profile differs from basis')
      for (const field of ['accept', 'accept_encoding', 'accept_language']) {
        same(requestHeaders(basis)[field], event.request_headers[field], 'INVALID_CONDITIONAL', 'conditional representation headers differ from basis')
      }
      const basisMetadata = responseMetadata(basis)
      check(SUPPORTED_VARY.has(basisMetadata.vary), 'INVALID_CONDITIONAL', 'unsupported Vary cannot support 304')
      if (event.outcome_code === 'not_modified') {
        same(event.resolved_location_code, basisResolved, 'INVALID_CONDITIONAL', '304 resolved location differs from basis')
        if (event.response_metadata.vary !== undefined) same(event.response_metadata.vary, basisMetadata.vary, 'INVALID_CONDITIONAL', '304 Vary differs from basis')
      }
      same(event.conditional_validator_value, event.conditional_validator_kind_code === 'etag' ? basisMetadata.etag : basisMetadata.last_modified, 'INVALID_CONDITIONAL', 'conditional validator does not match basis')
      assertDependency(manifest, context, basis.bundle_code, usedDependencies)
    } else {
      same(event.conditional_basis_retrieval_event_code, null, 'INVALID_CONDITIONAL', 'conditional basis must be null')
      same(event.conditional_validator_kind_code, null, 'INVALID_CONDITIONAL', 'conditional kind must be null')
      same(event.conditional_validator_value, null, 'INVALID_CONDITIONAL', 'conditional value must be null')
    }

    if (event.outcome_code === 'retrieved_retained') {
      check(resolved && event.resolved_location_code === event.last_attempted_location_code && artifact?.byte_layer_code === 'retrieved_body', 'INVALID_RETRIEVAL_OUTCOME', 'invalid retained retrieval')
      check(safePath(event.artifact_staged_path), 'UNSAFE_PATH', 'unsafe retained staged path')
      same(event.artifact_staged_path, custodyReference(artifact), 'IDENTITY_MISMATCH', 'retained staged path is not content addressed')
      check(canonicalTimestamp(event.captured_at) && event.started_at <= event.captured_at && event.captured_at <= event.completed_at, 'NONCAUSAL_RECORD', 'invalid capture time')
      same(event.http_status_code, 200, 'INVALID_RETRIEVAL_OUTCOME', 'retained representation must be HTTP 200')
      check(event.observed_sha256 === null && event.observed_byte_length === null && safeHttpFieldValue(event.detected_media_type, 255), 'INVALID_RETRIEVAL_OUTCOME', 'invalid retained body fields')
    } else if (event.outcome_code === 'observed_not_retained') {
      check(resolved && event.resolved_location_code === event.last_attempted_location_code && event.artifact_code === null && event.artifact_staged_path === null, 'INVALID_RETRIEVAL_OUTCOME', 'invalid observed-not-retained references')
      check(canonicalTimestamp(event.captured_at) && event.started_at <= event.captured_at && event.captured_at <= event.completed_at, 'NONCAUSAL_RECORD', 'invalid observation time')
      same(event.http_status_code, 200, 'INVALID_RETRIEVAL_OUTCOME', 'observed representation must be HTTP 200')
      check(safeHttpFieldValue(event.detected_media_type, 255), 'INVALID_RETRIEVAL_OUTCOME', 'invalid detected media type')
      const none = event.observed_sha256 === null && event.observed_byte_length === null
      const both = /^[0-9a-f]{64}$/u.test(event.observed_sha256 ?? '') && Number.isSafeInteger(event.observed_byte_length) && event.observed_byte_length >= 0
      check(none || both, 'INVALID_RETRIEVAL_OUTCOME', 'observed hash and length must be paired')
    } else if (event.outcome_code === 'not_modified') {
      check(resolved && event.resolved_location_code === event.last_attempted_location_code && event.artifact_code === null && event.artifact_staged_path === null && event.captured_at === null && event.http_status_code === 304 && event.detected_media_type === null && hasConditional, 'INVALID_RETRIEVAL_OUTCOME', 'invalid not-modified retrieval')
    } else if (event.outcome_code === 'network_failed') {
      check(event.resolved_location_code === null && event.artifact_code === null && event.artifact_staged_path === null && event.captured_at === null && event.http_status_code === null && event.detected_media_type === null && Object.keys(event.response_metadata).length === 0, 'INVALID_RETRIEVAL_OUTCOME', 'invalid network failure')
    } else if (event.outcome_code === 'http_failed') {
      check(resolved && event.resolved_location_code === event.last_attempted_location_code && event.artifact_code === null && event.artifact_staged_path === null && event.captured_at === null && Number.isInteger(event.http_status_code) && event.http_status_code >= 300 && event.http_status_code <= 599 && event.http_status_code !== 304 && event.detected_media_type === null, 'INVALID_RETRIEVAL_OUTCOME', 'invalid HTTP failure')
    } else fail('INVALID_RETRIEVAL_OUTCOME', 'unknown retrieval outcome')
    if (event.outcome_code !== 'observed_not_retained') check(event.observed_sha256 === null && event.observed_byte_length === null, 'INVALID_RETRIEVAL_OUTCOME', 'unexpected observed-body identity')
    check(event.http_status_code !== 206, 'INVALID_RETRIEVAL_OUTCOME', 'manifest v1 rejects partial content')

    requiredArray(event.redirects, 'redirects')
    unique(event.redirects.map((redirect) => redirect.ordinal), 'redirect ordinal')
    let from = event.requested_location_code
    event.redirects.forEach((redirect, index) => {
      same(redirect.ordinal, index + 1, 'INVALID_REDIRECT_CHAIN', 'redirect ordinals must be contiguous')
      check(validCode(redirect.record_code) && redirect.record_code.startsWith(prefix) && !context.redirects.has(redirect.record_code), 'IDENTITY_COLLISION', 'redirect code collision or invalid code')
      same(redirect.from_location_code, from, 'INVALID_REDIRECT_CHAIN', 'broken redirect chain')
      check(redirect.from_location_code !== redirect.to_location_code, 'INVALID_REDIRECT_CHAIN', 'redirect endpoints must differ')
      const source = locations.get(redirect.from_location_code)
      const target = locations.get(redirect.to_location_code)
      check(source && target && source.recorded_at <= event.completed_at && target.recorded_at <= event.completed_at, 'INVALID_REDIRECT_CHAIN', 'redirect endpoint missing or noncausal')
      check([301, 302, 303, 307, 308].includes(redirect.http_status_code), 'INVALID_REDIRECT_CHAIN', 'unsupported redirect status')
      assertDependency(manifest, context, target.bundle_code, usedDependencies)
      from = redirect.to_location_code
      allNewCodes.push(redirect.record_code)
    })
    if (event.redirects.length > 0) same(from, event.last_attempted_location_code, 'INVALID_REDIRECT_CHAIN', 'redirect chain does not reach last attempted location')
    else same(event.last_attempted_location_code, event.requested_location_code, 'INVALID_REDIRECT_CHAIN', 'last attempted location differs without redirect')
    if (event.resolved_location_code !== null) same(event.resolved_location_code, event.last_attempted_location_code, 'INVALID_REDIRECT_CHAIN', 'resolved location differs from last attempted location')
    retrievalEvents.set(event.record_code, { ...event, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(event.record_code)
  }

  for (const custody of manifest.custody_events) {
    check(validCode(custody.record_code) && custody.record_code.startsWith(prefix) && !custodyEvents.has(custody.record_code), 'IDENTITY_COLLISION', 'custody code collision or invalid code')
    check(['placed', 'restricted', 'relocated', 'quarantined', 'tombstoned', 'restored'].includes(custody.event_kind_code), 'INVALID_CUSTODY', 'unknown custody event kind')
    check(['repository', 'restricted_store'].includes(custody.custody_class_code), 'INVALID_CUSTODY', 'unknown custody class')
    const artifact = artifacts.get(custody.artifact_code)
    check(artifact, 'MISSING_REFERENCE', 'unknown custody artifact')
    assertDependency(manifest, context, artifact.bundle_code, usedDependencies)
    check(validCode(custody.copy_code, 120) && canonicalTimestamp(custody.occurred_at) && canonicalTimestamp(custody.recorded_at), 'INVALID_CUSTODY', 'invalid custody identity or time')
    check(custody.occurred_at <= custody.recorded_at && custody.recorded_at <= manifest.bundle_created_at, 'NONCAUSAL_RECORD', 'invalid custody chronology')
    same(custody.recorded_by_principal_code, manifest.submitter_principal_code, 'ATTRIBUTION_MISMATCH', 'custody recorder mismatch')
    check(submitter.created_at <= custody.recorded_at && artifact.recorded_at <= custody.recorded_at, 'NONCAUSAL_RECORD', 'custody predates attribution or artifact')
    check(boundedText(custody.reason, 1000), 'INVALID_CUSTODY', 'invalid custody reason')
    if (custody.event_kind_code === 'placed') {
      same(custody.predecessor_custody_event_code, null, 'INVALID_CUSTODY', 'placement cannot have a predecessor')
      check(![...custodyEvents.values()].some((row) => {
        const predecessorCode = row.predecessor_custody_event_code ?? codeById(context.custodyEvents, row.predecessor_custody_event_id, 'custody_event_code')
        return (row.artifact_code ?? codeById(context.artifacts, row.artifact_id, 'artifact_code')) === custody.artifact_code
          && row.copy_code === custody.copy_code
          && predecessorCode === undefined
      }), 'IDENTITY_COLLISION', 'custody copy already has a root')
    } else {
      const predecessor = custodyEvents.get(custody.predecessor_custody_event_code)
      check(predecessor, 'MISSING_REFERENCE', 'unknown custody predecessor')
      assertDependency(manifest, context, predecessor.bundle_code, usedDependencies)
      same(predecessor.artifact_code ?? codeById(context.artifacts, predecessor.artifact_id, 'artifact_code'), custody.artifact_code, 'INVALID_CUSTODY', 'custody predecessor artifact mismatch')
      same(predecessor.copy_code, custody.copy_code, 'INVALID_CUSTODY', 'custody predecessor copy mismatch')
      check(predecessor.recorded_at < custody.recorded_at && (predecessor.occurred_at ?? predecessor.recorded_at) <= custody.occurred_at, 'NONCAUSAL_RECORD', 'custody successor is noncausal')
      check(![...custodyEvents.values()].some((row) => (row.predecessor_custody_event_code ?? codeById(context.custodyEvents, row.predecessor_custody_event_id, 'custody_event_code')) === custody.predecessor_custody_event_code), 'INVALID_CUSTODY', 'custody predecessor is not current leaf')
      if (predecessor.event_kind_code === 'tombstoned') same(custody.event_kind_code, 'restored', 'INVALID_CUSTODY', 'only restoration may reverse a tombstone')
      else if (custody.event_kind_code === 'restored') check(['restricted', 'quarantined'].includes(predecessor.event_kind_code), 'INVALID_CUSTODY', 'restoration requires restricted or quarantined predecessor')
      else if (custody.event_kind_code === 'relocated') {
        check(['placed', 'relocated', 'restored'].includes(predecessor.event_kind_code), 'INVALID_CUSTODY', 'relocation cannot clear unavailable state')
        check(predecessor.backend_code !== custody.backend_code || predecessor.custody_class_code !== custody.custody_class_code, 'INVALID_CUSTODY', 'relocation must change backend or custody class')
      } else check(['restricted', 'quarantined', 'tombstoned'].includes(custody.event_kind_code), 'INVALID_CUSTODY', 'invalid custody successor kind')
    }
    if (custody.event_kind_code === 'tombstoned') {
      check(custody.backend_code === null && custody.backend_reference === null && custody.repository_eligibility_declaration === null, 'INVALID_CUSTODY', 'tombstone cannot carry live custody fields')
    } else {
      if (['restricted', 'quarantined'].includes(custody.event_kind_code)) same(custody.custody_class_code, 'restricted_store', 'INVALID_CUSTODY', 'unavailable custody must remain restricted')
      check(validCode(custody.backend_code, 40, 1), 'INVALID_CUSTODY', 'invalid custody backend')
      same(custody.backend_reference, custodyReference(artifact), 'IDENTITY_MISMATCH', 'custody reference is not content addressed')
      if (custody.custody_class_code === 'repository') {
        const declaration = requiredObject(custody.repository_eligibility_declaration, 'repository eligibility declaration')
        same(declaration.declared_by_principal_code, manifest.submitter_principal_code, 'ATTRIBUTION_MISMATCH', 'repository declaration must be made by submitter')
        check(principals.get(declaration.declared_by_principal_code)?.principal_kind_code === 'human', 'INVALID_ATTRIBUTION', 'repository declaration requires human')
        check(canonicalTimestamp(declaration.declared_at) && submitter.created_at <= declaration.declared_at && declaration.declared_at <= custody.recorded_at, 'NONCAUSAL_RECORD', 'repository declaration is noncausal')
        for (const field of ['redistribution_eligible_declared', 'no_sensitive_data_declared', 'size_eligible_declared', 'permanent_history_acknowledged']) same(declaration[field], true, 'INVALID_DECLARATION', `repository declaration ${field} must be true`)
      } else same(custody.repository_eligibility_declaration, null, 'INVALID_CUSTODY', 'restricted-store custody cannot carry repository declaration')
    }
    custodyEvents.set(custody.record_code, { ...custody, local: true, artifact_code: custody.artifact_code, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(custody.record_code)
  }

  for (const artifact of manifest.artifacts) {
    check(manifest.custody_events.some((custody) => custody.artifact_code === artifact.record_code && custody.event_kind_code === 'placed'), 'INCOMPLETE_GRAPH', `new artifact lacks initial placement: ${artifact.record_code}`)
    if (artifact.byte_layer_code === 'retrieved_body') check(manifest.retrieval_events.some((event) => event.outcome_code === 'retrieved_retained' && event.artifact_code === artifact.record_code && event.captured_at <= artifact.recorded_at), 'INCOMPLETE_GRAPH', `new artifact lacks retrieval origin: ${artifact.record_code}`)
  }

  const custodyArtifactCode = (row) => row.artifact_code ?? codeById(context.artifacts, row.artifact_id, 'artifact_code')
  const custodyRecordCode = (row) => row.record_code ?? row.custody_event_code
  const custodyPredecessorCode = (row) => row.predecessor_custody_event_code ?? codeById(context.custodyEvents, row.predecessor_custody_event_id, 'custody_event_code')
  const custodyAt = (artifactCodeValue, eventAsOf, knownThroughSequence) => {
    const known = [...custodyEvents.values()].filter((row) => custodyArtifactCode(row) === artifactCodeValue && (row.bundle_sequence ?? manifest.bundle_sequence) <= knownThroughSequence && (row.occurred_at ?? row.recorded_at) <= eventAsOf)
    return known.filter((row) => !known.some((successor) => custodyPredecessorCode(successor) === custodyRecordCode(row)))
  }
  const hasAvailableCustodyAt = (artifactCodeValue, at, sequence) => custodyAt(artifactCodeValue, at, sequence).some((row) => AVAILABLE_CUSTODY_KINDS.has(row.event_kind_code))
  const hasQualifyingCustodyAfter = (artifactCodeValue, at, sequence) => [...custodyEvents.values()].some((row) => custodyArtifactCode(row) === artifactCodeValue && (row.bundle_sequence ?? manifest.bundle_sequence) <= sequence && (row.occurred_at ?? row.recorded_at) >= at && AVAILABLE_CUSTODY_KINDS.has(row.event_kind_code))
  const hasCustodyForOccurrence = (artifactCodeValue, at, sequence) => hasAvailableCustodyAt(artifactCodeValue, at, sequence) || hasQualifyingCustodyAfter(artifactCodeValue, at, sequence)

  for (const event of manifest.retrieval_events.filter((row) => row.outcome_code === 'retrieved_retained')) check(hasCustodyForOccurrence(event.artifact_code, event.captured_at, manifest.bundle_sequence), 'INCOMPLETE_GRAPH', `retained retrieval lacks custody: ${event.record_code}`)

  const grounded = new Set()
  const lineage = new Map()
  const addLineage = (input, output) => {
    if (!lineage.has(input)) lineage.set(input, new Set())
    lineage.get(input).add(output)
  }
  const reaches = (start, target) => {
    if (start === target) return true
    const seen = new Set([start])
    const pending = [start]
    while (pending.length > 0) {
      const current = pending.shift()
      for (const next of lineage.get(current) ?? []) {
        if (next === target) return true
        if (!seen.has(next)) {
          seen.add(next)
          pending.push(next)
        }
      }
    }
    return false
  }
  for (const event of retrievalEvents.values()) if (event.outcome_code === 'retrieved_retained') grounded.add(event.artifact_code ?? codeById(context.artifacts, event.artifact_id, 'artifact_code'))
  const persistedRuns = [...context.processingRuns.values()].sort((left, right) => left.bundle_sequence - right.bundle_sequence || left.run_ordinal - right.run_ordinal || compareCode(left.processing_run_code, right.processing_run_code))
  for (const run of persistedRuns) {
    const input = codeById(context.artifacts, run.input_artifact_id, 'artifact_code')
    check(grounded.has(input), 'INVALID_PROCESSING_GRAPH', `persisted run input is not grounded: ${run.processing_run_code}`)
    const outputs = [...context.processingOutputs.values()].filter((output) => output.processing_run_id === run.id).sort((left, right) => left.output_ordinal - right.output_ordinal || compareCode(left.processing_output_code, right.processing_output_code))
    for (const output of outputs) {
      const outputCode = codeById(context.artifacts, output.artifact_id, 'artifact_code')
      check(!reaches(outputCode, input), 'INVALID_PROCESSING_GRAPH', `persisted processing cycle: ${run.processing_run_code}`)
      addLineage(input, outputCode)
      grounded.add(outputCode)
    }
  }

  unique(manifest.processing_runs.map((run) => run.ordinal), 'processing run ordinal')
  same(manifest.processing_runs.map((run) => run.ordinal).join(','), manifest.processing_runs.map((_, index) => index).join(','), 'INVALID_PROCESSING_GRAPH', 'processing run ordinals must be contiguous')
  for (const run of manifest.processing_runs) {
    check(validCode(run.record_code) && run.record_code.startsWith(prefix) && !processingRuns.has(run.record_code), 'IDENTITY_COLLISION', 'processing run collision or invalid code')
    const inputArtifact = artifacts.get(run.input_artifact_code)
    check(inputArtifact && grounded.has(run.input_artifact_code), 'INVALID_PROCESSING_GRAPH', 'processing input lacks earlier grounded origin')
    assertDependency(manifest, context, inputArtifact.bundle_code, usedDependencies)
    const processor = principals.get(run.processor_principal_code)
    check(processor && processor.principal_code !== 'system.bootstrap', 'INVALID_ATTRIBUTION', 'processor must resolve to non-bootstrap principal')
    check(run.processor_principal_code !== manifest.expected_importer_principal_code, 'SEPARATION_VIOLATION', 'processor and importer must differ')
    same(processor.principal_kind_code, run.method_code === 'manual_transcription' ? 'human' : 'service', 'INVALID_ATTRIBUTION', 'processor kind does not match method')
    check(canonicalTimestamp(run.started_at) && canonicalTimestamp(run.completed_at) && canonicalTimestamp(run.recorded_at), 'INVALID_TIMESTAMP', 'invalid processing time')
    check(processor.created_at <= run.started_at && run.started_at <= run.completed_at && run.completed_at <= run.recorded_at && run.recorded_at <= manifest.bundle_created_at, 'NONCAUSAL_RECORD', 'invalid processing chronology')
    same(run.recorded_by_principal_code, manifest.submitter_principal_code, 'ATTRIBUTION_MISMATCH', 'processing recorder mismatch')
    check(boundedTrimmedText(run.processor_software_code, 80) && boundedTrimmedText(run.processor_version, 80), 'INVALID_RUNTIME_IDENTITY', 'invalid processor identity')
    requiredObject(run.configuration, 'processing configuration')
    for (const [key, value] of Object.entries(run.configuration)) {
      check(/^[a-z][a-z0-9._-]{0,79}$/u.test(key) && !isForbiddenConfigurationKey(key), 'FORBIDDEN_MATERIAL', `invalid processing configuration key: ${key}`)
      if (typeof value === 'string') check(boundedText(value, 1000, { nonblank: false }), 'INVALID_PROCESSING_CONFIGURATION', 'invalid configuration string')
      else check(value === null || typeof value === 'boolean' || (Number.isSafeInteger(value) && value >= 0), 'INVALID_PROCESSING_CONFIGURATION', 'invalid configuration value')
    }
    same(run.configuration_sha256, canonicalSha256(run.configuration), 'DIGEST_MISMATCH', 'processing configuration digest mismatch')
    check(submitter.created_at <= run.recorded_at && inputArtifact.recorded_at <= run.started_at, 'NONCAUSAL_RECORD', 'processing predates attribution or input')
    check(hasAvailableCustodyAt(run.input_artifact_code, run.started_at, manifest.bundle_sequence), 'INVALID_PROCESSING_GRAPH', 'processing input was unavailable at accepted knowledge boundary')
    const allowedOutputs = PROCESSING_OUTPUT_KINDS[run.method_code]
    check(allowedOutputs, 'INVALID_PROCESSING_METHOD', 'unknown processing method')
    if (run.method_code === 'content_decoding') {
      same(inputArtifact.byte_layer_code, 'retrieved_body', 'INVALID_PROCESSING_METHOD', 'content decoding requires retrieved body')
      same(Object.keys(run.configuration).join('\0'), 'content_coding', 'INVALID_PROCESSING_CONFIGURATION', 'content decoding requires exact content_coding configuration')
      check(canonicalContentCoding(run.configuration.content_coding), 'INVALID_PROCESSING_CONFIGURATION', 'invalid pinned content coding')
      const codings = [...retrievalEvents.values()].filter((event) => event.outcome_code === 'retrieved_retained' && (event.artifact_code ?? codeById(context.artifacts, event.artifact_id, 'artifact_code')) === run.input_artifact_code).map((event) => responseMetadata(event).content_encoding)
      check(codings.includes(run.configuration.content_coding), 'INVALID_PROCESSING_CONFIGURATION', 'pinned content coding was not observed')
    }
    requiredArray(run.outputs, 'processing outputs')
    if (run.outcome_code === 'failed') {
      check(boundedText(run.failure_code, 80) && run.outputs.length === 0, 'INVALID_PROCESSING_OUTCOME', 'failed run requires failure code and no output')
    } else {
      same(run.outcome_code, 'succeeded', 'INVALID_PROCESSING_OUTCOME', 'unknown processing outcome')
      same(run.failure_code, null, 'INVALID_PROCESSING_OUTCOME', 'successful run cannot carry failure code')
      if (run.method_code === 'content_decoding') same(run.outputs.length, 1, 'INVALID_PROCESSING_OUTCOME', 'successful decoding requires one output')
    }
    unique(run.outputs.map((output) => output.record_code), 'processing output code')
    unique(run.outputs.map((output) => output.ordinal), 'processing output ordinal')
    same(run.outputs.map((output) => output.ordinal).join(','), run.outputs.map((_, index) => index).join(','), 'INVALID_PROCESSING_GRAPH', 'output ordinals must be contiguous')
    for (const output of run.outputs) {
      check(validCode(output.record_code) && output.record_code.startsWith(prefix) && !processingOutputs.has(output.record_code), 'IDENTITY_COLLISION', 'processing output collision or invalid code')
      const outputArtifact = artifacts.get(output.artifact_code)
      check(outputArtifact?.byte_layer_code === 'derived_output', 'INVALID_PROCESSING_GRAPH', 'processing output must reference derived artifact')
      check(allowedOutputs.has(output.output_kind_code), 'INVALID_PROCESSING_METHOD', 'processing method/output mismatch')
      check(!reaches(output.artifact_code, run.input_artifact_code), 'INVALID_PROCESSING_GRAPH', 'processing lineage cycle')
      assertDependency(manifest, context, outputArtifact.bundle_code, usedDependencies)
      check(canonicalTimestamp(output.produced_at) && run.started_at <= output.produced_at && output.produced_at <= run.completed_at, 'NONCAUSAL_RECORD', 'invalid output production time')
      check(safePath(output.staged_path), 'UNSAFE_PATH', 'unsafe output staged path')
      same(output.staged_path, custodyReference(outputArtifact), 'IDENTITY_MISMATCH', 'output path is not content addressed')
      check(outputArtifact.recorded_at <= run.recorded_at, 'NONCAUSAL_RECORD', 'derived artifact identity follows run record')
      const hasEarlierProduction = [...processingOutputs.values()].some((prior) => (prior.run_code ?? codeById(context.processingRuns, prior.processing_run_id, 'processing_run_code')) !== run.record_code && (prior.artifact_code ?? codeById(context.artifacts, prior.artifact_id, 'artifact_code')) === output.artifact_code)
      if (outputArtifact.local && !hasEarlierProduction) check(output.produced_at <= outputArtifact.recorded_at, 'NONCAUSAL_RECORD', 'derived artifact predates original production')
      check(safeHttpFieldValue(output.detected_media_type, 255), 'INVALID_HTTP_FIELD', 'invalid output media type')
      check(hasCustodyForOccurrence(output.artifact_code, output.produced_at, manifest.bundle_sequence), 'INCOMPLETE_GRAPH', 'processing output lacks custody')
      processingOutputs.set(output.record_code, { ...output, local: true, run_code: run.record_code, artifact_code: output.artifact_code, recorded_at: run.recorded_at, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
      addLineage(run.input_artifact_code, output.artifact_code)
      grounded.add(output.artifact_code)
      allNewCodes.push(output.record_code)
    }
    processingRuns.set(run.record_code, { ...run, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(run.record_code)
  }
  for (const artifact of manifest.artifacts.filter((row) => row.byte_layer_code === 'derived_output')) check(grounded.has(artifact.record_code), 'INVALID_PROCESSING_GRAPH', `derived artifact is not grounded: ${artifact.record_code}`)

  for (const candidate of manifest.candidate_occurrences) {
    check(validCode(candidate.record_code) && candidate.record_code.startsWith(prefix) && !candidates.has(candidate.record_code), 'IDENTITY_COLLISION', 'candidate collision or invalid code')
    const run = processingRuns.get(candidate.processing_run_code)
    const output = processingOutputs.get(candidate.processing_output_code)
    check(run && output, 'MISSING_REFERENCE', 'unknown candidate lineage')
    same(output.run_code ?? codeById(context.processingRuns, output.processing_run_id, 'processing_run_code'), candidate.processing_run_code, 'INVALID_CANDIDATE', 'candidate run/output mismatch')
    check(output.output_kind_code !== 'diagnostic', 'INVALID_CANDIDATE', 'diagnostic output cannot support candidate')
    assertDependency(manifest, context, run.bundle_code, usedDependencies)
    assertDependency(manifest, context, output.bundle_code, usedDependencies)
    check(canonicalTimestamp(candidate.recorded_at) && output.recorded_at <= candidate.recorded_at && candidate.recorded_at <= manifest.bundle_created_at, 'NONCAUSAL_RECORD', 'invalid candidate chronology')
    same(candidate.recorded_by_principal_code, manifest.submitter_principal_code, 'ATTRIBUTION_MISMATCH', 'candidate recorder mismatch')
    check(submitter.created_at <= candidate.recorded_at, 'NONCAUSAL_RECORD', 'candidate predates submitter')
    check(validCode(candidate.chain_code) && validCode(candidate.claim_type_code, 80) && boundedText(candidate.locator_value, 1000) && boundedText(candidate.reason, 1000), 'INVALID_CANDIDATE', 'invalid candidate fields')
    check(['byte_span', 'text_span'].includes(candidate.locator_kind_code), 'INVALID_CANDIDATE', 'unsupported locator kind')
    check(Number.isSafeInteger(candidate.span_start) && Number.isSafeInteger(candidate.span_end) && candidate.span_start >= 0 && candidate.span_end > candidate.span_start, 'INVALID_CANDIDATE', 'invalid candidate span')
    const outputArtifact = artifacts.get(output.artifact_code ?? codeById(context.artifacts, output.artifact_id, 'artifact_code'))
    check(candidate.span_end <= outputArtifact.byte_length, 'INVALID_CANDIDATE', 'candidate span exceeds output artifact')
    if (candidate.record_kind_code === 'assertion') {
      same(candidate.corrects_candidate_record_code, null, 'INVALID_CANDIDATE', 'candidate assertion cannot correct predecessor')
      check(typeof candidate.observed_value === 'string' && candidate.chain_code.startsWith(prefix), 'INVALID_CANDIDATE', 'invalid candidate assertion')
      check(![...candidates.values()].some((row) => {
        const predecessorCode = row.corrects_candidate_record_code ?? codeById(context.candidates, row.corrects_candidate_occurrence_id, 'candidate_record_code')
        return (row.candidate_chain_code ?? row.chain_code) === candidate.chain_code
          && predecessorCode === undefined
      }), 'IDENTITY_COLLISION', 'candidate chain already has a root')
    } else {
      const predecessor = candidates.get(candidate.corrects_candidate_record_code)
      check(predecessor, 'MISSING_REFERENCE', 'unknown candidate predecessor')
      assertDependency(manifest, context, predecessor.bundle_code, usedDependencies)
      same(predecessor.candidate_chain_code ?? predecessor.chain_code, candidate.chain_code, 'INVALID_CANDIDATE', 'candidate chain mismatch')
      same(predecessor.claim_type_code, candidate.claim_type_code, 'INVALID_CANDIDATE', 'candidate claim type mismatch')
      check(predecessor.recorded_at < candidate.recorded_at && (predecessor.bundle_sequence ?? manifest.bundle_sequence) <= manifest.bundle_sequence, 'NONCAUSAL_RECORD', 'candidate successor is noncausal')
      const predecessorCode = predecessor.candidate_record_code ?? predecessor.record_code
      check(![...candidates.values()].some((row) => (row.corrects_candidate_record_code ?? codeById(context.candidates, row.corrects_candidate_occurrence_id, 'candidate_record_code')) === predecessorCode), 'INVALID_CANDIDATE', 'candidate predecessor is not current leaf')
      if (candidate.record_kind_code === 'withdrawal') check(candidate.observed_value === null && candidate.normalized_value === null && candidate.confidence_basis_points === null, 'INVALID_CANDIDATE', 'withdrawal must clear values')
      else check(candidate.record_kind_code === 'correction' && typeof candidate.observed_value === 'string', 'INVALID_CANDIDATE', 'invalid candidate correction')
    }
    if (candidate.observed_value !== null) check(boundedText(candidate.observed_value, 8000), 'INVALID_CANDIDATE', 'invalid observed candidate value')
    if (candidate.normalized_value !== null) check(boundedText(candidate.normalized_value, 8000), 'INVALID_CANDIDATE', 'invalid normalized candidate value')
    if (candidate.confidence_basis_points !== null) check(Number.isSafeInteger(candidate.confidence_basis_points) && candidate.confidence_basis_points >= 0 && candidate.confidence_basis_points <= 10_000, 'INVALID_CANDIDATE', 'invalid candidate confidence metadata')
    candidates.set(candidate.record_code, { ...candidate, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(candidate.record_code)
  }

  unique(allNewCodes, 'new record code')
  const immediatePredecessor = [...context.receipts.values()].find((receipt) => receipt.bundle_sequence === manifest.bundle_sequence - 1)?.bundle_code
  for (const dependency of manifest.required_bundles) check(usedDependencies.has(dependency.bundle_id) || dependency.bundle_id === immediatePredecessor, 'UNUSED_DEPENDENCY', `unused required bundle: ${dependency.bundle_id}`)
  check(!database.isTransaction, 'PREFLIGHT_TRANSACTION_ACTIVE', 'semantic preflight unexpectedly entered a transaction')
  return finalizeResult({ manifest, runtime, context, mode: verifyAcceptedReplay ? 'no_op' : 'insert', usedDependencies: [...usedDependencies] })
}
