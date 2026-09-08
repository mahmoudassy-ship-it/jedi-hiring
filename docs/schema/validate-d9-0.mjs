import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { applyMigrations } from '../../data/lib/migrations.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const project = path.resolve(here, '../..')
const contractRoot = path.join(here, 'd9-0')
const fixtureRoot = path.join(contractRoot, 'fixtures')
const migrationsRoot = path.join(project, 'data/migrations')

const catalogPath = path.join(contractRoot, 'contract-catalog-v1.json')
const classificationPath = path.join(contractRoot, 'classifications-v1.json')
const fieldRegistryPath = path.join(contractRoot, 'field-registry-v1.json')
const digestProfilesPath = path.join(contractRoot, 'digest-profiles-v1.json')
const validFixturesPath = path.join(fixtureRoot, 'valid-contracts-v1.json')
const invalidFixturesPath = path.join(fixtureRoot, 'invalid-contracts-v1.json')
const goldenVectorsPath = path.join(fixtureRoot, 'golden-vectors-v1.json')
const evidenceManifestSchemaPath = path.join(here, 'tranche-2a-evidence-bundle-v1.schema.json')
const completeDocumentManifestPath = path.join(fixtureRoot, 'manifests/synthetic-bundle-002.json')
const completeDocumentArtifactPath = path.join(fixtureRoot, 'objects/sha256/c7/c76da313046a10971896c921d6bfaf00383159f10e5f1fa6d11f86f6276fc173')

const migrationHashes = {
  '001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  '002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  '003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
  '004_tranche_1a_foundations.sql': '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
  '005_tranche_2a_source_quarantine.sql': '1f83b484ca998be3bf5756492d4dffd958e2a6b37dbcc837e399226fdf41026b',
}

const atlasTables = [
  'atlas_artifact_custody_events',
  'atlas_artifacts',
  'atlas_evidence_bundle_receipts',
  'atlas_jurisdiction_versions',
  'atlas_jurisdictions',
  'atlas_languages',
  'atlas_principals',
  'atlas_processing_outputs',
  'atlas_processing_runs',
  'atlas_retrieval_events',
  'atlas_retrieval_locations',
  'atlas_retrieval_redirects',
  'atlas_unverified_candidate_occurrences',
]
const legacyTables = [
  'actors', 'country_overlays', 'hiring_stages', 'jurisdictions', 'legal_instruments',
  'legal_lenses', 'requirement_actors', 'requirement_hiring_stages',
  'requirement_legal_lenses', 'requirement_relations', 'requirement_search',
  'requirements', 'source_checks',
]
const pilotLimits = {
  contract_file_bytes_max: 262144,
  manifest_bytes_max: 2097152,
  relative_path_bytes_max: 240,
  path_component_bytes_max: 120,
  backend_reference_bytes_max: 82,
  artifact_bytes_max: 26214400,
  bundle_artifact_bytes_max: 26214400,
  json_depth_max: 32,
  json_members_max: 4096,
  result_bytes_max: 32768,
  journal_event_bytes_max: 65536,
  error_message_bytes_max: 512,
  stdout_bytes_max: 32768,
  stderr_bytes_max: 32768,
  scanner_output_bytes_max: 1048576,
  open_fds_max: 64,
  sandbox_processes_max: 1,
  sandbox_threads_max: 4,
  sandbox_cpu_time_ms_max: 600000,
  rss_bytes_max: 536870912,
  temporary_storage_bytes_max: 134217728,
  operation_timeout_ms: 900000,
  scanner_timeout_ms: 120000,
  scanner_result_age_seconds_max: 3600,
  scanner_rules_age_seconds_max: 86400,
  hash_copy_timeout_ms: 120000,
  backup_timeout_ms: 300000,
  database_busy_timeout_ms: 5000,
  orphan_grace_seconds: 86400,
  concurrent_operations_max: 1,
}
const pilotBundleShape = {
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
}
const frozenClassificationDigest = '6dff0288aa76baef2dcaeaed6ce5c810da25b1aa198f9664ee71622e0610ae4b'
const frozenDigestProfileSemanticDigest = '17f4bbed6d2a2080f58da9866bb7c3218a6f2f5ec9d48700e288bbcb1b9ecba7'
const frozenDigestBindingSemanticDigest = '108143e8f7556d46bd34ecd2e88955edf668f11bbeb523ac224c556cac9c83fd'
const frozenFieldRegistrySemanticDigest = '06a28a30e4de63d8ec4035b41e37c843b57d54280efde9da39961a5a7436ff74'

const schemaKeywords = new Set([
  '$defs', '$id', '$ref', '$schema', 'additionalProperties', 'const', 'description',
  'enum', 'items', 'maxItems', 'maxLength', 'maximum', 'minItems', 'minLength',
  'minimum', 'oneOf', 'pattern', 'properties', 'required', 'title', 'type',
  'uniqueItems',
])

class ContractError extends Error {
  constructor(layer, code, message) {
    super(`${layer}/${code}: ${message}`)
    this.name = 'ContractError'
    this.layer = layer
    this.code = code
  }
}

function fail(layer, code, message) {
  throw new ContractError(layer, code, message)
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function rawFileSha256(file) {
  return sha256(fs.readFileSync(file))
}

function canonical(value) {
  if (value === null) return 'null'
  if (typeof value === 'string') {
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index)
      if (code >= 0xd800 && code <= 0xdbff) {
        if (index + 1 >= value.length) fail('canonical', 'INVALID_UNICODE', 'lone high surrogate')
        const next = value.charCodeAt(index + 1)
        if (next < 0xdc00 || next > 0xdfff) fail('canonical', 'INVALID_UNICODE', 'lone high surrogate')
        index += 1
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        fail('canonical', 'INVALID_UNICODE', 'lone low surrogate')
      }
    }
    return JSON.stringify(value)
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
      fail('canonical', 'INVALID_NUMBER', 'numbers must be nonnegative safe integers')
    }
    return String(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('canonical', 'INVALID_VALUE', 'canonical JSON accepts only plain objects')
  }
  return `{${Object.keys(value).sort().map((key) => `${canonical(key)}:${canonical(value[key])}`).join(',')}}`
}

function withoutTopLevel(value, field) {
  const result = {}
  for (const [key, child] of Object.entries(value)) if (key !== field) result[key] = child
  return result
}

function recordDigest(value) {
  return sha256(Buffer.from(canonical(withoutTopLevel(value, 'record_digest_sha256')), 'utf8'))
}

function scanJsonLexically(text, { contractNumbers = false } = {}) {
  const stack = []
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    if (character === '"') {
      const start = index
      for (index += 1; index < text.length; index += 1) {
        if (text[index] === '\\') {
          index += 1
          continue
        }
        if (text[index] === '"') break
      }
      if (index >= text.length) fail('canonical', 'INVALID_JSON', 'unterminated JSON string')
      const raw = text.slice(start, index + 1)
      let next = index + 1
      while (/\s/u.test(text[next] || '')) next += 1
      if (stack.at(-1)?.type === 'object' && text[next] === ':') {
        let key
        try { key = JSON.parse(raw) } catch { fail('canonical', 'INVALID_JSON', 'invalid object key') }
        if (stack.at(-1).keys.has(key)) fail('canonical', 'DUPLICATE_KEY', `duplicate object key ${key}`)
        stack.at(-1).keys.add(key)
      }
      continue
    }
    if (character === '{') stack.push({ type: 'object', keys: new Set() })
    else if (character === '[') stack.push({ type: 'array' })
    else if (character === '}' || character === ']') stack.pop()
    else if (character === '-' || /[0-9]/u.test(character)) {
      const token = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u)?.[0]
      if (!token) fail('canonical', 'INVALID_JSON', 'invalid number token')
      if (contractNumbers && !/^(?:0|[1-9][0-9]*)$/u.test(token)) {
        fail('canonical', 'INVALID_NUMBER', `number token is outside the canonical profile: ${token}`)
      }
      index += token.length - 1
    }
  }
}

function parseJsonBytes(bytes, { contractNumbers = false, maximumBytes = 4 * 1024 * 1024 } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > maximumBytes) {
    fail('canonical', 'INVALID_SIZE', 'JSON input byte length is outside its fixed bound')
  }
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail('canonical', 'INVALID_ENCODING', 'UTF-8 BOM is prohibited')
  }
  let text
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes) } catch {
    fail('canonical', 'INVALID_ENCODING', 'input is not valid UTF-8')
  }
  scanJsonLexically(text, { contractNumbers })
  let value
  try { value = JSON.parse(text) } catch { fail('canonical', 'INVALID_JSON', 'input is not valid JSON') }
  const stats = objectStats(value)
  if (stats.maximumDepth > pilotLimits.json_depth_max || stats.members > pilotLimits.json_members_max) {
    fail('limits', 'RESOURCE_LIMIT_EXCEEDED', 'JSON graph exceeds the frozen depth or member limit')
  }
  canonical(value)
  return value
}

function loadJson(file) {
  return parseJsonBytes(fs.readFileSync(file), { contractNumbers: true, maximumBytes: pilotLimits.contract_file_bytes_max })
}

function schemaTypeMatches(value, type) {
  if (type === 'null') return value === null
  if (type === 'array') return Array.isArray(value)
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value)
  if (type === 'integer') return typeof value === 'number' && Number.isSafeInteger(value)
  if (type === 'number') return typeof value === 'number' && Number.isFinite(value)
  return typeof value === type
}

function auditSchemaNode(schema, pointer = '#') {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    fail('schema', 'SCHEMA_INVALID', `${pointer} must be a schema object`)
  }
  for (const key of Object.keys(schema)) {
    if (!schemaKeywords.has(key)) fail('schema', 'SCHEMA_KEYWORD_UNSUPPORTED', `${pointer} uses unsupported keyword ${key}`)
  }
  for (const key of ['$schema', '$id', '$ref', 'title', 'description', 'pattern']) {
    if (schema[key] !== undefined && typeof schema[key] !== 'string') fail('schema', 'SCHEMA_INVALID', `${pointer}/${key} must be a string`)
  }
  if (schema.$schema !== undefined && schema.$schema !== 'https://json-schema.org/draft/2020-12/schema') {
    fail('schema', 'SCHEMA_INVALID', `${pointer} uses an unsupported dialect`)
  }
  const types = schema.type === undefined ? [] : Array.isArray(schema.type) ? schema.type : [schema.type]
  const allowedTypes = new Set(['array', 'boolean', 'integer', 'null', 'number', 'object', 'string'])
  if (types.some((type) => typeof type !== 'string' || !allowedTypes.has(type)) || new Set(types).size !== types.length || (Array.isArray(schema.type) && schema.type.length === 0)) {
    fail('schema', 'SCHEMA_INVALID', `${pointer}/type is invalid`)
  }
  if ((types.includes('object') || schema.properties || schema.required) && schema.additionalProperties !== false) {
    fail('schema', 'SCHEMA_OPEN_OBJECT', `${pointer} must reject unknown fields`)
  }
  if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== 'boolean') fail('schema', 'SCHEMA_INVALID', `${pointer}/additionalProperties must be boolean`)
  if ((types.includes('array') || schema.items) && !schema.items) fail('schema', 'SCHEMA_INVALID', `${pointer} array lacks items`)
  for (const key of ['minItems', 'maxItems', 'minLength', 'maxLength', 'minimum', 'maximum']) {
    if (schema[key] !== undefined && (!Number.isSafeInteger(schema[key]) || schema[key] < 0)) fail('schema', 'SCHEMA_INVALID', `${pointer}/${key} must be a nonnegative safe integer`)
  }
  if (schema.minItems !== undefined && schema.maxItems !== undefined && schema.minItems > schema.maxItems) fail('schema', 'SCHEMA_INVALID', `${pointer} has inverted item bounds`)
  if (schema.minLength !== undefined && schema.maxLength !== undefined && schema.minLength > schema.maxLength) fail('schema', 'SCHEMA_INVALID', `${pointer} has inverted string bounds`)
  if (schema.minimum !== undefined && schema.maximum !== undefined && schema.minimum > schema.maximum) fail('schema', 'SCHEMA_INVALID', `${pointer} has inverted numeric bounds`)
  if (schema.uniqueItems !== undefined && typeof schema.uniqueItems !== 'boolean') fail('schema', 'SCHEMA_INVALID', `${pointer}/uniqueItems must be boolean`)
  if (schema.pattern !== undefined) {
    try { new RegExp(schema.pattern, 'u') } catch { fail('schema', 'SCHEMA_INVALID', `${pointer}/pattern is not a valid ECMAScript expression`) }
  }
  if (schema.required) {
    if (!Array.isArray(schema.required) || schema.required.some((key) => typeof key !== 'string') || new Set(schema.required).size !== schema.required.length) {
      fail('schema', 'SCHEMA_INVALID', `${pointer} has invalid required fields`)
    }
    if (schema.properties) {
      for (const key of schema.required) {
        if (!Object.hasOwn(schema.properties, key)) fail('schema', 'SCHEMA_INVALID', `${pointer} requires undeclared property ${key}`)
      }
    }
  }
  if (schema.enum && (!Array.isArray(schema.enum) || schema.enum.length === 0 || new Set(schema.enum.map(canonical)).size !== schema.enum.length)) {
    fail('schema', 'SCHEMA_INVALID', `${pointer} has an invalid enum`)
  }
  if (schema.oneOf && (!Array.isArray(schema.oneOf) || schema.oneOf.length < 2)) {
    fail('schema', 'SCHEMA_INVALID', `${pointer} has invalid oneOf`)
  }
  for (const container of ['$defs', 'properties']) {
    if (schema[container]) {
      if (typeof schema[container] !== 'object' || Array.isArray(schema[container])) fail('schema', 'SCHEMA_INVALID', `${pointer}/${container} is invalid`)
      for (const [key, child] of Object.entries(schema[container])) auditSchemaNode(child, `${pointer}/${container}/${key}`)
    }
  }
  if (schema.items) auditSchemaNode(schema.items, `${pointer}/items`)
  if (schema.oneOf) schema.oneOf.forEach((child, index) => auditSchemaNode(child, `${pointer}/oneOf/${index}`))
}

function jsonPointer(root, fragment) {
  if (fragment === '' || fragment === '#') return root
  const value = fragment.startsWith('#') ? fragment.slice(1) : fragment
  if (!value.startsWith('/')) fail('schema', 'REFERENCE_INVALID', `unsupported reference fragment ${fragment}`)
  return value.slice(1).split('/').reduce((node, part) => {
    const key = decodeURIComponent(part).replaceAll('~1', '/').replaceAll('~0', '~')
    if (!node || !Object.hasOwn(node, key)) fail('schema', 'REFERENCE_INVALID', `unresolved reference ${fragment}`)
    return node[key]
  }, root)
}

function createSchemaRegistry(schemaFiles) {
  const byId = new Map()
  const byFile = new Map()
  for (const [file, schema] of schemaFiles) {
    auditSchemaNode(schema, file)
    if (typeof schema.$id !== 'string' || byId.has(schema.$id)) fail('schema', 'SCHEMA_INVALID', `${file} has missing or duplicate $id`)
    byId.set(schema.$id, schema)
    byFile.set(file, schema)
  }
  const registry = { byId, byFile }
  const visit = (node, root, trail = new Set()) => {
    if (!node || typeof node !== 'object' || Array.isArray(node)) return
    if (node.$ref) {
      const marker = `${root.$id}|${node.$ref}`
      const resolved = resolveReference(node.$ref, root, registry)
      const nextRoot = node.$ref.startsWith('#') ? root : registry.byId.get(node.$ref.split('#')[0])
      if (!trail.has(marker)) visit(resolved, nextRoot, new Set(trail).add(marker))
    }
    for (const container of ['$defs', 'properties']) for (const child of Object.values(node[container] || {})) visit(child, root, trail)
    if (node.items) visit(node.items, root, trail)
    for (const child of node.oneOf || []) visit(child, root, trail)
  }
  for (const schema of byFile.values()) visit(schema, schema)
  return registry
}

function resolveReference(reference, currentRoot, registry) {
  if (reference.startsWith('#')) return jsonPointer(currentRoot, reference)
  const hash = reference.indexOf('#')
  const id = hash === -1 ? reference : reference.slice(0, hash)
  const fragment = hash === -1 ? '' : reference.slice(hash)
  const externalRoot = registry.byId.get(id)
  if (!externalRoot) fail('schema', 'REFERENCE_INVALID', `unresolved external reference ${reference}`)
  return jsonPointer(externalRoot, fragment)
}

function validateSchemaValue(value, schema, registry, rootSchema = schema, pointer = '$') {
  if (schema.$ref) validateSchemaValue(value, resolveReference(schema.$ref, rootSchema, registry), registry, schema.$ref.startsWith('#') ? rootSchema : registry.byId.get(schema.$ref.split('#')[0]), pointer)
  if (schema.oneOf) {
    let matches = 0
    const branchErrors = []
    for (const branch of schema.oneOf) {
      try {
        validateSchemaValue(value, branch, registry, rootSchema, pointer)
        matches += 1
      } catch (error) {
        if (!(error instanceof ContractError)) throw error
        branchErrors.push(error.message)
      }
    }
    if (matches !== 1) fail('schema', 'SCHEMA_INVALID', `${pointer} matched ${matches} oneOf branches (${branchErrors.join('; ')})`)
  }
  if (Object.hasOwn(schema, 'const') && !Object.is(value, schema.const)) fail('schema', 'SCHEMA_INVALID', `${pointer} differs from const`)
  if (schema.enum && !schema.enum.some((entry) => Object.is(entry, value))) fail('schema', 'SCHEMA_INVALID', `${pointer} is outside enum`)
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    if (!types.some((type) => schemaTypeMatches(value, type))) fail('schema', 'SCHEMA_INVALID', `${pointer} has wrong type`)
  }
  if (typeof value === 'string') {
    const length = Array.from(value).length
    if (schema.minLength !== undefined && length < schema.minLength) fail('schema', 'SCHEMA_INVALID', `${pointer} is shorter than minLength`)
    if (schema.maxLength !== undefined && length > schema.maxLength) fail('schema', 'SCHEMA_INVALID', `${pointer} is longer than maxLength`)
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) fail('schema', 'SCHEMA_INVALID', `${pointer} does not match pattern`)
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) fail('schema', 'SCHEMA_INVALID', `${pointer} is below minimum`)
    if (schema.maximum !== undefined && value > schema.maximum) fail('schema', 'SCHEMA_INVALID', `${pointer} is above maximum`)
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) fail('schema', 'SCHEMA_INVALID', `${pointer} has too few items`)
    if (schema.maxItems !== undefined && value.length > schema.maxItems) fail('schema', 'SCHEMA_INVALID', `${pointer} has too many items`)
    if (schema.uniqueItems && new Set(value.map(canonical)).size !== value.length) fail('schema', 'SCHEMA_INVALID', `${pointer} has duplicate items`)
    if (schema.items) value.forEach((item, index) => validateSchemaValue(item, schema.items, registry, rootSchema, `${pointer}/${index}`))
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const required of schema.required || []) if (!Object.hasOwn(value, required)) fail('schema', 'SCHEMA_INVALID', `${pointer} lacks ${required}`)
    for (const [key, child] of Object.entries(value)) {
      if (schema.properties?.[key]) validateSchemaValue(child, schema.properties[key], registry, rootSchema, `${pointer}/${key}`)
      else if (schema.additionalProperties === false) fail('schema', 'SCHEMA_INVALID', `${pointer} has unknown property ${key}`)
    }
  }
}

function unique(values, layer, code, label) {
  if (new Set(values).size !== values.length) fail(layer, code, `duplicate ${label}`)
}

function assertExactOrder(values, expected, layer, code, label) {
  unique(values, layer, code, label)
  if (canonical(values) !== canonical(expected)) fail(layer, code, `${label} order or membership is not frozen`)
}

function canonicalTimestamp(value) {
  return typeof value === 'string'
    && /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u.test(value)
    && !Number.isNaN(Date.parse(value))
    && new Date(value).toISOString() === value
}

function assertSemanticTimestamps(value, pointer = '$') {
  if (Array.isArray(value)) return value.forEach((item, index) => assertSemanticTimestamps(item, `${pointer}/${index}`))
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if ((key.endsWith('_at') || key === 'valid_from' || key === 'valid_until' || key === 'not_before' || key === 'expires_at') && child !== null && !canonicalTimestamp(child)) {
      fail('canonical', 'INVALID_TIMESTAMP', `${pointer}/${key} is not a canonical real UTC timestamp`)
    }
    assertSemanticTimestamps(child, `${pointer}/${key}`)
  }
}

function isSafeRelativePath(value, maximum = 240) {
  return typeof value === 'string'
    && Buffer.byteLength(value, 'utf8') >= 1
    && Buffer.byteLength(value, 'utf8') <= maximum
    && !value.includes('\0')
    && !value.startsWith('/')
    && !value.includes('\\')
    && !value.includes('//')
    && value.split('/').every((segment) => segment !== '.' && segment !== '..' && /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/u.test(segment))
}

function assertSemanticPaths(value, key = '') {
  if (Array.isArray(value)) return value.forEach((item) => assertSemanticPaths(item, key))
  if (!value || typeof value !== 'object') return
  for (const [childKey, child] of Object.entries(value)) {
    if (typeof child === 'string' && childKey.endsWith('_path') && (!isSafeRelativePath(child) || child.split('/').some((segment) => Buffer.byteLength(segment, 'utf8') > pilotLimits.path_component_bytes_max))) fail('path', 'PATH_INVALID', `${childKey} is not a safe relative path`)
    assertSemanticPaths(child, childKey)
  }
}

function forbiddenKey(value) {
  if (['contains_credentials', 'contains_personal_data', 'no_sensitive_data', 'no_sensitive_data_declared', 'peer_credentials_required', 'source_handle_token', 'preparation_token', 'sealed_capability_token', 'authorization_permit_record_digest_sha256', 'authorization_bundle_seal_record_digest_sha256', 'prepromotion_authorization_record_digest_sha256', 'source_authorization_record_digest_sha256'].includes(value)) return false
  const splitCamel = value.replace(/([a-z0-9])([A-Z])/gu, '$1_$2').toLowerCase()
  const parts = splitCamel.split(/[^a-z0-9]+/u).filter(Boolean)
  const singletons = new Set(['authorization', 'cookie', 'credential', 'credentials', 'passwd', 'password', 'secret', 'secrets', 'token', 'tokens'])
  const pairs = new Set(['api:key', 'private:key', 'signing:key', 'access:key', 'client:secret', 'refresh:token', 'bearer:token', 'session:cookie', 'auth:token'])
  if (parts.some((part) => singletons.has(part))) return true
  for (let index = 0; index + 1 < parts.length; index += 1) if (pairs.has(`${parts[index]}:${parts[index + 1]}`)) return true
  return ['apikey', 'privatekey', 'signingkey', 'accesskey', 'clientsecret'].includes(parts.join(''))
}

function assertNoSecretMaterial(value, key = '') {
  if (Array.isArray(value)) return value.forEach((item) => assertNoSecretMaterial(item, key))
  if (value && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value)) {
      if (forbiddenKey(childKey)) fail('secret_scan', 'MANIFEST_SECRET_REJECTED', `forbidden credential-like key ${childKey}`)
      assertNoSecretMaterial(child, childKey)
    }
    return
  }
  if (typeof value !== 'string') return
  const secretPattern = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]+=*|\b(?:api[_-]?key|private[_-]?key|signing[_-]?key|access[_-]?key|client[_-]?secret|refresh[_-]?token|auth(?:orization)?|cookie|passw(?:or)?d)\s*[:=]\s*\S+|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bAIza[0-9A-Za-z_-]{20,}\b|\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/iu
  if (secretPattern.test(value)) fail('secret_scan', 'MANIFEST_SECRET_REJECTED', `secret-like value in ${key || 'value'}`)
  const credentialLocator = /:\/\/[^/?#\s]*@|[?&#](?:token|access[_-]?token|key|api[_-]?key|signature|sig|x-amz-credential|x-amz-security-token|awsaccesskeyid|googleaccessid|x-goog-credential|x-(?:amz|goog)-signature)=/iu
  if (credentialLocator.test(value)) {
    fail('secret_scan', 'MANIFEST_SECRET_REJECTED', `secret-like locator in ${key}`)
  }
}

function assertNoSyntheticPersonalDataMarkers(value, key = '') {
  if (Array.isArray(value)) return value.forEach((item) => assertNoSyntheticPersonalDataMarkers(item, key))
  if (value && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value)) assertNoSyntheticPersonalDataMarkers(child, childKey)
    return
  }
  if (typeof value === 'string' && (value.includes('SYNTHETIC_PERSONAL_DATA:') || /synthetic[-_.a-z0-9]*@example\.invalid/iu.test(value))) fail('privacy_scan', 'PERSONAL_DATA_DETECTED', `synthetic personal-data marker in ${key || 'value'}`)
}

function assertRedactedOperationalOutput(value) {
  const visit = (child, key = '') => {
    if (Array.isArray(child)) return child.forEach((item) => visit(item, key))
    if (child && typeof child === 'object') return Object.entries(child).forEach(([childKey, item]) => visit(item, childKey))
    if (typeof child !== 'string') return
    if (/https?:\/\//iu.test(child) || child.startsWith('/') || /(?:^|\s)(?:etag|set-cookie|authorization|content-type)\s*:/iu.test(child)) fail('redaction', 'UNSAFE_OUTPUT', `unredacted operational material in ${key || 'value'}`)
  }
  visit(value)
}

function fixtureMap(validFixtures) {
  unique(validFixtures.fixtures.map((fixture) => fixture.fixture_code), 'fixture', 'DUPLICATE_FIXTURE', 'fixture code')
  return new Map(validFixtures.fixtures.map((fixture) => [fixture.fixture_code, fixture]))
}

function schemaErrorOverrides(value) {
  const version = value?.format_version ?? value?.result_version
  if (version !== undefined && version !== '1.0.0') fail('schema', 'INCOMPATIBLE_CONTRACT_VERSION', 'contract version is not supported')
  try { assertSemanticPaths(value) } catch (error) {
    if (error instanceof ContractError) fail('schema', 'INPUT_PATH_INVALID', error.message)
    throw error
  }
  if (value?.format === 'jedi-atlas-runtime-profile') {
    if (value.profile_code !== 'pilot_local_restricted_v1' || value.processor_policy_code !== 'disabled' || value.limits?.artifact_bytes_max !== 26214400) {
      fail('schema', 'RUNTIME_PROFILE_MISMATCH', 'runtime profile differs from the frozen pilot')
    }
  }
  if (value?.record_kind_code === 'replay_certificate' && value.target_database_class_code !== 'disposable_recovery_only') {
    fail('schema', 'REPLAY_CERTIFICATE_INVALID', 'replay certificate cannot target canonical storage')
  }
  if (value?.format === 'jedi-atlas-custody-adapter-message' && (!Number.isSafeInteger(value.request_sequence) || value.request_sequence < 1)) {
    fail('schema', 'IPC_REPLAY_DETECTED', 'IPC request sequence must be positive')
  }
}

function validateContractStructure(value, schemaFile, registry) {
  assertNoSecretMaterial(value)
  assertNoSyntheticPersonalDataMarkers(value)
  if (['importer-result-v1.schema.json', 'operation-journal-event-v1.schema.json'].includes(schemaFile)) assertRedactedOperationalOutput(value)
  schemaErrorOverrides(value)
  const schema = registry.byFile.get(schemaFile)
  if (!schema) fail('schema', 'INCOMPATIBLE_CONTRACT_VERSION', `unknown schema file ${schemaFile}`)
  try {
    validateSchemaValue(value, schema, registry)
  } catch (error) {
    if (error instanceof ContractError && error.layer === 'schema' && error.code === 'SCHEMA_INVALID') {
      fail('schema', 'MANIFEST_SCHEMA_INVALID', error.message)
    }
    throw error
  }
  assertSemanticTimestamps(value)
}

function assertDigest(value) {
  if (Object.hasOwn(value, 'record_digest_sha256') && value.record_digest_sha256 !== recordDigest(value)) {
    fail('digest', 'RECORD_DIGEST_MISMATCH', 'record digest differs from canonical payload')
  }
}

function assertExactMigrationList(entries) {
  if (!Array.isArray(entries) || entries.length !== Object.keys(migrationHashes).length) fail('semantic', 'RUNTIME_PROFILE_MISMATCH', 'migration list is incomplete')
  const names = entries.map((entry) => entry.migration_name)
  if (canonical(names) !== canonical(Object.keys(migrationHashes))) fail('semantic', 'RUNTIME_PROFILE_MISMATCH', 'migration list order is not frozen')
  for (const entry of entries) if (entry.sha256 !== migrationHashes[entry.migration_name]) fail('semantic', 'RUNTIME_PROFILE_MISMATCH', `migration digest mismatch for ${entry.migration_name}`)
}

function assertRuntimeProfile(value, catalogRawSha, classification) {
  assertExactMigrationList(value.migration_hashes)
  if (value.contract_catalog_sha256 !== catalogRawSha) fail('semantic', 'RUNTIME_PROFILE_MISMATCH', 'runtime profile does not pin the contract catalog bytes')
  if (value.evidence_bundle_contract.schema_sha256 !== rawFileSha256(path.join(here, 'tranche-2a-evidence-bundle-v1.schema.json'))) fail('semantic', 'RUNTIME_PROFILE_MISMATCH', 'runtime profile pins the wrong evidence-bundle schema')
  if (canonical(value.limits) !== canonical(pilotLimits) || canonical(value.pilot_bundle_shape) !== canonical(pilotBundleShape)) fail('semantic', 'RUNTIME_PROFILE_MISMATCH', 'runtime profile limits or pilot shape differ from the frozen constants')
  const expectedSlots = ['backup_adapter', 'candidate_database', 'canonical_query', 'clearance_register', 'custody_adapter', 'custody_capability_store', 'handoff_registry', 'operation_journal', 'permit_control_store', 'recovery_database', 'reviewed_root', 'staging_root']
  assertExactOrder(value.logical_handle_slots.map((item) => item.slot_code), expectedSlots, 'semantic', 'RUNTIME_PROFILE_MISMATCH', 'logical handle slot')
  assertExactOrder(value.scanner_policy.required_scanners.map((item) => item.scanner_code), ['malware', 'personal_data', 'secrets'], 'semantic', 'RUNTIME_PROFILE_MISMATCH', 'required scanner')
  assertExactOrder(value.component_releases.map((item) => item.runtime_role_code), componentReleaseRoles, 'semantic', 'RUNTIME_PROFILE_MISMATCH', 'component release')
  assertExactOrder(value.operational_profiles.map((item) => item.profile_kind_code), ['backup', 'clearance', 'custody_adapter', 'handoff', 'journal', 'scanner_registry'], 'semantic', 'RUNTIME_PROFILE_MISMATCH', 'operational profile')
  const expectedCandidateTables = ['atlas_artifact_custody_events', 'atlas_artifacts', 'atlas_evidence_bundle_receipts', 'atlas_principals', 'atlas_processing_outputs', 'atlas_processing_runs', 'atlas_retrieval_events', 'atlas_retrieval_locations', 'atlas_retrieval_redirects', 'atlas_unverified_candidate_occurrences']
  assertExactOrder(value.write_surface_policy.candidate_insert_tables, expectedCandidateTables, 'semantic', 'RUNTIME_PROFILE_MISMATCH', 'candidate insert table')
  assertExactOrder(value.write_surface_policy.forbidden_operation_codes, ['attach', 'ddl', 'delete', 'extension_load', 'replace', 'update', 'writable_schema'], 'semantic', 'RUNTIME_PROFILE_MISMATCH', 'forbidden operation')
  const expectedIpc = { address_family_code: 'AF_UNIX', socket_type_code: 'SOCK_SEQPACKET', encoding_code: 'utf8', framing_code: 'one_json_document_per_packet', max_packet_bytes: 65536, max_ancillary_fds: 8, request_timeout_ms: 30000, peer_credentials_required: true, canonical_payload_required: true }
  if (canonical(value.ipc) !== canonical(expectedIpc)) {
    fail('semantic', 'RUNTIME_PROFILE_MISMATCH', 'IPC profile is not fail closed')
  }
  if (canonical(value.logical_handle_slots) !== canonical(classification.logical_handle_slot_rules)) fail('semantic', 'RUNTIME_PROFILE_MISMATCH', 'logical handle recipients differ from the frozen least-privilege matrix')
}

const humanRoles = new Set(['human_submitter', 'operational_witness', 'recovery_operator', 'recovery_authority', 'clearance_decider', 'clearance_checker', 'bootstrap_authority'])
const attributedRoles = new Set(['human_submitter', 'collector', 'bundle_importer'])
const componentReleaseRoles = ['backup_adapter', 'bundle_importer', 'clearance_broker', 'cloner_promoter', 'collector', 'custody_adapter', 'database_writer', 'handoff_broker', 'independent_verifier', 'journal_broker', 'scanner', 'trusted_launcher']
const exactRuntimeRoles = [
  'backup_adapter', 'bootstrap_authority', 'bundle_importer', 'clearance_broker',
  'clearance_checker', 'clearance_decider', 'cloner_promoter', 'collector',
  'custody_adapter', 'database_writer', 'handoff_broker', 'human_submitter',
  'independent_verifier', 'journal_broker', 'operational_witness', 'recovery_authority', 'recovery_operator',
  'scanner', 'trusted_launcher',
]
const expectedRuntimeRoleBindingRules = [
  ['backup_adapter', 'service', 'ipc.backup', ['bootstrap', 'document_import', 'recovery']],
  ['bootstrap_authority', 'human', null, ['bootstrap']],
  ['bundle_importer', 'service', 'ipc.importer', ['bootstrap', 'document_import', 'dry_run', 'no_op_verification', 'recovery']],
  ['clearance_broker', 'service', 'ipc.clearance', ['document_import', 'dry_run', 'no_op_verification']],
  ['clearance_checker', 'human', null, ['document_import', 'dry_run', 'no_op_verification']],
  ['clearance_decider', 'human', null, ['document_import', 'dry_run', 'no_op_verification']],
  ['cloner_promoter', 'service', 'ipc.cloner', ['bootstrap', 'document_import', 'recovery']],
  ['collector', 'service', 'ipc.handoff', ['document_import']],
  ['custody_adapter', 'service', 'ipc.custody', ['document_import', 'dry_run', 'no_op_verification', 'recovery']],
  ['database_writer', 'service', 'ipc.writer', ['bootstrap', 'document_import', 'recovery']],
  ['handoff_broker', 'service', 'ipc.handoff', ['document_import', 'dry_run', 'no_op_verification']],
  ['human_submitter', 'human', null, ['bootstrap', 'document_import', 'dry_run', 'no_op_verification']],
  ['independent_verifier', 'service', 'ipc.verifier', ['bootstrap', 'document_import', 'dry_run', 'no_op_verification', 'recovery']],
  ['journal_broker', 'service', 'ipc.journal', ['bootstrap', 'document_import', 'dry_run', 'no_op_verification', 'recovery']],
  ['operational_witness', 'human', null, ['bootstrap', 'recovery']],
  ['recovery_authority', 'human', null, ['recovery']],
  ['recovery_operator', 'human', null, ['recovery']],
  ['scanner', 'service', 'ipc.scanner', ['document_import', 'dry_run', 'no_op_verification']],
  ['trusted_launcher', 'service', 'ipc.launcher', ['bootstrap', 'document_import', 'dry_run', 'no_op_verification', 'recovery']],
].map(([runtime_role_code, principal_kind_code, ipc_endpoint_code, allowed_operation_modes]) => ({ runtime_role_code, principal_kind_code, ipc_endpoint_code, allowed_operation_modes }))
const expectedCustodyCapabilityRules = [
  ['source_handle', 'source_handle_token', 'custody_adapter', 'bundle_importer', 'custody_adapter', 'open_staged', 'opened', ['prepare'], 'single_consume_prepare', 30000],
  ['preparation', 'preparation_token', 'custody_adapter', 'bundle_importer', 'custody_adapter', 'prepare', 'prepared', ['verify_prepared', 'publish_no_replace', 'abandon_temp'], 'ordered_verify_then_publish_or_abandon', 900000],
  ['sealed_custody_access', 'sealed_capability_token', 'custody_adapter', 'bundle_importer', 'custody_adapter', 'seal_custody_access', 'sealed', ['open_custody'], 'single_consume_open_custody', 30000],
].map(([capability_kind_code, payload_field_code, issued_by_runtime_role_code, requester_runtime_role_code, adapter_runtime_role_code, issuance_operation_code, issuance_outcome_code, allowed_consumer_operation_codes, replay_policy_code, lifetime_ms_max]) => ({ capability_kind_code, payload_field_code, issued_by_runtime_role_code, requester_runtime_role_code, adapter_runtime_role_code, issuance_operation_code, issuance_outcome_code, allowed_consumer_operation_codes, replay_policy_code, lifetime_ms_max }))

function assertIdentityBindings(value, classification) {
  if (!(value.issued_at < value.expires_at)) fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'binding set validity is empty')
  unique(value.bindings.map((item) => item.binding_code), 'semantic', 'IDENTITY_BINDING_MISMATCH', 'binding code')
  assertExactOrder(value.bindings.map((item) => item.runtime_role_code), exactRuntimeRoles, 'semantic', 'IDENTITY_BINDING_MISMATCH', 'runtime role')
  unique(value.bindings.map((item) => item.unix_uid), 'semantic', 'IDENTITY_BINDING_MISMATCH', 'authenticated Unix subject')
  for (const binding of value.bindings) {
    const roleRule = classification.runtime_role_binding_rules.find((item) => item.runtime_role_code === binding.runtime_role_code)
    if (!roleRule || binding.principal_kind_code !== roleRule.principal_kind_code || binding.ipc_endpoint_code !== roleRule.ipc_endpoint_code || canonical(binding.allowed_operation_modes) !== canonical(roleRule.allowed_operation_modes)) fail('semantic', 'IDENTITY_BINDING_MISMATCH', `${binding.runtime_role_code} differs from the exact role/endpoint/mode matrix`)
    const mustBeHuman = humanRoles.has(binding.runtime_role_code)
    if ((binding.principal_kind_code === 'human') !== mustBeHuman) fail('semantic', 'IDENTITY_BINDING_MISMATCH', `${binding.runtime_role_code} has wrong principal kind`)
    if (!(value.issued_at <= binding.valid_from && binding.valid_from < binding.valid_until && binding.valid_until <= value.expires_at)) {
      fail('semantic', 'IDENTITY_BINDING_MISMATCH', `${binding.binding_code} has invalid validity bounds`)
    }
    if (mustBeHuman && (binding.executable_sha256 !== null || binding.ipc_endpoint_code !== null)) fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'human binding claims a service executable or endpoint')
    if (!mustBeHuman && (binding.executable_sha256 === null || binding.ipc_endpoint_code === null)) fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'service binding lacks executable or endpoint')
    if (attributedRoles.has(binding.runtime_role_code) !== (binding.atlas_principal_code !== null)) fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'Atlas attribution exists on the wrong runtime role')
    if (binding.atlas_principal_code === 'system.bootstrap') fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'bootstrap trust root cannot be an operational binding')
  }
  const roles = new Map(value.bindings.map((item) => [item.runtime_role_code, item]))
  for (const role of ['human_submitter', 'collector', 'bundle_importer']) if (!roles.has(role)) fail('semantic', 'IDENTITY_BINDING_MISMATCH', `missing ${role}`)
  unique(['human_submitter', 'collector', 'bundle_importer'].map((role) => roles.get(role).unix_uid), 'semantic', 'IDENTITY_BINDING_MISMATCH', 'submitter/collector/importer subject')
  unique(['human_submitter', 'collector', 'bundle_importer'].map((role) => roles.get(role).atlas_principal_code), 'semantic', 'IDENTITY_BINDING_MISMATCH', 'submitter/collector/importer Atlas principal')
  const bootstrapHumanRoles = classification.bootstrap_distinct_human_roles
  assertExactOrder(bootstrapHumanRoles, ['human_submitter', 'operational_witness', 'bootstrap_authority'], 'semantic', 'IDENTITY_BINDING_MISMATCH', 'bootstrap distinct-human role')
  for (const role of bootstrapHumanRoles) if (!roles.has(role) || roles.get(role).principal_kind_code !== 'human') fail('semantic', 'IDENTITY_BINDING_MISMATCH', `bootstrap role ${role} lacks an authenticated human binding`)
  unique(bootstrapHumanRoles.map((role) => roles.get(role).unix_uid), 'semantic', 'IDENTITY_BINDING_MISMATCH', 'bootstrap submitter/witness/authority subject')
}

function findBinding(bindings, code, role, at) {
  const binding = bindings.bindings.find((item) => item.binding_code === code)
  if (!binding || (role && binding.runtime_role_code !== role)) fail('semantic', 'IDENTITY_BINDING_MISMATCH', `binding ${code} is not eligible as ${role}`)
  if (at !== undefined && !(bindings.issued_at <= at && at < bindings.expires_at && binding.valid_from <= at && at < binding.valid_until)) fail('semantic', 'IDENTITY_BINDING_MISMATCH', `binding ${code} is not active at ${at}`)
  return binding
}

function assertUniquePermitSuccessors(transitions) {
  const successorKeys = transitions.map((transition) => `${transition.permit_issuance_record_digest_sha256}|${transition.previous_transition_record_digest_sha256 ?? 'root'}`)
  unique(successorKeys, 'semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit predecessor successor')
}

function assertPermitTransition(transition, issuance, previous, expectedStateReference, recoveryAuthority, bindings, classification, expectedStateProducedAt = null) {
  const rule = classification.permit_transition_rules.find((item) => item.permit_kind_code === transition.permit_kind_code && item.from_state_code === transition.from_state_code && item.to_state_code === transition.to_state_code && item.transition_code === transition.transition_code && item.reason_code === transition.reason_code)
  if (!rule || transition.permit_kind_code !== issuance.permit_kind_code || transition.permit_code !== issuance.permit_code || transition.permit_issuance_record_digest_sha256 !== issuance.record_digest_sha256 || transition.operation_nonce !== issuance.operation_nonce) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition does not match its frozen edge or permit')
  const exactExpected = rule.observed_state_policy_code === 'exact_expected'
  const optionalLastKnown = rule.observed_state_policy_code === 'optional_last_known'
  if ((!exactExpected && !optionalLastKnown) || (exactExpected && (expectedStateReference === null || canonical(transition.observed_logical_state) !== canonical(expectedStateReference))) || (optionalLastKnown && transition.observed_logical_state !== null && (expectedStateReference === null || canonical(transition.observed_logical_state) !== canonical(expectedStateReference))) || (transition.observed_logical_state !== null && expectedStateProducedAt !== null && expectedStateProducedAt > transition.occurred_at)) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition violates its exact-expected or optional-last-known observed-state policy')
  const expectedFromState = previous === null ? 'ready' : previous.to_state_code
  if (transition.from_state_code !== expectedFromState) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition does not continue the current state')
  const rootInvalid = previous === null && (transition.transition_sequence !== 1 || transition.previous_transition_record_digest_sha256 !== null || (['recovery', 'post_promotion_completion'].includes(issuance.permit_kind_code) && transition.operation_id !== issuance.operation_id))
  const successorInvalid = previous !== null && (transition.transition_sequence !== previous.transition_sequence + 1 || transition.previous_transition_record_digest_sha256 !== previous.record_digest_sha256 || transition.operation_id !== previous.operation_id || transition.occurred_at <= previous.occurred_at || transition.persisted_at <= previous.persisted_at)
  if (rootInvalid || successorInvalid) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition chain has a gap, fork, operation change, or backdated semantic/broker successor')
  const lowerBound = rule.occurrence_window_code === 'issuance_inclusive_to_expiry_exclusive' ? issuance.issued_at : issuance.not_before
  if (!(lowerBound <= transition.occurred_at && transition.occurred_at <= transition.persisted_at && transition.persisted_at < issuance.expires_at)) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition occurrence or protected persistence falls outside its registered window')
  if (transition.recorded_by_runtime_role_code !== rule.recorder_runtime_role_code) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition declares the wrong recorder role')
  if (rule.recorder_binding_policy_code === 'exact_permit_issuer_binding' && transition.recorded_by_binding_code !== issuance.issuer_binding_code) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'authority withdrawal was not recorded by the exact permit issuer')
  findBinding(bindings, transition.recorded_by_binding_code, rule.recorder_runtime_role_code, transition.occurred_at)
  if (rule.persisted_by_runtime_role_code !== 'trusted_launcher' || rule.persisted_by_binding_policy_code !== 'exact_runtime_role_binding') fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition lacks its frozen protected-register writer policy')
  findBinding(bindings, transition.persisted_by_binding_code, rule.persisted_by_runtime_role_code, transition.persisted_at)
  if (rule.recovery_permit_required) {
    if (!recoveryAuthority || transition.recovery_permit_record_digest_sha256 !== recoveryAuthority.record_digest_sha256 || recoveryAuthority.canonical_lineage_code !== issuance.canonical_lineage_code || !(recoveryAuthority.not_before <= transition.occurred_at && transition.occurred_at < recoveryAuthority.expires_at)) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition lacks the exact active recovery authority')
  } else if (transition.recovery_permit_record_digest_sha256 !== null) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition claims unnecessary recovery authority')
  const requiresCompletionJournal = issuance.permit_kind_code === 'post_promotion_completion' && transition.to_state_code === 'spent' && transition.transition_code === 'no_effect_verified'
  if (requiresCompletionJournal !== (transition.completion_journal_head_record_digest_sha256 !== null)) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit transition completion-journal evidence presence differs from its terminal edge')
  return rule
}

function clearanceScopeProjection(decision) {
  return {
    artifact: structuredClone(decision.artifact),
    capture_context_code: decision.capture_context_code,
    conditions: structuredClone(decision.conditions),
    contains_credentials: decision.contains_credentials,
    contains_personal_data: decision.contains_personal_data,
    decision_code: decision.decision_code,
    derivative_use_code: decision.derivative_use_code,
    expires_at: decision.expires_at,
    git_permanence_acknowledged: decision.git_permanence_acknowledged,
    limitations: structuredClone(decision.limitations),
    not_before: decision.not_before,
    redistribution_scope_code: decision.redistribution_scope_code,
    repository_declarations: structuredClone(decision.repository_declarations),
    retention_scope_code: decision.retention_scope_code,
    sensitivity_code: decision.sensitivity_code,
  }
}

function clearanceScopeDigest(decision) {
  return sha256(Buffer.from(canonical(clearanceScopeProjection(decision)), 'utf8'))
}

function assertRecoveryPermitWindow(permit, replay, bindings, classification) {
  const lifetimeMs = Date.parse(permit.expires_at) - Date.parse(permit.issued_at)
  if (!(replay.issued_at <= permit.issued_at && permit.issued_at <= permit.not_before && permit.not_before < permit.expires_at && permit.expires_at <= replay.expires_at && permit.expires_at <= bindings.expires_at) || lifetimeMs < 1 || lifetimeMs > classification.recovery_permit_policy.maximum_lifetime_ms) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'recovery permit has an invalid, overlong, or dependency-outliving validity window')
}

function assertClearanceDecisionMatrix(decision, classification) {
  const rule = classification.clearance_decision_rules.find((item) => item.decision_code === decision.decision_code)
  const declarationCode = Object.values(decision.repository_declarations).every((item) => item === true)
    ? 'all_true'
    : Object.values(decision.repository_declarations).every((item) => item === false) ? 'all_false' : 'mixed'
  if (!rule || ['retention_scope_code', 'redistribution_scope_code', 'derivative_use_code', 'sensitivity_code', 'git_permanence_acknowledged'].some((key) => decision[key] !== rule[key]) || declarationCode !== rule.repository_declaration_code || decision.contains_personal_data || decision.contains_credentials) fail('semantic', 'CLEARANCE_INVALID', 'clearance decision is outside the total admission matrix')
  if (decision.clearance_scope_sha256 !== clearanceScopeDigest(decision)) fail('semantic', 'CLEARANCE_INVALID', 'clearance scope digest differs from the exact same-record projection')
  if (!(decision.decided_at <= decision.not_before && decision.decided_at <= decision.recorded_at && decision.not_before <= decision.recorded_at && decision.recorded_at < decision.expires_at)) fail('semantic', 'CLEARANCE_INVALID', 'clearance decision chronology is invalid')
  return rule
}

function assertClearanceTransitions(decision, transitions, replacements, classification) {
  if (transitions.length > 1) fail('semantic', 'CLEARANCE_INVALID', 'clearance decision has competing terminal successors')
  if (transitions.length === 0) return null
  const transition = transitions[0]
  const rule = classification.clearance_transition_rules.find((item) => item.state_code === transition.state_code)
  if (!rule || !rule.allowed_reason_codes.includes(transition.reason_code) || transition.clearance_code !== decision.clearance_code || transition.decision_record_digest_sha256 !== decision.record_digest_sha256 || transition.transition_sequence !== 1 || transition.previous_transition_record_digest_sha256 !== null || transition.occurred_at <= decision.recorded_at) fail('semantic', 'CLEARANCE_INVALID', 'clearance transition is not a valid closed successor')
  if (rule.replacement_code === 'must_be_null') {
    if (transition.replacement_clearance_record_digest_sha256 !== null) fail('semantic', 'CLEARANCE_INVALID', 'revocation cannot name a replacement')
  } else {
    const replacement = replacements.get(transition.replacement_clearance_record_digest_sha256)
    if (!replacement || replacement.record_digest_sha256 === decision.record_digest_sha256 || canonical(replacement.artifact) !== canonical(decision.artifact)) fail('semantic', 'CLEARANCE_INVALID', 'supersession must resolve a distinct same-artifact decision')
    assertClearanceDecisionMatrix(replacement, classification)
    if (replacement.recorded_at > transition.occurred_at) fail('semantic', 'CLEARANCE_INVALID', 'replacement decision was not recorded when supersession occurred')
  }
  return transition
}

function clearanceLeafAt(decision, transitions, replacements, classification, asOf) {
  assertClearanceDecisionMatrix(decision, classification)
  const transition = assertClearanceTransitions(decision, transitions, replacements, classification)
  if (!(decision.recorded_at <= asOf && decision.not_before <= asOf && asOf < decision.expires_at)) return null
  if (!transition || asOf < transition.occurred_at) return decision
  if (transition.state_code === 'revoked') return null
  const replacement = replacements.get(transition.replacement_clearance_record_digest_sha256)
  return replacement && replacement.recorded_at <= asOf && replacement.not_before <= asOf && asOf < replacement.expires_at ? replacement : null
}

function assertCurrentPilotClearance(decision, controls, bindings, runtime, classification, asOf, expectedArtifact, expectedScopeSha256, expectedDecisionDigest) {
  if (!decision) fail('semantic', 'CLEARANCE_INVALID', 'clearance does not resolve an immutable decision')
  assertDigest(decision)
  if (decision.record_digest_sha256 !== expectedDecisionDigest) fail('semantic', 'CLEARANCE_INVALID', 'clearance resolver key differs from the immutable decision digest')
  assertClearanceDecisionMatrix(decision, classification)
  if (decision.decision_code !== 'restricted_store_only') fail('semantic', 'CLEARANCE_INVALID', 'the controlled pilot admits only restricted-store clearance')
  if (canonical(decision.artifact) !== canonical(expectedArtifact) || decision.clearance_scope_sha256 !== expectedScopeSha256) fail('semantic', 'CLEARANCE_INVALID', 'clearance artifact or exact semantic scope differs')
  const clearanceProfiles = runtime.operational_profiles.filter((item) => item.profile_kind_code === 'clearance')
  if (decision.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || decision.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || bindings.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || clearanceProfiles.length !== 1 || decision.clearance_operational_profile_sha256 !== clearanceProfiles[0].profile_sha256) fail('semantic', 'CLEARANCE_INVALID', 'clearance cannot resolve its exact runtime, identity bindings, or operational profile')
  const decider = findBinding(bindings, decision.decided_by_binding_code, 'clearance_decider', decision.decided_at)
  const checker = findBinding(bindings, decision.independently_checked_by_binding_code, 'clearance_checker', decision.decided_at)
  if (decider.principal_kind_code !== 'human' || checker.principal_kind_code !== 'human' || decider.unix_uid === checker.unix_uid) fail('semantic', 'CLEARANCE_INVALID', 'clearance lacks distinct eligible human decision maker and checker')
  const requiredScanners = new Map(runtime.scanner_policy.required_scanners.map((item) => [item.scanner_code, item]))
  unique(decision.scanner_results.map((item) => item.scanner_code), 'semantic', 'CLEARANCE_INVALID', 'scanner result')
  assertExactOrder(decision.scanner_results.map((item) => item.scanner_code), [...requiredScanners.keys()], 'semantic', 'CLEARANCE_INVALID', 'clearance scanner result')
  for (const scan of decision.scanner_results) {
    const required = requiredScanners.get(scan.scanner_code)
    const decisionAgeSeconds = (Date.parse(decision.decided_at) - Date.parse(scan.completed_at)) / 1000
    const ageSeconds = (Date.parse(asOf) - Date.parse(scan.completed_at)) / 1000
    if (!required || scan.scanner_build_sha256 !== required.build_sha256 || scan.rules_sha256 !== required.rules_sha256 || scan.result_code !== 'clear' || decisionAgeSeconds < 0 || ageSeconds < 0 || ageSeconds > runtime.limits.scanner_result_age_seconds_max) fail('semantic', ageSeconds > runtime.limits.scanner_result_age_seconds_max ? 'SCREENING_STALE' : 'CLEARANCE_INVALID', 'clearance scanner set, build, rules, result, or use-time age differs from runtime policy')
  }
  for (const transition of controls.clearanceTransitions ?? []) {
    assertDigest(transition)
    findBinding(bindings, transition.recorded_by_binding_code, 'clearance_broker', transition.occurred_at)
  }
  for (const [replacementKey, replacement] of (controls.clearanceReplacements ?? new Map()).entries()) {
    if (replacementKey !== replacement.record_digest_sha256) fail('semantic', 'CLEARANCE_INVALID', 'replacement-clearance lookup key differs from immutable content')
    assertDigest(replacement)
    assertClearanceDecisionMatrix(replacement, classification)
    if (canonical(replacement.artifact) !== canonical(decision.artifact) || replacement.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || replacement.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256) fail('semantic', 'CLEARANCE_INVALID', 'replacement clearance crosses artifact, runtime, or identity-binding context')
  }
  const leaf = clearanceLeafAt(decision, controls.clearanceTransitions ?? [], controls.clearanceReplacements ?? new Map(), classification, asOf)
  if (leaf?.record_digest_sha256 !== decision.record_digest_sha256) fail('semantic', 'CLEARANCE_INVALID', 'clearance is expired, inactive, revoked, superseded, or no longer the exact current decision')
  return decision
}

function assertPrePromotionAuthorization(record, controls, bindings, runtime, classification, usedAt = null, protectedUsedAt = usedAt) {
  if (!record || controls?.prepromotionAuthorizations?.get(record.record_digest_sha256) !== record) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization does not resolve one exact protected record')
  assertDigest(record)
  if (record.record_kind_code !== 'prepromotion_authorization' || record.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || record.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || bindings.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization crosses its immutable runtime or identity bindings')
  if (!(record.evaluated_at <= record.persisted_at && record.persisted_at < record.expires_at) || (usedAt !== null && !(record.persisted_at <= usedAt && usedAt <= protectedUsedAt && protectedUsedAt < record.expires_at))) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization is expired, not yet broker-persisted, backdated after use, or has an invalid lifetime')

  const authorizer = findBinding(bindings, record.authorized_by_binding_code, 'independent_verifier', record.evaluated_at)
  const persister = findBinding(bindings, record.persisted_by_binding_code, 'clearance_broker', record.persisted_at)
  if (authorizer.principal_kind_code !== 'service' || persister.principal_kind_code !== 'service' || authorizer.unix_uid === persister.unix_uid || record.expires_at > authorizer.valid_until || record.expires_at > persister.valid_until) fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'pre-promotion authorization lacks distinct active verifier and fixed-function persister bindings')

  const seal = controls.bundleSeals?.get(record.bundle_seal_record_digest_sha256)
  const handoff = controls.handoffs?.get(record.collector_handoff_record_digest_sha256)
  const candidateSeal = controls.candidateSeals?.get(record.candidate_file_seal_record_digest_sha256)
  const clearance = controls.clearances?.get(record.clearance_decision_record_digest_sha256)
  if (!seal || seal.record_digest_sha256 !== record.bundle_seal_record_digest_sha256 || !handoff || handoff.record_digest_sha256 !== record.collector_handoff_record_digest_sha256 || !candidateSeal || candidateSeal.record_digest_sha256 !== record.candidate_file_seal_record_digest_sha256 || !clearance || clearance.record_digest_sha256 !== record.clearance_decision_record_digest_sha256) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization lacks an exact sealed prerequisite')
  for (const prerequisite of [seal, handoff, candidateSeal]) assertDigest(prerequisite)

  if (seal.record_kind_code !== 'bundle_seal' || seal.bundle_kind_code !== 'single_document' || seal.operation_id !== record.operation_id || seal.operation_nonce !== record.operation_nonce || seal.runtime_profile_record_digest_sha256 !== record.runtime_profile_record_digest_sha256 || seal.identity_bindings_record_digest_sha256 !== record.identity_bindings_record_digest_sha256 || seal.bundle.bundle_sequence !== record.known_through_bundle_sequence || record.known_through_bundle_sequence !== controls.currentBundleSequence || seal.collector_handoffs.length !== 1 || seal.collector_handoffs[0].record_digest_sha256 !== handoff.record_digest_sha256) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization crosses its exact operation, bundle seal, current knowledge sequence, or handoff')
  if (!(seal.sealed_at <= record.evaluated_at && record.evaluated_at < seal.expires_at && handoff.handoff_recorded_at <= record.evaluated_at && record.evaluated_at < handoff.expires_at && candidateSeal.produced_at <= record.evaluated_at && record.evaluated_at < candidateSeal.expires_at)) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization uses a prerequisite outside its active interval')
  if (usedAt !== null && !(usedAt < seal.expires_at && usedAt < handoff.expires_at && usedAt < candidateSeal.expires_at)) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion prerequisite expired before promotion use')
  if (candidateSeal.operation_id !== record.operation_id || candidateSeal.operation_nonce !== record.operation_nonce || candidateSeal.produced_by_binding_code !== record.authorized_by_binding_code || canonical(candidateSeal.expected_prior_logical_state) !== canonical(seal.target_logical_state)) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization crosses its exact candidate seal, verifier, or prior state')
  resolveLogicalStateReference(candidateSeal.expected_prior_logical_state, controls, 'pre-promotion prior logical state', record.evaluated_at)
  resolveLogicalStateReference(candidateSeal.candidate_logical_state, controls, 'pre-promotion candidate logical state', record.evaluated_at)

  if (canonical(record.artifact) !== canonical(handoff.artifact) || canonical(record.artifact) !== canonical(clearance.artifact) || record.source_clearance_scope_sha256 !== clearance.clearance_scope_sha256) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization crosses its exact artifact or clearance scope')
  assertCurrentPilotClearance(clearance, controls, bindings, runtime, classification, record.evaluated_at, record.artifact, record.source_clearance_scope_sha256, record.clearance_decision_record_digest_sha256)
  assertCurrentPilotClearance(clearance, controls, bindings, runtime, classification, record.persisted_at, record.artifact, record.source_clearance_scope_sha256, record.clearance_decision_record_digest_sha256)
  if (usedAt !== null) assertCurrentPilotClearance(clearance, controls, bindings, runtime, classification, usedAt, record.artifact, record.source_clearance_scope_sha256, record.clearance_decision_record_digest_sha256)

  const copyCodes = [...new Set((controls.custodyRecords ?? []).filter((item) => canonical(item.artifact) === canonical(record.artifact)).map((item) => item.copy_code))]
  const custodyLeaves = copyCodes.map((copyCode) => resolveCustodyLeaf(controls.custodyRecords, record.artifact, copyCode, record.evaluated_at, record.known_through_bundle_sequence)).filter(Boolean)
  const matchingLeaves = custodyLeaves.filter((leaf) => ['placed', 'relocated', 'restored'].includes(leaf.event_kind_code) && custodyLeafProjectionDigest(leaf) === record.custody_leaf_projection_sha256)
  if (matchingLeaves.length !== 1) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion authorization does not pin one exact openable custody leaf')
  if (usedAt !== null) {
    const liveLeaf = resolveCustodyLeaf(controls.custodyRecords, record.artifact, matchingLeaves[0].copy_code, usedAt, record.known_through_bundle_sequence)
    if (!liveLeaf || !['placed', 'relocated', 'restored'].includes(liveLeaf.event_kind_code) || custodyLeafProjectionDigest(liveLeaf) !== record.custody_leaf_projection_sha256) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion custody leaf changed before promotion use')
  }
  return { seal, handoff, candidateSeal, clearance, custodyLeaf: matchingLeaves[0] }
}

function assertPrePromotionBoundary(controls, bindings, runtime, classification, evaluatedAt, expectedArtifact, expectedScopeSha256, expectedDecisionDigest, bundleSealDigest, handoffDigest) {
  const records = [...(controls.prepromotionAuthorizations?.values() ?? [])].filter((record) => record.evaluated_at === evaluatedAt && canonical(record.artifact) === canonical(expectedArtifact) && record.source_clearance_scope_sha256 === expectedScopeSha256 && record.clearance_decision_record_digest_sha256 === expectedDecisionDigest && record.bundle_seal_record_digest_sha256 === bundleSealDigest && record.collector_handoff_record_digest_sha256 === handoffDigest)
  if (records.length !== 1) fail('semantic', 'CLEARANCE_INVALID', 'pre-promotion boundary does not resolve one exact authorization record')
  return assertPrePromotionAuthorization(records[0], controls, bindings, runtime, classification, records[0].persisted_at, records[0].persisted_at)
}

function custodyLeafProjection(record) {
  return {
    artifact: structuredClone(record.artifact),
    backend_code: record.backend_code,
    backend_reference: record.backend_reference,
    copy_code: record.copy_code,
    custody_class_code: record.custody_class_code,
    custody_event_code: record.custody_event_code,
    event_kind_code: record.event_kind_code,
    evidence_bundle: structuredClone(record.evidence_bundle),
    occurred_at: record.occurred_at,
    predecessor_custody_event_code: record.predecessor_custody_event_code,
    reason: record.reason,
    recorded_at: record.recorded_at,
    recorded_by_principal_code: record.recorded_by_principal_code,
    repository_eligibility_declaration: structuredClone(record.repository_eligibility_declaration),
  }
}

function custodyLeafProjectionDigest(record) {
  return sha256(Buffer.from(canonical(custodyLeafProjection(record)), 'utf8'))
}

function assertPilotCasReference(artifact, backendCode, backendReference) {
  if (artifact === null || artifact === undefined || backendCode === null || backendCode === undefined || backendReference === null || backendReference === undefined) return
  const expected = `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}`
  if (backendCode !== 'pilot_local_cas_v1' || backendReference !== expected) fail('semantic', 'IPC_REPLAY_DETECTED', 'pilot custody reference is not the exact content-addressed key for its artifact bytes')
}

function custodyRecordsFromManifest(manifest) {
  const artifacts = new Map(manifest.artifacts.map((item) => [item.record_code, {
    byte_layer_code: item.byte_layer_code,
    byte_length: item.byte_length,
    hash_algorithm_code: item.hash_algorithm_code,
    sha256: item.sha256,
  }]))
  const evidenceBundle = {
    bundle_digest_sha256: manifest.bundle_digest_sha256,
    bundle_id: manifest.bundle_id,
    bundle_sequence: manifest.bundle_sequence,
  }
  return manifest.custody_events.map((event) => ({
    artifact: structuredClone(artifacts.get(event.artifact_code)),
    backend_code: event.backend_code,
    backend_reference: event.backend_reference,
    copy_code: event.copy_code,
    custody_class_code: event.custody_class_code,
    custody_event_code: event.record_code,
    event_kind_code: event.event_kind_code,
    evidence_bundle: structuredClone(evidenceBundle),
    occurred_at: event.occurred_at,
    predecessor_custody_event_code: event.predecessor_custody_event_code,
    reason: event.reason,
    recorded_at: event.recorded_at,
    recorded_by_principal_code: event.recorded_by_principal_code,
    repository_eligibility_declaration: event.repository_eligibility_declaration === null ? null : {
      declared_at: event.repository_eligibility_declaration.declared_at,
      declared_by_principal_code: event.repository_eligibility_declaration.declared_by_principal_code,
      no_sensitive_data_declared: event.repository_eligibility_declaration.no_sensitive_data_declared,
      permanent_history_acknowledged: event.repository_eligibility_declaration.permanent_history_acknowledged,
      redistribution_eligible_declared: event.repository_eligibility_declaration.redistribution_eligible_declared,
      size_eligible_declared: event.repository_eligibility_declaration.size_eligible_declared,
    },
  }))
}

function resolveCustodyLeaf(records, artifact, copyCode, evaluatedAt, knownThroughBundleSequence) {
  const subject = records.filter((record) => canonical(record.artifact) === canonical(artifact) && record.copy_code === copyCode)
  unique(subject.map((record) => record.custody_event_code), 'semantic', 'IPC_REPLAY_DETECTED', 'custody event code')
  const byCode = new Map(subject.map((record) => [record.custody_event_code, record]))
  const successors = new Map()
  for (const record of subject) {
    if (!record.artifact || !record.evidence_bundle || !Number.isSafeInteger(record.evidence_bundle.bundle_sequence) || record.evidence_bundle.bundle_sequence < 1 || record.recorded_at < record.occurred_at) fail('semantic', 'IPC_REPLAY_DETECTED', 'custody history has an invalid subject, bundle, or chronology')
    assertPilotCasReference(record.artifact, record.backend_code, record.backend_reference)
    if (record.predecessor_custody_event_code === null) continue
    const predecessor = byCode.get(record.predecessor_custody_event_code)
    if (!predecessor || predecessor.occurred_at > record.occurred_at || predecessor.recorded_at >= record.recorded_at || predecessor.evidence_bundle.bundle_sequence > record.evidence_bundle.bundle_sequence) fail('semantic', 'IPC_REPLAY_DETECTED', 'custody history has a wrong-subject, backdated, or unknown predecessor')
    const list = successors.get(predecessor.custody_event_code) ?? []
    list.push(record)
    successors.set(predecessor.custody_event_code, list)
  }
  if ([...successors.values()].some((items) => items.length > 1)) fail('semantic', 'IPC_REPLAY_DETECTED', 'custody history has competing successors')
  const bounded = subject.filter((record) => record.occurred_at <= evaluatedAt && record.recorded_at <= evaluatedAt && record.evidence_bundle.bundle_sequence <= knownThroughBundleSequence)
  if (bounded.length === 0) return null
  const boundedCodes = new Set(bounded.map((record) => record.custody_event_code))
  const roots = bounded.filter((record) => record.predecessor_custody_event_code === null)
  if (roots.length !== 1) fail('semantic', 'IPC_REPLAY_DETECTED', 'custody projection lacks exactly one bounded root')
  let leaf = roots[0]
  const visited = new Set([leaf.custody_event_code])
  while (true) {
    const next = (successors.get(leaf.custody_event_code) ?? []).filter((record) => boundedCodes.has(record.custody_event_code))
    if (next.length === 0) break
    if (next.length !== 1 || visited.has(next[0].custody_event_code)) fail('semantic', 'IPC_REPLAY_DETECTED', 'custody projection contains a fork or cycle')
    leaf = next[0]
    visited.add(leaf.custody_event_code)
  }
  if (visited.size !== bounded.length) fail('semantic', 'IPC_REPLAY_DETECTED', 'custody projection contains a disconnected assertion')
  return leaf
}

function assertCanonicalLineage(expected, values) {
  if (!expected || values.some((item) => item !== expected)) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'state seals, permits, and replay authority cross canonical lineages')
}

function assertHandoffManifestLink(handoff, manifest, retainedManifests = [manifest]) {
  for (const retainedManifest of retainedManifests) {
    const computedDigest = sha256(Buffer.from(canonical(withoutTopLevel(retainedManifest, 'bundle_digest_sha256')), 'utf8'))
    if (retainedManifest.bundle_digest_sha256 !== computedDigest) fail('semantic', 'HANDOFF_MISMATCH', 'retained manifest content does not match its declared bundle digest')
  }
  const currentManifestMatches = retainedManifests.filter((candidateManifest) => candidateManifest.bundle_id === manifest.bundle_id && candidateManifest.bundle_sequence === manifest.bundle_sequence && candidateManifest.bundle_digest_sha256 === manifest.bundle_digest_sha256 && canonical(candidateManifest) === canonical(manifest))
  if (currentManifestMatches.length !== 1) fail('semantic', 'HANDOFF_MISMATCH', 'current manifest does not resolve exactly once to immutable retained bytes')
  const currentOwner = currentManifestMatches[0]
  const resolveUniqueRecord = (collectionName, recordCode, label) => {
    const matches = retainedManifests.flatMap((candidateManifest) => candidateManifest[collectionName]
      .filter((item) => item.record_code === recordCode)
      .map((record) => ({ manifest: candidateManifest, record })))
    if (matches.length !== 1) fail('semantic', 'HANDOFF_MISMATCH', `${label} does not resolve exactly once across the retained manifest lineage`)
    return matches[0]
  }
  const assertPinnedOwner = (ownerManifest, label) => {
    if (ownerManifest === currentOwner) return
    const matches = manifest.required_bundles.filter((dependency) => dependency.bundle_id === ownerManifest.bundle_id && dependency.bundle_digest_sha256 === ownerManifest.bundle_digest_sha256)
    if (matches.length !== 1 || ownerManifest.bundle_sequence >= manifest.bundle_sequence) fail('semantic', 'HANDOFF_MISMATCH', `${label} is not pinned to one earlier retained bundle`)
  }
  const retrievals = manifest.retrieval_events.filter((item) => item.record_code === handoff.retrieval_event_code)
  if (retrievals.length !== 1) fail('semantic', 'HANDOFF_MISMATCH', 'collector handoff does not resolve exactly one manifest retrieval event')
  const retrieval = retrievals[0]
  const conditionalFields = [retrieval.conditional_basis_retrieval_event_code, retrieval.conditional_validator_kind_code, retrieval.conditional_validator_value]
  const hasNoConditionalBasis = conditionalFields.every((item) => item === null)
  const hasCompleteConditionalBasis = retrieval.conditional_basis_retrieval_event_code !== null
    && ['etag', 'last_modified'].includes(retrieval.conditional_validator_kind_code)
    && typeof retrieval.conditional_validator_value === 'string'
  if (!hasNoConditionalBasis && !hasCompleteConditionalBasis) fail('semantic', 'HANDOFF_MISMATCH', 'collector handoff conditional basis is partial')
  const locationMatch = resolveUniqueRecord('retrieval_locations', retrieval.requested_location_code, 'collector handoff requested location')
  const artifactMatch = resolveUniqueRecord('artifacts', retrieval.artifact_code, 'collector handoff artifact')
  const location = locationMatch.record
  const artifact = artifactMatch.record
  assertPinnedOwner(locationMatch.manifest, 'collector handoff requested location')
  assertPinnedOwner(artifactMatch.manifest, 'collector handoff artifact')
  const basisMatch = hasNoConditionalBasis
    ? null
    : resolveUniqueRecord('retrieval_events', retrieval.conditional_basis_retrieval_event_code, 'collector handoff conditional basis')
  const basis = basisMatch?.record ?? null
  if (basisMatch) {
    assertPinnedOwner(basisMatch.manifest, 'collector handoff conditional basis')
    if (basis.outcome_code !== 'retrieved_retained' || basis.http_status_code !== 200 || basis.completed_at >= retrieval.started_at) fail('semantic', 'HANDOFF_MISMATCH', 'collector handoff conditional basis is not an earlier retained full representation')
    if (basis.request_method_code !== retrieval.request_method_code || basis.request_profile_code !== retrieval.request_profile_code || canonical(basis.request_headers) !== canonical(retrieval.request_headers)) fail('semantic', 'HANDOFF_MISMATCH', 'collector handoff conditional basis uses a different representation profile')
    const expectedValidator = retrieval.conditional_validator_kind_code === 'etag' ? basis.response_metadata.etag : basis.response_metadata.last_modified
    if (retrieval.conditional_validator_value !== expectedValidator) fail('semantic', 'HANDOFF_MISMATCH', 'collector handoff conditional validator differs from the exact basis representation')
  }
  if (!location || !artifact || retrieval.outcome_code !== 'retrieved_retained' || retrieval.captured_at === null) fail('semantic', 'HANDOFF_MISMATCH', 'collector handoff retrieval lacks an exact captured retained artifact and location')
  const requestProjection = {
    conditional_basis: {
      bundle_digest_sha256: basis === null ? null : basisMatch.manifest.bundle_digest_sha256,
      bundle_id: basis === null ? null : basisMatch.manifest.bundle_id,
      bundle_sequence: basis === null ? null : basisMatch.manifest.bundle_sequence,
      retrieval_event_code: basis?.record_code ?? null,
      validator_kind_code: retrieval.conditional_validator_kind_code,
      validator_value: retrieval.conditional_validator_value,
    },
    request_headers: structuredClone(retrieval.request_headers),
    request_method_code: retrieval.request_method_code,
    request_profile_code: retrieval.request_profile_code,
    requested_location_url: location.url,
  }
  const artifactIdentity = { byte_layer_code: artifact.byte_layer_code, hash_algorithm_code: artifact.hash_algorithm_code, sha256: artifact.sha256, byte_length: artifact.byte_length }
  if (handoff.request_fingerprint_sha256 !== sha256(Buffer.from(canonical(requestProjection), 'utf8')) || canonical(handoff.artifact) !== canonical(artifactIdentity) || handoff.staged_path !== artifact.staged_path || retrieval.artifact_staged_path !== artifact.staged_path || handoff.collector_principal_code !== retrieval.collector_principal_code || handoff.collector_software_code !== retrieval.collector_software_code || handoff.collector_version !== retrieval.collector_version || handoff.collection_started_at !== retrieval.started_at || handoff.collection_completed_at !== retrieval.captured_at) fail('semantic', 'HANDOFF_MISMATCH', 'collector handoff differs from its exact retrieval request, collector, chronology, artifact, or staged path')
}

function assertCrossContractSemantics(fixtures, classification, catalogRawSha) {
  const value = (code) => {
    const result = fixtures.get(code)?.value
    if (!result) fail('fixture', 'MISSING_FIXTURE', `missing ${code}`)
    return result
  }
  const runtime = value('runtime_profile')
  const bindings = value('identity_bindings')
  const emptyState = value('logical_state_empty')
  const bootstrapState = value('logical_state_bootstrap')
  const handoff = value('collector_handoff')
  const bootstrapSeal = value('bootstrap_bundle_seal')
  const documentSeal = value('document_bundle_seal')
  const permit = value('bootstrap_permit')
  const transition1 = value('bootstrap_transition_in_progress')
  const transition2 = value('bootstrap_transition_spent')
  const replay = value('replay_certificate')
  const recoveryPermit = value('recovery_permit')
  const recoveryTransition1 = value('recovery_transition_in_progress')
  const recoveryTransition2 = value('recovery_transition_spent')
  const completionPermit = value('post_promotion_completion_permit')
  const completionTransition1 = value('post_promotion_completion_transition_in_progress')
  const completionTransition2 = value('post_promotion_completion_transition_spent')
  const recoveredResult = value('import_result_recovered')
  const request = value('custody_open_request')
  const response = value('custody_open_response')
  const sourceCapabilityIssuance = value('capability_source_issuance')
  const preparationCapabilityIssuance = value('capability_preparation_issuance')
  const sealedCapabilityIssuance = value('capability_sealed_issuance')
  const sourceCapabilityTransition = value('capability_source_transition')
  const sealedCapabilityTransition = value('capability_sealed_transition')
  const prepareRequest = value('custody_prepare_request')
  const prepareResponse = value('custody_prepare_response')
  const sealRequest = value('custody_seal_request')
  const sealResponse = value('custody_seal_response')
  const custodyAccessRequest = value('custody_open_access_request')
  const custodyAccessResponse = value('custody_open_access_response')
  const clearance = value('clearance_decision')
  const clearanceTransition = value('clearance_transition')
  const prepromotionAuthorization = value('prepromotion_authorization')
  const candidateSeal = value('candidate_file_seal')
  const journal1 = value('journal_started')
  const journal2 = value('journal_completed')
  const documentState = value('logical_state_document_002')
  const documentJournal1 = value('journal_document_started')
  const documentJournal2 = value('journal_document_recovery_required')
  const completionJournal1 = value('journal_completion_started')
  const completionJournal2 = value('journal_completion_completed')
  const bootstrapCompletionSourceJournal = value('journal_bootstrap_backup_recovery_required')
  const bootstrapCompletionPermit = value('post_promotion_bootstrap_completion_permit')
  const bootstrapCompletionTransition1 = value('post_promotion_bootstrap_completion_transition_in_progress')
  const bootstrapCompletionTransition2 = value('post_promotion_bootstrap_completion_transition_spent')
  const bootstrapCompletionJournal1 = value('journal_bootstrap_completion_started')
  const bootstrapCompletionJournal2 = value('journal_bootstrap_completion_verified')
  const bootstrapCompletionJournal3 = value('journal_bootstrap_completion_completed')
  const bootstrapCompletionResult = value('import_result_bootstrap_completion_recovered')
  const documentManifest = parseJsonBytes(fs.readFileSync(completeDocumentManifestPath), { contractNumbers: true, maximumBytes: pilotLimits.manifest_bytes_max })
  const bootstrapManifest = loadJson(goldenVectorsPath).complete_manifest_vector.value
  const allJournalEvents = [...fixtures.values()].filter((fixture) => fixture.schema_file === 'operation-journal-event-v1.schema.json').map((fixture) => fixture.value)
  const allCandidateSeals = [...fixtures.values()].filter((fixture) => fixture.schema_file === 'logical-state-seal-v1.schema.json' && fixture.value.record_kind_code === 'candidate_file_seal').map((fixture) => fixture.value)
  const stateReference = (state) => ({ state_seal_code: state.record_code, state_seal_record_digest_sha256: state.record_digest_sha256, logical_state_sha256: state.logical_state_sha256 })
  const authorizationControls = {
    bindings,
    runtime,
    permits: new Map([permit, recoveryPermit, completionPermit, bootstrapCompletionPermit].map((item) => [item.record_digest_sha256, item])),
    transitions: new Map([transition1, transition2, recoveryTransition1, recoveryTransition2, completionTransition1, completionTransition2, bootstrapCompletionTransition1, bootstrapCompletionTransition2].map((item) => [item.record_digest_sha256, item])),
    bundleReferences: new Map([
      [bundleResolverKey('principal_bootstrap', bootstrapSeal.bundle), structuredClone(bootstrapSeal.bundle)],
      [bundleResolverKey('single_document', documentSeal.bundle), structuredClone(documentSeal.bundle)],
    ]),
    bootstrapManifests: new Map([[bundleResolverKey('principal_bootstrap', bootstrapSeal.bundle), bootstrapManifest]]),
    logicalStateRecords: new Map([emptyState, bootstrapState, documentState].map((state) => [state.record_digest_sha256, state])),
    bundleSeals: new Map([bootstrapSeal, documentSeal].map((item) => [item.record_digest_sha256, item])),
    replayCertificates: new Map([[replay.record_digest_sha256, replay]]),
    journalEvents: new Map(allJournalEvents.map((item) => [item.record_digest_sha256, item])),
    candidateSeals: new Map(allCandidateSeals.map((item) => [item.record_digest_sha256, item])),
    prepromotionAuthorizations: new Map([[prepromotionAuthorization.record_digest_sha256, prepromotionAuthorization]]),
    clearances: new Map([[clearance.record_digest_sha256, clearance]]),
    handoffs: new Map([[handoff.record_digest_sha256, handoff]]),
    clearanceTransitions: [],
    clearanceReplacements: new Map(),
    custodyRecords: custodyRecordsFromManifest(documentManifest),
    currentBundleSequence: documentManifest.bundle_sequence,
    journalTargetStates: new Map([
      [permit.record_digest_sha256, stateReference(emptyState)],
      [recoveryPermit.record_digest_sha256, structuredClone(recoveryPermit.target_empty_logical_state)],
      [completionPermit.record_digest_sha256, structuredClone(completionPermit.verified_canonical_logical_state)],
      [bootstrapCompletionPermit.record_digest_sha256, structuredClone(bootstrapCompletionPermit.verified_canonical_logical_state)],
    ]),
    permitTerminalStates: new Map([
      [permit.record_digest_sha256, stateReference(bootstrapState)],
      [recoveryPermit.record_digest_sha256, stateReference(bootstrapState)],
      [completionPermit.record_digest_sha256, stateReference(documentState)],
      [bootstrapCompletionPermit.record_digest_sha256, stateReference(bootstrapState)],
    ]),
  }
  // Validate the trust anchors before resolving any dependent authorization
  // record so an identity/profile defect cannot be masked as a downstream
  // permit-reference failure.
  assertRuntimeProfile(runtime, catalogRawSha, classification)
  assertIdentityBindings(bindings, classification)
  const emptyReference = stateReference(emptyState)
  const assertPermitIssuanceMatrix = () => {
    assertPermitIssuance(permit, authorizationControls, classification)
    // Exercise the journal root itself before dependent recovery authorities;
    // this preserves the direct failure surface for malformed operation facts.
    assertJournalEvent(journal1, classification, bindings, runtime, authorizationControls)
    resolvePermitTransitionChain(permit, authorizationControls, classification)
    for (const candidate of [recoveryPermit, completionPermit, bootstrapCompletionPermit]) assertPermitIssuance(candidate, authorizationControls, classification)
    const rejectPermit = (label, base, mutate, mutateControls = null) => {
      const candidate = structuredClone(base)
      mutate(candidate)
      candidate.record_digest_sha256 = recordDigest(candidate)
      const controls = mutateControls ? mutateControls(authorizationControls, candidate) : authorizationControls
      assert.throws(() => assertPermitIssuance(candidate, controls, classification), /BOOTSTRAP_PERMIT_INVALID|RECOVERY_PERMIT_INVALID|REPLAY_CERTIFICATE_INVALID|RECOVERY_STATE_AMBIGUOUS|IDENTITY_BINDING_MISMATCH/, `${label} unexpectedly passed`)
    }
    rejectPermit('bootstrap-lineage-substitution', permit, (item) => { item.canonical_lineage_code = 'synthetic.other-lineage' })
    rejectPermit('bootstrap-roster-commitment-substitution', permit, (item) => { item.expected_principal_roster_sha256 = '9'.repeat(64) })
    rejectPermit('bootstrap-overlong-lifetime', permit, (item) => { item.expires_at = new Date(Date.parse(item.issued_at) + classification.bootstrap_permit_policy.maximum_lifetime_ms + 1).toISOString() })
    rejectPermit('bootstrap-self-review-role', permit, (item) => { item.witness_binding_code = item.submitter_binding_code })
    rejectPermit('recovery-replay-substitution', recoveryPermit, (item) => { item.replay_certificate.record_digest_sha256 = '8'.repeat(64) })
    rejectPermit('recovery-human-role-collision', recoveryPermit, (item) => { item.witness_binding_code = item.operator_binding_code })
    rejectPermit('completion-action-expansion', completionPermit, (item) => { item.allowed_actions.push('write_canonical_database') })
    rejectPermit('completion-source-authorization-substitution', completionPermit, (item) => { item.source_authorization_record_digest_sha256 = permit.record_digest_sha256 })
    rejectPermit('bootstrap-completion-without-spent-source', bootstrapCompletionPermit, () => {}, (controls) => ({
      ...controls,
      transitions: new Map([...controls.transitions].filter(([digest]) => digest !== transition2.record_digest_sha256)),
    }))
    const lateClaim = structuredClone(transition1)
    lateClaim.occurred_at = new Date(Date.parse(permit.expires_at) - classification.permit_claim_policy.minimum_remaining_lifetime_ms + 1).toISOString()
    lateClaim.persisted_at = lateClaim.occurred_at
    lateClaim.record_digest_sha256 = recordDigest(lateClaim)
    const lateClaimControls = { ...authorizationControls, transitions: new Map([[lateClaim.record_digest_sha256, lateClaim]]) }
    assert.throws(() => resolvePermitTransitionChain(permit, lateClaimControls, classification), /minimum remaining lifetime/)
    const unclaimedControls = { ...authorizationControls, transitions: new Map() }
    const beforeIssuance = new Date(Date.parse(permit.issued_at) - 1).toISOString()
    const beforeExpiry = new Date(Date.parse(permit.expires_at) - 1).toISOString()
    if (resolvePermitTransitionChain(permit, unclaimedControls, classification, beforeIssuance).derivedStateCode !== null) fail('fixture', 'FIXTURE_INVALID', 'permit lifecycle became visible before issuance')
    if (resolvePermitTransitionChain(permit, unclaimedControls, classification, beforeExpiry).derivedStateCode !== 'ready') fail('fixture', 'FIXTURE_INVALID', 'unclaimed permit did not project ready before expiry')
    if (resolvePermitTransitionChain(permit, unclaimedControls, classification, permit.expires_at).derivedStateCode !== classification.permit_claim_policy.expired_ready_projection_code) fail('fixture', 'FIXTURE_INVALID', 'expired unclaimed permit did not project its terminal unused state')
    const claimOnlyControls = { ...authorizationControls, transitions: new Map([[transition1.record_digest_sha256, transition1]]) }
    if (resolvePermitTransitionChain(permit, claimOnlyControls, classification, beforeExpiry).derivedStateCode !== 'in_progress') fail('fixture', 'FIXTURE_INVALID', 'claimed permit did not project in_progress before expiry')
    if (resolvePermitTransitionChain(permit, claimOnlyControls, classification, permit.expires_at).derivedStateCode !== classification.permit_claim_policy.expired_in_progress_projection_code) fail('fixture', 'FIXTURE_INVALID', 'expired claimed permit did not project the terminal recovery hold')
    assert.throws(() => resolvePermitTransitionChain(permit, claimOnlyControls, classification, '2030-01-01T00:00:00Z'), /as_of is not a canonical UTC timestamp/)
    const impossibleKnowledgeOrder = structuredClone(transition1)
    impossibleKnowledgeOrder.persisted_at = new Date(Date.parse(impossibleKnowledgeOrder.occurred_at) - 1).toISOString()
    impossibleKnowledgeOrder.record_digest_sha256 = recordDigest(impossibleKnowledgeOrder)
    assert.throws(() => assertPermitTransition(impossibleKnowledgeOrder, permit, null, emptyReference, null, bindings, classification, emptyState.produced_at), /protected persistence falls outside/)
    const backdatedAfterExpiry = structuredClone(transition2)
    backdatedAfterExpiry.persisted_at = permit.expires_at
    backdatedAfterExpiry.previous_transition_record_digest_sha256 = transition1.record_digest_sha256
    backdatedAfterExpiry.record_digest_sha256 = recordDigest(backdatedAfterExpiry)
    const backdatedAfterExpiryControls = { ...authorizationControls, transitions: new Map([[transition1.record_digest_sha256, transition1], [backdatedAfterExpiry.record_digest_sha256, backdatedAfterExpiry]]) }
    assert.throws(() => resolvePermitTransitionChain(permit, backdatedAfterExpiryControls, classification), /protected persistence falls outside/)
    const nonMonotonicSuccessor = structuredClone(transition2)
    nonMonotonicSuccessor.persisted_at = transition1.persisted_at
    nonMonotonicSuccessor.record_digest_sha256 = recordDigest(nonMonotonicSuccessor)
    assert.throws(() => assertPermitTransition(nonMonotonicSuccessor, permit, transition1, authorizationControls.permitTerminalStates.get(permit.record_digest_sha256), null, bindings, classification), /backdated semantic\/broker successor/)
    const wrongTransitionWriter = structuredClone(transition1)
    wrongTransitionWriter.persisted_by_binding_code = 'binding.importer'
    wrongTransitionWriter.record_digest_sha256 = recordDigest(wrongTransitionWriter)
    assert.throws(() => assertPermitTransition(wrongTransitionWriter, permit, null, emptyReference, null, bindings, classification, emptyState.produced_at), /BOOTSTRAP_PERMIT_INVALID|IDENTITY_BINDING_MISMATCH/)
    const ambiguousTransition = structuredClone(transition2)
    ambiguousTransition.record_code = 'synthetic.bootstrap-transition-ambiguous'
    ambiguousTransition.to_state_code = 'recovery_required'
    ambiguousTransition.transition_code = 'state_ambiguous'
    ambiguousTransition.reason_code = 'state_ambiguous'
    ambiguousTransition.observed_logical_state = null
    ambiguousTransition.completion_journal_head_record_digest_sha256 = null
    ambiguousTransition.occurred_at = new Date(Date.parse(transition1.occurred_at) + 1000).toISOString()
    ambiguousTransition.persisted_at = ambiguousTransition.occurred_at
    ambiguousTransition.previous_transition_record_digest_sha256 = transition1.record_digest_sha256
    ambiguousTransition.record_digest_sha256 = recordDigest(ambiguousTransition)
    const ambiguousControls = {
      ...authorizationControls,
      transitions: new Map([[transition1.record_digest_sha256, transition1], [ambiguousTransition.record_digest_sha256, ambiguousTransition]]),
      permitTerminalStates: new Map(authorizationControls.permitTerminalStates),
    }
    assert.doesNotThrow(() => resolvePermitTransitionChain(permit, ambiguousControls, classification))
    const lastKnownAmbiguity = structuredClone(ambiguousTransition)
    lastKnownAmbiguity.observed_logical_state = structuredClone(emptyReference)
    lastKnownAmbiguity.record_digest_sha256 = recordDigest(lastKnownAmbiguity)
    const lastKnownControls = { ...ambiguousControls, transitions: new Map([[transition1.record_digest_sha256, transition1], [lastKnownAmbiguity.record_digest_sha256, lastKnownAmbiguity]]), permitTerminalStates: new Map([[permit.record_digest_sha256, emptyReference]]) }
    assert.doesNotThrow(() => resolvePermitTransitionChain(permit, lastKnownControls, classification))
    const futureStateAmbiguity = structuredClone(lastKnownAmbiguity)
    futureStateAmbiguity.observed_logical_state = { state_seal_code: documentState.record_code, state_seal_record_digest_sha256: documentState.record_digest_sha256, logical_state_sha256: documentState.logical_state_sha256 }
    futureStateAmbiguity.record_digest_sha256 = recordDigest(futureStateAmbiguity)
    const futureStateControls = { ...lastKnownControls, transitions: new Map([[transition1.record_digest_sha256, transition1], [futureStateAmbiguity.record_digest_sha256, futureStateAmbiguity]]), permitTerminalStates: new Map([[permit.record_digest_sha256, futureStateAmbiguity.observed_logical_state]]) }
    assert.throws(() => resolvePermitTransitionChain(permit, futureStateControls, classification), /was not available/)
  }

  const canonicalLineageCode = emptyState.state_payload.canonical_lineage_code
  const lineageValues = [
    bootstrapState.state_payload.canonical_lineage_code,
    documentState.state_payload.canonical_lineage_code,
    permit.canonical_lineage_code,
    replay.canonical_lineage_code,
    recoveryPermit.canonical_lineage_code,
    completionPermit.canonical_lineage_code,
  ]
  assertCanonicalLineage(canonicalLineageCode, lineageValues)

  assertRuntimeProfile(runtime, catalogRawSha, classification)
  assertIdentityBindings(bindings, classification)
  if (bindings.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256) fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'binding set pins wrong runtime profile')
  if (bindings.issued_at < runtime.issued_at) fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'identity bindings were issued before their runtime profile')
  if (bindings.runtime_domain_sha256 !== runtime.runtime_domain_sha256) fail('semantic', 'IDENTITY_BINDING_MISMATCH', 'binding set belongs to another runtime domain')
  const releases = new Map(runtime.component_releases.map((item) => [item.runtime_role_code, item]))
  for (const binding of bindings.bindings.filter((item) => item.principal_kind_code === 'service')) {
    const release = releases.get(binding.runtime_role_code)
    if (!release || release.executable_sha256 !== binding.executable_sha256) fail('semantic', 'IDENTITY_BINDING_MISMATCH', `${binding.runtime_role_code} is not bound to its frozen component release`)
  }

  const assertState = (state) => {
    if (state.state_payload.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || state.state_payload.contract_catalog_sha256 !== catalogRawSha || state.state_payload.complete_schema_sha256 !== runtime.database_contract.complete_schema_sha256 || state.state_payload.legacy_schema_sha256 !== runtime.database_contract.legacy_schema_sha256) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'logical state pins wrong runtime or database-schema contract')
    assertExactMigrationList(state.state_payload.migration_hashes)
    if (state.logical_state_sha256 !== sha256(Buffer.from(canonical(state.state_payload), 'utf8'))) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'logical state payload digest mismatch')
    if (state.state_payload.principal_roster_sha256 !== sha256(Buffer.from(canonical(state.state_payload.principal_roster), 'utf8'))) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'principal roster digest mismatch')
    const legacyNames = state.state_payload.legacy_rows.map((row) => row.table_code)
    const atlasNames = state.state_payload.atlas_tables.map((row) => row.table_code)
    unique(legacyNames, 'semantic', 'LOGICAL_STATE_MISMATCH', 'legacy table digest')
    unique(atlasNames, 'semantic', 'LOGICAL_STATE_MISMATCH', 'Atlas table digest')
    assertExactOrder(legacyNames, legacyTables, 'semantic', 'LOGICAL_STATE_MISMATCH', 'legacy table digest')
    assertExactOrder(atlasNames, atlasTables, 'semantic', 'LOGICAL_STATE_MISMATCH', 'Atlas table digest')
    findBinding(bindings, state.produced_by_binding_code, 'independent_verifier', state.produced_at)
  }
  assertState(emptyState)
  assertState(bootstrapState)
  assertState(documentState)
  if (emptyState.state_payload.receipt_head !== null || emptyState.state_payload.principal_roster.length !== 0 || emptyState.state_payload.prior_logical_state_sha256 !== null || emptyState.state_payload.atlas_tables.some((row) => row.row_count !== 0)) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'empty logical state is not actually empty')
  if (bootstrapState.state_payload.prior_logical_state_sha256 !== emptyState.logical_state_sha256 || bootstrapState.state_payload.principal_roster.length !== runtime.pilot_bundle_shape.bootstrap_principals_exact) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'bootstrap state is not the exact successor of the empty state')
  assertExactOrder(bootstrapState.state_payload.principal_roster.map((row) => row.id), [1, 2, 3, 4], 'semantic', 'LOGICAL_STATE_MISMATCH', 'bootstrap principal ID')
  assertExactOrder(bootstrapState.state_payload.principal_roster.map((row) => row.principal_code), ['system.bootstrap', 'synthetic.human', 'synthetic.collector', 'synthetic.importer'], 'semantic', 'LOGICAL_STATE_MISMATCH', 'bootstrap principal roster')
  const bootstrapCounts = new Map(bootstrapState.state_payload.atlas_tables.map((row) => [row.table_code, row.row_count]))
  if (bootstrapCounts.get('atlas_principals') !== 4 || bootstrapCounts.get('atlas_evidence_bundle_receipts') !== 1 || [...bootstrapCounts].some(([table, count]) => !['atlas_principals', 'atlas_evidence_bundle_receipts'].includes(table) && count !== 0)) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'bootstrap state contains data outside its exact first-bundle effect')
  if (bootstrapState.state_payload.receipt_head.bundle_id !== bootstrapSeal.bundle.bundle_id || bootstrapState.state_payload.receipt_head.bundle_sequence !== bootstrapSeal.bundle.bundle_sequence || bootstrapState.state_payload.receipt_head.bundle_digest_sha256 !== bootstrapSeal.bundle.bundle_digest_sha256) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'bootstrap state receipt head differs from the sealed accepted bundle')
  const documentCounts = new Map(documentState.state_payload.atlas_tables.map((row) => [row.table_code, row.row_count]))
  const expectedDocumentCounts = new Map([
    ['atlas_principals', 4],
    ['atlas_evidence_bundle_receipts', 2],
    ['atlas_retrieval_locations', 1],
    ['atlas_artifacts', 1],
    ['atlas_retrieval_events', 1],
    ['atlas_retrieval_redirects', 0],
    ['atlas_artifact_custody_events', 1],
    ['atlas_processing_runs', 0],
    ['atlas_processing_outputs', 0],
    ['atlas_unverified_candidate_occurrences', 0],
    ['atlas_languages', 0],
    ['atlas_jurisdictions', 0],
    ['atlas_jurisdiction_versions', 0],
  ])
  if (documentState.state_payload.prior_logical_state_sha256 !== bootstrapState.logical_state_sha256 || canonical(documentState.state_payload.principal_roster) !== canonical(bootstrapState.state_payload.principal_roster) || documentState.state_payload.receipt_head?.bundle_sequence !== 2 || [...expectedDocumentCounts].some(([table, count]) => documentCounts.get(table) !== count)) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'document state is not the exact successor of the bootstrap state')

  findBinding(bindings, handoff.collector_binding_code, 'collector', handoff.collection_started_at)
  findBinding(bindings, handoff.collector_binding_code, 'collector', handoff.collection_completed_at)
  findBinding(bindings, handoff.handoff_broker_binding_code, 'handoff_broker', handoff.handoff_recorded_at)
  if (handoff.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || handoff.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256) fail('semantic', 'HANDOFF_MISMATCH', 'handoff pins wrong profile or bindings')
  if (handoff.collector_build_sha256 !== findBinding(bindings, handoff.collector_binding_code).executable_sha256 || handoff.collector_build_sha256 !== releases.get('collector').executable_sha256) fail('semantic', 'HANDOFF_MISMATCH', 'handoff collector build is not the authenticated frozen release')
  if (handoff.collector_principal_code !== findBinding(bindings, handoff.collector_binding_code).atlas_principal_code) fail('semantic', 'HANDOFF_MISMATCH', 'handoff collector attribution differs from authenticated binding')
  if (canonical(handoff.artifact) !== canonical(clearance.artifact) || canonical(handoff.artifact) !== canonical(response.payload.artifact)) fail('semantic', 'HANDOFF_MISMATCH', 'handoff artifact differs from independently referenced exact bytes')
  if (!(handoff.collection_started_at <= handoff.collection_completed_at && handoff.collection_completed_at <= handoff.handoff_recorded_at && handoff.handoff_recorded_at < handoff.expires_at)) fail('semantic', 'HANDOFF_MISMATCH', 'handoff chronology is invalid')

  const assertSeal = (seal, kind, targetState, expectedHandoffs, expectedOperationId, useAt) => {
    findBinding(bindings, seal.submitter_binding_code, 'human_submitter', seal.sealed_at)
    findBinding(bindings, seal.importer_binding_code, 'bundle_importer', seal.sealed_at)
    findBinding(bindings, seal.launcher_binding_code, 'trusted_launcher', seal.sealed_at)
    if (seal.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || seal.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || seal.bundle_kind_code !== kind) fail('semantic', 'BUNDLE_SEAL_INVALID', 'bundle seal pins wrong profile, bindings, or bundle kind')
    if (seal.operation_id !== expectedOperationId || canonical(seal.target_logical_state) !== canonical(stateReference(targetState)) || targetState.produced_at > seal.sealed_at || !(seal.sealed_at <= useAt && useAt < seal.expires_at) || seal.collector_handoffs.length !== expectedHandoffs) fail('semantic', 'BUNDLE_SEAL_INVALID', 'bundle seal operation, target, use-time validity, or handoff cardinality is invalid')
  }
  assertSeal(bootstrapSeal, 'principal_bootstrap', emptyState, 0, transition1.operation_id, transition1.occurred_at)
  assertSeal(documentSeal, 'single_document', bootstrapState, 1, documentJournal1.operation_id, documentJournal1.event_at)
  if (documentSeal.collector_handoffs[0].format !== handoff.format || documentSeal.collector_handoffs[0].format_version !== handoff.format_version || documentSeal.collector_handoffs[0].record_code !== handoff.record_code || documentSeal.collector_handoffs[0].record_digest_sha256 !== handoff.record_digest_sha256 || !(handoff.handoff_recorded_at <= documentSeal.sealed_at && documentJournal1.event_at < handoff.expires_at)) fail('semantic', 'BUNDLE_SEAL_INVALID', 'document bundle seal does not pin an exact collector handoff active at document use')
  assertCurrentPilotClearance(clearance, { clearanceTransitions: [], clearanceReplacements: new Map() }, bindings, runtime, classification, clearance.not_before, clearance.artifact, clearance.clearance_scope_sha256, clearance.record_digest_sha256)
  assertPermitIssuanceMatrix()
  assertPermitIssuance(permit, authorizationControls, classification)
  assertPermitIssuance(recoveryPermit, authorizationControls, classification)
  assertPermitIssuance(completionPermit, authorizationControls, classification)
  assertPermitIssuance(bootstrapCompletionPermit, authorizationControls, classification)

  const bootstrapHumans = [
    findBinding(bindings, permit.submitter_binding_code, 'human_submitter', permit.issued_at).unix_uid,
    findBinding(bindings, permit.witness_binding_code, 'operational_witness', permit.issued_at).unix_uid,
    findBinding(bindings, permit.issuer_binding_code, 'bootstrap_authority', permit.issued_at).unix_uid,
  ]
  unique(bootstrapHumans, 'semantic', 'BOOTSTRAP_PERMIT_INVALID', 'bootstrap submitter/witness/authority subject')
  if (permit.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || permit.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || permit.importer_release_sha256 !== releases.get('bundle_importer').executable_sha256 || permit.importer_binding_code !== findBinding(bindings, permit.importer_binding_code, 'bundle_importer', permit.issued_at).binding_code) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit pins wrong profile, bindings, importer binding, or release')
  if (canonical(permit.target_empty_logical_state) !== canonical(stateReference(emptyState)) || emptyState.produced_at > permit.issued_at || canonical(permit.bootstrap_bundle) !== canonical(bootstrapSeal.bundle) || permit.manifest_path !== bootstrapSeal.manifest_path || permit.reviewed_git_commit !== bootstrapSeal.reviewed_git_commit || permit.operation_nonce !== bootstrapSeal.operation_nonce || permit.expected_principal_roster_sha256 !== bootstrapState.state_payload.principal_roster_sha256 || !(permit.issued_at <= permit.not_before && permit.not_before < permit.expires_at)) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'permit target, state chronology, bundle, roster, or time window is invalid')
  const assertTransition = (transition, issuance, previous, expectedState, recoveryAuthority = null) => assertPermitTransition(transition, issuance, previous, stateReference(expectedState), recoveryAuthority, bindings, classification, expectedState.produced_at)
  assertTransition(transition1, permit, null, emptyState)
  assertTransition(transition2, permit, transition1, bootstrapState)
  if (replay.permit_code !== permit.permit_code || replay.canonical_lineage_code !== permit.canonical_lineage_code || replay.permit_spent_transition_record_digest_sha256 !== transition2.record_digest_sha256 || replay.target_database_class_code !== 'disposable_recovery_only' || replay.issuer_binding_code === replay.witness_binding_code || replay.principal_roster_sha256 !== bootstrapState.state_payload.principal_roster_sha256 || canonical(replay.accepted_bootstrap_bundle) !== canonical(permit.bootstrap_bundle) || canonical(replay.accepted_logical_state) !== canonical(stateReference(bootstrapState)) || replay.accepted_receipt_sha256 !== bootstrapState.state_payload.receipt_head.receipt_row_sha256 || !(transition2.occurred_at <= replay.issued_at && replay.issued_at < replay.expires_at)) fail('semantic', 'REPLAY_CERTIFICATE_INVALID', 'replay certificate is not bound to the accepted receipt, state, roster, spent permit, lineage, and independent witness')
  findBinding(bindings, replay.issuer_binding_code, 'independent_verifier', replay.issued_at)
  findBinding(bindings, replay.witness_binding_code, 'operational_witness', replay.issued_at)

  const replayReference = { format: replay.format, format_version: replay.format_version, record_code: replay.record_code, record_digest_sha256: replay.record_digest_sha256 }
  assertRecoveryPermitWindow(recoveryPermit, replay, bindings, classification)
  if (canonical(recoveryPermit.replay_certificate) !== canonical(replayReference) || recoveryPermit.canonical_lineage_code !== replay.canonical_lineage_code || canonical(recoveryPermit.accepted_bootstrap_bundle) !== canonical(replay.accepted_bootstrap_bundle) || canonical(recoveryPermit.accepted_logical_state) !== canonical(replay.accepted_logical_state) || canonical(recoveryPermit.target_empty_logical_state) !== canonical(stateReference(emptyState)) || recoveryPermit.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || recoveryPermit.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || recoveryPermit.importer_release_sha256 !== releases.get('bundle_importer').executable_sha256 || recoveryPermit.importer_binding_code !== findBinding(bindings, recoveryPermit.importer_binding_code, 'bundle_importer', recoveryPermit.issued_at).binding_code) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'recovery permit does not pin the exact accepted evidence, lineage, runtime, or importer')
  const recoveryHumans = [
    findBinding(bindings, recoveryPermit.operator_binding_code, 'recovery_operator', recoveryPermit.issued_at).unix_uid,
    findBinding(bindings, recoveryPermit.witness_binding_code, 'operational_witness', recoveryPermit.issued_at).unix_uid,
    findBinding(bindings, recoveryPermit.issuer_binding_code, 'recovery_authority', recoveryPermit.issued_at).unix_uid,
  ]
  unique(recoveryHumans, 'semantic', 'RECOVERY_PERMIT_INVALID', 'recovery human')
  assertTransition(recoveryTransition1, recoveryPermit, null, emptyState)
  assertTransition(recoveryTransition2, recoveryPermit, recoveryTransition1, bootstrapState)
  assertUniquePermitSuccessors([transition1, transition2, recoveryTransition1, recoveryTransition2])

  const capabilityControls = {
    issuances: new Map([[sourceCapabilityIssuance.record_digest_sha256, sourceCapabilityIssuance]]),
    transitions: [],
    requests: new Map([[request.record_digest_sha256, request]]),
    responses: new Map([[response.record_digest_sha256, response]]),
    clearances: new Map(),
    handoffs: new Map([[handoff.record_digest_sha256, handoff]]),
    bundleSeals: new Map([[documentSeal.record_digest_sha256, documentSeal]]),
    custodyRecords: [],
    currentBundleSequence: 2,
  }
  assertIpcPair(request, response, bindings, runtime, classification, capabilityControls)

  assertCurrentPilotClearance(clearance, { clearanceTransitions: [], clearanceReplacements: new Map() }, bindings, runtime, classification, clearance.not_before, clearance.artifact, clearance.clearance_scope_sha256, clearance.record_digest_sha256)
  assertClearanceTransitions(clearance, [clearanceTransition], new Map(), classification)
  if (clearanceLeafAt(clearance, [], new Map(), classification, clearance.not_before)?.record_digest_sha256 !== clearance.record_digest_sha256 || clearanceLeafAt(clearance, [clearanceTransition], new Map(), classification, clearanceTransition.occurred_at) !== null) fail('semantic', 'CLEARANCE_INVALID', 'clearance leaf projection ignores activation or revocation')
  findBinding(bindings, clearanceTransition.recorded_by_binding_code, 'clearance_broker', clearanceTransition.occurred_at)

  assertHandoffManifestLink(handoff, documentManifest)
  assert.doesNotThrow(() => assertHandoffManifestLink(handoff, structuredClone(documentManifest), [documentManifest]))
  for (const mutate of [
    (item) => { item.retrieval_event_code = 'synthetic.bundle-002.retrieval-missing' },
    (item) => { item.request_fingerprint_sha256 = '9'.repeat(64) },
    (item) => { item.staged_path = 'objects/sha256/c7/'.concat('9'.repeat(64)) },
  ]) {
    const invalidHandoff = structuredClone(handoff)
    mutate(invalidHandoff)
    invalidHandoff.record_digest_sha256 = recordDigest(invalidHandoff)
    assert.throws(() => assertHandoffManifestLink(invalidHandoff, documentManifest), /HANDOFF_MISMATCH/)
  }
  const supportManifest = structuredClone(documentManifest)
  supportManifest.bundle_id = 'synthetic.bundle-support-001'
  supportManifest.bundle_sequence = 1
  supportManifest.required_bundles = []
  supportManifest.retrieval_events = []
  supportManifest.custody_events = []
  supportManifest.bundle_digest_sha256 = sha256(Buffer.from(canonical(withoutTopLevel(supportManifest, 'bundle_digest_sha256')), 'utf8'))
  const basisManifest = structuredClone(documentManifest)
  basisManifest.bundle_id = 'synthetic.bundle-basis-002'
  basisManifest.bundle_sequence = 2
  basisManifest.required_bundles = [{ bundle_id: supportManifest.bundle_id, bundle_digest_sha256: supportManifest.bundle_digest_sha256 }]
  basisManifest.retrieval_locations = []
  basisManifest.artifacts = []
  basisManifest.custody_events = []
  basisManifest.bundle_digest_sha256 = sha256(Buffer.from(canonical(withoutTopLevel(basisManifest, 'bundle_digest_sha256')), 'utf8'))
  const conditionalManifest = structuredClone(documentManifest)
  conditionalManifest.bundle_id = 'synthetic.bundle-003'
  conditionalManifest.bundle_sequence = 3
  conditionalManifest.required_bundles = [
    { bundle_id: supportManifest.bundle_id, bundle_digest_sha256: supportManifest.bundle_digest_sha256 },
    { bundle_id: basisManifest.bundle_id, bundle_digest_sha256: basisManifest.bundle_digest_sha256 },
  ]
  conditionalManifest.retrieval_locations = []
  conditionalManifest.artifacts = []
  conditionalManifest.custody_events = []
  const conditionalRetrieval = conditionalManifest.retrieval_events[0]
  conditionalRetrieval.record_code = 'synthetic.bundle-003.retrieval-001'
  conditionalRetrieval.conditional_basis_retrieval_event_code = basisManifest.retrieval_events[0].record_code
  conditionalRetrieval.conditional_validator_kind_code = 'etag'
  conditionalRetrieval.conditional_validator_value = basisManifest.retrieval_events[0].response_metadata.etag
  conditionalRetrieval.started_at = '2030-01-01T00:10:00.000Z'
  conditionalRetrieval.completed_at = '2030-01-01T00:10:01.000Z'
  conditionalRetrieval.captured_at = '2030-01-01T00:10:01.000Z'
  conditionalRetrieval.recorded_at = '2030-01-01T00:10:02.000Z'
  conditionalManifest.bundle_digest_sha256 = sha256(Buffer.from(canonical(withoutTopLevel(conditionalManifest, 'bundle_digest_sha256')), 'utf8'))
  const conditionalHandoff = structuredClone(handoff)
  conditionalHandoff.record_code = 'synthetic.handoff-003'
  conditionalHandoff.retrieval_event_code = conditionalRetrieval.record_code
  conditionalHandoff.collection_started_at = conditionalRetrieval.started_at
  conditionalHandoff.collection_completed_at = conditionalRetrieval.captured_at
  conditionalHandoff.handoff_recorded_at = conditionalRetrieval.recorded_at
  conditionalHandoff.expires_at = '2030-01-01T00:20:00.000Z'
  conditionalHandoff.request_fingerprint_sha256 = sha256(Buffer.from(canonical({
    conditional_basis: {
      bundle_digest_sha256: basisManifest.bundle_digest_sha256,
      bundle_id: basisManifest.bundle_id,
      bundle_sequence: basisManifest.bundle_sequence,
      retrieval_event_code: basisManifest.retrieval_events[0].record_code,
      validator_kind_code: conditionalRetrieval.conditional_validator_kind_code,
      validator_value: conditionalRetrieval.conditional_validator_value,
    },
    request_headers: structuredClone(conditionalRetrieval.request_headers),
    request_method_code: conditionalRetrieval.request_method_code,
    request_profile_code: conditionalRetrieval.request_profile_code,
    requested_location_url: supportManifest.retrieval_locations[0].url,
  }), 'utf8'))
  conditionalHandoff.record_digest_sha256 = recordDigest(conditionalHandoff)
  assert.doesNotThrow(() => assertHandoffManifestLink(conditionalHandoff, conditionalManifest, [supportManifest, basisManifest, conditionalManifest]))
  assert.throws(() => assertHandoffManifestLink(conditionalHandoff, conditionalManifest, [supportManifest, conditionalManifest]), /does not resolve exactly once/)
  const wrongBasisDependency = structuredClone(conditionalManifest)
  wrongBasisDependency.required_bundles[1].bundle_digest_sha256 = '4'.repeat(64)
  wrongBasisDependency.bundle_digest_sha256 = sha256(Buffer.from(canonical(withoutTopLevel(wrongBasisDependency, 'bundle_digest_sha256')), 'utf8'))
  assert.throws(() => assertHandoffManifestLink(conditionalHandoff, wrongBasisDependency, [supportManifest, basisManifest, wrongBasisDependency]), /not pinned to one earlier retained bundle/)
  const duplicateBasisManifest = structuredClone(basisManifest)
  duplicateBasisManifest.bundle_id = 'synthetic.duplicate-basis'
  duplicateBasisManifest.bundle_sequence = 1
  duplicateBasisManifest.bundle_digest_sha256 = sha256(Buffer.from(canonical(withoutTopLevel(duplicateBasisManifest, 'bundle_digest_sha256')), 'utf8'))
  assert.throws(() => assertHandoffManifestLink(conditionalHandoff, conditionalManifest, [supportManifest, basisManifest, duplicateBasisManifest, conditionalManifest]), /does not resolve exactly once/)
  const partialConditionalHandoffManifest = structuredClone(conditionalManifest)
  partialConditionalHandoffManifest.retrieval_events[0].conditional_basis_retrieval_event_code = null
  partialConditionalHandoffManifest.bundle_digest_sha256 = sha256(Buffer.from(canonical(withoutTopLevel(partialConditionalHandoffManifest, 'bundle_digest_sha256')), 'utf8'))
  assert.throws(() => assertHandoffManifestLink(conditionalHandoff, partialConditionalHandoffManifest, [supportManifest, basisManifest, partialConditionalHandoffManifest]), /conditional basis is partial/)
  const staleDigestOwner = structuredClone(supportManifest)
  staleDigestOwner.retrieval_locations[0].url = 'https://synthetic.invalid/changed-owner'
  assert.throws(() => assertHandoffManifestLink(conditionalHandoff, conditionalManifest, [staleDigestOwner, basisManifest, conditionalManifest]), /retained manifest content does not match its declared bundle digest/)
  if (documentManifest.bundle_id !== documentSeal.bundle.bundle_id || documentManifest.bundle_sequence !== documentSeal.bundle.bundle_sequence || documentManifest.bundle_digest_sha256 !== documentSeal.bundle.bundle_digest_sha256 || documentManifest.manifest_path !== documentSeal.manifest_path) fail('semantic', 'BUNDLE_SEAL_INVALID', 'document bundle seal differs from the exact reviewed manifest')
  if (documentState.state_payload.receipt_head.bundle_id !== documentManifest.bundle_id || documentState.state_payload.receipt_head.bundle_sequence !== documentManifest.bundle_sequence || documentState.state_payload.receipt_head.bundle_digest_sha256 !== documentManifest.bundle_digest_sha256) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'document state receipt head differs from the exact accepted manifest')
  const fixedCapabilityControls = {
    issuances: new Map([sourceCapabilityIssuance, preparationCapabilityIssuance, sealedCapabilityIssuance].map((issuance) => [issuance.record_digest_sha256, issuance])),
    transitions: [sourceCapabilityTransition, sealedCapabilityTransition],
    clearances: new Map([[clearance.record_digest_sha256, clearance]]),
    handoffs: new Map([[handoff.record_digest_sha256, handoff]]),
    bundleSeals: new Map([[documentSeal.record_digest_sha256, documentSeal]]),
    clearanceTransitions: [],
    clearanceReplacements: new Map(),
    custodyRecords: custodyRecordsFromManifest(documentManifest),
    currentBundleSequence: documentManifest.bundle_sequence,
    prepromotionAuthorizations: new Map([[prepromotionAuthorization.record_digest_sha256, prepromotionAuthorization]]),
    candidateSeals: authorizationControls.candidateSeals,
    logicalStateRecords: authorizationControls.logicalStateRecords,
  }
  assertCustodyCapabilitySequence([request, response, prepareRequest, prepareResponse, sealRequest, sealResponse, custodyAccessRequest, custodyAccessResponse], fixedCapabilityControls, bindings, runtime, classification)
  assertPrePromotionBoundary(fixedCapabilityControls, bindings, runtime, classification, prepromotionAuthorization.evaluated_at, clearance.artifact, clearance.clearance_scope_sha256, clearance.record_digest_sha256, documentSeal.record_digest_sha256, handoff.record_digest_sha256)

  if (canonical(candidateSeal.expected_prior_logical_state) !== canonical(stateReference(emptyState)) || canonical(candidateSeal.candidate_logical_state) !== canonical(stateReference(bootstrapState)) || candidateSeal.operation_id !== transition1.operation_id || candidateSeal.operation_nonce !== permit.operation_nonce || candidateSeal.produced_by_binding_code !== findBinding(bindings, candidateSeal.produced_by_binding_code, 'independent_verifier').binding_code || candidateSeal.link_count !== 1 || !(bootstrapState.produced_at <= candidateSeal.produced_at && candidateSeal.produced_at <= transition2.occurred_at && transition2.occurred_at < candidateSeal.expires_at)) fail('semantic', 'LOGICAL_STATE_MISMATCH', 'candidate file seal is not tied to the exact verified prior/candidate states and active promotion boundary')
  findBinding(bindings, candidateSeal.produced_by_binding_code, 'independent_verifier', candidateSeal.produced_at)

  const bootstrapHistory = journalHistoryAtCurrentTerminal(journal2, authorizationControls, classification)
  for (const journal of bootstrapHistory) {
    const component = findBinding(bindings, journal.component_binding_code, null, journal.event_at)
    findBinding(bindings, journal.recorded_by_binding_code, 'journal_broker', journal.persisted_at)
    if (journal.component_executable_sha256 !== component.executable_sha256 || journal.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || journal.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || journal.operation_nonce !== permit.operation_nonce || canonical(journal.bundle) !== canonical(permit.bootstrap_bundle) || canonical(journal.target_logical_state) !== canonical(stateReference(emptyState))) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event lacks exact origin, broker, runtime, operation, bundle, or pre-operation target binding')
  }
  const documentIncidentHistory = journalHistoryAtCurrentTerminal(documentJournal2, authorizationControls, classification)
  const completionHistory = journalHistoryAtCurrentTerminal(completionJournal2, authorizationControls, classification)
  for (const journal of documentIncidentHistory) {
    if (canonical(journal.bundle) !== canonical(documentSeal.bundle) || canonical(journal.target_logical_state) !== canonical(stateReference(bootstrapState))) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'document incident journal does not preserve its exact bundle and pre-operation target state')
  }
  if (canonical(documentJournal2.observed_logical_state) !== canonical(stateReference(documentState))) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'document recovery event does not identify the exact observed promoted state')
  const completionPolicy = classification.post_promotion_completion_permit_policy
  const sourceErrorRule = classification.post_promotion_source_error_rules.find((item) => item.error_code === documentJournal2.error_code)
  if (completionPermit.scope_code !== completionPolicy.scope_code || canonical(completionPermit.allowed_actions) !== canonical(completionPolicy.allowed_actions) || completionPermit.canonical_write_code !== completionPolicy.canonical_write_code || completionPermit.allowed_canonical_effect_code !== completionPolicy.allowed_canonical_effect_code || !completionPolicy.required_bundle_kind_codes.includes(documentSeal.bundle_kind_code) || canonical(completionPermit.target_bundle) !== canonical(documentSeal.bundle) || completionPermit.verified_canonical_receipt_sha256 !== documentState.state_payload.receipt_head.receipt_row_sha256 || canonical(completionPermit.verified_canonical_logical_state) !== canonical(stateReference(documentState)) || completionPermit.source_recovery_journal_event_record_digest_sha256 !== documentJournal2.record_digest_sha256 || canonical(documentJournal2.bundle) !== canonical(completionPermit.target_bundle) || canonical(documentJournal2.observed_logical_state) !== canonical(completionPermit.verified_canonical_logical_state) || documentJournal2.event_kind_code !== 'recovery_required' || documentJournal2.recovery_class_code !== completionPolicy.required_source_recovery_class_code || !completionPolicy.allowed_source_error_codes.includes(documentJournal2.error_code) || !sourceErrorRule || !sourceErrorRule.allowed_bundle_kind_codes.includes(documentSeal.bundle_kind_code) || documentJournal2.canonical_effect_code !== sourceErrorRule.canonical_effect_code || documentJournal2.object_disposition_code !== sourceErrorRule.object_disposition_code || documentJournal2.persisted_at > completionPermit.issued_at || completionPermit.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || completionPermit.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || !(completionPermit.issued_at <= completionPermit.not_before && completionPermit.not_before < completionPermit.expires_at && completionPermit.expires_at <= bindings.expires_at) || Date.parse(completionPermit.expires_at) - Date.parse(completionPermit.issued_at) > completionPolicy.maximum_lifetime_ms) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'post-promotion completion permit is not bound to the exact protected-persistence-visible receipt, state, incident journal, runtime, or narrow action policy')
  findBinding(bindings, completionPermit.importer_binding_code, 'bundle_importer', completionPermit.issued_at)
  const completionHumans = [
    findBinding(bindings, completionPermit.operator_binding_code, 'recovery_operator', completionPermit.issued_at).unix_uid,
    findBinding(bindings, completionPermit.witness_binding_code, 'operational_witness', completionPermit.issued_at).unix_uid,
    findBinding(bindings, completionPermit.issuer_binding_code, 'recovery_authority', completionPermit.issued_at).unix_uid,
  ]
  unique(completionHumans, 'semantic', 'RECOVERY_PERMIT_INVALID', 'post-promotion completion human')
  assertTransition(completionTransition1, completionPermit, null, documentState)
  assertTransition(completionTransition2, completionPermit, completionTransition1, documentState)
  if (completionTransition2.completion_journal_head_record_digest_sha256 !== completionJournal2.record_digest_sha256 || completionHistory[0].record_digest_sha256 !== completionJournal1.record_digest_sha256 || completionHistory.at(-1).record_digest_sha256 !== completionJournal2.record_digest_sha256 || completionJournal2.event_kind_code !== 'operation_completed' || completionJournal2.operation_mode_code !== completionPolicy.required_operation_mode_code || completionJournal2.operation_id !== completionPermit.operation_id || completionJournal2.operation_nonce !== completionPermit.operation_nonce || completionJournal2.authorization_permit_record_digest_sha256 !== completionPermit.record_digest_sha256 || canonical(completionJournal2.bundle) !== canonical(completionPermit.target_bundle) || canonical(completionJournal2.target_logical_state) !== canonical(completionPermit.verified_canonical_logical_state) || canonical(completionJournal2.observed_logical_state) !== canonical(completionPermit.verified_canonical_logical_state) || completionJournal2.result_outcome_code !== 'recovered' || completionJournal2.canonical_effect_code !== 'none_verified' || completionJournal2.error_code !== null || completionJournal2.backup_inventory_sha256 === null || Object.values(completionJournal2.rows_delta).some((count) => count !== 0) || Object.values(completionJournal2.objects_delta).some((count) => count !== 0) || completionJournal2.persisted_at > completionTransition2.occurred_at) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'spent post-promotion completion permit does not resolve the exact authorized current protected-persistence-visible terminal completion proof')
  if (recoveredResult.outcome !== 'recovered' || recoveredResult.operation_mode_code !== completionPolicy.required_operation_mode_code || recoveredResult.bundle_kind_code !== documentSeal.bundle_kind_code || canonical({ bundle_id: recoveredResult.bundle_id, bundle_sequence: recoveredResult.bundle_sequence, bundle_digest_sha256: recoveredResult.bundle_digest_sha256 }) !== canonical(completionPermit.target_bundle) || recoveredResult.operation_id !== completionPermit.operation_id || recoveredResult.recovery_permit_record_digest_sha256 !== completionPermit.record_digest_sha256 || recoveredResult.recovery_terminal_transition_record_digest_sha256 !== completionTransition2.record_digest_sha256) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result is not bound to the exact spent post-promotion completion permit')
  assertTransition(bootstrapCompletionTransition1, bootstrapCompletionPermit, null, bootstrapState)
  assertTransition(bootstrapCompletionTransition2, bootstrapCompletionPermit, bootstrapCompletionTransition1, bootstrapState)
  const bootstrapCompletionHistory = journalHistoryAtCurrentTerminal(bootstrapCompletionJournal3, authorizationControls, classification)
  if (bootstrapCompletionTransition2.completion_journal_head_record_digest_sha256 !== bootstrapCompletionJournal3.record_digest_sha256 || bootstrapCompletionResult.recovery_permit_record_digest_sha256 !== bootstrapCompletionPermit.record_digest_sha256 || bootstrapCompletionResult.recovery_terminal_transition_record_digest_sha256 !== bootstrapCompletionTransition2.record_digest_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'bootstrap post-promotion completion branch is not bound to its exact terminal evidence')
  assertUniquePermitSuccessors([transition1, transition2, recoveryTransition1, recoveryTransition2, completionTransition1, completionTransition2, bootstrapCompletionTransition1, bootstrapCompletionTransition2])
  assertImporterResult(value('import_result_success'), classification, authorizationControls)
  const bootstrapResult = structuredClone(value('import_result_success'))
  bootstrapResult.bundle_id = permit.bootstrap_bundle.bundle_id
  bootstrapResult.bundle_sequence = permit.bootstrap_bundle.bundle_sequence
  bootstrapResult.bundle_digest_sha256 = permit.bootstrap_bundle.bundle_digest_sha256
  bootstrapResult.bundle_kind_code = 'principal_bootstrap'
  bootstrapResult.operation_id = permit.operation_id ?? transition1.operation_id
  bootstrapResult.operation_mode_code = 'bootstrap'
  bootstrapResult.bootstrap_principals_inserted = pilotBundleShape.bootstrap_principals_exact
  bootstrapResult.rows_inserted = structuredClone(journal2.rows_delta)
  bootstrapResult.objects = structuredClone(journal2.objects_delta)
  bootstrapResult.checks = Object.fromEntries(Object.keys(bootstrapResult.checks).map((key) => [key, 'passed']))
  assertJournalResultAgreement(bootstrapHistory, bootstrapResult, classification, bindings, runtime, authorizationControls)
  const documentRecoveryResult = structuredClone(value('import_result_recovery_required'))
  documentRecoveryResult.operation_id = documentJournal2.operation_id
  assertJournalResultAgreement(documentIncidentHistory, documentRecoveryResult, classification, bindings, runtime, authorizationControls)
  assertJournalResultAgreement(completionHistory, recoveredResult, classification, bindings, runtime, authorizationControls)
  assertJournalResultAgreement(bootstrapCompletionHistory, bootstrapCompletionResult, classification, bindings, runtime, authorizationControls)
}

function capabilityEnvelopeFromIssuance(issuance) {
  return {
    capability_kind_code: issuance.capability_kind_code,
    capability_sha256: issuance.record_digest_sha256,
    issued_by_binding_code: issuance.issued_by_binding_code,
    requester_binding_code: issuance.requester_binding_code,
    adapter_binding_code: issuance.adapter_binding_code,
    operation_id: issuance.operation_id,
    operation_nonce: issuance.operation_nonce,
    runtime_profile_record_digest_sha256: issuance.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: issuance.identity_bindings_record_digest_sha256,
    artifact: structuredClone(issuance.artifact),
    allowed_consumer_operation_codes: structuredClone(issuance.allowed_consumer_operation_codes),
    replay_policy_code: issuance.replay_policy_code,
    issued_at: issuance.issued_at,
    expires_at: issuance.expires_at,
  }
}

function assertCapabilityIssuance(issuance, controls, bindings, runtime, classification) {
  if (!issuance || issuance.record_kind_code !== 'capability_issuance') fail('semantic', 'IPC_REPLAY_DETECTED', 'capability does not resolve an immutable issuance')
  assertDigest(issuance)
  const rule = classification.custody_capability_rules.find((item) => item.capability_kind_code === issuance.capability_kind_code)
  if (!rule || canonical(issuance.allowed_consumer_operation_codes) !== canonical(rule.allowed_consumer_operation_codes) || issuance.replay_policy_code !== rule.replay_policy_code) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability issuance differs from its frozen policy')
  if (issuance.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || issuance.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability issuance pins another runtime or binding set')
  const issuerBinding = findBinding(bindings, issuance.issued_by_binding_code, rule.issued_by_runtime_role_code, issuance.issued_at)
  const requesterBinding = findBinding(bindings, issuance.requester_binding_code, rule.requester_runtime_role_code, issuance.issued_at)
  const adapterBinding = findBinding(bindings, issuance.adapter_binding_code, rule.adapter_runtime_role_code, issuance.issued_at)
  const lifetimeMs = Date.parse(issuance.expires_at) - Date.parse(issuance.issued_at)
  if (lifetimeMs < 1 || lifetimeMs > rule.lifetime_ms_max || issuance.expires_at > bindings.expires_at || [issuerBinding, requesterBinding, adapterBinding].some((binding) => issuance.expires_at > binding.valid_until)) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability issuance lifetime is invalid or outlives a binding')
  const scope = issuance.grant_scope
  if (scope.scope_kind_code !== issuance.capability_kind_code) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability issuance scope kind differs')
  const request = controls.requests.get(scope.basis_request_record_digest_sha256)
  const expectedOperation = issuance.capability_kind_code === 'source_handle' ? 'open_staged' : issuance.capability_kind_code === 'preparation' ? 'prepare' : 'seal_custody_access'
  if (!request || request.message_kind_code !== 'request' || request.operation_code !== expectedOperation || request.record_digest_sha256 !== scope.basis_request_record_digest_sha256 || request.operation_id !== issuance.operation_id || request.operation_nonce !== issuance.operation_nonce || request.runtime_profile_record_digest_sha256 !== issuance.runtime_profile_record_digest_sha256 || request.sender_binding_code !== issuance.requester_binding_code || request.recipient_binding_code !== issuance.adapter_binding_code || request.created_at > issuance.issued_at) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability issuance does not resolve its exact preceding request')
  assertCustodyMessageMatrix(request, classification)
  if (issuance.capability_kind_code === 'source_handle' || issuance.capability_kind_code === 'preparation') {
    if (issuance.capability_kind_code === 'source_handle') {
      if (scope.staging_root_slot_code !== request.payload.staging_root_slot_code || scope.relative_path !== request.payload.relative_path || scope.collector_handoff_record_digest_sha256 !== request.payload.collector_handoff_record_digest_sha256 || scope.staging_snapshot_code !== request.payload.staging_snapshot_code || scope.bundle_seal_record_digest_sha256 !== request.payload.bundle_seal_record_digest_sha256 || scope.descriptor_role_code !== 'staged_source' || scope.staged_source_descriptor_ordinal !== 1) fail('semantic', 'IPC_REPLAY_DETECTED', 'source capability scope differs from its staged request')
      const handoff = controls.handoffs?.get(scope.collector_handoff_record_digest_sha256)
      if (!handoff || handoff.record_digest_sha256 !== scope.collector_handoff_record_digest_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'source capability lacks an exact protected collector handoff')
      assertDigest(handoff)
      const matchingSeals = [...(controls.bundleSeals?.entries() ?? [])].filter(([, item]) => item.record_digest_sha256 === scope.bundle_seal_record_digest_sha256 && item.collector_handoffs.some((reference) => reference.record_digest_sha256 === handoff.record_digest_sha256))
      if (matchingSeals.length !== 1 || matchingSeals[0][0] !== matchingSeals[0][1].record_digest_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'source capability handoff lacks its exact protected bundle seal')
      const seal = matchingSeals[0][1]
      assertDigest(seal)
      const collectorAtStart = findBinding(bindings, handoff.collector_binding_code, 'collector', handoff.collection_started_at)
      const collectorAtCompletion = findBinding(bindings, handoff.collector_binding_code, 'collector', handoff.collection_completed_at)
      findBinding(bindings, handoff.handoff_broker_binding_code, 'handoff_broker', handoff.handoff_recorded_at)
      findBinding(bindings, seal.submitter_binding_code, 'human_submitter', seal.sealed_at)
      findBinding(bindings, seal.importer_binding_code, 'bundle_importer', seal.sealed_at)
      findBinding(bindings, seal.launcher_binding_code, 'trusted_launcher', seal.sealed_at)
      const collectorRelease = runtime.component_releases.find((item) => item.runtime_role_code === 'collector')
      if (collectorAtStart.binding_code !== collectorAtCompletion.binding_code || handoff.collector_principal_code !== collectorAtStart.atlas_principal_code || handoff.collector_build_sha256 !== collectorAtStart.executable_sha256 || handoff.collector_build_sha256 !== collectorRelease?.executable_sha256 || !(handoff.collection_started_at <= handoff.collection_completed_at && handoff.collection_completed_at <= handoff.handoff_recorded_at && handoff.handoff_recorded_at <= seal.sealed_at && handoff.handoff_recorded_at < handoff.expires_at) || handoff.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || handoff.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || handoff.staged_path !== scope.relative_path || handoff.staging_snapshot_code !== scope.staging_snapshot_code || canonical(handoff.artifact) !== canonical(issuance.artifact) || handoff.handoff_recorded_at > request.created_at || handoff.handoff_recorded_at > issuance.issued_at || request.created_at >= handoff.expires_at || issuance.issued_at >= handoff.expires_at || issuance.expires_at > handoff.expires_at || seal.record_kind_code !== 'bundle_seal' || seal.bundle_kind_code !== 'single_document' || seal.operation_id !== issuance.operation_id || seal.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || seal.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || seal.operation_nonce !== issuance.operation_nonce || seal.sealed_at > request.created_at || seal.sealed_at > issuance.issued_at || request.created_at >= seal.expires_at || issuance.issued_at >= seal.expires_at || issuance.expires_at > seal.expires_at || seal.collector_handoffs.length !== 1 || seal.collector_handoffs[0].record_code !== handoff.record_code || seal.collector_handoffs[0].record_digest_sha256 !== handoff.record_digest_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'source capability crosses its exact active handoff, staging snapshot, path, artifact, seal, runtime, operation, lifetime, producer chronology, or actor bindings')
    } else {
      const source = controls.issuances.get(scope.source_capability_record_digest_sha256)
      if (!source || source.capability_kind_code !== 'source_handle' || request.payload.source_handle_token?.capability_sha256 !== source.record_digest_sha256 || canonical(request.payload.artifact) !== canonical(issuance.artifact)) fail('semantic', 'IPC_REPLAY_DETECTED', 'preparation capability lacks a grounded source capability or exact artifact')
    }
  } else {
    const clearance = controls.clearances.get(scope.clearance_decision_record_digest_sha256)
    if (!clearance || clearance.decision_code === 'do_not_retain' || canonical(clearance.artifact) !== canonical(issuance.artifact) || scope.clearance_scope_sha256 !== clearance.clearance_scope_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'sealed custody capability lacks its exact eligible clearance')
    assertCurrentPilotClearance(clearance, controls, bindings, runtime, classification, issuance.issued_at, issuance.artifact, scope.clearance_scope_sha256, scope.clearance_decision_record_digest_sha256)
    for (const key of ['backend_code', 'backend_reference', 'copy_code', 'purpose_code', 'clearance_decision_record_digest_sha256', 'clearance_scope_sha256']) if (request.payload[key] !== scope[key]) fail('semantic', 'IPC_REPLAY_DETECTED', `sealed custody issuance request differs on ${key}`)
    assertPilotCasReference(issuance.artifact, scope.backend_code, scope.backend_reference)
    if (canonical(request.payload.artifact) !== canonical(issuance.artifact) || scope.custody_evaluated_at !== issuance.issued_at || scope.known_through_bundle_sequence !== controls.currentBundleSequence) fail('semantic', 'IPC_REPLAY_DETECTED', 'sealed custody issuance does not pin the adapter-selected issuance time and current knowledge sequence')
    const custodyLeaf = resolveCustodyLeaf(controls.custodyRecords ?? [], issuance.artifact, scope.copy_code, issuance.issued_at, scope.known_through_bundle_sequence)
    if (!custodyLeaf || !['placed', 'relocated', 'restored'].includes(custodyLeaf.event_kind_code) || custodyLeaf.backend_code !== scope.backend_code || custodyLeaf.backend_reference !== scope.backend_reference || custodyLeafProjectionDigest(custodyLeaf) !== scope.custody_leaf_projection_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'sealed custody capability lacks its exact current openable custody projection')
  }
  return issuance
}

function assertCustodyCapability(capability, fieldCode, message, bindings, runtime, classification, capabilityControls, expectedArtifact = null, { issuance = false } = {}) {
  const rule = classification.custody_capability_rules.find((item) => item.payload_field_code === fieldCode && item.capability_kind_code === capability?.capability_kind_code)
  if (!rule || canonical(capability.allowed_consumer_operation_codes) !== canonical(rule.allowed_consumer_operation_codes) || capability.replay_policy_code !== rule.replay_policy_code) fail('semantic', 'IPC_REPLAY_DETECTED', `invalid ${fieldCode} capability policy`)
  const protectedIssuance = assertCapabilityIssuance(capabilityControls?.issuances.get(capability.capability_sha256), capabilityControls, bindings, runtime, classification)
  if (canonical(capability) !== canonical(capabilityEnvelopeFromIssuance(protectedIssuance))) fail('semantic', 'IPC_REPLAY_DETECTED', `${fieldCode} is not the exact projection of its protected issuance`)
  if (capability.operation_id !== message.operation_id || capability.operation_nonce !== message.operation_nonce || capability.runtime_profile_record_digest_sha256 !== message.runtime_profile_record_digest_sha256 || capability.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', `${fieldCode} crosses an operation, nonce, or runtime boundary`)
  const issuer = findBinding(bindings, capability.issued_by_binding_code, rule.issued_by_runtime_role_code, capability.issued_at)
  const requester = findBinding(bindings, capability.requester_binding_code, rule.requester_runtime_role_code, capability.issued_at)
  const adapter = findBinding(bindings, capability.adapter_binding_code, rule.adapter_runtime_role_code, capability.issued_at)
  findBinding(bindings, capability.issued_by_binding_code, rule.issued_by_runtime_role_code, message.created_at)
  findBinding(bindings, capability.requester_binding_code, rule.requester_runtime_role_code, message.created_at)
  findBinding(bindings, capability.adapter_binding_code, rule.adapter_runtime_role_code, message.created_at)
  if (requester.binding_code !== (message.message_kind_code === 'request' ? message.sender_binding_code : message.recipient_binding_code) || adapter.binding_code !== (message.message_kind_code === 'request' ? message.recipient_binding_code : message.sender_binding_code)) fail('semantic', 'IPC_PEER_MISMATCH', `${fieldCode} is bound to different requester or adapter peers`)
  if (issuance && (message.message_kind_code !== 'response' || message.operation_code !== rule.issuance_operation_code || message.payload.outcome_code !== rule.issuance_outcome_code || capability.issued_at !== message.created_at || issuer.binding_code !== message.sender_binding_code || message.request_record_digest_sha256 !== protectedIssuance.grant_scope.basis_request_record_digest_sha256)) fail('semantic', 'IPC_REPLAY_DETECTED', `${fieldCode} was not minted by and exposed through its exact registered request/response`)
  const lifetimeMs = Date.parse(capability.expires_at) - Date.parse(capability.issued_at)
  if (!(capability.issued_at <= message.created_at && message.created_at < capability.expires_at) || lifetimeMs < 1 || lifetimeMs > rule.lifetime_ms_max) fail('semantic', 'IPC_REPLAY_DETECTED', `${fieldCode} is expired or exceeds its exact lifetime`)
  if (expectedArtifact && canonical(capability.artifact) !== canonical(expectedArtifact)) fail('semantic', 'IPC_REPLAY_DETECTED', `${fieldCode} is bound to different artifact bytes`)
  if (capability.capability_kind_code === 'sealed_custody_access' && message.message_kind_code === 'request') {
    const scope = protectedIssuance.grant_scope
    for (const key of ['backend_code', 'backend_reference', 'copy_code', 'purpose_code']) if (message.payload[key] !== scope[key]) fail('semantic', 'IPC_REPLAY_DETECTED', `sealed custody capability scope differs on ${key}`)
    if (scope.known_through_bundle_sequence !== capabilityControls.currentBundleSequence) fail('semantic', 'IPC_REPLAY_DETECTED', 'sealed custody capability is stale against the current accepted bundle sequence')
    const clearance = capabilityControls.clearances.get(scope.clearance_decision_record_digest_sha256)
    assertCurrentPilotClearance(clearance, capabilityControls, bindings, runtime, classification, message.created_at, capability.artifact, scope.clearance_scope_sha256, scope.clearance_decision_record_digest_sha256)
    assertPilotCasReference(capability.artifact, scope.backend_code, scope.backend_reference)
    const custodyLeaf = resolveCustodyLeaf(capabilityControls.custodyRecords ?? [], capability.artifact, scope.copy_code, message.created_at, capabilityControls.currentBundleSequence)
    if (!custodyLeaf || !['placed', 'relocated', 'restored'].includes(custodyLeaf.event_kind_code) || custodyLeaf.backend_code !== scope.backend_code || custodyLeaf.backend_reference !== scope.backend_reference || custodyLeafProjectionDigest(custodyLeaf) !== scope.custody_leaf_projection_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'sealed custody capability is no longer backed by its exact openable custody projection')
  }
  return rule
}

function assertIpcPair(request, response, bindings, runtime, classification, capabilityControls) {
  const requestSender = bindings.bindings.find((item) => item.binding_code === request.sender_binding_code)
  const requestRecipient = bindings.bindings.find((item) => item.binding_code === request.recipient_binding_code)
  const activeAt = (binding, at) => binding && bindings.issued_at <= at && at < bindings.expires_at && binding.valid_from <= at && at < binding.valid_until
  if (!activeAt(requestSender, request.created_at) || requestSender.runtime_role_code !== 'bundle_importer' || !activeAt(requestRecipient, request.created_at) || requestRecipient.runtime_role_code !== 'custody_adapter') fail('semantic', 'IPC_PEER_MISMATCH', 'custody request peer binding is invalid')
  if (request.message_kind_code !== 'request' || request.request_record_digest_sha256 !== null || requestSender.runtime_role_code !== 'bundle_importer') fail('semantic', 'IPC_MALFORMED', 'custody request direction is invalid')
  if (request.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256) fail('semantic', 'IPC_MALFORMED', 'custody request pins wrong profile')
  if (response.message_kind_code !== 'response' || response.sender_binding_code !== requestRecipient.binding_code || response.recipient_binding_code !== requestSender.binding_code) fail('semantic', 'IPC_PEER_MISMATCH', 'custody response peer binding is invalid')
  if (!activeAt(requestRecipient, response.created_at) || !activeAt(requestSender, response.created_at)) fail('semantic', 'IPC_PEER_MISMATCH', 'custody response peer binding is inactive')
  for (const key of ['operation_code', 'operation_id', 'request_id', 'request_sequence', 'operation_nonce', 'runtime_profile_record_digest_sha256']) {
    if (response[key] !== request[key]) fail('semantic', 'IPC_MALFORMED', `custody response differs on ${key}`)
  }
  if (response.request_record_digest_sha256 !== request.record_digest_sha256 || response.created_at < request.created_at) fail('semantic', 'IPC_MALFORMED', 'custody response does not bind the request')
  assertCustodyMessageMatrix(request, classification)
  assertCustodyMessageMatrix(response, classification)
  if (response.operation_code === 'open_staged' && response.payload.outcome_code === 'opened' && response.payload.bundle_seal_record_digest_sha256 !== request.payload.bundle_seal_record_digest_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'open-staged response does not preserve the exact reviewed bundle seal')
  if (response.operation_code === 'seal_custody_access' && response.payload.outcome_code === 'sealed') {
    const issuance = capabilityControls.issuances.get(response.payload.sealed_capability_token.capability_sha256)
    const scope = issuance?.grant_scope
    if (!scope || response.created_at !== issuance.issued_at) fail('semantic', 'IPC_REPLAY_DETECTED', 'sealed custody response does not expose an adapter-time issuance')
    for (const key of ['backend_code', 'backend_reference', 'copy_code', 'purpose_code', 'custody_evaluated_at', 'known_through_bundle_sequence', 'clearance_decision_record_digest_sha256', 'clearance_scope_sha256', 'custody_leaf_projection_sha256']) if (response.payload[key] !== scope[key]) fail('semantic', 'IPC_REPLAY_DETECTED', `sealed custody response differs from the issued scope on ${key}`)
  }
  if (response.operation_code === 'open_custody' && response.payload.outcome_code === 'available') {
    const envelope = request.payload.sealed_capability_token
    const issuance = envelope && capabilityControls.issuances.get(envelope.capability_sha256)
    const scope = issuance?.grant_scope
    if (!scope || response.payload.custody_evaluated_at !== response.created_at || response.payload.known_through_bundle_sequence !== capabilityControls.currentBundleSequence) fail('semantic', 'IPC_REPLAY_DETECTED', 'open-custody response does not pin the adapter-selected response time and current knowledge sequence')
    for (const key of ['artifact', 'backend_code', 'backend_reference', 'copy_code', 'purpose_code']) if (canonical(response.payload[key]) !== canonical(request.payload[key])) fail('semantic', 'IPC_REPLAY_DETECTED', `open-custody response differs from its request on ${key}`)
    if (response.payload.clearance_decision_record_digest_sha256 !== scope.clearance_decision_record_digest_sha256 || response.payload.clearance_scope_sha256 !== scope.clearance_scope_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'open-custody response does not bind the sealed clearance')
    const clearance = capabilityControls.clearances.get(scope.clearance_decision_record_digest_sha256)
    assertCurrentPilotClearance(clearance, capabilityControls, bindings, runtime, classification, response.created_at, envelope.artifact, scope.clearance_scope_sha256, scope.clearance_decision_record_digest_sha256)
    assertPilotCasReference(envelope.artifact, scope.backend_code, scope.backend_reference)
    const custodyLeaf = resolveCustodyLeaf(capabilityControls.custodyRecords ?? [], envelope.artifact, scope.copy_code, response.created_at, capabilityControls.currentBundleSequence)
    if (!custodyLeaf || !['placed', 'relocated', 'restored'].includes(custodyLeaf.event_kind_code) || custodyLeaf.backend_code !== scope.backend_code || custodyLeaf.backend_reference !== scope.backend_reference || custodyLeafProjectionDigest(custodyLeaf) !== response.payload.custody_leaf_projection_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'open-custody response lacks its exact current openable custody projection')
  }
  for (const fieldCode of ['source_handle_token', 'preparation_token', 'sealed_capability_token']) {
    if (response.payload[fieldCode] !== null) {
      const capabilityRule = classification.custody_capability_rules.find((item) => item.payload_field_code === fieldCode)
      const issuance = capabilityRule?.issuance_operation_code === response.operation_code && capabilityRule?.issuance_outcome_code === response.payload.outcome_code
      assertCustodyCapability(response.payload[fieldCode], fieldCode, response, bindings, runtime, classification, capabilityControls, response.payload.artifact ?? request.payload.artifact, { issuance })
    }
  }
  const canonicalRequest = Buffer.from(canonical(request), 'utf8')
  const canonicalResponse = Buffer.from(canonical(response), 'utf8')
  assertIpcPacket(canonicalRequest, request, request.ancillary_descriptors.map((item) => item.role_code), runtime)
  assertIpcPacket(canonicalResponse, response, response.ancillary_descriptors.map((item) => item.role_code), runtime)
}

const nullableCustodyPayloadKeys = [
  'staging_root_slot_code', 'relative_path', 'bundle_seal_record_digest_sha256', 'collector_handoff_record_digest_sha256', 'staging_snapshot_code',
  'artifact', 'source_handle_token', 'preparation_token',
  'backend_code', 'backend_reference', 'copy_code', 'purpose_code', 'sealed_capability_token',
  'custody_evaluated_at', 'known_through_bundle_sequence', 'outcome_code',
  'clearance_decision_record_digest_sha256', 'clearance_scope_sha256', 'custody_leaf_projection_sha256',
  'durability_receipt_sha256', 'error_code',
]

function payloadShape(payload, requiredNonNull, permittedNonNull) {
  for (const key of requiredNonNull) if (payload[key] === null || payload[key] === undefined) return false
  for (const key of nullableCustodyPayloadKeys) if (!permittedNonNull.has(key) && payload[key] !== null && payload[key] !== undefined) return false
  return true
}

function assertCustodyMessageMatrix(message, classification) {
  const payload = message.payload
  const rule = classification.custody_message_rules.find((item) => item.operation_code === message.operation_code)
  if (!rule) fail('semantic', 'IPC_MALFORMED', `unregistered custody operation ${message.operation_code}`)
  const descriptorRoles = message.ancillary_descriptors.map((item) => item.role_code)
  let valid = false
  if (message.message_kind_code === 'request') {
    valid = payloadShape(payload, rule.request_nonnull_fields, new Set(rule.request_nonnull_fields)) && payload.outcome_code === null && payload.error_code === null && canonical(descriptorRoles) === canonical(rule.request_descriptor_roles)
  } else if (rule.success_outcomes.includes(payload.outcome_code)) {
    valid = payloadShape(payload, rule.success_nonnull_fields, new Set(rule.success_nonnull_fields)) && payload.error_code === null && canonical(descriptorRoles) === canonical(rule.success_descriptor_roles)
  } else if (rule.failure_outcomes.includes(payload.outcome_code)) {
    valid = payloadShape(payload, ['outcome_code', 'error_code'], new Set(['outcome_code', 'error_code'])) && descriptorRoles.length === 0
    if (valid) {
      const error = errorRule(classification, payload.error_code)
      if (error.stage !== 'custody_prepare' || !rule.failure_error_codes[payload.outcome_code]?.includes(payload.error_code)) valid = false
    }
  }
  if (!valid) fail('semantic', 'IPC_MALFORMED', `invalid ${message.message_kind_code}/${message.operation_code} payload or descriptor combination`)
  assertPilotCasReference(payload.artifact, payload.backend_code, payload.backend_reference)
  if (message.operation_code === 'open_custody' && message.message_kind_code === 'request' && message.payload.purpose_code !== 'integrity') fail('semantic', 'IPC_MALFORMED', 'pilot custody opening is integrity-only while processing remains disabled')
  for (const [fieldCode, kind] of [['source_handle_token', 'source_handle'], ['preparation_token', 'preparation'], ['sealed_capability_token', 'sealed_custody_access']]) {
    const capability = payload[fieldCode]
    if (capability !== null && capability.capability_kind_code !== kind) fail('semantic', 'IPC_MALFORMED', `${fieldCode} has the wrong capability kind`)
  }
  unique(message.ancillary_descriptors.map((item) => item.ordinal), 'semantic', 'IPC_MALFORMED', 'ancillary descriptor ordinal')
  if (message.ancillary_descriptors.some((item, index) => item.ordinal !== index + 1)) fail('semantic', 'IPC_MALFORMED', 'ancillary descriptor ordinals are not contiguous')
}

function assertIpcPacket(bytes, expected, suppliedDescriptorRoles, runtime) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > runtime.ipc.max_packet_bytes) fail('ipc', 'IPC_MALFORMED', 'IPC packet size is invalid')
  const value = parseJsonBytes(bytes, { contractNumbers: true, maximumBytes: runtime.ipc.max_packet_bytes })
  if (!bytes.equals(Buffer.from(canonical(value), 'utf8'))) fail('ipc', 'IPC_MALFORMED', 'IPC packet is not one canonical JSON document')
  if (canonical(value) !== canonical(expected)) fail('ipc', 'IPC_MALFORMED', 'IPC packet content differs from expected message')
  const declared = value.ancillary_descriptors.map((item) => item.role_code)
  if (canonical(declared) !== canonical(suppliedDescriptorRoles)) fail('ipc', 'IPC_MALFORMED', 'SCM_RIGHTS roles differ from message declaration')
  return value
}

function registerIpcMessage(message, state) {
  const operationKey = `${message.operation_nonce}:${message.operation_id}:${message.runtime_profile_record_digest_sha256}`
  const priorOperation = state.nonces.get(message.operation_nonce)
  if (priorOperation !== undefined && priorOperation !== operationKey) fail('ipc', 'IPC_REPLAY_DETECTED', 'operation nonce was rebound to another operation or runtime profile')
  state.nonces.set(message.operation_nonce, operationKey)
  if (message.message_kind_code === 'request') {
    const stream = state.streams.get(operationKey) || { nextSequence: 1, sender: message.sender_binding_code, recipient: message.recipient_binding_code }
    if (stream.sender !== message.sender_binding_code || stream.recipient !== message.recipient_binding_code || message.request_sequence !== stream.nextSequence || state.requestIds.has(message.request_id)) fail('ipc', 'IPC_REPLAY_DETECTED', 'request peer, identifier, or sequence was replayed or skipped')
    state.requestIds.add(message.request_id)
    state.requests.set(message.request_id, message)
    stream.nextSequence += 1
    state.streams.set(operationKey, stream)
    return
  }
  const request = state.requests.get(message.request_id)
  if (!request || state.responses.has(message.request_id) || message.request_record_digest_sha256 !== request.record_digest_sha256 || message.request_sequence !== request.request_sequence || message.sender_binding_code !== request.recipient_binding_code || message.recipient_binding_code !== request.sender_binding_code) fail('ipc', 'IPC_REPLAY_DETECTED', 'response is duplicate, orphaned, or bound to another request')
  state.responses.add(message.request_id)
}

function errorRule(classification, code) {
  const rule = classification.error_rules.find((item) => item.code === code)
  if (!rule) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', `unregistered error code ${code}`)
  return rule
}

function assertErrorTuple(error, classification) {
  const rule = errorRule(classification, error.code)
  if (error.stage !== rule.stage || error.retryable !== rule.retryable || error.retryability_code !== rule.retryability_code || error.recovery_class_code !== rule.recovery_class_code || error.message !== rule.safe_message) {
    fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', `error tuple differs from registry for ${error.code}`)
  }
}

function assertResultErrorCompatibility(outcome, errorCode, classification) {
  const rule = classification.result_error_rules.find((item) => item.result_outcome_code === outcome)
  if (!rule || !rule.allowed_error_codes.includes(errorCode)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', `${errorCode} cannot produce ${outcome}`)
}

function errorEffectRule(classification, errorCode) {
  const rules = classification.error_effect_rules.filter((item) => item.error_code === errorCode)
  if (rules.length !== 1) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', `${errorCode} lacks one exact effect/disposition rule`)
  return rules[0]
}

function errorBundleReferenceRule(classification, errorCode) {
  const rules = classification.error_bundle_reference_rules.filter((item) => item.error_code === errorCode)
  if (rules.length !== 1) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', `${errorCode} lacks one exact bundle-reference rule`)
  return rules[0]
}

function assertErrorBundleReferencePolicy(errorCode, references, classification) {
  const bundlePolicy = errorBundleReferenceRule(classification, errorCode).bundle_reference_policy_code
  const allNull = references.every((item) => item === null)
  const allPresent = references.every((item) => item !== null)
  if ((bundlePolicy === 'forbidden' && !allNull) || (bundlePolicy === 'required' && !allPresent) || (bundlePolicy === 'optional_all_or_none' && !allNull && !allPresent)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'bundle identity presence differs from the error-specific policy')
}

function permitBundleReference(permit) {
  if (permit.permit_kind_code === 'bootstrap') return permit.bootstrap_bundle
  if (permit.permit_kind_code === 'recovery') return permit.accepted_bootstrap_bundle
  if (permit.permit_kind_code === 'post_promotion_completion') return permit.target_bundle
  return null
}

function permitTerminalStateReference(permit) {
  if (permit.permit_kind_code === 'recovery') return permit.accepted_logical_state
  if (permit.permit_kind_code === 'post_promotion_completion') return permit.verified_canonical_logical_state
  return null
}

function bundleResolverKey(kind, bundle) {
  return `${kind}|${canonical(bundle)}`
}

function permitScopeExecutionRule(permit, classification) {
  const rules = classification.permit_scope_execution_rules.filter((item) => item.permit_kind_code === permit.permit_kind_code && item.scope_code === permit.scope_code)
  if (rules.length !== 1) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit lacks one exact frozen execution scope')
  return rules[0]
}

function resolveLogicalStateReference(reference, controls, label, availableAt = null) {
  if (reference === null || !controls?.logicalStateRecords) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} lacks an exact logical-state resolver`)
  const state = controls.logicalStateRecords.get(reference.state_seal_record_digest_sha256)
  if (!state || state.record_digest_sha256 !== reference.state_seal_record_digest_sha256 || state.record_code !== reference.state_seal_code || state.logical_state_sha256 !== reference.logical_state_sha256 || recordDigest(state) !== state.record_digest_sha256 || sha256(Buffer.from(canonical(state.state_payload), 'utf8')) !== state.logical_state_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} does not resolve exact immutable logical-state content`)
  if (availableAt !== null && state.produced_at > availableAt) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} was not available at the asserted time`)
  return state
}

function resolveBundleReference(kind, bundle, controls, label) {
  const resolved = controls?.bundleReferences?.get(bundleResolverKey(kind, bundle))
  if (!resolved || canonical(resolved) !== canonical(bundle)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} does not resolve exact reviewed bundle evidence`)
  return resolved
}

function bootstrapPrincipalRosterProjection(manifest) {
  if (!manifest?.principal_bootstrap) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'bootstrap manifest lacks its exact planned principal roster')
  return [manifest.principal_bootstrap.trust_root, ...manifest.principal_bootstrap.principals].map((principal) => ({
    id: principal.id,
    principal_code: principal.principal_code,
    principal_kind_code: principal.principal_kind_code,
    created_by_principal_code: principal.created_by_principal_code,
    created_at: principal.created_at,
  }))
}

function resolveBootstrapManifestRoster(permit, controls) {
  const manifest = controls?.bootstrapManifests?.get(bundleResolverKey('principal_bootstrap', permit.bootstrap_bundle))
  if (!manifest || canonical({ bundle_id: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence, bundle_digest_sha256: manifest.bundle_digest_sha256 }) !== canonical(permit.bootstrap_bundle) || manifest.manifest_path !== permit.manifest_path || manifest.bundle_digest_sha256 !== sha256(Buffer.from(canonical(withoutTopLevel(manifest, 'bundle_digest_sha256')), 'utf8'))) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'bootstrap permit does not resolve one exact reviewed bootstrap manifest')
  const roster = bootstrapPrincipalRosterProjection(manifest)
  const rosterSha256 = sha256(Buffer.from(canonical(roster), 'utf8'))
  if (permit.expected_principal_roster_sha256 !== rosterSha256) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'bootstrap permit roster commitment differs from its exact reviewed manifest')
  return { manifest, roster, rosterSha256 }
}

function assertPermitCommon(permit, controls, classification, useAt = null) {
  if (!controls?.bindings || !controls?.runtime) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit validation lacks its frozen runtime and identity bindings')
  assertDigest(permit)
  const { bindings, runtime } = controls
  const expectedKinds = new Map([
    ['bootstrap', 'permit_issuance'],
    ['recovery', 'recovery_permit'],
    ['post_promotion_completion', 'post_promotion_completion_permit'],
  ])
  if (permit.record_kind_code !== expectedKinds.get(permit.permit_kind_code)) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'permit record kind and permit kind differ')
  const scopeRule = permitScopeExecutionRule(permit, classification)
  if (permit.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || permit.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || bindings.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'permit pins another runtime profile or identity-binding generation')
  if (!(permit.issued_at <= permit.not_before && permit.not_before < permit.expires_at && permit.expires_at <= bindings.expires_at)) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'permit has invalid or dependency-outliving validity bounds')
  if (useAt !== null && !(permit.not_before <= useAt && useAt < permit.expires_at)) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'permit use falls outside its active interval')
  const importer = findBinding(bindings, permit.importer_binding_code, 'bundle_importer', permit.issued_at)
  const importerRelease = runtime.component_releases.find((item) => item.runtime_role_code === 'bundle_importer')
  if (!importerRelease || importer.executable_sha256 !== importerRelease.executable_sha256 || permit.expires_at > importer.valid_until) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'permit is not pinned to an active frozen importer release')
  if ('importer_release_sha256' in permit && permit.importer_release_sha256 !== importerRelease.executable_sha256) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'permit names the wrong importer release')
  return scopeRule
}

function assertReplayCertificate(replay, controls, classification, useAt = null) {
  if (!replay || replay.record_kind_code !== 'replay_certificate' || !controls?.permits || !controls?.transitions) fail('semantic', 'REPLAY_CERTIFICATE_INVALID', 'replay certificate lacks protected source resolvers')
  assertDigest(replay)
  const issuer = findBinding(controls.bindings, replay.issuer_binding_code, 'independent_verifier', replay.issued_at)
  const witness = findBinding(controls.bindings, replay.witness_binding_code, 'operational_witness', replay.issued_at)
  if (issuer.unix_uid === witness.unix_uid || !(replay.issued_at < replay.expires_at) || (useAt !== null && !(replay.issued_at <= useAt && useAt < replay.expires_at))) fail('semantic', 'REPLAY_CERTIFICATE_INVALID', 'replay certificate lacks independent issuer/witness identities or valid bounds')
  const spent = controls.transitions.get(replay.permit_spent_transition_record_digest_sha256)
  if (!spent || spent.record_digest_sha256 !== replay.permit_spent_transition_record_digest_sha256) fail('semantic', 'REPLAY_CERTIFICATE_INVALID', 'replay certificate does not resolve its exact spent transition')
  const sourcePermit = controls.permits.get(spent.permit_issuance_record_digest_sha256)
  if (!sourcePermit || sourcePermit.permit_kind_code !== 'bootstrap' || sourcePermit.permit_code !== replay.permit_code || sourcePermit.canonical_lineage_code !== replay.canonical_lineage_code) fail('semantic', 'REPLAY_CERTIFICATE_INVALID', 'replay certificate does not resolve its original bootstrap permit')
  const lifecycle = resolvePermitTransitionChain(sourcePermit, controls, classification, replay.issued_at)
  if (!lifecycle.terminal || lifecycle.terminal.record_digest_sha256 !== spent.record_digest_sha256 || lifecycle.projectedTransitionHead?.record_digest_sha256 !== spent.record_digest_sha256 || spent.to_state_code !== 'spent' || spent.transition_code !== 'verified_effect' || spent.persisted_at > replay.issued_at) fail('semantic', 'REPLAY_CERTIFICATE_INVALID', 'replay certificate source is not the current protected-time-visible spent bootstrap head')
  const acceptedState = resolveLogicalStateReference(replay.accepted_logical_state, controls, 'replay accepted state', replay.issued_at)
  resolveBundleReference('principal_bootstrap', replay.accepted_bootstrap_bundle, controls, 'replay accepted bootstrap bundle')
  if (replay.target_database_class_code !== 'disposable_recovery_only' || canonical(replay.accepted_bootstrap_bundle) !== canonical(sourcePermit.bootstrap_bundle) || canonical(replay.accepted_logical_state) !== canonical(spent.observed_logical_state) || replay.accepted_receipt_sha256 !== acceptedState.state_payload.receipt_head?.receipt_row_sha256 || replay.principal_roster_sha256 !== acceptedState.state_payload.principal_roster_sha256) fail('semantic', 'REPLAY_CERTIFICATE_INVALID', 'replay certificate differs from its accepted bootstrap state, receipt, or principal roster')
  return { sourcePermit, lifecycle }
}

function journalHistoryAtCurrentTerminal(event, controls, classification) {
  if (!controls?.journalEvents) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'protected journal resolver is unavailable')
  const resolved = controls.journalEvents.get(event.record_digest_sha256)
  if (!resolved || canonical(resolved) !== canonical(event) || recordDigest(resolved) !== event.record_digest_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal reference does not resolve exact immutable content')
  const protectedRows = [...controls.journalEvents.entries()]
    .map(([key, candidate]) => {
      if (key !== candidate.record_digest_sha256 || recordDigest(candidate) !== candidate.record_digest_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal register key differs from immutable event content')
      return candidate
    })
  for (const candidate of protectedRows) {
    if (candidate.previous_event_record_digest_sha256 === null) continue
    const predecessor = controls.journalEvents.get(candidate.previous_event_record_digest_sha256)
    if (predecessor && predecessor.journal_code !== candidate.journal_code) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'protected journal register contains a cross-journal predecessor edge')
  }
  const journalRows = protectedRows.filter((candidate) => candidate.journal_code === event.journal_code)
  if (journalRows.length === 0) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'protected journal register lacks the cited journal')
  const contextProjection = (candidate) => canonical({
    authorization_bundle_seal_record_digest_sha256: candidate.authorization_bundle_seal_record_digest_sha256,
    authorization_permit_record_digest_sha256: candidate.authorization_permit_record_digest_sha256,
    bundle: candidate.bundle,
    identity_bindings_record_digest_sha256: candidate.identity_bindings_record_digest_sha256,
    journal_code: candidate.journal_code,
    operation_id: candidate.operation_id,
    operation_mode_code: candidate.operation_mode_code,
    operation_nonce: candidate.operation_nonce,
    runtime_profile_record_digest_sha256: candidate.runtime_profile_record_digest_sha256,
    target_logical_state: candidate.target_logical_state,
  })
  if (journalRows.some((candidate) => contextProjection(candidate) !== contextProjection(event))) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'one journal code spans multiple operation or authorization contexts')
  unique(journalRows.map((candidate) => candidate.event_sequence), 'semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event sequence')
  unique(journalRows.map((candidate) => candidate.previous_event_record_digest_sha256 ?? 'root'), 'semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal predecessor successor')
  if (journalRows.filter((candidate) => candidate.previous_event_record_digest_sha256 === null).length !== 1) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal register does not contain exactly one operation-start root')
  if (protectedRows.some((candidate) => candidate.previous_event_record_digest_sha256 === event.record_digest_sha256)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal reference is not the current terminal head')
  const reverseHistory = []
  const visited = new Set()
  let current = event
  while (current !== null) {
    if (visited.has(current.record_digest_sha256)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal source chain contains a cycle')
    visited.add(current.record_digest_sha256)
    reverseHistory.push(current)
    if (current.previous_event_record_digest_sha256 === null) break
    const previous = controls.journalEvents.get(current.previous_event_record_digest_sha256)
    if (!previous || previous.record_digest_sha256 !== current.previous_event_record_digest_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal source chain has an unresolved predecessor')
    current = previous
  }
  const history = reverseHistory.reverse()
  if (history.length !== journalRows.length) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal register contains a disconnected or branched event outside the cited history')
  assertJournalHistory(history, classification, controls.bindings, controls.runtime, controls)
  return history
}

function assertPermitIssuance(permit, controls, classification, useAt = null) {
  const scopeRule = assertPermitCommon(permit, controls, classification, useAt)
  const { bindings, runtime } = controls
  if (permit.permit_kind_code === 'bootstrap') {
    const target = resolveLogicalStateReference(permit.target_empty_logical_state, controls, 'bootstrap target state', permit.issued_at)
    resolveBundleReference('principal_bootstrap', permit.bootstrap_bundle, controls, 'bootstrap bundle')
    const matchingSeals = [...(controls.bundleSeals?.values() ?? [])].filter((seal) => seal.bundle_kind_code === 'principal_bootstrap' && canonical(seal.bundle) === canonical(permit.bootstrap_bundle))
    if (matchingSeals.length !== 1) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'bootstrap permit lacks one exact launcher seal')
    const seal = matchingSeals[0]
    assertDigest(seal)
    resolveBootstrapManifestRoster(permit, controls)
    if (Date.parse(permit.expires_at) - Date.parse(permit.issued_at) > classification.bootstrap_permit_policy.maximum_lifetime_ms || permit.canonical_lineage_code !== target.state_payload.canonical_lineage_code || canonical(seal.target_logical_state) !== canonical(permit.target_empty_logical_state) || seal.manifest_path !== permit.manifest_path || seal.reviewed_git_commit !== permit.reviewed_git_commit || seal.operation_nonce !== permit.operation_nonce || seal.sealed_at > permit.issued_at || permit.issued_at >= seal.expires_at || target.state_payload.receipt_head !== null || target.state_payload.principal_roster.length !== 0 || target.state_payload.atlas_tables.some((row) => row.row_count !== 0)) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'bootstrap permit does not pin the exact sealed empty target, roster, bounded lifetime, and lineage')
    const humans = [
      findBinding(bindings, permit.submitter_binding_code, 'human_submitter', permit.issued_at),
      findBinding(bindings, permit.witness_binding_code, 'operational_witness', permit.issued_at),
      findBinding(bindings, permit.issuer_binding_code, 'bootstrap_authority', permit.issued_at),
    ]
    unique(humans.map((binding) => binding.unix_uid), 'semantic', 'BOOTSTRAP_PERMIT_INVALID', 'bootstrap human subject')
    if (humans.some((binding) => permit.expires_at > binding.valid_until)) fail('semantic', 'BOOTSTRAP_PERMIT_INVALID', 'bootstrap permit outlives a human binding')
  } else if (permit.permit_kind_code === 'recovery') {
    const replay = controls.replayCertificates?.get(permit.replay_certificate.record_digest_sha256)
    if (!replay || replay.record_code !== permit.replay_certificate.record_code || replay.format !== permit.replay_certificate.format || replay.format_version !== permit.replay_certificate.format_version) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'recovery permit does not resolve its exact replay certificate')
    assertReplayCertificate(replay, controls, classification, permit.issued_at)
    assertRecoveryPermitWindow(permit, replay, bindings, classification)
    resolveBundleReference('principal_bootstrap', permit.accepted_bootstrap_bundle, controls, 'recovery accepted bootstrap bundle')
    const accepted = resolveLogicalStateReference(permit.accepted_logical_state, controls, 'recovery accepted state', permit.issued_at)
    const target = resolveLogicalStateReference(permit.target_empty_logical_state, controls, 'recovery empty target state', permit.issued_at)
    if (permit.target_database_class_code !== 'disposable_recovery_only' || canonical(permit.replay_certificate) !== canonical({ format: replay.format, format_version: replay.format_version, record_code: replay.record_code, record_digest_sha256: replay.record_digest_sha256 }) || permit.canonical_lineage_code !== replay.canonical_lineage_code || permit.canonical_lineage_code !== accepted.state_payload.canonical_lineage_code || permit.canonical_lineage_code !== target.state_payload.canonical_lineage_code || canonical(permit.accepted_bootstrap_bundle) !== canonical(replay.accepted_bootstrap_bundle) || canonical(permit.accepted_logical_state) !== canonical(replay.accepted_logical_state) || canonical(permit.target_empty_logical_state) === canonical(permit.accepted_logical_state) || accepted.state_payload.receipt_head?.receipt_row_sha256 !== replay.accepted_receipt_sha256 || target.state_payload.receipt_head !== null || target.state_payload.principal_roster.length !== 0 || target.state_payload.atlas_tables.some((row) => row.row_count !== 0)) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'recovery permit differs from its replay authority, lineage, or empty disposable target')
    const humans = [
      findBinding(bindings, permit.operator_binding_code, 'recovery_operator', permit.issued_at),
      findBinding(bindings, permit.witness_binding_code, 'operational_witness', permit.issued_at),
      findBinding(bindings, permit.issuer_binding_code, 'recovery_authority', permit.issued_at),
    ]
    unique(humans.map((binding) => binding.unix_uid), 'semantic', 'RECOVERY_PERMIT_INVALID', 'recovery human subject')
    if (humans.some((binding) => permit.expires_at > binding.valid_until)) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'recovery permit outlives a human binding')
  } else {
    const policy = classification.post_promotion_completion_permit_policy
    const sourceJournal = controls.journalEvents?.get(permit.source_recovery_journal_event_record_digest_sha256)
    if (!sourceJournal) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'completion permit lacks its exact source recovery journal event')
    journalHistoryAtCurrentTerminal(sourceJournal, controls, classification)
    const sourceError = classification.post_promotion_source_error_rules.find((item) => item.error_code === sourceJournal.error_code)
    if (!policy.required_bundle_kind_codes.includes(permit.target_bundle_kind_code) || !sourceError || !sourceError.allowed_bundle_kind_codes.includes(permit.target_bundle_kind_code) || !policy.allowed_source_error_codes.includes(sourceJournal.error_code) || sourceJournal.event_kind_code !== 'recovery_required' || sourceJournal.recovery_class_code !== policy.required_source_recovery_class_code || sourceJournal.canonical_effect_code !== sourceError.canonical_effect_code || sourceJournal.object_disposition_code !== sourceError.object_disposition_code || canonical(sourceJournal.bundle) !== canonical(permit.target_bundle) || permit.source_recovery_journal_event_record_digest_sha256 !== sourceJournal.record_digest_sha256 || sourceJournal.persisted_at > permit.issued_at) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'completion permit source journal is not an eligible current protected-persistence-visible terminal incident')
    resolveBundleReference(permit.target_bundle_kind_code, permit.target_bundle, controls, 'completion target bundle')
    const verified = resolveLogicalStateReference(permit.verified_canonical_logical_state, controls, 'completion verified canonical state', permit.issued_at)
    const verifiedReceipt = verified.state_payload.receipt_head
    const sourceObservedMustMatch = sourceError.observed_state_policy_code === 'required' || sourceJournal.observed_logical_state !== null
    if (permit.verified_canonical_receipt_sha256 !== verifiedReceipt?.receipt_row_sha256 || permit.canonical_lineage_code !== verified.state_payload.canonical_lineage_code || verifiedReceipt?.bundle_id !== permit.target_bundle.bundle_id || verifiedReceipt?.bundle_sequence !== permit.target_bundle.bundle_sequence || verifiedReceipt?.bundle_digest_sha256 !== permit.target_bundle.bundle_digest_sha256 || (sourceObservedMustMatch && canonical(sourceJournal.observed_logical_state) !== canonical(permit.verified_canonical_logical_state)) || permit.scope_code !== policy.scope_code || canonical(permit.allowed_actions) !== canonical(policy.allowed_actions) || permit.canonical_write_code !== policy.canonical_write_code || permit.allowed_canonical_effect_code !== policy.allowed_canonical_effect_code || Date.parse(permit.expires_at) - Date.parse(permit.issued_at) > policy.maximum_lifetime_ms) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'completion permit differs from its exact verified state, receipt, lineage, source observation, or frozen narrow policy')
    if (permit.target_bundle_kind_code === 'single_document') {
      const sourceSeal = controls.bundleSeals?.get(permit.source_authorization_record_digest_sha256)
      if (!sourceSeal || sourceSeal.bundle_kind_code !== 'single_document' || sourceSeal.record_digest_sha256 !== permit.source_authorization_record_digest_sha256 || sourceJournal.authorization_bundle_seal_record_digest_sha256 !== sourceSeal.record_digest_sha256 || sourceJournal.authorization_permit_record_digest_sha256 !== null || permit.source_terminal_transition_record_digest_sha256 !== null || canonical(sourceSeal.bundle) !== canonical(permit.target_bundle)) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'document completion does not pin its exact source launcher seal')
      assertDigest(sourceSeal)
    } else {
      const sourcePermit = controls.permits?.get(permit.source_authorization_record_digest_sha256)
      const sourceTerminal = controls.transitions?.get(permit.source_terminal_transition_record_digest_sha256)
      if (!sourcePermit || sourcePermit.permit_kind_code !== 'bootstrap' || !sourceTerminal || sourceJournal.authorization_permit_record_digest_sha256 !== sourcePermit.record_digest_sha256 || sourceJournal.authorization_bundle_seal_record_digest_sha256 !== null) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'bootstrap completion does not pin its original bootstrap authorization')
      const sourceLifecycle = resolvePermitTransitionChain(sourcePermit, controls, classification, permit.issued_at)
      if (!sourceLifecycle.terminal || sourceLifecycle.terminal.record_digest_sha256 !== sourceTerminal.record_digest_sha256 || sourceLifecycle.projectedTransitionHead?.record_digest_sha256 !== sourceTerminal.record_digest_sha256 || sourceTerminal.to_state_code !== 'spent' || sourceTerminal.transition_code !== 'verified_effect' || canonical(sourcePermit.bootstrap_bundle) !== canonical(permit.target_bundle) || canonical(sourceTerminal.observed_logical_state) !== canonical(permit.verified_canonical_logical_state) || sourceTerminal.persisted_at > permit.issued_at) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'bootstrap completion source is not the current protected-time-visible spent bootstrap permit')
    }
    const humans = [
      findBinding(bindings, permit.operator_binding_code, 'recovery_operator', permit.issued_at),
      findBinding(bindings, permit.witness_binding_code, 'operational_witness', permit.issued_at),
      findBinding(bindings, permit.issuer_binding_code, 'recovery_authority', permit.issued_at),
    ]
    unique(humans.map((binding) => binding.unix_uid), 'semantic', 'RECOVERY_PERMIT_INVALID', 'completion human subject')
    if (humans.some((binding) => permit.expires_at > binding.valid_until)) fail('semantic', 'RECOVERY_PERMIT_INVALID', 'completion permit outlives a human binding')
  }
  return scopeRule
}

function resolvePermitTransitionChain(permit, controls, classification, asOf = null) {
  if (!controls?.transitions || !controls?.bindings) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit lifecycle resolver is unavailable')
  if (asOf !== null && !canonicalTimestamp(asOf)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit lifecycle as_of is not a canonical UTC timestamp')
  assertPermitIssuance(permit, controls, classification)
  const rows = [...controls.transitions.entries()]
    .filter(([, transition]) => transition.permit_issuance_record_digest_sha256 === permit.record_digest_sha256)
    .map(([key, transition]) => {
      if (key !== transition.record_digest_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit transition lookup key differs from immutable content')
      assertDigest(transition)
      return transition
    })
    .toSorted((left, right) => left.transition_sequence - right.transition_sequence)
  if (rows.length > 2) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit lifecycle contains more than one root and one terminal successor')
  assertUniquePermitSuccessors(rows)
  const initialState = controls.journalTargetStates?.get(permit.record_digest_sha256)
  const terminalState = controls.permitTerminalStates?.get(permit.record_digest_sha256)
  if (!initialState) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit lifecycle lacks its exact initial-state resolver')
  if (rows.length === 0) {
    const derivedStateCode = asOf !== null && asOf < permit.issued_at
      ? null
      : asOf !== null && asOf >= permit.expires_at
        ? classification.permit_claim_policy.expired_ready_projection_code
        : 'ready'
    return { claim: null, terminal: null, projectedTransitionHead: null, derivedStateCode, scopeRule: permitScopeExecutionRule(permit, classification) }
  }
  const root = rows[0]
  if (root.from_state_code !== 'ready') fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit lifecycle root does not start from ready')
  if (root.observed_logical_state !== null) resolveLogicalStateReference(root.observed_logical_state, controls, 'permit root observed state', root.occurred_at)
  if (root.to_state_code === 'revoked' && root.transition_code === 'authority_withdrawal') {
    if (rows.length !== 1) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'revoked permit lifecycle has an illegal successor')
    assertPermitTransition(root, permit, null, initialState, null, controls.bindings, classification)
    const visible = asOf === null || root.persisted_at <= asOf
    const derivedStateCode = asOf !== null && asOf < permit.issued_at
      ? null
      : visible ? 'revoked' : asOf !== null && asOf >= permit.expires_at
        ? classification.permit_claim_policy.expired_ready_projection_code
        : 'ready'
    return {
      claim: null,
      terminal: root,
      projectedTransitionHead: visible ? root : null,
      derivedStateCode,
      scopeRule: permitScopeExecutionRule(permit, classification),
    }
  }
  const claim = root
  if (claim.to_state_code !== 'in_progress' || claim.transition_code !== 'operation_claimed') fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit lifecycle lacks an exact claim or authority-withdrawal root')
  if (permit.permit_kind_code === 'bootstrap') {
    const seals = [...(controls.bundleSeals?.values() ?? [])].filter((seal) => seal.bundle_kind_code === 'principal_bootstrap' && canonical(seal.bundle) === canonical(permit.bootstrap_bundle))
    if (seals.length !== 1 || seals[0].operation_id !== claim.operation_id || seals[0].operation_nonce !== claim.operation_nonce) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'bootstrap claim crosses its sealed operation identity')
  }
  resolveLogicalStateReference(claim.observed_logical_state, controls, 'permit claim observed state', claim.occurred_at)
  assertPermitTransition(claim, permit, null, initialState, null, controls.bindings, classification)
  if (Date.parse(permit.expires_at) - Date.parse(claim.occurred_at) < classification.permit_claim_policy.minimum_remaining_lifetime_ms) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit claim lacks the frozen minimum remaining lifetime')
  let terminal = null
  if (rows.length === 2) {
    terminal = rows[1]
    const terminalRule = classification.permit_transition_rules.find((item) => item.permit_kind_code === terminal.permit_kind_code && item.from_state_code === terminal.from_state_code && item.to_state_code === terminal.to_state_code && item.transition_code === terminal.transition_code && item.reason_code === terminal.reason_code)
    if (!terminalRule || (terminalRule.observed_state_policy_code === 'exact_expected' && !terminalState)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit terminal state resolver is unavailable')
    if (terminal.observed_logical_state !== null) resolveLogicalStateReference(terminal.observed_logical_state, controls, 'permit terminal observed state', terminal.occurred_at)
    assertPermitTransition(terminal, permit, claim, terminalState, null, controls.bindings, classification)
    if (!['spent', 'recovery_required'].includes(terminal.to_state_code)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit lifecycle has an invalid post-claim terminal state')
  }
  const visibleRows = asOf === null ? rows : rows.filter((row) => row.persisted_at <= asOf)
  const projectedTransitionHead = visibleRows.at(-1) ?? null
  let derivedStateCode
  if (asOf !== null && asOf < permit.issued_at) derivedStateCode = null
  else if (projectedTransitionHead?.to_state_code === 'spent') derivedStateCode = 'spent'
  else if (projectedTransitionHead?.to_state_code === 'recovery_required') derivedStateCode = 'recovery_required'
  else if (projectedTransitionHead?.to_state_code === 'in_progress') {
    derivedStateCode = asOf !== null && asOf >= permit.expires_at
      ? classification.permit_claim_policy.expired_in_progress_projection_code
      : 'in_progress'
  } else {
    derivedStateCode = asOf !== null && asOf >= permit.expires_at
      ? classification.permit_claim_policy.expired_ready_projection_code
      : 'ready'
  }
  return { claim, terminal, projectedTransitionHead, derivedStateCode, scopeRule: permitScopeExecutionRule(permit, classification) }
}

function assertRecoveredResultAuthorization(result, classification, controls) {
  if (!controls?.permits || !controls?.transitions) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result lacks an exact protected authorization resolver')
  const permit = controls.permits.get(result.recovery_permit_record_digest_sha256)
  const terminal = controls.transitions.get(result.recovery_terminal_transition_record_digest_sha256)
  if (!permit || !terminal || permit.record_digest_sha256 !== result.recovery_permit_record_digest_sha256 || terminal.record_digest_sha256 !== result.recovery_terminal_transition_record_digest_sha256) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result authorization does not resolve exact protected records')
  assertDigest(permit)
  assertDigest(terminal)
  const lifecycle = resolvePermitTransitionChain(permit, controls, classification)
  if (!lifecycle.terminal || lifecycle.terminal.record_digest_sha256 !== terminal.record_digest_sha256) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result does not resolve the current terminal head of a complete permit chain')
  const authorizationRules = classification.recovered_result_authorization_rules.filter((item) => item.bundle_kind_code === result.bundle_kind_code && item.permit_kind_code === permit.permit_kind_code && item.terminal_transition_code === terminal.transition_code)
  if (authorizationRules.length !== 1) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result does not match one closed bundle/permit/terminal authorization rule')
  const authorizationRule = authorizationRules[0]
  const targetBundle = permitBundleReference(permit)
  const targetState = permitTerminalStateReference(permit)
  const resultBundle = { bundle_id: result.bundle_id, bundle_sequence: result.bundle_sequence, bundle_digest_sha256: result.bundle_digest_sha256 }
  if (!targetBundle || canonical(resultBundle) !== canonical(targetBundle) || result.operation_id !== permit.operation_id || terminal.permit_kind_code !== permit.permit_kind_code || terminal.permit_code !== permit.permit_code || terminal.permit_issuance_record_digest_sha256 !== permit.record_digest_sha256 || terminal.operation_id !== permit.operation_id || terminal.operation_nonce !== permit.operation_nonce || terminal.to_state_code !== 'spent' || canonical(terminal.observed_logical_state) !== canonical(targetState) || terminal.occurred_at < permit.not_before || terminal.occurred_at >= permit.expires_at) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result is not bound to the exact spent permit, bundle, operation, and verified state')
  const transitionRows = [...controls.transitions.values()]
  if (transitionRows.some((item) => item.previous_transition_record_digest_sha256 === terminal.record_digest_sha256)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result cites a nonterminal permit-transition head')
  if (permit.permit_kind_code === 'post_promotion_completion') {
    const completionHead = controls.journalEvents?.get(terminal.completion_journal_head_record_digest_sha256)
    if (!completionHead) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'post-promotion result lacks its exact completion-journal head')
    const completionHistory = journalHistoryAtCurrentTerminal(completionHead, controls, classification)
    const zeroRows = completionHead.rows_delta !== null && Object.values(completionHead.rows_delta).every((value) => value === 0)
    const zeroObjects = completionHead.objects_delta !== null && Object.values(completionHead.objects_delta).every((value) => value === 0)
    if (completionHead.event_kind_code !== 'operation_completed' || completionHead.result_outcome_code !== 'recovered' || completionHead.error_code !== null || completionHead.canonical_effect_code !== 'none_verified' || completionHead.authorization_permit_record_digest_sha256 !== permit.record_digest_sha256 || completionHead.authorization_bundle_seal_record_digest_sha256 !== null || completionHead.operation_mode_code !== 'recovery' || completionHead.operation_id !== permit.operation_id || completionHead.operation_nonce !== permit.operation_nonce || canonical(completionHead.bundle) !== canonical(targetBundle) || canonical(completionHead.target_logical_state) !== canonical(targetState) || canonical(completionHead.observed_logical_state) !== canonical(targetState) || !zeroRows || !zeroObjects || completionHead.backup_inventory_sha256 === null || completionHead.persisted_at > terminal.occurred_at || completionHistory.at(-1).record_digest_sha256 !== completionHead.record_digest_sha256) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'post-promotion result completion proof is not exact, zero-effect, current, protected-persistence-visible, and fully journaled')
  }
  const allCountsKnown = result.bootstrap_principals_inserted !== null && result.rows_inserted !== null && result.objects !== null
  const allCountsZero = allCountsKnown && result.bootstrap_principals_inserted === 0 && Object.values(result.rows_inserted).every((value) => value === 0) && Object.values(result.objects).every((value) => value === 0)
  if (authorizationRule.count_policy_code === 'known' && !allCountsKnown) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovery authorization requires known effect counts')
  if (authorizationRule.count_policy_code === 'all_zero' && !allCountsZero) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'post-promotion completion authorization requires exact zero database and custody effects')
}

function assertImporterResult(result, classification, authorizationControls = null) {
  const rules = classification.result_rules.filter((item) => item.outcome === result.outcome && item.allowed_operation_modes.includes(result.operation_mode_code) && item.allowed_bundle_kinds.includes(result.bundle_kind_code === null ? 'null' : result.bundle_kind_code))
  if (rules.length !== 1) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', `result matches ${rules.length} closed outcome/mode/bundle rules`)
  const rule = rules[0]
  if (!rule.allowed_canonical_effects.includes(result.canonical_effect_code) || rule.error_required !== (result.error !== null)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'outcome, canonical effect, or error presence conflicts with result rule')
  if (result.error) {
    assertErrorTuple(result.error, classification)
    assertResultErrorCompatibility(result.outcome, result.error.code, classification)
    const effectRule = errorEffectRule(classification, result.error.code)
    if (result.outcome !== effectRule.result_outcome_code || result.canonical_effect_code !== effectRule.canonical_effect_code) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'result error and canonical effect differ from the total error/effect matrix')
  }
  const references = [result.bundle_kind_code, result.bundle_id, result.bundle_sequence, result.bundle_digest_sha256]
  if (rule.bundle_reference_policy === 'required_all' && references.some((item) => item === null)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'result lacks required bundle reference')
  if (rule.bundle_reference_policy === 'all_or_none' && !(references.every((item) => item === null) || references.every((item) => item !== null))) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'result has a partial bundle reference')
  if (result.error !== null) {
    assertErrorBundleReferencePolicy(result.error.code, references, classification)
  }
  if (result.bundle_kind_code === 'principal_bootstrap' && result.bundle_sequence !== 1) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'bootstrap result must identify bundle sequence 1')
  if (result.bundle_kind_code === 'single_document' && result.bundle_sequence !== null && result.bundle_sequence < 2) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'document result cannot identify the bootstrap sequence')
  if (references.every((item) => item !== null)) {
    const bundle = { bundle_id: result.bundle_id, bundle_sequence: result.bundle_sequence, bundle_digest_sha256: result.bundle_digest_sha256 }
    const resolved = authorizationControls?.bundleReferences?.get(bundleResolverKey(result.bundle_kind_code, bundle))
    if (!resolved || canonical(resolved) !== canonical(bundle)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'result bundle tuple does not resolve exact reviewed evidence')
  }
  const allCountsKnown = result.bootstrap_principals_inserted !== null && result.rows_inserted !== null && result.objects !== null
  const allCountsZero = allCountsKnown && result.bootstrap_principals_inserted === 0 && Object.values(result.rows_inserted).every((value) => value === 0) && Object.values(result.objects).every((value) => value === 0)
  const hasRecoveryPermit = result.recovery_permit_record_digest_sha256 !== null
  const hasRecoveryTerminal = result.recovery_terminal_transition_record_digest_sha256 !== null
  if (hasRecoveryPermit !== hasRecoveryTerminal || (result.outcome === 'recovered') !== hasRecoveryPermit) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovery authorization must be a complete permit/terminal-transition pair present only for recovered results')
  if (result.outcome === 'recovered' && result.operation_mode_code !== 'recovery') fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result must use the recovery operation mode')
  if (result.outcome === 'recovered') assertRecoveredResultAuthorization(result, classification, authorizationControls)
  if (result.outcome === 'recovered' && result.bundle_kind_code === 'single_document' && !allCountsZero) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'post-promotion document completion must prove exact zero database and custody effects')
  if (rule.count_policy === 'all_zero' && !allCountsZero) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'result expected exact zero effects')
  if (rule.count_policy === 'rows_zero_objects_orphan_only' && (!allCountsKnown || result.bootstrap_principals_inserted !== 0 || Object.values(result.rows_inserted).some((value) => value !== 0) || result.objects.prepared !== 0 || result.objects.reused !== 0)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'rejected result must prove zero database/prepared/reused effects while preserving orphan counts')
  if (rule.count_policy === 'known' && !allCountsKnown) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'result effects must be known')
  if (rule.count_policy === 'bootstrap_exact' && (!allCountsKnown || result.bootstrap_principals_inserted !== pilotBundleShape.bootstrap_principals_exact || result.rows_inserted.atlas_evidence_bundle_receipts !== 1 || Object.entries(result.rows_inserted).some(([key, count]) => key !== 'atlas_evidence_bundle_receipts' && count !== 0) || Object.values(result.objects).some((value) => value !== 0))) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'bootstrap result differs from the exact pilot shape')
  if (rule.count_policy === 'document_exact' && (!allCountsKnown || result.bootstrap_principals_inserted !== 0 || result.rows_inserted.atlas_evidence_bundle_receipts !== 1 || result.rows_inserted.atlas_retrieval_locations !== 1 || result.rows_inserted.atlas_artifacts !== 1 || result.rows_inserted.atlas_retrieval_events !== 1 || result.rows_inserted.atlas_retrieval_redirects !== 0 || result.rows_inserted.atlas_artifact_custody_events !== 1 || result.rows_inserted.atlas_processing_runs !== 0 || result.rows_inserted.atlas_processing_outputs !== 0 || result.rows_inserted.atlas_unverified_candidate_occurrences !== 0 || result.objects.prepared !== 1 || result.objects.reused !== 0 || result.objects.orphaned !== 0)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'document result differs from the exact pilot shape')
  const checkValues = Object.values(result.checks)
  if (rule.check_policy === 'all_passed' && !checkValues.every((value) => value === 'passed')) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'successful result has incomplete checks')
  if (rule.check_policy === 'failed_or_early_all_not_run') {
    const earlyStages = new Set(['startup', 'authorization', 'operation_lock', 'input_open'])
    const hasFailedCheck = checkValues.includes('failed')
    const isPrecheckRejection = result.error && earlyStages.has(result.error.stage) && checkValues.every((value) => value === 'not_run')
    if (!hasFailedCheck && !isPrecheckRejection) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'rejected result lacks a failed check or a registered pre-check failure')
  }
  if (rule.check_policy === 'ambiguity_visible' && (!checkValues.includes('not_run') || checkValues.includes('failed'))) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovery result does not expose an ambiguous incomplete verification')
  if (rule.check_policy === 'plan_passed' && !(result.checks.manifest === 'passed' && result.checks.runtime_binding === 'passed' && result.checks.screening === 'passed' && result.checks.clearance === 'passed' && Object.entries(result.checks).filter(([key]) => !['manifest', 'runtime_binding', 'screening', 'clearance'].includes(key)).every(([, value]) => value === 'not_run'))) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'dry-run result has an invalid check projection')
  if (rule.check_policy === 'recovery_verified' && !(result.checks.manifest === 'passed' && result.checks.runtime_binding === 'passed' && result.checks.projection === 'passed' && result.checks.integrity === 'passed' && result.checks.foreign_keys === 'passed' && result.checks.forbidden_surfaces === 'passed' && result.checks.screening === 'not_run' && result.checks.clearance === 'not_run' && result.checks.live_custody === 'not_run')) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'recovered result has an invalid exact recovery-check projection')
  if (Buffer.byteLength(canonical(result), 'utf8') > 32768) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'importer result exceeds fixed byte bound')
}

function assertJournalResolvedReferences(event, controls) {
  if (!controls?.bundleReferences || !controls?.logicalStateRecords) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal reference resolvers are unavailable')
  if (event.bundle !== null) {
    const matches = [...controls.bundleReferences.values()].filter((bundle) => canonical(bundle) === canonical(event.bundle))
    if (matches.length !== 1) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal bundle does not resolve exactly once to accepted reviewed evidence')
  }
  for (const [label, reference] of [['target', event.target_logical_state], ['observed', event.observed_logical_state]]) {
    if (reference === null) continue
    resolveLogicalStateReference(reference, controls, `journal ${label} logical state`, event.event_at)
  }
}

function assertJournalAuthorization(event, classification, authorizationRule, controls) {
  const digest = event.authorization_permit_record_digest_sha256
  if (authorizationRule.authorization_policy_code === 'forbidden') {
    if (digest !== null || event.authorization_bundle_seal_record_digest_sha256 !== null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal operation mode forbids an authorization reference')
    return null
  }
  if (authorizationRule.authorization_policy_code === 'required_exact_bundle_seal') {
    if (digest !== null || event.authorization_bundle_seal_record_digest_sha256 === null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'document journal requires exactly one bundle-seal authorization')
    const seal = controls?.bundleSeals?.get(event.authorization_bundle_seal_record_digest_sha256)
    if (!seal || seal.record_digest_sha256 !== event.authorization_bundle_seal_record_digest_sha256 || seal.record_kind_code !== 'bundle_seal') fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'document journal does not resolve its exact launcher bundle seal')
    assertDigest(seal)
    if (seal.bundle_kind_code !== 'single_document' || seal.operation_id !== event.operation_id || seal.operation_nonce !== event.operation_nonce || seal.runtime_profile_record_digest_sha256 !== event.runtime_profile_record_digest_sha256 || seal.identity_bindings_record_digest_sha256 !== event.identity_bindings_record_digest_sha256 || canonical(seal.bundle) !== canonical(event.bundle) || canonical(seal.target_logical_state) !== canonical(event.target_logical_state) || !(seal.sealed_at <= event.event_at && event.event_at <= event.persisted_at && event.persisted_at < seal.expires_at)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'document journal crosses its sealed operation, bundle, state, runtime, bindings, nonce, semantic time, protected persistence time, or use window')
    findBinding(controls.bindings, seal.submitter_binding_code, 'human_submitter', event.persisted_at)
    findBinding(controls.bindings, seal.importer_binding_code, 'bundle_importer', event.persisted_at)
    findBinding(controls.bindings, seal.launcher_binding_code, 'trusted_launcher', event.persisted_at)
    return null
  }
  if (event.authorization_bundle_seal_record_digest_sha256 !== null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'permit-authorized journal cannot also cite a bundle seal')
  const permit = controls?.permits?.get(digest)
  if (!permit || permit.record_digest_sha256 !== digest || !authorizationRule.allowed_permit_kind_codes.includes(permit.permit_kind_code)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal authorization does not resolve one exact allowed permit')
  assertPermitIssuance(permit, controls, classification, event.persisted_at)
  const lifecycle = resolvePermitTransitionChain(permit, controls, classification, event.persisted_at)
  const targetBundle = permitBundleReference(permit)
  const targetState = controls?.journalTargetStates?.get(digest)
  if (!lifecycle.claim || lifecycle.projectedTransitionHead?.record_digest_sha256 !== lifecycle.claim.record_digest_sha256 || !targetBundle || !targetState || canonical(event.bundle) !== canonical(targetBundle) || canonical(event.target_logical_state) !== canonical(targetState) || event.operation_id !== lifecycle.claim.operation_id || event.operation_nonce !== permit.operation_nonce || event.runtime_profile_record_digest_sha256 !== permit.runtime_profile_record_digest_sha256 || event.identity_bindings_record_digest_sha256 !== permit.identity_bindings_record_digest_sha256 || event.event_at < lifecycle.claim.persisted_at || event.event_at < permit.not_before || event.event_at > event.persisted_at || event.persisted_at >= permit.expires_at) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event is outside its protected-time-visible claimed permit lifecycle, bundle, target state, operation, nonce, runtime, bindings, semantic time, protected persistence time, or active window')
  if (!lifecycle.scopeRule.allowed_journal_event_kind_codes.includes(event.event_kind_code) || !lifecycle.scopeRule.allowed_stage_codes.includes(event.stage_code) || !lifecycle.scopeRule.allowed_canonical_effect_codes.includes(event.canonical_effect_code)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event exceeds its exact permit execution scope')
  return lifecycle.scopeRule
}

function assertJournalEvent(event, classification, bindings = null, runtime = null, authorizationControls = null) {
  if (!classification.operation_modes.includes(event.operation_mode_code) || !classification.journal_event_kinds.includes(event.event_kind_code) || !classification.stages.includes(event.stage_code) || !classification.canonical_effects.includes(event.canonical_effect_code) || !classification.retryability_classes.includes(event.retryability_code) || !classification.recovery_classes.includes(event.recovery_class_code)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event uses unregistered classification')
  if (event.event_at > event.persisted_at) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal semantic event time is later than broker-protected persistence time')
  assertJournalResolvedReferences(event, authorizationControls)
  const authorizationRule = classification.journal_authorization_rules.find((item) => item.operation_mode_code === event.operation_mode_code)
  if (!authorizationRule) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal operation mode lacks a closed authorization rule')
  const permitScopeRule = assertJournalAuthorization(event, classification, authorizationRule, authorizationControls)
  const prepromotionRequired = event.operation_mode_code === 'document_import' && event.event_kind_code === 'promotion_started'
  if (prepromotionRequired !== (event.prepromotion_authorization_record_digest_sha256 !== null)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'pre-promotion authorization is required exactly at document promotion start')
  if (prepromotionRequired) {
    const prepromotion = authorizationControls?.prepromotionAuthorizations?.get(event.prepromotion_authorization_record_digest_sha256)
    if (!prepromotion || prepromotion.record_digest_sha256 !== event.prepromotion_authorization_record_digest_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'document promotion does not resolve its exact pre-promotion authorization')
    const resolved = assertPrePromotionAuthorization(prepromotion, authorizationControls, bindings, runtime, classification, event.event_at, event.persisted_at)
    if (prepromotion.operation_id !== event.operation_id || prepromotion.operation_nonce !== event.operation_nonce || prepromotion.runtime_profile_record_digest_sha256 !== event.runtime_profile_record_digest_sha256 || prepromotion.identity_bindings_record_digest_sha256 !== event.identity_bindings_record_digest_sha256 || prepromotion.bundle_seal_record_digest_sha256 !== event.authorization_bundle_seal_record_digest_sha256 || canonical(resolved.seal.bundle) !== canonical(event.bundle) || canonical(resolved.candidateSeal.expected_prior_logical_state) !== canonical(event.target_logical_state) || resolved.candidateSeal.file_sha256 !== event.candidate_file_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'document promotion crosses its authorized operation, bundle, state, or candidate file')
  }
  const rule = classification.journal_event_rules.find((item) => item.event_kind_code === event.event_kind_code)
  if (!rule) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event lacks a closed event rule')
  if (!rule.allowed_canonical_effects.includes(event.canonical_effect_code) || !rule.allowed_dispositions.includes(event.object_disposition_code)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal effect or object disposition is invalid for event kind')
  const policyPresence = (policy, value, label, nonzero = false) => {
    const present = value !== null
    if (policy === 'forbidden' && present) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} is forbidden`)
    if ((policy === 'required' || policy === 'required_nonzero') && !present) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} is required`)
    if (policy === 'required_zero' && (!present || Object.values(value).some((item) => item !== 0))) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} must contain exact zero values`)
    if ((policy === 'required_nonzero' || nonzero) && present && !Object.values(value).some((item) => item > 0)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} must identify a nonzero effect`)
  }
  policyPresence(rule.rows_policy, event.rows_delta, 'row delta')
  policyPresence(rule.objects_policy, event.objects_delta, 'object delta')
  const scalarPolicy = (policy, value, label) => {
    if (policy === 'forbidden' && value !== null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} is forbidden`)
    if (policy === 'required' && value === null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `${label} is required`)
  }
  scalarPolicy(rule.candidate_hash_policy, event.candidate_file_sha256, 'candidate hash')
  scalarPolicy(rule.backup_hash_policy, event.backup_inventory_sha256, 'backup hash')
  if (rule.observed_state_policy === 'required_when_error_absent_else_error_policy') {
    if (event.error_code === null && event.observed_logical_state === null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'error-free terminal observed state is required')
  } else {
    scalarPolicy(rule.observed_state_policy, event.observed_logical_state, 'observed state')
  }
  const stageMatches = rule.stage_policy === 'any_registered'
    || (rule.stage_policy === 'startup_only' && event.stage_code === 'startup')
    || (rule.stage_policy === 'custody_prepare_only' && event.stage_code === 'custody_prepare')
    || (rule.stage_policy === 'database_transaction_only' && event.stage_code === 'database_transaction')
    || (rule.stage_policy === 'independent_verification_only' && event.stage_code === 'independent_verification')
    || (rule.stage_policy === 'promotion_only' && event.stage_code === 'promotion')
    || (rule.stage_policy === 'post_promotion_only' && event.stage_code === 'post_promotion_verification')
    || (rule.stage_policy === 'completion_only' && event.stage_code === 'completion')
  if (!stageMatches && rule.stage_policy !== 'matches_error') fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal stage is invalid for event kind')
  if (event.error_code !== null) {
    const error = errorRule(classification, event.error_code)
    const effect = errorEffectRule(classification, event.error_code)
    const bundleReferences = event.bundle === null
      ? [null, null, null]
      : [event.bundle.bundle_id, event.bundle.bundle_sequence, event.bundle.bundle_digest_sha256]
    assertErrorBundleReferencePolicy(event.error_code, bundleReferences, classification)
    const errorStageMustMatchEvent = event.event_kind_code !== 'operation_completed'
    if (errorStageMustMatchEvent && event.stage_code !== error.stage || event.retryability_code !== error.retryability_code || event.recovery_class_code !== error.recovery_class_code) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal error tuple differs from registry')
    if (event.canonical_effect_code !== effect.canonical_effect_code || event.object_disposition_code !== effect.object_disposition_code || (effect.observed_state_policy_code === 'required' && event.observed_logical_state === null) || (effect.observed_state_policy_code === 'forbidden' && event.observed_logical_state !== null)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal error, effect, disposition, or observed-state presence differs from the total matrix')
  } else if (event.retryability_code !== 'never' || event.recovery_class_code !== 'none') fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'non-error journal event carries retry or recovery classification')
  if (rule.error_policy === 'required' && event.error_code === null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal failure event lacks error')
  if (rule.error_policy === 'forbidden' && event.error_code !== null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event cannot carry an error')
  if (rule.stage_policy === 'matches_error' && event.error_code !== null && event.stage_code !== errorRule(classification, event.error_code).stage) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal stage does not match error')
  if (event.result_outcome_code !== null) {
    const outcome = classification.outcome_rules.find((item) => item.outcome === event.result_outcome_code)
    if (!outcome || !outcome.allowed_canonical_effects.includes(event.canonical_effect_code) || outcome.error_required !== (event.error_code !== null)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'journal terminal outcome is inconsistent')
    if (event.error_code !== null) assertResultErrorCompatibility(event.result_outcome_code, event.error_code, classification)
  }
  if (rule.result_policy === 'forbidden' && event.result_outcome_code !== null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'nonterminal journal event carries a result')
  if (rule.result_policy === 'recovery_required_only' && event.result_outcome_code !== 'recovery_required') fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'recovery event lacks recovery result')
  if (rule.result_policy === 'required_terminal' && event.result_outcome_code === null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'terminal completion lacks result')
  if ((event.event_kind_code === 'recovery_required') !== (event.result_outcome_code === 'recovery_required')) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal terminal event and recovery-required outcome point in different directions')
  if (rule.terminal !== ['operation_completed', 'recovery_required'].includes(event.event_kind_code)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal terminal classification is inconsistent')
  if (event.event_kind_code === 'operation_started' && (event.event_sequence !== 1 || event.previous_event_record_digest_sha256 !== null || event.result_outcome_code !== null || event.error_code !== null || event.canonical_effect_code !== 'none_verified')) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'operation-start event has terminal state')
  if (bindings && runtime) {
    if (event.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256 || event.identity_bindings_record_digest_sha256 !== bindings.record_digest_sha256 || bindings.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event pins another runtime profile or identity-binding generation')
    const originRule = classification.journal_event_origin_rules.find((item) => item.event_kind_code === event.event_kind_code)
    const requiredRole = originRule?.origin_policy_code === 'exact_role'
      ? originRule.runtime_role_code
      : classification.journal_stage_origin_rules.find((item) => item.stage_code === event.stage_code)?.runtime_role_code
    if (!requiredRole) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event has no exact origin authority')
    const component = findBinding(bindings, event.component_binding_code, requiredRole, event.event_at)
    const broker = findBinding(bindings, event.recorded_by_binding_code, 'journal_broker', event.persisted_at)
    if (!component.allowed_operation_modes.includes(event.operation_mode_code) || !broker.allowed_operation_modes.includes(event.operation_mode_code)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal origin or broker is not bound for the operation mode')
    if (permitScopeRule && !permitScopeRule.allowed_origin_runtime_role_codes.includes(requiredRole)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal origin role exceeds its permit execution scope')
    const release = runtime.component_releases.find((item) => item.runtime_role_code === component.runtime_role_code)
    if (component.principal_kind_code !== 'service' || !release || event.component_executable_sha256 !== component.executable_sha256 || event.component_executable_sha256 !== release.executable_sha256 || component.binding_code === broker.binding_code) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal origin, executable, or independent broker binding is invalid')
  }
}

function assertJournalChain(first, second, classification, bindings = null, runtime = null, authorizationControls = null) {
  assertJournalEvent(first, classification, bindings, runtime, authorizationControls)
  assertJournalEvent(second, classification, bindings, runtime, authorizationControls)
  const firstRule = classification.journal_event_rules.find((item) => item.event_kind_code === first.event_kind_code)
  if (firstRule.terminal) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal terminal event has a successor')
  if (second.journal_code !== first.journal_code || second.operation_mode_code !== first.operation_mode_code || second.operation_id !== first.operation_id || second.operation_nonce !== first.operation_nonce || second.runtime_profile_record_digest_sha256 !== first.runtime_profile_record_digest_sha256 || second.identity_bindings_record_digest_sha256 !== first.identity_bindings_record_digest_sha256 || second.authorization_permit_record_digest_sha256 !== first.authorization_permit_record_digest_sha256 || second.authorization_bundle_seal_record_digest_sha256 !== first.authorization_bundle_seal_record_digest_sha256 || canonical(second.bundle) !== canonical(first.bundle) || canonical(second.target_logical_state) !== canonical(first.target_logical_state) || second.event_sequence !== first.event_sequence + 1 || second.previous_event_record_digest_sha256 !== first.record_digest_sha256 || second.event_at <= first.event_at || second.persisted_at <= first.persisted_at) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal chain has a gap, fork, changed mode/authorization/context, or backdated semantic/protected-persistence successor')
}

function journalBundleKind(event, permit, controls) {
  if (permit?.permit_kind_code === 'post_promotion_completion') return permit.target_bundle_kind_code
  if (permit?.permit_kind_code === 'bootstrap' || permit?.permit_kind_code === 'recovery') return 'principal_bootstrap'
  if (event.operation_mode_code === 'document_import') return 'single_document'
  if (event.bundle === null) return 'null'
  const kinds = [...(controls?.bundleReferences?.entries() ?? [])]
    .filter(([, bundle]) => canonical(bundle) === canonical(event.bundle))
    .map(([key]) => key.slice(0, key.indexOf('|')))
  unique(kinds, 'semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal bundle kind')
  if (kinds.length !== 1 || !['principal_bootstrap', 'single_document'].includes(kinds[0])) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal bundle kind does not resolve exactly once')
  return kinds[0]
}

function assertJournalTerminalCounts(terminal, countPolicy) {
  const rowsKnown = terminal.rows_delta !== null
  const objectsKnown = terminal.objects_delta !== null
  const allKnown = rowsKnown && objectsKnown
  const rowsZero = rowsKnown && Object.values(terminal.rows_delta).every((value) => value === 0)
  const objectsZero = objectsKnown && Object.values(terminal.objects_delta).every((value) => value === 0)
  if (countPolicy === 'all_zero' && !(rowsZero && objectsZero)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal terminal must prove exact zero effects')
  if (countPolicy === 'known' && !allKnown) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal terminal must report known effects')
  if (countPolicy === 'rows_zero_objects_orphan_only' && (!allKnown || !rowsZero || terminal.objects_delta.prepared !== 0 || terminal.objects_delta.reused !== 0)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal rejection terminal reports prohibited durable effects')
  if (countPolicy === 'bootstrap_exact' && (!allKnown || terminal.rows_delta.atlas_evidence_bundle_receipts !== 1 || Object.entries(terminal.rows_delta).some(([key, value]) => key !== 'atlas_evidence_bundle_receipts' && value !== 0) || !objectsZero)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'bootstrap journal terminal differs from the exact pilot effect')
  if (countPolicy === 'document_exact' && (!allKnown || terminal.rows_delta.atlas_evidence_bundle_receipts !== 1 || terminal.rows_delta.atlas_retrieval_locations !== 1 || terminal.rows_delta.atlas_artifacts !== 1 || terminal.rows_delta.atlas_retrieval_events !== 1 || terminal.rows_delta.atlas_retrieval_redirects !== 0 || terminal.rows_delta.atlas_artifact_custody_events !== 1 || terminal.rows_delta.atlas_processing_runs !== 0 || terminal.rows_delta.atlas_processing_outputs !== 0 || terminal.rows_delta.atlas_unverified_candidate_occurrences !== 0 || terminal.objects_delta.prepared !== 1 || terminal.objects_delta.reused !== 0 || terminal.objects_delta.orphaned !== 0)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'document journal terminal differs from the exact pilot effect')
  if (countPolicy === 'unknown_allowed' && ((rowsKnown && !objectsKnown) || (!rowsKnown && objectsKnown))) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'ambiguous journal terminal has a partial effect-count projection')
}

function journalHistoryRule(events, classification, controls) {
  const terminal = events.at(-1)
  const permit = terminal.authorization_permit_record_digest_sha256 === null ? null : controls?.permits?.get(terminal.authorization_permit_record_digest_sha256)
  const permitKind = permit?.permit_kind_code ?? 'none'
  const rules = classification.journal_history_rules.filter((rule) => rule.operation_mode_code === terminal.operation_mode_code && rule.result_outcome_code === terminal.result_outcome_code && rule.canonical_effect_code === terminal.canonical_effect_code && rule.permit_kind_code === permitKind && rule.terminal_error_code === terminal.error_code)
  if (rules.length !== 1) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', `journal history matches ${rules.length} closed history rules`)
  return { rule: rules[0], permit }
}

function assertJournalMilestoneContinuity(events, controls) {
  const byKind = new Map(events.map((event) => [event.event_kind_code, event]))
  const candidateEvents = ['candidate_committed', 'candidate_sealed', 'promotion_started', 'promotion_observed'].map((kind) => byKind.get(kind)).filter(Boolean)
  if (candidateEvents.length > 0) {
    const hashes = candidateEvents.map((event) => event.candidate_file_sha256)
    if (hashes.some((hash) => hash === null) || new Set(hashes).size !== 1) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal candidate milestones do not preserve one candidate-file hash')
  }
  const promotionEvents = ['promotion_started', 'promotion_observed'].map((kind) => byKind.get(kind)).filter(Boolean)
  if (promotionEvents.length > 0 && (promotionEvents.some((event) => event.backup_inventory_sha256 === null) || new Set(promotionEvents.map((event) => event.backup_inventory_sha256)).size !== 1)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal promotion milestones do not preserve one prior-backup inventory')
  const sealed = byKind.get('candidate_sealed')
  if (sealed) {
    const seals = [...(controls?.candidateSeals?.values() ?? [])].filter((candidate) => candidate.operation_id === sealed.operation_id && candidate.operation_nonce === sealed.operation_nonce && candidate.file_sha256 === sealed.candidate_file_sha256)
    if (seals.length !== 1) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'candidate-sealed milestone does not resolve one exact candidate-file seal')
    const candidateSeal = seals[0]
    assertDigest(candidateSeal)
    if (candidateSeal.operation_id !== sealed.operation_id || candidateSeal.operation_nonce !== sealed.operation_nonce || candidateSeal.produced_at > sealed.event_at || canonical(candidateSeal.candidate_logical_state) !== canonical(sealed.observed_logical_state)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'candidate-sealed milestone crosses its exact seal, operation, nonce, time, or state')
    const observed = byKind.get('promotion_observed')?.observed_logical_state ?? events.at(-1).observed_logical_state
    if (observed === null || canonical(sealed.observed_logical_state) !== canonical(observed)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'candidate-sealed state differs from the promotion/terminal observed state')
  }
}

function assertStageFailureTerminalization(events) {
  for (let index = 0; index < events.length; index += 1) {
    if (events[index].event_kind_code !== 'stage_failed') continue
    const failure = events[index]
    const successor = events[index + 1]
    const expectedTerminal = successor && (successor.event_kind_code === 'operation_completed' && successor.result_outcome_code === 'rejected'
      || successor.event_kind_code === 'recovery_required' && successor.result_outcome_code === 'recovery_required')
    const sameContext = expectedTerminal
      && successor.error_code === failure.error_code
      && successor.canonical_effect_code === failure.canonical_effect_code
      && successor.object_disposition_code === failure.object_disposition_code
      && successor.retryability_code === failure.retryability_code
      && successor.recovery_class_code === failure.recovery_class_code
      && canonical(successor.rows_delta) === canonical(failure.rows_delta)
      && canonical(successor.objects_delta) === canonical(failure.objects_delta)
      && successor.candidate_file_sha256 === failure.candidate_file_sha256
      && successor.backup_inventory_sha256 === failure.backup_inventory_sha256
      && canonical(successor.observed_logical_state) === canonical(failure.observed_logical_state)
    if (!sameContext) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'stage failure is not immediately terminalized with the same complete error/effect context')
  }
}

function assertJournalHistory(events, classification, bindings = null, runtime = null, authorizationControls = null) {
  if (!Array.isArray(events) || events.length === 0 || events[0].event_kind_code !== 'operation_started' || events[0].event_sequence !== 1 || events[0].previous_event_record_digest_sha256 !== null) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal history lacks its unique operation-start root')
  unique(events.map((event) => event.record_digest_sha256), 'semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal event digest')
  for (let index = 0; index < events.length; index += 1) {
    assertJournalEvent(events[index], classification, bindings, runtime, authorizationControls)
    if (index > 0) assertJournalChain(events[index - 1], events[index], classification, bindings, runtime, authorizationControls)
  }
  assertStageFailureTerminalization(events)
  const terminal = events.at(-1)
  if (!['operation_completed', 'recovery_required'].includes(terminal.event_kind_code)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal history lacks a terminal event')
  if ((terminal.event_kind_code === 'recovery_required') !== (terminal.result_outcome_code === 'recovery_required')) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal terminal event direction differs from its result outcome')
  const { rule, permit } = journalHistoryRule(events, classification, authorizationControls)
  const stageFailures = events.filter((event) => event.event_kind_code === 'stage_failed')
  if (rule.stage_failure_milestone_policy_code === 'forbidden' && stageFailures.length !== 0) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal history rule forbids a stage-failure milestone')
  if (rule.stage_failure_milestone_policy_code === 'optional_penultimate_same_terminal_context' && (stageFailures.length > 1 || (stageFailures.length === 1 && events.at(-2) !== stageFailures[0]))) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal history permits at most one penultimate stage-failure milestone')
  const baseEvents = stageFailures.length === 1 ? events.filter((event) => event !== stageFailures[0]) : events
  const milestones = baseEvents.map((event) => ({ event_kind_code: event.event_kind_code, stage_code: event.stage_code }))
  if (canonical(milestones) !== canonical(rule.required_ordered_milestones)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal history differs from its exact ordered milestone contract')
  if (events.some((event) => rule.forbidden_event_kind_codes.includes(event.event_kind_code))) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal history contains an explicitly forbidden milestone')
  const bundleKind = journalBundleKind(terminal, permit, authorizationControls)
  const resultRules = classification.result_rules.filter((resultRule) => resultRule.outcome === terminal.result_outcome_code && resultRule.allowed_operation_modes.includes(terminal.operation_mode_code) && resultRule.allowed_bundle_kinds.includes(bundleKind))
  if (resultRules.length !== 1 || !resultRules[0].allowed_canonical_effects.includes(terminal.canonical_effect_code) || resultRules[0].error_required !== (terminal.error_code !== null) || rule.terminal_count_policy_code !== 'match_result_rule') fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal terminal differs from its exact importer-result rule')
  assertJournalTerminalCounts(terminal, resultRules[0].count_policy)
  if ((rule.terminal_backup_policy_code === 'required' && terminal.backup_inventory_sha256 === null) || (rule.terminal_backup_policy_code === 'forbidden' && terminal.backup_inventory_sha256 !== null)) fail('semantic', 'RECOVERY_STATE_AMBIGUOUS', 'journal terminal backup evidence differs from its history rule')
  assertJournalMilestoneContinuity(events, authorizationControls)
  return { rule, permit, terminal, resultRule: resultRules[0], bundleKind }
}

function assertJournalResultAgreement(events, result, classification, bindings, runtime, controls) {
  const { terminal, bundleKind } = assertJournalHistory(events, classification, bindings, runtime, controls)
  assertImporterResult(result, classification, controls)
  const resultBundle = result.bundle_id === null ? null : { bundle_id: result.bundle_id, bundle_sequence: result.bundle_sequence, bundle_digest_sha256: result.bundle_digest_sha256 }
  const terminalError = terminal.error_code === null ? null : errorRule(classification, terminal.error_code)
  if (result.outcome !== terminal.result_outcome_code || result.operation_mode_code !== terminal.operation_mode_code || result.operation_id !== terminal.operation_id || result.bundle_kind_code !== (bundleKind === 'null' ? null : bundleKind) || canonical(resultBundle) !== canonical(terminal.bundle) || result.canonical_effect_code !== terminal.canonical_effect_code || result.error?.code !== terminalError?.code || canonical(result.rows_inserted) !== canonical(terminal.rows_delta) || canonical(result.objects) !== canonical(terminal.objects_delta)) fail('semantic', 'INTERNAL_CONTRACT_VIOLATION', 'importer result differs from its exact terminal journal history')
}

function assertClassificationRegistry(classification) {
  const exact = [
    'format', 'format_version', 'outcomes', 'canonical_effects', 'stages',
    'retryability_classes', 'recovery_classes', 'journal_event_kinds',
    'operation_modes', 'runtime_role_binding_rules', 'logical_handle_slot_rules',
    'custody_capability_rules', 'custody_capability_policy', 'custody_clearance_revalidation_policy', 'pilot_custody_purpose_rules',
    'custody_capability_transition_rules',
    'permit_transition_rules', 'permit_claim_policy', 'bootstrap_permit_policy', 'permit_scope_execution_rules', 'recovery_permit_policy', 'bootstrap_distinct_human_roles', 'post_promotion_completion_permit_policy', 'post_promotion_source_error_rules', 'clearance_context_binding_policy', 'clearance_decision_rules',
    'clearance_transition_rules', 'custody_message_rules',
    'journal_stage_origin_rules', 'journal_event_origin_rules', 'journal_authorization_rules', 'journal_event_rules', 'journal_history_rules',
    'result_rules', 'recovered_result_authorization_rules', 'outcome_rules', 'result_error_rules', 'error_rules', 'error_effect_rules', 'error_bundle_reference_rules',
    'record_digest_sha256',
  ]
  if (canonical(Object.keys(classification).toSorted()) !== canonical(exact.toSorted())) fail('classification', 'REGISTRY_INVALID', 'classification registry has unknown or missing fields')
  if (classification.format !== 'jedi-atlas-d90-classifications' || classification.format_version !== '1.0.0') fail('classification', 'REGISTRY_INVALID', 'classification registry identity is invalid')
  for (const [key, values] of Object.entries({ outcomes: classification.outcomes, canonical_effects: classification.canonical_effects, stages: classification.stages, retryability_classes: classification.retryability_classes, recovery_classes: classification.recovery_classes, journal_event_kinds: classification.journal_event_kinds, operation_modes: classification.operation_modes })) {
    if (!Array.isArray(values) || values.length === 0 || values.some((value) => typeof value !== 'string' || !/^[a-z][a-z0-9_]*$/u.test(value))) fail('classification', 'REGISTRY_INVALID', `${key} is not a closed stable-code list`)
    unique(values, 'classification', 'REGISTRY_INVALID', key)
  }
  assertExactOrder(classification.operation_modes, ['bootstrap', 'document_import', 'dry_run', 'no_op_verification', 'recovery'], 'classification', 'REGISTRY_INVALID', 'operation mode')
  assertExactOrder(classification.runtime_role_binding_rules.map((rule) => rule.runtime_role_code), exactRuntimeRoles, 'classification', 'REGISTRY_INVALID', 'runtime role binding rule')
  for (const rule of classification.runtime_role_binding_rules) {
    assertExactKeys(rule, ['runtime_role_code', 'principal_kind_code', 'ipc_endpoint_code', 'allowed_operation_modes'], 'classification', 'REGISTRY_INVALID', 'runtime role binding rule')
    if (!['human', 'service'].includes(rule.principal_kind_code) || humanRoles.has(rule.runtime_role_code) !== (rule.principal_kind_code === 'human') || (rule.principal_kind_code === 'human') !== (rule.ipc_endpoint_code === null) || !Array.isArray(rule.allowed_operation_modes) || rule.allowed_operation_modes.length === 0 || rule.allowed_operation_modes.some((mode) => !classification.operation_modes.includes(mode))) fail('classification', 'REGISTRY_INVALID', `invalid role/endpoint/mode rule for ${rule.runtime_role_code}`)
    unique(rule.allowed_operation_modes, 'classification', 'REGISTRY_INVALID', `${rule.runtime_role_code} operation mode`)
  }
  if (canonical(classification.runtime_role_binding_rules) !== canonical(expectedRuntimeRoleBindingRules)) fail('classification', 'REGISTRY_INVALID', 'runtime role kind, endpoint, and operation-mode matrix differs from the frozen least-privilege matrix')
  const expectedHandles = [
    { slot_code: 'backup_adapter', recipients: [{ runtime_role_code: 'bundle_importer', access_code: 'fixed_function_client' }] },
    { slot_code: 'candidate_database', recipients: [{ runtime_role_code: 'cloner_promoter', access_code: 'create_and_transfer' }, { runtime_role_code: 'database_writer', access_code: 'write_fixed_function' }, { runtime_role_code: 'independent_verifier', access_code: 'read_only' }] },
    { slot_code: 'canonical_query', recipients: [{ runtime_role_code: 'bundle_importer', access_code: 'read_only' }, { runtime_role_code: 'independent_verifier', access_code: 'read_only' }, { runtime_role_code: 'custody_adapter', access_code: 'read_only' }] },
    { slot_code: 'clearance_register', recipients: [{ runtime_role_code: 'bundle_importer', access_code: 'read_only' }, { runtime_role_code: 'custody_adapter', access_code: 'read_only' }, { runtime_role_code: 'independent_verifier', access_code: 'read_only' }, { runtime_role_code: 'trusted_launcher', access_code: 'read_only' }, { runtime_role_code: 'cloner_promoter', access_code: 'read_only' }, { runtime_role_code: 'clearance_broker', access_code: 'write_fixed_function' }] },
    { slot_code: 'custody_adapter', recipients: [{ runtime_role_code: 'bundle_importer', access_code: 'fixed_function_client' }] },
    { slot_code: 'custody_capability_store', recipients: [{ runtime_role_code: 'custody_adapter', access_code: 'write_fixed_function' }, { runtime_role_code: 'independent_verifier', access_code: 'read_only' }] },
    { slot_code: 'handoff_registry', recipients: [{ runtime_role_code: 'bundle_importer', access_code: 'read_only' }, { runtime_role_code: 'custody_adapter', access_code: 'read_only' }, { runtime_role_code: 'independent_verifier', access_code: 'read_only' }] },
    { slot_code: 'operation_journal', recipients: [{ runtime_role_code: 'journal_broker', access_code: 'append_intended' }] },
    { slot_code: 'permit_control_store', recipients: [{ runtime_role_code: 'trusted_launcher', access_code: 'write_fixed_function' }, { runtime_role_code: 'bundle_importer', access_code: 'read_only' }, { runtime_role_code: 'independent_verifier', access_code: 'read_only' }] },
    { slot_code: 'recovery_database', recipients: [{ runtime_role_code: 'database_writer', access_code: 'write_fixed_function' }, { runtime_role_code: 'independent_verifier', access_code: 'read_only' }] },
    { slot_code: 'reviewed_root', recipients: [{ runtime_role_code: 'bundle_importer', access_code: 'read_only' }] },
    { slot_code: 'staging_root', recipients: [{ runtime_role_code: 'custody_adapter', access_code: 'read_only' }] },
  ]
  if (canonical(classification.logical_handle_slot_rules) !== canonical(expectedHandles)) fail('classification', 'REGISTRY_INVALID', 'logical handle recipient matrix differs from the frozen least-privilege matrix')
  for (const slot of classification.logical_handle_slot_rules) unique(slot.recipients.map((item) => item.runtime_role_code), 'classification', 'REGISTRY_INVALID', `${slot.slot_code} recipient role`)
  const expectedCapabilityKinds = ['source_handle', 'preparation', 'sealed_custody_access']
  assertExactOrder(classification.custody_capability_rules.map((rule) => rule.capability_kind_code), expectedCapabilityKinds, 'classification', 'REGISTRY_INVALID', 'custody capability rule')
  for (const rule of classification.custody_capability_rules) {
    assertExactKeys(rule, ['capability_kind_code', 'payload_field_code', 'issued_by_runtime_role_code', 'requester_runtime_role_code', 'adapter_runtime_role_code', 'issuance_operation_code', 'issuance_outcome_code', 'allowed_consumer_operation_codes', 'replay_policy_code', 'lifetime_ms_max'], 'classification', 'REGISTRY_INVALID', 'custody capability rule')
    if (rule.requester_runtime_role_code !== 'bundle_importer' || rule.adapter_runtime_role_code !== 'custody_adapter' || !Number.isSafeInteger(rule.lifetime_ms_max) || rule.lifetime_ms_max < 1 || !Array.isArray(rule.allowed_consumer_operation_codes) || rule.allowed_consumer_operation_codes.length === 0) fail('classification', 'REGISTRY_INVALID', `invalid custody capability rule ${rule.capability_kind_code}`)
    unique(rule.allowed_consumer_operation_codes, 'classification', 'REGISTRY_INVALID', `${rule.capability_kind_code} consumer operation`)
  }
  if (canonical(classification.custody_capability_rules) !== canonical(expectedCustodyCapabilityRules)) fail('classification', 'REGISTRY_INVALID', 'custody capability issuer, peer, operation, replay, or lifetime matrix differs from the frozen policy')
  assertExactKeys(classification.custody_capability_policy, ['binding_policy_code', 'transport_code', 'persistence_code', 'static_credentials_code', 'capability_alone_authorizes_code'], 'classification', 'REGISTRY_INVALID', 'custody capability policy')
  if (canonical(classification.custody_capability_policy) !== canonical({ binding_policy_code: 'exact_operation_nonce_runtime_requester_adapter_artifact', transport_code: 'authenticated_custody_ipc_only', persistence_code: 'protected_short_lived_state_until_expiry_or_reconciliation', static_credentials_code: 'forbidden_everywhere', capability_alone_authorizes_code: 'never' })) fail('classification', 'REGISTRY_INVALID', 'custody capability policy differs from the frozen policy')
  if (canonical(classification.custody_clearance_revalidation_policy) !== canonical({ required_decision_code: 'restricted_store_only', recheck_points: ['sealed_issuance', 'open_request_claim', 'open_response', 'pre_promotion'] })) fail('classification', 'REGISTRY_INVALID', 'custody clearance revalidation policy differs from the frozen policy')
  const capabilityTransitionKeys = ['capability_kind_code', 'from_state_code', 'to_state_code', 'transition_code', 'consumer_operation_code', 'trigger_code', 'response_policy_code', 'reason_code']
  if (!Array.isArray(classification.custody_capability_transition_rules) || classification.custody_capability_transition_rules.length !== 8) fail('classification', 'REGISTRY_INVALID', 'custody capability transition matrix is incomplete')
  unique(classification.custody_capability_transition_rules.map((rule) => `${rule.capability_kind_code}|${rule.from_state_code}|${rule.consumer_operation_code}|${rule.response_policy_code}`), 'classification', 'REGISTRY_INVALID', 'custody capability transition edge')
  for (const rule of classification.custody_capability_transition_rules) {
    assertExactKeys(rule, capabilityTransitionKeys, 'classification', 'REGISTRY_INVALID', 'custody capability transition rule')
    if (!['source_handle', 'preparation', 'sealed_custody_access'].includes(rule.capability_kind_code) || !['ready', 'verified'].includes(rule.from_state_code) || !['verified', 'consumed', 'abandoned', 'invalidated'].includes(rule.to_state_code) || !['verification_succeeded', 'consumer_succeeded', 'temporary_abandoned', 'integrity_failure'].includes(rule.transition_code) || !['prepare', 'verify_prepared', 'publish_no_replace', 'open_custody', 'abandon_temp'].includes(rule.consumer_operation_code) || !['authenticated_request_accepted_atomic_claim', 'successful_response', 'corrupt_response'].includes(rule.trigger_code) || !['must_be_null', 'required', 'required_corrupt'].includes(rule.response_policy_code) || !['request_claimed', 'verified_response', 'successful_response', 'abandon_response', 'corrupt_response'].includes(rule.reason_code)) fail('classification', 'REGISTRY_INVALID', 'custody capability transition rule has an unknown value')
  }
  if (canonical(classification.pilot_custody_purpose_rules) !== canonical([{ operation_code: 'open_custody', processor_policy_code: 'disabled', allowed_purpose_codes: ['integrity'] }])) fail('classification', 'REGISTRY_INVALID', 'pilot custody purpose matrix is not integrity-only')
  assertExactKeys(classification.permit_claim_policy, ['minimum_remaining_lifetime_ms', 'expired_ready_projection_code', 'expired_in_progress_projection_code', 'post_expiry_transition_policy_code'], 'classification', 'REGISTRY_INVALID', 'permit claim policy')
  if (canonical(classification.permit_claim_policy) !== canonical({ minimum_remaining_lifetime_ms: 60000, expired_ready_projection_code: 'terminal_expired_unused', expired_in_progress_projection_code: 'terminal_recovery_hold', post_expiry_transition_policy_code: 'forbidden' })) fail('classification', 'REGISTRY_INVALID', 'permit claim lifetime and expiry policy differs from the frozen fail-closed policy')
  assertExactKeys(classification.bootstrap_permit_policy, ['maximum_lifetime_ms'], 'classification', 'REGISTRY_INVALID', 'bootstrap permit policy')
  if (canonical(classification.bootstrap_permit_policy) !== canonical({ maximum_lifetime_ms: 3600000 })) fail('classification', 'REGISTRY_INVALID', 'bootstrap permit maximum lifetime differs from the frozen policy')
  assertExactKeys(classification.recovery_permit_policy, ['validity_window_code', 'maximum_lifetime_ms', 'must_not_outlive_replay_certificate', 'must_not_outlive_identity_bindings', 'authority_withdrawal_window_code'], 'classification', 'REGISTRY_INVALID', 'recovery permit policy')
  if (canonical(classification.recovery_permit_policy) !== canonical({ validity_window_code: 'not_before_inclusive_to_expiry_exclusive', maximum_lifetime_ms: 900000, must_not_outlive_replay_certificate: true, must_not_outlive_identity_bindings: true, authority_withdrawal_window_code: 'issuance_inclusive_to_expiry_exclusive' })) fail('classification', 'REGISTRY_INVALID', 'recovery permit policy differs from the frozen bounded policy')
  if (canonical(classification.bootstrap_distinct_human_roles) !== canonical(['human_submitter', 'operational_witness', 'bootstrap_authority'])) fail('classification', 'REGISTRY_INVALID', 'bootstrap human separation policy differs from the frozen role set')
  const completionPolicy = classification.post_promotion_completion_permit_policy
  assertExactKeys(completionPolicy, ['scope_code', 'maximum_lifetime_ms', 'allowed_actions', 'canonical_write_code', 'allowed_canonical_effect_code', 'required_operation_mode_code', 'required_bundle_kind_codes', 'required_source_recovery_class_code', 'allowed_source_error_codes', 'source_journal_head_policy_code', 'completion_journal_head_policy_code', 'completion_backup_inventory_required', 'distinct_human_roles'], 'classification', 'REGISTRY_INVALID', 'post-promotion completion permit policy')
  if (canonical(completionPolicy) !== canonical({ scope_code: 'noncanonical_completion_only', maximum_lifetime_ms: 900000, allowed_actions: ['complete_final_backup', 'complete_operation_journal'], canonical_write_code: 'denied', allowed_canonical_effect_code: 'none_verified', required_operation_mode_code: 'recovery', required_bundle_kind_codes: ['principal_bootstrap', 'single_document'], required_source_recovery_class_code: 'complete_post_promotion', allowed_source_error_codes: ['PROMOTION_STATE_AMBIGUOUS', 'FINAL_BACKUP_FAILED', 'JOURNAL_COMPLETION_WRITE_FAILED'], source_journal_head_policy_code: 'current_terminal_head', completion_journal_head_policy_code: 'exact_authorized_operation_completed_current_terminal', completion_backup_inventory_required: true, distinct_human_roles: ['operational_witness', 'recovery_authority', 'recovery_operator'] })) fail('classification', 'REGISTRY_INVALID', 'post-promotion completion permit policy is not narrow and fail closed')
  const expectedSourceErrors = [
    { error_code: 'PROMOTION_STATE_AMBIGUOUS', allowed_bundle_kind_codes: ['single_document'], canonical_effect_code: 'possibly_promoted', object_disposition_code: 'candidate_only', observed_state_policy_code: 'optional' },
    { error_code: 'FINAL_BACKUP_FAILED', allowed_bundle_kind_codes: ['principal_bootstrap', 'single_document'], canonical_effect_code: 'promoted_verified', object_disposition_code: 'durable_referenced', observed_state_policy_code: 'required' },
    { error_code: 'JOURNAL_COMPLETION_WRITE_FAILED', allowed_bundle_kind_codes: ['principal_bootstrap', 'single_document'], canonical_effect_code: 'promoted_verified', object_disposition_code: 'durable_referenced', observed_state_policy_code: 'required' },
  ]
  if (canonical(classification.post_promotion_source_error_rules) !== canonical(expectedSourceErrors)) fail('classification', 'REGISTRY_INVALID', 'post-promotion source error/effect/disposition matrix differs from the frozen policy')
  const expectedJournalAuthorization = [
    { operation_mode_code: 'bootstrap', authorization_policy_code: 'required_exact_permit', allowed_permit_kind_codes: ['bootstrap'] },
    { operation_mode_code: 'document_import', authorization_policy_code: 'required_exact_bundle_seal', allowed_permit_kind_codes: [] },
    { operation_mode_code: 'dry_run', authorization_policy_code: 'forbidden', allowed_permit_kind_codes: [] },
    { operation_mode_code: 'no_op_verification', authorization_policy_code: 'forbidden', allowed_permit_kind_codes: [] },
    { operation_mode_code: 'recovery', authorization_policy_code: 'required_exact_permit', allowed_permit_kind_codes: ['recovery', 'post_promotion_completion'] },
  ]
  if (canonical(classification.journal_authorization_rules) !== canonical(expectedJournalAuthorization)) fail('classification', 'REGISTRY_INVALID', 'journal operation-mode authorization matrix differs from the frozen policy')
  const scopeKeys = ['permit_kind_code', 'scope_code', 'canonical_write_code', 'allowed_canonical_effect_codes', 'allowed_journal_event_kind_codes', 'allowed_stage_codes', 'allowed_origin_runtime_role_codes', 'allowed_handle_slot_codes']
  if (!Array.isArray(classification.permit_scope_execution_rules) || classification.permit_scope_execution_rules.length !== 3) fail('classification', 'REGISTRY_INVALID', 'permit execution scopes are incomplete')
  unique(classification.permit_scope_execution_rules.map((rule) => `${rule.permit_kind_code}|${rule.scope_code}`), 'classification', 'REGISTRY_INVALID', 'permit execution scope')
  for (const rule of classification.permit_scope_execution_rules) {
    assertExactKeys(rule, scopeKeys, 'classification', 'REGISTRY_INVALID', 'permit execution scope')
    if (!['bootstrap', 'recovery', 'post_promotion_completion'].includes(rule.permit_kind_code) || !['canonical_first_acceptance_only', 'exact_bootstrap_reconstruction_only', 'noncanonical_completion_only'].includes(rule.scope_code) || !['one_atomic_promotion', 'denied'].includes(rule.canonical_write_code) || rule.allowed_canonical_effect_codes.some((code) => !classification.canonical_effects.includes(code)) || rule.allowed_journal_event_kind_codes.some((code) => !classification.journal_event_kinds.includes(code)) || rule.allowed_stage_codes.some((code) => !classification.stages.includes(code)) || rule.allowed_origin_runtime_role_codes.some((code) => !classification.runtime_role_binding_rules.some((binding) => binding.runtime_role_code === code && binding.principal_kind_code === 'service')) || rule.allowed_handle_slot_codes.some((code) => !classification.logical_handle_slot_rules.some((slot) => slot.slot_code === code))) fail('classification', 'REGISTRY_INVALID', 'permit execution scope contains an unknown or unsafe value')
    for (const key of ['allowed_canonical_effect_codes', 'allowed_journal_event_kind_codes', 'allowed_stage_codes', 'allowed_origin_runtime_role_codes', 'allowed_handle_slot_codes']) unique(rule[key], 'classification', 'REGISTRY_INVALID', `${rule.scope_code}/${key}`)
    if (rule.canonical_write_code === 'denied' && rule.allowed_canonical_effect_codes.includes('promoted_verified')) fail('classification', 'REGISTRY_INVALID', 'noncanonical permit scope claims canonical promotion')
  }
  const expectedRecoveredAuthorization = [
    { bundle_kind_code: 'principal_bootstrap', permit_kind_code: 'recovery', terminal_transition_code: 'verified_effect', count_policy_code: 'known' },
    { bundle_kind_code: 'principal_bootstrap', permit_kind_code: 'post_promotion_completion', terminal_transition_code: 'no_effect_verified', count_policy_code: 'all_zero' },
    { bundle_kind_code: 'single_document', permit_kind_code: 'post_promotion_completion', terminal_transition_code: 'no_effect_verified', count_policy_code: 'all_zero' },
  ]
  if (canonical(classification.recovered_result_authorization_rules) !== canonical(expectedRecoveredAuthorization)) fail('classification', 'REGISTRY_INVALID', 'recovered-result authorization matrix differs from the frozen policy')
  assertExactKeys(classification.clearance_context_binding_policy, ['runtime_profile_policy_code', 'identity_bindings_policy_code', 'clearance_operational_profile_policy_code', 'clearance_scope_policy_code'], 'classification', 'REGISTRY_INVALID', 'clearance context binding policy')
  unique(classification.outcome_rules.map((item) => item.outcome), 'classification', 'REGISTRY_INVALID', 'outcome rule')
  if (canonical(classification.outcome_rules.map((item) => item.outcome).toSorted()) !== canonical(classification.outcomes.toSorted())) fail('classification', 'REGISTRY_INVALID', 'outcome rules are incomplete')
  for (const rule of classification.outcome_rules) {
    assertExactKeys(rule, ['outcome', 'allowed_canonical_effects', 'error_required', 'counts_may_be_unknown', 'exit_zero'], 'classification', 'REGISTRY_INVALID', `outcome rule ${rule.outcome}`)
    if (!classification.outcomes.includes(rule.outcome) || !Array.isArray(rule.allowed_canonical_effects) || rule.allowed_canonical_effects.length === 0 || rule.allowed_canonical_effects.some((code) => !classification.canonical_effects.includes(code)) || new Set(rule.allowed_canonical_effects).size !== rule.allowed_canonical_effects.length) fail('classification', 'REGISTRY_INVALID', `outcome rule ${rule.outcome} has invalid canonical effects`)
    for (const key of ['error_required', 'counts_may_be_unknown', 'exit_zero']) if (typeof rule[key] !== 'boolean') fail('classification', 'REGISTRY_INVALID', `outcome rule ${rule.outcome} has non-boolean ${key}`)
  }
  unique(classification.error_rules.map((item) => item.code), 'classification', 'REGISTRY_INVALID', 'error rule')
  for (const rule of classification.error_rules) {
    const keys = ['code', 'stage', 'retryable', 'retryability_code', 'recovery_class_code', 'safe_message']
    if (canonical(Object.keys(rule).toSorted()) !== canonical(keys.toSorted()) || !classification.stages.includes(rule.stage) || !classification.retryability_classes.includes(rule.retryability_code) || !classification.recovery_classes.includes(rule.recovery_class_code)) fail('classification', 'REGISTRY_INVALID', `invalid error rule ${rule.code}`)
    if (rule.retryable !== (rule.retryability_code === 'new_operation_same_bundle')) fail('classification', 'REGISTRY_INVALID', `retryability conflict for ${rule.code}`)
    if (!/^[ -~]{1,512}$/u.test(rule.safe_message)) fail('classification', 'REGISTRY_INVALID', `unsafe error message for ${rule.code}`)
  }
  if (!Array.isArray(classification.result_error_rules) || classification.result_error_rules.length !== 2) fail('classification', 'REGISTRY_INVALID', 'terminal result/error matrix is incomplete')
  assertExactOrder(classification.result_error_rules.map((rule) => rule.result_outcome_code), ['rejected', 'recovery_required'], 'classification', 'REGISTRY_INVALID', 'terminal result/error rule')
  const classifiedErrors = []
  for (const rule of classification.result_error_rules) {
    assertExactKeys(rule, ['result_outcome_code', 'allowed_error_codes'], 'classification', 'REGISTRY_INVALID', 'terminal result/error rule')
    if (!Array.isArray(rule.allowed_error_codes) || rule.allowed_error_codes.length === 0) fail('classification', 'REGISTRY_INVALID', `${rule.result_outcome_code} has no allowed errors`)
    unique(rule.allowed_error_codes, 'classification', 'REGISTRY_INVALID', `${rule.result_outcome_code} error`)
    for (const code of rule.allowed_error_codes) {
      if (!classification.error_rules.some((item) => item.code === code)) fail('classification', 'REGISTRY_INVALID', `${rule.result_outcome_code} names unknown error ${code}`)
      classifiedErrors.push(code)
    }
  }
  unique(classifiedErrors, 'classification', 'REGISTRY_INVALID', 'terminally classified error')
  if (canonical(classifiedErrors.toSorted()) !== canonical(classification.error_rules.map((item) => item.code).toSorted())) fail('classification', 'REGISTRY_INVALID', 'every error must belong to exactly one terminal result class')
  if (!Array.isArray(classification.error_effect_rules) || classification.error_effect_rules.length !== classification.error_rules.length) fail('classification', 'REGISTRY_INVALID', 'error/effect/disposition matrix is incomplete')
  unique(classification.error_effect_rules.map((rule) => rule.error_code), 'classification', 'REGISTRY_INVALID', 'error/effect rule')
  const dispositions = new Set(['none', 'temporary', 'durable_referenced', 'durable_orphan', 'candidate_only', 'backup_only'])
  for (const rule of classification.error_effect_rules) {
    assertExactKeys(rule, ['error_code', 'result_outcome_code', 'canonical_effect_code', 'object_disposition_code', 'observed_state_policy_code'], 'classification', 'REGISTRY_INVALID', 'error/effect rule')
    const resultClass = classification.result_error_rules.find((item) => item.allowed_error_codes.includes(rule.error_code))
    if (!resultClass || rule.result_outcome_code !== resultClass.result_outcome_code || !classification.canonical_effects.includes(rule.canonical_effect_code) || !dispositions.has(rule.object_disposition_code) || !['forbidden', 'optional', 'required'].includes(rule.observed_state_policy_code)) fail('classification', 'REGISTRY_INVALID', `invalid error/effect rule ${rule.error_code}`)
  }
  if (canonical(classification.error_effect_rules.map((rule) => rule.error_code).toSorted()) !== canonical(classification.error_rules.map((rule) => rule.code).toSorted())) fail('classification', 'REGISTRY_INVALID', 'every error lacks exactly one effect/disposition rule')
  if (!Array.isArray(classification.error_bundle_reference_rules) || classification.error_bundle_reference_rules.length !== classification.error_rules.length) fail('classification', 'REGISTRY_INVALID', 'error/bundle-reference matrix is incomplete')
  unique(classification.error_bundle_reference_rules.map((rule) => rule.error_code), 'classification', 'REGISTRY_INVALID', 'error bundle-reference rule')
  for (const rule of classification.error_bundle_reference_rules) {
    assertExactKeys(rule, ['error_code', 'bundle_reference_policy_code'], 'classification', 'REGISTRY_INVALID', 'error bundle-reference rule')
    if (!classification.error_rules.some((error) => error.code === rule.error_code) || !['forbidden', 'optional_all_or_none', 'required'].includes(rule.bundle_reference_policy_code)) fail('classification', 'REGISTRY_INVALID', 'error bundle-reference rule has an unknown error or policy')
  }
  if (canonical(classification.error_bundle_reference_rules.map((rule) => rule.error_code).toSorted()) !== canonical(classification.error_rules.map((rule) => rule.code).toSorted())) fail('classification', 'REGISTRY_INVALID', 'every error lacks exactly one bundle-reference rule')
  for (const recoveryClass of classification.recovery_classes.filter((code) => code !== 'none')) if (!classification.error_rules.some((rule) => rule.recovery_class_code === recoveryClass)) fail('classification', 'REGISTRY_INVALID', `unreachable recovery class ${recoveryClass}`)
  if (!Array.isArray(classification.journal_history_rules) || classification.journal_history_rules.length === 0) fail('classification', 'REGISTRY_INVALID', 'journal history matrix is missing')
  const historyRuleKeys = ['operation_mode_code', 'result_outcome_code', 'canonical_effect_code', 'permit_kind_code', 'terminal_error_code', 'required_ordered_milestones', 'forbidden_event_kind_codes', 'terminal_count_policy_code', 'terminal_backup_policy_code', 'stage_failure_milestone_policy_code']
  const historySelectors = []
  for (const rule of classification.journal_history_rules) {
    assertExactKeys(rule, historyRuleKeys, 'classification', 'REGISTRY_INVALID', 'journal history rule')
    if (!classification.operation_modes.includes(rule.operation_mode_code) || !classification.outcomes.includes(rule.result_outcome_code) || !classification.canonical_effects.includes(rule.canonical_effect_code) || !['none', 'bootstrap', 'recovery', 'post_promotion_completion'].includes(rule.permit_kind_code) || (rule.terminal_error_code !== null && !classification.error_rules.some((error) => error.code === rule.terminal_error_code)) || !Array.isArray(rule.required_ordered_milestones) || rule.required_ordered_milestones.length < 2 || !Array.isArray(rule.forbidden_event_kind_codes) || rule.terminal_count_policy_code !== 'match_result_rule' || !['forbidden', 'optional', 'required'].includes(rule.terminal_backup_policy_code) || !['forbidden', 'optional_penultimate_same_terminal_context'].includes(rule.stage_failure_milestone_policy_code)) fail('classification', 'REGISTRY_INVALID', 'journal history rule contains an unknown or incomplete classification')
    for (const milestone of rule.required_ordered_milestones) {
      assertExactKeys(milestone, ['event_kind_code', 'stage_code'], 'classification', 'REGISTRY_INVALID', 'journal history milestone')
      if (!classification.journal_event_kinds.includes(milestone.event_kind_code) || !classification.stages.includes(milestone.stage_code)) fail('classification', 'REGISTRY_INVALID', 'journal history milestone uses an unknown event or stage')
    }
    unique(rule.forbidden_event_kind_codes, 'classification', 'REGISTRY_INVALID', 'journal forbidden event kind')
    if (rule.forbidden_event_kind_codes.some((code) => !classification.journal_event_kinds.includes(code) || rule.required_ordered_milestones.some((milestone) => milestone.event_kind_code === code))) fail('classification', 'REGISTRY_INVALID', 'journal history rule both requires and forbids an event kind')
    if (rule.required_ordered_milestones[0].event_kind_code !== 'operation_started' || !['operation_completed', 'recovery_required'].includes(rule.required_ordered_milestones.at(-1).event_kind_code)) fail('classification', 'REGISTRY_INVALID', 'journal history milestones lack exact start and terminal boundaries')
    if ((rule.required_ordered_milestones.at(-1).event_kind_code === 'recovery_required') !== (rule.result_outcome_code === 'recovery_required')) fail('classification', 'REGISTRY_INVALID', 'journal terminal direction and outcome differ')
    if ((rule.terminal_error_code !== null) !== ['rejected', 'recovery_required'].includes(rule.result_outcome_code)) fail('classification', 'REGISTRY_INVALID', 'journal terminal error presence differs from its outcome')
    if ((rule.stage_failure_milestone_policy_code === 'optional_penultimate_same_terminal_context') !== (rule.terminal_error_code !== null)) fail('classification', 'REGISTRY_INVALID', 'journal stage-failure milestone policy differs from terminal error presence')
    if (rule.required_ordered_milestones.some((milestone) => milestone.event_kind_code === 'stage_failed')) fail('classification', 'REGISTRY_INVALID', 'base journal milestones must not inline the optional penultimate failure event')
    if (rule.terminal_error_code !== null) {
      const effect = errorEffectRule(classification, rule.terminal_error_code)
      if (effect.result_outcome_code !== rule.result_outcome_code || effect.canonical_effect_code !== rule.canonical_effect_code) fail('classification', 'REGISTRY_INVALID', 'journal terminal error differs from the total error/effect matrix')
    }
    const matchingResults = classification.result_rules.filter((resultRule) => resultRule.outcome === rule.result_outcome_code && resultRule.allowed_operation_modes.includes(rule.operation_mode_code) && resultRule.allowed_canonical_effects.includes(rule.canonical_effect_code))
    if (matchingResults.length === 0) fail('classification', 'REGISTRY_INVALID', 'journal history terminal has no compatible importer-result rule')
    historySelectors.push([rule.operation_mode_code, rule.result_outcome_code, rule.canonical_effect_code, rule.permit_kind_code, rule.terminal_error_code].map((item) => item ?? 'null').join('|'))
  }
  unique(historySelectors, 'classification', 'REGISTRY_INVALID', 'journal history selector')
  const permitRuleKeys = ['permit_kind_code', 'from_state_code', 'to_state_code', 'transition_code', 'reason_code', 'recovery_permit_required', 'recorder_runtime_role_code', 'recorder_binding_policy_code', 'persisted_by_runtime_role_code', 'persisted_by_binding_policy_code', 'occurrence_window_code', 'observed_state_policy_code']
  const permitFromStates = new Set(['ready', 'in_progress', 'recovery_required'])
  const permitToStates = new Set(['in_progress', 'spent', 'revoked', 'recovery_required'])
  const permitTransitionCodes = new Set(['operation_claimed', 'authority_withdrawal', 'verified_effect', 'state_ambiguous', 'no_effect_verified'])
  const permitReasonCodes = new Set(['operation_claimed', 'authority_withdrawal', 'canonical_receipt_verified', 'state_ambiguous', 'no_effect_verified'])
  unique(classification.permit_transition_rules.map((rule) => canonical(rule)), 'classification', 'REGISTRY_INVALID', 'permit transition rule')
  for (const rule of classification.permit_transition_rules) {
    assertExactKeys(rule, permitRuleKeys, 'classification', 'REGISTRY_INVALID', 'permit transition rule')
    if (!['bootstrap', 'recovery', 'post_promotion_completion'].includes(rule.permit_kind_code) || !permitFromStates.has(rule.from_state_code) || !permitToStates.has(rule.to_state_code) || !permitTransitionCodes.has(rule.transition_code) || !permitReasonCodes.has(rule.reason_code) || typeof rule.recovery_permit_required !== 'boolean' || !['bootstrap_authority', 'independent_verifier', 'recovery_authority', 'trusted_launcher'].includes(rule.recorder_runtime_role_code) || !['exact_runtime_role_binding', 'exact_permit_issuer_binding'].includes(rule.recorder_binding_policy_code) || rule.persisted_by_runtime_role_code !== 'trusted_launcher' || rule.persisted_by_binding_policy_code !== 'exact_runtime_role_binding' || !['not_before_inclusive_to_expiry_exclusive', 'issuance_inclusive_to_expiry_exclusive'].includes(rule.occurrence_window_code) || !['exact_expected', 'optional_last_known'].includes(rule.observed_state_policy_code) || (rule.transition_code === 'state_ambiguous') !== (rule.observed_state_policy_code === 'optional_last_known')) fail('classification', 'REGISTRY_INVALID', 'invalid permit transition rule')
  }
  const permitGraph = classification.permit_transition_rules.map((rule) => `${rule.permit_kind_code}|${rule.from_state_code}|${rule.to_state_code}|${rule.transition_code}|${rule.reason_code}|${rule.recovery_permit_required}|${rule.recorder_runtime_role_code}|${rule.recorder_binding_policy_code}|${rule.occurrence_window_code}|${rule.observed_state_policy_code}|${rule.persisted_by_runtime_role_code}|${rule.persisted_by_binding_policy_code}`).toSorted()
  const expectedPermitGraph = [
    'bootstrap|in_progress|recovery_required|state_ambiguous|state_ambiguous|false|trusted_launcher|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'bootstrap|in_progress|spent|verified_effect|canonical_receipt_verified|false|trusted_launcher|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'bootstrap|ready|in_progress|operation_claimed|operation_claimed|false|trusted_launcher|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'bootstrap|ready|revoked|authority_withdrawal|authority_withdrawal|false|bootstrap_authority|exact_permit_issuer_binding|issuance_inclusive_to_expiry_exclusive',
    'recovery|in_progress|recovery_required|state_ambiguous|state_ambiguous|false|trusted_launcher|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'recovery|in_progress|spent|verified_effect|canonical_receipt_verified|false|trusted_launcher|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'recovery|ready|in_progress|operation_claimed|operation_claimed|false|trusted_launcher|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'recovery|ready|revoked|authority_withdrawal|authority_withdrawal|false|recovery_authority|exact_permit_issuer_binding|issuance_inclusive_to_expiry_exclusive',
    'post_promotion_completion|in_progress|recovery_required|state_ambiguous|state_ambiguous|false|independent_verifier|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'post_promotion_completion|in_progress|spent|no_effect_verified|no_effect_verified|false|independent_verifier|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'post_promotion_completion|ready|in_progress|operation_claimed|operation_claimed|false|trusted_launcher|exact_runtime_role_binding|not_before_inclusive_to_expiry_exclusive',
    'post_promotion_completion|ready|revoked|authority_withdrawal|authority_withdrawal|false|recovery_authority|exact_permit_issuer_binding|issuance_inclusive_to_expiry_exclusive',
  ].map((row) => `${row}|${row.includes('|state_ambiguous|state_ambiguous|') ? 'optional_last_known' : 'exact_expected'}|trusted_launcher|exact_runtime_role_binding`).toSorted()
  if (canonical(permitGraph) !== canonical(expectedPermitGraph)) fail('classification', 'REGISTRY_INVALID', 'permit transition graph differs from the frozen complete graph')

  unique(classification.clearance_decision_rules.map((rule) => rule.decision_code), 'classification', 'REGISTRY_INVALID', 'clearance decision rule')
  for (const rule of classification.clearance_decision_rules) {
    assertExactKeys(rule, ['decision_code', 'retention_scope_code', 'redistribution_scope_code', 'derivative_use_code', 'sensitivity_code', 'git_permanence_acknowledged', 'repository_declaration_code'], 'classification', 'REGISTRY_INVALID', 'clearance decision rule')
    if (!['all_true', 'all_false'].includes(rule.repository_declaration_code) || typeof rule.git_permanence_acknowledged !== 'boolean') fail('classification', 'REGISTRY_INVALID', 'invalid clearance decision rule')
  }
  if (canonical(classification.clearance_decision_rules.map((rule) => rule.decision_code).toSorted()) !== canonical(['do_not_retain', 'repository_eligible', 'restricted_store_only'])) fail('classification', 'REGISTRY_INVALID', 'clearance decisions are not total')
  const expectedClearanceRows = [
    'do_not_retain|none|none|none|restricted|false|all_false',
    'repository_eligible|repository_history|repository|repository_allowed|repository_safe|true|all_true',
    'restricted_store_only|pilot_only|none|internal_only|restricted|false|all_false',
  ].toSorted()
  const clearanceRows = classification.clearance_decision_rules.map((rule) => `${rule.decision_code}|${rule.retention_scope_code}|${rule.redistribution_scope_code}|${rule.derivative_use_code}|${rule.sensitivity_code}|${rule.git_permanence_acknowledged}|${rule.repository_declaration_code}`).toSorted()
  if (canonical(clearanceRows) !== canonical(expectedClearanceRows)) fail('classification', 'REGISTRY_INVALID', 'clearance admission matrix differs from its frozen rows')

  unique(classification.clearance_transition_rules.map((rule) => rule.state_code), 'classification', 'REGISTRY_INVALID', 'clearance transition rule')
  for (const rule of classification.clearance_transition_rules) {
    assertExactKeys(rule, ['state_code', 'replacement_code', 'allowed_reason_codes'], 'classification', 'REGISTRY_INVALID', 'clearance transition rule')
    if (!['revoked', 'superseded'].includes(rule.state_code) || !['must_be_null', 'required_distinct_same_artifact_decision'].includes(rule.replacement_code) || !Array.isArray(rule.allowed_reason_codes) || rule.allowed_reason_codes.length === 0 || rule.allowed_reason_codes.some((code) => !['new_information', 'operator_withdrawal', 'policy_changed', 'record_corrected'].includes(code))) fail('classification', 'REGISTRY_INVALID', 'invalid clearance transition rule')
    unique(rule.allowed_reason_codes, 'classification', 'REGISTRY_INVALID', `${rule.state_code} clearance reasons`)
  }
  const clearanceTransitions = classification.clearance_transition_rules.map((rule) => `${rule.state_code}|${rule.replacement_code}|${rule.allowed_reason_codes.join(',')}`).toSorted()
  if (canonical(clearanceTransitions) !== canonical(['revoked|must_be_null|new_information,operator_withdrawal,policy_changed', 'superseded|required_distinct_same_artifact_decision|new_information,policy_changed,record_corrected'])) fail('classification', 'REGISTRY_INVALID', 'clearance transition rules are incomplete or reordered')

  unique(classification.custody_message_rules.map((rule) => rule.operation_code), 'classification', 'REGISTRY_INVALID', 'custody operation rule')
  const custodyPayloadFields = new Set(nullableCustodyPayloadKeys)
  const custodyDescriptorRoles = new Set(['staged_source', 'custody_source'])
  const custodyOutcomes = new Set(['opened', 'prepared', 'verified', 'published', 'reused_verified', 'sealed', 'available', 'abandoned', 'already_absent', 'rejected', 'retryable_failure', 'corrupt'])
  for (const rule of classification.custody_message_rules) {
    assertExactKeys(rule, ['operation_code', 'request_nonnull_fields', 'request_descriptor_roles', 'success_outcomes', 'success_nonnull_fields', 'success_descriptor_roles', 'failure_outcomes', 'failure_error_codes'], 'classification', 'REGISTRY_INVALID', 'custody operation rule')
    for (const key of ['request_nonnull_fields', 'request_descriptor_roles', 'success_outcomes', 'success_nonnull_fields', 'success_descriptor_roles', 'failure_outcomes']) {
      if (!Array.isArray(rule[key])) fail('classification', 'REGISTRY_INVALID', `custody rule ${rule.operation_code} has non-array ${key}`)
      unique(rule[key], 'classification', 'REGISTRY_INVALID', `${rule.operation_code}/${key}`)
    }
    if (rule.request_nonnull_fields.some((code) => !custodyPayloadFields.has(code)) || rule.success_nonnull_fields.some((code) => !custodyPayloadFields.has(code)) || [...rule.request_descriptor_roles, ...rule.success_descriptor_roles].some((code) => !custodyDescriptorRoles.has(code)) || [...rule.success_outcomes, ...rule.failure_outcomes].some((code) => !custodyOutcomes.has(code))) fail('classification', 'REGISTRY_INVALID', `custody rule ${rule.operation_code} uses an unknown field, descriptor, or outcome`)
    if (rule.success_outcomes.length === 0 || rule.failure_outcomes.length === 0 || rule.success_outcomes.some((code) => rule.failure_outcomes.includes(code))) fail('classification', 'REGISTRY_INVALID', `custody rule ${rule.operation_code} has incomplete outcome partition`)
    assertExactKeys(rule.failure_error_codes, rule.failure_outcomes, 'classification', 'REGISTRY_INVALID', `${rule.operation_code} failure/error map`)
    for (const [outcome, codes] of Object.entries(rule.failure_error_codes)) {
      if (!Array.isArray(codes) || codes.length === 0) fail('classification', 'REGISTRY_INVALID', `${rule.operation_code}/${outcome} lacks exact error codes`)
      unique(codes, 'classification', 'REGISTRY_INVALID', `${rule.operation_code}/${outcome} error code`)
      for (const code of codes) if (!classification.error_rules.some((error) => error.code === code)) fail('classification', 'REGISTRY_INVALID', `${rule.operation_code}/${outcome} names an unknown error`)
    }
  }
  if (canonical(classification.custody_message_rules.map((rule) => rule.operation_code).toSorted()) !== canonical(['abandon_temp', 'open_custody', 'open_staged', 'prepare', 'publish_no_replace', 'seal_custody_access', 'verify_prepared'])) fail('classification', 'REGISTRY_INVALID', 'custody operation rules are incomplete')

  if (!Array.isArray(classification.journal_stage_origin_rules) || classification.journal_stage_origin_rules.length !== classification.stages.length) fail('classification', 'REGISTRY_INVALID', 'journal stage-origin matrix is incomplete')
  assertExactOrder(classification.journal_stage_origin_rules.map((rule) => rule.stage_code), classification.stages, 'classification', 'REGISTRY_INVALID', 'journal stage-origin rule')
  for (const rule of classification.journal_stage_origin_rules) {
    assertExactKeys(rule, ['stage_code', 'runtime_role_code'], 'classification', 'REGISTRY_INVALID', 'journal stage-origin rule')
    const role = classification.runtime_role_binding_rules.find((item) => item.runtime_role_code === rule.runtime_role_code)
    if (!role || role.principal_kind_code !== 'service') fail('classification', 'REGISTRY_INVALID', `journal stage ${rule.stage_code} lacks a service origin`)
  }
  if (!Array.isArray(classification.journal_event_origin_rules) || classification.journal_event_origin_rules.length !== classification.journal_event_kinds.length) fail('classification', 'REGISTRY_INVALID', 'journal event-origin matrix is incomplete')
  assertExactOrder(classification.journal_event_origin_rules.map((rule) => rule.event_kind_code), classification.journal_event_kinds, 'classification', 'REGISTRY_INVALID', 'journal event-origin rule')
  for (const rule of classification.journal_event_origin_rules) {
    assertExactKeys(rule, ['event_kind_code', 'origin_policy_code', 'runtime_role_code'], 'classification', 'REGISTRY_INVALID', 'journal event-origin rule')
    if (!['exact_role', 'stage_role'].includes(rule.origin_policy_code) || (rule.origin_policy_code === 'stage_role') !== (rule.runtime_role_code === null)) fail('classification', 'REGISTRY_INVALID', `journal event ${rule.event_kind_code} has an invalid origin policy`)
    if (rule.runtime_role_code !== null && classification.runtime_role_binding_rules.find((item) => item.runtime_role_code === rule.runtime_role_code)?.principal_kind_code !== 'service') fail('classification', 'REGISTRY_INVALID', `journal event ${rule.event_kind_code} names a non-service origin`)
  }

  unique(classification.journal_event_rules.map((rule) => rule.event_kind_code), 'classification', 'REGISTRY_INVALID', 'journal event rule')
  if (canonical(classification.journal_event_rules.map((rule) => rule.event_kind_code).toSorted()) !== canonical(classification.journal_event_kinds.toSorted())) fail('classification', 'REGISTRY_INVALID', 'journal event rules are incomplete')
  const journalPolicyCodes = {
    stage_policy: new Set(['startup_only', 'any_registered', 'matches_error', 'custody_prepare_only', 'database_transaction_only', 'independent_verification_only', 'promotion_only', 'post_promotion_only', 'completion_only']),
    error_policy: new Set(['forbidden', 'required', 'matches_result']),
    result_policy: new Set(['forbidden', 'recovery_required_only', 'required_terminal']),
    rows_policy: new Set(['forbidden', 'optional', 'required', 'required_zero', 'required_nonzero']),
    objects_policy: new Set(['forbidden', 'optional', 'required', 'required_zero', 'required_nonzero']),
    candidate_hash_policy: new Set(['forbidden', 'optional', 'required']),
    backup_hash_policy: new Set(['forbidden', 'optional', 'required']),
    observed_state_policy: new Set(['forbidden', 'optional', 'required', 'required_when_error_absent_else_error_policy']),
  }
  const journalDispositions = new Set(['none', 'temporary', 'durable_referenced', 'durable_orphan', 'candidate_only', 'backup_only'])
  for (const rule of classification.journal_event_rules) {
    assertExactKeys(rule, ['event_kind_code', 'stage_policy', 'error_policy', 'result_policy', 'allowed_canonical_effects', 'allowed_dispositions', 'rows_policy', 'objects_policy', 'candidate_hash_policy', 'backup_hash_policy', 'observed_state_policy', 'terminal'], 'classification', 'REGISTRY_INVALID', 'journal event rule')
    if (typeof rule.terminal !== 'boolean' || rule.allowed_canonical_effects.some((code) => !classification.canonical_effects.includes(code)) || rule.allowed_dispositions.some((code) => !journalDispositions.has(code)) || Object.entries(journalPolicyCodes).some(([key, values]) => !values.has(rule[key]))) fail('classification', 'REGISTRY_INVALID', `invalid journal event rule ${rule.event_kind_code}`)
    unique(rule.allowed_canonical_effects, 'classification', 'REGISTRY_INVALID', `${rule.event_kind_code} canonical effect`)
    unique(rule.allowed_dispositions, 'classification', 'REGISTRY_INVALID', `${rule.event_kind_code} disposition`)
    if (rule.terminal !== ['operation_completed', 'recovery_required'].includes(rule.event_kind_code)) fail('classification', 'REGISTRY_INVALID', `journal terminal marker is wrong for ${rule.event_kind_code}`)
    if ((rule.observed_state_policy === 'required_when_error_absent_else_error_policy') !== (rule.event_kind_code === 'operation_completed')) fail('classification', 'REGISTRY_INVALID', 'conditional terminal observed-state policy is assigned to the wrong event kind')
  }

  const resultPolicyCodes = {
    operation_mode: new Set(['dry_run', 'bootstrap', 'document_import', 'no_op_verification', 'recovery']),
    bundle_kind: new Set(['principal_bootstrap', 'single_document', 'null']),
    bundle_reference_policy: new Set(['required_all', 'all_or_none']),
    count_policy: new Set(['all_zero', 'known', 'bootstrap_exact', 'document_exact', 'rows_zero_objects_orphan_only', 'unknown_allowed']),
    check_policy: new Set(['all_passed', 'ambiguity_visible', 'plan_passed', 'recovery_verified', 'failed_or_early_all_not_run']),
  }
  for (const rule of classification.result_rules) {
    assertExactKeys(rule, ['outcome', 'allowed_operation_modes', 'allowed_bundle_kinds', 'bundle_reference_policy', 'count_policy', 'check_policy', 'allowed_canonical_effects', 'error_required', 'exit_zero'], 'classification', 'REGISTRY_INVALID', 'result rule')
    if (!classification.outcomes.includes(rule.outcome) || typeof rule.error_required !== 'boolean' || typeof rule.exit_zero !== 'boolean' || !Array.isArray(rule.allowed_operation_modes) || rule.allowed_operation_modes.length === 0 || rule.allowed_operation_modes.some((code) => !resultPolicyCodes.operation_mode.has(code)) || !Array.isArray(rule.allowed_bundle_kinds) || rule.allowed_bundle_kinds.length === 0 || rule.allowed_bundle_kinds.some((code) => !resultPolicyCodes.bundle_kind.has(code)) || !resultPolicyCodes.bundle_reference_policy.has(rule.bundle_reference_policy) || !resultPolicyCodes.count_policy.has(rule.count_policy) || !resultPolicyCodes.check_policy.has(rule.check_policy) || rule.allowed_canonical_effects.some((code) => !classification.canonical_effects.includes(code))) fail('classification', 'REGISTRY_INVALID', 'invalid result rule')
    unique(rule.allowed_operation_modes, 'classification', 'REGISTRY_INVALID', `${rule.outcome} operation mode`)
    unique(rule.allowed_bundle_kinds, 'classification', 'REGISTRY_INVALID', `${rule.outcome} bundle kind`)
    unique(rule.allowed_canonical_effects, 'classification', 'REGISTRY_INVALID', `${rule.outcome} canonical effect`)
    for (const field of ['allowed_operation_modes', 'allowed_bundle_kinds', 'allowed_canonical_effects']) if (canonical(rule[field]) !== canonical(rule[field].toSorted())) fail('classification', 'REGISTRY_INVALID', `${rule.outcome} ${field} is not in canonical code order`)
    const outcomeRule = classification.outcome_rules.find((item) => item.outcome === rule.outcome)
    if (!outcomeRule || rule.error_required !== outcomeRule.error_required || rule.exit_zero !== outcomeRule.exit_zero || rule.allowed_canonical_effects.some((code) => !outcomeRule.allowed_canonical_effects.includes(code))) fail('classification', 'REGISTRY_INVALID', `result rule conflicts with outcome rule ${rule.outcome}`)
  }
  const expandedResultKeys = classification.result_rules.flatMap((rule) => rule.allowed_operation_modes.flatMap((mode) => rule.allowed_bundle_kinds.map((kind) => `${rule.outcome}|${mode}|${kind}`)))
  unique(expandedResultKeys, 'classification', 'REGISTRY_INVALID', 'expanded result rule discriminator')
  const expectedResultKeys = [
    'planned|dry_run|principal_bootstrap',
    'planned|dry_run|single_document',
    'imported|bootstrap|principal_bootstrap',
    'imported|document_import|single_document',
    'no_op|no_op_verification|principal_bootstrap',
    'no_op|no_op_verification|single_document',
    'recovered|recovery|principal_bootstrap',
    'recovered|recovery|single_document',
    'rejected|bootstrap|principal_bootstrap',
    'rejected|document_import|single_document',
    'rejected|dry_run|principal_bootstrap',
    'rejected|dry_run|single_document',
    'rejected|no_op_verification|principal_bootstrap',
    'rejected|no_op_verification|single_document',
    'rejected|recovery|principal_bootstrap',
    'rejected|recovery|single_document',
    'rejected|bootstrap|null',
    'rejected|document_import|null',
    'rejected|dry_run|null',
    'rejected|no_op_verification|null',
    'rejected|recovery|null',
    'recovery_required|bootstrap|principal_bootstrap',
    'recovery_required|document_import|single_document',
    'recovery_required|recovery|principal_bootstrap',
    'recovery_required|recovery|single_document',
  ].toSorted()
  if (canonical(expandedResultKeys.toSorted()) !== canonical(expectedResultKeys)) fail('classification', 'REGISTRY_INVALID', 'result rules do not define the exact frozen outcome/mode/bundle matrix')
  assertDigest(classification)
  if (classification.record_digest_sha256 !== frozenClassificationDigest) fail('classification', 'REGISTRY_INVALID', 'classification semantics differ from the frozen v1 digest')
}

function assertExactKeys(value, expected, layer, code, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || canonical(Object.keys(value).toSorted()) !== canonical(expected.toSorted())) {
    fail(layer, code, `${label} has unknown or missing fields`)
  }
}

function assertCatalogSchemaBytes(catalog, schemaFile, bytes) {
  const entry = catalog.schemas.find((item) => item.schema_file === schemaFile)
  if (!entry || sha256(bytes) !== entry.raw_sha256) fail('catalog', 'CATALOG_INVALID', `schema bytes drifted for ${schemaFile}`)
}

function assertCatalog(catalog, schemaEntries, classification, fieldRegistry, digestProfiles) {
  assertExactKeys(catalog, ['format', 'format_version', 'hash_profile', 'catalog_self_digest', 'instance_policy', 'schemas', 'classifications', 'field_registry', 'digest_profiles'], 'catalog', 'CATALOG_INVALID', 'contract catalog')
  if (catalog.format !== 'jedi-atlas-d90-contract-catalog' || catalog.format_version !== '1.0.0' || catalog.hash_profile !== 'sha256-over-exact-file-bytes' || catalog.catalog_self_digest !== 'not_present_to_avoid_self_reference') fail('catalog', 'CATALOG_INVALID', 'contract catalog identity is invalid')
  assertExactKeys(catalog.instance_policy, ['repository_contents', 'real_contract_instances', 'credentials_permitted', 'operational_authorization_created'], 'catalog', 'CATALOG_INVALID', 'catalog instance policy')
  if (catalog.instance_policy.repository_contents !== 'schemas_and_synthetic_fixtures_only' || catalog.instance_policy.real_contract_instances !== 'protected_operational_storage_outside_git_and_atlas_sqlite' || catalog.instance_policy.credentials_permitted !== false || catalog.instance_policy.operational_authorization_created !== false) fail('catalog', 'CATALOG_INVALID', 'catalog claims unsupported contents, storage, credentials, or operational authorization')
  unique(catalog.schemas.map((entry) => entry.schema_file), 'catalog', 'CATALOG_INVALID', 'catalog schema file')
  unique(catalog.schemas.map((entry) => entry.schema_id), 'catalog', 'CATALOG_INVALID', 'catalog schema id')
  const actualNames = schemaEntries.map(([file]) => file).toSorted()
  if (canonical(catalog.schemas.map((entry) => entry.schema_file).toSorted()) !== canonical(actualNames)) fail('catalog', 'CATALOG_INVALID', 'catalog does not list the exact schema set')
  for (const entry of catalog.schemas) {
    const keys = entry.schema_role === 'shared_definitions'
      ? ['schema_role', 'schema_file', 'schema_id', 'raw_sha256']
      : ['schema_role', 'schema_file', 'schema_id', 'contract_format', 'contract_version', 'raw_sha256']
    assertExactKeys(entry, keys, 'catalog', 'CATALOG_INVALID', 'schema catalog entry')
    if (!['shared_definitions', 'top_level_contract', 'protected_operational_helper'].includes(entry.schema_role) || (entry.schema_role !== 'shared_definitions' && entry.contract_version !== '1.0.0')) fail('catalog', 'CATALOG_INVALID', 'invalid schema role or contract version')
    const pair = schemaEntries.find(([file]) => file === entry.schema_file)
    if (!pair || entry.schema_id !== pair[1].$id) fail('catalog', 'CATALOG_INVALID', `schema identity drifted for ${entry.schema_file}`)
    assertCatalogSchemaBytes(catalog, entry.schema_file, fs.readFileSync(path.join(contractRoot, entry.schema_file)))
  }
  for (const [key, expectedFile, expectedValue] of [
    ['classifications', 'classifications-v1.json', classification],
    ['field_registry', 'field-registry-v1.json', fieldRegistry],
    ['digest_profiles', 'digest-profiles-v1.json', digestProfiles],
  ]) {
    const entry = catalog[key]
    assertExactKeys(entry, ['file', 'format', 'format_version', 'raw_sha256'], 'catalog', 'CATALOG_INVALID', key)
    if (entry.file !== expectedFile || entry.format !== expectedValue.format || entry.format_version !== '1.0.0' || entry.raw_sha256 !== rawFileSha256(path.join(contractRoot, expectedFile))) fail('catalog', 'CATALOG_INVALID', `${key} does not pin exact bytes and identity`)
  }
}

function collectSchemaLeafPaths(schema, registry, rootSchema = schema, pointer = '', seen = new Set()) {
  const result = new Set()
  if (schema.$ref) {
    const marker = `${schema.$ref}@${pointer}`
    if (!seen.has(marker)) {
      const nextSeen = new Set(seen).add(marker)
      const nextRoot = schema.$ref.startsWith('#') ? rootSchema : registry.byId.get(schema.$ref.split('#')[0])
      for (const item of collectSchemaLeafPaths(resolveReference(schema.$ref, rootSchema, registry), registry, nextRoot, pointer, nextSeen)) result.add(item)
    }
  }
  if (schema.oneOf) for (const branch of schema.oneOf) for (const item of collectSchemaLeafPaths(branch, registry, rootSchema, pointer, seen)) result.add(item)
  if (schema.properties) {
    for (const [key, child] of Object.entries(schema.properties)) {
      const escaped = key.replaceAll('~', '~0').replaceAll('/', '~1')
      for (const item of collectSchemaLeafPaths(child, registry, rootSchema, `${pointer}/${escaped}`, seen)) result.add(item)
    }
  } else if (schema.items) {
    for (const item of collectSchemaLeafPaths(schema.items, registry, rootSchema, `${pointer}/*`, seen)) result.add(item)
  } else if (!schema.$ref && !schema.oneOf) result.add(pointer || '/')
  return result
}

function pointerPatternMatches(pattern, pointer) {
  const patternParts = pattern.split('/').slice(1)
  const pointerParts = pointer.split('/').slice(1)
  return patternParts.length <= pointerParts.length && patternParts.every((part, index) => part === '*' || part === pointerParts[index])
}

function pointerSuffixPatternMatches(pattern, pointer) {
  const patternParts = pattern.split('/').slice(1)
  const pointerParts = pointer.split('/').slice(1)
  if (patternParts.length > pointerParts.length) return false
  const offset = pointerParts.length - patternParts.length
  return patternParts.every((part, index) => part === '*' || part === pointerParts[offset + index])
}

function pointerExactPatternMatches(pattern, pointer) {
  const patternParts = pattern.split('/').slice(1)
  const pointerParts = pointer.split('/').slice(1)
  return patternParts.length === pointerParts.length
    && patternParts.every((part, index) => part === '*' || part === pointerParts[index])
}

function assertFieldMapping(mapping, fieldRegistry, label, { partial = false } = {}) {
  const mappingKeys = ['trusted_producers', 'consumers', 'storage', 'confidentiality', 'atlas_state_class', 'digest_coverage']
  const keys = Object.keys(mapping)
  if ((!partial && canonical(keys.toSorted()) !== canonical(mappingKeys.toSorted())) || (partial && (keys.length === 0 || keys.some((key) => !mappingKeys.includes(key))))) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${label} has unknown or missing mapping fields`)
  for (const key of ['trusted_producers', 'consumers']) {
    if (mapping[key] !== undefined && (!Array.isArray(mapping[key]) || mapping[key].length === 0 || mapping[key].some((value) => typeof value !== 'string' || !/^[a-z][a-z0-9_]*$/u.test(value)) || new Set(mapping[key]).size !== mapping[key].length)) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${label} has invalid ${key}`)
  }
  if (mapping.trusted_producers !== undefined && mapping.trusted_producers.length !== 1) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${label} must identify exactly one trusted producer`)
  if (mapping.storage !== undefined && (typeof mapping.storage !== 'string' || !/^[a-z][a-z0-9_]*$/u.test(mapping.storage))) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${label} has invalid storage`)
  if (mapping.confidentiality !== undefined && !fieldRegistry.controlled_values.confidentiality_codes.includes(mapping.confidentiality)) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${label} has unknown confidentiality`)
  if (mapping.atlas_state_class !== undefined && !fieldRegistry.controlled_values.atlas_state_classes.includes(mapping.atlas_state_class)) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${label} has unknown Atlas state class`)
  if (mapping.digest_coverage !== undefined && !fieldRegistry.controlled_values.digest_coverage_codes.includes(mapping.digest_coverage)) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${label} has unknown digest coverage`)
}

function fieldRegistrySemanticProjection(fieldRegistry, registry) {
  const rows = []
  for (const entry of fieldRegistry.schemas) {
    const schema = registry.byFile.get(entry.schema_file)
    const variants = Object.hasOwn(entry, 'variants') ? entry.variants : [{ variant_code: 'whole_contract', selector: {}, default: entry.default, overrides: entry.overrides }]
    const branches = resolvedTopBranches(schema, registry)
    for (const variant of variants) {
      const matched = schema.oneOf ? branches.filter((branch) => selectorMatchesBranch(variant.selector, branch)) : [schema]
      const leaves = [...new Set(matched.flatMap((branch) => [...collectSchemaLeafPaths(branch, registry, schema)]))]
      for (const leaf of leaves) {
        const override = variant.overrides.find((item) => pointerPatternMatches(item.json_pointer_pattern, leaf))
        const mapping = { ...variant.default, ...(override ?? {}) }
        delete mapping.json_pointer_pattern
        rows.push({
          schema_file: entry.schema_file,
          variant_code: variant.variant_code,
          json_pointer: leaf,
          trusted_producers: [...mapping.trusted_producers].toSorted(),
          consumers: [...mapping.consumers].toSorted(),
          storage: mapping.storage,
          confidentiality: mapping.confidentiality,
          atlas_state_class: mapping.atlas_state_class,
          digest_coverage: mapping.digest_coverage,
        })
      }
    }
  }
  return rows.toSorted((left, right) => {
    const leftKey = `${left.schema_file}\u0000${left.variant_code}\u0000${left.json_pointer}`
    const rightKey = `${right.schema_file}\u0000${right.variant_code}\u0000${right.json_pointer}`
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
  })
}

function resolvedTopBranches(schema, registry) {
  if (!schema.oneOf) return [schema]
  return schema.oneOf.map((branch) => branch.$ref ? resolveReference(branch.$ref, schema, registry) : branch)
}

function selectorMatchesBranch(selector, branch) {
  return Object.entries(selector).every(([key, expected]) => {
    const property = branch.properties?.[key]
    if (!property) return false
    if (Object.hasOwn(property, 'const')) return property.const === expected
    if (property.enum) return property.enum.includes(expected)
    return false
  })
}

function assertFieldRegistry(fieldRegistry, registry, schemaFiles) {
  assertExactKeys(fieldRegistry, ['format', 'format_version', 'pointer_pattern_profile', 'instance_policy', 'controlled_values', 'schemas'], 'field_registry', 'FIELD_REGISTRY_INVALID', 'field registry')
  if (fieldRegistry.format !== 'jedi-atlas-d90-field-registry' || fieldRegistry.format_version !== '1.0.0') fail('field_registry', 'FIELD_REGISTRY_INVALID', 'field registry identity is invalid')
  if (fieldRegistry.pointer_pattern_profile !== 'rfc6901-single-segment-wildcard-v1') fail('field_registry', 'FIELD_REGISTRY_INVALID', 'unknown pointer profile')
  assertExactKeys(fieldRegistry.instance_policy, ['version_controlled_instances', 'real_instances', 'credentials_allowed', 'static_credentials_allowed', 'ephemeral_custody_capabilities_allowed', 'full_custody_capability_persistence', 'authorization_implication', 'legal_review_implication'], 'field_registry', 'FIELD_REGISTRY_INVALID', 'field instance policy')
  if (fieldRegistry.instance_policy.version_controlled_instances !== 'synthetic_fixtures_only' || fieldRegistry.instance_policy.real_instances !== 'protected_operational_storage_outside_git_and_atlas_sqlite' || fieldRegistry.instance_policy.credentials_allowed !== false || fieldRegistry.instance_policy.static_credentials_allowed !== false || fieldRegistry.instance_policy.ephemeral_custody_capabilities_allowed !== 'custody_adapter_authenticated_ipc_only' || fieldRegistry.instance_policy.full_custody_capability_persistence !== 'protected_short_lived_store_only' || fieldRegistry.instance_policy.authorization_implication !== false || fieldRegistry.instance_policy.legal_review_implication !== false) fail('field_registry', 'FIELD_REGISTRY_INVALID', 'field registry widens contents, storage, capability transport, authority, or review')
  assertExactKeys(fieldRegistry.controlled_values, ['confidentiality_codes', 'atlas_state_classes', 'digest_coverage_codes'], 'field_registry', 'FIELD_REGISTRY_INVALID', 'field controlled values')
  for (const [key, values] of Object.entries(fieldRegistry.controlled_values)) {
    if (!Array.isArray(values) || values.length === 0 || values.some((value) => typeof value !== 'string' || !/^[a-z][a-z0-9_]*$/u.test(value))) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${key} is not a closed stable-code list`)
    unique(values, 'field_registry', 'FIELD_REGISTRY_INVALID', key)
  }
  unique(fieldRegistry.schemas.map((entry) => entry.schema_file), 'field_registry', 'FIELD_REGISTRY_INVALID', 'schema field map')
  const defaultFiles = fieldRegistry.schemas.map((entry) => entry.schema_file).toSorted()
  if (canonical(defaultFiles) !== canonical(schemaFiles.toSorted())) fail('field_registry', 'FIELD_REGISTRY_INVALID', 'field registry lacks an exact default for every schema')
  for (const entry of fieldRegistry.schemas) {
    if (!registry.byFile.has(entry.schema_file)) fail('field_registry', 'FIELD_REGISTRY_INVALID', `unknown default schema ${entry.schema_file}`)
    const schema = registry.byFile.get(entry.schema_file)
    if (entry.schema_id !== schema.$id) fail('field_registry', 'FIELD_REGISTRY_INVALID', 'field map has wrong schema identity')
    const hasVariants = Object.hasOwn(entry, 'variants')
    const variants = hasVariants
      ? entry.variants
      : [{ variant_code: 'whole_contract', selector: {}, default: entry.default, overrides: entry.overrides }]
    assertExactKeys(entry, hasVariants ? ['schema_id', 'schema_file', 'variants'] : ['schema_id', 'schema_file', 'default', 'overrides'], 'field_registry', 'FIELD_REGISTRY_INVALID', 'schema field map')
    if (!Array.isArray(variants) || variants.length === 0) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file} has no field variants`)
    unique(variants.map((variant) => variant.variant_code), 'field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file} variant code`)
    unique(variants.map((variant) => canonical(variant.selector)), 'field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file} variant selector`)
    const branches = resolvedTopBranches(schema, registry)
    if (schema.oneOf) {
      for (const branch of branches) {
        const matches = variants.filter((variant) => selectorMatchesBranch(variant.selector, branch))
        if (matches.length !== 1) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file} branch has ${matches.length} trusted-producer mappings`)
      }
    } else if (variants.length > 1) {
      const selectorKeys = [...new Set(variants.flatMap((variant) => Object.keys(variant.selector)))]
      if (selectorKeys.length !== 1 || variants.some((variant) => Object.keys(variant.selector).length !== 1)) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file} flat variants require one common discriminator`)
      const property = schema.properties?.[selectorKeys[0]]
      if (!property?.enum || canonical(variants.map((variant) => variant.selector[selectorKeys[0]]).toSorted()) !== canonical(property.enum.toSorted())) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file} flat variants do not exhaust the discriminator enum`)
    }
    for (const variant of variants) {
      assertExactKeys(variant, ['variant_code', 'selector', 'default', 'overrides'], 'field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file} field variant`)
      if (!/^[a-z][a-z0-9_]*$/u.test(variant.variant_code) || !variant.selector || typeof variant.selector !== 'object' || Array.isArray(variant.selector)) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file} has invalid variant selector`)
      const matchedBranches = schema.oneOf ? branches.filter((branch) => selectorMatchesBranch(variant.selector, branch)) : [schema]
      if (matchedBranches.length < 1) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file}/${variant.variant_code} selector does not identify its intended branch set`)
      assertFieldMapping(variant.default, fieldRegistry, `${entry.schema_file}/${variant.variant_code} default`)
      const leaves = [...new Set(matchedBranches.flatMap((branch) => [...collectSchemaLeafPaths(branch, registry, schema)]))]
      unique(variant.overrides.map((override) => override.json_pointer_pattern), 'field_registry', 'FIELD_REGISTRY_INVALID', `override for ${entry.schema_file}/${variant.variant_code}`)
      for (const override of variant.overrides) {
        const { json_pointer_pattern: pattern, ...mapping } = override
        if (!/^\/(?:\*|(?:[^~/]|~[01])+)(?:\/(?:\*|(?:[^~/]|~[01])+))*$/u.test(pattern)) fail('field_registry', 'FIELD_REGISTRY_INVALID', `invalid pointer pattern ${pattern}`)
        if (!leaves.some((leaf) => pointerPatternMatches(pattern, leaf))) fail('field_registry', 'FIELD_REGISTRY_INVALID', `field override matches no branch leaf: ${pattern}`)
        assertFieldMapping(mapping, fieldRegistry, `${entry.schema_file}/${variant.variant_code}${pattern}`, { partial: true })
      }
      for (const leaf of leaves) {
        const applicable = variant.overrides.filter((override) => pointerPatternMatches(override.json_pointer_pattern, leaf))
        if (applicable.length > 1) fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file}/${variant.variant_code}${leaf} has ambiguous overlapping overrides`)
        const resolved = { ...variant.default }
        for (const override of applicable) Object.assign(resolved, override)
        delete resolved.json_pointer_pattern
        assertFieldMapping(resolved, fieldRegistry, `${entry.schema_file}/${variant.variant_code}${leaf}`)
        if (leaf === '/record_digest_sha256' && resolved.digest_coverage !== 'excluded_self_digest') fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file}/${variant.variant_code} fails to exclude only its top-level self-digest`)
        if (leaf !== '/record_digest_sha256' && resolved.digest_coverage === 'excluded_self_digest') fail('field_registry', 'FIELD_REGISTRY_INVALID', `${entry.schema_file}/${variant.variant_code}${leaf} improperly excludes a covered field`)
      }
    }
  }
  const semanticDigest = sha256(Buffer.from(canonical(fieldRegistrySemanticProjection(fieldRegistry, registry)), 'utf8'))
  if (semanticDigest !== frozenFieldRegistrySemanticDigest) fail('field_registry', 'FIELD_REGISTRY_INVALID', `effective field producer, consumer, storage, confidentiality, state, or digest semantics differ from frozen v1 projection ${semanticDigest}`)
}

function assertDigestProfiles(digestProfiles, registry, schemaFiles) {
  assertExactKeys(digestProfiles, ['format', 'format_version', 'algorithm_code', 'domain_separator_code', 'canonical_json_profile', 'payload_profiles', 'registry_self_digest', 'external_byte_source_contract', 'contract_projections', 'sqlite_projections', 'digest_bindings'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'digest profile registry')
  if (digestProfiles.format !== 'jedi-atlas-d90-digest-profiles' || digestProfiles.format_version !== '1.0.0' || digestProfiles.algorithm_code !== 'sha256' || digestProfiles.domain_separator_code !== 'none_v1' || digestProfiles.registry_self_digest !== 'not_present_to_avoid_self_reference') fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'digest profile identity is invalid')
  assertExactKeys(digestProfiles.canonical_json_profile, ['encoding_code', 'unicode_normalization_code', 'object_key_order_code', 'array_order_code', 'number_code', 'null_code', 'line_ending_code', 'duplicate_key_code'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'canonical JSON profile')
  if (canonical(digestProfiles.canonical_json_profile) !== canonical({ encoding_code: 'utf8_no_bom', unicode_normalization_code: 'none', object_key_order_code: 'utf16_code_unit_ascending', array_order_code: 'as_declared_unless_projection_profile_requires_order', number_code: 'nonnegative_safe_integer_decimal_no_exponent', null_code: 'literal_null', line_ending_code: 'none_after_compact_serialization', duplicate_key_code: 'reject' })) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'canonical JSON profile drifted')
  unique(digestProfiles.payload_profiles.map((profile) => profile.profile_code), 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'payload profile')
  const profileCodes = new Set(digestProfiles.payload_profiles.map((profile) => profile.profile_code))
  for (const profile of digestProfiles.payload_profiles) {
    assertExactKeys(profile, ['profile_code', 'input_code', 'projection_code', 'ordering_code', 'retention_code', 'description'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'payload profile')
    if (![profile.profile_code, profile.input_code, profile.projection_code, profile.ordering_code, profile.retention_code].every((value) => /^[a-z][a-z0-9_]*$/u.test(value)) || typeof profile.description !== 'string' || profile.description.length < 1) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `invalid payload profile ${profile.profile_code}`)
  }
  const profileProjection = digestProfiles.payload_profiles.map(({ profile_code, input_code, projection_code, ordering_code, retention_code }) => ({ profile_code, input_code, projection_code, ordering_code, retention_code })).toSorted((left, right) => left.profile_code < right.profile_code ? -1 : left.profile_code > right.profile_code ? 1 : 0)
  const profileSemanticDigest = sha256(Buffer.from(canonical(profileProjection), 'utf8'))
  if (profileSemanticDigest !== frozenDigestProfileSemanticDigest) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `payload-profile semantics differ from frozen v1 projection ${profileSemanticDigest}`)

  const byteSource = digestProfiles.external_byte_source_contract
  assertExactKeys(byteSource, ['hash_input_code', 'start_offset', 'extent_code', 'transformations', 'symlink_policy_code', 'file_type_code', 'confinement_code', 'stability_code', 'short_read_code', 'growth_or_truncation_code', 'byte_length_code', 'availability_code', 'authorization_code', 'resolver_definitions'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'external byte-source contract')
  const exactByteSourcePolicy = {
    hash_input_code: 'entire_opened_regular_file_v1', start_offset: 0, extent_code: 'through_eof_exactly_once', transformations: [],
    symlink_policy_code: 'reject_every_path_component_and_final_target', file_type_code: 'regular_file',
    confinement_code: 'open_relative_to_preopened_logical_root_no_absolute_path_no_parent_escape',
    stability_code: 'same_device_inode_size_and_change_metadata_before_and_after_hash', short_read_code: 'reject', growth_or_truncation_code: 'reject',
    byte_length_code: 'opened_file_size_must_equal_declared_length_when_a_length_is_present',
    availability_code: 'exact_bytes_must_be_retrievable_from_the_named_protected_store', authorization_code: 'digest_and_retrievability_do_not_grant_access_or_authority',
  }
  for (const [key, value] of Object.entries(exactByteSourcePolicy)) if (canonical(byteSource[key]) !== canonical(value)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `external byte-source ${key} drifted`)
  if (!Array.isArray(byteSource.resolver_definitions) || byteSource.resolver_definitions.length !== 19) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'external byte-source resolver inventory is incomplete')
  unique(byteSource.resolver_definitions.map((item) => item.resolver_code), 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'external byte-source resolver')
  for (const resolver of byteSource.resolver_definitions) {
    assertExactKeys(resolver, ['resolver_code', 'storage_code', 'selection_code'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'external byte-source resolver')
    if (![resolver.resolver_code, resolver.storage_code, resolver.selection_code].every((value) => typeof value === 'string' && /^[a-z][a-z0-9_]*$/u.test(value))) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'external byte-source resolver is malformed')
  }
  const exactExternalResolvers = [
    ['repository_contract_catalog_v1', 'reviewed_git_tree', 'fixed_path_docs_schema_d9_0_contract_catalog_v1_json'],
    ['repository_evidence_bundle_schema_v1', 'reviewed_git_tree', 'fixed_path_docs_schema_tranche_2a_evidence_bundle_v1_schema_json'],
    ['repository_migration_by_name_v1', 'reviewed_git_tree', 'data_migrations_child_selected_by_sibling_migration_name'],
    ['protected_component_executable_by_role_v1', 'protected_release_store', 'exact_release_file_selected_by_runtime_profile_generation_and_sibling_runtime_role_code'],
    ['protected_dependency_lock_by_role_v1', 'protected_release_store', 'exact_lock_file_selected_by_runtime_profile_generation_and_sibling_runtime_role_code'],
    ['protected_scanner_executable_by_scanner_v1', 'authenticated_scanner_registry', 'exact_release_file_selected_by_scanner_code_and_build_digest'],
    ['protected_scanner_rules_by_scanner_v1', 'authenticated_scanner_registry', 'one_exact_ruleset_file_selected_by_scanner_code_and_rules_digest'],
    ['protected_runtime_domain_marker_v1', 'protected_runtime_profile_store', 'one_noncredential_marker_file_selected_by_profile_code_and_profile_generation'],
    ['protected_operational_profile_v1', 'protected_profile_store', 'one_exact_profile_file_selected_by_profile_kind_code_profile_code_and_generation'],
    ['protected_collection_profile_v1', 'protected_handoff_dependency_store', 'one_exact_profile_file_selected_by_collector_binding_retrieval_event_and_collection_profile_digest'],
    ['protected_clearance_support_record_v1', 'protected_clearance_register', 'one_exact_file_selected_by_supporting_record_code_and_supporting_record_digest'],
    ['protected_scanner_result_record_v1', 'protected_clearance_register', 'one_exact_file_selected_by_artifact_scanner_code_build_rules_completed_at_and_result_digest'],
    ['protected_custody_durability_receipt_v1', 'protected_operation_journal', 'one_exact_file_selected_by_request_record_digest_backend_reference_and_durability_receipt_digest'],
    ['protected_backup_inventory_v1', 'protected_backup_register', 'one_exact_file_selected_by_operation_id_and_backup_inventory_digest'],
    ['protected_incident_record_v1', 'protected_recovery_store', 'content_addressed_exact_file_selected_by_incident_record_digest'],
    ['protected_repair_plan_v1', 'protected_recovery_store', 'content_addressed_exact_file_selected_by_repair_plan_digest'],
    ['protected_restore_plan_v1', 'protected_recovery_store', 'content_addressed_exact_file_selected_by_restore_plan_digest'],
    ['candidate_database_by_operation_v1', 'operation_candidate_store', 'closed_candidate_file_selected_by_operation_id_and_candidate_file_digest'],
    ['artifact_bytes_by_identity_v1', 'verified_staging_or_custody_store', 'exact_bytes_selected_by_byte_layer_sha256_and_byte_length'],
  ].map(([resolver_code, storage_code, selection_code]) => ({ resolver_code, storage_code, selection_code }))
  if (canonical(byteSource.resolver_definitions) !== canonical(exactExternalResolvers)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'external byte-source resolver semantics drifted')

  assertExactKeys(digestProfiles.contract_projections, ['clearance_scope_v1'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'contract projection registry')
  const clearanceProjection = digestProfiles.contract_projections.clearance_scope_v1
  assertExactKeys(clearanceProjection, ['source_schema_file', 'source_record_kind_code', 'field_mappings', 'nested_field_sets', 'ordered_array_fields', 'transformation_code', 'omission_code'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'clearance scope projection')
  const expectedClearanceMappings = ['artifact', 'capture_context_code', 'conditions', 'contains_credentials', 'contains_personal_data', 'decision_code', 'derivative_use_code', 'expires_at', 'git_permanence_acknowledged', 'limitations', 'not_before', 'redistribution_scope_code', 'repository_declarations', 'retention_scope_code', 'sensitivity_code'].map((output_field) => ({ output_field, source_pointer: `/${output_field}` }))
  const expectedNestedFields = [
    { output_field: 'artifact', fields: ['byte_layer_code', 'byte_length', 'hash_algorithm_code', 'sha256'] },
    { output_field: 'repository_declarations', fields: ['no_sensitive_data', 'permanent_history_acknowledged', 'redistribution_eligible', 'size_eligible'] },
  ]
  if (clearanceProjection.source_schema_file !== 'clearance-record-v1.schema.json' || clearanceProjection.source_record_kind_code !== 'clearance_decision' || canonical(clearanceProjection.field_mappings) !== canonical(expectedClearanceMappings) || canonical(clearanceProjection.nested_field_sets) !== canonical(expectedNestedFields) || canonical(clearanceProjection.ordered_array_fields) !== canonical(['conditions', 'limitations']) || clearanceProjection.transformation_code !== 'identity_from_same_record' || clearanceProjection.omission_code !== 'all_unlisted_fields') fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'clearance scope projection differs from its exact same-record contract')

  const sqlite = digestProfiles.sqlite_projections
  assertExactKeys(sqlite, ['value_encoding_code', 'integer_encoding_code', 'text_encoding_code', 'null_encoding_code', 'blob_encoding_code', 'unsupported_storage_classes', 'schema_inventories', 'table_rows', 'receipt_row', 'receipt_dependency_graph', 'custody_leaf', 'prohibited_surfaces'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'SQLite projection contract')
  if (canonical({ value_encoding_code: sqlite.value_encoding_code, integer_encoding_code: sqlite.integer_encoding_code, text_encoding_code: sqlite.text_encoding_code, null_encoding_code: sqlite.null_encoding_code, blob_encoding_code: sqlite.blob_encoding_code, unsupported_storage_classes: sqlite.unsupported_storage_classes }) !== canonical({ value_encoding_code: 'canonical_json_sqlite_values_v1', integer_encoding_code: 'json_safe_integer', text_encoding_code: 'json_string_without_normalization', null_encoding_code: 'json_null', blob_encoding_code: 'object_with_single_blob_hex_member_lowercase_even_length', unsupported_storage_classes: ['real'] })) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'SQLite value encoding drifted')
  if (!Array.isArray(sqlite.schema_inventories) || canonical(sqlite.schema_inventories.map((item) => item.projection_code)) !== canonical(['complete_schema', 'legacy_schema', 'exact_object_inventory'])) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'SQLite schema projections are incomplete or reordered')
  const exactSchemaSelects = {
    complete_schema: "SELECT type,name,tbl_name AS table_name,sql FROM sqlite_schema WHERE substr(name,1,7) <> 'sqlite_' ORDER BY type COLLATE BINARY ASC,name COLLATE BINARY ASC",
    legacy_schema: "SELECT type,name,tbl_name AS table_name,sql FROM sqlite_schema WHERE substr(name,1,7) <> 'sqlite_' AND substr(name,1,6) <> 'atlas_' AND name NOT IN ('schema_migrations','migration_checksums') ORDER BY type COLLATE BINARY ASC,name COLLATE BINARY ASC",
    exact_object_inventory: "SELECT type,name,tbl_name AS table_name FROM sqlite_schema WHERE substr(name,1,7) <> 'sqlite_' ORDER BY type COLLATE BINARY ASC,name COLLATE BINARY ASC",
  }
  for (const projection of sqlite.schema_inventories) {
    const keys = projection.projection_code === 'legacy_schema' ? ['projection_code', 'select_sql', 'included_objects_code', 'included_objects'] : ['projection_code', 'select_sql', 'included_objects_code']
    assertExactKeys(projection, keys, 'digest_profiles', 'DIGEST_PROFILE_INVALID', `${projection.projection_code} schema projection`)
    if (projection.select_sql !== exactSchemaSelects[projection.projection_code]) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `${projection.projection_code} schema SELECT drifted`)
  }
  const legacyProjection = sqlite.schema_inventories.find((item) => item.projection_code === 'legacy_schema')
  if (legacyProjection.included_objects_code !== 'exact_frozen_v1_object_set' || !Array.isArray(legacyProjection.included_objects) || legacyProjection.included_objects.length !== 27) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'legacy schema object inventory is incomplete')
  unique(legacyProjection.included_objects.map((item) => `${item.type}:${item.name}:${item.table_name}`), 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'legacy schema object')
  for (const item of legacyProjection.included_objects) assertExactKeys(item, ['type', 'name', 'table_name'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'legacy schema object')
  assertExactKeys(sqlite.table_rows, ['foreign_key_projection_code', 'row_projection_code', 'row_order_code', 'projections'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'table-row projection registry')
  if (sqlite.table_rows.foreign_key_projection_code !== 'raw_deterministic_integer_ids_no_code_substitution' || sqlite.table_rows.row_projection_code !== 'all_columns_in_declared_pragma_table_info_order' || sqlite.table_rows.row_order_code !== 'all_projection_columns_binary_ascending_in_declared_order') fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'table-row projection semantics drifted')
  const expectedTables = [...legacyTables, ...atlasTables]
  if (canonical(sqlite.table_rows.projections.map((item) => item.table_code)) !== canonical(expectedTables)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'table-row projection inventory is incomplete or reordered')
  for (const projection of sqlite.table_rows.projections) {
    assertExactKeys(projection, ['table_code', 'columns', 'ordering_columns'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', `${projection.table_code} row projection`)
    if (!Array.isArray(projection.columns) || projection.columns.length === 0 || projection.columns.some((column) => !/^[a-z][a-z0-9_]*$/u.test(column)) || new Set(projection.columns).size !== projection.columns.length || canonical(projection.columns) !== canonical(projection.ordering_columns)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `${projection.table_code} row projection columns are invalid`)
  }
  assertExactKeys(sqlite.receipt_row, ['selector_code', 'selector_fields', 'excluded_columns', 'output_fields', 'foreign_key_replacements', 'canonical_container_code'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'receipt-row projection')
  if (canonical(sqlite.receipt_row.selector_fields) !== canonical(['bundle_code', 'bundle_sequence', 'bundle_digest_sha256']) || canonical(sqlite.receipt_row.excluded_columns) !== canonical(['id']) || sqlite.receipt_row.canonical_container_code !== 'single_json_object_not_array') fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'receipt-row identity or container drifted')
  if (canonical(sqlite.receipt_row.output_fields) !== canonical(['bundle_sequence', 'bundle_code', 'format_version_code', 'bundle_digest_sha256', 'manifest_path', 'bundle_created_at', 'submitted_by_principal_code', 'imported_by_principal_code', 'importer_software_code', 'importer_version', 'recorded_by_principal_code', 'recorded_at'])) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'receipt-row fields drifted')
  if (!Array.isArray(sqlite.receipt_row.foreign_key_replacements) || sqlite.receipt_row.foreign_key_replacements.length !== 3) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'receipt-row FK replacements are incomplete')
  for (const replacement of sqlite.receipt_row.foreign_key_replacements) assertExactKeys(replacement, ['input_field', 'output_field', 'target_table', 'target_field'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'receipt-row FK replacement')
  assertExactKeys(sqlite.receipt_dependency_graph, ['receipt_order_fields', 'receipt_order_collations', 'receipt_fields', 'dependency_fields', 'dependency_order_code', 'genesis_payload', 'bootstrap_successor_payload', 'document_successor_payload'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'receipt graph projection')
  if (canonical(sqlite.receipt_dependency_graph.receipt_order_fields) !== canonical(['bundle_sequence', 'bundle_code']) || canonical(sqlite.receipt_dependency_graph.receipt_order_collations) !== canonical(['numeric_ascending', 'binary_ascending']) || canonical(sqlite.receipt_dependency_graph.receipt_fields) !== canonical(['bundle_code', 'bundle_sequence', 'bundle_digest_sha256', 'required_bundles']) || canonical(sqlite.receipt_dependency_graph.dependency_fields) !== canonical(['bundle_id', 'bundle_sequence', 'bundle_digest_sha256']) || sqlite.receipt_dependency_graph.dependency_order_code !== 'retained_manifest_array_order' || canonical(sqlite.receipt_dependency_graph.genesis_payload) !== '[]') fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'receipt dependency-graph projection drifted')
  if (!Array.isArray(sqlite.receipt_dependency_graph.bootstrap_successor_payload) || sqlite.receipt_dependency_graph.bootstrap_successor_payload.length !== 1) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'bootstrap receipt dependency graph must contain one receipt')
  const bootstrapReceiptGraph = sqlite.receipt_dependency_graph.bootstrap_successor_payload[0]
  assertExactKeys(bootstrapReceiptGraph, ['bundle_code', 'bundle_sequence', 'bundle_digest_sha256', 'required_bundles'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'bootstrap receipt dependency graph item')
  if (bootstrapReceiptGraph.bundle_sequence !== 1 || !/^[a-z0-9][a-z0-9._-]*[a-z0-9]$/u.test(bootstrapReceiptGraph.bundle_code) || !/^[0-9a-f]{64}$/u.test(bootstrapReceiptGraph.bundle_digest_sha256) || !Array.isArray(bootstrapReceiptGraph.required_bundles) || bootstrapReceiptGraph.required_bundles.length !== 0) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'bootstrap receipt dependency graph is malformed')
  const expectedDocumentReceiptGraph = [
    { bundle_code: 'synthetic.bootstrap-bundle', bundle_sequence: 1, bundle_digest_sha256: '327c4ce915f9ca9b69193ccb86c89a1d11a2395d36f7088ae256fa228e566875', required_bundles: [] },
    { bundle_code: 'synthetic.bundle-002', bundle_sequence: 2, bundle_digest_sha256: '2273ab881df419197add1b749671571d35779b4768eca2b90a946341b4cac152', required_bundles: [{ bundle_id: 'synthetic.bootstrap-bundle', bundle_sequence: 1, bundle_digest_sha256: '327c4ce915f9ca9b69193ccb86c89a1d11a2395d36f7088ae256fa228e566875' }] },
  ]
  if (canonical(sqlite.receipt_dependency_graph.document_successor_payload) !== canonical(expectedDocumentReceiptGraph)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'document receipt dependency graph is not the exact two-bundle successor projection')
  const custodyLeaf = sqlite.custody_leaf
  assertExactKeys(custodyLeaf, ['selector_code', 'event_time_bound_code', 'knowledge_bound_code', 'leaf_resolution_code', 'eligible_event_kind_codes', 'ineligible_event_kind_codes', 'output_fields', 'artifact_fields', 'evidence_bundle_fields', 'repository_declaration_fields', 'null_encoding_code', 'canonical_container_code'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'custody-leaf projection')
  const expectedCustodyLeaf = {
    selector_code: 'current_leaf_for_exact_artifact_and_copy_with_dual_time_bounds',
    event_time_bound_code: 'occurred_at_and_recorded_at_lte_adapter_selected_custody_evaluated_at',
    knowledge_bound_code: 'evidence_bundle_sequence_lte_known_through_bundle_sequence',
    leaf_resolution_code: 'one_root_one_successor_per_predecessor_same_artifact_copy_then_no_qualifying_successor',
    eligible_event_kind_codes: ['placed', 'relocated', 'restored'],
    ineligible_event_kind_codes: ['restricted', 'quarantined', 'tombstoned'],
    output_fields: ['artifact', 'backend_code', 'backend_reference', 'copy_code', 'custody_class_code', 'custody_event_code', 'event_kind_code', 'evidence_bundle', 'occurred_at', 'predecessor_custody_event_code', 'reason', 'recorded_at', 'recorded_by_principal_code', 'repository_eligibility_declaration'],
    artifact_fields: ['byte_layer_code', 'byte_length', 'hash_algorithm_code', 'sha256'],
    evidence_bundle_fields: ['bundle_digest_sha256', 'bundle_id', 'bundle_sequence'],
    repository_declaration_fields: ['declared_at', 'declared_by_principal_code', 'no_sensitive_data_declared', 'permanent_history_acknowledged', 'redistribution_eligible_declared', 'size_eligible_declared'],
    null_encoding_code: 'explicit_json_null',
    canonical_container_code: 'single_json_object_not_array',
  }
  if (canonical(custodyLeaf) !== canonical(expectedCustodyLeaf)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'custody-leaf projection semantics drifted')
  assertExactKeys(sqlite.prohibited_surfaces, ['item_fields', 'ordering_fields', 'ordering_collations', 'inventory_source_code', 'items'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'prohibited-surface projection')
  if (canonical(sqlite.prohibited_surfaces.item_fields) !== canonical(['surface_code', 'path', 'kind', 'exact_content_sha256']) || canonical(sqlite.prohibited_surfaces.ordering_fields) !== canonical(['surface_code', 'path']) || canonical(sqlite.prohibited_surfaces.ordering_collations) !== canonical(['binary_ascending', 'utf8_binary_ascending']) || sqlite.prohibited_surfaces.inventory_source_code !== 'version_controlled_closed_surface_inventory_required' || !Array.isArray(sqlite.prohibited_surfaces.items) || sqlite.prohibited_surfaces.items.length === 0) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'prohibited-surface inventory is incomplete')
  const prohibitedOrder = sqlite.prohibited_surfaces.items.map((item) => `${item.surface_code}\u0000${item.path}`)
  if (canonical(prohibitedOrder) !== canonical(prohibitedOrder.toSorted())) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'prohibited-surface inventory is not in binary key order')
  unique(prohibitedOrder, 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'prohibited-surface inventory key')
  for (const item of sqlite.prohibited_surfaces.items) {
    assertExactKeys(item, ['surface_code', 'path', 'kind', 'exact_content_sha256'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'prohibited-surface item')
    if (!/^[a-z][a-z0-9_]*$/u.test(item.surface_code) || item.kind !== 'file' || !isSafeRelativePath(item.path, 240) || !/^[0-9a-f]{64}$/u.test(item.exact_content_sha256)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'prohibited-surface item is malformed')
    const target = path.resolve(project, item.path)
    if (!target.startsWith(`${project}${path.sep}`) || !fs.existsSync(target) || !fs.statSync(target).isFile() || rawFileSha256(target) !== item.exact_content_sha256) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `prohibited surface differs: ${item.path}`)
  }

  const externalResolvers = new Set(byteSource.resolver_definitions.map((item) => item.resolver_code))
  const internalResolvers = new Set([
    'same_contract_object_omit_self_digest_v1', 'runtime_profile_record_by_active_input_v1', 'identity_binding_record_by_active_input_v1',
    'retrieval_request_projection_from_manifest_v1', 'evidence_bundle_by_tuple_v1', 'logical_state_seal_record_by_reference_v1',
    'logical_state_payload_by_reference_v1', 'contract_record_by_explicit_reference_v1', 'principal_roster_from_referenced_state_v1',
    'contract_record_by_digest_and_context_v1', 'receipt_row_by_bundle_tuple_v1', 'receipt_row_by_referenced_logical_state_v1', 'custody_request_record_by_operation_request_v1',
    'custody_capability_issuance_by_digest_v1', 'custody_capability_control_by_digest_v1', 'custody_leaf_by_exact_bitemporal_projection_v1',
    'same_record_state_payload_v1', 'sqlite_complete_schema_projection_v1', 'sqlite_legacy_schema_projection_v1',
    'sqlite_object_inventory_projection_v1', 'sqlite_table_projection_by_sibling_table_code_v1', 'same_state_payload_principal_roster_v1',
    'accepted_receipt_graph_from_retained_manifests_v1', 'prohibited_surfaces_projection_v1', 'prior_logical_state_payload_by_digest_v1',
    'previous_journal_record_by_sequence_v1', 'same_clearance_decision_scope_projection_v1',
  ])
  if (!Array.isArray(digestProfiles.digest_bindings) || digestProfiles.digest_bindings.length === 0) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'digest bindings are missing')
  unique(digestProfiles.digest_bindings.map((item) => item.binding_code), 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'digest binding')
  const usedPatterns = new Map()
  const usedProfiles = new Set()
  const expectedSchemaFiles = ['bootstrap-control-v1.schema.json', 'clearance-record-v1.schema.json', 'collector-handoff-v1.schema.json', 'custody-adapter-message-v1.schema.json', 'custody-capability-control-v1.schema.json', 'identity-bindings-v1.schema.json', 'importer-result-v1.schema.json', 'logical-state-seal-v1.schema.json', 'operation-journal-event-v1.schema.json', 'runtime-profile-v1.schema.json']
  if (canonical([...schemaFiles].toSorted()) !== canonical(expectedSchemaFiles)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'digest binding schema inventory must be the nine external contracts plus the protected capability helper')
  for (const binding of digestProfiles.digest_bindings) {
    assertExactKeys(binding, ['binding_code', 'schema_file', 'json_pointer_patterns', 'digest_role_code', 'payload_profile_code', 'resolver_code'], 'digest_profiles', 'DIGEST_PROFILE_INVALID', 'digest binding')
    if (!/^[a-z][a-z0-9.-]*$/u.test(binding.binding_code) || !expectedSchemaFiles.includes(binding.schema_file) || !['defines', 'references'].includes(binding.digest_role_code) || !profileCodes.has(binding.payload_profile_code) || (!internalResolvers.has(binding.resolver_code) && !externalResolvers.has(binding.resolver_code)) || !Array.isArray(binding.json_pointer_patterns) || binding.json_pointer_patterns.length === 0) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `invalid digest binding ${binding.binding_code}`)
    unique(binding.json_pointer_patterns, 'digest_profiles', 'DIGEST_PROFILE_INVALID', `pointer in ${binding.binding_code}`)
    usedProfiles.add(binding.payload_profile_code)
    const leaves = [...collectSchemaLeafPaths(registry.byFile.get(binding.schema_file), registry)].filter((leaf) => leaf.split('/').at(-1)?.endsWith('sha256'))
    for (const pattern of binding.json_pointer_patterns) {
      if (!/^\/(?:\*|(?:[^~/]|~[01])+)(?:\/(?:\*|(?:[^~/]|~[01])+))*$/u.test(pattern)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `invalid digest pointer ${pattern}`)
      const matches = leaves.filter((leaf) => pointerExactPatternMatches(pattern, leaf))
      if (matches.length === 0) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `unused digest pointer ${binding.schema_file}${pattern}`)
      usedPatterns.set(`${binding.schema_file}:${pattern}`, matches)
    }
    if (binding.payload_profile_code.startsWith('exact_') && !externalResolvers.has(binding.resolver_code)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `${binding.binding_code} lacks an exact external byte-source resolver`)
  }
  if (canonical([...usedProfiles].toSorted()) !== canonical([...profileCodes].toSorted())) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'one or more payload profiles are unused')
  for (const schemaFile of schemaFiles) {
    for (const leaf of collectSchemaLeafPaths(registry.byFile.get(schemaFile), registry)) {
      if (!leaf.split('/').at(-1)?.endsWith('sha256')) continue
      const matches = digestProfiles.digest_bindings.filter((binding) => binding.schema_file === schemaFile && binding.json_pointer_patterns.some((pattern) => pointerExactPatternMatches(pattern, leaf)))
      if (matches.length !== 1) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `${schemaFile}${leaf} resolves to ${matches.length} pointer-scoped digest bindings`)
    }
  }
  const bindingProjection = digestProfiles.digest_bindings.map((binding) => ({
    binding_code: binding.binding_code,
    schema_file: binding.schema_file,
    json_pointer_patterns: [...binding.json_pointer_patterns].toSorted(),
    digest_role_code: binding.digest_role_code,
    payload_profile_code: binding.payload_profile_code,
    resolver_code: binding.resolver_code,
  })).toSorted((left, right) => left.binding_code < right.binding_code ? -1 : left.binding_code > right.binding_code ? 1 : 0)
  const bindingSemanticDigest = sha256(Buffer.from(canonical(bindingProjection), 'utf8'))
  if (bindingSemanticDigest !== frozenDigestBindingSemanticDigest) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `pointer-to-profile/resolver semantics differ from frozen v1 projection ${bindingSemanticDigest}`)
}

function assertFixtureEnvelope(value, kind) {
  const expectedFormat = kind === 'valid' ? 'jedi-atlas-d90-valid-fixtures' : 'jedi-atlas-d90-invalid-fixtures'
  const collection = kind === 'valid' ? 'fixtures' : 'cases'
  assertExactKeys(value, ['fixture_format', 'fixture_version', collection], 'fixture', 'FIXTURE_INVALID', `${kind} fixture envelope`)
  if (value.fixture_format !== expectedFormat || value.fixture_version !== '1.0.0' || !Array.isArray(value[collection])) fail('fixture', 'FIXTURE_INVALID', `${kind} fixture identity is invalid`)
}

const frozenPayloadVectorProfileAssignments = [
  ['payload-canonical-contract', ['canonical_contract_record_v1']],
  ['payload-evidence-bundle', ['canonical_evidence_bundle_v1']],
  ['payload-retrieval-request-fingerprint', ['canonical_retrieval_request_fingerprint_v1']],
  ['payload-principal-roster', ['canonical_principal_roster_v1']],
  ['payload-logical-state', ['canonical_logical_state_payload_v1']],
  ['payload-exact-file-bytes', [
    'exact_artifact_bytes_v1',
    'exact_backup_inventory_bytes_v1',
    'exact_candidate_database_bytes_v1',
    'exact_clearance_support_bytes_v1',
    'exact_collection_profile_bytes_v1',
    'exact_contract_file_bytes_v1',
    'exact_custody_durability_receipt_bytes_v1',
    'exact_dependency_lock_bytes_v1',
    'exact_executable_bytes_v1',
    'exact_incident_record_bytes_v1',
    'exact_migration_file_bytes_v1',
    'exact_operational_profile_bytes_v1',
    'exact_restore_plan_bytes_v1',
    'exact_runtime_domain_marker_bytes_v1',
    'exact_scanner_result_bytes_v1',
    'exact_scanner_rules_bytes_v1',
  ]],
  ['payload-sqlite-schema-inventory', ['sqlite_complete_schema_inventory_v1', 'sqlite_legacy_schema_inventory_v1']],
  ['payload-sqlite-table-rows', ['sqlite_table_rows_v1']],
  ['payload-sqlite-receipt-row', ['sqlite_receipt_row_v1']],
  ['payload-sqlite-object-inventory', ['sqlite_object_inventory_v1']],
  ['payload-receipt-dependency-graph', ['receipt_dependency_graph_v1']],
  ['payload-clearance-scope', ['canonical_clearance_scope_v1']],
  ['payload-prohibited-surfaces', ['prohibited_surfaces_v1']],
  ['payload-custody-leaf-projection', ['canonical_custody_leaf_projection_v1']],
  ['payload-exact-repair-plan-bytes', ['exact_repair_plan_bytes_v1']],
]

function assertPayloadVectorProfileAssignments(golden) {
  const actual = golden.payload_vectors.map((vector) => [vector.vector_code, vector.profile_codes])
  if (canonical(actual) !== canonical(frozenPayloadVectorProfileAssignments)) fail('golden', 'GOLDEN_INVALID', 'payload-vector labels or profile assignments differ from the independently frozen mapping')
}

function assertGoldenVectors(golden, fixtures, digestProfiles) {
  assertExactKeys(golden, ['fixture_format', 'fixture_version', 'micro_vectors', 'complete_manifest_vector', 'complete_document_manifest_vector', 'payload_vectors', 'contract_vectors', 'raw_file_hashes'], 'golden', 'GOLDEN_INVALID', 'golden-vector envelope')
  if (golden.fixture_format !== 'jedi-atlas-d90-golden-vectors' || golden.fixture_version !== '1.0.0') fail('golden', 'GOLDEN_INVALID', 'golden-vector identity is invalid')
  unique(golden.micro_vectors.map((item) => item.vector_code), 'golden', 'GOLDEN_INVALID', 'micro vector')
  const expectedMicroVectors = ['utf16-key-order-astral-before-bmp-private-use', 'unicode-is-not-normalized', 'arrays-and-nulls-preserve-order', 'exclude-only-top-level-self-digest', 'insignificant-whitespace-and-crlf', 'configuration-object-hash', 'object-key-order']
  assertExactOrder(golden.micro_vectors.map((item) => item.vector_code), expectedMicroVectors, 'golden', 'GOLDEN_INVALID', 'micro vector')
  for (const vector of golden.micro_vectors) {
    assertExactKeys(vector, ['vector_code', 'value', 'excluded_top_level_field', 'canonical_utf8', 'sha256'], 'golden', 'GOLDEN_INVALID', 'micro vector')
    if (typeof vector.vector_code !== 'string' || !/^[a-z0-9][a-z0-9._-]*[a-z0-9]$/u.test(vector.vector_code) || (vector.excluded_top_level_field !== null && typeof vector.excluded_top_level_field !== 'string') || typeof vector.canonical_utf8 !== 'string' || !/^[0-9a-f]{64}$/u.test(vector.sha256)) fail('golden', 'GOLDEN_INVALID', 'micro vector has malformed metadata')
    const payload = vector.excluded_top_level_field === null ? vector.value : withoutTopLevel(vector.value, vector.excluded_top_level_field)
    if (canonical(payload) !== vector.canonical_utf8 || sha256(Buffer.from(vector.canonical_utf8, 'utf8')) !== vector.sha256) fail('golden', 'GOLDEN_INVALID', `independent micro-vector mismatch: ${vector.vector_code}`)
  }
  const manifestVector = golden.complete_manifest_vector
  assertExactKeys(manifestVector, ['vector_code', 'value', 'excluded_top_level_field', 'canonical_utf8', 'sha256'], 'golden', 'GOLDEN_INVALID', 'complete manifest vector')
  if (manifestVector.vector_code !== 'complete-principal-bootstrap-manifest-v1' || manifestVector.excluded_top_level_field !== 'bundle_digest_sha256') fail('golden', 'GOLDEN_INVALID', 'complete manifest vector identity is invalid')
  const manifest = manifestVector.value
  const exactManifestKeys = ['format', 'format_version', 'bundle_id', 'bundle_sequence', 'required_bundles', 'bundle_created_at', 'bundle_digest_sha256', 'manifest_path', 'submitter_principal_code', 'expected_importer_principal_code', 'expected_importer_software_code', 'expected_importer_version', 'bundle_declarations', 'principal_bootstrap', 'retrieval_locations', 'artifacts', 'retrieval_events', 'custody_events', 'processing_runs', 'candidate_occurrences']
  assertExactKeys(manifest, exactManifestKeys, 'golden', 'GOLDEN_INVALID', 'complete bootstrap manifest')
  if (manifest.format !== 'jedi-atlas-evidence-bundle' || manifest.format_version !== '1.0.0' || manifest.bundle_sequence !== 1 || manifest.required_bundles.length !== 0 || manifest.principal_bootstrap.principals.length !== pilotBundleShape.bootstrap_principals_exact - 1 || ['retrieval_locations', 'artifacts', 'retrieval_events', 'custody_events', 'processing_runs', 'candidate_occurrences'].some((key) => manifest[key].length !== 0)) fail('golden', 'GOLDEN_INVALID', 'complete manifest vector is not the exact synthetic bootstrap shape')
  const manifestPayload = withoutTopLevel(manifest, 'bundle_digest_sha256')
  if (canonical(manifestPayload) !== manifestVector.canonical_utf8 || sha256(Buffer.from(manifestVector.canonical_utf8, 'utf8')) !== manifestVector.sha256 || manifest.bundle_digest_sha256 !== manifestVector.sha256) fail('golden', 'GOLDEN_INVALID', 'independent complete-manifest vector mismatch')
  let coveredManifestLeaves = 0
  const visitManifest = (child, parts) => {
    if (child === null || ['boolean', 'number', 'string'].includes(typeof child)) {
      const mutated = structuredClone(manifestPayload)
      setAtPath(mutated, parts, changedScalar(child))
      if (sha256(Buffer.from(canonical(mutated), 'utf8')) === manifestVector.sha256) fail('golden', 'GOLDEN_INVALID', `complete manifest digest-insensitive leaf ${parts.join('/')}`)
      coveredManifestLeaves += 1
    } else if (Array.isArray(child)) child.forEach((item, index) => visitManifest(item, [...parts, index]))
    else for (const [key, value] of Object.entries(child)) visitManifest(value, [...parts, key])
  }
  for (const [key, value] of Object.entries(manifestPayload)) visitManifest(value, [key])
  if (coveredManifestLeaves < 20) fail('golden', 'GOLDEN_INVALID', 'complete manifest vector has insufficient field sensitivity coverage')
  const reorderedPrincipals = structuredClone(manifestPayload)
  reorderedPrincipals.principal_bootstrap.principals.reverse()
  if (sha256(Buffer.from(canonical(reorderedPrincipals), 'utf8')) === manifestVector.sha256) fail('golden', 'GOLDEN_INVALID', 'manifest array ordering does not affect the digest')
  const changedSelfDigest = structuredClone(manifest)
  changedSelfDigest.bundle_digest_sha256 = 'f'.repeat(64)
  if (sha256(Buffer.from(canonical(withoutTopLevel(changedSelfDigest, 'bundle_digest_sha256')), 'utf8')) !== manifestVector.sha256) fail('golden', 'GOLDEN_INVALID', 'manifest digest excludes more or less than the one top-level digest field')

  const documentVector = golden.complete_document_manifest_vector
  assertExactKeys(documentVector, ['vector_code', 'source_file', 'excluded_top_level_field', 'canonical_utf8', 'sha256', 'value'], 'golden', 'GOLDEN_INVALID', 'complete document manifest vector')
  if (documentVector.vector_code !== 'complete-manifest-single-document' || documentVector.source_file !== 'fixtures/manifests/synthetic-bundle-002.json' || documentVector.excluded_top_level_field !== 'bundle_digest_sha256' || documentVector.sha256 !== '2273ab881df419197add1b749671571d35779b4768eca2b90a946341b4cac152') fail('golden', 'GOLDEN_INVALID', 'complete document manifest vector identity is invalid')
  const documentManifestBytes = fs.readFileSync(completeDocumentManifestPath)
  const documentManifest = parseJsonBytes(documentManifestBytes, { contractNumbers: true, maximumBytes: pilotLimits.manifest_bytes_max })
  const documentSeal = fixtures.get('document_bundle_seal').value
  if (rawFileSha256(evidenceManifestSchemaPath) !== fixtures.get('runtime_profile').value.evidence_bundle_contract.schema_sha256) fail('golden', 'GOLDEN_INVALID', 'complete document manifest is not pinned to the approved evidence-bundle schema bytes')
  assertNoSecretMaterial(documentManifest)
  assertNoSyntheticPersonalDataMarkers(documentManifest)
  assertExactKeys(documentManifest, ['format', 'format_version', 'bundle_id', 'bundle_sequence', 'required_bundles', 'bundle_created_at', 'bundle_digest_sha256', 'manifest_path', 'submitter_principal_code', 'expected_importer_principal_code', 'expected_importer_software_code', 'expected_importer_version', 'bundle_declarations', 'retrieval_locations', 'artifacts', 'retrieval_events', 'custody_events', 'processing_runs', 'candidate_occurrences'], 'golden', 'GOLDEN_INVALID', 'complete document manifest')
  if (documentManifest.format !== 'jedi-atlas-evidence-bundle' || documentManifest.format_version !== '1.0.0' || documentManifest.bundle_sequence !== 2 || documentManifest.bundle_declarations.contains_credentials !== false || documentManifest.bundle_declarations.contains_personal_data !== false || documentManifest.bundle_declarations.hostile_input_acknowledged !== true || documentManifest.retrieval_locations.length !== 1 || documentManifest.artifacts.length !== 1 || documentManifest.retrieval_events.length !== 1 || documentManifest.custody_events.length !== 1 || documentManifest.processing_runs.length !== 0 || documentManifest.candidate_occurrences.length !== 0) fail('golden', 'GOLDEN_INVALID', 'complete document manifest differs from the frozen single-document pilot shape')
  if (documentManifest.bundle_id !== documentSeal.bundle.bundle_id || documentManifest.bundle_sequence !== documentSeal.bundle.bundle_sequence || documentManifest.bundle_digest_sha256 !== documentSeal.bundle.bundle_digest_sha256 || documentManifest.manifest_path !== documentSeal.manifest_path) fail('golden', 'GOLDEN_INVALID', 'complete document manifest differs from its exact launcher seal')
  if (canonical(documentManifest) !== canonical(documentVector.value)) fail('golden', 'GOLDEN_INVALID', 'complete document manifest source differs from its independently fixed vector')
  const documentPayload = withoutTopLevel(documentManifest, 'bundle_digest_sha256')
  if (canonical(documentPayload) !== documentVector.canonical_utf8 || sha256(Buffer.from(documentVector.canonical_utf8, 'utf8')) !== documentVector.sha256 || documentManifest.bundle_digest_sha256 !== documentVector.sha256) fail('golden', 'GOLDEN_INVALID', 'independent complete-document-manifest vector mismatch')
  const documentArtifact = documentManifest.artifacts[0]
  const artifactBytes = fs.readFileSync(completeDocumentArtifactPath)
  if (documentArtifact.staged_path !== 'objects/sha256/c7/c76da313046a10971896c921d6bfaf00383159f10e5f1fa6d11f86f6276fc173' || documentArtifact.byte_length !== 32 || documentArtifact.sha256 !== 'c76da313046a10971896c921d6bfaf00383159f10e5f1fa6d11f86f6276fc173' || artifactBytes.length !== documentArtifact.byte_length || sha256(artifactBytes) !== documentArtifact.sha256) fail('golden', 'GOLDEN_INVALID', 'complete document manifest is not grounded in its exact fixed synthetic bytes')
  const retrieval = documentManifest.retrieval_events[0]
  const custody = documentManifest.custody_events[0]
  if (retrieval.artifact_code !== documentArtifact.record_code || retrieval.artifact_staged_path !== documentArtifact.staged_path || custody.artifact_code !== documentArtifact.record_code || custody.backend_reference !== documentArtifact.staged_path || documentManifest.required_bundles[0]?.bundle_digest_sha256 !== manifestVector.sha256) fail('golden', 'GOLDEN_INVALID', 'complete document manifest lineage is incomplete')
  assertPilotCasReference({ byte_layer_code: documentArtifact.byte_layer_code, hash_algorithm_code: documentArtifact.hash_algorithm_code, sha256: documentArtifact.sha256, byte_length: documentArtifact.byte_length }, custody.backend_code, custody.backend_reference)
  let coveredDocumentManifestLeaves = 0
  const visitDocumentManifest = (child, parts) => {
    if (child === null || ['boolean', 'number', 'string'].includes(typeof child)) {
      const mutated = structuredClone(documentPayload)
      setAtPath(mutated, parts, changedScalar(child))
      if (sha256(Buffer.from(canonical(mutated), 'utf8')) === documentVector.sha256) fail('golden', 'GOLDEN_INVALID', `complete document manifest digest-insensitive leaf ${parts.join('/')}`)
      coveredDocumentManifestLeaves += 1
    } else if (Array.isArray(child)) child.forEach((item, index) => visitDocumentManifest(item, [...parts, index]))
    else for (const [key, value] of Object.entries(child)) visitDocumentManifest(value, [...parts, key])
  }
  for (const [key, value] of Object.entries(documentPayload)) visitDocumentManifest(value, [key])
  if (coveredDocumentManifestLeaves < 70) fail('golden', 'GOLDEN_INVALID', 'complete document manifest has insufficient field-sensitivity coverage')
  const changedDocumentSelfDigest = structuredClone(documentManifest)
  changedDocumentSelfDigest.bundle_digest_sha256 = 'f'.repeat(64)
  if (sha256(Buffer.from(canonical(withoutTopLevel(changedDocumentSelfDigest, 'bundle_digest_sha256')), 'utf8')) !== documentVector.sha256) fail('golden', 'GOLDEN_INVALID', 'document manifest digest excludes more or less than the one top-level digest field')

  unique(golden.payload_vectors.map((item) => item.vector_code), 'golden', 'GOLDEN_INVALID', 'payload vector')
  assertPayloadVectorProfileAssignments(golden)
  const swappedPayloadAssignments = structuredClone(golden)
  ;[swappedPayloadAssignments.payload_vectors[0].profile_codes, swappedPayloadAssignments.payload_vectors[1].profile_codes] = [swappedPayloadAssignments.payload_vectors[1].profile_codes, swappedPayloadAssignments.payload_vectors[0].profile_codes]
  assert.throws(() => assertPayloadVectorProfileAssignments(swappedPayloadAssignments), /payload-vector labels or profile assignments/)
  const byteProfiles = new Set(digestProfiles.payload_profiles.filter((profile) => profile.ordering_code === 'byte_sequence').map((profile) => profile.profile_code))
  const declaredProfileCodes = new Set(digestProfiles.payload_profiles.map((profile) => profile.profile_code))
  const coveredProfiles = []
  let payloadVectorMutations = 0
  for (const vector of golden.payload_vectors) {
    if (!Array.isArray(vector.profile_codes) || vector.profile_codes.length === 0 || canonical(vector.profile_codes) !== canonical(vector.profile_codes.toSorted())) fail('golden', 'GOLDEN_INVALID', `payload vector has an empty or unordered profile set: ${vector.vector_code}`)
    unique(vector.profile_codes, 'golden', 'GOLDEN_INVALID', `${vector.vector_code} profile`)
    for (const profileCode of vector.profile_codes) {
      if (!declaredProfileCodes.has(profileCode)) fail('golden', 'GOLDEN_INVALID', `payload vector names unknown profile ${profileCode}`)
      coveredProfiles.push(profileCode)
    }
    if (vector.input_encoding_code === 'exact_bytes_hex') {
      assertExactKeys(vector, ['vector_code', 'profile_codes', 'input_encoding_code', 'input_bytes_hex', 'sha256'], 'golden', 'GOLDEN_INVALID', 'exact-byte payload vector')
      if (vector.profile_codes.some((profileCode) => !byteProfiles.has(profileCode)) || typeof vector.input_bytes_hex !== 'string' || !/^(?:[0-9a-f]{2})+$/u.test(vector.input_bytes_hex)) fail('golden', 'GOLDEN_INVALID', `invalid exact-byte payload vector ${vector.vector_code}`)
      const bytes = Buffer.from(vector.input_bytes_hex, 'hex')
      if (sha256(bytes) !== vector.sha256) fail('golden', 'GOLDEN_INVALID', `independent exact-byte payload mismatch: ${vector.vector_code}`)
      const mutated = Buffer.from(bytes)
      mutated[0] ^= 0xff
      if (sha256(mutated) === vector.sha256) fail('golden', 'GOLDEN_INVALID', `exact-byte payload mutation was digest-insensitive: ${vector.vector_code}`)
      payloadVectorMutations += 1
    } else if (vector.input_encoding_code === 'canonical_json') {
      assertExactKeys(vector, ['vector_code', 'profile_codes', 'input_encoding_code', 'value', 'excluded_top_level_field', 'canonical_utf8', 'sha256'], 'golden', 'GOLDEN_INVALID', 'canonical payload vector')
      if (vector.profile_codes.some((profileCode) => byteProfiles.has(profileCode)) || (vector.excluded_top_level_field !== null && typeof vector.excluded_top_level_field !== 'string')) fail('golden', 'GOLDEN_INVALID', `invalid canonical payload vector ${vector.vector_code}`)
      const payload = vector.excluded_top_level_field === null ? vector.value : withoutTopLevel(vector.value, vector.excluded_top_level_field)
      if (canonical(payload) !== vector.canonical_utf8 || sha256(Buffer.from(vector.canonical_utf8, 'utf8')) !== vector.sha256) fail('golden', 'GOLDEN_INVALID', `independent canonical payload mismatch: ${vector.vector_code}`)
      let changed = false
      const mutateOneLeaf = (child, parts) => {
        if (changed) return
        if (child === null || ['boolean', 'number', 'string'].includes(typeof child)) {
          const mutated = structuredClone(payload)
          setAtPath(mutated, parts, changedScalar(child))
          if (sha256(Buffer.from(canonical(mutated), 'utf8')) === vector.sha256) fail('golden', 'GOLDEN_INVALID', `canonical payload mutation was digest-insensitive: ${vector.vector_code}`)
          changed = true
          payloadVectorMutations += 1
          return
        }
        if (Array.isArray(child)) child.forEach((item, index) => mutateOneLeaf(item, [...parts, index]))
        else for (const [key, item] of Object.entries(child)) mutateOneLeaf(item, [...parts, key])
      }
      mutateOneLeaf(payload, [])
      if (!changed) fail('golden', 'GOLDEN_INVALID', `canonical payload vector is empty: ${vector.vector_code}`)
    } else fail('golden', 'GOLDEN_INVALID', `unknown payload-vector encoding: ${vector.input_encoding_code}`)
  }
  unique(coveredProfiles, 'golden', 'GOLDEN_INVALID', 'covered payload profile')
  if (canonical(coveredProfiles.toSorted()) !== canonical([...declaredProfileCodes].toSorted())) fail('golden', 'GOLDEN_INVALID', 'independent payload vectors do not cover every digest profile exactly once')
  const bootstrapSeal = fixtures.get('bootstrap_bundle_seal').value
  if (manifest.bundle_id !== bootstrapSeal.bundle.bundle_id || manifest.bundle_sequence !== bootstrapSeal.bundle.bundle_sequence || manifest.bundle_digest_sha256 !== bootstrapSeal.bundle.bundle_digest_sha256 || manifest.manifest_path !== bootstrapSeal.manifest_path) fail('golden', 'GOLDEN_INVALID', 'complete bootstrap manifest differs from its sealed bundle identity')
  const payloadByCode = new Map(golden.payload_vectors.map((vector) => [vector.vector_code, vector]))
  const receiptVector = payloadByCode.get('payload-sqlite-receipt-row')
  const receiptGraphVector = payloadByCode.get('payload-receipt-dependency-graph')
  const prohibitedVector = payloadByCode.get('payload-prohibited-surfaces')
  if (!receiptVector || receiptVector.value.bundle_code !== manifest.bundle_id || receiptVector.value.bundle_sequence !== manifest.bundle_sequence || receiptVector.value.bundle_digest_sha256 !== manifest.bundle_digest_sha256 || receiptVector.value.manifest_path !== manifest.manifest_path || receiptVector.value.bundle_created_at !== manifest.bundle_created_at) fail('golden', 'GOLDEN_INVALID', 'receipt-row vector differs from the complete bootstrap manifest')
  if (!receiptGraphVector || canonical(receiptGraphVector.value) !== canonical(digestProfiles.sqlite_projections.receipt_dependency_graph.document_successor_payload) || receiptGraphVector.sha256 !== '1321a2e15618b035eb6195442dea475fe59e8786f8d7f4c40ffa7efa75a8e197') fail('golden', 'GOLDEN_INVALID', 'receipt dependency-graph vector differs from the independently fixed two-bundle successor')
  if (!prohibitedVector || canonical(prohibitedVector.value) !== canonical(digestProfiles.sqlite_projections.prohibited_surfaces.items)) fail('golden', 'GOLDEN_INVALID', 'prohibited-surface vector differs from the closed registered inventory')
  const emptyState = fixtures.get('logical_state_empty').value.state_payload
  const bootstrapState = fixtures.get('logical_state_bootstrap').value.state_payload
  const documentState = fixtures.get('logical_state_document_002').value.state_payload
  const receiptDigest = sha256(Buffer.from(canonical(receiptVector.value), 'utf8'))
  const genesisGraphDigest = sha256(Buffer.from(canonical(digestProfiles.sqlite_projections.receipt_dependency_graph.genesis_payload), 'utf8'))
  const successorGraphDigest = sha256(Buffer.from(canonical(digestProfiles.sqlite_projections.receipt_dependency_graph.bootstrap_successor_payload), 'utf8'))
  const documentGraphDigest = sha256(Buffer.from(canonical(digestProfiles.sqlite_projections.receipt_dependency_graph.document_successor_payload), 'utf8'))
  const prohibitedDigest = sha256(Buffer.from(canonical(digestProfiles.sqlite_projections.prohibited_surfaces.items), 'utf8'))
  if (emptyState.receipt_dependency_graph_sha256 !== genesisGraphDigest || bootstrapState.receipt_dependency_graph_sha256 !== successorGraphDigest || documentState.receipt_dependency_graph_sha256 !== documentGraphDigest || bootstrapState.receipt_head.receipt_row_sha256 !== receiptDigest || emptyState.prohibited_surfaces_sha256 !== prohibitedDigest || bootstrapState.prohibited_surfaces_sha256 !== prohibitedDigest || documentState.prohibited_surfaces_sha256 !== prohibitedDigest || fixtures.get('runtime_profile').value.database_contract.prohibited_surfaces_sha256 !== prohibitedDigest) fail('golden', 'GOLDEN_INVALID', 'logical/runtime projections differ from their exact registered payloads')
  const changedGraph = structuredClone(digestProfiles.sqlite_projections.receipt_dependency_graph.document_successor_payload)
  changedGraph[1].bundle_code = 'synthetic.changed-bundle'
  if (canonical(changedGraph) === canonical(receiptGraphVector.value) || sha256(Buffer.from(canonical(changedGraph), 'utf8')) === documentState.receipt_dependency_graph_sha256) fail('golden', 'GOLDEN_INVALID', 'receipt dependency-graph mutation was not detected')
  const changedSurface = structuredClone(digestProfiles.sqlite_projections.prohibited_surfaces.items)
  changedSurface[0].exact_content_sha256 = '0'.repeat(64)
  if (canonical(changedSurface) === canonical(prohibitedVector.value) || sha256(Buffer.from(canonical(changedSurface), 'utf8')) === prohibitedDigest) fail('golden', 'GOLDEN_INVALID', 'prohibited-surface mutation was not detected')
  unique(golden.contract_vectors.map((item) => item.fixture_code), 'golden', 'GOLDEN_INVALID', 'contract vector')
  if (canonical(golden.contract_vectors.map((item) => item.fixture_code).toSorted()) !== canonical([...fixtures.keys()].toSorted())) fail('golden', 'GOLDEN_INVALID', 'contract golden vectors do not cover every valid fixture')
  for (const vector of golden.contract_vectors) {
    assertExactKeys(vector, ['fixture_code', 'canonical_utf8_sha256'], 'golden', 'GOLDEN_INVALID', 'contract vector')
    if (!/^[0-9a-f]{64}$/u.test(vector.canonical_utf8_sha256)) fail('golden', 'GOLDEN_INVALID', `contract golden has malformed digest: ${vector.fixture_code}`)
    const value = fixtures.get(vector.fixture_code).value
    const payload = Object.hasOwn(value, 'record_digest_sha256') ? withoutTopLevel(value, 'record_digest_sha256') : value
    const digest = sha256(Buffer.from(canonical(payload), 'utf8'))
    if (digest !== vector.canonical_utf8_sha256) fail('golden', 'GOLDEN_INVALID', `contract golden mismatch: ${vector.fixture_code}`)
    if (Object.hasOwn(value, 'record_digest_sha256') && value.record_digest_sha256 !== vector.canonical_utf8_sha256) fail('golden', 'GOLDEN_INVALID', `record self-digest differs from golden: ${vector.fixture_code}`)
  }
  unique(golden.raw_file_hashes.map((item) => item.file), 'golden', 'GOLDEN_INVALID', 'raw file golden')
  const expectedRawFiles = [
    ...fs.readdirSync(contractRoot).filter((name) => name.endsWith('.schema.json')),
    'classifications-v1.json',
    'contract-catalog-v1.json',
    'digest-profiles-v1.json',
    'field-registry-v1.json',
    'fixtures/invalid-contracts-v1.json',
    'fixtures/manifests/synthetic-bundle-002.json',
    'fixtures/objects/sha256/c7/c76da313046a10971896c921d6bfaf00383159f10e5f1fa6d11f86f6276fc173',
    'fixtures/valid-contracts-v1.json',
  ].toSorted()
  if (canonical(golden.raw_file_hashes.map((item) => item.file).toSorted()) !== canonical(expectedRawFiles)) {
    fail('golden', 'GOLDEN_INVALID', 'raw-file goldens do not cover the exact non-self-referential contract artifact set')
  }
  for (const entry of golden.raw_file_hashes) {
    assertExactKeys(entry, ['file', 'sha256'], 'golden', 'GOLDEN_INVALID', 'raw-file golden')
    if (!/^[0-9a-f]{64}$/u.test(entry.sha256)) fail('golden', 'GOLDEN_INVALID', `raw-file golden has malformed digest: ${entry.file}`)
    if (!isSafeRelativePath(entry.file, 240)) fail('golden', 'GOLDEN_INVALID', `unsafe raw-file vector path ${entry.file}`)
    const target = path.resolve(contractRoot, entry.file)
    if (!target.startsWith(`${contractRoot}${path.sep}`) || !fs.existsSync(target) || rawFileSha256(target) !== entry.sha256) fail('golden', 'GOLDEN_INVALID', `raw-file golden mismatch: ${entry.file}`)
  }
  return { payloadVectors: golden.payload_vectors.length, payloadVectorMutations }
}

function changedScalar(value) {
  if (value === null) return 'changed-null'
  if (typeof value === 'boolean') return !value
  if (typeof value === 'number') return value === Number.MAX_SAFE_INTEGER ? value - 1 : value + 1
  if (typeof value === 'string') return `${value}~`
  throw new Error('not a scalar')
}

function setAtPath(value, parts, replacement) {
  let current = value
  for (const part of parts.slice(0, -1)) current = current[part]
  current[parts.at(-1)] = replacement
}

function assertDigestSensitivity(fixtures) {
  let scalarMutations = 0
  let arrayMutations = 0
  for (const { value } of fixtures.values()) {
    const excluded = Object.hasOwn(value, 'record_digest_sha256') ? 'record_digest_sha256' : null
    const payload = excluded ? withoutTopLevel(value, excluded) : value
    const baseline = sha256(Buffer.from(canonical(payload), 'utf8'))
    const visit = (child, parts) => {
      if (child === null || ['boolean', 'number', 'string'].includes(typeof child)) {
        const mutated = structuredClone(payload)
        setAtPath(mutated, parts, changedScalar(child))
        if (sha256(Buffer.from(canonical(mutated), 'utf8')) === baseline) fail('golden', 'GOLDEN_INVALID', `digest-insensitive leaf ${parts.join('/')}`)
        scalarMutations += 1
      } else if (Array.isArray(child)) {
        if (child.length >= 2 && canonical(child[0]) !== canonical(child[1])) {
          const mutated = structuredClone(payload)
          let array = mutated
          for (const part of parts) array = array[part]
          ;[array[0], array[1]] = [array[1], array[0]]
          if (sha256(Buffer.from(canonical(mutated), 'utf8')) === baseline) fail('golden', 'GOLDEN_INVALID', `digest-insensitive array ${parts.join('/')}`)
          arrayMutations += 1
        }
        child.forEach((item, index) => visit(item, [...parts, index]))
      } else for (const [key, item] of Object.entries(child)) visit(item, [...parts, key])
    }
    for (const [key, child] of Object.entries(payload)) visit(child, [key])
    if (excluded) {
      const mutation = structuredClone(value)
      mutation[excluded] = 'f'.repeat(64)
      if (recordDigest(mutation) !== baseline) fail('golden', 'GOLDEN_INVALID', 'top-level self-digest was not the sole exclusion')
    }
  }
  if (scalarMutations < 1 || arrayMutations < 1) fail('golden', 'GOLDEN_INVALID', `fixture sensitivity corpus lacks scalar or order-bearing array leaves (${scalarMutations} scalar, ${arrayMutations} array)`)
  return { scalarMutations, arrayMutations }
}

function pointerParts(pointer) {
  if (!pointer.startsWith('/')) fail('fixture', 'FIXTURE_INVALID', `invalid JSON pointer ${pointer}`)
  return pointer.slice(1).split('/').map((item) => item.replaceAll('~1', '/').replaceAll('~0', '~')).map((item) => /^(?:0|[1-9][0-9]*)$/u.test(item) ? Number(item) : item)
}

function applyFixtureMutation(value, mutation) {
  const clone = structuredClone(value)
  const parts = pointerParts(mutation.json_pointer)
  let parent = clone
  for (const part of parts.slice(0, -1)) {
    if (parent === null || parent[part] === undefined) fail('fixture', 'FIXTURE_INVALID', `mutation path does not exist: ${mutation.json_pointer}`)
    parent = parent[part]
  }
  const key = parts.at(-1)
  if (mutation.operation === 'remove') {
    if (!(key in parent)) fail('fixture', 'FIXTURE_INVALID', `remove target does not exist: ${mutation.json_pointer}`)
    if (Array.isArray(parent)) parent.splice(key, 1)
    else delete parent[key]
  } else if (mutation.operation === 'add') {
    if (key in parent) fail('fixture', 'FIXTURE_INVALID', `add target already exists: ${mutation.json_pointer}`)
    parent[key] = structuredClone(mutation.value)
  } else if (mutation.operation === 'set') {
    if (!(key in parent)) fail('fixture', 'FIXTURE_INVALID', `set target does not exist: ${mutation.json_pointer}`)
    parent[key] = structuredClone(mutation.value)
  } else fail('fixture', 'FIXTURE_INVALID', `unknown mutation operation ${mutation.operation}`)
  return clone
}

function resealIfNeeded(value, invalidCase) {
  if (Object.hasOwn(value, 'record_digest_sha256') && invalidCase.expected_layer_code !== 'digest') value.record_digest_sha256 = recordDigest(value)
  return value
}

function validateFixtureSet(fixtures, registry, classification, catalogRawSha) {
  for (const fixture of fixtures.values()) {
    assertExactKeys(fixture, ['fixture_code', 'schema_file', 'value'], 'fixture', 'FIXTURE_INVALID', 'valid fixture')
    if (typeof fixture.fixture_code !== 'string' || !/^[a-z0-9][a-z0-9._-]*[a-z0-9]$/u.test(fixture.fixture_code) || typeof fixture.schema_file !== 'string' || !/^[a-z0-9][a-z0-9-]*\.schema\.json$/u.test(fixture.schema_file) || !fixture.value || typeof fixture.value !== 'object' || Array.isArray(fixture.value)) fail('fixture', 'FIXTURE_INVALID', 'valid fixture metadata is malformed')
    try {
      validateContractStructure(fixture.value, fixture.schema_file, registry)
      assertDigest(fixture.value)
    } catch (error) {
      if (error instanceof Error) error.message = `${fixture.fixture_code}: ${error.message}`
      throw error
    }
  }
  assertCrossContractSemantics(fixtures, classification, catalogRawSha)
}

function assertInvalidFixtures(invalidFixtures, baseFixtures, registry, classification, catalogRawSha) {
  assertFixtureEnvelope(invalidFixtures, 'invalid')
  unique(invalidFixtures.cases.map((item) => item.case_code), 'fixture', 'FIXTURE_INVALID', 'invalid case')
  const layers = new Set(['schema', 'secret_scan', 'semantic', 'digest', 'path', 'ipc', 'canonical'])
  for (const invalidCase of invalidFixtures.cases) {
    assertExactKeys(invalidCase, ['case_code', 'base_fixture_code', 'mutation', 'expected_layer_code', 'expected_error_code'], 'fixture', 'FIXTURE_INVALID', 'invalid case')
    const mutationKeys = invalidCase.mutation.operation === 'remove' ? ['operation', 'json_pointer'] : ['operation', 'json_pointer', 'value']
    assertExactKeys(invalidCase.mutation, mutationKeys, 'fixture', 'FIXTURE_INVALID', `mutation ${invalidCase.case_code}`)
    if (!['set', 'add', 'remove'].includes(invalidCase.mutation.operation) || typeof invalidCase.mutation.json_pointer !== 'string' || typeof invalidCase.case_code !== 'string' || typeof invalidCase.base_fixture_code !== 'string' || typeof invalidCase.expected_error_code !== 'string') fail('fixture', 'FIXTURE_INVALID', `invalid mutation metadata for ${invalidCase.case_code}`)
    if (!layers.has(invalidCase.expected_layer_code)) fail('fixture', 'FIXTURE_INVALID', `invalid expected layer ${invalidCase.expected_layer_code}`)
    const original = baseFixtures.get(invalidCase.base_fixture_code)
    if (!original) fail('fixture', 'FIXTURE_INVALID', `unknown base fixture ${invalidCase.base_fixture_code}`)
    const mutatedFixtures = new Map([...baseFixtures].map(([key, fixture]) => [key, structuredClone(fixture)]))
    const mutated = resealIfNeeded(applyFixtureMutation(original.value, invalidCase.mutation), invalidCase)
    mutatedFixtures.get(invalidCase.base_fixture_code).value = mutated
    let observed
    try { validateFixtureSet(mutatedFixtures, registry, classification, catalogRawSha) } catch (error) {
      if (!(error instanceof ContractError)) throw error
      observed = error
    }
    if (!observed) fail('fixture', 'FIXTURE_INVALID', `negative fixture unexpectedly passed: ${invalidCase.case_code}`)
    if (observed.layer !== invalidCase.expected_layer_code || observed.code !== invalidCase.expected_error_code) {
      fail('fixture', 'FIXTURE_INVALID', `${invalidCase.case_code} expected ${invalidCase.expected_layer_code}/${invalidCase.expected_error_code} but got ${observed.layer}/${observed.code}: ${observed.message}`)
    }
  }
  return invalidFixtures.cases.map((item) => item.case_code)
}

function assertTrustBoundaryMutations(baseFixtures, registry, classification, catalogRawSha) {
  const cases = [
    ['bundle-seal-issued-by-handoff-broker', 'document_bundle_seal', 'launcher_binding_code', 'binding.handoff-broker'],
    ['handoff-recorded-by-launcher', 'collector_handoff', 'handoff_broker_binding_code', 'binding.launcher'],
    ['bootstrap-permit-issued-by-launcher', 'bootstrap_permit', 'issuer_binding_code', 'binding.launcher'],
    ['bootstrap-transition-recorded-by-handoff-broker', 'bootstrap_transition_spent', 'recorded_by_binding_code', 'binding.handoff-broker'],
  ]
  for (const [caseCode, fixtureCode, field, replacement] of cases) {
    const mutated = new Map([...baseFixtures].map(([key, fixture]) => [key, structuredClone(fixture)]))
    mutated.get(fixtureCode).value[field] = replacement
    mutated.get(fixtureCode).value.record_digest_sha256 = recordDigest(mutated.get(fixtureCode).value)
    let observed
    try { validateFixtureSet(mutated, registry, classification, catalogRawSha) } catch (error) { observed = error }
    if (!(observed instanceof ContractError) || observed.layer !== 'semantic' || observed.code !== 'IDENTITY_BINDING_MISMATCH') fail('fixture', 'FIXTURE_INVALID', `${caseCode} did not fail at the identity trust boundary`)
  }
  const backdated = new Map([...baseFixtures].map(([key, fixture]) => [key, structuredClone(fixture)]))
  backdated.get('identity_bindings').value.issued_at = '2029-12-31T23:59:59.999Z'
  backdated.get('identity_bindings').value.record_digest_sha256 = recordDigest(backdated.get('identity_bindings').value)
  assert.throws(() => validateFixtureSet(backdated, registry, classification, catalogRawSha), /IDENTITY_BINDING_MISMATCH/)
  const humanCollisions = []
  for (const [caseCode, sourceRole] of [['bootstrap-issuer-is-submitter', 'human_submitter'], ['bootstrap-issuer-is-witness', 'operational_witness']]) {
    const mutated = new Map([...baseFixtures].map(([key, fixture]) => [key, structuredClone(fixture)]))
    const bindingSet = mutated.get('identity_bindings').value
    bindingSet.bindings.find((item) => item.runtime_role_code === 'bootstrap_authority').unix_uid = bindingSet.bindings.find((item) => item.runtime_role_code === sourceRole).unix_uid
    bindingSet.record_digest_sha256 = recordDigest(bindingSet)
    assert.throws(() => validateFixtureSet(mutated, registry, classification, catalogRawSha), /IDENTITY_BINDING_MISMATCH/)
    humanCollisions.push(caseCode)
  }
  return [...cases.map(([caseCode]) => caseCode), 'identity-bindings-before-runtime-profile', ...humanCollisions]
}

function assertClearanceContextMutations(baseFixtures, registry, classification, catalogRawSha) {
  const rejected = []
  for (const [caseCode, mutate] of [
    ['clearance-scope-stale-after-included-field-change', (value) => { value.conditions[0] = 'Changed synthetic scope.' }],
    ['clearance-runtime-profile-mismatch', (value) => { value.runtime_profile_record_digest_sha256 = '7'.repeat(64) }],
    ['clearance-identity-bindings-mismatch', (value) => { value.identity_bindings_record_digest_sha256 = '7'.repeat(64) }],
    ['clearance-operational-profile-mismatch', (value) => { value.clearance_operational_profile_sha256 = '7'.repeat(64) }],
  ]) {
    const mutated = new Map([...baseFixtures].map(([key, fixture]) => [key, structuredClone(fixture)]))
    const decision = mutated.get('clearance_decision').value
    mutate(decision)
    decision.record_digest_sha256 = recordDigest(decision)
    assert.throws(() => validateFixtureSet(mutated, registry, classification, catalogRawSha), /CLEARANCE_INVALID/, `${caseCode} unexpectedly passed`)
    rejected.push(caseCode)
  }
  const excludedSupportChange = structuredClone(baseFixtures.get('clearance_decision').value)
  const originalScope = excludedSupportChange.clearance_scope_sha256
  excludedSupportChange.supporting_record_sha256 = '7'.repeat(64)
  excludedSupportChange.record_digest_sha256 = recordDigest(excludedSupportChange)
  assertClearanceDecisionMatrix(excludedSupportChange, classification)
  if (excludedSupportChange.clearance_scope_sha256 !== originalScope || excludedSupportChange.record_digest_sha256 === baseFixtures.get('clearance_decision').value.record_digest_sha256) fail('fixture', 'FIXTURE_INVALID', 'clearance supporting-record mutation did not preserve scope while changing the full record digest')
  return { rejected, excluded_support_changes_record_only: true }
}

function assertDeterministicOrderMutations(baseFixtures, registry, classification, catalogRawSha) {
  const cases = [
    ['runtime-migrations', 'runtime_profile', (value) => value.migration_hashes.reverse()],
    ['runtime-components', 'runtime_profile', (value) => value.component_releases.reverse()],
    ['runtime-operational-profiles', 'runtime_profile', (value) => value.operational_profiles.reverse()],
    ['runtime-handles', 'runtime_profile', (value) => value.logical_handle_slots.reverse()],
    ['runtime-scanners', 'runtime_profile', (value) => value.scanner_policy.required_scanners.reverse()],
    ['identity-bindings', 'identity_bindings', (value) => value.bindings.reverse()],
    ['legacy-table-digests', 'logical_state_empty', (value) => value.state_payload.legacy_rows.reverse()],
    ['atlas-table-digests', 'logical_state_empty', (value) => value.state_payload.atlas_tables.reverse()],
    ['principal-roster', 'logical_state_bootstrap', (value) => value.state_payload.principal_roster.reverse()],
    ['clearance-scanners', 'clearance_decision', (value) => value.scanner_results.reverse()],
  ]
  for (const [label, fixtureCode, mutate] of cases) {
    const mutated = new Map([...baseFixtures].map(([key, fixture]) => [key, structuredClone(fixture)]))
    const value = mutated.get(fixtureCode).value
    mutate(value)
    if (value.record_kind_code === 'logical_state_seal') {
      value.state_payload.principal_roster_sha256 = sha256(Buffer.from(canonical(value.state_payload.principal_roster), 'utf8'))
      value.logical_state_sha256 = sha256(Buffer.from(canonical(value.state_payload), 'utf8'))
    }
    if (Object.hasOwn(value, 'record_digest_sha256')) value.record_digest_sha256 = recordDigest(value)
    assert.throws(() => validateFixtureSet(mutated, registry, classification, catalogRawSha), ContractError, `${label} reordering unexpectedly passed`)
  }
  return cases.map(([label]) => label)
}

function assertRegistryMutationMatrix({ classification, fieldRegistry, digestProfiles, registry, fieldSchemaNames, digestSchemaNames }) {
  const cases = []
  const mutatedProducer = structuredClone(fieldRegistry)
  mutatedProducer.schemas.find((entry) => entry.schema_file === 'runtime-profile-v1.schema.json').default.trusted_producers.push('second_producer')
  assert.throws(() => assertFieldRegistry(mutatedProducer, registry, fieldSchemaNames), /FIELD_REGISTRY_INVALID/)
  cases.push('ambiguous-trusted-producer')
  const mutatedVariant = structuredClone(fieldRegistry)
  mutatedVariant.schemas.find((entry) => entry.schema_file === 'custody-adapter-message-v1.schema.json').variants[1].selector.message_kind_code = 'request'
  assert.throws(() => assertFieldRegistry(mutatedVariant, registry, fieldSchemaNames), /FIELD_REGISTRY_INVALID/)
  cases.push('overlapping-variant-producer')
  const overlappingFieldOverride = structuredClone(fieldRegistry)
  overlappingFieldOverride.schemas.find((entry) => entry.schema_file === 'runtime-profile-v1.schema.json').overrides.push({ json_pointer_pattern: '/migration_hashes/*/sha256', confidentiality: 'restricted_operational' })
  assert.throws(() => assertFieldRegistry(overlappingFieldOverride, registry, fieldSchemaNames), /FIELD_REGISTRY_INVALID/)
  cases.push('overlapping-field-override')
  const validProducerSubstitution = structuredClone(fieldRegistry)
  validProducerSubstitution.schemas.find((entry) => entry.schema_file === 'runtime-profile-v1.schema.json').default.trusted_producers = ['system_administrator']
  assert.throws(() => assertFieldRegistry(validProducerSubstitution, registry, fieldSchemaNames), /FIELD_REGISTRY_INVALID/)
  cases.push('valid-but-wrong-producer-substitution')
  const validStorageSubstitution = structuredClone(fieldRegistry)
  validStorageSubstitution.schemas.find((entry) => entry.schema_file === 'runtime-profile-v1.schema.json').default.storage = 'protected_identity_binding_store_outside_git_and_sqlite'
  assert.throws(() => assertFieldRegistry(validStorageSubstitution, registry, fieldSchemaNames), /FIELD_REGISTRY_INVALID/)
  cases.push('valid-but-wrong-storage-substitution')
  const missingDigest = structuredClone(digestProfiles)
  missingDigest.digest_bindings = missingDigest.digest_bindings.filter((binding) => binding.binding_code !== 'runtime.self')
  assert.throws(() => assertDigestProfiles(missingDigest, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('missing-pointer-scoped-digest-binding')
  const duplicateDigest = structuredClone(digestProfiles)
  duplicateDigest.digest_bindings.push({ ...structuredClone(duplicateDigest.digest_bindings[0]), binding_code: 'mutation.ambiguous-runtime-self' })
  assert.throws(() => assertDigestProfiles(duplicateDigest, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('ambiguous-pointer-scoped-digest-binding')
  const unusedDigestPointer = structuredClone(digestProfiles)
  unusedDigestPointer.digest_bindings.find((binding) => binding.binding_code === 'runtime.self').json_pointer_patterns.push('/not/a/sha256')
  assert.throws(() => assertDigestProfiles(unusedDigestPointer, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('unused-digest-pointer-pattern')
  const unknownDigestResolver = structuredClone(digestProfiles)
  unknownDigestResolver.digest_bindings.find((binding) => binding.binding_code === 'runtime.self').resolver_code = 'unknown_resolver_v1'
  assert.throws(() => assertDigestProfiles(unknownDigestResolver, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('unknown-digest-resolver')
  const validResolverSubstitution = structuredClone(digestProfiles)
  const runtimeBinding = validResolverSubstitution.digest_bindings.find((binding) => binding.binding_code === 'bindings.runtime')
  const handoffBinding = validResolverSubstitution.digest_bindings.find((binding) => binding.binding_code === 'handoff.bindings')
  ;[runtimeBinding.resolver_code, handoffBinding.resolver_code] = [handoffBinding.resolver_code, runtimeBinding.resolver_code]
  assert.throws(() => assertDigestProfiles(validResolverSubstitution, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('valid-but-wrong-resolver-substitution')
  const validProfileSubstitution = structuredClone(digestProfiles)
  const stateRecordBinding = validProfileSubstitution.digest_bindings.find((binding) => binding.binding_code === 'handoff.state-record')
  const statePayloadBinding = validProfileSubstitution.digest_bindings.find((binding) => binding.binding_code === 'handoff.state')
  ;[stateRecordBinding.payload_profile_code, statePayloadBinding.payload_profile_code] = [statePayloadBinding.payload_profile_code, stateRecordBinding.payload_profile_code]
  assert.throws(() => assertDigestProfiles(validProfileSubstitution, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('valid-but-wrong-profile-substitution')
  for (const [field, replacement] of [
    ['input_code', 'different_frozen_input'],
    ['projection_code', 'different_frozen_projection'],
    ['ordering_code', 'different_frozen_ordering'],
    ['retention_code', 'different_frozen_retention'],
  ]) {
    const changedProfileSemantics = structuredClone(digestProfiles)
    changedProfileSemantics.payload_profiles.find((profile) => profile.profile_code === 'canonical_custody_leaf_projection_v1')[field] = replacement
    assert.throws(() => assertDigestProfiles(changedProfileSemantics, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
    cases.push(`changed-payload-profile-${field}`)
  }
  const weakenedByteSource = structuredClone(digestProfiles)
  weakenedByteSource.external_byte_source_contract.extent_code = 'caller_selected'
  assert.throws(() => assertDigestProfiles(weakenedByteSource, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('weakened-external-byte-source')
  const changedByteResolver = structuredClone(digestProfiles)
  changedByteResolver.external_byte_source_contract.resolver_definitions[0].selection_code = 'some_other_valid_selection'
  assert.throws(() => assertDigestProfiles(changedByteResolver, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('changed-external-byte-resolver')
  const missingSqliteProjection = structuredClone(digestProfiles)
  missingSqliteProjection.sqlite_projections.table_rows.projections.pop()
  assert.throws(() => assertDigestProfiles(missingSqliteProjection, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('missing-sqlite-table-projection')
  const mismatchedSqliteProjection = structuredClone(digestProfiles)
  mismatchedSqliteProjection.sqlite_projections.table_rows.projections.find((projection) => projection.table_code === 'actors').columns.pop()
  assert.throws(() => assertDigestProfiles(mismatchedSqliteProjection, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('mismatched-sqlite-table-ordering')
  const missingLegacyObject = structuredClone(digestProfiles)
  missingLegacyObject.sqlite_projections.schema_inventories.find((projection) => projection.projection_code === 'legacy_schema').included_objects.pop()
  assert.throws(() => assertDigestProfiles(missingLegacyObject, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('missing-legacy-schema-object')
  const changedLegacyProjection = structuredClone(digestProfiles)
  changedLegacyProjection.sqlite_projections.schema_inventories.find((projection) => projection.projection_code === 'legacy_schema').select_sql += ' '
  assert.throws(() => assertDigestProfiles(changedLegacyProjection, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('changed-legacy-schema-projection')
  const wildcardPrefixProjection = structuredClone(digestProfiles)
  wildcardPrefixProjection.sqlite_projections.schema_inventories.find((projection) => projection.projection_code === 'legacy_schema').select_sql = "SELECT type,name,tbl_name AS table_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND name NOT LIKE 'atlas_%' AND name NOT IN ('schema_migrations','migration_checksums') ORDER BY type COLLATE BINARY ASC,name COLLATE BINARY ASC"
  assert.throws(() => assertDigestProfiles(wildcardPrefixProjection, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('wildcard-prefix-schema-filter')
  const changedProhibitedSurface = structuredClone(digestProfiles)
  changedProhibitedSurface.sqlite_projections.prohibited_surfaces.items[0].exact_content_sha256 = '0'.repeat(64)
  assert.throws(() => assertDigestProfiles(changedProhibitedSurface, registry, digestSchemaNames), /DIGEST_PROFILE_INVALID/)
  cases.push('changed-prohibited-surface-content')
  const incompleteClassification = structuredClone(classification)
  incompleteClassification.custody_message_rules.pop()
  incompleteClassification.record_digest_sha256 = recordDigest(incompleteClassification)
  assert.throws(() => assertClassificationRegistry(incompleteClassification), /REGISTRY_INVALID/)
  cases.push('incomplete-custody-classification')
  for (const [label, mutate] of [
    ['changed-role-endpoint-mode-matrix', (value) => { value.runtime_role_binding_rules.find((rule) => rule.runtime_role_code === 'journal_broker').ipc_endpoint_code = 'ipc.importer' }],
    ['changed-logical-handle-recipient-matrix', (value) => { value.logical_handle_slot_rules.find((rule) => rule.slot_code === 'operation_journal').recipients[0].runtime_role_code = 'bundle_importer' }],
    ['changed-custody-capability-lifetime', (value) => { value.custody_capability_rules.find((rule) => rule.capability_kind_code === 'source_handle').lifetime_ms_max += 1 }],
    ['changed-custody-capability-transition', (value) => { value.custody_capability_transition_rules.find((rule) => rule.capability_kind_code === 'source_handle').consumer_operation_code = 'open_custody' }],
    ['changed-pilot-custody-purpose', (value) => { value.pilot_custody_purpose_rules[0].allowed_purpose_codes.push('processing') }],
    ['changed-bootstrap-permit-lifetime', (value) => { value.bootstrap_permit_policy.maximum_lifetime_ms += 1 }],
    ['changed-recovery-permit-lifetime', (value) => { value.recovery_permit_policy.maximum_lifetime_ms += 1 }],
    ['changed-clearance-context-binding', (value) => { value.clearance_context_binding_policy.clearance_scope_policy_code = 'caller_asserted' }],
    ['changed-journal-stage-origin', (value) => { value.journal_stage_origin_rules.find((rule) => rule.stage_code === 'promotion').runtime_role_code = 'bundle_importer' }],
    ['changed-journal-event-origin', (value) => { value.journal_event_origin_rules.find((rule) => rule.event_kind_code === 'candidate_committed').runtime_role_code = 'bundle_importer' }],
    ['changed-stage-failure-history-policy', (value) => { value.journal_history_rules.find((rule) => rule.result_outcome_code === 'recovery_required').stage_failure_milestone_policy_code = 'forbidden' }],
    ['changed-operation-completed-observed-policy', (value) => { value.journal_event_rules.find((rule) => rule.event_kind_code === 'operation_completed').observed_state_policy = 'optional' }],
    ['changed-result-error-partition', (value) => {
      const code = value.result_error_rules[0].allowed_error_codes.pop()
      value.result_error_rules[1].allowed_error_codes.push(code)
    }],
    ['widened-recovered-canonical-effect', (value) => {
      value.outcome_rules.find((rule) => rule.outcome === 'recovered').allowed_canonical_effects.push('promoted_verified')
      value.result_rules.find((rule) => rule.outcome === 'recovered').allowed_canonical_effects.push('promoted_verified')
    }],
  ]) {
    const mutated = structuredClone(classification)
    mutate(mutated)
    mutated.record_digest_sha256 = recordDigest(mutated)
    assert.throws(() => assertClassificationRegistry(mutated), /REGISTRY_INVALID/)
    cases.push(label)
  }
  const unknownJournalPolicy = structuredClone(classification)
  unknownJournalPolicy.journal_event_rules.find((rule) => rule.event_kind_code === 'candidate_committed').rows_policy = 'sometimes'
  unknownJournalPolicy.record_digest_sha256 = recordDigest(unknownJournalPolicy)
  assert.throws(() => assertClassificationRegistry(unknownJournalPolicy), /REGISTRY_INVALID/)
  cases.push('unknown-journal-policy')
  const resurrectedPermit = structuredClone(classification)
  resurrectedPermit.permit_transition_rules.push({ ...structuredClone(resurrectedPermit.permit_transition_rules.find((rule) => rule.permit_kind_code === 'bootstrap' && rule.from_state_code === 'ready' && rule.to_state_code === 'in_progress')), from_state_code: 'spent' })
  resurrectedPermit.record_digest_sha256 = recordDigest(resurrectedPermit)
  assert.throws(() => assertClassificationRegistry(resurrectedPermit), /REGISTRY_INVALID/)
  cases.push('terminal-permit-resurrection')
  const overlappingResult = structuredClone(classification)
  overlappingResult.result_rules.push(structuredClone(overlappingResult.result_rules.find((rule) => rule.outcome === 'imported' && rule.allowed_operation_modes.includes('bootstrap'))))
  overlappingResult.record_digest_sha256 = recordDigest(overlappingResult)
  assert.throws(() => assertClassificationRegistry(overlappingResult), /REGISTRY_INVALID/)
  cases.push('overlapping-result-rule')
  const impossibleResult = structuredClone(classification)
  impossibleResult.result_rules.find((rule) => rule.outcome === 'rejected' && rule.allowed_operation_modes.includes('bootstrap') && !rule.allowed_bundle_kinds.includes('null')).allowed_bundle_kinds.push('single_document')
  impossibleResult.record_digest_sha256 = recordDigest(impossibleResult)
  assert.throws(() => assertClassificationRegistry(impossibleResult), /REGISTRY_INVALID/)
  cases.push('impossible-result-mode-bundle-pair')
  const reorderedSet = structuredClone(classification)
  reorderedSet.result_rules.find((rule) => rule.outcome === 'rejected' && rule.allowed_bundle_kinds.includes('null')).allowed_operation_modes.reverse()
  reorderedSet.record_digest_sha256 = recordDigest(reorderedSet)
  assert.throws(() => assertClassificationRegistry(reorderedSet), /REGISTRY_INVALID/)
  cases.push('reordered-result-set')
  return cases
}

function assertGeneratedStateMatrices(fixtures, registry, classification) {
  const value = (code) => structuredClone(fixtures.get(code).value)
  const runtime = value('runtime_profile')
  const bindings = value('identity_bindings')
  const bootstrapPermit = value('bootstrap_permit')
  const bootstrapClaim = value('bootstrap_transition_in_progress')
  const bootstrapTerminal = value('bootstrap_transition_spent')
  const recoveryPermitFixture = value('recovery_permit')
  const recoveryClaim = value('recovery_transition_in_progress')
  const recoveryTerminal = value('recovery_transition_spent')
  const completionPermitFixture = value('post_promotion_completion_permit')
  const completionClaim = value('post_promotion_completion_transition_in_progress')
  const completionTerminal = value('post_promotion_completion_transition_spent')
  const bootstrapCompletionPermit = value('post_promotion_bootstrap_completion_permit')
  const bootstrapCompletionClaim = value('post_promotion_bootstrap_completion_transition_in_progress')
  const bootstrapCompletionTerminal = value('post_promotion_bootstrap_completion_transition_spent')
  const bootstrapSeal = value('bootstrap_bundle_seal')
  const documentSeal = value('document_bundle_seal')
  const emptyState = value('logical_state_empty')
  const bootstrapState = value('logical_state_bootstrap')
  const documentState = value('logical_state_document_002')
  const replayCertificate = value('replay_certificate')
  const prepromotionAuthorization = value('prepromotion_authorization')
  const prepromotionClearance = value('clearance_decision')
  const prepromotionHandoff = value('collector_handoff')
  const prepromotionManifest = parseJsonBytes(fs.readFileSync(completeDocumentManifestPath), { contractNumbers: true, maximumBytes: pilotLimits.manifest_bytes_max })
  const bootstrapManifest = loadJson(goldenVectorsPath).complete_manifest_vector.value
  const journalEvents = [...fixtures.values()].filter((fixture) => fixture.schema_file === 'operation-journal-event-v1.schema.json').map((fixture) => structuredClone(fixture.value))
  const candidateSeals = [...fixtures.values()].filter((fixture) => fixture.schema_file === 'logical-state-seal-v1.schema.json' && fixture.value.record_kind_code === 'candidate_file_seal').map((fixture) => structuredClone(fixture.value))
  const emptyReference = { state_seal_code: emptyState.record_code, state_seal_record_digest_sha256: emptyState.record_digest_sha256, logical_state_sha256: emptyState.logical_state_sha256 }
  const authorizationControls = {
    bindings,
    runtime,
    permits: new Map([bootstrapPermit, recoveryPermitFixture, completionPermitFixture, bootstrapCompletionPermit].map((item) => [item.record_digest_sha256, item])),
    transitions: new Map([bootstrapClaim, bootstrapTerminal, recoveryClaim, recoveryTerminal, completionClaim, completionTerminal, bootstrapCompletionClaim, bootstrapCompletionTerminal].map((item) => [item.record_digest_sha256, item])),
    bundleReferences: new Map([
      [bundleResolverKey('principal_bootstrap', bootstrapSeal.bundle), structuredClone(bootstrapSeal.bundle)],
      [bundleResolverKey('single_document', documentSeal.bundle), structuredClone(documentSeal.bundle)],
    ]),
    bootstrapManifests: new Map([[bundleResolverKey('principal_bootstrap', bootstrapSeal.bundle), bootstrapManifest]]),
    logicalStateRecords: new Map([emptyState, bootstrapState, documentState].map((state) => [state.record_digest_sha256, state])),
    bundleSeals: new Map([bootstrapSeal, documentSeal].map((item) => [item.record_digest_sha256, item])),
    replayCertificates: new Map([[replayCertificate.record_digest_sha256, replayCertificate]]),
    journalEvents: new Map(journalEvents.map((item) => [item.record_digest_sha256, item])),
    candidateSeals: new Map(candidateSeals.map((item) => [item.record_digest_sha256, item])),
    prepromotionAuthorizations: new Map([[prepromotionAuthorization.record_digest_sha256, prepromotionAuthorization]]),
    clearances: new Map([[prepromotionClearance.record_digest_sha256, prepromotionClearance]]),
    handoffs: new Map([[prepromotionHandoff.record_digest_sha256, prepromotionHandoff]]),
    clearanceTransitions: [],
    clearanceReplacements: new Map(),
    custodyRecords: custodyRecordsFromManifest(prepromotionManifest),
    currentBundleSequence: prepromotionManifest.bundle_sequence,
    journalTargetStates: new Map([
      [bootstrapPermit.record_digest_sha256, structuredClone(emptyReference)],
      [recoveryPermitFixture.record_digest_sha256, structuredClone(recoveryPermitFixture.target_empty_logical_state)],
      [completionPermitFixture.record_digest_sha256, structuredClone(completionPermitFixture.verified_canonical_logical_state)],
      [bootstrapCompletionPermit.record_digest_sha256, structuredClone(bootstrapCompletionPermit.verified_canonical_logical_state)],
    ]),
    permitTerminalStates: new Map([
      [bootstrapPermit.record_digest_sha256, { state_seal_code: bootstrapState.record_code, state_seal_record_digest_sha256: bootstrapState.record_digest_sha256, logical_state_sha256: bootstrapState.logical_state_sha256 }],
      [recoveryPermitFixture.record_digest_sha256, structuredClone(recoveryPermitFixture.accepted_logical_state)],
      [completionPermitFixture.record_digest_sha256, structuredClone(completionPermitFixture.verified_canonical_logical_state)],
      [bootstrapCompletionPermit.record_digest_sha256, structuredClone(bootstrapCompletionPermit.verified_canonical_logical_state)],
    ]),
  }
  const wrongLineagePermit = structuredClone(completionPermitFixture)
  wrongLineagePermit.canonical_lineage_code = 'synthetic.other-lineage'
  const expectedLineage = value('logical_state_document_002').state_payload.canonical_lineage_code
  assert.throws(() => assertCanonicalLineage(expectedLineage, [wrongLineagePermit.canonical_lineage_code]), /LOGICAL_STATE_MISMATCH/)
  const permitRoot = value('bootstrap_transition_in_progress')
  const competingPermitRoot = structuredClone(permitRoot)
  competingPermitRoot.record_code = 'synthetic.permit-transition-competing'
  competingPermitRoot.record_digest_sha256 = recordDigest(competingPermitRoot)
  assert.throws(() => assertUniquePermitSuccessors([permitRoot, competingPermitRoot]), /duplicate permit predecessor successor/)
  const preactivationWithdrawals = []
  for (const [kind, issuanceCode, authorityRole, authorityBinding, notBefore, occurredAt, targetReference, targetProducedAt] of [
    ['bootstrap', 'bootstrap_permit', 'bootstrap_authority', 'binding.bootstrap-authority', '2030-01-01T00:05:10.000Z', '2030-01-01T00:05:05.000Z', emptyReference, emptyState.produced_at],
    ['recovery', 'recovery_permit', 'recovery_authority', 'binding.recovery-authority', '2030-01-01T00:06:12.000Z', '2030-01-01T00:06:07.000Z', recoveryPermitFixture.target_empty_logical_state, emptyState.produced_at],
    ['post_promotion_completion', 'post_promotion_completion_permit', 'recovery_authority', 'binding.recovery-authority', '2030-01-01T00:10:10.000Z', '2030-01-01T00:10:05.000Z', completionPermitFixture.verified_canonical_logical_state, documentState.produced_at],
  ]) {
    const issuance = value(issuanceCode)
    issuance.not_before = notBefore
    issuance.record_digest_sha256 = recordDigest(issuance)
    const withdrawal = structuredClone(permitRoot)
    withdrawal.record_code = `synthetic.${kind}-preactivation-withdrawal`
    withdrawal.permit_kind_code = kind
    withdrawal.permit_code = issuance.permit_code
    withdrawal.permit_issuance_record_digest_sha256 = issuance.record_digest_sha256
    withdrawal.transition_sequence = 1
    withdrawal.previous_transition_record_digest_sha256 = null
    withdrawal.from_state_code = 'ready'
    withdrawal.to_state_code = 'revoked'
    withdrawal.transition_code = 'authority_withdrawal'
    withdrawal.operation_id = kind === 'recovery' ? issuance.operation_id : 'synthetic.operation-revocation'
    if (kind === 'post_promotion_completion') withdrawal.operation_id = issuance.operation_id
    withdrawal.operation_nonce = issuance.operation_nonce
    withdrawal.observed_logical_state = structuredClone(targetReference)
    withdrawal.recovery_permit_record_digest_sha256 = null
    withdrawal.completion_journal_head_record_digest_sha256 = null
    withdrawal.recorded_by_runtime_role_code = authorityRole
    withdrawal.recorded_by_binding_code = authorityBinding
    withdrawal.occurred_at = occurredAt
    withdrawal.persisted_at = new Date(Date.parse(occurredAt) + 1).toISOString()
    withdrawal.reason_code = 'authority_withdrawal'
    withdrawal.record_digest_sha256 = recordDigest(withdrawal)
    validateContractStructure(withdrawal, 'bootstrap-control-v1.schema.json', registry)
    assertPermitTransition(withdrawal, issuance, null, targetReference, null, bindings, classification, targetProducedAt)
    const withdrawalControls = {
      ...authorizationControls,
      transitions: new Map([...authorizationControls.transitions, [withdrawal.record_digest_sha256, withdrawal]]),
      journalTargetStates: new Map([...authorizationControls.journalTargetStates, [issuance.record_digest_sha256, structuredClone(targetReference)]]),
    }
    const lifecycle = resolvePermitTransitionChain(issuance, withdrawalControls, classification)
    if (lifecycle.claim !== null || lifecycle.terminal?.record_digest_sha256 !== withdrawal.record_digest_sha256 || lifecycle.derivedStateCode !== 'revoked') fail('fixture', 'FIXTURE_INVALID', `${kind} pre-activation withdrawal did not resolve as a terminal revoked root`)
    if (resolvePermitTransitionChain(issuance, withdrawalControls, classification, withdrawal.occurred_at).derivedStateCode !== 'ready') fail('fixture', 'FIXTURE_INVALID', `${kind} withdrawal was visible before its protected persistence time`)
    if (resolvePermitTransitionChain(issuance, withdrawalControls, classification, withdrawal.persisted_at).derivedStateCode !== 'revoked') fail('fixture', 'FIXTURE_INVALID', `${kind} withdrawal was not visible at its protected persistence time`)
    for (const mutate of [
      (item) => { item.recorded_by_runtime_role_code = 'trusted_launcher' },
      (item) => { item.recorded_by_binding_code = 'binding.launcher' },
      (item) => { item.occurred_at = '2029-12-31T23:59:59.999Z' },
      (item) => { item.occurred_at = issuance.expires_at },
    ]) {
      const invalid = structuredClone(withdrawal)
      mutate(invalid)
      assert.throws(() => assertPermitTransition(invalid, issuance, null, targetReference, null, bindings, classification, targetProducedAt), /BOOTSTRAP_PERMIT_INVALID|IDENTITY_BINDING_MISMATCH/)
    }
    preactivationWithdrawals.push(kind)
  }
  const boundedRecovery = value('recovery_permit')
  const replayForWindow = value('replay_certificate')
  assert.doesNotThrow(() => assertRecoveryPermitWindow(boundedRecovery, replayForWindow, bindings, classification))
  for (const mutate of [
    (item) => { item.expires_at = new Date(Date.parse(item.issued_at) + classification.recovery_permit_policy.maximum_lifetime_ms + 1).toISOString() },
    (item) => { item.expires_at = new Date(Date.parse(replayForWindow.expires_at) + 1).toISOString() },
    (item) => { item.expires_at = new Date(Date.parse(bindings.expires_at) + 1).toISOString() },
    (item) => { item.issued_at = new Date(Date.parse(replayForWindow.issued_at) - 1).toISOString() },
    (item) => { item.not_before = item.expires_at },
  ]) {
    const invalid = structuredClone(boundedRecovery)
    mutate(invalid)
    assert.throws(() => assertRecoveryPermitWindow(invalid, replayForWindow, bindings, classification), /RECOVERY_PERMIT_INVALID/)
  }
  const zeroRows = () => Object.fromEntries(Object.keys(value('import_result_success').rows_inserted).map((key) => [key, 0]))
  const zeroObjects = () => ({ prepared: 0, reused: 0, orphaned: 0 })
  const allChecks = (status) => Object.fromEntries(Object.keys(value('import_result_success').checks).map((key) => [key, status]))
  const errorFor = (code) => {
    const rule = errorRule(classification, code)
    return { stage: rule.stage, code, message: rule.safe_message, retryable: rule.retryable, retryability_code: rule.retryability_code, recovery_class_code: rule.recovery_class_code }
  }
  const resultCases = []
  for (const rule of classification.result_rules) {
    for (const operationMode of rule.allowed_operation_modes) for (const configuredBundleKind of rule.allowed_bundle_kinds) {
      const result = value('import_result_success')
      const bundleKind = configuredBundleKind === 'null' ? null : configuredBundleKind
      result.outcome = rule.outcome
      result.operation_mode_code = operationMode
      result.bundle_kind_code = bundleKind
      if (bundleKind === null) result.bundle_id = result.bundle_sequence = result.bundle_digest_sha256 = null
      else if (bundleKind === 'principal_bootstrap') {
        result.bundle_id = 'synthetic.bootstrap-bundle'
        result.bundle_sequence = 1
        result.bundle_digest_sha256 = '327c4ce915f9ca9b69193ccb86c89a1d11a2395d36f7088ae256fa228e566875'
      } else {
        result.bundle_id = 'synthetic.bundle-002'
        result.bundle_sequence = 2
        result.bundle_digest_sha256 = completionPermitFixture.target_bundle.bundle_digest_sha256
      }
      result.bootstrap_principals_inserted = 0
      result.rows_inserted = zeroRows()
      result.objects = zeroObjects()
      result.checks = allChecks('passed')
      result.canonical_effect_code = rule.allowed_canonical_effects[0]
      result.recovery_permit_record_digest_sha256 = null
      result.recovery_terminal_transition_record_digest_sha256 = null
      result.error = null
      if (rule.count_policy === 'bootstrap_exact') {
        result.bootstrap_principals_inserted = pilotBundleShape.bootstrap_principals_exact
        result.rows_inserted.atlas_evidence_bundle_receipts = 1
      } else if (rule.count_policy === 'document_exact') {
        result.rows_inserted.atlas_evidence_bundle_receipts = 1
        result.rows_inserted.atlas_retrieval_locations = 1
        result.rows_inserted.atlas_artifacts = 1
        result.rows_inserted.atlas_retrieval_events = 1
        result.rows_inserted.atlas_artifact_custody_events = 1
        result.objects.prepared = 1
      } else if (rule.count_policy === 'rows_zero_objects_orphan_only') {
        result.objects.orphaned = 1
      } else if (rule.count_policy === 'unknown_allowed') {
        result.bootstrap_principals_inserted = result.rows_inserted = result.objects = null
      }
      if (rule.check_policy === 'plan_passed') {
        result.checks = allChecks('not_run')
        for (const key of ['manifest', 'runtime_binding', 'screening', 'clearance']) result.checks[key] = 'passed'
      } else if (rule.check_policy === 'failed_or_early_all_not_run') {
        result.checks = allChecks('not_run')
        if (bundleKind === null) result.error = errorFor('AUTHENTICATION_FAILED')
        else {
          for (const key of ['manifest', 'runtime_binding', 'screening']) result.checks[key] = 'passed'
          result.checks.clearance = 'failed'
          result.error = errorFor('CLEARANCE_INVALID')
        }
      } else if (rule.check_policy === 'ambiguity_visible') {
        result.checks = allChecks('not_run')
        result.checks.manifest = 'passed'
        result.error = errorFor('PROMOTION_STATE_AMBIGUOUS')
      } else if (rule.check_policy === 'recovery_verified') {
        result.checks = allChecks('not_run')
        for (const key of ['manifest', 'runtime_binding', 'projection', 'integrity', 'foreign_keys', 'forbidden_surfaces']) result.checks[key] = 'passed'
      }
      if (result.error) result.canonical_effect_code = errorEffectRule(classification, result.error.code).canonical_effect_code
      if (rule.outcome === 'recovered') {
        const permitFixture = bundleKind === 'single_document' ? value('post_promotion_completion_permit') : value('recovery_permit')
        const terminalFixture = bundleKind === 'single_document' ? value('post_promotion_completion_transition_spent') : value('recovery_transition_spent')
        result.operation_id = permitFixture.operation_id
        result.recovery_permit_record_digest_sha256 = permitFixture.record_digest_sha256
        result.recovery_terminal_transition_record_digest_sha256 = terminalFixture.record_digest_sha256
      }
      validateContractStructure(result, 'importer-result-v1.schema.json', registry)
      assertImporterResult(result, classification, authorizationControls)
      resultCases.push(`${rule.outcome}/${result.operation_mode_code}/${result.bundle_kind_code}`)
    }
  }
  const expectedResultCases = classification.result_rules.flatMap((rule) => rule.allowed_operation_modes.flatMap((mode) => rule.allowed_bundle_kinds.map((kind) => `${rule.outcome}/${mode}/${kind}`)))
  if (canonical(resultCases.toSorted()) !== canonical(expectedResultCases.toSorted())) fail('fixture', 'FIXTURE_INVALID', 'generated importer-result matrix is incomplete')
  const ordinaryBundleMutations = []
  for (const [field, replacement] of [['bundle_id', 'synthetic.other-bundle'], ['bundle_sequence', 3], ['bundle_digest_sha256', '9'.repeat(64)]]) {
    const invalid = value('import_result_success')
    invalid[field] = replacement
    assert.throws(() => assertImporterResult(invalid, classification, authorizationControls), /INTERNAL_CONTRACT_VIOLATION/)
    ordinaryBundleMutations.push(`ordinary-result-${field}`)
  }
  const lateFailureWithoutBundle = value('import_result_success')
  lateFailureWithoutBundle.outcome = 'rejected'
  lateFailureWithoutBundle.operation_mode_code = 'document_import'
  lateFailureWithoutBundle.bundle_kind_code = null
  lateFailureWithoutBundle.bundle_id = null
  lateFailureWithoutBundle.bundle_sequence = null
  lateFailureWithoutBundle.bundle_digest_sha256 = null
  lateFailureWithoutBundle.bootstrap_principals_inserted = 0
  lateFailureWithoutBundle.rows_inserted = zeroRows()
  lateFailureWithoutBundle.objects = zeroObjects()
  lateFailureWithoutBundle.checks = allChecks('not_run')
  lateFailureWithoutBundle.checks.clearance = 'failed'
  lateFailureWithoutBundle.canonical_effect_code = 'none_verified'
  lateFailureWithoutBundle.error = errorFor('CLEARANCE_INVALID')
  assert.throws(() => assertImporterResult(lateFailureWithoutBundle, classification, authorizationControls), /bundle identity presence differs from the error-specific policy/)
  ordinaryBundleMutations.push('late-rejection-without-validated-bundle')
  const earlyFailureWithBundle = value('import_result_success')
  earlyFailureWithBundle.outcome = 'rejected'
  earlyFailureWithBundle.operation_mode_code = 'document_import'
  earlyFailureWithBundle.bootstrap_principals_inserted = 0
  earlyFailureWithBundle.rows_inserted = zeroRows()
  earlyFailureWithBundle.objects = zeroObjects()
  earlyFailureWithBundle.checks = allChecks('not_run')
  earlyFailureWithBundle.canonical_effect_code = 'none_verified'
  earlyFailureWithBundle.error = errorFor('AUTHENTICATION_FAILED')
  assert.throws(() => assertImporterResult(earlyFailureWithBundle, classification, authorizationControls), /bundle identity presence differs from the error-specific policy/)
  ordinaryBundleMutations.push('early-rejection-with-untrusted-bundle')
  const overAuthorizedRecovery = value('import_result_success')
  overAuthorizedRecovery.outcome = 'recovered'
  overAuthorizedRecovery.operation_mode_code = 'recovery'
  overAuthorizedRecovery.canonical_effect_code = 'promoted_verified'
  overAuthorizedRecovery.recovery_permit_record_digest_sha256 = value('recovery_permit').record_digest_sha256
  overAuthorizedRecovery.recovery_terminal_transition_record_digest_sha256 = value('recovery_transition_spent').record_digest_sha256
  assert.throws(() => assertImporterResult(overAuthorizedRecovery, classification, authorizationControls), /INTERNAL_CONTRACT_VIOLATION/)
  for (const [label, mutate] of [
    ['recovered-missing-permit', (item) => { item.recovery_permit_record_digest_sha256 = null }],
    ['recovered-missing-terminal-transition', (item) => { item.recovery_terminal_transition_record_digest_sha256 = null }],
    ['ordinary-result-with-recovery-authority', (item) => { item.outcome = 'no_op'; item.operation_mode_code = 'no_op_verification' }],
    ['post-promotion-recovery-with-row-effect', (item) => { item.rows_inserted.atlas_evidence_bundle_receipts = 1 }],
    ['post-promotion-recovery-with-custody-effect', (item) => { item.objects.reused = 1 }],
  ]) {
    const invalid = value('import_result_recovered')
    mutate(invalid)
    assert.throws(() => assertImporterResult(invalid, classification, authorizationControls), /INTERNAL_CONTRACT_VIOLATION/, `${label} unexpectedly passed`)
  }
  const recoveredAuthorizationMutations = []
  const rejectRecoveredMutation = (label, mutateResult, mutateControls = null) => {
    const invalid = value('import_result_recovered')
    mutateResult(invalid)
    const controls = mutateControls ? mutateControls(authorizationControls) : authorizationControls
    assert.throws(() => assertImporterResult(invalid, classification, controls), /INTERNAL_CONTRACT_VIOLATION|RECOVERY_STATE_AMBIGUOUS|RECORD_DIGEST_MISMATCH|BOOTSTRAP_PERMIT_INVALID/, `${label} unexpectedly passed`)
    recoveredAuthorizationMutations.push(label)
  }
  rejectRecoveredMutation('unresolved-recovery-permit', (item) => { item.recovery_permit_record_digest_sha256 = '8'.repeat(64) })
  rejectRecoveredMutation('swapped-recovery-terminal', (item) => { item.recovery_terminal_transition_record_digest_sha256 = recoveryTerminal.record_digest_sha256 })
  rejectRecoveredMutation('wrong-kind-recovery-pair', (item) => {
    item.operation_id = recoveryPermitFixture.operation_id
    item.recovery_permit_record_digest_sha256 = recoveryPermitFixture.record_digest_sha256
    item.recovery_terminal_transition_record_digest_sha256 = recoveryTerminal.record_digest_sha256
  })
  rejectRecoveredMutation('nonterminal-recovery-head', () => {}, (controls) => {
    const successor = structuredClone(completionTerminal)
    successor.record_digest_sha256 = '7'.repeat(64)
    successor.previous_transition_record_digest_sha256 = completionTerminal.record_digest_sha256
    return { ...controls, transitions: new Map([...controls.transitions, [successor.record_digest_sha256, successor]]) }
  })
  const fakeJournalHeadTerminal = structuredClone(completionTerminal)
  fakeJournalHeadTerminal.completion_journal_head_record_digest_sha256 = '8'.repeat(64)
  fakeJournalHeadTerminal.record_digest_sha256 = recordDigest(fakeJournalHeadTerminal)
  rejectRecoveredMutation('unresolved-completion-journal-head', (item) => { item.recovery_terminal_transition_record_digest_sha256 = fakeJournalHeadTerminal.record_digest_sha256 }, (controls) => ({
    ...controls,
    transitions: new Map([...controls.transitions].filter(([digest]) => digest !== completionTerminal.record_digest_sha256).concat([[fakeJournalHeadTerminal.record_digest_sha256, fakeJournalHeadTerminal]])),
  }))
  const swappedJournalHeadTerminal = structuredClone(completionTerminal)
  swappedJournalHeadTerminal.completion_journal_head_record_digest_sha256 = value('journal_bootstrap_completion_completed').record_digest_sha256
  swappedJournalHeadTerminal.record_digest_sha256 = recordDigest(swappedJournalHeadTerminal)
  rejectRecoveredMutation('swapped-completion-journal-head', (item) => { item.recovery_terminal_transition_record_digest_sha256 = swappedJournalHeadTerminal.record_digest_sha256 }, (controls) => ({
    ...controls,
    transitions: new Map([...controls.transitions].filter(([digest]) => digest !== completionTerminal.record_digest_sha256).concat([[swappedJournalHeadTerminal.record_digest_sha256, swappedJournalHeadTerminal]])),
  }))
  let terminalErrorCrossProduct = 0
  for (const outcome of ['rejected', 'recovery_required']) for (const error of classification.error_rules) {
    const allowed = classification.result_error_rules.find((rule) => rule.result_outcome_code === outcome).allowed_error_codes.includes(error.code)
    if (allowed) assert.doesNotThrow(() => assertResultErrorCompatibility(outcome, error.code, classification))
    else assert.throws(() => assertResultErrorCompatibility(outcome, error.code, classification), /INTERNAL_CONTRACT_VIOLATION/)
    terminalErrorCrossProduct += 1
  }
  let errorBundleReferenceCrossProduct = 0
  const referenceShapes = {
    none: [null, null, null, null],
    complete: ['single_document', 'synthetic.bundle-002', 2, completionPermitFixture.target_bundle.bundle_digest_sha256],
    partial: ['single_document', null, 2, completionPermitFixture.target_bundle.bundle_digest_sha256],
  }
  for (const error of classification.error_rules) {
    const policy = errorBundleReferenceRule(classification, error.code).bundle_reference_policy_code
    for (const [shape, references] of Object.entries(referenceShapes)) {
      const allowed = shape === 'none'
        ? ['forbidden', 'optional_all_or_none'].includes(policy)
        : shape === 'complete' ? ['required', 'optional_all_or_none'].includes(policy) : false
      if (allowed) assert.doesNotThrow(() => assertErrorBundleReferencePolicy(error.code, references, classification))
      else assert.throws(() => assertErrorBundleReferencePolicy(error.code, references, classification), /error-specific policy/)
      errorBundleReferenceCrossProduct += 1
    }
  }

  const historyEndingAt = (fixtureCode) => {
    const reverse = []
    const seen = new Set()
    let current = value(fixtureCode)
    while (current) {
      if (seen.has(current.record_digest_sha256)) fail('fixture', 'FIXTURE_INVALID', 'synthetic journal history contains a cycle')
      seen.add(current.record_digest_sha256)
      reverse.push(current)
      current = current.previous_event_record_digest_sha256 === null ? null : authorizationControls.journalEvents.get(current.previous_event_record_digest_sha256)
      if (current === undefined) fail('fixture', 'FIXTURE_INVALID', 'synthetic journal history lacks a predecessor')
    }
    return reverse.reverse()
  }
  const resealHistory = (history) => {
    let previous = null
    return history.map((source, index) => {
      const event = structuredClone(source)
      event.event_sequence = index + 1
      event.previous_event_record_digest_sha256 = previous?.record_digest_sha256 ?? null
      event.persisted_at = event.event_at
      event.record_digest_sha256 = recordDigest(event)
      previous = event
      return event
    })
  }
  const fullBootstrapHistory = historyEndingAt('journal_completed')
  const fullDocumentIncidentHistory = historyEndingAt('journal_document_recovery_required')
  assert.doesNotThrow(() => assertJournalHistory(fullBootstrapHistory, classification, bindings, runtime, authorizationControls))
  assert.doesNotThrow(() => assertJournalHistory(fullDocumentIncidentHistory, classification, bindings, runtime, authorizationControls))
  const journalTopologyMutations = []
  const branchedJournalEvent = structuredClone(fullBootstrapHistory[1])
  branchedJournalEvent.record_code = 'synthetic.journal-bootstrap-fork'
  branchedJournalEvent.event_at = new Date(Date.parse(branchedJournalEvent.event_at) + 1).toISOString()
  branchedJournalEvent.persisted_at = branchedJournalEvent.event_at
  branchedJournalEvent.record_digest_sha256 = recordDigest(branchedJournalEvent)
  const branchedJournalControls = { ...authorizationControls, journalEvents: new Map([...authorizationControls.journalEvents, [branchedJournalEvent.record_digest_sha256, branchedJournalEvent]]) }
  assert.throws(() => journalHistoryAtCurrentTerminal(fullBootstrapHistory.at(-1), branchedJournalControls, classification), /duplicate journal event sequence|duplicate journal predecessor successor|branched event/)
  journalTopologyMutations.push('sibling-successor-fork')
  const duplicateJournalRoot = structuredClone(fullBootstrapHistory[0])
  duplicateJournalRoot.record_code = 'synthetic.journal-bootstrap-second-root'
  duplicateJournalRoot.record_digest_sha256 = recordDigest(duplicateJournalRoot)
  const duplicateRootControls = { ...authorizationControls, journalEvents: new Map([...authorizationControls.journalEvents, [duplicateJournalRoot.record_digest_sha256, duplicateJournalRoot]]) }
  assert.throws(() => journalHistoryAtCurrentTerminal(fullBootstrapHistory.at(-1), duplicateRootControls, classification), /duplicate journal event sequence|duplicate journal predecessor successor|exactly one operation-start root/)
  journalTopologyMutations.push('duplicate-operation-root')
  const crossJournalSuccessor = structuredClone(fullBootstrapHistory[1])
  crossJournalSuccessor.record_code = 'synthetic.journal-cross-journal-successor'
  crossJournalSuccessor.journal_code = 'synthetic.other-journal'
  crossJournalSuccessor.event_at = new Date(Date.parse(crossJournalSuccessor.event_at) + 1).toISOString()
  crossJournalSuccessor.persisted_at = crossJournalSuccessor.event_at
  crossJournalSuccessor.record_digest_sha256 = recordDigest(crossJournalSuccessor)
  const crossJournalControls = { ...authorizationControls, journalEvents: new Map([...authorizationControls.journalEvents, [crossJournalSuccessor.record_digest_sha256, crossJournalSuccessor]]) }
  assert.throws(() => journalHistoryAtCurrentTerminal(fullBootstrapHistory.at(-1), crossJournalControls, classification), /cross-journal predecessor edge/)
  journalTopologyMutations.push('cross-journal-predecessor')

  const protectedTimeConsumerMutations = []
  const latePersistedClaim = structuredClone(bootstrapClaim)
  latePersistedClaim.persisted_at = new Date(Date.parse(value('journal_started').event_at) + 1).toISOString()
  latePersistedClaim.record_digest_sha256 = recordDigest(latePersistedClaim)
  const lateClaimConsumerControls = {
    ...authorizationControls,
    transitions: new Map([[latePersistedClaim.record_digest_sha256, latePersistedClaim]]),
  }
  assert.throws(() => assertJournalEvent(value('journal_started'), classification, bindings, runtime, lateClaimConsumerControls), /protected-time-visible claimed permit lifecycle/)
  protectedTimeConsumerMutations.push('journal-before-claim-persistence')
  const backdatedEventPersistedAtTerminal = value('journal_started')
  backdatedEventPersistedAtTerminal.persisted_at = bootstrapTerminal.persisted_at
  backdatedEventPersistedAtTerminal.record_digest_sha256 = recordDigest(backdatedEventPersistedAtTerminal)
  assert.throws(() => assertJournalEvent(backdatedEventPersistedAtTerminal, classification, bindings, runtime, authorizationControls), /protected-time-visible claimed permit lifecycle/)
  protectedTimeConsumerMutations.push('backdated-journal-appended-at-terminal-persistence')
  const backdatedEventPersistedAfterTerminal = value('journal_started')
  backdatedEventPersistedAfterTerminal.persisted_at = new Date(Date.parse(bootstrapTerminal.persisted_at) + 1).toISOString()
  backdatedEventPersistedAfterTerminal.record_digest_sha256 = recordDigest(backdatedEventPersistedAfterTerminal)
  assert.throws(() => assertJournalEvent(backdatedEventPersistedAfterTerminal, classification, bindings, runtime, authorizationControls), /protected-time-visible claimed permit lifecycle/)
  protectedTimeConsumerMutations.push('backdated-journal-appended-after-terminal-persistence')
  const semanticAfterPersistence = value('journal_started')
  semanticAfterPersistence.persisted_at = new Date(Date.parse(semanticAfterPersistence.event_at) - 1).toISOString()
  semanticAfterPersistence.record_digest_sha256 = recordDigest(semanticAfterPersistence)
  assert.throws(() => assertJournalEvent(semanticAfterPersistence, classification, bindings, runtime, authorizationControls), /semantic event time is later than broker-protected persistence time/)
  protectedTimeConsumerMutations.push('journal-semantic-time-after-persistence')

  const latePersistedBootstrapTerminal = structuredClone(bootstrapTerminal)
  latePersistedBootstrapTerminal.persisted_at = new Date(Date.parse(replayCertificate.issued_at) + 1).toISOString()
  latePersistedBootstrapTerminal.record_digest_sha256 = recordDigest(latePersistedBootstrapTerminal)
  const lateReplay = structuredClone(replayCertificate)
  lateReplay.permit_spent_transition_record_digest_sha256 = latePersistedBootstrapTerminal.record_digest_sha256
  lateReplay.record_digest_sha256 = recordDigest(lateReplay)
  const lateReplayControls = {
    ...authorizationControls,
    transitions: new Map([
      [bootstrapClaim.record_digest_sha256, bootstrapClaim],
      [latePersistedBootstrapTerminal.record_digest_sha256, latePersistedBootstrapTerminal],
    ]),
  }
  assert.throws(() => assertReplayCertificate(lateReplay, lateReplayControls, classification), /current protected-time-visible spent bootstrap head/)
  protectedTimeConsumerMutations.push('replay-before-terminal-persistence')

  const lateCompletionSourceTerminal = structuredClone(bootstrapTerminal)
  lateCompletionSourceTerminal.persisted_at = new Date(Date.parse(bootstrapCompletionPermit.issued_at) + 1).toISOString()
  lateCompletionSourceTerminal.record_digest_sha256 = recordDigest(lateCompletionSourceTerminal)
  const lateCompletionPermit = structuredClone(bootstrapCompletionPermit)
  lateCompletionPermit.source_terminal_transition_record_digest_sha256 = lateCompletionSourceTerminal.record_digest_sha256
  lateCompletionPermit.record_digest_sha256 = recordDigest(lateCompletionPermit)
  const lateCompletionControls = {
    ...authorizationControls,
    transitions: new Map([
      ...[...authorizationControls.transitions].filter(([digest]) => digest !== bootstrapTerminal.record_digest_sha256),
      [lateCompletionSourceTerminal.record_digest_sha256, lateCompletionSourceTerminal],
    ]),
  }
  assert.throws(() => assertPermitIssuance(lateCompletionPermit, lateCompletionControls, classification), /current protected-time-visible spent bootstrap permit/)
  protectedTimeConsumerMutations.push('completion-permit-before-terminal-persistence')
  const prepromotionAuthorizationMutations = []
  const documentPromotion = fullDocumentIncidentHistory.find((event) => event.event_kind_code === 'promotion_started')
  const rejectPrepromotion = (label, mutateAuthorization = null, mutateEvent = null, mutateControls = null) => {
    const authorization = structuredClone(prepromotionAuthorization)
    if (mutateAuthorization) mutateAuthorization(authorization)
    authorization.record_digest_sha256 = recordDigest(authorization)
    const event = structuredClone(documentPromotion)
    event.prepromotion_authorization_record_digest_sha256 = authorization.record_digest_sha256
    if (mutateEvent) mutateEvent(event)
    event.record_digest_sha256 = recordDigest(event)
    let controls = { ...authorizationControls, prepromotionAuthorizations: new Map([[authorization.record_digest_sha256, authorization]]) }
    if (mutateControls) controls = mutateControls(controls, authorization)
    assert.throws(() => assertJournalEvent(event, classification, bindings, runtime, controls), /CLEARANCE_INVALID|IDENTITY_BINDING_MISMATCH|RECOVERY_STATE_AMBIGUOUS/, `${label} unexpectedly passed`)
    prepromotionAuthorizationMutations.push(label)
  }
  rejectPrepromotion('missing-document-prepromotion-authorization', null, (event) => { event.prepromotion_authorization_record_digest_sha256 = null })
  rejectPrepromotion('unresolved-document-prepromotion-authorization', null, (event) => { event.prepromotion_authorization_record_digest_sha256 = '9'.repeat(64) })
  rejectPrepromotion('prepromotion-cross-operation', (record) => { record.operation_id = 'synthetic.other-operation' })
  rejectPrepromotion('prepromotion-cross-nonce', (record) => { record.operation_nonce = '9'.repeat(64) })
  rejectPrepromotion('prepromotion-cross-artifact', (record) => { record.artifact.sha256 = '9'.repeat(64) })
  rejectPrepromotion('prepromotion-expired-before-promotion', (record) => { record.expires_at = '2030-01-01T00:08:45.000Z' })
  rejectPrepromotion('prepromotion-wrong-authorizer', (record) => { record.authorized_by_binding_code = 'binding.clearance-broker' })
  rejectPrepromotion('prepromotion-wrong-persister', (record) => { record.persisted_by_binding_code = 'binding.verifier' })
  rejectPrepromotion('prepromotion-persisted-before-evaluation', (record) => { record.persisted_at = new Date(Date.parse(record.evaluated_at) - 1).toISOString() })
  rejectPrepromotion('prepromotion-backdated-after-promotion', (record) => { record.persisted_at = new Date(Date.parse(documentPromotion.persisted_at) + 1).toISOString() })
  rejectPrepromotion('prepromotion-missing-candidate-seal', null, null, (controls) => ({ ...controls, candidateSeals: new Map() }))
  rejectPrepromotion('prepromotion-stale-knowledge-sequence', null, null, (controls) => ({ ...controls, currentBundleSequence: 3 }))
  rejectPrepromotion('prepromotion-clearance-revoked-before-use', null, null, (controls) => {
    const transition = value('clearance_transition')
    transition.occurred_at = '2030-01-01T00:08:45.000Z'
    transition.record_digest_sha256 = recordDigest(transition)
    return { ...controls, clearanceTransitions: [transition] }
  })
  const changedCandidateHistory = structuredClone(fullBootstrapHistory)
  changedCandidateHistory.find((event) => event.event_kind_code === 'promotion_started').candidate_file_sha256 = '9'.repeat(64)
  assert.throws(() => assertJournalMilestoneContinuity(changedCandidateHistory, authorizationControls), /one candidate-file hash/)
  const changedBackupHistory = structuredClone(fullBootstrapHistory)
  changedBackupHistory.find((event) => event.event_kind_code === 'promotion_observed').backup_inventory_sha256 = '8'.repeat(64)
  assert.throws(() => assertJournalMilestoneContinuity(changedBackupHistory, authorizationControls), /one prior-backup inventory/)
  const swappedCandidateSealControls = { ...authorizationControls, candidateSeals: new Map([...authorizationControls.candidateSeals].filter(([, seal]) => seal.operation_id !== bootstrapClaim.operation_id)) }
  assert.throws(() => assertJournalMilestoneContinuity(fullBootstrapHistory, swappedCandidateSealControls), /does not resolve one exact candidate-file seal/)
  const bootstrapCandidateSeal = [...authorizationControls.candidateSeals.values()].find((seal) => seal.operation_id === bootstrapClaim.operation_id)
  const unrelatedSameBytesSeal = structuredClone(bootstrapCandidateSeal)
  unrelatedSameBytesSeal.record_code = 'synthetic.unrelated-same-bytes-candidate-seal'
  unrelatedSameBytesSeal.operation_id = 'synthetic.unrelated-operation'
  unrelatedSameBytesSeal.operation_nonce = '9'.repeat(64)
  unrelatedSameBytesSeal.record_digest_sha256 = recordDigest(unrelatedSameBytesSeal)
  const unrelatedSameBytesControls = { ...authorizationControls, candidateSeals: new Map([...authorizationControls.candidateSeals, [unrelatedSameBytesSeal.record_digest_sha256, unrelatedSameBytesSeal]]) }
  assert.doesNotThrow(() => assertJournalMilestoneContinuity(fullBootstrapHistory, unrelatedSameBytesControls))
  if (fullBootstrapHistory.length < 4) fail('fixture', 'FIXTURE_INVALID', 'bootstrap journal does not exercise ordered intermediate milestones')
  const missingMilestone = resealHistory(fullBootstrapHistory.filter((_event, index) => index !== 1))
  assert.throws(() => assertJournalHistory(missingMilestone, classification, bindings, runtime, authorizationControls), /ordered milestone contract|candidate milestones|candidate-sealed/)
  const reorderedMilestones = fullBootstrapHistory.map((event) => structuredClone(event))
  const reorderedTimes = reorderedMilestones.map((event) => event.event_at)
  ;[reorderedMilestones[3], reorderedMilestones[4]] = [reorderedMilestones[4], reorderedMilestones[3]]
  reorderedMilestones.forEach((event, index) => { event.event_at = reorderedTimes[index] })
  const resealedReorderedMilestones = resealHistory(reorderedMilestones)
  assert.throws(() => assertJournalHistory(resealedReorderedMilestones, classification, bindings, runtime, authorizationControls), /ordered milestone contract/)
  const futureStateJournal = structuredClone(fullBootstrapHistory[0])
  futureStateJournal.target_logical_state = { state_seal_code: documentState.record_code, state_seal_record_digest_sha256: documentState.record_digest_sha256, logical_state_sha256: documentState.logical_state_sha256 }
  futureStateJournal.record_digest_sha256 = recordDigest(futureStateJournal)
  assert.throws(() => assertJournalEvent(futureStateJournal, classification, bindings, runtime, authorizationControls), /was not available/)
  const stageFailure = structuredClone(fullDocumentIncidentHistory.at(-1))
  stageFailure.record_code = 'synthetic.generated-stage-failure'
  stageFailure.event_kind_code = 'stage_failed'
  stageFailure.result_outcome_code = null
  stageFailure.record_digest_sha256 = recordDigest(stageFailure)
  const nonterminalAfterFailure = structuredClone(fullDocumentIncidentHistory[0])
  nonterminalAfterFailure.event_kind_code = 'stage_entered'
  nonterminalAfterFailure.stage_code = 'recovery'
  nonterminalAfterFailure.error_code = null
  nonterminalAfterFailure.retryability_code = 'never'
  nonterminalAfterFailure.recovery_class_code = 'none'
  nonterminalAfterFailure.canonical_effect_code = 'none_verified'
  nonterminalAfterFailure.object_disposition_code = 'none'
  nonterminalAfterFailure.result_outcome_code = null
  assert.throws(() => assertStageFailureTerminalization([stageFailure, nonterminalAfterFailure, fullDocumentIncidentHistory.at(-1)]), /immediately terminalized/)

  const failureHistoryCases = []
  const failureHistoryMutations = []
  const documentRecoveryFailure = structuredClone(fullDocumentIncidentHistory.at(-1))
  documentRecoveryFailure.record_code = 'synthetic.document-stage-failed'
  documentRecoveryFailure.event_kind_code = 'stage_failed'
  documentRecoveryFailure.result_outcome_code = null
  documentRecoveryFailure.event_at = new Date(Date.parse(fullDocumentIncidentHistory.at(-1).event_at) - 1).toISOString()
  documentRecoveryFailure.persisted_at = documentRecoveryFailure.event_at
  documentRecoveryFailure.record_digest_sha256 = recordDigest(documentRecoveryFailure)
  const documentRecoveryTerminal = structuredClone(fullDocumentIncidentHistory.at(-1))
  documentRecoveryTerminal.record_code = 'synthetic.document-recovery-after-stage-failure'
  documentRecoveryTerminal.event_sequence += 1
  documentRecoveryTerminal.previous_event_record_digest_sha256 = documentRecoveryFailure.record_digest_sha256
  documentRecoveryTerminal.record_digest_sha256 = recordDigest(documentRecoveryTerminal)
  const recoveryFailureHistory = [...fullDocumentIncidentHistory.slice(0, -1), documentRecoveryFailure, documentRecoveryTerminal]
  assert.doesNotThrow(() => assertJournalHistory(recoveryFailureHistory, classification, bindings, runtime, authorizationControls))
  failureHistoryCases.push('stage_failed-to-recovery_required')

  const manifestError = errorRule(classification, 'MANIFEST_SCHEMA_INVALID')
  const manifestEffect = errorEffectRule(classification, manifestError.code)
  const rejectedRoot = structuredClone(value('journal_document_started'))
  rejectedRoot.record_code = 'synthetic.rejected-dry-run-started'
  rejectedRoot.journal_code = 'synthetic.rejected-dry-run-journal'
  rejectedRoot.operation_id = 'synthetic.operation-rejected-dry-run'
  rejectedRoot.operation_mode_code = 'dry_run'
  rejectedRoot.bundle = null
  rejectedRoot.authorization_bundle_seal_record_digest_sha256 = null
  rejectedRoot.record_digest_sha256 = recordDigest(rejectedRoot)
  const rejectedFailure = structuredClone(rejectedRoot)
  rejectedFailure.record_code = 'synthetic.rejected-dry-run-stage-failed'
  rejectedFailure.event_sequence = 2
  rejectedFailure.previous_event_record_digest_sha256 = rejectedRoot.record_digest_sha256
  rejectedFailure.event_kind_code = 'stage_failed'
  rejectedFailure.stage_code = manifestError.stage
  rejectedFailure.component_binding_code = 'binding.importer'
  rejectedFailure.component_executable_sha256 = findBinding(bindings, rejectedFailure.component_binding_code, 'bundle_importer').executable_sha256
  rejectedFailure.canonical_effect_code = manifestEffect.canonical_effect_code
  rejectedFailure.result_outcome_code = null
  rejectedFailure.error_code = manifestError.code
  rejectedFailure.retryability_code = manifestError.retryability_code
  rejectedFailure.recovery_class_code = manifestError.recovery_class_code
  rejectedFailure.object_disposition_code = manifestEffect.object_disposition_code
  rejectedFailure.candidate_file_sha256 = null
  rejectedFailure.backup_inventory_sha256 = null
  rejectedFailure.observed_logical_state = null
  rejectedFailure.event_at = new Date(Date.parse(rejectedRoot.event_at) + 1).toISOString()
  rejectedFailure.persisted_at = rejectedFailure.event_at
  rejectedFailure.record_digest_sha256 = recordDigest(rejectedFailure)
  const rejectedTerminal = structuredClone(rejectedFailure)
  rejectedTerminal.record_code = 'synthetic.rejected-dry-run-completed'
  rejectedTerminal.event_sequence = 3
  rejectedTerminal.previous_event_record_digest_sha256 = rejectedFailure.record_digest_sha256
  rejectedTerminal.event_kind_code = 'operation_completed'
  rejectedTerminal.stage_code = 'completion'
  rejectedTerminal.result_outcome_code = 'rejected'
  rejectedTerminal.event_at = new Date(Date.parse(rejectedFailure.event_at) + 1).toISOString()
  rejectedTerminal.persisted_at = rejectedTerminal.event_at
  rejectedTerminal.record_digest_sha256 = recordDigest(rejectedTerminal)
  const rejectedHistory = [rejectedRoot, rejectedFailure, rejectedTerminal]
  assert.doesNotThrow(() => assertJournalHistory(rejectedHistory, classification, bindings, runtime, authorizationControls))
  const rejectedWithBundle = resealHistory(rejectedHistory.map((event) => ({ ...structuredClone(event), bundle: structuredClone(value('journal_document_started').bundle) })))
  assert.throws(() => assertJournalHistory(rejectedWithBundle, classification, bindings, runtime, authorizationControls), /bundle identity presence differs from the error-specific policy/)
  failureHistoryMutations.push('early-error-journal-bundle-forbidden')
  const rejectedResult = value('import_result_success')
  rejectedResult.outcome = 'rejected'
  rejectedResult.operation_mode_code = 'dry_run'
  rejectedResult.operation_id = rejectedRoot.operation_id
  rejectedResult.bundle_kind_code = null
  rejectedResult.bundle_id = null
  rejectedResult.bundle_sequence = null
  rejectedResult.bundle_digest_sha256 = null
  rejectedResult.bootstrap_principals_inserted = 0
  rejectedResult.rows_inserted = zeroRows()
  rejectedResult.objects = zeroObjects()
  rejectedResult.checks = allChecks('not_run')
  rejectedResult.checks.manifest = 'failed'
  rejectedResult.canonical_effect_code = manifestEffect.canonical_effect_code
  rejectedResult.error = errorFor(manifestError.code)
  rejectedResult.recovery_permit_record_digest_sha256 = null
  rejectedResult.recovery_terminal_transition_record_digest_sha256 = null
  assert.doesNotThrow(() => assertJournalResultAgreement(rejectedHistory, rejectedResult, classification, bindings, runtime, authorizationControls))
  failureHistoryCases.push('stage_failed-to-rejected-completion')

  assert.throws(() => assertJournalHistory(rejectedHistory.slice(0, -1), classification, bindings, runtime, authorizationControls), /lacks a terminal event|not immediately terminalized/)
  failureHistoryMutations.push('missing-failure-terminal')
  const misplacedFailureHistory = resealHistory([rejectedRoot, rejectedFailure, structuredClone(rejectedRoot), rejectedTerminal])
  assert.throws(() => assertJournalHistory(misplacedFailureHistory, classification, bindings, runtime, authorizationControls), /operation-start event has terminal state|immediately terminalized|penultimate stage-failure/)
  failureHistoryMutations.push('nonpenultimate-stage-failure')
  const duplicateFailure = structuredClone(rejectedFailure)
  duplicateFailure.record_code = 'synthetic.rejected-dry-run-stage-failed-duplicate'
  duplicateFailure.event_at = new Date(Date.parse(rejectedFailure.event_at) + 1).toISOString()
  duplicateFailure.persisted_at = duplicateFailure.event_at
  const duplicateFailureTerminal = structuredClone(rejectedTerminal)
  duplicateFailureTerminal.event_at = new Date(Date.parse(duplicateFailure.event_at) + 1).toISOString()
  duplicateFailureTerminal.persisted_at = duplicateFailureTerminal.event_at
  const duplicateFailureHistory = resealHistory([rejectedRoot, rejectedFailure, duplicateFailure, duplicateFailureTerminal])
  assert.throws(() => assertJournalHistory(duplicateFailureHistory, classification, bindings, runtime, authorizationControls), /immediately terminalized|penultimate stage-failure/)
  failureHistoryMutations.push('duplicate-stage-failure')
  const mismatchedFailure = structuredClone(documentRecoveryFailure)
  mismatchedFailure.rows_delta = zeroRows()
  mismatchedFailure.objects_delta = zeroObjects()
  mismatchedFailure.record_digest_sha256 = recordDigest(mismatchedFailure)
  const mismatchedTerminal = structuredClone(documentRecoveryTerminal)
  mismatchedTerminal.previous_event_record_digest_sha256 = mismatchedFailure.record_digest_sha256
  mismatchedTerminal.record_digest_sha256 = recordDigest(mismatchedTerminal)
  assert.throws(() => assertJournalHistory([...fullDocumentIncidentHistory.slice(0, -1), mismatchedFailure, mismatchedTerminal], classification, bindings, runtime, authorizationControls), /same complete error\/effect context/)
  failureHistoryMutations.push('failure-terminal-context-mismatch')
  const observedRejectedTerminal = structuredClone(rejectedTerminal)
  observedRejectedTerminal.observed_logical_state = structuredClone(rejectedRoot.target_logical_state)
  observedRejectedTerminal.record_digest_sha256 = recordDigest(observedRejectedTerminal)
  assert.throws(() => assertJournalEvent(observedRejectedTerminal, classification, bindings, runtime, authorizationControls), /error, effect, disposition, or observed-state presence/)
  failureHistoryMutations.push('rejected-terminal-observed-state')

  const baseJournal = value('journal_started')
  const targetState = baseJournal.target_logical_state
  const journalCases = []
  for (const rule of classification.journal_event_rules) {
    const event = structuredClone(baseJournal)
    event.record_code = `synthetic.generated-${rule.event_kind_code}`
    event.event_kind_code = rule.event_kind_code
    event.event_sequence = rule.event_kind_code === 'operation_started' ? 1 : 2
    event.previous_event_record_digest_sha256 = rule.event_kind_code === 'operation_started' ? null : '9'.repeat(64)
    event.stage_code = rule.stage_policy === 'startup_only' ? 'startup'
      : rule.stage_policy === 'custody_prepare_only' ? 'custody_prepare'
        : rule.stage_policy === 'database_transaction_only' ? 'database_transaction'
          : rule.stage_policy === 'independent_verification_only' ? 'independent_verification'
            : rule.stage_policy === 'promotion_only' ? 'promotion'
              : rule.stage_policy === 'post_promotion_only' ? 'post_promotion_verification'
                : rule.stage_policy === 'completion_only' ? 'completion' : 'preflight'
    event.canonical_effect_code = rule.allowed_canonical_effects[0]
    event.result_outcome_code = null
    event.error_code = null
    event.retryability_code = 'never'
    event.recovery_class_code = 'none'
    event.rows_delta = null
    event.objects_delta = null
    event.object_disposition_code = rule.allowed_dispositions[0]
    event.candidate_file_sha256 = null
    event.backup_inventory_sha256 = null
    event.observed_logical_state = null
    const nonzeroRows = () => ({ ...zeroRows(), atlas_evidence_bundle_receipts: 1 })
    const nonzeroObjects = () => ({ ...zeroObjects(), prepared: 1 })
    if (rule.rows_policy === 'required_zero') event.rows_delta = zeroRows()
    else if (rule.rows_policy === 'required') event.rows_delta = zeroRows()
    else if (rule.rows_policy === 'required_nonzero') event.rows_delta = nonzeroRows()
    if (rule.objects_policy === 'required_zero') event.objects_delta = zeroObjects()
    else if (rule.objects_policy === 'required') event.objects_delta = zeroObjects()
    else if (rule.objects_policy === 'required_nonzero') event.objects_delta = nonzeroObjects()
    if (rule.candidate_hash_policy === 'required') event.candidate_file_sha256 = '4'.repeat(64)
    if (rule.backup_hash_policy === 'required') event.backup_inventory_sha256 = '5'.repeat(64)
    if (rule.observed_state_policy === 'required' || rule.observed_state_policy === 'required_when_error_absent_else_error_policy') event.observed_logical_state = targetState
    if (rule.error_policy === 'required') {
      const code = rule.event_kind_code === 'recovery_required' ? 'PROMOTION_STATE_AMBIGUOUS' : 'PREFLIGHT_REJECTED'
      const error = errorRule(classification, code)
      event.error_code = code
      event.stage_code = error.stage
      event.retryability_code = error.retryability_code
      event.recovery_class_code = error.recovery_class_code
      const effect = errorEffectRule(classification, code)
      event.canonical_effect_code = effect.canonical_effect_code
      event.object_disposition_code = effect.object_disposition_code
      if (effect.observed_state_policy_code === 'required') event.observed_logical_state = targetState
      if (effect.observed_state_policy_code === 'forbidden') event.observed_logical_state = null
    }
    if (rule.result_policy === 'recovery_required_only') {
      event.result_outcome_code = 'recovery_required'
      event.canonical_effect_code = 'possibly_promoted'
    } else if (rule.result_policy === 'required_terminal') {
      event.result_outcome_code = 'imported'
      event.canonical_effect_code = 'promoted_verified'
    }
    const originRule = classification.journal_event_origin_rules.find((item) => item.event_kind_code === event.event_kind_code)
    const requiredRole = originRule.origin_policy_code === 'exact_role' ? originRule.runtime_role_code : classification.journal_stage_origin_rules.find((item) => item.stage_code === event.stage_code).runtime_role_code
    const originBinding = bindings.bindings.find((item) => item.runtime_role_code === requiredRole)
    if (!originBinding.allowed_operation_modes.includes(event.operation_mode_code)) {
      event.operation_mode_code = 'document_import'
      event.operation_id = documentSeal.operation_id
      event.operation_nonce = documentSeal.operation_nonce
      event.authorization_permit_record_digest_sha256 = null
      event.authorization_bundle_seal_record_digest_sha256 = documentSeal.record_digest_sha256
      event.bundle = structuredClone(documentSeal.bundle)
      event.target_logical_state = structuredClone(documentSeal.target_logical_state)
      event.event_at = '2030-01-01T00:07:01.000Z'
      event.persisted_at = event.event_at
    }
    event.component_binding_code = originBinding.binding_code
    event.component_executable_sha256 = originBinding.executable_sha256
    event.recorded_by_binding_code = 'binding.journal-broker'
    event.record_digest_sha256 = recordDigest(event)
    validateContractStructure(event, 'operation-journal-event-v1.schema.json', registry)
    assertJournalEvent(event, classification, bindings, runtime, authorizationControls)
    const wrongOrigin = structuredClone(event)
    const wrongBinding = bindings.bindings.find((item) => item.principal_kind_code === 'service' && item.runtime_role_code !== requiredRole && item.runtime_role_code !== 'journal_broker')
    wrongOrigin.component_binding_code = wrongBinding.binding_code
    wrongOrigin.component_executable_sha256 = wrongBinding.executable_sha256
    wrongOrigin.record_digest_sha256 = recordDigest(wrongOrigin)
    assert.throws(() => assertJournalEvent(wrongOrigin, classification, bindings, runtime, authorizationControls), /IDENTITY_BINDING_MISMATCH/)
    journalCases.push(rule.event_kind_code)
  }

  const terminal = value('journal_completed')
  const successor = structuredClone(baseJournal)
  successor.event_kind_code = 'stage_entered'
  successor.stage_code = 'recovery'
  successor.event_sequence = terminal.event_sequence + 1
  successor.previous_event_record_digest_sha256 = terminal.record_digest_sha256
  successor.event_at = '2030-01-01T00:06:06.000Z'
  successor.persisted_at = successor.event_at
  successor.rows_delta = successor.objects_delta = null
  successor.record_digest_sha256 = recordDigest(successor)
  assert.throws(() => assertJournalChain(terminal, successor, classification, null, null, authorizationControls), /terminal event has a successor|outside its (?:protected-time-visible )?claimed permit lifecycle/)
  assert.throws(() => assertJournalHistory([successor], classification, null, null, authorizationControls), /unique operation-start root/)
  const journalRoot = value('journal_started')
  const journalNext = value('journal_completed')
  for (const mutate of [
    (item) => { item.journal_code = 'synthetic.other-journal' },
    (item) => { item.operation_id = 'synthetic.other-operation' },
    (item) => { item.operation_nonce = '7'.repeat(64) },
    (item) => { item.runtime_profile_record_digest_sha256 = '6'.repeat(64) },
    (item) => { item.identity_bindings_record_digest_sha256 = '5'.repeat(64) },
    (item) => { item.bundle.bundle_digest_sha256 = '4'.repeat(64) },
    (item) => { item.target_logical_state.logical_state_sha256 = '3'.repeat(64) },
  ]) {
    const invalid = structuredClone(journalNext)
    mutate(invalid)
    invalid.record_digest_sha256 = recordDigest(invalid)
    assert.throws(() => assertJournalChain(journalRoot, invalid, classification, bindings, runtime, authorizationControls), /RECOVERY_STATE_AMBIGUOUS|RUNTIME_PROFILE_MISMATCH/)
  }
  const originAsBroker = structuredClone(journalNext)
  originAsBroker.component_binding_code = originAsBroker.recorded_by_binding_code
  originAsBroker.component_executable_sha256 = findBinding(bindings, originAsBroker.recorded_by_binding_code).executable_sha256
  originAsBroker.record_digest_sha256 = recordDigest(originAsBroker)
  assert.throws(() => assertJournalEvent(originAsBroker, classification, bindings, runtime, authorizationControls), /IDENTITY_BINDING_MISMATCH|RECOVERY_STATE_AMBIGUOUS/)
  const wrongBroker = structuredClone(journalNext)
  wrongBroker.recorded_by_binding_code = 'binding.launcher'
  wrongBroker.record_digest_sha256 = recordDigest(wrongBroker)
  assert.throws(() => assertJournalEvent(wrongBroker, classification, bindings, runtime, authorizationControls), /IDENTITY_BINDING_MISMATCH/)
  assert.throws(() => assertJournalHistory([journalNext, journalRoot], classification, bindings, runtime, authorizationControls), /unique operation-start root/)
  const journalAuthorizationMutations = []
  const bootstrapWrongPermit = structuredClone(journalRoot)
  bootstrapWrongPermit.authorization_permit_record_digest_sha256 = recoveryPermitFixture.record_digest_sha256
  bootstrapWrongPermit.record_digest_sha256 = recordDigest(bootstrapWrongPermit)
  assert.throws(() => assertJournalEvent(bootstrapWrongPermit, classification, bindings, runtime, authorizationControls), /RECOVERY_STATE_AMBIGUOUS/)
  journalAuthorizationMutations.push('bootstrap-journal-wrong-permit-kind')
  const bootstrapUnknownPermit = structuredClone(journalRoot)
  bootstrapUnknownPermit.authorization_permit_record_digest_sha256 = '8'.repeat(64)
  bootstrapUnknownPermit.record_digest_sha256 = recordDigest(bootstrapUnknownPermit)
  assert.throws(() => assertJournalEvent(bootstrapUnknownPermit, classification, bindings, runtime, authorizationControls), /RECOVERY_STATE_AMBIGUOUS/)
  journalAuthorizationMutations.push('bootstrap-journal-unresolved-permit')
  const documentWithPermit = value('journal_document_started')
  documentWithPermit.authorization_permit_record_digest_sha256 = bootstrapPermit.record_digest_sha256
  documentWithPermit.record_digest_sha256 = recordDigest(documentWithPermit)
  assert.throws(() => assertJournalEvent(documentWithPermit, classification, bindings, runtime, authorizationControls), /RECOVERY_STATE_AMBIGUOUS/)
  journalAuthorizationMutations.push('document-journal-forbidden-permit')
  const recoveryWrongPermit = value('journal_completion_started')
  recoveryWrongPermit.authorization_permit_record_digest_sha256 = recoveryPermitFixture.record_digest_sha256
  recoveryWrongPermit.record_digest_sha256 = recordDigest(recoveryWrongPermit)
  assert.throws(() => assertJournalEvent(recoveryWrongPermit, classification, bindings, runtime, authorizationControls), /RECOVERY_STATE_AMBIGUOUS/)
  journalAuthorizationMutations.push('completion-journal-wrong-exact-permit')
  const recoveryAuthorizedJournal = value('journal_started')
  recoveryAuthorizedJournal.record_code = 'synthetic.recovery-authorized-journal'
  recoveryAuthorizedJournal.journal_code = 'synthetic.recovery-authorized-history'
  recoveryAuthorizedJournal.operation_mode_code = 'recovery'
  recoveryAuthorizedJournal.operation_id = recoveryPermitFixture.operation_id
  recoveryAuthorizedJournal.operation_nonce = recoveryPermitFixture.operation_nonce
  recoveryAuthorizedJournal.authorization_permit_record_digest_sha256 = recoveryPermitFixture.record_digest_sha256
  recoveryAuthorizedJournal.bundle = structuredClone(recoveryPermitFixture.accepted_bootstrap_bundle)
  recoveryAuthorizedJournal.target_logical_state = structuredClone(recoveryPermitFixture.target_empty_logical_state)
  recoveryAuthorizedJournal.event_at = recoveryClaim.occurred_at
  recoveryAuthorizedJournal.persisted_at = recoveryAuthorizedJournal.event_at
  recoveryAuthorizedJournal.record_digest_sha256 = recordDigest(recoveryAuthorizedJournal)
  assertJournalEvent(recoveryAuthorizedJournal, classification, bindings, runtime, authorizationControls)
  const wrongRecoveryTarget = structuredClone(recoveryAuthorizedJournal)
  wrongRecoveryTarget.target_logical_state = structuredClone(recoveryPermitFixture.accepted_logical_state)
  wrongRecoveryTarget.record_digest_sha256 = recordDigest(wrongRecoveryTarget)
  assert.throws(() => assertJournalEvent(wrongRecoveryTarget, classification, bindings, runtime, authorizationControls), /RECOVERY_STATE_AMBIGUOUS/)
  journalAuthorizationMutations.push('recovery-journal-exact-target-state', 'recovery-journal-wrong-target-state')

  const dryRunRoot = value('journal_started')
  dryRunRoot.record_code = 'synthetic.dry-run-journal-001'
  dryRunRoot.journal_code = 'synthetic.dry-run-journal'
  dryRunRoot.operation_mode_code = 'dry_run'
  dryRunRoot.operation_id = 'synthetic.operation-dry-run'
  dryRunRoot.operation_nonce = '6'.repeat(64)
  dryRunRoot.authorization_permit_record_digest_sha256 = null
  dryRunRoot.authorization_bundle_seal_record_digest_sha256 = null
  dryRunRoot.event_at = '2030-01-01T00:07:00.000Z'
  dryRunRoot.persisted_at = dryRunRoot.event_at
  dryRunRoot.record_digest_sha256 = recordDigest(dryRunRoot)
  const dryRunTerminal = value('journal_completed')
  dryRunTerminal.record_code = 'synthetic.dry-run-journal-002'
  dryRunTerminal.journal_code = dryRunRoot.journal_code
  dryRunTerminal.operation_mode_code = dryRunRoot.operation_mode_code
  dryRunTerminal.operation_id = dryRunRoot.operation_id
  dryRunTerminal.operation_nonce = dryRunRoot.operation_nonce
  dryRunTerminal.event_sequence = 2
  dryRunTerminal.previous_event_record_digest_sha256 = dryRunRoot.record_digest_sha256
  dryRunTerminal.authorization_permit_record_digest_sha256 = null
  dryRunTerminal.authorization_bundle_seal_record_digest_sha256 = null
  dryRunTerminal.bundle = structuredClone(dryRunRoot.bundle)
  dryRunTerminal.target_logical_state = structuredClone(dryRunRoot.target_logical_state)
  dryRunTerminal.observed_logical_state = structuredClone(dryRunRoot.target_logical_state)
  dryRunTerminal.canonical_effect_code = 'none_verified'
  dryRunTerminal.result_outcome_code = 'planned'
  dryRunTerminal.rows_delta = zeroRows()
  dryRunTerminal.objects_delta = zeroObjects()
  dryRunTerminal.object_disposition_code = 'none'
  dryRunTerminal.candidate_file_sha256 = null
  dryRunTerminal.backup_inventory_sha256 = null
  dryRunTerminal.event_at = '2030-01-01T00:07:01.000Z'
  dryRunTerminal.persisted_at = dryRunTerminal.event_at
  dryRunTerminal.record_digest_sha256 = recordDigest(dryRunTerminal)
  assert.doesNotThrow(() => assertJournalHistory([dryRunRoot, dryRunTerminal], classification, bindings, runtime, authorizationControls))
  const dryRunOutcomeMisuse = structuredClone(dryRunTerminal)
  dryRunOutcomeMisuse.result_outcome_code = 'recovered'
  dryRunOutcomeMisuse.record_digest_sha256 = recordDigest(dryRunOutcomeMisuse)
  assert.throws(() => assertJournalHistory([dryRunRoot, dryRunOutcomeMisuse], classification, bindings, runtime, authorizationControls), /closed history rules|importer-result rule/)
  journalAuthorizationMutations.push('dry-run-recovered-outcome-forbidden')
  for (const [label, mutate] of [
    ['permitless-journal-fake-bundle', (first, second) => { first.bundle.bundle_digest_sha256 = second.bundle.bundle_digest_sha256 = '7'.repeat(64) }],
    ['permitless-journal-fake-target-state', (first, second) => { first.target_logical_state.logical_state_sha256 = second.target_logical_state.logical_state_sha256 = '7'.repeat(64) }],
    ['permitless-journal-fake-observed-state', (_first, second) => { second.observed_logical_state.logical_state_sha256 = '7'.repeat(64) }],
  ]) {
    const first = structuredClone(dryRunRoot)
    const second = structuredClone(dryRunTerminal)
    mutate(first, second)
    first.record_digest_sha256 = recordDigest(first)
    second.previous_event_record_digest_sha256 = first.record_digest_sha256
    second.record_digest_sha256 = recordDigest(second)
    assert.throws(() => assertJournalHistory([first, second], classification, bindings, runtime, authorizationControls), /does not resolve exactly once|does not resolve exact immutable/)
    journalAuthorizationMutations.push(label)
  }

  const matrixClearance = value('clearance_decision')
  for (const rule of classification.clearance_decision_rules) {
    const candidate = structuredClone(matrixClearance)
    for (const key of ['decision_code', 'retention_scope_code', 'redistribution_scope_code', 'derivative_use_code', 'sensitivity_code', 'git_permanence_acknowledged']) candidate[key] = rule[key]
    const declarationValue = rule.repository_declaration_code === 'all_true'
    for (const key of Object.keys(candidate.repository_declarations)) candidate.repository_declarations[key] = declarationValue
    candidate.record_code = `synthetic.clearance-${rule.decision_code}`
    candidate.clearance_scope_sha256 = clearanceScopeDigest(candidate)
    candidate.record_digest_sha256 = recordDigest(candidate)
    validateContractStructure(candidate, 'clearance-record-v1.schema.json', registry)
    assertClearanceDecisionMatrix(candidate, classification)
  }
  const revoked = value('clearance_transition')
  assert.throws(() => assertClearanceTransitions(matrixClearance, [revoked, structuredClone(revoked)], new Map(), classification), /competing terminal successors/)
  const replacement = structuredClone(matrixClearance)
  replacement.record_code = 'synthetic.clearance-replacement'
  replacement.clearance_code = 'synthetic.artifact-clearance-replacement'
  replacement.recorded_at = replacement.not_before = '2030-01-01T00:08:30.000Z'
  replacement.clearance_scope_sha256 = clearanceScopeDigest(replacement)
  replacement.record_digest_sha256 = recordDigest(replacement)
  const superseded = structuredClone(revoked)
  superseded.record_code = 'synthetic.clearance-supersession'
  superseded.state_code = 'superseded'
  superseded.reason_code = 'record_corrected'
  superseded.replacement_clearance_record_digest_sha256 = replacement.record_digest_sha256
  superseded.occurred_at = '2030-01-01T00:09:00.000Z'
  superseded.record_digest_sha256 = recordDigest(superseded)
  const replacementMap = new Map([[replacement.record_digest_sha256, replacement]])
  assertClearanceTransitions(matrixClearance, [superseded], replacementMap, classification)
  if (clearanceLeafAt(matrixClearance, [superseded], replacementMap, classification, superseded.occurred_at)?.record_digest_sha256 !== replacement.record_digest_sha256) fail('fixture', 'FIXTURE_INVALID', 'clearance supersession did not select its exact replacement')

  return {
    resultCases,
    journalCases,
    preactivationWithdrawals,
    terminalErrorCrossProduct,
    errorBundleReferenceCrossProduct,
    journalOriginSubstitutions: journalCases.length,
    recoveredPromotionRejected: true,
    recoveredAuthorizationMutations,
    ordinaryBundleMutations,
    journalAuthorizationMutations,
    journalTopologyMutations,
    protectedTimeConsumerMutations,
    failureHistoryCases,
    failureHistoryMutations,
    prepromotionAuthorizationMutations,
    canonicalLineageMutation: true,
  }
}

function schemaRegistryWithMutation(schemaEntries, file, mutate) {
  const clones = schemaEntries.map(([name, schema]) => [name, structuredClone(schema)])
  const target = clones.find(([name]) => name === file)?.[1]
  if (!target) throw new Error(`missing mutation schema ${file}`)
  mutate(target)
  return createSchemaRegistry(clones)
}

function assertSchemaMutationMatrix(schemaEntries, registry, fixtures, catalog, classification, fieldRegistry, digestProfiles) {
  const runtime = fixtures.get('runtime_profile').value
  const cases = []
  const expectCanonicalRejectMutantAccept = (label, buildValue, mutateSchema) => {
    const value = buildValue(structuredClone(runtime))
    assert.throws(() => validateSchemaValue(value, registry.byFile.get('runtime-profile-v1.schema.json'), registry), ContractError, `${label} canonical schema accepted mutation`)
    const mutant = schemaRegistryWithMutation(schemaEntries, 'runtime-profile-v1.schema.json', mutateSchema)
    assert.doesNotThrow(() => validateSchemaValue(value, mutant.byFile.get('runtime-profile-v1.schema.json'), mutant), `${label} mutant did not expose intended weakening`)
    assert.throws(() => assertCatalogSchemaBytes(catalog, 'runtime-profile-v1.schema.json', Buffer.from(`${JSON.stringify(mutant.byFile.get('runtime-profile-v1.schema.json'), null, 2)}\n`, 'utf8')), /CATALOG_INVALID/, `${label} was not detected by the catalog pin`)
    cases.push(label)
  }
  expectCanonicalRejectMutantAccept('required-field-removal', (value) => { delete value.limits.artifact_bytes_max; return value }, (schema) => {
    schema.properties.limits.required = schema.properties.limits.required.filter((item) => item !== 'artifact_bytes_max')
    delete schema.properties.limits.properties.artifact_bytes_max
  })
  const extra = structuredClone(runtime)
  extra.unreviewed_override = 1
  assert.throws(() => validateSchemaValue(extra, registry.byFile.get('runtime-profile-v1.schema.json'), registry), ContractError)
  const openSchemas = schemaEntries.map(([name, schema]) => [name, structuredClone(schema)])
  openSchemas.find(([name]) => name === 'runtime-profile-v1.schema.json')[1].additionalProperties = true
  assert.throws(() => createSchemaRegistry(openSchemas), /SCHEMA_OPEN_OBJECT/)
  assert.throws(() => assertCatalogSchemaBytes(catalog, 'runtime-profile-v1.schema.json', Buffer.from(`${JSON.stringify(openSchemas.find(([name]) => name === 'runtime-profile-v1.schema.json')[1], null, 2)}\n`, 'utf8')), /CATALOG_INVALID/)
  cases.push('unknown-field-policy-removal')
  expectCanonicalRejectMutantAccept('closed-enum-widening', (value) => { value.processor_policy_code = 'enabled'; return value }, (schema) => {
    delete schema.properties.processor_policy_code.const
    schema.properties.processor_policy_code.enum = ['disabled', 'enabled']
  })
  for (const limitCode of Object.keys(runtime.limits)) {
    expectCanonicalRejectMutantAccept(`fixed-limit-widening-${limitCode}`, (value) => { value.limits[limitCode] += 1; return value }, (schema) => {
      schema.properties.limits.properties[limitCode].const += 1
    })
  }
  expectCanonicalRejectMutantAccept('version-substitution', (value) => { value.format_version = '1.1.0'; return value }, (schema) => {
    schema.properties.format_version.const = '1.1.0'
  })
  const unsupported = schemaEntries.map(([name, schema]) => [name, structuredClone(schema)])
  unsupported.find(([name]) => name === 'runtime-profile-v1.schema.json')[1].unevaluatedProperties = false
  assert.throws(() => createSchemaRegistry(unsupported), /SCHEMA_KEYWORD_UNSUPPORTED/)
  assert.throws(() => assertCatalogSchemaBytes(catalog, 'runtime-profile-v1.schema.json', Buffer.from(`${JSON.stringify(unsupported.find(([name]) => name === 'runtime-profile-v1.schema.json')[1], null, 2)}\n`, 'utf8')), /CATALOG_INVALID/)
  cases.push('unsupported-keyword-injection')
  const malformedDigest = structuredClone(runtime)
  malformedDigest.runtime_domain_sha256 = 'G'.repeat(64)
  assert.throws(() => validateSchemaValue(malformedDigest, registry.byFile.get('runtime-profile-v1.schema.json'), registry), ContractError)
  const weakenedDigestRegistry = schemaRegistryWithMutation(schemaEntries, 'common-v1.schema.json', (schema) => { schema.$defs.sha256.pattern = '^[0-9A-Za-z]{64}$' })
  assert.doesNotThrow(() => validateSchemaValue(malformedDigest, weakenedDigestRegistry.byFile.get('runtime-profile-v1.schema.json'), weakenedDigestRegistry))
  assert.throws(() => assertCatalogSchemaBytes(catalog, 'common-v1.schema.json', Buffer.from(`${JSON.stringify(weakenedDigestRegistry.byFile.get('common-v1.schema.json'), null, 2)}\n`, 'utf8')), /CATALOG_INVALID/)
  cases.push('sha256-constraint-weakening')
  const recoveryPermit = structuredClone(fixtures.get('recovery_permit').value)
  recoveryPermit.replay_certificate.format = 'jedi-atlas-unknown-contract'
  assert.throws(() => validateSchemaValue(recoveryPermit, registry.byFile.get('bootstrap-control-v1.schema.json'), registry), ContractError)
  const widenedReferenceRegistry = schemaRegistryWithMutation(schemaEntries, 'common-v1.schema.json', (schema) => { schema.$defs.contractReference.properties.format.enum.push('jedi-atlas-unknown-contract') })
  assert.doesNotThrow(() => validateSchemaValue(recoveryPermit, widenedReferenceRegistry.byFile.get('bootstrap-control-v1.schema.json'), widenedReferenceRegistry))
  assert.throws(() => assertCatalogSchemaBytes(catalog, 'common-v1.schema.json', Buffer.from(`${JSON.stringify(widenedReferenceRegistry.byFile.get('common-v1.schema.json'), null, 2)}\n`, 'utf8')), /CATALOG_INVALID/)
  cases.push('nested-contract-format-widening')
  assert.throws(() => assertCatalog(catalog, schemaEntries.slice(1), classification, fieldRegistry, digestProfiles), /CATALOG_INVALID/)
  const extraSchemas = [...schemaEntries, ['unexpected-v1.schema.json', { $id: 'https://jedi-hiring.invalid/schema/d9-0/unexpected-v1.schema.json' }]]
  assert.throws(() => assertCatalog(catalog, extraSchemas, classification, fieldRegistry, digestProfiles), /CATALOG_INVALID/)
  cases.push('schema-inventory-deletion', 'schema-inventory-addition')
  return cases
}

function assertRawLexicalAndCanonicalMutations() {
  assert.deepEqual(parseJsonBytes(Buffer.from('{\r\n "b": [null,2], "a": 1\r\n}', 'utf8'), { contractNumbers: true }), { b: [null, 2], a: 1 })
  for (const text of ['{"a":1,"a":2}', '{"n":1.0}', '{"n":1e0}', '{"n":-1}', '{"n":-0}', '{"s":"\\ud800"}']) assert.throws(() => parseJsonBytes(Buffer.from(text), { contractNumbers: true }), ContractError)
  assert.throws(() => parseJsonBytes(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), ContractError)
  assert.throws(() => parseJsonBytes(Buffer.from([0xc3, 0x28])), ContractError)
  const ordered = Buffer.from('{"a":1,"b":2}', 'utf8')
  const reversed = Buffer.from('{"b":2,"a":1}', 'utf8')
  assert.equal(canonical(parseJsonBytes(reversed, { contractNumbers: true })), ordered.toString('utf8'))
  assert.notEqual(sha256(reversed), sha256(ordered))
  const nestedContainers = (count) => Array.from({ length: count }).reduce((value, _, index) => index % 2 === 0 ? [value] : { child: value }, null)
  assert.doesNotThrow(() => parseJsonBytes(Buffer.from(JSON.stringify(nestedContainers(32)))))
  assert.throws(() => parseJsonBytes(Buffer.from(JSON.stringify(nestedContainers(33)))), /RESOURCE_LIMIT_EXCEEDED/)
  assert.throws(() => parseJsonBytes(Buffer.from(JSON.stringify(Object.fromEntries(Array.from({ length: 4097 }, (_, index) => [`k${index}`, null]))))), /RESOURCE_LIMIT_EXCEEDED/)
  assert.throws(() => parseJsonBytes(Buffer.alloc(pilotLimits.contract_file_bytes_max + 1, 0x20), { maximumBytes: pilotLimits.contract_file_bytes_max }), /INVALID_SIZE/)
  const lexicalRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d90-lexical-'))
  try {
    const exponentFile = path.join(lexicalRoot, 'exponent.json')
    fs.writeFileSync(exponentFile, '{"format_version":"1e0"}')
    const numericExponentFile = path.join(lexicalRoot, 'numeric-exponent.json')
    fs.writeFileSync(numericExponentFile, '{"value":1e0}')
    assert.doesNotThrow(() => loadJson(exponentFile))
    assert.throws(() => loadJson(numericExponentFile), /INVALID_NUMBER/)
  } finally {
    fs.rmSync(lexicalRoot, { recursive: true, force: true })
  }
}

function objectStats(value) {
  let members = 0
  let maximumDepth = 0
  const pending = [[value, Array.isArray(value) || (value && typeof value === 'object') ? 1 : 0]]
  while (pending.length > 0) {
    const [child, depth] = pending.pop()
    if (Array.isArray(child)) {
      maximumDepth = Math.max(maximumDepth, depth)
      for (const item of child) pending.push([item, Array.isArray(item) || (item && typeof item === 'object') ? depth + 1 : depth])
    } else if (child && typeof child === 'object') {
      maximumDepth = Math.max(maximumDepth, depth)
      members += Object.keys(child).length
      for (const item of Object.values(child)) pending.push([item, Array.isArray(item) || (item && typeof item === 'object') ? depth + 1 : depth])
    }
  }
  return { members, maximumDepth }
}

function assertResourceLimits(runtime, { contractFiles, manifestFiles, artifactFiles }, fixtures) {
  for (const [files, limit, label] of [[contractFiles, runtime.limits.contract_file_bytes_max, 'contract'], [manifestFiles, runtime.limits.manifest_bytes_max, 'manifest'], [artifactFiles, runtime.limits.artifact_bytes_max, 'artifact']]) {
    for (const file of files) {
      if (!fs.statSync(file).isFile() || fs.statSync(file).size > limit) fail('limits', 'RESOURCE_LIMIT_EXCEEDED', `${file} exceeds ${label}-file contract`)
    }
  }
  const aggregateArtifactBytes = artifactFiles.reduce((total, file) => total + fs.statSync(file).size, 0)
  if (aggregateArtifactBytes > runtime.limits.bundle_artifact_bytes_max) fail('limits', 'RESOURCE_LIMIT_EXCEEDED', 'fixture artifact aggregate exceeds bundle limit')
  for (const [limitCode, limit] of [['manifest_bytes_max', runtime.limits.manifest_bytes_max], ['artifact_bytes_max', runtime.limits.artifact_bytes_max], ['bundle_artifact_bytes_max', runtime.limits.bundle_artifact_bytes_max]]) {
    assert.doesNotThrow(() => { if (Buffer.alloc(limit).length > limit) fail('limits', 'RESOURCE_LIMIT_EXCEEDED', limitCode) })
    assert.throws(() => { if (Buffer.alloc(limit + 1).length > limit) fail('limits', 'RESOURCE_LIMIT_EXCEEDED', limitCode) }, /RESOURCE_LIMIT_EXCEEDED/)
  }
  for (const fixture of fixtures.values()) {
    const stats = objectStats(fixture.value)
    if (stats.maximumDepth > runtime.limits.json_depth_max || stats.members > runtime.limits.json_members_max) fail('limits', 'RESOURCE_LIMIT_EXCEEDED', `${fixture.fixture_code} exceeds JSON graph limit`)
    if (Buffer.byteLength(canonical(fixture.value), 'utf8') > runtime.limits.contract_file_bytes_max) fail('limits', 'RESOURCE_LIMIT_EXCEEDED', `${fixture.fixture_code} exceeds canonical record limit`)
  }
}

function assertSecurityMutationCorpus() {
  for (const key of ['api_key', 'apiKey', 'API-KEY', 'private_key', 'signing.key', 'clientSecret', 'refresh_token', 'authorization', 'cookie']) assert.throws(() => assertNoSecretMaterial({ [key]: 'synthetic' }), ContractError)
  for (const value of ['Bearer abcdefghijklmnop', 'AKIA1234567890123456', 'ghp_abcdefghijklmnopqrstuvwxyz', 'xoxb-1234567890-abcdef', 'AIza12345678901234567890', 'eyJaaaaaa.bbbbbbb.ccccccc', '-----BEGIN PRIVATE KEY-----']) assert.throws(() => assertNoSecretMaterial({ note: value }), ContractError)
  for (const value of ['api_key=synthetic-secret', 'client-secret: synthetic-secret', 'password = synthetic-secret']) assert.throws(() => assertNoSecretMaterial({ note: value }), ContractError)
  for (const value of ['https://user:secret@host.invalid/object', 'https://host.invalid/object?X-Amz-Security-Token=synthetic', 'https://host.invalid/object?x-goog-credential=synthetic', 'https://host.invalid/object?access_token=synthetic']) assert.throws(() => assertNoSecretMaterial({ note: value }), /MANIFEST_SECRET_REJECTED/)
  for (const value of ['SYNTHETIC_PERSONAL_DATA: synthetic person', 'synthetic-person@example.invalid']) assert.throws(() => assertNoSyntheticPersonalDataMarkers({ note: value }), /PERSONAL_DATA_DETECTED/)
  for (const value of ['https://example.invalid/source', '/protected/root/item', 'ETag: synthetic']) assert.throws(() => assertRedactedOperationalOutput({ message: value }), /UNSAFE_OUTPUT/)
  for (const key of ['payload', 'response_headers', 'scanner_output', 'capability_envelope']) assert.throws(() => assertRedactedOperationalOutput({ [key]: 'https://example.invalid/unredacted' }), /UNSAFE_OUTPUT/)
  for (const value of ['/absolute/file', '../escape', 'safe/../escape', 'safe\\escape', 'safe//escape', 'safe/\0escape']) assert.equal(isSafeRelativePath(value), false)
}

function confinedSyntheticRead(root, relativePath) {
  if (!isSafeRelativePath(relativePath)) fail('path', 'INPUT_PATH_INVALID', 'unsafe relative path')
  let current = root
  const rootReal = fs.realpathSync(root)
  const parts = relativePath.split('/')
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index])
    const stat = fs.lstatSync(current)
    if (stat.isSymbolicLink()) fail('path', 'INPUT_SYMLINK_REJECTED', 'symbolic link in path')
    if (index < parts.length - 1 && !stat.isDirectory()) fail('path', 'INPUT_TYPE_REJECTED', 'intermediate path is not a directory')
  }
  const real = fs.realpathSync(current)
  if (!real.startsWith(`${rootReal}${path.sep}`)) fail('path', 'INPUT_ROOT_ESCAPE', 'path escaped root')
  const stat = fs.statSync(real)
  if (!stat.isFile()) fail('path', 'INPUT_TYPE_REJECTED', 'input is not a regular file')
  return fs.readFileSync(real)
}

function assertPathBoundary() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d90-path-'))
  try {
    fs.mkdirSync(path.join(root, 'safe'))
    fs.writeFileSync(path.join(root, 'safe', 'fixture.bin'), 'synthetic')
    fs.symlinkSync(path.join(root, 'safe', 'fixture.bin'), path.join(root, 'safe', 'link.bin'))
    assert.equal(confinedSyntheticRead(root, 'safe/fixture.bin').toString(), 'synthetic')
    assert.throws(() => confinedSyntheticRead(root, 'safe/link.bin'), /INPUT_SYMLINK_REJECTED/)
    assert.throws(() => confinedSyntheticRead(root, '../escape'), /INPUT_PATH_INVALID/)
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
}

function assertIpcAdversarial(fixtures) {
  const runtime = fixtures.get('runtime_profile').value
  const request = fixtures.get('custody_open_request').value
  const packet = Buffer.from(canonical(request), 'utf8')
  assert.doesNotThrow(() => assertIpcPacket(packet, request, [], runtime))
  assert.throws(() => assertIpcPacket(Buffer.from(`${packet.toString()} `), request, [], runtime), ContractError)
  assert.throws(() => assertIpcPacket(Buffer.concat([packet, packet]), request, [], runtime), ContractError)
  assert.throws(() => assertIpcPacket(Buffer.alloc(runtime.ipc.max_packet_bytes + 1, 0x20), request, [], runtime), ContractError)
  assert.throws(() => assertIpcPacket(Buffer.from('{"broken":', 'utf8'), request, [], runtime), ContractError)
  const response = fixtures.get('custody_open_response').value
  const freshState = () => ({ nonces: new Map(), streams: new Map(), requestIds: new Set(), requests: new Map(), responses: new Set() })
  const state = freshState()
  registerIpcMessage(request, state)
  registerIpcMessage(response, state)
  assert.throws(() => registerIpcMessage(request, state), /IPC_REPLAY_DETECTED/)
  assert.throws(() => registerIpcMessage(response, state), /IPC_REPLAY_DETECTED/)
  const skipped = structuredClone(request)
  skipped.request_id = 'synthetic.request-skipped'
  skipped.request_sequence = 3
  skipped.record_digest_sha256 = recordDigest(skipped)
  assert.throws(() => registerIpcMessage(skipped, state), /IPC_REPLAY_DETECTED/)
  const second = structuredClone(request)
  second.request_id = 'synthetic.request-002'
  second.request_sequence = 2
  second.record_digest_sha256 = recordDigest(second)
  registerIpcMessage(second, state)
  const rebound = structuredClone(request)
  rebound.request_id = 'synthetic.request-rebound'
  rebound.request_sequence = 1
  rebound.operation_id = 'synthetic.operation-other'
  rebound.record_digest_sha256 = recordDigest(rebound)
  assert.throws(() => registerIpcMessage(rebound, state), /IPC_REPLAY_DETECTED/)
  const orphan = structuredClone(response)
  orphan.request_id = 'synthetic.request-orphan'
  orphan.record_digest_sha256 = recordDigest(orphan)
  assert.throws(() => registerIpcMessage(orphan, freshState()), /IPC_REPLAY_DETECTED/)
}

function assertCapabilityControlHistory(controls, messages, bindings, runtime, classification) {
  const requests = new Map(messages.filter((message) => message.message_kind_code === 'request').map((message) => [message.record_digest_sha256, message]))
  const responses = new Map(messages.filter((message) => message.message_kind_code === 'response').map((message) => [message.record_digest_sha256, message]))
  const context = { ...controls, requests, responses }
  unique([...controls.issuances.values()].map((record) => record.record_code), 'semantic', 'IPC_REPLAY_DETECTED', 'capability issuance code')
  unique([...controls.issuances.keys()], 'semantic', 'IPC_REPLAY_DETECTED', 'capability issuance digest')
  for (const [issuanceDigest, issuance] of controls.issuances) {
    if (issuanceDigest !== issuance.record_digest_sha256) fail('semantic', 'IPC_REPLAY_DETECTED', 'protected capability lookup key differs from its immutable issuance digest')
    assertCapabilityIssuance(issuance, context, bindings, runtime, classification)
  }
  const transitionsByIssuance = new Map()
  for (const transition of controls.transitions) {
    assertDigest(transition)
    const list = transitionsByIssuance.get(transition.capability_record_digest_sha256) ?? []
    list.push(transition)
    transitionsByIssuance.set(transition.capability_record_digest_sha256, list)
  }
  unique(controls.transitions.map((record) => record.record_code), 'semantic', 'IPC_REPLAY_DETECTED', 'capability transition code')
  unique(controls.transitions.map((record) => record.record_digest_sha256), 'semantic', 'IPC_REPLAY_DETECTED', 'capability transition digest')
  const finalStates = new Map()
  for (const [issuanceDigest, transitions] of transitionsByIssuance) {
    const issuance = controls.issuances.get(issuanceDigest)
    if (!issuance) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability transition lacks its protected issuance')
    transitions.sort((left, right) => left.transition_sequence - right.transition_sequence)
    let state = 'ready'
    let previous = null
    let previousAt = issuance.issued_at
    for (const [index, transition] of transitions.entries()) {
      if (transition.capability_kind_code !== issuance.capability_kind_code || transition.transition_sequence !== index + 1 || transition.previous_transition_record_digest_sha256 !== (previous?.record_digest_sha256 ?? null) || transition.from_state_code !== state || transition.occurred_at <= previousAt || transition.occurred_at >= issuance.expires_at) fail('semantic', 'IPC_REPLAY_DETECTED', `capability transition ${transition.record_code} has a gap, fork, wrong subject, backdating, or expiry violation`)
      const rule = classification.custody_capability_transition_rules.find((item) => item.capability_kind_code === issuance.capability_kind_code && item.from_state_code === state && item.to_state_code === transition.to_state_code && item.transition_code === transition.transition_code)
      if (!rule || rule.reason_code !== transition.reason_code || (rule.response_policy_code !== 'must_be_null') !== (transition.response_record_digest_sha256 !== null)) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability transition is outside its closed graph')
      const request = requests.get(transition.request_record_digest_sha256)
      const fieldCode = classification.custody_capability_rules.find((item) => item.capability_kind_code === issuance.capability_kind_code).payload_field_code
      if (!request || request.operation_code !== rule.consumer_operation_code || request.operation_id !== issuance.operation_id || request.operation_nonce !== issuance.operation_nonce || request.payload[fieldCode]?.capability_sha256 !== issuanceDigest || request.created_at > transition.occurred_at) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability transition does not bind its exact consuming request')
      findBinding(bindings, transition.recorded_by_binding_code, 'custody_adapter', transition.occurred_at)
      if (issuance.capability_kind_code === 'sealed_custody_access' && rule.trigger_code === 'authenticated_request_accepted_atomic_claim') {
        const scope = issuance.grant_scope
        const clearance = context.clearances.get(scope.clearance_decision_record_digest_sha256)
        assertCurrentPilotClearance(clearance, context, bindings, runtime, classification, transition.occurred_at, issuance.artifact, scope.clearance_scope_sha256, scope.clearance_decision_record_digest_sha256)
      }
      if (rule.response_policy_code !== 'must_be_null') {
        const response = responses.get(transition.response_record_digest_sha256)
        const messageRule = classification.custody_message_rules.find((item) => item.operation_code === request.operation_code)
        const responseMatches = rule.response_policy_code === 'required'
          ? messageRule?.success_outcomes.includes(response?.payload.outcome_code)
          : response?.payload.outcome_code === 'corrupt' && response?.payload.error_code === 'CUSTODY_CORRUPT'
        if (!response || response.request_record_digest_sha256 !== request.record_digest_sha256 || !responseMatches || response.created_at !== transition.occurred_at) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability transition lacks its exact required success or corruption response')
      } else {
        const response = [...responses.values()].find((item) => item.request_record_digest_sha256 === request.record_digest_sha256)
        if (transition.occurred_at < request.created_at || (response && transition.occurred_at > response.created_at)) fail('semantic', 'IPC_REPLAY_DETECTED', 'adapter-authored single-use claim falls outside request receipt and response production')
      }
      state = transition.to_state_code
      previous = transition
      previousAt = transition.occurred_at
    }
    finalStates.set(issuanceDigest, state)
  }
  const expectedTransitionRequests = new Set()
  for (const request of requests.values()) {
    for (const fieldCode of ['source_handle_token', 'preparation_token', 'sealed_capability_token']) {
      const envelope = request.payload[fieldCode]
      if (envelope === null) continue
      const issuance = controls.issuances.get(envelope.capability_sha256)
      if (!issuance) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability-consuming request lacks its protected issuance')
      const rules = classification.custody_capability_transition_rules.filter((item) => item.capability_kind_code === issuance.capability_kind_code && item.consumer_operation_code === request.operation_code)
      if (rules.length === 0) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability is used by an operation outside its frozen graph')
      const response = [...responses.values()].find((item) => item.request_record_digest_sha256 === request.record_digest_sha256)
      const responseRule = classification.custody_message_rules.find((item) => item.operation_code === request.operation_code)
      const transitionRequired = rules.some((rule) => rule.response_policy_code === 'must_be_null') || (response && (responseRule?.success_outcomes.includes(response.payload.outcome_code) || response.payload.outcome_code === 'corrupt'))
      if (transitionRequired) expectedTransitionRequests.add(request.record_digest_sha256)
    }
  }
  const actualTransitionRequests = controls.transitions.map((transition) => transition.request_record_digest_sha256)
  unique(actualTransitionRequests, 'semantic', 'IPC_REPLAY_DETECTED', 'capability-consuming transition request')
  if (canonical(actualTransitionRequests.toSorted()) !== canonical([...expectedTransitionRequests].toSorted())) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability transitions are not a bijection with accepted consuming requests')
  return finalStates
}

function assertCustodyCapabilitySequence(messages, controls, bindings, runtime, classification) {
  unique(messages.map((message) => message.record_digest_sha256), 'semantic', 'IPC_REPLAY_DETECTED', 'custody message digest')
  const ipcState = { nonces: new Map(), streams: new Map(), requestIds: new Set(), requests: new Map(), responses: new Set() }
  for (const message of messages) {
    assertDigest(message)
    registerIpcMessage(message, ipcState)
  }
  const requests = new Map(messages.filter((message) => message.message_kind_code === 'request').map((message) => [message.record_digest_sha256, message]))
  const context = { ...controls, requests, responses: new Map(messages.filter((message) => message.message_kind_code === 'response').map((message) => [message.record_digest_sha256, message])) }
  for (const response of context.responses.values()) {
    const request = requests.get(response.request_record_digest_sha256)
    if (!request) fail('semantic', 'IPC_REPLAY_DETECTED', 'custody response lacks an exact request in its stream')
    assertIpcPair(request, response, bindings, runtime, classification, context)
  }
  const exposures = new Map()
  for (const message of messages) {
    for (const fieldCode of ['source_handle_token', 'preparation_token', 'sealed_capability_token']) {
      const capability = message.payload[fieldCode]
      if (capability === null) continue
      const capabilityRule = classification.custody_capability_rules.find((item) => item.payload_field_code === fieldCode && item.capability_kind_code === capability.capability_kind_code)
      const issuanceExposure = message.message_kind_code === 'response' && capabilityRule?.issuance_operation_code === message.operation_code && capabilityRule?.issuance_outcome_code === message.payload.outcome_code
      const basisRequest = issuanceExposure ? requests.get(message.request_record_digest_sha256) : message
      assertCustodyCapability(capability, fieldCode, message, bindings, runtime, classification, context, message.payload.artifact ?? basisRequest?.payload.artifact ?? capability.artifact, { issuance: issuanceExposure })
      if (issuanceExposure) exposures.set(capability.capability_sha256, (exposures.get(capability.capability_sha256) ?? 0) + 1)
    }
  }
  for (const issuance of controls.issuances.values()) {
    const basisIsPresent = requests.has(issuance.grant_scope.basis_request_record_digest_sha256)
    if (basisIsPresent && (exposures.get(issuance.record_digest_sha256) ?? 0) !== 1) fail('semantic', 'IPC_REPLAY_DETECTED', 'capability issuance exposure cardinality is invalid')
  }
  return assertCapabilityControlHistory(context, messages, bindings, runtime, classification)
}

function assertCustodyOperationMatrix(fixtures, registry, classification) {
  const requestBase = fixtures.get('custody_open_request').value
  const responseBase = fixtures.get('custody_open_response').value
  const runtime = fixtures.get('runtime_profile').value
  const bindings = fixtures.get('identity_bindings').value
  const clearance = fixtures.get('clearance_decision').value
  const handoff = fixtures.get('collector_handoff').value
  const documentSeal = fixtures.get('document_bundle_seal').value
  const documentManifest = parseJsonBytes(fs.readFileSync(completeDocumentManifestPath), { contractNumbers: true, maximumBytes: pilotLimits.manifest_bytes_max })
  const custodyRecords = custodyRecordsFromManifest(documentManifest)
  const artifact = structuredClone(responseBase.payload.artifact)
  const backendReference = `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}`
  const descriptor = (role) => [{ ordinal: 1, role_code: role, access_code: 'read_only', file_type_code: 'regular_file' }]
  const blankPayload = () => Object.fromEntries(nullableCustodyPayloadKeys.map((key) => [key, null]))
  const make = (kind, operation, payload, descriptors = [], sequence = 1, createdAt = '2030-01-01T00:07:00.000Z', requestDigest = null) => {
    const message = structuredClone(kind === 'request' ? requestBase : responseBase)
    message.record_code = `synthetic.custody-${kind}-${operation}-${sequence}`
    message.message_kind_code = kind
    message.operation_code = operation
    message.request_id = `synthetic.request-${sequence}`
    message.request_sequence = sequence
    message.created_at = createdAt
    message.request_record_digest_sha256 = requestDigest
    message.ancillary_descriptors = descriptors
    message.payload = { ...blankPayload(), ...payload }
    message.record_digest_sha256 = recordDigest(message)
    validateContractStructure(message, 'custody-adapter-message-v1.schema.json', registry)
    assertDigest(message)
    assertCustodyMessageMatrix(message, classification)
    return message
  }
  const pair = (operation, requestPayload, responsePayload, requestDescriptors, responseDescriptors, sequence, requestAt, responseAt) => {
    const request = make('request', operation, requestPayload, requestDescriptors, sequence, requestAt)
    const response = make('response', operation, responsePayload, responseDescriptors, sequence, responseAt, request.record_digest_sha256)
    return [request, response]
  }
  const makeIssuance = (kind, basisRequest, issuedAt, expiresAt, authorizationScope) => {
    const rule = classification.custody_capability_rules.find((item) => item.capability_kind_code === kind)
    const issuance = {
      format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_issuance',
      record_code: `synthetic.capability-${kind}-${basisRequest?.request_sequence ?? 5}`, capability_kind_code: kind,
      issued_by_binding_code: 'binding.custody-adapter',
      requester_binding_code: 'binding.importer', adapter_binding_code: 'binding.custody-adapter',
      operation_id: requestBase.operation_id, operation_nonce: requestBase.operation_nonce,
      runtime_profile_record_digest_sha256: runtime.record_digest_sha256, identity_bindings_record_digest_sha256: bindings.record_digest_sha256,
      artifact: structuredClone(artifact), allowed_consumer_operation_codes: structuredClone(rule.allowed_consumer_operation_codes),
      replay_policy_code: rule.replay_policy_code, grant_scope: authorizationScope,
      issued_at: issuedAt, expires_at: expiresAt, record_digest_sha256: '0'.repeat(64),
    }
    issuance.record_digest_sha256 = recordDigest(issuance)
    validateContractStructure(issuance, 'custody-capability-control-v1.schema.json', registry)
    assertDigest(issuance)
    return issuance
  }
  const makeTransition = (issuance, rule, request, response, sequence, previous = null, acceptedAt = null) => {
    const transition = {
      format: 'jedi-atlas-custody-capability-control', format_version: '1.0.0', record_kind_code: 'capability_transition',
      record_code: `synthetic.capability-transition-${issuance.capability_kind_code}-${sequence}-${request.request_sequence}`,
      capability_kind_code: issuance.capability_kind_code, capability_record_digest_sha256: issuance.record_digest_sha256,
      transition_sequence: sequence, previous_transition_record_digest_sha256: previous?.record_digest_sha256 ?? null,
      from_state_code: rule.from_state_code, to_state_code: rule.to_state_code, transition_code: rule.transition_code,
      request_record_digest_sha256: request.record_digest_sha256, response_record_digest_sha256: response?.record_digest_sha256 ?? null,
      recorded_by_binding_code: 'binding.custody-adapter', occurred_at: response?.created_at ?? acceptedAt ?? request.created_at,
      reason_code: rule.reason_code, record_digest_sha256: '0'.repeat(64),
    }
    transition.record_digest_sha256 = recordDigest(transition)
    validateContractStructure(transition, 'custody-capability-control-v1.schema.json', registry)
    assertDigest(transition)
    return transition
  }
  const openRequest = make('request', 'open_staged', { staging_root_slot_code: 'staging_root', relative_path: handoff.staged_path, bundle_seal_record_digest_sha256: documentSeal.record_digest_sha256, collector_handoff_record_digest_sha256: handoff.record_digest_sha256, staging_snapshot_code: handoff.staging_snapshot_code }, [], 1, '2030-01-01T00:07:00.000Z')
  const sourceIssuance = makeIssuance('source_handle', openRequest, '2030-01-01T00:07:01.000Z', '2030-01-01T00:07:31.000Z', { scope_kind_code: 'source_handle', basis_request_record_digest_sha256: openRequest.record_digest_sha256, bundle_seal_record_digest_sha256: documentSeal.record_digest_sha256, collector_handoff_record_digest_sha256: handoff.record_digest_sha256, staging_snapshot_code: handoff.staging_snapshot_code, staging_root_slot_code: 'staging_root', relative_path: handoff.staged_path, descriptor_role_code: 'staged_source', staged_source_descriptor_ordinal: 1 })
  const source = capabilityEnvelopeFromIssuance(sourceIssuance)
  const openResponse = make('response', 'open_staged', { artifact, bundle_seal_record_digest_sha256: documentSeal.record_digest_sha256, source_handle_token: source, outcome_code: 'opened' }, descriptor('staged_source'), 1, '2030-01-01T00:07:01.000Z', openRequest.record_digest_sha256)
  const openPair = [openRequest, openResponse]
  const prepareRequest = make('request', 'prepare', { artifact, source_handle_token: source }, descriptor('staged_source'), 2, '2030-01-01T00:07:02.000Z')
  const sourceRule = classification.custody_capability_transition_rules.find((rule) => rule.capability_kind_code === 'source_handle')
  const sourceConsumed = makeTransition(sourceIssuance, sourceRule, prepareRequest, null, 1, null, '2030-01-01T00:07:02.500Z')
  const preparationIssuance = makeIssuance('preparation', prepareRequest, '2030-01-01T00:07:03.000Z', '2030-01-01T00:22:03.000Z', { scope_kind_code: 'preparation', basis_request_record_digest_sha256: prepareRequest.record_digest_sha256, source_capability_record_digest_sha256: sourceIssuance.record_digest_sha256, pending_object_code: 'synthetic.pending-object-001' })
  const preparation = capabilityEnvelopeFromIssuance(preparationIssuance)
  const prepareResponse = make('response', 'prepare', { preparation_token: preparation, outcome_code: 'prepared' }, [], 2, '2030-01-01T00:07:03.000Z', prepareRequest.record_digest_sha256)
  const preparePair = [prepareRequest, prepareResponse]
  const verifyPair = pair('verify_prepared', { artifact, preparation_token: preparation }, { artifact, preparation_token: preparation, outcome_code: 'verified' }, [], [], 3, '2030-01-01T00:07:04.000Z', '2030-01-01T00:07:05.000Z')
  const verifyRule = classification.custody_capability_transition_rules.find((rule) => rule.capability_kind_code === 'preparation' && rule.to_state_code === 'verified')
  const preparationVerified = makeTransition(preparationIssuance, verifyRule, verifyPair[0], verifyPair[1], 1)
  const publishPair = pair('publish_no_replace', { artifact, preparation_token: preparation, backend_code: 'pilot_local_cas_v1', backend_reference: backendReference }, { artifact, backend_code: 'pilot_local_cas_v1', backend_reference: backendReference, outcome_code: 'published', durability_receipt_sha256: '3'.repeat(64) }, [], [], 4, '2030-01-01T00:07:06.000Z', '2030-01-01T00:07:07.000Z')
  const wrongCasRequest = structuredClone(publishPair[0])
  wrongCasRequest.payload.backend_reference = `objects/sha256/99/${'9'.repeat(64)}`
  assert.throws(() => assertCustodyMessageMatrix(wrongCasRequest, classification), /IPC_REPLAY_DETECTED/)
  const publishRule = classification.custody_capability_transition_rules.find((rule) => rule.capability_kind_code === 'preparation' && rule.to_state_code === 'consumed')
  const preparationConsumed = makeTransition(preparationIssuance, publishRule, publishPair[0], publishPair[1], 2, preparationVerified)
  const custodyLeafDigest = custodyLeafProjectionDigest(resolveCustodyLeaf(custodyRecords, artifact, 'synthetic.copy-001', '2030-01-01T00:08:03.000Z', 2))
  if (custodyLeafDigest !== '25a5681e404a7fcc6f981703cad88a564fd07acffb7603d692f9aa04040013ae') fail('fixture', 'FIXTURE_INVALID', 'independent custody-leaf projection vector mismatch')
  const sealRequest = make('request', 'seal_custody_access', { artifact, backend_code: 'pilot_local_cas_v1', backend_reference: backendReference, copy_code: 'synthetic.copy-001', purpose_code: 'integrity', clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256 }, [], 5, '2030-01-01T00:08:02.000Z')
  const sealedIssuance = makeIssuance('sealed_custody_access', sealRequest, '2030-01-01T00:08:03.000Z', '2030-01-01T00:08:33.000Z', { scope_kind_code: 'sealed_custody_access', basis_request_record_digest_sha256: sealRequest.record_digest_sha256, clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256, custody_leaf_projection_sha256: custodyLeafDigest, backend_code: 'pilot_local_cas_v1', backend_reference: backendReference, copy_code: 'synthetic.copy-001', purpose_code: 'integrity', custody_evaluated_at: '2030-01-01T00:08:03.000Z', known_through_bundle_sequence: 2 })
  const sealed = capabilityEnvelopeFromIssuance(sealedIssuance)
  const sealResponse = make('response', 'seal_custody_access', { artifact, backend_code: 'pilot_local_cas_v1', backend_reference: backendReference, copy_code: 'synthetic.copy-001', purpose_code: 'integrity', custody_evaluated_at: '2030-01-01T00:08:03.000Z', known_through_bundle_sequence: 2, clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256, custody_leaf_projection_sha256: custodyLeafDigest, sealed_capability_token: sealed, outcome_code: 'sealed' }, [], 5, '2030-01-01T00:08:03.000Z', sealRequest.record_digest_sha256)
  const sealPair = [sealRequest, sealResponse]
  const custodyPair = pair('open_custody', { artifact, backend_code: 'pilot_local_cas_v1', backend_reference: backendReference, copy_code: 'synthetic.copy-001', purpose_code: 'integrity', sealed_capability_token: sealed }, { artifact, backend_code: 'pilot_local_cas_v1', backend_reference: backendReference, copy_code: 'synthetic.copy-001', purpose_code: 'integrity', custody_evaluated_at: '2030-01-01T00:08:05.000Z', known_through_bundle_sequence: 2, clearance_decision_record_digest_sha256: clearance.record_digest_sha256, clearance_scope_sha256: clearance.clearance_scope_sha256, custody_leaf_projection_sha256: custodyLeafDigest, outcome_code: 'available' }, [], descriptor('custody_source'), 6, '2030-01-01T00:08:04.000Z', '2030-01-01T00:08:05.000Z')
  const sealedRule = classification.custody_capability_transition_rules.find((rule) => rule.capability_kind_code === 'sealed_custody_access')
  const sealedConsumed = makeTransition(sealedIssuance, sealedRule, custodyPair[0], null, 1, null, '2030-01-01T00:08:04.500Z')
  const abandonRequest = make('request', 'abandon_temp', { preparation_token: preparation }, [], 7, '2030-01-01T00:07:08.000Z')
  const abandonResponse = make('response', 'abandon_temp', { preparation_token: preparation, outcome_code: 'already_absent' }, [], 7, '2030-01-01T00:07:09.000Z', abandonRequest.record_digest_sha256)
  const successCases = [...openPair, ...preparePair, ...verifyPair, ...publishPair, ...sealPair, ...custodyPair, abandonRequest, abandonResponse]
  const validSequence = [...openPair, ...preparePair, ...verifyPair, ...publishPair, ...sealPair, ...custodyPair]
  const controls = {
    issuances: new Map([sourceIssuance, preparationIssuance, sealedIssuance].map((issuance) => [issuance.record_digest_sha256, issuance])),
    transitions: [sourceConsumed, preparationVerified, preparationConsumed, sealedConsumed],
    clearances: new Map([[clearance.record_digest_sha256, clearance]]),
    handoffs: new Map([[handoff.record_digest_sha256, handoff]]),
    bundleSeals: new Map([[documentSeal.record_digest_sha256, documentSeal]]),
    clearanceTransitions: [],
    clearanceReplacements: new Map(),
    custodyRecords,
    currentBundleSequence: 2,
  }
  assertCustodyCapabilitySequence(validSequence, controls, bindings, runtime, classification)
  const sourceDependencyMutations = []
  const rejectSourceDependency = (label, mutateSeal = null, mutateHandoff = null) => {
    const protectedHandoff = structuredClone(handoff)
    if (mutateHandoff) mutateHandoff(protectedHandoff)
    protectedHandoff.record_digest_sha256 = recordDigest(protectedHandoff)
    const protectedSeal = structuredClone(documentSeal)
    protectedSeal.collector_handoffs = [{
      format: protectedHandoff.format,
      format_version: protectedHandoff.format_version,
      record_code: protectedHandoff.record_code,
      record_digest_sha256: protectedHandoff.record_digest_sha256,
    }]
    if (mutateSeal) mutateSeal(protectedSeal)
    protectedSeal.record_digest_sha256 = recordDigest(protectedSeal)
    const protectedRequest = structuredClone(openRequest)
    protectedRequest.payload.bundle_seal_record_digest_sha256 = protectedSeal.record_digest_sha256
    protectedRequest.payload.collector_handoff_record_digest_sha256 = protectedHandoff.record_digest_sha256
    protectedRequest.record_digest_sha256 = recordDigest(protectedRequest)
    const protectedIssuance = structuredClone(sourceIssuance)
    protectedIssuance.grant_scope.basis_request_record_digest_sha256 = protectedRequest.record_digest_sha256
    protectedIssuance.grant_scope.bundle_seal_record_digest_sha256 = protectedSeal.record_digest_sha256
    protectedIssuance.grant_scope.collector_handoff_record_digest_sha256 = protectedHandoff.record_digest_sha256
    protectedIssuance.record_digest_sha256 = recordDigest(protectedIssuance)
    const protectedControls = {
      ...controls,
      requests: new Map([[protectedRequest.record_digest_sha256, protectedRequest]]),
      issuances: new Map([[protectedIssuance.record_digest_sha256, protectedIssuance]]),
      handoffs: new Map([[protectedHandoff.record_digest_sha256, protectedHandoff]]),
      bundleSeals: new Map([[protectedSeal.record_digest_sha256, protectedSeal]]),
    }
    assert.throws(() => assertCapabilityIssuance(protectedIssuance, protectedControls, bindings, runtime, classification), /IPC_REPLAY_DETECTED|IDENTITY_BINDING_MISMATCH/, `${label} unexpectedly passed`)
    sourceDependencyMutations.push(label)
  }
  rejectSourceDependency('source-capability-cross-operation-bundle-seal', (seal) => { seal.operation_id = 'synthetic.other-operation' })
  rejectSourceDependency('source-capability-wrong-bundle-kind', (seal) => { seal.bundle_kind_code = 'principal_bootstrap' })
  rejectSourceDependency('source-capability-wrong-collector-principal', null, (item) => { item.collector_principal_code = 'synthetic.importer' })
  rejectSourceDependency('source-capability-wrong-collector-build', null, (item) => { item.collector_build_sha256 = '9'.repeat(64) })
  rejectSourceDependency('source-capability-handoff-before-actor-binding', null, (item) => {
    item.collection_started_at = '2030-01-01T00:00:10.000Z'
    item.collection_completed_at = '2030-01-01T00:00:11.000Z'
    item.handoff_recorded_at = '2030-01-01T00:00:12.000Z'
  })
  rejectSourceDependency('source-capability-seal-before-actor-binding', (seal) => { seal.sealed_at = '2030-01-01T00:00:30.000Z' })
  rejectSourceDependency('source-capability-handoff-expires-between-request-and-issuance', null, (item) => { item.expires_at = '2030-01-01T00:07:00.500Z' })
  rejectSourceDependency('source-capability-seal-expires-between-request-and-issuance', (seal) => { seal.expires_at = '2030-01-01T00:07:00.500Z' })
  for (const [label, original] of [['seal', sealRequest], ['open', custodyPair[0]]]) {
    const callerSelectedTime = structuredClone(original)
    callerSelectedTime.payload.custody_evaluated_at = '2030-01-01T00:05:15.000Z'
    assert.throws(() => assertCustodyMessageMatrix(callerSelectedTime, classification), /IPC_MALFORMED/)
    const callerSelectedSequence = structuredClone(original)
    callerSelectedSequence.payload.known_through_bundle_sequence = 1
    assert.throws(() => assertCustodyMessageMatrix(callerSelectedSequence, classification), /IPC_MALFORMED/)
  }
  const requiredTransitionOmissions = []
  for (const transition of controls.transitions) {
    const omitted = { ...controls, transitions: controls.transitions.filter((item) => item.record_digest_sha256 !== transition.record_digest_sha256) }
    assert.throws(() => assertCustodyCapabilitySequence(validSequence, omitted, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
    requiredTransitionOmissions.push(transition.capability_kind_code === 'preparation' ? `${transition.capability_kind_code}-${transition.to_state_code}` : transition.capability_kind_code)
  }
  const wrongExposure = structuredClone(openResponse)
  wrongExposure.request_record_digest_sha256 = prepareRequest.record_digest_sha256
  wrongExposure.record_digest_sha256 = recordDigest(wrongExposure)
  assert.throws(() => assertCustodyCapability(source, 'source_handle_token', wrongExposure, bindings, runtime, classification, { ...controls, requests: new Map([[openRequest.record_digest_sha256, openRequest], [prepareRequest.record_digest_sha256, prepareRequest]]) }, artifact, { issuance: true }), /IPC_REPLAY_DETECTED/)
  const failureCode = (outcome) => outcome === 'retryable_failure' ? 'CUSTODY_TIMEOUT' : outcome === 'corrupt' ? 'CUSTODY_CORRUPT' : 'CUSTODY_CONFLICT'
  const failureCases = classification.custody_message_rules.flatMap((rule) => rule.failure_outcomes.map((outcome) => make('response', rule.operation_code, { outcome_code: outcome, error_code: failureCode(outcome) })))
  const verifyCorrupt = make('response', 'verify_prepared', { outcome_code: 'corrupt', error_code: 'CUSTODY_CORRUPT' }, [], 3, '2030-01-01T00:07:05.000Z', verifyPair[0].record_digest_sha256)
  const verifyCorruptRule = classification.custody_capability_transition_rules.find((rule) => rule.capability_kind_code === 'preparation' && rule.from_state_code === 'ready' && rule.response_policy_code === 'required_corrupt')
  const preparationInvalidatedAtVerify = makeTransition(preparationIssuance, verifyCorruptRule, verifyPair[0], verifyCorrupt, 1)
  const verifyCorruptSequence = [...openPair, ...preparePair, verifyPair[0], verifyCorrupt]
  const verifyCorruptControls = { ...controls, issuances: new Map([sourceIssuance, preparationIssuance].map((issuance) => [issuance.record_digest_sha256, issuance])), transitions: [sourceConsumed, preparationInvalidatedAtVerify] }
  assertCustodyCapabilitySequence(verifyCorruptSequence, verifyCorruptControls, bindings, runtime, classification)
  const publishCorrupt = make('response', 'publish_no_replace', { outcome_code: 'corrupt', error_code: 'CUSTODY_CORRUPT' }, [], 4, '2030-01-01T00:07:07.000Z', publishPair[0].record_digest_sha256)
  const publishCorruptRule = classification.custody_capability_transition_rules.find((rule) => rule.capability_kind_code === 'preparation' && rule.from_state_code === 'verified' && rule.response_policy_code === 'required_corrupt')
  const preparationInvalidatedAtPublish = makeTransition(preparationIssuance, publishCorruptRule, publishPair[0], publishCorrupt, 2, preparationVerified)
  const publishCorruptSequence = [...openPair, ...preparePair, ...verifyPair, publishPair[0], publishCorrupt]
  const publishCorruptControls = { ...controls, issuances: new Map([sourceIssuance, preparationIssuance].map((issuance) => [issuance.record_digest_sha256, issuance])), transitions: [sourceConsumed, preparationVerified, preparationInvalidatedAtPublish] }
  assertCustodyCapabilitySequence(publishCorruptSequence, publishCorruptControls, bindings, runtime, classification)
  assert.throws(() => assertCustodyCapabilitySequence(verifyCorruptSequence, { ...verifyCorruptControls, transitions: [sourceConsumed] }, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  const retryableVerify = make('response', 'verify_prepared', { outcome_code: 'retryable_failure', error_code: 'CUSTODY_TIMEOUT' }, [], 3, '2030-01-01T00:07:05.000Z', verifyPair[0].record_digest_sha256)
  assertCustodyCapabilitySequence([...openPair, ...preparePair, verifyPair[0], retryableVerify], { ...verifyCorruptControls, transitions: [sourceConsumed] }, bindings, runtime, classification)
  assert.throws(() => assertCustodyCapabilitySequence([...verifyCorruptSequence, abandonRequest, abandonResponse], verifyCorruptControls, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  for (const message of successCases) {
    const extra = structuredClone(message)
    const unused = nullableCustodyPayloadKeys.find((key) => extra.payload[key] === null)
    if (unused) {
      extra.payload[unused] = unused === 'known_through_bundle_sequence' ? 1 : unused === 'artifact' ? artifact : unused.endsWith('_token') ? source : '5'.repeat(64)
      assert.throws(() => assertCustodyMessageMatrix(extra, classification), /IPC_MALFORMED/)
    }
  }
  const wrongDescriptor = structuredClone(successCases.find((message) => message.message_kind_code === 'request' && message.operation_code === 'prepare'))
  wrongDescriptor.ancillary_descriptors[0].role_code = 'custody_source'
  assert.throws(() => assertCustodyMessageMatrix(wrongDescriptor, classification), /IPC_MALFORMED/)
  for (const failure of failureCases) {
    for (const forbidden of nullableCustodyPayloadKeys.filter((key) => !['outcome_code', 'error_code'].includes(key))) {
      const impossible = structuredClone(failure)
      impossible.payload[forbidden] = forbidden === 'known_through_bundle_sequence' ? 1 : forbidden === 'artifact' ? artifact : forbidden.endsWith('_token') ? source : '5'.repeat(64)
      assert.throws(() => assertCustodyMessageMatrix(impossible, classification), /IPC_MALFORMED/)
    }
  }
  const mismatchedFailure = structuredClone(failureCases.find((message) => message.payload.outcome_code === 'rejected'))
  mismatchedFailure.payload.error_code = 'CUSTODY_CORRUPT'
  assert.throws(() => assertCustodyMessageMatrix(mismatchedFailure, classification), /IPC_MALFORMED/)
  const publishBeforeVerify = [...openPair, ...preparePair, ...publishPair]
  assert.throws(() => assertCustodyCapabilitySequence(publishBeforeVerify, controls, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  assert.throws(() => assertCustodyCapabilitySequence([...validSequence, publishPair[0]], controls, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  const capabilityLineageMutations = ['publish-before-verification', 'replayed-publish-request', 'cross-request-capability-exposure', 'content-addressed-backend-reference-mismatch', 'verify-corrupt-terminal-invalidation', 'publish-corrupt-terminal-invalidation', 'corrupt-response-without-invalidation', 'retryable-response-preserves-capability', 'invalidated-capability-reuse', ...sourceDependencyMutations, ...requiredTransitionOmissions.map((item) => `missing-required-transition-${item}`)]
  const lateClaim = structuredClone(sealedConsumed)
  lateClaim.record_code = 'synthetic.capability-transition-late-claim'
  lateClaim.occurred_at = '2030-01-01T00:08:33.001Z'
  lateClaim.record_digest_sha256 = recordDigest(lateClaim)
  const lateResponse = structuredClone(custodyPair[1])
  lateResponse.record_code = 'synthetic.custody-open-late-response'
  lateResponse.created_at = '2030-01-01T00:08:33.002Z'
  lateResponse.payload.custody_evaluated_at = lateResponse.created_at
  lateResponse.record_digest_sha256 = recordDigest(lateResponse)
  const lateSequence = validSequence.map((message) => message.record_digest_sha256 === custodyPair[1].record_digest_sha256 ? lateResponse : message)
  const lateControls = { ...controls, transitions: controls.transitions.map((transition) => transition.record_digest_sha256 === sealedConsumed.record_digest_sha256 ? lateClaim : transition) }
  assert.throws(() => assertCustodyCapabilitySequence(lateSequence, lateControls, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('adapter-claim-after-capability-expiry-despite-backdated-request')
  for (const [label, mutate] of [
    ['operation', (value) => { value.operation_id = 'synthetic.operation-other' }],
    ['nonce', (value) => { value.operation_nonce = '9'.repeat(64) }],
    ['runtime', (value) => { value.runtime_profile_record_digest_sha256 = '8'.repeat(64) }],
    ['artifact', (value) => { value.artifact.sha256 = '7'.repeat(64) }],
    ['requester', (value) => { value.requester_binding_code = 'binding.collector' }],
    ['adapter', (value) => { value.adapter_binding_code = 'binding.scanner' }],
    ['expiry', (value) => { value.expires_at = value.issued_at }],
  ]) {
    const mutated = structuredClone(preparePair[0])
    mutate(mutated.payload.source_handle_token)
    mutated.record_digest_sha256 = recordDigest(mutated)
    const sourceOnlyControls = { issuances: new Map([[sourceIssuance.record_digest_sha256, sourceIssuance]]), transitions: [sourceConsumed], clearances: new Map(), custodyRecords: [], currentBundleSequence: 2 }
    assert.throws(() => assertCustodyCapabilitySequence([...openPair, mutated], sourceOnlyControls, bindings, runtime, classification), /IPC_(?:REPLAY_DETECTED|PEER_MISMATCH)|IDENTITY_BINDING_MISMATCH/, `${label} capability mutation unexpectedly passed`)
    capabilityLineageMutations.push(`capability-envelope-${label}`)
  }
  const unknownCapabilityRequest = structuredClone(prepareRequest)
  unknownCapabilityRequest.payload.source_handle_token.capability_sha256 = 'f'.repeat(64)
  unknownCapabilityRequest.record_digest_sha256 = recordDigest(unknownCapabilityRequest)
  assert.throws(() => assertCustodyCapabilitySequence([...openPair, unknownCapabilityRequest], controls, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('unknown-protected-capability')

  const changedIssuance = structuredClone(sourceIssuance)
  changedIssuance.grant_scope.relative_path = 'synthetic/other-artifact.bin'
  changedIssuance.record_digest_sha256 = recordDigest(changedIssuance)
  const changedIssuanceControls = {
    issuances: new Map([[changedIssuance.record_digest_sha256, changedIssuance]]),
    transitions: [],
    requests: new Map([[openRequest.record_digest_sha256, openRequest]]),
    responses: new Map(),
    clearances: new Map(),
    custodyRecords: [],
    currentBundleSequence: 2,
  }
  assert.throws(() => assertCapabilityIssuance(changedIssuance, changedIssuanceControls, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('altered-protected-capability-scope')
  assert.throws(() => assertCapabilityControlHistory({
    ...controls,
    issuances: new Map([['f'.repeat(64), sourceIssuance]]),
    transitions: [],
  }, openPair, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('capability-store-key-mismatch')

  const assertTransitionMutation = (label, mutate, existingTransitions = []) => {
    const transition = structuredClone(sourceConsumed)
    mutate(transition)
    transition.record_digest_sha256 = recordDigest(transition)
    const transitionControls = {
      issuances: new Map([[sourceIssuance.record_digest_sha256, sourceIssuance]]),
      transitions: [...existingTransitions, transition],
      clearances: new Map(),
      custodyRecords: [],
      currentBundleSequence: 2,
    }
    assert.throws(() => assertCapabilityControlHistory(transitionControls, validSequence, bindings, runtime, classification), /IPC_REPLAY_DETECTED|IDENTITY_BINDING_MISMATCH/, `${label} capability transition unexpectedly passed`)
    capabilityLineageMutations.push(label)
  }
  assertTransitionMutation('capability-transition-gap', (transition) => {
    transition.record_code = 'synthetic.capability-transition-gap'
    transition.transition_sequence = 2
  })
  const competingSource = structuredClone(sourceConsumed)
  competingSource.record_code = 'synthetic.capability-transition-competing'
  competingSource.record_digest_sha256 = recordDigest(competingSource)
  const forkControls = { ...controls, transitions: [sourceConsumed, competingSource] }
  assert.throws(() => assertCapabilityControlHistory(forkControls, validSequence, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('competing-capability-successor')
  assertTransitionMutation('source-capability-terminal-resurrection', (transition) => {
    transition.record_code = 'synthetic.capability-transition-cycle'
    transition.transition_sequence = 2
    transition.previous_transition_record_digest_sha256 = transition.record_digest_sha256
    transition.from_state_code = 'consumed'
  }, [sourceConsumed])
  assertTransitionMutation('capability-transition-backdated', (transition) => {
    transition.record_code = 'synthetic.capability-transition-backdated'
    transition.occurred_at = sourceIssuance.issued_at
  })
  assertTransitionMutation('capability-transition-wrong-recorder', (transition) => {
    transition.record_code = 'synthetic.capability-transition-wrong-recorder'
    transition.recorded_by_binding_code = 'binding.importer'
  })
  const terminalSuccessor = structuredClone(preparationConsumed)
  terminalSuccessor.record_code = 'synthetic.capability-transition-resurrection'
  terminalSuccessor.transition_sequence = 3
  terminalSuccessor.previous_transition_record_digest_sha256 = preparationConsumed.record_digest_sha256
  terminalSuccessor.from_state_code = 'consumed'
  terminalSuccessor.to_state_code = 'abandoned'
  terminalSuccessor.transition_code = 'temporary_abandoned'
  terminalSuccessor.request_record_digest_sha256 = abandonRequest.record_digest_sha256
  terminalSuccessor.response_record_digest_sha256 = abandonResponse.record_digest_sha256
  terminalSuccessor.occurred_at = abandonResponse.created_at
  terminalSuccessor.reason_code = 'abandon_response'
  terminalSuccessor.record_digest_sha256 = recordDigest(terminalSuccessor)
  assert.throws(() => assertCapabilityControlHistory({ ...controls, transitions: [...controls.transitions, terminalSuccessor] }, [...validSequence, abandonRequest, abandonResponse], bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('terminal-capability-resurrection')

  const revokedSealedIssuance = structuredClone(sealedIssuance)
  revokedSealedIssuance.issued_at = '2030-01-01T00:09:01.000Z'
  revokedSealedIssuance.expires_at = '2030-01-01T00:09:31.000Z'
  revokedSealedIssuance.record_digest_sha256 = recordDigest(revokedSealedIssuance)
  assert.throws(() => assertCapabilityIssuance(revokedSealedIssuance, {
    ...controls,
    issuances: new Map([[revokedSealedIssuance.record_digest_sha256, revokedSealedIssuance]]),
    requests: new Map([[sealRequest.record_digest_sha256, sealRequest]]),
    clearanceTransitions: [fixtures.get('clearance_transition').value],
  }, bindings, runtime, classification), /IPC_REPLAY_DETECTED|CLEARANCE_INVALID/)
  capabilityLineageMutations.push('sealed-capability-after-clearance-revocation')

  const revokedAtUse = structuredClone(fixtures.get('clearance_transition').value)
  revokedAtUse.occurred_at = '2030-01-01T00:08:03.500Z'
  revokedAtUse.record_digest_sha256 = recordDigest(revokedAtUse)
  const sealedUseContext = {
    ...controls,
    requests: new Map([[sealRequest.record_digest_sha256, sealRequest], [custodyPair[0].record_digest_sha256, custodyPair[0]]]),
    responses: new Map([[sealResponse.record_digest_sha256, sealResponse], [custodyPair[1].record_digest_sha256, custodyPair[1]]]),
    clearanceTransitions: [revokedAtUse],
  }
  assert.throws(() => assertCustodyCapability(sealed, 'sealed_capability_token', custodyPair[0], bindings, runtime, classification, sealedUseContext, artifact), /IPC_REPLAY_DETECTED|CLEARANCE_INVALID/)
  capabilityLineageMutations.push('sealed-capability-clearance-revoked-before-use')

  const staleKnowledgeControls = { ...controls, currentBundleSequence: 3 }
  assert.throws(() => assertCustodyCapabilitySequence(validSequence, staleKnowledgeControls, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('sealed-capability-stale-knowledge-bound')

  const shortenedBindings = structuredClone(bindings)
  shortenedBindings.bindings.find((binding) => binding.binding_code === 'binding.custody-adapter').valid_until = '2030-01-01T00:08:20.000Z'
  assert.throws(() => assertCapabilityIssuance(sealedIssuance, { ...controls, requests: new Map([[sealRequest.record_digest_sha256, sealRequest]]) }, shortenedBindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('capability-outlives-adapter-binding')

  for (const eventKind of ['restricted', 'quarantined', 'tombstoned']) {
    const successor = {
      ...structuredClone(custodyRecords[0]),
      custody_event_code: `synthetic.bundle-003.custody-${eventKind}`,
      event_kind_code: eventKind,
      predecessor_custody_event_code: custodyRecords[0].custody_event_code,
      custody_class_code: 'restricted_store',
      backend_code: eventKind === 'tombstoned' ? null : custodyRecords[0].backend_code,
      backend_reference: eventKind === 'tombstoned' ? null : custodyRecords[0].backend_reference,
      reason: `Synthetic ${eventKind} successor.`,
      occurred_at: '2030-01-01T00:05:15.000Z',
      recorded_at: '2030-01-01T00:08:02.500Z',
      evidence_bundle: { bundle_digest_sha256: '7'.repeat(64), bundle_id: 'synthetic.bundle-003', bundle_sequence: 3 },
    }
    const changedRecords = [...custodyRecords, successor]
    const selected = resolveCustodyLeaf(changedRecords, artifact, 'synthetic.copy-001', '2030-01-01T00:08:03.000Z', 3)
    if (selected?.event_kind_code !== eventKind) fail('fixture', 'FIXTURE_INVALID', `custody ${eventKind} successor was not selected`)
    const changedSealRequest = structuredClone(sealRequest)
    const changedSealedIssuance = structuredClone(sealedIssuance)
    changedSealedIssuance.grant_scope.basis_request_record_digest_sha256 = changedSealRequest.record_digest_sha256
    changedSealedIssuance.grant_scope.known_through_bundle_sequence = 3
    changedSealedIssuance.grant_scope.custody_leaf_projection_sha256 = custodyLeafProjectionDigest(selected)
    changedSealedIssuance.record_digest_sha256 = recordDigest(changedSealedIssuance)
    assert.throws(() => assertCapabilityIssuance(changedSealedIssuance, { ...controls, currentBundleSequence: 3, custodyRecords: changedRecords, requests: new Map([[changedSealRequest.record_digest_sha256, changedSealRequest]]) }, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
    capabilityLineageMutations.push(`sealed-capability-${eventKind}-custody-leaf`)
  }

  const historicalRestriction = {
    ...structuredClone(custodyRecords[0]),
    custody_event_code: 'synthetic.bundle-003.custody-restricted-before-open',
    event_kind_code: 'restricted',
    predecessor_custody_event_code: custodyRecords[0].custody_event_code,
    custody_class_code: 'restricted_store',
    reason: 'Synthetic restriction known only after capability issuance.',
    occurred_at: '2030-01-01T00:05:30.000Z',
    recorded_at: '2030-01-01T00:08:03.500Z',
    evidence_bundle: { bundle_digest_sha256: '7'.repeat(64), bundle_id: 'synthetic.bundle-003', bundle_sequence: 3 },
  }
  const backdatedOpenRequest = structuredClone(custodyPair[0])
  backdatedOpenRequest.record_code = 'synthetic.custody-open-backdated-request'
  backdatedOpenRequest.request_id = 'synthetic.request-backdated-open'
  backdatedOpenRequest.created_at = '2030-01-01T00:08:03.250Z'
  backdatedOpenRequest.record_digest_sha256 = recordDigest(backdatedOpenRequest)
  const backdatedOpenResponse = structuredClone(custodyPair[1])
  backdatedOpenResponse.record_code = 'synthetic.custody-open-backdated-response'
  backdatedOpenResponse.request_id = backdatedOpenRequest.request_id
  backdatedOpenResponse.request_record_digest_sha256 = backdatedOpenRequest.record_digest_sha256
  backdatedOpenResponse.payload.known_through_bundle_sequence = 3
  backdatedOpenResponse.record_digest_sha256 = recordDigest(backdatedOpenResponse)
  const backdatedContext = {
    ...controls,
    currentBundleSequence: 3,
    custodyRecords: [...custodyRecords, historicalRestriction],
    requests: new Map([[sealRequest.record_digest_sha256, sealRequest], [backdatedOpenRequest.record_digest_sha256, backdatedOpenRequest]]),
    responses: new Map([[sealResponse.record_digest_sha256, sealResponse], [backdatedOpenResponse.record_digest_sha256, backdatedOpenResponse]]),
  }
  assert.throws(() => assertIpcPair(backdatedOpenRequest, backdatedOpenResponse, bindings, runtime, classification, backdatedContext), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('caller-backdated-open-cannot-bypass-later-known-restriction')

  const missingCustodyLeaf = structuredClone(sealedIssuance)
  missingCustodyLeaf.grant_scope.custody_leaf_projection_sha256 = '7'.repeat(64)
  missingCustodyLeaf.record_digest_sha256 = recordDigest(missingCustodyLeaf)
  assert.throws(() => assertCapabilityIssuance(missingCustodyLeaf, {
    ...controls,
    issuances: new Map([[missingCustodyLeaf.record_digest_sha256, missingCustodyLeaf]]),
    requests: new Map([[sealRequest.record_digest_sha256, sealRequest]]),
  }, bindings, runtime, classification), /IPC_REPLAY_DETECTED/)
  capabilityLineageMutations.push('sealed-capability-missing-custody-leaf')
  const processingPurpose = structuredClone(custodyPair[0])
  processingPurpose.payload.purpose_code = 'processing'
  assert.throws(() => validateContractStructure(processingPurpose, 'custody-adapter-message-v1.schema.json', registry), /MANIFEST_SCHEMA_INVALID/)
  capabilityLineageMutations.push('processing-purpose-disabled')
  return { direction_and_outcome_cases: successCases.length + failureCases.length, capability_lineage_mutations: capabilityLineageMutations, integrity_only_open: true }
}

function sqliteDigestValue(value) {
  if (value === null || typeof value === 'string') return value
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value
  if (value instanceof Uint8Array) return { blob_hex: Buffer.from(value).toString('hex') }
  fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `unsupported SQLite digest value ${typeof value}`)
}

function databaseTableDigest(database, table, digestProfiles) {
  const projection = digestProfiles.sqlite_projections.table_rows.projections.find((item) => item.table_code === table)
  if (!projection) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `missing row projection for ${table}`)
  const actualColumns = database.prepare(`PRAGMA table_info("${table}")`).all().map((row) => row.name)
  if (canonical(actualColumns) !== canonical(projection.columns) || canonical(projection.columns) !== canonical(projection.ordering_columns)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `${table} physical columns differ from its digest projection`)
  const select = projection.columns.map((column) => `"${column}"`).join(',')
  const order = projection.ordering_columns.map((column) => `"${column}" COLLATE BINARY ASC`).join(',')
  const rows = database.prepare(`SELECT ${select} FROM "${table}" ORDER BY ${order}`).all().map((row) => Object.fromEntries(projection.columns.map((column) => [column, sqliteDigestValue(row[column])])))
  return sha256(Buffer.from(canonical(rows), 'utf8'))
}

function databaseReceiptRowProjection(database, digestProfiles, bundle) {
  const specification = digestProfiles.sqlite_projections.receipt_row
  const rows = database.prepare(`
    SELECT r.bundle_sequence,
           r.bundle_code,
           r.format_version_code,
           r.bundle_digest_sha256,
           r.manifest_path,
           r.bundle_created_at,
           submitted.principal_code AS submitted_by_principal_code,
           imported.principal_code AS imported_by_principal_code,
           r.importer_software_code,
           r.importer_version,
           recorded.principal_code AS recorded_by_principal_code,
           r.recorded_at
      FROM atlas_evidence_bundle_receipts r
      JOIN atlas_principals submitted ON submitted.id = r.submitted_by_principal_id
      JOIN atlas_principals imported ON imported.id = r.imported_by_principal_id
      JOIN atlas_principals recorded ON recorded.id = r.recorded_by_principal_id
     WHERE r.bundle_code = ? AND r.bundle_sequence = ? AND r.bundle_digest_sha256 = ?
  `).all(bundle.bundle_id, bundle.bundle_sequence, bundle.bundle_digest_sha256)
  if (rows.length !== 1) fail('migration', 'MIGRATION_DRIFT', 'receipt projection does not resolve exactly one row by the sealed bundle tuple')
  const row = rows[0]
  if (canonical(Object.keys(row)) !== canonical(specification.output_fields)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'receipt SQL projection fields differ from the registry')
  return Object.fromEntries(specification.output_fields.map((field) => [field, sqliteDigestValue(row[field])]))
}

function insertSyntheticBootstrapState(database, manifest) {
  const principals = [manifest.principal_bootstrap.trust_root, ...manifest.principal_bootstrap.principals]
  const idsByCode = new Map(principals.map((principal) => [principal.principal_code, principal.id]))
  const insertPrincipal = database.prepare('INSERT INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at) VALUES (?,?,?,?,?)')
  for (const principal of principals) insertPrincipal.run(principal.id, principal.principal_code, principal.principal_kind_code, idsByCode.get(principal.created_by_principal_code), principal.created_at)
  database.prepare(`
    INSERT INTO atlas_evidence_bundle_receipts(
      id,bundle_sequence,bundle_code,format_version_code,bundle_digest_sha256,manifest_path,bundle_created_at,
      submitted_by_principal_id,imported_by_principal_id,importer_software_code,importer_version,recorded_by_principal_id,recorded_at
    ) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    manifest.bundle_sequence,
    manifest.bundle_id,
    manifest.format_version,
    manifest.bundle_digest_sha256,
    manifest.manifest_path,
    manifest.bundle_created_at,
    idsByCode.get(manifest.submitter_principal_code),
    idsByCode.get(manifest.expected_importer_principal_code),
    manifest.expected_importer_software_code,
    manifest.expected_importer_version,
    idsByCode.get(manifest.submitter_principal_code),
    manifest.bundle_created_at,
  )
}

function insertSyntheticDocumentState(database, manifest) {
  const principalRows = database.prepare('SELECT id,principal_code FROM atlas_principals').all()
  const principalIds = new Map(principalRows.map((row) => [row.principal_code, row.id]))
  const submitterId = principalIds.get(manifest.submitter_principal_code)
  const importerId = principalIds.get(manifest.expected_importer_principal_code)
  database.prepare(`
    INSERT INTO atlas_evidence_bundle_receipts(
      id,bundle_sequence,bundle_code,format_version_code,bundle_digest_sha256,manifest_path,bundle_created_at,
      submitted_by_principal_id,imported_by_principal_id,importer_software_code,importer_version,recorded_by_principal_id,recorded_at
    ) VALUES (2,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    manifest.bundle_sequence,
    manifest.bundle_id,
    manifest.format_version,
    manifest.bundle_digest_sha256,
    manifest.manifest_path,
    manifest.bundle_created_at,
    submitterId,
    importerId,
    manifest.expected_importer_software_code,
    manifest.expected_importer_version,
    submitterId,
    manifest.bundle_created_at,
  )
  const locationIds = new Map()
  const insertLocation = database.prepare('INSERT INTO atlas_retrieval_locations(id,location_code,location_url,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at) VALUES (?,?,?,?,?,?)')
  for (const [index, location] of manifest.retrieval_locations.entries()) {
    const id = index + 1
    insertLocation.run(id, location.record_code, location.url, 2, principalIds.get(location.recorded_by_principal_code), location.recorded_at)
    locationIds.set(location.record_code, id)
  }
  const artifactIds = new Map()
  const insertArtifact = database.prepare('INSERT INTO atlas_artifacts(id,artifact_code,byte_layer_code,hash_algorithm_code,sha256,byte_length,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at) VALUES (?,?,?,?,?,?,?,?,?)')
  for (const [index, artifact] of manifest.artifacts.entries()) {
    const id = index + 1
    insertArtifact.run(id, artifact.record_code, artifact.byte_layer_code, artifact.hash_algorithm_code, artifact.sha256, artifact.byte_length, 2, principalIds.get(artifact.recorded_by_principal_code), artifact.recorded_at)
    artifactIds.set(artifact.record_code, id)
  }
  const retrievalIds = new Map()
  const insertRetrieval = database.prepare(`
    INSERT INTO atlas_retrieval_events(
      id,retrieval_event_code,requested_location_id,last_attempted_location_id,resolved_location_id,
      conditional_basis_retrieval_event_id,conditional_validator_kind_code,conditional_validator_value,artifact_id,
      outcome_code,request_method_code,request_profile_code,request_accept,request_accept_language,request_accept_encoding,
      started_at,completed_at,captured_at,http_status_code,response_etag,response_last_modified,response_content_type,
      response_content_length,response_content_encoding,response_vary,detected_media_type,observed_sha256,observed_byte_length,
      collector_principal_id,collector_software_code,collector_version,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `)
  for (const [index, retrieval] of manifest.retrieval_events.entries()) {
    const id = index + 1
    const response = retrieval.response_metadata ?? {}
    insertRetrieval.run(
      id,
      retrieval.record_code,
      locationIds.get(retrieval.requested_location_code),
      locationIds.get(retrieval.last_attempted_location_code),
      retrieval.resolved_location_code === null ? null : locationIds.get(retrieval.resolved_location_code),
      retrieval.conditional_basis_retrieval_event_code === null ? null : retrievalIds.get(retrieval.conditional_basis_retrieval_event_code),
      retrieval.conditional_validator_kind_code,
      retrieval.conditional_validator_value,
      retrieval.artifact_code === null ? null : artifactIds.get(retrieval.artifact_code),
      retrieval.outcome_code,
      retrieval.request_method_code,
      retrieval.request_profile_code,
      retrieval.request_headers.accept,
      retrieval.request_headers.accept_language,
      retrieval.request_headers.accept_encoding,
      retrieval.started_at,
      retrieval.completed_at,
      retrieval.captured_at,
      retrieval.http_status_code,
      response.etag ?? null,
      response.last_modified ?? null,
      response.content_type ?? null,
      response.content_length ?? null,
      response.content_encoding ?? null,
      response.vary ?? null,
      retrieval.detected_media_type,
      retrieval.observed_sha256,
      retrieval.observed_byte_length,
      principalIds.get(retrieval.collector_principal_code),
      retrieval.collector_software_code,
      retrieval.collector_version,
      2,
      principalIds.get(retrieval.recorded_by_principal_code),
      retrieval.recorded_at,
    )
    retrievalIds.set(retrieval.record_code, id)
  }
  const custodyIds = new Map()
  const insertCustody = database.prepare(`
    INSERT INTO atlas_artifact_custody_events(
      id,custody_event_code,artifact_id,copy_code,event_kind_code,predecessor_custody_event_id,custody_class_code,
      backend_code,backend_reference,eligibility_declared_by_principal_id,eligibility_declared_at,
      redistribution_eligible_declared,no_sensitive_data_declared,size_eligible_declared,permanent_history_acknowledged,
      reason,occurred_at,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `)
  for (const [index, custody] of manifest.custody_events.entries()) {
    const id = index + 1
    const declaration = custody.repository_eligibility_declaration
    insertCustody.run(
      id,
      custody.record_code,
      artifactIds.get(custody.artifact_code),
      custody.copy_code,
      custody.event_kind_code,
      custody.predecessor_custody_event_code === null ? null : custodyIds.get(custody.predecessor_custody_event_code),
      custody.custody_class_code,
      custody.backend_code,
      custody.backend_reference,
      declaration === null ? null : principalIds.get(declaration.declared_by_principal_code),
      declaration?.declared_at ?? null,
      declaration?.redistribution_eligible ?? null,
      declaration?.no_sensitive_data ?? null,
      declaration?.size_eligible ?? null,
      declaration?.permanent_history_acknowledged ?? null,
      custody.reason,
      custody.occurred_at,
      2,
      principalIds.get(custody.recorded_by_principal_code),
      custody.recorded_at,
    )
    custodyIds.set(custody.record_code, id)
  }
}

function databaseSchemaProjection(database, digestProfiles, projectionCode) {
  const projection = digestProfiles.sqlite_projections.schema_inventories.find((item) => item.projection_code === projectionCode)
  if (!projection) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', `missing schema projection ${projectionCode}`)
  return database.prepare(projection.select_sql).all().map((row) => Object.fromEntries(Object.entries(row).map(([key, value]) => [key, sqliteDigestValue(value)])))
}

function assertFrozenMigrationsAndEmptyAtlas(fixtures, digestProfiles, goldenVectors) {
  const names = fs.readdirSync(migrationsRoot).filter((name) => name.endsWith('.sql')).sort()
  if (canonical(names) !== canonical(Object.keys(migrationHashes))) fail('migration', 'MIGRATION_DRIFT', 'migration inventory differs from frozen 001-005')
  for (const [name, expected] of Object.entries(migrationHashes)) if (rawFileSha256(path.join(migrationsRoot, name)) !== expected) fail('migration', 'MIGRATION_DRIFT', `${name} changed`)
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d90-db-'))
  const databasePath = path.join(root, 'atlas.sqlite')
  let projectionSummary
  try {
    const result = applyMigrations({ databasePath, migrationsDirectory: migrationsRoot })
    if (canonical(result.appliedNow) !== canonical(Object.keys(migrationHashes))) fail('migration', 'MIGRATION_DRIFT', 'fresh migration application differs')
    const rerun = applyMigrations({ databasePath, migrationsDirectory: migrationsRoot })
    if (rerun.appliedNow.length !== 0 || rerun.total !== Object.keys(migrationHashes).length) fail('migration', 'MIGRATION_DRIFT', 'migration no-op rerun differs')
    const database = new DatabaseSync(databasePath)
    try {
      database.exec('PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON;')
      const actualTables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,6) = 'atlas_' ORDER BY name COLLATE BINARY ASC").all().map((row) => row.name)
      if (canonical(actualTables) !== canonical(atlasTables)) fail('migration', 'MIGRATION_DRIFT', 'Atlas table inventory differs')
      for (const table of atlasTables) if (database.prepare(`SELECT count(*) AS count FROM ${table}`).get().count !== 0) fail('migration', 'ATLAS_NOT_EMPTY', `${table} is not empty`)
      const runtime = fixtures.get('runtime_profile').value
      const state = fixtures.get('logical_state_empty').value.state_payload
      const completeProjection = databaseSchemaProjection(database, digestProfiles, 'complete_schema')
      const legacyProjection = databaseSchemaProjection(database, digestProfiles, 'legacy_schema')
      const inventoryProjection = databaseSchemaProjection(database, digestProfiles, 'exact_object_inventory')
      const declaredLegacyObjects = digestProfiles.sqlite_projections.schema_inventories.find((item) => item.projection_code === 'legacy_schema').included_objects
      const observedLegacyObjects = legacyProjection.map(({ type, name, table_name }) => ({ type, name, table_name }))
      if (canonical(observedLegacyObjects) !== canonical(declaredLegacyObjects)) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'frozen legacy schema object set differs from the database')
      const completeSchemaSha = sha256(Buffer.from(canonical(completeProjection), 'utf8'))
      const legacySchemaSha = sha256(Buffer.from(canonical(legacyProjection), 'utf8'))
      const inventorySha = sha256(Buffer.from(canonical(inventoryProjection), 'utf8'))
      if (runtime.database_contract.complete_schema_sha256 !== completeSchemaSha || state.complete_schema_sha256 !== completeSchemaSha || runtime.database_contract.legacy_schema_sha256 !== legacySchemaSha || state.legacy_schema_sha256 !== legacySchemaSha || runtime.database_contract.exact_object_inventory_sha256 !== inventorySha) fail('migration', 'MIGRATION_DRIFT', 'runtime or state seal database inventory digest differs from actual SQLite')
      for (const row of state.legacy_rows) if (databaseTableDigest(database, row.table_code, digestProfiles) !== row.rows_sha256 || database.prepare(`SELECT count(*) AS count FROM "${row.table_code}"`).get().count !== row.row_count) fail('migration', 'MIGRATION_DRIFT', `legacy state digest differs for ${row.table_code}`)
      for (const row of state.atlas_tables) if (databaseTableDigest(database, row.table_code, digestProfiles) !== row.rows_sha256 || row.row_count !== 0) fail('migration', 'MIGRATION_DRIFT', `empty Atlas state digest differs for ${row.table_code}`)
      database.exec('BEGIN')
      try {
        database.exec('CREATE TABLE sqliteXshadow(id INTEGER PRIMARY KEY) STRICT')
        const completeNames = databaseSchemaProjection(database, digestProfiles, 'complete_schema').map((row) => row.name)
        const legacyNames = databaseSchemaProjection(database, digestProfiles, 'legacy_schema').map((row) => row.name)
        const inventoryNames = databaseSchemaProjection(database, digestProfiles, 'exact_object_inventory').map((row) => row.name)
        if (![completeNames, legacyNames, inventoryNames].every((names) => names.includes('sqliteXshadow'))) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'literal sqlite_ prefix projection omitted sqliteXshadow')
        const wildcardMutation = digestProfiles.sqlite_projections.schema_inventories.find((item) => item.projection_code === 'legacy_schema').select_sql.replace("substr(name,1,7) <> 'sqlite_'", "name NOT LIKE 'sqlite_%'")
        if (database.prepare(wildcardMutation).all().some((row) => row.name === 'sqliteXshadow')) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'wildcard-prefix mutation unexpectedly preserved sqliteXshadow')
      } finally {
        database.exec('ROLLBACK')
      }
      const manifest = goldenVectors.complete_manifest_vector.value
      insertSyntheticBootstrapState(database, manifest)
      const bootstrapState = fixtures.get('logical_state_bootstrap').value.state_payload
      const assertPostBootstrapTables = (declaredState) => {
        if (declaredState.complete_schema_sha256 !== completeSchemaSha || declaredState.legacy_schema_sha256 !== legacySchemaSha) fail('migration', 'MIGRATION_DRIFT', 'successor logical state schema digests differ from actual SQLite')
        for (const row of declaredState.legacy_rows) if (databaseTableDigest(database, row.table_code, digestProfiles) !== row.rows_sha256 || database.prepare(`SELECT count(*) AS count FROM "${row.table_code}"`).get().count !== row.row_count) fail('migration', 'MIGRATION_DRIFT', `post-bootstrap legacy digest differs for ${row.table_code}`)
        for (const row of declaredState.atlas_tables) {
          const actualCount = database.prepare(`SELECT count(*) AS count FROM "${row.table_code}"`).get().count
          if (databaseTableDigest(database, row.table_code, digestProfiles) !== row.rows_sha256 || actualCount !== row.row_count) fail('migration', 'MIGRATION_DRIFT', `post-bootstrap Atlas projection differs for ${row.table_code}`)
        }
      }
      assertPostBootstrapTables(bootstrapState)
      for (const field of ['complete_schema_sha256', 'legacy_schema_sha256']) {
        const mutation = structuredClone(bootstrapState)
        mutation[field] = '0'.repeat(64)
        assert.throws(() => assertPostBootstrapTables(mutation), /MIGRATION_DRIFT/, `post-bootstrap ${field} mutation unexpectedly passed`)
      }
      for (const tableCode of ['atlas_principals', 'atlas_evidence_bundle_receipts']) {
        const mutation = structuredClone(bootstrapState)
        mutation.atlas_tables.find((row) => row.table_code === tableCode).rows_sha256 = '0'.repeat(64)
        assert.throws(() => assertPostBootstrapTables(mutation), /MIGRATION_DRIFT/, `${tableCode} projection mutation unexpectedly passed`)
      }
      const roster = database.prepare(`
        SELECT p.id,p.principal_code,p.principal_kind_code,creator.principal_code AS created_by_principal_code,p.created_at
          FROM atlas_principals p JOIN atlas_principals creator ON creator.id=p.created_by_principal_id
         ORDER BY p.id ASC
      `).all().map((row) => Object.fromEntries(Object.entries(row).map(([key, value]) => [key, sqliteDigestValue(value)])))
      if (canonical(roster) !== canonical(bootstrapState.principal_roster) || sha256(Buffer.from(canonical(roster), 'utf8')) !== bootstrapState.principal_roster_sha256) fail('migration', 'MIGRATION_DRIFT', 'post-bootstrap principal roster projection differs')
      const rawPrincipalsDigest = databaseTableDigest(database, 'atlas_principals', digestProfiles)
      if (rawPrincipalsDigest === bootstrapState.principal_roster_sha256) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'raw principal table digest was conflated with the stable-code principal roster digest')
      const assertReceiptHeadProjection = (projection, declaredState, label) => {
        const digest = sha256(Buffer.from(canonical(projection), 'utf8'))
        if (projection.bundle_code !== declaredState.receipt_head.bundle_id || projection.bundle_sequence !== declaredState.receipt_head.bundle_sequence || projection.bundle_digest_sha256 !== declaredState.receipt_head.bundle_digest_sha256 || digest !== declaredState.receipt_head.receipt_row_sha256) fail('migration', 'MIGRATION_DRIFT', `${label} receipt head tuple or row projection differs`)
      }
      const receiptProjection = databaseReceiptRowProjection(database, digestProfiles, manifest)
      const receiptProjectionDigest = sha256(Buffer.from(canonical(receiptProjection), 'utf8'))
      assertReceiptHeadProjection(receiptProjection, bootstrapState, 'post-bootstrap')
      const rawReceiptDigest = databaseTableDigest(database, 'atlas_evidence_bundle_receipts', digestProfiles)
      if (rawReceiptDigest === receiptProjectionDigest) fail('digest_profiles', 'DIGEST_PROFILE_INVALID', 'raw receipt table digest was conflated with the stable-code receipt-row digest')
      const observedReceiptGraph = [{
        bundle_code: receiptProjection.bundle_code,
        bundle_sequence: receiptProjection.bundle_sequence,
        bundle_digest_sha256: receiptProjection.bundle_digest_sha256,
        required_bundles: manifest.required_bundles.map(({ bundle_id, bundle_sequence, bundle_digest_sha256 }) => ({ bundle_id, bundle_sequence, bundle_digest_sha256 })),
      }]
      if (canonical(observedReceiptGraph) !== canonical(digestProfiles.sqlite_projections.receipt_dependency_graph.bootstrap_successor_payload) || sha256(Buffer.from(canonical(observedReceiptGraph), 'utf8')) !== bootstrapState.receipt_dependency_graph_sha256) fail('migration', 'MIGRATION_DRIFT', 'post-bootstrap receipt dependency graph differs')
      const changedReceiptProjection = structuredClone(receiptProjection)
      changedReceiptProjection.importer_version = '1.0.1'
      if (sha256(Buffer.from(canonical(changedReceiptProjection), 'utf8')) === bootstrapState.receipt_head.receipt_row_sha256) fail('migration', 'MIGRATION_DRIFT', 'receipt projection mutation was not detected')
      const documentManifest = parseJsonBytes(fs.readFileSync(completeDocumentManifestPath), { contractNumbers: true, maximumBytes: pilotLimits.manifest_bytes_max })
      insertSyntheticDocumentState(database, documentManifest)
      const documentState = fixtures.get('logical_state_document_002').value.state_payload
      assertPostBootstrapTables(documentState)
      for (const field of ['complete_schema_sha256', 'legacy_schema_sha256']) {
        const mutation = structuredClone(documentState)
        mutation[field] = '0'.repeat(64)
        assert.throws(() => assertPostBootstrapTables(mutation), /MIGRATION_DRIFT/, `post-document ${field} mutation unexpectedly passed`)
      }
      const documentRoster = database.prepare(`
        SELECT p.id,p.principal_code,p.principal_kind_code,creator.principal_code AS created_by_principal_code,p.created_at
          FROM atlas_principals p JOIN atlas_principals creator ON creator.id=p.created_by_principal_id
         ORDER BY p.id ASC
      `).all().map((row) => Object.fromEntries(Object.entries(row).map(([key, value]) => [key, sqliteDigestValue(value)])))
      if (canonical(documentRoster) !== canonical(documentState.principal_roster) || documentState.prior_logical_state_sha256 !== fixtures.get('logical_state_bootstrap').value.logical_state_sha256) fail('migration', 'MIGRATION_DRIFT', 'document state changed the principal roster or skipped its exact predecessor state')
      const documentReceiptProjection = databaseReceiptRowProjection(database, digestProfiles, documentManifest)
      assertReceiptHeadProjection(documentReceiptProjection, documentState, 'document')
      for (const [field, replacement] of [['bundle_id', 'synthetic.wrong-bundle'], ['bundle_sequence', 3], ['bundle_digest_sha256', '0'.repeat(64)], ['receipt_row_sha256', '0'.repeat(64)]]) {
        const mutation = structuredClone(documentState)
        mutation.receipt_head[field] = replacement
        assert.throws(() => assertReceiptHeadProjection(documentReceiptProjection, mutation, 'mutated document'), /MIGRATION_DRIFT/, `document receipt-head ${field} mutation unexpectedly passed`)
      }
      const documentReceiptGraph = database.prepare('SELECT bundle_code,bundle_sequence,bundle_digest_sha256 FROM atlas_evidence_bundle_receipts ORDER BY bundle_sequence ASC').all().map((row) => ({
        bundle_code: row.bundle_code,
        bundle_sequence: row.bundle_sequence,
        bundle_digest_sha256: row.bundle_digest_sha256,
        required_bundles: row.bundle_sequence === documentManifest.bundle_sequence
          ? documentManifest.required_bundles.map((required) => {
            const dependency = database.prepare('SELECT bundle_code AS bundle_id,bundle_sequence,bundle_digest_sha256 FROM atlas_evidence_bundle_receipts WHERE bundle_code=? AND bundle_digest_sha256=?').all(required.bundle_id, required.bundle_digest_sha256)
            if (dependency.length !== 1) fail('migration', 'MIGRATION_DRIFT', 'document receipt dependency does not resolve exactly once')
            return { bundle_id: dependency[0].bundle_id, bundle_sequence: dependency[0].bundle_sequence, bundle_digest_sha256: dependency[0].bundle_digest_sha256 }
          })
          : [],
      }))
      if (canonical(documentReceiptGraph) !== canonical(digestProfiles.sqlite_projections.receipt_dependency_graph.document_successor_payload) || sha256(Buffer.from(canonical(documentReceiptGraph), 'utf8')) !== documentState.receipt_dependency_graph_sha256) fail('migration', 'MIGRATION_DRIFT', 'document receipt dependency graph differs')
      const documentMutationTables = ['atlas_evidence_bundle_receipts', 'atlas_retrieval_locations', 'atlas_artifacts', 'atlas_retrieval_events', 'atlas_artifact_custody_events']
      for (const tableCode of documentMutationTables) {
        const mutation = structuredClone(documentState)
        mutation.atlas_tables.find((row) => row.table_code === tableCode).rows_sha256 = '0'.repeat(64)
        assert.throws(() => assertPostBootstrapTables(mutation), /MIGRATION_DRIFT/, `${tableCode} document projection mutation unexpectedly passed`)
      }
      if (database.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok' || database.prepare('PRAGMA foreign_key_check').all().length !== 0) fail('migration', 'MIGRATION_DRIFT', 'temporary database integrity failed')
      projectionSummary = {
        legacy_table_projections_recomputed: bootstrapState.legacy_rows.length,
        atlas_table_projections_recomputed: bootstrapState.atlas_tables.length,
        raw_and_stable_principal_digests_distinct: true,
        raw_and_stable_receipt_digests_distinct: true,
        receipt_dependency_graph_recomputed: true,
        literal_prefix_shadow_object_preserved: true,
        prohibited_surface_files_verified: digestProfiles.sqlite_projections.prohibited_surfaces.items.length,
        post_bootstrap_projection_mutations_rejected: ['atlas_principals', 'atlas_evidence_bundle_receipts'],
        post_document_projection_mutations_rejected: documentMutationTables,
        synthetic_document_state_recomputed: true,
      }
    } finally { database.close() }
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
  return projectionSummary
}

function assertCommonClassificationProjection(common, classification) {
  const pairs = [
    ['importOutcomeCode', classification.outcomes],
    ['canonicalEffectCode', classification.canonical_effects],
    ['stageCode', classification.stages],
    ['errorCode', classification.error_rules.map((item) => item.code)],
    ['retryabilityCode', classification.retryability_classes],
    ['recoveryClassCode', classification.recovery_classes],
  ]
  for (const [definition, expected] of pairs) {
    const actual = common.$defs?.[definition]?.enum
    if (!actual || canonical(actual) !== canonical(expected)) fail('classification', 'REGISTRY_INVALID', `${definition} differs from classification registry`)
  }
}

function assertContractReferenceProjection(common, catalog, registry, { exerciseMutation = true } = {}) {
  const actual = common.$defs?.contractReference?.properties?.format?.enum
  const expected = catalog.schemas.filter((entry) => entry.schema_role === 'top_level_contract' && entry.contract_format !== 'jedi-atlas-import-result').map((entry) => entry.contract_format)
  if (!Array.isArray(actual) || canonical(actual) !== canonical(expected)) fail('catalog', 'CATALOG_INVALID', 'generic contract references differ from the exact addressable external-record formats')
  for (const format of actual) {
    const entry = catalog.schemas.find((item) => item.contract_format === format)
    const schema = registry.byFile.get(entry.schema_file)
    const branches = resolvedTopBranches(schema, registry)
    for (const branch of branches) {
      for (const field of ['format', 'format_version', 'record_code', 'record_digest_sha256']) if (!branch.required?.includes(field) || !branch.properties?.[field]) fail('catalog', 'CATALOG_INVALID', `${format} cannot be addressed by the generic contract reference`)
    }
  }
  if (exerciseMutation) {
    const expanded = structuredClone(common)
    expanded.$defs.contractReference.properties.format.enum.push('jedi-atlas-import-result')
    assert.throws(() => assertContractReferenceProjection(expanded, catalog, registry, { exerciseMutation: false }), /CATALOG_INVALID/)
  }
  return exerciseMutation ? 1 : 0
}

function recursiveRegularFileInventory(root) {
  const result = []
  const visit = (directory, relativeDirectory = '') => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).toSorted((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const relative = relativeDirectory === '' ? entry.name : `${relativeDirectory}/${entry.name}`
      const absolute = path.join(directory, entry.name)
      if (entry.isSymbolicLink()) fail('catalog', 'CATALOG_INVALID', `contract root contains a symbolic link: ${relative}`)
      if (entry.isDirectory()) visit(absolute, relative)
      else if (entry.isFile()) result.push(relative)
      else fail('catalog', 'CATALOG_INVALID', `contract root contains a non-regular object: ${relative}`)
    }
  }
  visit(root)
  return result
}

function assertContractRootInventory(root, golden, injectedPaths = []) {
  const goldenRelative = 'fixtures/golden-vectors-v1.json'
  const hashedPaths = golden.raw_file_hashes.map((item) => item.file)
  if (hashedPaths.includes(goldenRelative)) fail('catalog', 'CATALOG_INVALID', 'golden-vector file cannot recursively hash itself')
  unique(hashedPaths, 'catalog', 'CATALOG_INVALID', 'contract-root hashed file')
  const expected = [...hashedPaths, goldenRelative].toSorted()
  const actual = [...recursiveRegularFileInventory(root), ...injectedPaths].toSorted()
  if (canonical(actual) !== canonical(expected)) fail('catalog', 'CATALOG_INVALID', 'recursive contract-root file inventory differs from the closed golden inventory')
  const manifests = actual.filter((relative) => relative.startsWith('fixtures/manifests/'))
  const artifacts = actual.filter((relative) => relative.startsWith('fixtures/objects/'))
  const contracts = actual.filter((relative) => !manifests.includes(relative) && !artifacts.includes(relative))
  if (canonical([...contracts, ...manifests, ...artifacts].toSorted()) !== canonical(actual)) fail('catalog', 'CATALOG_INVALID', 'contract-root resource partition is incomplete')
  return {
    relativePaths: actual,
    contractFiles: contracts.map((relative) => path.join(root, relative)),
    manifestFiles: manifests.map((relative) => path.join(root, relative)),
    artifactFiles: artifacts.map((relative) => path.join(root, relative)),
  }
}

const requiredDesignFiles = [
  catalogPath,
  classificationPath,
  fieldRegistryPath,
  digestProfilesPath,
  validFixturesPath,
  invalidFixturesPath,
  goldenVectorsPath,
]

const requiredManifestFiles = [completeDocumentManifestPath]
const requiredArtifactFiles = [completeDocumentArtifactPath]

for (const file of [...requiredDesignFiles, evidenceManifestSchemaPath, ...requiredManifestFiles, ...requiredArtifactFiles]) if (!fs.existsSync(file)) throw new Error(`Missing D9.0 contract artifact: ${path.relative(project, file)}`)

const schemaNames = fs.readdirSync(contractRoot).filter((name) => name.endsWith('.schema.json')).sort()
const schemaEntries = schemaNames.map((name) => [name, loadJson(path.join(contractRoot, name))])
const schemaRegistry = createSchemaRegistry(schemaEntries)
const catalog = loadJson(catalogPath)
const classification = loadJson(classificationPath)
const fieldRegistry = loadJson(fieldRegistryPath)
const digestProfiles = loadJson(digestProfilesPath)
const validFixtureEnvelope = loadJson(validFixturesPath)
const invalidFixtureEnvelope = loadJson(invalidFixturesPath)
const goldenVectors = loadJson(goldenVectorsPath)
const contractRootInventory = assertContractRootInventory(contractRoot, goldenVectors)
assert.throws(() => assertContractRootInventory(contractRoot, goldenVectors, ['fixtures/injected-undisclosed.json']), /recursive contract-root file inventory differs/)

assertFixtureEnvelope(validFixtureEnvelope, 'valid')
const fixtures = fixtureMap(validFixtureEnvelope)
const instanceSchemaFiles = catalog.schemas.filter((entry) => entry.schema_role === 'top_level_contract').map((entry) => entry.schema_file)
const protectedHelperSchemaFiles = catalog.schemas.filter((entry) => entry.schema_role === 'protected_operational_helper').map((entry) => entry.schema_file)
const fixtureSchemaFiles = [...new Set([...fixtures.values()].map((fixture) => fixture.schema_file))]
if (canonical(fixtureSchemaFiles.filter((file) => instanceSchemaFiles.includes(file)).toSorted()) !== canonical(instanceSchemaFiles.toSorted())) fail('fixture', 'FIXTURE_INVALID', 'valid fixtures do not exercise every top-level contract schema')
if (canonical(fixtureSchemaFiles.filter((file) => protectedHelperSchemaFiles.includes(file)).toSorted()) !== canonical(protectedHelperSchemaFiles.toSorted())) fail('fixture', 'FIXTURE_INVALID', 'valid fixtures do not exercise every protected helper schema')
for (const fixture of fixtures.values()) {
  const catalogEntry = catalog.schemas.find((entry) => entry.schema_file === fixture.schema_file)
  if (!catalogEntry || !['top_level_contract', 'protected_operational_helper'].includes(catalogEntry.schema_role) || (fixture.value?.format ?? fixture.value?.result_format) !== catalogEntry.contract_format || (fixture.value?.format_version ?? fixture.value?.result_version) !== catalogEntry.contract_version) fail('fixture', 'FIXTURE_INVALID', `${fixture.fixture_code} differs from its cataloged contract identity`)
}

assertClassificationRegistry(classification)
assertCommonClassificationProjection(schemaRegistry.byFile.get('common-v1.schema.json'), classification)
const contractReferenceMutations = assertContractReferenceProjection(schemaRegistry.byFile.get('common-v1.schema.json'), catalog, schemaRegistry)
assertFieldRegistry(fieldRegistry, schemaRegistry, schemaNames)
assertDigestProfiles(digestProfiles, schemaRegistry, [...instanceSchemaFiles, ...protectedHelperSchemaFiles])
assertCatalog(catalog, schemaEntries, classification, fieldRegistry, digestProfiles)
validateFixtureSet(fixtures, schemaRegistry, classification, rawFileSha256(catalogPath))
const runtime = fixtures.get('runtime_profile').value
assertResourceLimits(runtime, {
  contractFiles: [...contractRootInventory.contractFiles, evidenceManifestSchemaPath],
  manifestFiles: contractRootInventory.manifestFiles,
  artifactFiles: contractRootInventory.artifactFiles,
}, fixtures)
const goldenCoverage = assertGoldenVectors(goldenVectors, fixtures, digestProfiles)
const sensitivity = assertDigestSensitivity(fixtures)
const invalidCases = assertInvalidFixtures(invalidFixtureEnvelope, fixtures, schemaRegistry, classification, rawFileSha256(catalogPath))
const trustBoundaryMutations = assertTrustBoundaryMutations(fixtures, schemaRegistry, classification, rawFileSha256(catalogPath))
const clearanceContextMutations = assertClearanceContextMutations(fixtures, schemaRegistry, classification, rawFileSha256(catalogPath))
const deterministicOrderMutations = assertDeterministicOrderMutations(fixtures, schemaRegistry, classification, rawFileSha256(catalogPath))
const registryMutations = assertRegistryMutationMatrix({
  classification,
  fieldRegistry,
  digestProfiles,
  registry: schemaRegistry,
  fieldSchemaNames: schemaNames,
  digestSchemaNames: [...instanceSchemaFiles, ...protectedHelperSchemaFiles],
})
const stateMatrices = assertGeneratedStateMatrices(fixtures, schemaRegistry, classification)
const schemaMutations = assertSchemaMutationMatrix(schemaEntries, schemaRegistry, fixtures, catalog, classification, fieldRegistry, digestProfiles)
assertRawLexicalAndCanonicalMutations()
assertSecurityMutationCorpus()
assertPathBoundary()
assertIpcAdversarial(fixtures)
const custodyMatrixCases = assertCustodyOperationMatrix(fixtures, schemaRegistry, classification)
const databaseProjectionChecks = assertFrozenMigrationsAndEmptyAtlas(fixtures, digestProfiles, goldenVectors)

console.log(JSON.stringify({
  scope: 'D9.0 design-contract validator only; no importer, credential, bootstrap, custody store, database writer, or real evidence',
  offline: true,
  schema_dialect: 'deliberately supported strict JSON Schema 2020-12 subset; unknown keywords rejected',
  schema_files: schemaNames.length,
  digest_profile_inventory: {
    payload_profiles: digestProfiles.payload_profiles.length,
    pointer_scoped_bindings: digestProfiles.digest_bindings.length,
    exact_byte_resolvers: digestProfiles.external_byte_source_contract.resolver_definitions.length,
  },
  golden_inventory: {
    canonicalization_micro_vectors: goldenVectors.micro_vectors.length,
    complete_manifest_vectors: 2,
    nested_payload_vectors: goldenVectors.payload_vectors.length,
    contract_vectors: goldenVectors.contract_vectors.length,
    raw_file_hashes: goldenVectors.raw_file_hashes.length,
  },
  valid_contract_fixtures: fixtures.size,
  invalid_contract_mutations: invalidCases.length,
  trust_boundary_mutations_rejected: trustBoundaryMutations,
  clearance_context_mutations: clearanceContextMutations,
  deterministic_order_mutations_rejected: deterministicOrderMutations,
  registry_mutations_rejected: registryMutations,
  exhaustive_state_matrices: stateMatrices,
  schema_mutations_rejected: schemaMutations,
  canonical_leaf_mutations: sensitivity.scalarMutations,
  canonical_array_order_mutations: sensitivity.arrayMutations,
  canonicalization_and_independent_goldens: 'passed',
  independent_nested_payload_vectors: goldenCoverage,
  raw_json_lexical_profile: 'passed',
  closed_classification_matrix: { outcomes: classification.outcomes.length, errors: classification.error_rules.length },
  field_producer_consumer_storage_confidentiality_mapping: 'passed',
  secret_and_path_adversarial_corpus: 'passed',
  recursive_contract_root_inventory: { regular_files: contractRootInventory.relativePaths.length, injected_extra_path_rejected: true, golden_self_hash_exception: 'required_and_only_unhashed_contract_root_file' },
  identity_handoff_bootstrap_clearance_replay_semantics: 'passed',
  ipc_framing_descriptor_peer_and_replay_semantics: 'passed',
  custody_operation_direction_cases: custodyMatrixCases,
  journal_and_recovery_semantics: 'passed',
  frozen_migrations: Object.keys(migrationHashes),
  empty_atlas_tables: atlasTables.length,
  database_projection_checks: databaseProjectionChecks,
}, null, 2))
