import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import zlib from 'node:zlib'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { applyMigrations } from '../../data/lib/migrations.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const project = path.resolve(here, '../..')
const migrations = path.join(project, 'data/migrations')
const proposalPath = path.join(here, 'tranche-2a-source-quarantine.proposed.sql')
const schemaPath = path.join(here, 'tranche-2a-evidence-bundle-v1.schema.json')
const migrationNames = [
  '001_schema.sql',
  '002_reference_data.sql',
  '003_seed_eu_core.sql',
  '004_tranche_1a_foundations.sql',
]
const migrationHashes = {
  '001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  '002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  '003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
  '004_tranche_1a_foundations.sql': '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
}
const legacyTables = [
  'jurisdictions',
  'legal_instruments',
  'requirements',
  'hiring_stages',
  'legal_lenses',
  'actors',
  'requirement_hiring_stages',
  'requirement_legal_lenses',
  'requirement_actors',
  'requirement_relations',
  'country_overlays',
  'source_checks',
  'requirement_search',
]
const tables = [
  'atlas_artifact_custody_events',
  'atlas_artifacts',
  'atlas_evidence_bundle_receipts',
  'atlas_processing_outputs',
  'atlas_processing_runs',
  'atlas_retrieval_events',
  'atlas_retrieval_locations',
  'atlas_retrieval_redirects',
  'atlas_unverified_candidate_occurrences',
]
let indexes = [
  'atlas_artifact_custody_events_code_uidx',
  'atlas_artifact_custody_events_leaf_idx',
  'atlas_artifact_custody_events_one_root_uidx',
  'atlas_artifact_custody_events_predecessor_uidx',
  'atlas_artifacts_code_uidx',
  'atlas_artifacts_identity_uidx',
  'atlas_candidate_occurrences_leaf_idx',
  'atlas_candidate_occurrences_one_root_uidx',
  'atlas_candidate_occurrences_predecessor_uidx',
  'atlas_candidate_occurrences_record_code_uidx',
  'atlas_candidate_occurrences_run_output_idx',
  'atlas_evidence_bundle_receipts_code_uidx',
  'atlas_evidence_bundle_receipts_digest_uidx',
  'atlas_evidence_bundle_receipts_path_uidx',
  'atlas_evidence_bundle_receipts_sequence_uidx',
  'atlas_processing_outputs_code_uidx',
  'atlas_processing_outputs_id_run_uidx',
  'atlas_processing_outputs_run_ordinal_uidx',
  'atlas_processing_runs_code_uidx',
  'atlas_processing_runs_input_time_idx',
  'atlas_processing_runs_receipt_ordinal_uidx',
  'atlas_retrieval_events_code_uidx',
  'atlas_retrieval_events_location_time_idx',
  'atlas_retrieval_locations_code_uidx',
  'atlas_retrieval_locations_url_uidx',
  'atlas_retrieval_redirects_code_uidx',
  'atlas_retrieval_redirects_event_ordinal_uidx',
]
const triggers = tables.flatMap((name) => {
  const stem = name === 'atlas_unverified_candidate_occurrences'
    ? 'atlas_candidate_occurrences'
    : name
  return [`${stem}_immutable_delete`, `${stem}_immutable_update`, `${stem}_validate_insert`]
}).sort()
const cleanup = []

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function temporaryDirectory(prefix) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix))
  cleanup.push(directory)
  return directory
}

function canonical(value) {
  if (value === null) return 'null'
  if (typeof value === 'string') {
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index)
      if (code >= 0xd800 && code <= 0xdbff) {
        assert.ok(index + 1 < value.length, 'lone high surrogate')
        const next = value.charCodeAt(index + 1)
        assert.ok(next >= 0xdc00 && next <= 0xdfff, 'lone high surrogate')
        index += 1
      } else {
        assert.ok(code < 0xdc00 || code > 0xdfff, 'lone low surrogate')
      }
    }
    return JSON.stringify(value)
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    assert.ok(Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0), 'invalid canonical number')
    return String(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  assert.equal(Object.getPrototypeOf(value), Object.prototype, 'canonical JSON accepts plain objects only')
  return `{${Object.keys(value).sort().map((key) => `${canonical(key)}:${canonical(value[key])}`).join(',')}}`
}

function scanRawJson(text) {
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
      assert.ok(index < text.length, 'unterminated JSON string')
      const raw = text.slice(start, index + 1)
      let next = index + 1
      while (/\s/.test(text[next] || '')) next += 1
      if (stack.at(-1)?.type === 'object' && text[next] === ':') {
        const key = JSON.parse(raw)
        assert.ok(!stack.at(-1).keys.has(key), `duplicate key: ${key}`)
        stack.at(-1).keys.add(key)
      }
      continue
    }
    if (character === '{') stack.push({ type: 'object', keys: new Set() })
    else if (character === '[') stack.push({ type: 'array' })
    else if (character === '}' || character === ']') stack.pop()
    else if (character === '-' || /[0-9]/.test(character)) {
      const number = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/)?.[0]
      assert.ok(number, 'invalid JSON number')
      assert.match(number, /^(?:0|[1-9][0-9]*)$/, `noncanonical number token: ${number}`)
      index += number.length - 1
    }
  }
  JSON.parse(text)
}

function schemaTypeMatches(value, type) {
  if (type === 'null') return value === null
  if (type === 'array') return Array.isArray(value)
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value)
  if (type === 'integer') return typeof value === 'number' && Number.isSafeInteger(value)
  return typeof value === type
}

function resolveSchemaReference(root, reference) {
  assert.ok(reference.startsWith('#/'), `unsupported schema reference: ${reference}`)
  return reference.slice(2).split('/').reduce((node, segment) => node[segment.replaceAll('~1', '/').replaceAll('~0', '~')], root)
}

function validateAgainstSchema(root, schema, value, pointer = '$') {
  if (schema.$ref) return validateAgainstSchema(root, resolveSchemaReference(root, schema.$ref), value, pointer)
  if (schema.allOf) {
    for (const branch of schema.allOf) validateAgainstSchema(root, branch, value, pointer)
  }
  if (schema.if) {
    let matches = true
    try {
      validateAgainstSchema(root, schema.if, value, pointer)
    } catch {
      matches = false
    }
    if (matches && schema.then) validateAgainstSchema(root, schema.then, value, pointer)
    if (!matches && schema.else) validateAgainstSchema(root, schema.else, value, pointer)
  }
  if (schema.anyOf) {
    const matches = schema.anyOf.filter((branch) => {
      try {
        validateAgainstSchema(root, branch, value, pointer)
        return true
      } catch {
        return false
      }
    })
    assert.ok(matches.length >= 1, `${pointer} must match at least one anyOf branch`)
    return
  }
  if ('const' in schema) assert.deepEqual(value, schema.const, `${pointer} const mismatch`)
  if (schema.enum) assert.ok(schema.enum.some((item) => Object.is(item, value)), `${pointer} enum mismatch`)
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    assert.ok(types.some((type) => schemaTypeMatches(value, type)), `${pointer} type mismatch`)
  }
  if (typeof value === 'string') {
    const length = Array.from(value).length
    if (schema.minLength !== undefined) assert.ok(length >= schema.minLength, `${pointer} below minLength`)
    if (schema.maxLength !== undefined) assert.ok(length <= schema.maxLength, `${pointer} above maxLength`)
    if (schema.pattern) assert.match(value, new RegExp(schema.pattern, 'u'), `${pointer} pattern mismatch`)
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined) assert.ok(value >= schema.minimum, `${pointer} below minimum`)
    if (schema.maximum !== undefined) assert.ok(value <= schema.maximum, `${pointer} above maximum`)
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined) assert.ok(value.length >= schema.minItems, `${pointer} below minItems`)
    if (schema.maxItems !== undefined) assert.ok(value.length <= schema.maxItems, `${pointer} above maxItems`)
    if (schema.uniqueItems) {
      const identities = value.map(canonical)
      assert.equal(new Set(identities).size, identities.length, `${pointer} contains duplicate items`)
    }
    if (schema.items) value.forEach((item, index) => validateAgainstSchema(root, schema.items, item, `${pointer}/${index}`))
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value)
    if (schema.minProperties !== undefined) assert.ok(keys.length >= schema.minProperties, `${pointer} below minProperties`)
    if (schema.maxProperties !== undefined) assert.ok(keys.length <= schema.maxProperties, `${pointer} above maxProperties`)
    for (const required of schema.required || []) assert.ok(Object.hasOwn(value, required), `${pointer} missing ${required}`)
    for (const key of keys) {
      if (schema.propertyNames) validateAgainstSchema(root, schema.propertyNames, key, `${pointer}/<key>`)
      if (schema.properties?.[key]) validateAgainstSchema(root, schema.properties[key], value[key], `${pointer}/${key}`)
      else if (schema.additionalProperties === false) assert.fail(`${pointer} unknown property ${key}`)
      else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') validateAgainstSchema(root, schema.additionalProperties, value[key], `${pointer}/${key}`)
    }
  }
}

function parseManifestBytes(bytes, schema) {
  assert.ok(Buffer.isBuffer(bytes), 'manifest must be bytes')
  assert.ok(bytes.length > 0 && bytes.length <= 2 * 1024 * 1024, 'manifest byte size outside pilot limit')
  assert.ok(!(bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf), 'UTF-8 BOM is prohibited')
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  scanRawJson(text)
  const value = JSON.parse(text)
  validateAgainstSchema(schema, schema, value)
  return value
}

function bundleDigest(manifest) {
  const { bundle_digest_sha256: ignored, ...payload } = manifest
  return sha256(Buffer.from(canonical(payload), 'utf8'))
}

function configurationDigest(configuration) {
  return sha256(Buffer.from(canonical(configuration), 'utf8'))
}

function assertIndependentCanonicalGoldenVectors(schema) {
  const vectors = [
    {
      value: { '\uE000': 'bmp', '😀': 'astral', a: [null, true, 0] },
      canonical: '{"a":[null,true,0],"😀":"astral","":"bmp"}',
      sha256: '399ef25b59ef34e7bc8794bc8a1e4ed91b61bb6052a3c2af3d7a34f8e08b5ad7',
    },
    {
      value: { 'é': 'NFC', 'é': 'NFD' },
      canonical: '{"é":"NFD","é":"NFC"}',
      sha256: '897b10cef0f117a16e395bf3b5d553fc6fdddbffb887ed8dc71bfb07b653959d',
    },
  ]
  for (const vector of vectors) {
    assert.equal(canonical(vector.value), vector.canonical)
    assert.equal(sha256(Buffer.from(vector.canonical, 'utf8')), vector.sha256)
  }
  const whitespaceA = JSON.parse('{\r\n  "b" : [ null, 2 ],\r\n  "a" : 1\r\n}')
  const whitespaceB = JSON.parse('{"a":1,"b":[null,2]}')
  const whitespaceCanonical = '{"a":1,"b":[null,2]}'
  const whitespaceDigest = '6345bd8358a8b8436e6943f731e2c7a17f456854bdc5de3ffa2eefd927e9652a'
  assert.equal(canonical(whitespaceA), whitespaceCanonical)
  assert.equal(canonical(whitespaceB), whitespaceCanonical)
  assert.equal(sha256(Buffer.from(whitespaceCanonical, 'utf8')), whitespaceDigest)

  const digestEnvelope = { bundle_digest_sha256: 'omit', nested: { bundle_digest_sha256: 'keep' }, a: null }
  const digestPayload = '{"a":null,"nested":{"bundle_digest_sha256":"keep"}}'
  assert.equal(canonical((({ bundle_digest_sha256: ignored, ...payload }) => payload)(digestEnvelope)), digestPayload)
  assert.equal(bundleDigest(digestEnvelope), 'b50e49d2fe981fe2966682436f68fa5c2b0b2d0ac52dee732e110b2b2a43d6a9')

  const configuration = { scripts_enabled: false, page_limit: 2, mode: 'synthetic' }
  assert.equal(canonical(configuration), '{"mode":"synthetic","page_limit":2,"scripts_enabled":false}')
  assert.equal(configurationDigest(configuration), '1fd20eb02ac208b429577e7087b6fea4e81cc0627f891b0da964ceb76d8c2d73')

  const ordered = '{"a":1,"b":2}'
  const reversedNoncanonical = '{"b":2,"a":1}'
  assert.equal(sha256(Buffer.from(ordered)), '43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777')
  assert.equal(sha256(Buffer.from(reversedNoncanonical)), '3fb75453225c732a76b7899ea2096dda1455189c89817239732182f73fe5a09f')
  assert.notEqual(sha256(Buffer.from(reversedNoncanonical)), sha256(Buffer.from(ordered)), 'reversed purported canonical output must fail its golden digest')
  assert.equal(canonical({ b: 2, a: 1 }), ordered, 'raw source key order remains irrelevant')

  const completeManifestCanonical = '{"artifacts":[],"bundle_created_at":"2026-02-01T00:00:00.000Z","bundle_declarations":{"contains_credentials":false,"contains_personal_data":false,"hostile_input_acknowledged":true},"bundle_id":"golden-bundle-001","bundle_sequence":1,"candidate_occurrences":[],"custody_events":[],"expected_importer_principal_code":"golden.importer","expected_importer_software_code":"golden-fixed-importer","expected_importer_version":"1.0.0","format":"jedi-atlas-evidence-bundle","format_version":"1.0.0","manifest_path":"fixtures/golden-bundle-001.json","principal_bootstrap":{"principals":[{"created_at":"2026-01-01T00:00:01.000Z","created_by_principal_code":"system.bootstrap","id":2,"principal_code":"golden.researcher","principal_kind_code":"human","runtime_role_code":"manifest_submitter"},{"created_at":"2026-01-01T00:00:02.000Z","created_by_principal_code":"golden.researcher","id":3,"principal_code":"golden.collector","principal_kind_code":"service","runtime_role_code":"collector"},{"created_at":"2026-01-01T00:00:02.000Z","created_by_principal_code":"golden.researcher","id":4,"principal_code":"golden.importer","principal_kind_code":"service","runtime_role_code":"bundle_importer"}],"trust_root":{"created_at":"2026-01-01T00:00:00.000Z","created_by_principal_code":"system.bootstrap","id":1,"principal_code":"system.bootstrap","principal_kind_code":"service"}},"processing_runs":[],"required_bundles":[],"retrieval_events":[],"retrieval_locations":[],"submitter_principal_code":"golden.researcher"}'
  const completeManifestSha256 = '63a19074159f0ad98347f2ad148db1b048d8f41af3857f407396f4e7932dacb4'
  const completePayload = JSON.parse(completeManifestCanonical)
  const completeManifest = { ...completePayload, bundle_digest_sha256: completeManifestSha256 }
  validateAgainstSchema(schema, schema, completeManifest)
  assert.equal(canonical(completePayload), completeManifestCanonical, 'complete manifest canonical serialization drift')
  assert.equal(sha256(Buffer.from(completeManifestCanonical, 'utf8')), completeManifestSha256, 'complete manifest independent SHA-256 drift')
  assert.equal(bundleDigest(completeManifest), completeManifestSha256, 'complete manifest bundle digest drift')
}

function assertEveryManifestLeafAffectsDigest(manifest) {
  const baseline = bundleDigest(manifest)
  const leaves = []
  const visit = (value, pathParts) => {
    if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
      leaves.push([pathParts, value])
      return
    }
    if (Array.isArray(value)) value.forEach((item, index) => visit(item, [...pathParts, index]))
    else for (const [key, child] of Object.entries(value)) visit(child, [...pathParts, key])
  }
  visit(manifest, [])
  let covered = 0
  for (const [pathParts, original] of leaves) {
    if (pathParts.length === 1 && pathParts[0] === 'bundle_digest_sha256') continue
    const mutated = structuredClone(manifest)
    let cursor = mutated
    for (const part of pathParts.slice(0, -1)) cursor = cursor[part]
    const leaf = pathParts.at(-1)
    cursor[leaf] = original === null
      ? '__null_changed__'
      : typeof original === 'boolean'
        ? !original
        : typeof original === 'number'
          ? original === Number.MAX_SAFE_INTEGER ? original - 1 : original + 1
          : `${original}__changed__`
    assert.notEqual(bundleDigest(mutated), baseline, `digest-insensitive manifest leaf: ${pathParts.join('/')}`)
    covered += 1
  }
  assert.ok(covered > 100, 'complete manifest field-sensitivity traversal was unexpectedly small')
  const digestOnly = structuredClone(manifest)
  digestOnly.bundle_digest_sha256 = 'f'.repeat(64)
  assert.equal(bundleDigest(digestOnly), baseline, 'top-level bundle digest must be the only excluded leaf')
}

function assertManifestArrayOrderAffectsDigest(manifest) {
  const baseline = bundleDigest(manifest)
  let covered = 0
  const visit = (value, pathParts) => {
    if (Array.isArray(value)) {
      if (value.length >= 2 && canonical(value[0]) !== canonical(value[1])) {
        const mutated = structuredClone(manifest)
        let cursor = mutated
        for (const part of pathParts) cursor = cursor[part]
        ;[cursor[0], cursor[1]] = [cursor[1], cursor[0]]
        assert.notEqual(bundleDigest(mutated), baseline, `digest-insensitive array order: ${pathParts.join('/')}`)
        covered += 1
      }
      value.forEach((item, index) => visit(item, [...pathParts, index]))
    } else if (value && typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) visit(child, [...pathParts, key])
    }
  }
  visit(manifest, [])
  assert.ok(covered > 5, 'manifest did not exercise enough independently ordered arrays')
}

const artifactCode = (layer, digest, length) => `artifact.${layer}.sha256.${digest}.${length}`
const locationCode = (url) => `location.${sha256(Buffer.from(url, 'utf8'))}`
const custodyReference = (artifact) => `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}`

function timestamp(value) {
  return typeof value === 'string'
    && /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/.test(value)
    && !Number.isNaN(Date.parse(value))
    && new Date(value).toISOString() === value
}

function code(value, maximum = 160, minimum = 3) {
  return typeof value === 'string'
    && Buffer.byteLength(value) >= minimum
    && Buffer.byteLength(value) <= maximum
    && /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(value)
}

function canonicalVary(value) {
  if (value === '*') return true
  if (!boundedTrimmedText(value, 512) || value !== value.toLowerCase()) return false
  const tokens = value.split(', ')
  return tokens.length > 0
    && tokens.every((token) => /^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(token))
    && new Set(tokens).size === tokens.length
    && value === tokens.toSorted().join(', ')
}

function safeHttpFieldValue(value, maximum = 512) {
  return typeof value === 'string'
    && Buffer.byteLength(value) >= 1
    && Buffer.byteLength(value) <= maximum
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

function canonicalContentCoding(value) {
  return safeHttpFieldValue(value, 255)
    && value === value.toLowerCase()
    && value.split(', ').every((token) => /^[a-z0-9!#$%&'*+.^_`|~-]+$/u.test(token))
}

const processingOutputKinds = {
  content_decoding: new Set(['decoded_body']),
  parser: new Set(['extracted_text', 'structured_data', 'diagnostic']),
  ocr: new Set(['ocr_text', 'diagnostic']),
  normalization: new Set(['normalized_text', 'diagnostic']),
  manual_transcription: new Set(['manual_transcript', 'diagnostic']),
}

function boundedText(value, maximum, { nullable = false, nonblank = true } = {}) {
  if (value === null && nullable) return true
  return typeof value === 'string'
    && !value.includes('\0')
    && Buffer.byteLength(value) <= maximum
    && (!nonblank || (Buffer.byteLength(value) > 0 && value.trim() !== ''))
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
    && value.split('/').every((segment) => segment !== '.' && segment !== '..' && /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(segment))
}

function safeUrl(value) {
  if (!boundedText(value, 2048) || /[\u0000-\u0020\u007f\\]/u.test(value)) return false
  try {
    const parsed = new URL(value)
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) return false
    return !Array.from(parsed.searchParams.keys()).some((key) => /^(?:x-amz-.+|x-goog-.+|sv|se|sp|sig)$|(?:^|[_-])(?:access|auth|authorization|credential|key|password|secret|signature|token)(?:$|[_-])/i.test(key))
  } catch {
    return false
  }
}

function unique(values, label) {
  assert.equal(new Set(values).size, values.length, `duplicate ${label}`)
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
  if (Array.isArray(value)) return value.forEach((item) => assertNoForbiddenMaterial(item, key))
  if (value && typeof value === 'object') {
    return Object.entries(value).forEach(([childKey, child]) => {
      if (childKey !== 'contains_credentials') assert.equal(isForbiddenConfigurationKey(childKey), false, `forbidden credential-like key: ${childKey}`)
      assertNoForbiddenMaterial(child, childKey)
    })
  }
  if (typeof value === 'string' && (key.endsWith('url') || key.includes('reference') || key.includes('path'))) {
    assert.doesNotMatch(value, /(?:bearer%20|x-(?:amz|goog)-signature|[?#&](?:token|key|api[_-]?key|signature|sig)=)/i)
  }
  if (typeof value === 'string') {
    assert.doesNotMatch(value, /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]+=*|\bAKIA[0-9A-Z]{16}\b/i)
  }
}

function databaseContext(database) {
  const map = (sql, key) => new Map(database.prepare(sql).all().map((row) => [row[key], { ...row }]))
  const receipts = map('SELECT * FROM atlas_evidence_bundle_receipts', 'bundle_code')
  const receiptById = new Map(Array.from(receipts.values()).map((row) => [row.id, row]))
  const withBundle = (sql, key) => {
    const result = map(sql, key)
    for (const row of result.values()) {
      const receipt = receiptById.get(row.evidence_bundle_receipt_id)
      row.bundle_code = receipt?.bundle_code
      row.bundle_sequence = receipt?.bundle_sequence
    }
    return result
  }
  const principals = map('SELECT id,principal_code,principal_kind_code,created_at FROM atlas_principals', 'principal_code')
  const locations = withBundle('SELECT * FROM atlas_retrieval_locations', 'location_code')
  const artifacts = withBundle('SELECT * FROM atlas_artifacts', 'artifact_code')
  const retrievalEvents = withBundle('SELECT * FROM atlas_retrieval_events', 'retrieval_event_code')
  const redirects = withBundle('SELECT * FROM atlas_retrieval_redirects', 'redirect_code')
  const custodyEvents = withBundle('SELECT * FROM atlas_artifact_custody_events', 'custody_event_code')
  const processingRuns = withBundle('SELECT * FROM atlas_processing_runs', 'processing_run_code')
  const processingOutputs = withBundle('SELECT * FROM atlas_processing_outputs', 'processing_output_code')
  const candidates = withBundle('SELECT * FROM atlas_unverified_candidate_occurrences', 'candidate_record_code')
  return { database, receipts, receiptById, principals, locations, artifacts, retrievalEvents, redirects, custodyEvents, processingRuns, processingOutputs, candidates }
}

function emptyContext(database) {
  return {
    database,
    receipts: new Map(),
    receiptById: new Map(),
    principals: new Map(),
    locations: new Map(),
    artifacts: new Map(),
    retrievalEvents: new Map(),
    redirects: new Map(),
    custodyEvents: new Map(),
    processingRuns: new Map(),
    processingOutputs: new Map(),
    candidates: new Map(),
  }
}

function assertDependency(manifest, context, bundleCode, usedDependencies) {
  if (!bundleCode) return
  if (bundleCode === manifest.bundle_id) return
  const dependency = manifest.required_bundles.find((item) => item.bundle_id === bundleCode)
  const receipt = context.receipts.get(bundleCode)
  assert.ok(receipt && dependency, `unpinned cross-bundle reference: ${bundleCode}`)
  assert.equal(dependency.bundle_digest_sha256, receipt.bundle_digest_sha256, `dependency digest mismatch: ${bundleCode}`)
  assert.ok(receipt.bundle_sequence < manifest.bundle_sequence, `dependency is not earlier: ${bundleCode}`)
  usedDependencies.add(bundleCode)
}

function validatePrincipalBootstrap(manifest, context, principals) {
  const bootstrap = manifest.principal_bootstrap
  if (context.principals.size === 0) {
    assert.equal(manifest.bundle_sequence, 1, 'empty Atlas starts at bundle sequence 1')
    assert.ok(bootstrap, 'empty Atlas requires explicit principal bootstrap')
    assert.deepEqual(bootstrap.trust_root, {
      id: 1,
      principal_code: 'system.bootstrap',
      principal_kind_code: 'service',
      created_by_principal_code: 'system.bootstrap',
      created_at: bootstrap.trust_root.created_at,
    })
    assert.ok(timestamp(bootstrap.trust_root.created_at))
    const ids = new Set([1])
    const available = new Map([['system.bootstrap', { id: 1, principal_code: 'system.bootstrap', principal_kind_code: 'service', created_at: bootstrap.trust_root.created_at }]])
    unique(bootstrap.principals.map((principal) => principal.principal_code), 'bootstrap principal code')
    for (const principal of bootstrap.principals) {
      assert.ok(principal.id > 1 && !ids.has(principal.id), 'duplicate or reserved bootstrap principal ID')
      assert.ok(!available.has(principal.principal_code), 'bootstrap principal collides with the trust root or an earlier principal')
      ids.add(principal.id)
      const creator = available.get(principal.created_by_principal_code)
      assert.ok(creator, `bootstrap creator must precede principal ${principal.principal_code}`)
      assert.ok(timestamp(principal.created_at) && creator.created_at <= principal.created_at, 'noncausal principal creation')
      available.set(principal.principal_code, { ...principal })
    }
    const submitter = available.get(manifest.submitter_principal_code)
    const importer = available.get(manifest.expected_importer_principal_code)
    assert.equal(submitter?.principal_kind_code, 'human', 'bootstrap submitter must be human')
    assert.equal(submitter?.runtime_role_code, 'manifest_submitter', 'submitter role must bind named submitter')
    assert.equal(importer?.principal_kind_code, 'service', 'bootstrap importer must be service')
    assert.equal(importer?.runtime_role_code, 'bundle_importer', 'importer role must bind named importer')
    assert.ok(Array.from(available.values()).some((principal) => principal.runtime_role_code === 'collector' && principal.principal_kind_code === 'service'), 'bootstrap requires a service collector')
    for (const [principalCode, principal] of available) principals.set(principalCode, principal)
  } else {
    assert.equal(bootstrap, undefined, 'principal bootstrap is a one-time empty-database ceremony')
  }
}

function validateManifestSemantics(manifest, context) {
  assert.equal(manifest.format, 'jedi-atlas-evidence-bundle')
  assert.equal(manifest.format_version, '1.0.0')
  assert.ok(code(manifest.bundle_id, 80))
  assert.ok(Number.isSafeInteger(manifest.bundle_sequence) && manifest.bundle_sequence > 0)
  assert.ok(timestamp(manifest.bundle_created_at) && safePath(manifest.manifest_path))
  assert.deepEqual(manifest.bundle_declarations, {
    contains_credentials: false,
    contains_personal_data: false,
    hostile_input_acknowledged: true,
  })
  assert.equal(manifest.bundle_digest_sha256, bundleDigest(manifest), 'bundle digest mismatch')
  assert.ok(code(manifest.submitter_principal_code, 80, 1) && code(manifest.expected_importer_principal_code, 80, 1))
  assert.ok(boundedTrimmedText(manifest.expected_importer_software_code, 80) && boundedTrimmedText(manifest.expected_importer_version, 80))
  assert.notEqual(manifest.submitter_principal_code, 'system.bootstrap')
  assert.notEqual(manifest.expected_importer_principal_code, 'system.bootstrap')
  const dependencies = manifest.required_bundles
  unique(dependencies.map((item) => item.bundle_id), 'required bundle')
  assert.deepEqual(dependencies.map((item) => item.bundle_id), dependencies.map((item) => item.bundle_id).toSorted(), 'required bundles must be sorted by bundle_id')
  for (const dependency of dependencies) {
    assert.notEqual(dependency.bundle_id, manifest.bundle_id)
    const receipt = context.receipts.get(dependency.bundle_id)
    assert.ok(receipt, `missing required bundle: ${dependency.bundle_id}`)
    assert.equal(receipt.bundle_digest_sha256, dependency.bundle_digest_sha256, `required bundle digest mismatch: ${dependency.bundle_id}`)
    assert.ok(receipt.bundle_sequence < manifest.bundle_sequence, 'required bundle must be earlier')
  }
  const expectedSequence = Math.max(0, ...Array.from(context.receipts.values()).map((receipt) => receipt.bundle_sequence)) + 1
  assert.equal(manifest.bundle_sequence, expectedSequence, 'bundle sequence must be contiguous')
  assert.ok(!Array.from(context.receipts.values()).some((receipt) => receipt.bundle_digest_sha256 === manifest.bundle_digest_sha256), 'bundle digest collision')
  assert.ok(!Array.from(context.receipts.values()).some((receipt) => receipt.manifest_path === manifest.manifest_path), 'manifest path collision')
  if (expectedSequence === 1) assert.equal(dependencies.length, 0, 'first bundle has no dependencies')
  else {
    const predecessor = Array.from(context.receipts.values()).find((receipt) => receipt.bundle_sequence === expectedSequence - 1)
    assert.ok(dependencies.some((item) => item.bundle_id === predecessor.bundle_code), 'immediate predecessor bundle must be pinned')
    assert.ok(predecessor.bundle_created_at <= manifest.bundle_created_at, 'bundle creation chronology must be monotonic')
  }

  const principals = new Map(context.principals)
  validatePrincipalBootstrap(manifest, context, principals)
  const submitter = principals.get(manifest.submitter_principal_code)
  const importer = principals.get(manifest.expected_importer_principal_code)
  assert.equal(submitter?.principal_kind_code, 'human', 'submitter must resolve to a human')
  assert.equal(importer?.principal_kind_code, 'service', 'importer must resolve to a service')
  assert.ok(submitter.created_at <= manifest.bundle_created_at && importer.created_at <= manifest.bundle_created_at, 'bundle predates principal')

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
    assert.equal(location.record_code, locationCode(location.url), 'location code mismatch')
    assert.ok(safeUrl(location.url) && timestamp(location.recorded_at) && location.recorded_at <= manifest.bundle_created_at)
    assert.equal(location.recorded_by_principal_code, manifest.submitter_principal_code)
    assert.ok(submitter.created_at <= location.recorded_at, 'retrieval location predates submitter')
    assert.ok(!locations.has(location.record_code), 'location declaration collides with existing identity; reference it instead')
    assert.ok(!Array.from(locations.values()).some((row) => row.location_url === location.url), 'location URL already exists')
    locations.set(location.record_code, { ...location, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(location.record_code)
  }

  for (const artifact of manifest.artifacts) {
    assert.ok(['retrieved_body', 'derived_output'].includes(artifact.byte_layer_code))
    assert.equal(artifact.hash_algorithm_code, 'sha256')
    assert.match(artifact.sha256, /^[0-9a-f]{64}$/)
    assert.ok(Number.isSafeInteger(artifact.byte_length) && artifact.byte_length >= 0 && safePath(artifact.staged_path))
    assert.equal(artifact.record_code, artifactCode(artifact.byte_layer_code, artifact.sha256, artifact.byte_length), 'artifact code mismatch')
    assert.equal(artifact.staged_path, custodyReference(artifact), 'staged artifact path is not content addressed')
    assert.ok(timestamp(artifact.recorded_at) && artifact.recorded_at <= manifest.bundle_created_at)
    assert.equal(artifact.recorded_by_principal_code, manifest.submitter_principal_code)
    assert.ok(submitter.created_at <= artifact.recorded_at, 'artifact identity predates submitter')
    assert.ok(!artifacts.has(artifact.record_code), 'artifact declaration collides with existing identity; reference it instead')
    assert.ok(!Array.from(artifacts.values()).some((row) => row.byte_layer_code === artifact.byte_layer_code && row.sha256 === artifact.sha256 && row.byte_length === artifact.byte_length), 'artifact identity already exists')
    artifacts.set(artifact.record_code, { ...artifact, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(artifact.record_code)
  }

  for (const event of manifest.retrieval_events) {
    assert.ok(event.record_code.startsWith(prefix) && code(event.record_code))
    assert.ok(!retrievalEvents.has(event.record_code), 'retrieval event collision')
    const requested = locations.get(event.requested_location_code)
    assert.ok(requested, 'unknown requested location')
    assertDependency(manifest, context, requested.bundle_code, usedDependencies)
    const lastAttempted = locations.get(event.last_attempted_location_code)
    assert.ok(lastAttempted, 'unknown last attempted location')
    assertDependency(manifest, context, lastAttempted.bundle_code, usedDependencies)
    const resolved = event.resolved_location_code === null ? null : locations.get(event.resolved_location_code)
    if (event.resolved_location_code !== null) assert.ok(resolved, 'unknown resolved location')
    assertDependency(manifest, context, resolved?.bundle_code, usedDependencies)
    assert.ok(timestamp(event.started_at) && timestamp(event.completed_at) && timestamp(event.recorded_at))
    assert.ok(event.started_at <= event.completed_at && event.completed_at <= event.recorded_at && event.recorded_at <= manifest.bundle_created_at)
    assert.ok(requested.recorded_at <= event.started_at, 'requested location was recorded after attempt start')
    assert.ok(lastAttempted.recorded_at <= event.completed_at, 'last attempted location was recorded after attempt completion')
    if (resolved) assert.ok(resolved.recorded_at <= event.completed_at, 'resolved location was recorded after attempt completion')
    assert.equal(event.recorded_by_principal_code, manifest.submitter_principal_code)
    assert.ok(submitter.created_at <= event.recorded_at, 'retrieval event predates submitter')
    const collector = principals.get(event.collector_principal_code)
    assert.equal(collector?.principal_kind_code, 'service', 'collector must resolve to a service')
    assert.notEqual(event.collector_principal_code, manifest.expected_importer_principal_code, 'collector and technical importer must be distinct')
    assert.ok(collector.created_at <= event.started_at, 'retrieval predates collector')
    assert.ok(boundedTrimmedText(event.collector_software_code, 80) && boundedTrimmedText(event.collector_version, 80))
    assert.equal(event.request_method_code, 'GET', 'manifest v1 is GET-only')
    assert.equal(event.request_profile_code, 'http_get_representation_v1')
    assert.deepEqual(Object.keys(event.request_headers).toSorted(), ['accept', 'accept_encoding', 'accept_language'])
    for (const value of Object.values(event.request_headers)) {
      if (value !== null) assert.ok(safeHttpFieldValue(value, 512), 'invalid representation request header')
    }
    if (event.response_metadata.etag !== undefined) assert.ok(validEtag(event.response_metadata.etag), 'invalid response etag')
    if (event.response_metadata.last_modified !== undefined) assert.ok(validHttpDate(event.response_metadata.last_modified), 'invalid response last_modified')
    if (event.response_metadata.content_type !== undefined) assert.ok(safeHttpFieldValue(event.response_metadata.content_type, 255), 'invalid response content_type')
    if (event.response_metadata.content_encoding !== undefined) assert.ok(canonicalContentCoding(event.response_metadata.content_encoding), 'invalid response content_encoding')
    if (event.response_metadata.vary !== undefined) assert.ok(canonicalVary(event.response_metadata.vary), 'noncanonical Vary value')
    const artifact = event.artifact_code === null ? null : artifacts.get(event.artifact_code)
    if (event.artifact_code !== null) assert.ok(artifact, 'unknown event artifact')
    assertDependency(manifest, context, artifact?.bundle_code, usedDependencies)
    if (artifact) assert.ok(artifact.recorded_at <= event.recorded_at, 'retrieval artifact was recorded after event')
    const hasConditional = event.conditional_basis_retrieval_event_code !== null
      || event.conditional_validator_kind_code !== null
      || event.conditional_validator_value !== null
    if (hasConditional) {
      assert.ok(event.conditional_basis_retrieval_event_code !== null && ['etag', 'last_modified'].includes(event.conditional_validator_kind_code) && safeHttpFieldValue(event.conditional_validator_value, 512), 'incomplete conditional request basis')
      if (event.conditional_validator_kind_code === 'etag') assert.ok(validEtag(event.conditional_validator_value), 'invalid conditional ETag')
      else assert.ok(validHttpDate(event.conditional_validator_value), 'invalid conditional HTTP-date')
      const basis = retrievalEvents.get(event.conditional_basis_retrieval_event_code)
      assert.ok(basis?.outcome_code === 'retrieved_retained' && basis.http_status_code === 200, 'invalid conditional-request basis')
      const basisRequestedLocationCode = basis.requested_location_code ?? locationCodeFromId(context, basis.requested_location_id)
      const basisResolvedLocationCode = basis.resolved_location_code ?? locationCodeFromId(context, basis.resolved_location_id)
      assert.equal(basisRequestedLocationCode, event.requested_location_code)
      assert.equal(basisResolvedLocationCode, event.last_attempted_location_code, 'conditional attempt target differs from basis response location')
      assert.ok(basis.completed_at < event.started_at)
      const basisHeaders = basis.request_headers ?? {
        accept: basis.request_accept,
        accept_language: basis.request_accept_language,
        accept_encoding: basis.request_accept_encoding,
      }
      assert.equal(basis.request_method_code, event.request_method_code)
      assert.equal(basis.request_profile_code, event.request_profile_code)
      assert.deepEqual(basisHeaders, event.request_headers, 'conditional request representation profile differs from basis')
      const basisMetadata = basis.response_metadata ?? {
        etag: basis.response_etag ?? undefined,
        last_modified: basis.response_last_modified ?? undefined,
        vary: basis.response_vary ?? undefined,
      }
      const supportedVary = new Set([undefined, 'accept', 'accept-encoding', 'accept-language', 'accept, accept-encoding', 'accept, accept-language', 'accept-encoding, accept-language', 'accept, accept-encoding, accept-language'])
      assert.ok(supportedVary.has(basisMetadata.vary), 'unsupported Vary cannot support a reusable 304 basis')
      if (event.outcome_code === 'not_modified') {
        assert.equal(event.resolved_location_code, basisResolvedLocationCode, 'conditional response resolved location differs from basis')
        if (event.response_metadata.vary !== undefined) assert.equal(event.response_metadata.vary, basisMetadata.vary, '304 Vary differs from basis')
      }
      assert.equal(
        event.conditional_validator_value,
        event.conditional_validator_kind_code === 'etag' ? basisMetadata.etag : basisMetadata.last_modified,
        'conditional validator does not match basis response',
      )
      assertDependency(manifest, context, basis.bundle_code, usedDependencies)
    } else {
      assert.equal(event.conditional_basis_retrieval_event_code, null)
      assert.equal(event.conditional_validator_kind_code, null)
      assert.equal(event.conditional_validator_value, null)
    }
    if (event.outcome_code === 'retrieved_retained') {
      assert.ok(resolved && event.resolved_location_code === event.last_attempted_location_code && artifact?.byte_layer_code === 'retrieved_body')
      assert.ok(safePath(event.artifact_staged_path) && event.artifact_staged_path === custodyReference(artifact), 'retained retrieval staged path is not content addressed')
      assert.ok(timestamp(event.captured_at) && event.captured_at >= event.started_at && event.captured_at <= event.completed_at)
      assert.equal(event.http_status_code, 200, 'manifest v1 full retained representation requires HTTP 200')
      assert.equal(event.observed_sha256, null)
      assert.equal(event.observed_byte_length, null)
      assert.ok(safeHttpFieldValue(event.detected_media_type, 255))
    } else if (event.outcome_code === 'observed_not_retained') {
      assert.ok(resolved && event.resolved_location_code === event.last_attempted_location_code && event.artifact_code === null && event.artifact_staged_path === null && timestamp(event.captured_at))
      assert.ok(event.captured_at >= event.started_at && event.captured_at <= event.completed_at)
      assert.equal(event.http_status_code, 200, 'manifest v1 observed full representation requires HTTP 200')
      assert.ok(safeHttpFieldValue(event.detected_media_type, 255))
      assert.ok((event.observed_sha256 === null && event.observed_byte_length === null)
        || (/^[0-9a-f]{64}$/.test(event.observed_sha256) && Number.isSafeInteger(event.observed_byte_length) && event.observed_byte_length >= 0))
    } else if (event.outcome_code === 'not_modified') {
      assert.ok(resolved && event.resolved_location_code === event.last_attempted_location_code && event.artifact_code === null && event.artifact_staged_path === null && event.captured_at === null && event.http_status_code === 304)
      assert.equal(event.detected_media_type, null)
      assert.ok(hasConditional, '304 requires exact conditional-request basis and validator')
    } else if (event.outcome_code === 'network_failed') {
      assert.ok(event.resolved_location_code === null && event.artifact_code === null && event.artifact_staged_path === null && event.captured_at === null && event.http_status_code === null)
      assert.equal(event.detected_media_type, null)
      assert.deepEqual(event.response_metadata, {})
    } else if (event.outcome_code === 'http_failed') {
      assert.ok(resolved && event.resolved_location_code === event.last_attempted_location_code && event.artifact_code === null && event.artifact_staged_path === null && event.captured_at === null && event.http_status_code >= 300 && event.http_status_code <= 599 && event.http_status_code !== 304)
      assert.equal(event.detected_media_type, null)
    } else assert.fail('invalid retrieval outcome')
    if (event.outcome_code !== 'observed_not_retained') {
      assert.equal(event.observed_sha256, null, `${event.outcome_code} cannot carry an observed body hash`)
      assert.equal(event.observed_byte_length, null, `${event.outcome_code} cannot carry an observed body length`)
    }
    assert.notEqual(event.http_status_code, 206, 'manifest v1 rejects partial content')
    let from = event.requested_location_code
    event.redirects.forEach((redirect, index) => {
      assert.equal(redirect.ordinal, index + 1, 'redirect ordinals must be contiguous')
      assert.ok(redirect.record_code.startsWith(prefix) && code(redirect.record_code))
      assert.ok(!context.redirects.has(redirect.record_code), 'retrieval redirect collision')
      assert.equal(redirect.from_location_code, from, 'broken redirect chain')
      assert.notEqual(redirect.from_location_code, redirect.to_location_code, 'redirect endpoints must differ')
      const source = locations.get(redirect.from_location_code)
      const target = locations.get(redirect.to_location_code)
      assert.ok(source && target && source.recorded_at <= event.completed_at && target.recorded_at <= event.completed_at && [301, 302, 303, 307, 308].includes(redirect.http_status_code))
      assertDependency(manifest, context, target.bundle_code, usedDependencies)
      from = redirect.to_location_code
      allNewCodes.push(redirect.record_code)
    })
    if (event.redirects.length) assert.equal(from, event.last_attempted_location_code, 'redirect chain does not reach last attempted location')
    else assert.equal(event.last_attempted_location_code, event.requested_location_code, 'last attempted location differs without redirect evidence')
    if (event.resolved_location_code !== null) assert.equal(event.resolved_location_code, event.last_attempted_location_code, 'resolved response location differs from last attempted location')
    retrievalEvents.set(event.record_code, { ...event, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(event.record_code)
  }

  for (const custody of manifest.custody_events) {
    assert.ok(custody.record_code.startsWith(prefix) && code(custody.record_code))
    assert.ok(!custodyEvents.has(custody.record_code), 'custody event collision')
    const artifact = artifacts.get(custody.artifact_code)
    assert.ok(artifact, 'unknown custody artifact')
    assertDependency(manifest, context, artifact.bundle_code, usedDependencies)
    assert.ok(code(custody.copy_code, 120) && timestamp(custody.occurred_at) && timestamp(custody.recorded_at) && custody.occurred_at <= custody.recorded_at && custody.recorded_at <= manifest.bundle_created_at)
    assert.equal(custody.recorded_by_principal_code, manifest.submitter_principal_code)
    assert.ok(submitter.created_at <= custody.recorded_at && artifact.recorded_at <= custody.recorded_at, 'custody event predates its attribution or artifact')
    assert.ok(boundedText(custody.reason, 1000))
    let predecessor = null
    if (custody.event_kind_code === 'placed') {
      assert.equal(custody.predecessor_custody_event_code, null)
      assert.ok(!Array.from(custodyEvents.values()).some((row) => (row.artifact_code ?? artifactCodeFromId(context, row.artifact_id)) === custody.artifact_code && row.copy_code === custody.copy_code && (row.predecessor_custody_event_code ?? row.predecessor_custody_event_id) === null), 'custody copy already has a root')
    }
    else {
      predecessor = custodyEvents.get(custody.predecessor_custody_event_code)
      assert.ok(predecessor, 'unknown custody predecessor')
      assertDependency(manifest, context, predecessor.bundle_code, usedDependencies)
      assert.equal(predecessor.artifact_code ?? artifactsFromId(context, predecessor.artifact_id)?.artifact_code, custody.artifact_code)
      assert.equal(predecessor.copy_code, custody.copy_code)
      assert.ok(predecessor.recorded_at < custody.recorded_at)
      assert.ok((predecessor.occurred_at ?? predecessor.recorded_at) <= custody.occurred_at, 'custody occurrence predates predecessor occurrence')
      assert.ok(!Array.from(custodyEvents.values()).some((row) => (row.predecessor_custody_event_code ?? custodyCodeFromId(context, row.predecessor_custody_event_id)) === custody.predecessor_custody_event_code), 'custody predecessor is not current leaf')
      if (predecessor.event_kind_code === 'tombstoned') assert.equal(custody.event_kind_code, 'restored', 'only restoration may reverse a tombstone')
      else if (custody.event_kind_code === 'restored') assert.ok(['restricted', 'quarantined'].includes(predecessor.event_kind_code))
      else if (custody.event_kind_code === 'relocated') {
        assert.ok(['placed', 'relocated', 'restored'].includes(predecessor.event_kind_code), 'relocation cannot clear a restriction, quarantine, or tombstone')
        assert.ok(predecessor.backend_code !== custody.backend_code || predecessor.custody_class_code !== custody.custody_class_code, 'relocation must change backend or custody class')
      }
      else assert.ok(['restricted', 'quarantined', 'tombstoned'].includes(custody.event_kind_code))
    }
    if (custody.event_kind_code === 'tombstoned') {
      assert.equal(custody.backend_code, null)
      assert.equal(custody.backend_reference, null)
      assert.equal(custody.repository_eligibility_declaration, null)
    } else {
      if (['restricted', 'quarantined'].includes(custody.event_kind_code)) assert.equal(custody.custody_class_code, 'restricted_store')
      assert.ok(code(custody.backend_code, 40, 1))
      assert.equal(custody.backend_reference, custodyReference(artifact), 'custody reference is not content addressed')
      if (custody.custody_class_code === 'repository') {
        const declaration = custody.repository_eligibility_declaration
        assert.ok(declaration, 'repository custody requires an eligibility declaration')
        assert.equal(declaration.declared_by_principal_code, manifest.submitter_principal_code, 'eligibility declaration must be made by authenticated submitter')
        const declarant = principals.get(declaration.declared_by_principal_code)
        assert.equal(declarant?.principal_kind_code, 'human')
        assert.ok(timestamp(declaration.declared_at) && declarant.created_at <= declaration.declared_at && declaration.declared_at <= custody.recorded_at)
      } else assert.equal(custody.repository_eligibility_declaration, null)
    }
    custodyEvents.set(custody.record_code, { ...custody, local: true, artifact_id: artifact.id, bundle_sequence: manifest.bundle_sequence, bundle_code: manifest.bundle_id })
    allNewCodes.push(custody.record_code)
  }
  for (const artifact of manifest.artifacts) {
    assert.ok(manifest.custody_events.some((custody) => custody.artifact_code === artifact.record_code && custody.event_kind_code === 'placed'), `new artifact lacks initial durable placement: ${artifact.record_code}`)
    if (artifact.byte_layer_code === 'retrieved_body') {
      assert.ok(manifest.retrieval_events.some((event) => event.outcome_code === 'retrieved_retained' && event.artifact_code === artifact.record_code && event.captured_at <= artifact.recorded_at), `new artifact lacks a typed retrieval origin: ${artifact.record_code}`)
    }
  }
  const custodyArtifactCode = (row) => row.artifact_code ?? artifactCodeFromId(context, row.artifact_id)
  const custodyRecordCode = (row) => row.record_code ?? row.custody_event_code
  const custodyPredecessorCode = (row) => row.predecessor_custody_event_code ?? custodyCodeFromId(context, row.predecessor_custody_event_id)
  const custodyAt = (artifactCodeValue, eventAsOf, knownThroughSequence) => {
    const known = Array.from(custodyEvents.values()).filter((row) => custodyArtifactCode(row) === artifactCodeValue
      && (row.bundle_sequence ?? manifest.bundle_sequence) <= knownThroughSequence
      && (row.occurred_at ?? row.recorded_at) <= eventAsOf)
    return known.filter((row) => !known.some((successor) => custodyPredecessorCode(successor) === custodyRecordCode(row)))
  }
  const hasAvailableCustodyAt = (artifactCodeValue, eventAsOf, knownThroughSequence) => custodyAt(artifactCodeValue, eventAsOf, knownThroughSequence)
    .some((row) => ['placed', 'relocated', 'restored'].includes(row.event_kind_code))
  const hasQualifyingCustodyAfter = (artifactCodeValue, occurrenceAt, knownThroughSequence) => Array.from(custodyEvents.values())
    .some((row) => custodyArtifactCode(row) === artifactCodeValue
      && (row.bundle_sequence ?? manifest.bundle_sequence) <= knownThroughSequence
      && (row.occurred_at ?? row.recorded_at) >= occurrenceAt
      && ['placed', 'relocated', 'restored'].includes(row.event_kind_code))
  const hasCustodyForOccurrence = (artifactCodeValue, occurrenceAt, knownThroughSequence) => hasAvailableCustodyAt(artifactCodeValue, occurrenceAt, knownThroughSequence)
    || hasQualifyingCustodyAfter(artifactCodeValue, occurrenceAt, knownThroughSequence)
  const groundedArtifacts = new Set()
  const lineage = new Map()
  const addLineage = (inputCode, outputCode) => {
    if (!lineage.has(inputCode)) lineage.set(inputCode, new Set())
    lineage.get(inputCode).add(outputCode)
  }
  const reaches = (startCode, targetCode) => {
    if (startCode === targetCode) return true
    const visited = new Set([startCode])
    const pending = [startCode]
    while (pending.length) {
      const current = pending.shift()
      for (const next of lineage.get(current) ?? []) {
        if (next === targetCode) return true
        if (!visited.has(next)) {
          visited.add(next)
          pending.push(next)
        }
      }
    }
    return false
  }
  for (const event of retrievalEvents.values()) {
    if (event.outcome_code === 'retrieved_retained') groundedArtifacts.add(event.artifact_code ?? artifactCodeFromId(context, event.artifact_id))
  }
  const persistedRuns = Array.from(context.processingRuns.values()).toSorted((left, right) =>
    left.bundle_sequence - right.bundle_sequence || left.run_ordinal - right.run_ordinal || left.processing_run_code.localeCompare(right.processing_run_code))
  for (const run of persistedRuns) {
    const inputCode = artifactCodeFromId(context, run.input_artifact_id)
    assert.ok(groundedArtifacts.has(inputCode), `persisted processing input is not grounded: ${run.processing_run_code}`)
    const outputs = Array.from(context.processingOutputs.values())
      .filter((output) => output.processing_run_id === run.id)
      .toSorted((left, right) => left.output_ordinal - right.output_ordinal || left.processing_output_code.localeCompare(right.processing_output_code))
    for (const output of outputs) {
      const outputCode = artifactCodeFromId(context, output.artifact_id)
      assert.ok(!reaches(outputCode, inputCode), `persisted processing lineage cycle: ${run.processing_run_code}`)
      addLineage(inputCode, outputCode)
      groundedArtifacts.add(outputCode)
    }
  }
  for (const event of manifest.retrieval_events.filter((row) => row.outcome_code === 'retrieved_retained')) {
    assert.ok(hasCustodyForOccurrence(event.artifact_code, event.captured_at, manifest.bundle_sequence), `retained retrieval has no custody interval at or after capture: ${event.record_code}`)
  }

  unique(manifest.processing_runs.map((run) => run.ordinal), 'processing run ordinal')
  assert.deepEqual(manifest.processing_runs.map((run) => run.ordinal), manifest.processing_runs.map((_, index) => index), 'processing run ordinals must be contiguous from zero')
  for (const run of manifest.processing_runs) {
    assert.ok(run.record_code.startsWith(prefix) && code(run.record_code))
    assert.ok(!processingRuns.has(run.record_code), 'processing run collision')
    const artifact = artifacts.get(run.input_artifact_code)
    assert.ok(artifact, 'unknown processing input')
    assertDependency(manifest, context, artifact.bundle_code, usedDependencies)
    assert.ok(groundedArtifacts.has(run.input_artifact_code), 'processing input lacks an earlier grounded retrieval or run')
    const processor = principals.get(run.processor_principal_code)
    assert.ok(processor && processor.principal_code !== 'system.bootstrap')
    assert.notEqual(run.processor_principal_code, manifest.expected_importer_principal_code, 'processor and technical importer must be distinct')
    if (run.method_code === 'manual_transcription') assert.equal(processor.principal_kind_code, 'human')
    else assert.equal(processor.principal_kind_code, 'service')
    assert.ok(timestamp(run.started_at) && timestamp(run.completed_at) && timestamp(run.recorded_at))
    assert.ok(processor.created_at <= run.started_at && run.started_at <= run.completed_at && run.completed_at <= run.recorded_at && run.recorded_at <= manifest.bundle_created_at)
    assert.equal(run.recorded_by_principal_code, manifest.submitter_principal_code)
    assert.ok(boundedTrimmedText(run.processor_software_code, 80) && boundedTrimmedText(run.processor_version, 80))
    for (const value of Object.values(run.configuration)) {
      if (typeof value === 'string') assert.ok(boundedText(value, 1000, { nonblank: false }), 'invalid configuration string')
    }
    assert.equal(run.configuration_sha256, configurationDigest(run.configuration), 'configuration digest mismatch')
    assert.ok(submitter.created_at <= run.recorded_at && artifact.recorded_at <= run.started_at, 'processing run predates attribution or input identity')
    assert.ok(hasAvailableCustodyAt(run.input_artifact_code, run.started_at, manifest.bundle_sequence), 'processing input is not retained and available at its acceptance knowledge boundary')
    assert.ok(processingOutputKinds[run.method_code], 'unknown processing method')
    if (run.method_code === 'content_decoding') {
      assert.equal(artifact.byte_layer_code, 'retrieved_body', 'content decoding requires a retrieved-body input')
      assert.deepEqual(Object.keys(run.configuration), ['content_coding'], 'content decoding requires exactly the pinned content_coding configuration')
      assert.ok(canonicalContentCoding(run.configuration.content_coding), 'invalid pinned content coding')
      const observedCodings = Array.from(retrievalEvents.values())
        .filter((event) => event.outcome_code === 'retrieved_retained' && (event.artifact_code ?? artifactCodeFromId(context, event.artifact_id)) === run.input_artifact_code)
        .map((event) => (event.response_metadata ?? { content_encoding: event.response_content_encoding }).content_encoding)
      assert.ok(observedCodings.includes(run.configuration.content_coding), 'pinned content coding was not observed on a retained input occurrence')
    }
    if (run.outcome_code === 'failed') {
      assert.ok(boundedText(run.failure_code, 80))
      assert.equal(run.outputs.length, 0)
    } else {
      assert.equal(run.outcome_code, 'succeeded')
      assert.equal(run.failure_code, null)
      if (run.method_code === 'content_decoding') {
        assert.equal(run.outputs.length, 1, 'successful content decoding requires exactly one decoded body')
      }
    }
    unique(run.outputs.map((output) => output.record_code), 'processing output code')
    unique(run.outputs.map((output) => output.ordinal), 'processing output ordinal')
    assert.deepEqual(run.outputs.map((output) => output.ordinal), run.outputs.map((_, index) => index), 'output ordinals must be contiguous from zero')
    for (const output of run.outputs) {
      assert.ok(output.record_code.startsWith(prefix) && code(output.record_code) && !processingOutputs.has(output.record_code))
      const outputArtifact = artifacts.get(output.artifact_code)
      assert.equal(outputArtifact?.byte_layer_code, 'derived_output')
      assert.ok(processingOutputKinds[run.method_code].has(output.output_kind_code), 'processing method/output kind mismatch')
      assert.ok(!reaches(output.artifact_code, run.input_artifact_code), 'processing lineage cycle')
      assertDependency(manifest, context, outputArtifact.bundle_code, usedDependencies)
      assert.ok(timestamp(output.produced_at) && run.started_at <= output.produced_at && output.produced_at <= run.completed_at)
      assert.ok(safePath(output.staged_path) && output.staged_path === custodyReference(outputArtifact), 'staged output path is not content addressed')
      assert.ok(outputArtifact.recorded_at <= run.recorded_at, 'derived artifact identity chronology')
      const hasEarlierProduction = Array.from(processingOutputs.values()).some((prior) => {
        const priorRunCode = prior.run_code ?? processingRunCodeFromId(context, prior.processing_run_id)
        return priorRunCode !== run.record_code && (prior.artifact_code ?? artifactCodeFromId(context, prior.artifact_id)) === output.artifact_code
      })
      if (outputArtifact.local && !hasEarlierProduction) assert.ok(output.produced_at <= outputArtifact.recorded_at, 'new derived artifact identity predates its original production event')
      assert.ok(safeHttpFieldValue(output.detected_media_type, 255))
      assert.ok(hasCustodyForOccurrence(output.artifact_code, output.produced_at, manifest.bundle_sequence), `processing output has no custody interval at or after production: ${output.record_code}`)
      processingOutputs.set(output.record_code, { ...output, local: true, run_code: run.record_code, artifact_code: output.artifact_code, recorded_at: run.recorded_at, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
      addLineage(run.input_artifact_code, output.artifact_code)
      groundedArtifacts.add(output.artifact_code)
      allNewCodes.push(output.record_code)
    }
    processingRuns.set(run.record_code, { ...run, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(run.record_code)
  }
  for (const artifact of manifest.artifacts.filter((row) => row.byte_layer_code === 'derived_output')) {
    assert.ok(groundedArtifacts.has(artifact.record_code), `new artifact lacks an acyclic grounded processing origin: ${artifact.record_code}`)
  }

  for (const candidate of manifest.candidate_occurrences) {
    assert.ok(candidate.record_code.startsWith(prefix) && code(candidate.record_code))
    assert.ok(!candidates.has(candidate.record_code), 'candidate occurrence collision')
    const run = processingRuns.get(candidate.processing_run_code)
    const output = processingOutputs.get(candidate.processing_output_code)
    assert.ok(run && output, 'unknown candidate lineage')
    const outputRunCode = output.run_code ?? processingRunCodeFromId(context, output.processing_run_id)
    assert.equal(outputRunCode, candidate.processing_run_code, 'candidate output/run mismatch')
    assert.notEqual(output.output_kind_code, 'diagnostic', 'diagnostic output cannot support a candidate')
    assertDependency(manifest, context, run.bundle_code, usedDependencies)
    assertDependency(manifest, context, output.bundle_code, usedDependencies)
    assert.ok(timestamp(candidate.recorded_at) && output.recorded_at <= candidate.recorded_at && candidate.recorded_at <= manifest.bundle_created_at)
    assert.equal(candidate.recorded_by_principal_code, manifest.submitter_principal_code)
    assert.ok(submitter.created_at <= candidate.recorded_at, 'candidate occurrence predates submitter')
    assert.ok(code(candidate.claim_type_code, 80) && boundedText(candidate.locator_value, 1000) && boundedText(candidate.reason, 1000))
    assert.ok(['byte_span', 'text_span'].includes(candidate.locator_kind_code))
    assert.ok(Number.isSafeInteger(candidate.span_start) && Number.isSafeInteger(candidate.span_end) && candidate.span_start >= 0 && candidate.span_end > candidate.span_start)
    const outputArtifact = artifacts.get(output.artifact_code ?? artifactCodeFromId(context, output.artifact_id))
    assert.ok(candidate.span_end <= outputArtifact.byte_length, 'candidate span exceeds output byte bound')
    if (candidate.record_kind_code === 'assertion') {
      assert.equal(candidate.corrects_candidate_record_code, null)
      assert.equal(typeof candidate.observed_value, 'string')
      assert.ok(candidate.chain_code.startsWith(prefix), 'new candidate chain must be bundle-prefixed')
      assert.ok(!Array.from(candidates.values()).some((row) => (row.candidate_chain_code ?? row.chain_code) === candidate.chain_code && !(row.corrects_candidate_occurrence_id ?? row.corrects_candidate_record_code)), 'candidate chain already has root')
    } else {
      const predecessor = candidates.get(candidate.corrects_candidate_record_code)
      assert.ok(predecessor, 'unknown candidate predecessor')
      assertDependency(manifest, context, predecessor.bundle_code, usedDependencies)
      assert.equal(predecessor.candidate_chain_code ?? predecessor.chain_code, candidate.chain_code)
      assert.equal(predecessor.claim_type_code, candidate.claim_type_code)
      assert.ok(predecessor.recorded_at < candidate.recorded_at)
      const predecessorCode = predecessor.candidate_record_code ?? predecessor.record_code
      assert.ok(!Array.from(candidates.values()).some((row) => (row.corrects_candidate_record_code ?? candidateCodeFromId(context, row.corrects_candidate_occurrence_id)) === predecessorCode), 'candidate predecessor is not current leaf')
      if (candidate.record_kind_code === 'withdrawal') {
        assert.equal(candidate.observed_value, null)
        assert.equal(candidate.normalized_value, null)
        assert.equal(candidate.confidence_basis_points, null)
      } else {
        assert.equal(candidate.record_kind_code, 'correction')
        assert.equal(typeof candidate.observed_value, 'string')
      }
    }
    if (candidate.observed_value !== null) assert.ok(boundedText(candidate.observed_value, 8000))
    if (candidate.normalized_value !== null) assert.ok(boundedText(candidate.normalized_value, 8000))
    candidates.set(candidate.record_code, { ...candidate, local: true, bundle_code: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence })
    allNewCodes.push(candidate.record_code)
  }

  unique(allNewCodes, 'new record code')
  for (const dependency of dependencies) assert.ok(usedDependencies.has(dependency.bundle_id) || dependency.bundle_id === Array.from(context.receipts.values()).find((receipt) => receipt.bundle_sequence === manifest.bundle_sequence - 1)?.bundle_code, `unused required bundle: ${dependency.bundle_id}`)
  assertNoForbiddenMaterial(manifest)
  return true
}

function artifactsFromId(context, id) {
  return Array.from(context.artifacts.values()).find((row) => row.id === id)
}

function artifactCodeFromId(context, id) {
  return artifactsFromId(context, id)?.artifact_code
}

function locationCodeFromId(context, id) {
  return Array.from(context.locations.values()).find((row) => row.id === id)?.location_code
}

function custodyCodeFromId(context, id) {
  return Array.from(context.custodyEvents.values()).find((row) => row.id === id)?.custody_event_code
}

function processingRunCodeFromId(context, id) {
  return Array.from(context.processingRuns.values()).find((row) => row.id === id)?.processing_run_code
}

function candidateCodeFromId(context, id) {
  return Array.from(context.candidates.values()).find((row) => row.id === id)?.candidate_record_code
}

function confinedRead(root, relativePath) {
  assert.ok(safePath(relativePath, 512), `unsafe relative path: ${relativePath}`)
  const rootReal = fs.realpathSync(root)
  const segments = relativePath.split('/')
  let cursor = rootReal
  for (const segment of segments) {
    cursor = path.join(cursor, segment)
    const stat = fs.lstatSync(cursor)
    assert.ok(!stat.isSymbolicLink(), `symbolic link prohibited: ${relativePath}`)
  }
  const candidateReal = fs.realpathSync(cursor)
  assert.ok(candidateReal.startsWith(`${rootReal}${path.sep}`), 'path escapes adapter root')
  const descriptor = fs.openSync(candidateReal, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0))
  try {
    assert.ok(fs.fstatSync(descriptor).isFile(), `adapter target is not a regular file: ${relativePath}`)
    return fs.readFileSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
}

function verifyBytes(bytes, artifact, label) {
  assert.equal(bytes.length, artifact.byte_length, `${label} byte-length mismatch`)
  assert.equal(sha256(bytes), artifact.sha256, `${label} SHA-256 mismatch`)
}

function verifyEvidenceBytes(manifest, context, adapter, { noOp = false } = {}) {
  const artifacts = new Map(context.artifacts)
  if (noOp) {
    const referencedArtifactCodes = new Set(manifest.artifacts.map((artifact) => artifact.record_code))
    for (const event of manifest.retrieval_events) if (event.artifact_code !== null) referencedArtifactCodes.add(event.artifact_code)
    for (const custody of manifest.custody_events) referencedArtifactCodes.add(custody.artifact_code)
    for (const run of manifest.processing_runs) {
      referencedArtifactCodes.add(run.input_artifact_code)
      for (const output of run.outputs) referencedArtifactCodes.add(output.artifact_code)
    }
    const custodyRows = Array.from(context.custodyEvents.values())
    for (const artifactCodeValue of referencedArtifactCodes) {
      const artifact = artifacts.get(artifactCodeValue)
      assert.ok(artifact, `unknown accepted artifact ${artifactCodeValue}`)
      const artifactCustody = custodyRows.filter((row) => row.artifact_id === artifact.id)
      const leaves = artifactCustody.filter((row) => !artifactCustody.some((successor) => successor.predecessor_custody_event_id === row.id))
      for (const leaf of leaves.filter((row) => row.event_kind_code !== 'tombstoned')) {
        const root = adapter.backendRoots.get(leaf.backend_code)
        assert.ok(root, `unconfigured current custody backend ${leaf.backend_code}`)
        verifyBytes(confinedRead(root, leaf.backend_reference), artifact, `current custody copy ${leaf.custody_event_code}`)
      }
    }
    return
  }
  for (const artifact of manifest.artifacts) {
    const bytes = confinedRead(adapter.stagingRoot, artifact.staged_path)
    verifyBytes(bytes, artifact, `staged artifact ${artifact.record_code}`)
    artifacts.set(artifact.record_code, artifact)
  }
  for (const event of manifest.retrieval_events.filter((row) => row.outcome_code === 'retrieved_retained')) {
    const artifact = artifacts.get(event.artifact_code)
    assert.ok(artifact, `unknown retained retrieval artifact: ${event.record_code}`)
    assert.equal(event.artifact_staged_path, custodyReference(artifact), 'non-content-addressed retained retrieval bytes')
    verifyBytes(
      confinedRead(adapter.stagingRoot, event.artifact_staged_path),
      artifact,
      `staged retained retrieval ${event.record_code}`,
    )
  }
  for (const custody of manifest.custody_events) {
    if (custody.event_kind_code === 'tombstoned') continue
    const artifact = artifacts.get(custody.artifact_code)
    assert.ok(artifact, `unknown custody artifact ${custody.artifact_code}`)
    assert.equal(custody.backend_reference, custodyReference(artifact), 'non-content-addressed custody reference')
    const root = adapter.backendRoots.get(custody.backend_code)
    assert.ok(root, `unconfigured custody backend ${custody.backend_code}`)
    const bytes = confinedRead(root, custody.backend_reference)
    verifyBytes(bytes, artifact, `custody copy ${custody.record_code}`)
  }
  const custodyRows = [...context.custodyEvents.values(), ...manifest.custody_events]
  const custodyCode = (row) => row.custody_event_code ?? row.record_code
  const custodyPredecessorCode = (row) => row.predecessor_custody_event_code ?? custodyCodeFromId(context, row.predecessor_custody_event_id)
  const custodyArtifactCode = (row) => row.artifact_code ?? artifactCodeFromId(context, row.artifact_id)
  const verifiedRetainedBytes = (artifactCodeValue, eventAsOf, knownThroughSequence, label) => {
    const artifact = artifacts.get(artifactCodeValue)
    assert.ok(artifact, `unknown retained artifact: ${label}`)
    const rowsAtTime = custodyRows.filter((row) => custodyArtifactCode(row) === artifactCodeValue
      && (row.bundle_sequence ?? manifest.bundle_sequence) <= knownThroughSequence
      && (row.occurred_at ?? row.recorded_at) <= eventAsOf)
    const eligibleLeaves = rowsAtTime
      .filter((row) => !rowsAtTime.some((successor) => custodyPredecessorCode(successor) === custodyCode(row)))
      .filter((row) => ['placed', 'relocated', 'restored'].includes(row.event_kind_code))
      .toSorted((left, right) => custodyCode(left).localeCompare(custodyCode(right)))
    assert.ok(eligibleLeaves.length > 0, `artifact has no retained custody at use time: ${label}`)
    for (const leaf of eligibleLeaves) {
      const root = adapter.backendRoots.get(leaf.backend_code)
      if (!root) continue
      const bytes = confinedRead(root, leaf.backend_reference)
      verifyBytes(bytes, artifact, label)
      return bytes
    }
    assert.fail(`no accessible configured custody copy: ${label}`)
  }
  for (const run of manifest.processing_runs) {
    verifiedRetainedBytes(run.input_artifact_code, run.started_at, manifest.bundle_sequence, `processing input ${run.record_code}`)
    for (const output of run.outputs) {
      const artifact = artifacts.get(output.artifact_code)
      assert.ok(artifact, `unknown processing output artifact: ${output.record_code}`)
      assert.equal(output.staged_path, custodyReference(artifact), 'non-content-addressed staged processing output')
      const bytes = confinedRead(adapter.stagingRoot, output.staged_path)
      verifyBytes(bytes, artifact, `staged processing output ${output.record_code}`)
    }
  }
  const outputs = new Map(context.processingOutputs)
  for (const run of manifest.processing_runs) {
    for (const output of run.outputs) outputs.set(output.record_code, { ...output })
  }
  for (const candidate of manifest.candidate_occurrences.filter((row) => ['byte_span', 'text_span'].includes(row.locator_kind_code))) {
    const output = outputs.get(candidate.processing_output_code)
    const artifactCodeValue = output?.artifact_code ?? artifactCodeFromId(context, output?.artifact_id)
    const artifact = artifacts.get(artifactCodeValue)
    assert.ok(artifact, `locator output artifact is unavailable: ${candidate.record_code}`)
    const bytes = verifiedRetainedBytes(artifactCodeValue, candidate.recorded_at, manifest.bundle_sequence, `locator artifact ${candidate.record_code}`)
    const upperBound = candidate.locator_kind_code === 'byte_span'
      ? bytes.length
      : Array.from(new TextDecoder('utf-8', { fatal: true }).decode(bytes)).length
    assert.ok(candidate.span_end <= upperBound, `locator span exceeds verified ${candidate.locator_kind_code} bound`)
  }
}

function migrationDirectory(proposalSql = fs.readFileSync(proposalPath)) {
  const directory = temporaryDirectory('jedi-2a-migrations-')
  for (const name of migrationNames) fs.copyFileSync(path.join(migrations, name), path.join(directory, name))
  fs.writeFileSync(path.join(directory, '005_tranche_2a_design.sql'), proposalSql)
  return directory
}

function digestTable(database, table) {
  const columns = database.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name)
  const order = columns.map((column) => `"${column}"`).join(',')
  const rows = database.prepare(`SELECT * FROM "${table}" ORDER BY ${order}`).all().map((row) => ({ ...row }))
  return sha256(JSON.stringify(rows))
}

function custodyLeafAt(database, copyCode, eventAsOf, knownThroughSequence) {
  return database.prepare(`SELECT c.event_kind_code,c.occurred_at,c.recorded_at,r.bundle_sequence
    FROM atlas_artifact_custody_events c
    JOIN atlas_evidence_bundle_receipts r ON r.id=c.evidence_bundle_receipt_id
    WHERE c.copy_code=? AND c.occurred_at<=? AND r.bundle_sequence<=?
      AND NOT EXISTS(
        SELECT 1 FROM atlas_artifact_custody_events successor
        JOIN atlas_evidence_bundle_receipts successor_receipt ON successor_receipt.id=successor.evidence_bundle_receipt_id
        WHERE successor.predecessor_custody_event_id=c.id AND successor.occurred_at<=? AND successor_receipt.bundle_sequence<=?
      )
    ORDER BY c.occurred_at DESC,r.bundle_sequence DESC,c.id DESC LIMIT 1`).get(copyCode, eventAsOf, knownThroughSequence, eventAsOf, knownThroughSequence)
}

function candidateLeafAt(database, chainCode, knownAt) {
  return database.prepare(`SELECT c.record_kind_code,c.observed_value,c.recorded_at
    FROM atlas_unverified_candidate_occurrences c
    WHERE c.candidate_chain_code=? AND c.recorded_at<=?
      AND NOT EXISTS(
        SELECT 1 FROM atlas_unverified_candidate_occurrences successor
        WHERE successor.corrects_candidate_occurrence_id=c.id AND successor.recorded_at<=?
      )
    ORDER BY c.recorded_at DESC,c.id DESC LIMIT 1`).get(chainCode, knownAt, knownAt)
}

function legacyDigests(databasePath) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    return Object.fromEntries(legacyTables.map((table) => [table, digestTable(database, table)]))
  } finally {
    database.close()
  }
}

function atlasState(database) {
  const stateTables = ['atlas_principals', ...tables]
  return Object.fromEntries(stateTables.map((table) => [table, {
    count: database.prepare(`SELECT count(*) AS count FROM ${table}`).get().count,
    digest: digestTable(database, table),
  }]))
}

function assertRejectedBeforeBegin({ database, manifest, environment, schema, runtime, pattern }) {
  const before = atlasState(database)
  const observer = { beginCount: 0 }
  const input = materializeManifest(environment, manifest)
  const originalExec = database.exec.bind(database)
  let actualBeginCount = 0
  database.exec = (sql) => {
    if (/^\s*BEGIN\b/i.test(sql)) actualBeginCount += 1
    return originalExec(sql)
  }
  try {
    assert.throws(
      () => simulateImport({ database, ...input, schema, adapter: environment.adapter, ...runtime, transactionObserver: observer }),
      pattern,
    )
  } finally {
    database.exec = originalExec
  }
  assert.equal(observer.beginCount, 0, 'invalid bundle reached importer BEGIN boundary')
  assert.equal(actualBeginCount, 0, 'invalid bundle executed BEGIN')
  assert.equal(database.isTransaction, false, 'invalid bundle left a transaction open')
  assert.deepEqual(atlasState(database), before, 'preflight rejection mutated the database')
}

function openDatabase(databasePath, recursiveTriggers = true) {
  const database = new DatabaseSync(databasePath)
  database.exec(`PRAGMA foreign_keys=ON;PRAGMA recursive_triggers=${recursiveTriggers ? 'ON' : 'OFF'}`)
  assert.equal(database.prepare('PRAGMA foreign_keys').get().foreign_keys, 1)
  assert.equal(database.prepare('PRAGMA recursive_triggers').get().recursive_triggers, recursiveTriggers ? 1 : 0)
  return database
}

function schemaInventory(database) {
  const rows = database.prepare("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").all()
  return {
    table: rows.filter((row) => row.type === 'table').map((row) => row.name),
    index: rows.filter((row) => row.type === 'index').map((row) => row.name),
    trigger: rows.filter((row) => row.type === 'trigger').map((row) => row.name),
    view: rows.filter((row) => row.type === 'view').map((row) => row.name),
  }
}

function normalizeSchemaSql(sql) {
  assert.equal(typeof sql, 'string', 'schema definition SQL is missing')
  let normalized = ''
  let quote = null
  let pendingSpace = false
  for (let index = 0; index < sql.length; index += 1) {
    const character = sql[index]
    if (quote !== null) {
      normalized += character
      if (quote === '[') {
        if (character === ']') quote = null
      } else if (character === quote) {
        if (sql[index + 1] === quote) normalized += sql[++index]
        else quote = null
      }
      continue
    }
    if (character === "'" || character === '"' || character === '`' || character === '[') {
      if (pendingSpace && normalized.length) normalized += ' '
      pendingSpace = false
      quote = character
      normalized += character
      continue
    }
    assert.ok(!(character === '-' && sql[index + 1] === '-') && !(character === '/' && sql[index + 1] === '*'), 'schema definitions may not contain SQL comments')
    if (' \t\n\v\f\r'.includes(character)) {
      pendingSpace = normalized.length > 0
      continue
    }
    if (pendingSpace && normalized.length) normalized += ' '
    pendingSpace = false
    normalized += character
  }
  assert.equal(quote, null, 'unterminated schema identifier or string')
  return normalized.trim().replace(/;$/u, '')
}

function schemaDefinitionSnapshot(database) {
  return database.prepare(`SELECT type,name,tbl_name,sql
    FROM sqlite_schema
    ORDER BY type,name,tbl_name`).all().map((row) => ({ ...row }))
}

function schemaDefinitionKey(row) {
  return `${row.type}\0${row.name}\0${row.tbl_name}`
}

function assertPriorSchemaPreserved(before, after) {
  const afterByKey = new Map(after.map((row) => [schemaDefinitionKey(row), row]))
  for (const expected of before) {
    const actual = afterByKey.get(schemaDefinitionKey(expected))
    assert.ok(actual, `pre-existing schema object was deleted: ${expected.type} ${expected.name}`)
    assert.equal(actual.sql, expected.sql, `pre-existing schema object was modified: ${expected.type} ${expected.name}`)
  }
}

const expectedSchemaDefinitionHashes = {
  'table:atlas_artifact_custody_events': 'ec753dafa52e71b0743dca1eb1688f19280cc543b00822d527385959cca464eb',
  'table:atlas_artifacts': '4b11118f683aae54acc251a24c61f630b4260656e6b516f286794c7ced75b947',
  'table:atlas_evidence_bundle_receipts': '159c2871f3cb9269273f03d97e953b3312b042520cab5db3165a4ed6fd726af9',
  'table:atlas_processing_outputs': '63fce990c34a7cc64bd59c745316cc3437c2f285ba4be0b75b0feb4440e6e503',
  'table:atlas_processing_runs': '9a9198d22ee102e6d0a918e812a2e14d0de31bd109b870d354f65e28f38ae69f',
  'table:atlas_retrieval_events': '448fa9e00680497d920eb5d7b44693ceb255df1c0bb44fefa0bbf940488d82ab',
  'table:atlas_retrieval_locations': 'f16659fb6aeb6af2e066acecad294d00150408e3d37419be99214a5cf921abd7',
  'table:atlas_retrieval_redirects': '200e94a34112f9e6a859c685053cdf76b424b2d4ebe1db225313c2502a720be2',
  'table:atlas_unverified_candidate_occurrences': '3497bd04f8602a27038b1d12ed89f42f0c371a0c80a5c35ef4aea0dc90fae894',
  'trigger:atlas_artifact_custody_events_immutable_delete': 'f0e4729900a72b17c1333532f9cbd5aca7ff6a779491f0cc691cb616ba344ddc',
  'trigger:atlas_artifact_custody_events_immutable_update': '4ad87fb4ee544614990bb0e68e6bee12a20b3983a4001f62be4d81e9903849a7',
  'trigger:atlas_artifact_custody_events_validate_insert': 'c097afd6256429de5c9e4e7169166e3cd3910c906c317a54349eaa52da7964fc',
  'trigger:atlas_artifacts_immutable_delete': '5687672d77722c8e0654dffecd351d23edcf3d59222f1636ecb5399e655ca001',
  'trigger:atlas_artifacts_immutable_update': '2642411edf4e6cbe9d5a69d3ff2b495f01d7c6cf6c19341ea98fa593d45f51a0',
  'trigger:atlas_artifacts_validate_insert': 'ee15f7b5f3326ac4f0c364c09b871ab88c07ca7afc72a122ba07c4bac6cced5b',
  'trigger:atlas_candidate_occurrences_immutable_delete': '62b3a5572382b0a293d434cbf4f87b4f8efe8e28d8e99e808e8b2325844c4ef5',
  'trigger:atlas_candidate_occurrences_immutable_update': '6f83e78b56c8c8eee7b789c689e2c0677e2ccf2761d067d4b2c114d4d7e6d6b9',
  'trigger:atlas_candidate_occurrences_validate_insert': '491100caee34b6b6234ae08eed5f73d0f443c50c3f680c0bf1f2222d75d8fc8e',
  'trigger:atlas_evidence_bundle_receipts_immutable_delete': 'd67d920ff62647a07d495ba8aea810fb0cbbab545b08c5897b70d4718b0a08d4',
  'trigger:atlas_evidence_bundle_receipts_immutable_update': '38bae632a5b030ef3c370b3400eaea1a200bf92de6e18224caf9a5bcef8e4c20',
  'trigger:atlas_evidence_bundle_receipts_validate_insert': 'c523c7938329c606f743f46823e216f8e490b1d1fc3181a19591c6dde3d6991a',
  'trigger:atlas_processing_outputs_immutable_delete': '638e9b056221fb0ac7177a7be1cd6d0910ba922eeba8f497c61b00f294ef5ece',
  'trigger:atlas_processing_outputs_immutable_update': '40044736ef07ab698e2a853dd467ad82b4f11a2c9a945b935a571974f35c8763',
  'trigger:atlas_processing_outputs_validate_insert': 'fecdb0d193afd57d565c4cf125334aaec73d4319a48fa87e5c2bd2af8c48e5c5',
  'trigger:atlas_processing_runs_immutable_delete': 'f97376d996a2ecb7cd9713047468722f4c0bf4cb78ca756adf2773672215a9b4',
  'trigger:atlas_processing_runs_immutable_update': '33e46a4e96b6e5f5591efb9b581b81051d824dbf8ff3173ac1ceb02ad4aa6eda',
  'trigger:atlas_processing_runs_validate_insert': '29aedcf94038534c7fd1053d3a92cab80ca5449027f3b16c54c3b8a53a21e54d',
  'trigger:atlas_retrieval_events_immutable_delete': 'a9a6acd1e822557e517d3851a6b6a37ebf56233094a2e9c493e2a9a58ed6bc11',
  'trigger:atlas_retrieval_events_immutable_update': 'f70fe5a85f7f523b2a0f867b8f5408b72758d67c1d4d04ce84ef5232b3bf06ba',
  'trigger:atlas_retrieval_events_validate_insert': '6585ee268d249ef661f0292ac905bab32132c53898578d56cbe99eb869ff38e5',
  'trigger:atlas_retrieval_locations_immutable_delete': '7b938ac0ce988dc3088aba5b3736c81be6aa5f79efb03381a90eef98babc40ee',
  'trigger:atlas_retrieval_locations_immutable_update': '4f167ab7f1f42931a11676e24ab2da9a4f7388482fd697915b2f5aa2e8bcebd1',
  'trigger:atlas_retrieval_locations_validate_insert': '0ecb412c3afefcf96d6bc93d612d173dce912b2867fd2587fddae021ced2b7a3',
  'trigger:atlas_retrieval_redirects_immutable_delete': '359110fcb70b87d1977038d198fc726f44761968f717ba7a13b6ca608486b102',
  'trigger:atlas_retrieval_redirects_immutable_update': '39de1782a1f9a88f7661aef646125ca2f59d23a68aa8e016a4485782397cfa57',
  'trigger:atlas_retrieval_redirects_validate_insert': 'd7ccd67ce4da3167d7ef7dc8ef173837f99b2811f1e416041bc5868e8cdd633d',
}

function schemaDefinitionDigest(row) {
  return sha256(`${row.type}\0${row.name}\0${row.tbl_name}\0${normalizeSchemaSql(row.sql)}`)
}

function inventoryDelta(before, after) {
  return Object.fromEntries(Object.keys(after).map((type) => [type, after[type].filter((name) => !before[type].includes(name))]))
}

function rowId(map, codeValue) {
  return map.get(codeValue)?.id ?? null
}

const persistedProjectionColumns = {
  atlas_evidence_bundle_receipts: ['id', 'bundle_sequence', 'bundle_code', 'format_version_code', 'bundle_digest_sha256', 'manifest_path', 'bundle_created_at', 'submitted_by_principal_id', 'imported_by_principal_id', 'importer_software_code', 'importer_version', 'recorded_by_principal_id', 'recorded_at'],
  atlas_retrieval_locations: ['id', 'location_code', 'location_url', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_artifacts: ['id', 'artifact_code', 'byte_layer_code', 'hash_algorithm_code', 'sha256', 'byte_length', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_retrieval_events: ['id', 'retrieval_event_code', 'requested_location_id', 'last_attempted_location_id', 'resolved_location_id', 'conditional_basis_retrieval_event_id', 'conditional_validator_kind_code', 'conditional_validator_value', 'artifact_id', 'outcome_code', 'request_method_code', 'request_profile_code', 'request_accept', 'request_accept_language', 'request_accept_encoding', 'started_at', 'completed_at', 'captured_at', 'http_status_code', 'response_etag', 'response_last_modified', 'response_content_type', 'response_content_length', 'response_content_encoding', 'response_vary', 'detected_media_type', 'observed_sha256', 'observed_byte_length', 'collector_principal_id', 'collector_software_code', 'collector_version', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_retrieval_redirects: ['id', 'redirect_code', 'retrieval_event_id', 'hop_ordinal', 'from_location_id', 'to_location_id', 'http_status_code', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_artifact_custody_events: ['id', 'custody_event_code', 'artifact_id', 'copy_code', 'event_kind_code', 'predecessor_custody_event_id', 'custody_class_code', 'backend_code', 'backend_reference', 'eligibility_declared_by_principal_id', 'eligibility_declared_at', 'redistribution_eligible_declared', 'no_sensitive_data_declared', 'size_eligible_declared', 'permanent_history_acknowledged', 'reason', 'occurred_at', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_processing_runs: ['id', 'processing_run_code', 'run_ordinal', 'input_artifact_id', 'method_code', 'processor_principal_id', 'processor_software_code', 'processor_version', 'configuration_sha256', 'started_at', 'completed_at', 'outcome_code', 'failure_code', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_processing_outputs: ['id', 'processing_output_code', 'processing_run_id', 'artifact_id', 'output_ordinal', 'output_kind_code', 'detected_media_type', 'produced_at', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_unverified_candidate_occurrences: ['id', 'candidate_record_code', 'candidate_chain_code', 'record_kind_code', 'corrects_candidate_occurrence_id', 'processing_run_id', 'processing_output_id', 'claim_type_code', 'observed_value', 'normalized_value', 'confidence_basis_points', 'locator_kind_code', 'locator_value', 'span_start', 'span_end', 'reason', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
}

const integerColumns = {
  atlas_evidence_bundle_receipts: ['id', 'bundle_sequence', 'submitted_by_principal_id', 'imported_by_principal_id', 'recorded_by_principal_id'],
  atlas_retrieval_locations: ['id', 'evidence_bundle_receipt_id', 'recorded_by_principal_id'],
  atlas_artifacts: ['id', 'byte_length', 'evidence_bundle_receipt_id', 'recorded_by_principal_id'],
  atlas_retrieval_events: ['id', 'requested_location_id', 'last_attempted_location_id', 'resolved_location_id', 'conditional_basis_retrieval_event_id', 'artifact_id', 'http_status_code', 'response_content_length', 'observed_byte_length', 'collector_principal_id', 'evidence_bundle_receipt_id', 'recorded_by_principal_id'],
  atlas_retrieval_redirects: ['id', 'retrieval_event_id', 'hop_ordinal', 'from_location_id', 'to_location_id', 'http_status_code', 'evidence_bundle_receipt_id', 'recorded_by_principal_id'],
  atlas_artifact_custody_events: ['id', 'artifact_id', 'predecessor_custody_event_id', 'eligibility_declared_by_principal_id', 'redistribution_eligible_declared', 'no_sensitive_data_declared', 'size_eligible_declared', 'permanent_history_acknowledged', 'evidence_bundle_receipt_id', 'recorded_by_principal_id'],
  atlas_processing_runs: ['id', 'run_ordinal', 'input_artifact_id', 'processor_principal_id', 'evidence_bundle_receipt_id', 'recorded_by_principal_id'],
  atlas_processing_outputs: ['id', 'processing_run_id', 'artifact_id', 'output_ordinal', 'evidence_bundle_receipt_id', 'recorded_by_principal_id'],
  atlas_unverified_candidate_occurrences: ['id', 'corrects_candidate_occurrence_id', 'processing_run_id', 'processing_output_id', 'confidence_basis_points', 'span_start', 'span_end', 'evidence_bundle_receipt_id', 'recorded_by_principal_id'],
}

const nullableColumns = {
  atlas_evidence_bundle_receipts: [], atlas_retrieval_locations: [], atlas_artifacts: [], atlas_retrieval_redirects: [],
  atlas_retrieval_events: ['resolved_location_id', 'conditional_basis_retrieval_event_id', 'conditional_validator_kind_code', 'conditional_validator_value', 'artifact_id', 'request_accept', 'request_accept_language', 'request_accept_encoding', 'captured_at', 'http_status_code', 'response_etag', 'response_last_modified', 'response_content_type', 'response_content_length', 'response_content_encoding', 'response_vary', 'detected_media_type', 'observed_sha256', 'observed_byte_length'],
  atlas_artifact_custody_events: ['predecessor_custody_event_id', 'backend_code', 'backend_reference', 'eligibility_declared_by_principal_id', 'eligibility_declared_at', 'redistribution_eligible_declared', 'no_sensitive_data_declared', 'size_eligible_declared', 'permanent_history_acknowledged'],
  atlas_processing_runs: ['failure_code'],
  atlas_processing_outputs: [],
  atlas_unverified_candidate_occurrences: ['corrects_candidate_occurrence_id', 'observed_value', 'normalized_value', 'confidence_basis_points', 'span_start', 'span_end'],
}

const expectedForeignKeyGroups = {
  atlas_evidence_bundle_receipts: [[['submitted_by_principal_id', 'atlas_principals', 'id']], [['imported_by_principal_id', 'atlas_principals', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
  atlas_retrieval_locations: [[['evidence_bundle_receipt_id', 'atlas_evidence_bundle_receipts', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
  atlas_artifacts: [[['evidence_bundle_receipt_id', 'atlas_evidence_bundle_receipts', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
  atlas_retrieval_events: [[['requested_location_id', 'atlas_retrieval_locations', 'id']], [['last_attempted_location_id', 'atlas_retrieval_locations', 'id']], [['resolved_location_id', 'atlas_retrieval_locations', 'id']], [['conditional_basis_retrieval_event_id', 'atlas_retrieval_events', 'id']], [['artifact_id', 'atlas_artifacts', 'id']], [['collector_principal_id', 'atlas_principals', 'id']], [['evidence_bundle_receipt_id', 'atlas_evidence_bundle_receipts', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
  atlas_retrieval_redirects: [[['retrieval_event_id', 'atlas_retrieval_events', 'id']], [['from_location_id', 'atlas_retrieval_locations', 'id']], [['to_location_id', 'atlas_retrieval_locations', 'id']], [['evidence_bundle_receipt_id', 'atlas_evidence_bundle_receipts', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
  atlas_artifact_custody_events: [[['artifact_id', 'atlas_artifacts', 'id']], [['predecessor_custody_event_id', 'atlas_artifact_custody_events', 'id']], [['eligibility_declared_by_principal_id', 'atlas_principals', 'id']], [['evidence_bundle_receipt_id', 'atlas_evidence_bundle_receipts', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
  atlas_processing_runs: [[['input_artifact_id', 'atlas_artifacts', 'id']], [['processor_principal_id', 'atlas_principals', 'id']], [['evidence_bundle_receipt_id', 'atlas_evidence_bundle_receipts', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
  atlas_processing_outputs: [[['processing_run_id', 'atlas_processing_runs', 'id']], [['artifact_id', 'atlas_artifacts', 'id']], [['evidence_bundle_receipt_id', 'atlas_evidence_bundle_receipts', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
  atlas_unverified_candidate_occurrences: [[['corrects_candidate_occurrence_id', 'atlas_unverified_candidate_occurrences', 'id']], [['processing_run_id', 'atlas_processing_runs', 'id']], [['processing_output_id', 'atlas_processing_outputs', 'id'], ['processing_run_id', 'atlas_processing_outputs', 'processing_run_id']], [['evidence_bundle_receipt_id', 'atlas_evidence_bundle_receipts', 'id']], [['recorded_by_principal_id', 'atlas_principals', 'id']]],
}

const expectedIndexSpecs = {
  atlas_evidence_bundle_receipts_code_uidx: [1, 0, ['bundle_code'], null],
  atlas_evidence_bundle_receipts_sequence_uidx: [1, 0, ['bundle_sequence'], null],
  atlas_evidence_bundle_receipts_digest_uidx: [1, 0, ['bundle_digest_sha256'], null],
  atlas_evidence_bundle_receipts_path_uidx: [1, 0, ['manifest_path'], null],
  atlas_retrieval_locations_code_uidx: [1, 0, ['location_code'], null],
  atlas_retrieval_locations_url_uidx: [1, 0, ['location_url'], null],
  atlas_artifacts_code_uidx: [1, 0, ['artifact_code'], null],
  atlas_artifacts_identity_uidx: [1, 0, ['byte_layer_code', 'hash_algorithm_code', 'sha256', 'byte_length'], null],
  atlas_retrieval_events_code_uidx: [1, 0, ['retrieval_event_code'], null],
  atlas_retrieval_events_location_time_idx: [0, 0, ['requested_location_id', 'last_attempted_location_id', 'resolved_location_id', 'completed_at', 'id'], null],
  atlas_retrieval_redirects_code_uidx: [1, 0, ['redirect_code'], null],
  atlas_retrieval_redirects_event_ordinal_uidx: [1, 0, ['retrieval_event_id', 'hop_ordinal'], null],
  atlas_artifact_custody_events_code_uidx: [1, 0, ['custody_event_code'], null],
  atlas_artifact_custody_events_one_root_uidx: [1, 1, ['artifact_id', 'copy_code'], 'predecessor_custody_event_id IS NULL'],
  atlas_artifact_custody_events_predecessor_uidx: [1, 1, ['predecessor_custody_event_id'], 'predecessor_custody_event_id IS NOT NULL'],
  atlas_artifact_custody_events_leaf_idx: [0, 0, ['artifact_id', 'copy_code', 'occurred_at', 'evidence_bundle_receipt_id', 'id'], null],
  atlas_processing_runs_code_uidx: [1, 0, ['processing_run_code'], null],
  atlas_processing_runs_receipt_ordinal_uidx: [1, 0, ['evidence_bundle_receipt_id', 'run_ordinal'], null],
  atlas_processing_runs_input_time_idx: [0, 0, ['input_artifact_id', 'evidence_bundle_receipt_id', 'run_ordinal', 'started_at', 'id'], null],
  atlas_processing_outputs_code_uidx: [1, 0, ['processing_output_code'], null],
  atlas_processing_outputs_run_ordinal_uidx: [1, 0, ['processing_run_id', 'output_ordinal'], null],
  atlas_processing_outputs_id_run_uidx: [1, 0, ['id', 'processing_run_id'], null],
  atlas_candidate_occurrences_record_code_uidx: [1, 0, ['candidate_record_code'], null],
  atlas_candidate_occurrences_one_root_uidx: [1, 1, ['candidate_chain_code'], 'corrects_candidate_occurrence_id IS NULL'],
  atlas_candidate_occurrences_predecessor_uidx: [1, 1, ['corrects_candidate_occurrence_id'], 'corrects_candidate_occurrence_id IS NOT NULL'],
  atlas_candidate_occurrences_leaf_idx: [0, 0, ['candidate_chain_code', 'recorded_at', 'id'], null],
  atlas_candidate_occurrences_run_output_idx: [0, 0, ['processing_run_id', 'processing_output_id', 'id'], null],
}

function assertPhysicalSchema(database) {
  const tableList = new Map(database.prepare('PRAGMA table_list').all().map((row) => [row.name, row]))
  for (const table of tables) {
    assert.equal(tableList.get(table)?.strict, 1, `${table} is not STRICT`)
    const integers = new Set(integerColumns[table])
    const nullable = new Set(nullableColumns[table])
    const expectedColumns = persistedProjectionColumns[table].map((name, cid) => ({
      cid, name, type: integers.has(name) ? 'INTEGER' : 'TEXT', notnull: name === 'id' || nullable.has(name) ? 0 : 1,
      dflt_value: null, pk: name === 'id' ? 1 : 0, hidden: 0,
    }))
    assert.deepEqual(database.prepare(`PRAGMA table_xinfo(${table})`).all().map((row) => ({ ...row })), expectedColumns, `${table} physical columns drift`)
    const actualGroups = new Map()
    for (const row of database.prepare(`PRAGMA foreign_key_list(${table})`).all()) {
      assert.equal(row.on_update, 'RESTRICT')
      assert.equal(row.on_delete, 'RESTRICT')
      assert.equal(row.match, 'NONE')
      if (!actualGroups.has(row.id)) actualGroups.set(row.id, [])
      actualGroups.get(row.id).push([row.from, row.table, row.to])
    }
    const normalizeGroups = (groups) => groups.map((group) => JSON.stringify(group)).toSorted()
    assert.deepEqual(normalizeGroups(Array.from(actualGroups.values())), normalizeGroups(expectedForeignKeyGroups[table]), `${table} foreign keys drift`)
    assert.ok(database.prepare("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?").get(table).sql.trimEnd().endsWith('STRICT'), `${table} CREATE SQL is not STRICT`)
  }
  const allIndexes = new Map()
  for (const table of tables) {
    for (const row of database.prepare(`PRAGMA index_list(${table})`).all()) allIndexes.set(row.name, { ...row, table })
  }
  assert.deepEqual(Array.from(allIndexes.keys()).toSorted(), Object.keys(expectedIndexSpecs).toSorted(), 'physical index inventory drift')
  for (const [name, [uniqueValue, partial, columns, predicate]] of Object.entries(expectedIndexSpecs)) {
    const index = allIndexes.get(name)
    assert.deepEqual({ unique: index.unique, origin: index.origin, partial: index.partial }, { unique: uniqueValue, origin: 'c', partial }, `${name} flags drift`)
    const actualColumns = database.prepare(`PRAGMA index_xinfo(${name})`).all().filter((row) => row.key === 1).map((row) => row.name)
    assert.deepEqual(actualColumns, columns, `${name} indexed columns drift`)
    const sql = database.prepare("SELECT sql FROM sqlite_schema WHERE type='index' AND name=?").get(name).sql
    const actualPredicate = /\bWHERE\s+(.+)$/is.exec(sql)?.[1].trim() ?? null
    assert.equal(actualPredicate, predicate, `${name} partial predicate drift`)
  }
  const expectedDefinitionNames = [
    ...tables.map((name) => `table:${name}`),
    ...triggers.map((name) => `trigger:${name}`),
  ].toSorted()
  assert.deepEqual(Object.keys(expectedSchemaDefinitionHashes).toSorted(), expectedDefinitionNames, 'pinned schema-definition inventory is incomplete')
  const definitions = database.prepare(`SELECT type,name,tbl_name,sql FROM sqlite_schema
    WHERE (type='table' AND name IN (${tables.map(() => '?').join(',')}))
       OR (type='trigger' AND name IN (${triggers.map(() => '?').join(',')}))
    ORDER BY type,name`).all(...tables, ...triggers).map((row) => ({ ...row }))
  assert.deepEqual(definitions.map((row) => `${row.type}:${row.name}`).toSorted(), expectedDefinitionNames, 'table/trigger definition inventory drift')
  for (const definition of definitions) {
    assert.equal(
      schemaDefinitionDigest(definition),
      expectedSchemaDefinitionHashes[`${definition.type}:${definition.name}`],
      `${definition.type} ${definition.name} normalized definition drift`,
    )
  }
}

function replaceExactlyOnce(source, needle, replacement, label) {
  const parts = source.split(needle)
  assert.equal(parts.length, 2, `${label} mutation target must occur exactly once`)
  return `${parts[0]}${replacement}${parts[1]}`
}

function assertSchemaDefinitionMutationDetected(proposal, label, needle, replacement, expectedPattern) {
  const mutant = replaceExactlyOnce(proposal, needle, replacement, label)
  const root = temporaryDirectory(`jedi-2a-schema-mutant-${label}-`)
  const databasePath = path.join(root, 'mutant.sqlite')
  applyMigrations({ databasePath, migrationsDirectory: migrationDirectory(mutant) })
  const database = openDatabase(databasePath)
  try {
    assert.throws(() => assertPhysicalSchema(database), expectedPattern, `${label} schema mutation escaped physical validation`)
  } finally {
    database.close()
  }
  return mutant
}

function assertProjectionComplete(database, manifest) {
  for (const [table, columns] of Object.entries(persistedProjectionColumns)) {
    assert.deepEqual(database.prepare(`PRAGMA table_xinfo(${table})`).all().map((row) => row.name), columns, `${table} projection column coverage drift`)
  }
  const receipt = database.prepare('SELECT * FROM atlas_evidence_bundle_receipts WHERE bundle_code=?').get(manifest.bundle_id)
  assert.ok(receipt, 'accepted bundle receipt is missing')
  const codeMaps = {
    principal: new Map(database.prepare('SELECT id,principal_code FROM atlas_principals').all().map((row) => [row.id, row.principal_code])),
    receipt: new Map(database.prepare('SELECT id,bundle_code FROM atlas_evidence_bundle_receipts').all().map((row) => [row.id, row.bundle_code])),
    location: new Map(database.prepare('SELECT id,location_code FROM atlas_retrieval_locations').all().map((row) => [row.id, row.location_code])),
    artifact: new Map(database.prepare('SELECT id,artifact_code FROM atlas_artifacts').all().map((row) => [row.id, row.artifact_code])),
    retrieval: new Map(database.prepare('SELECT id,retrieval_event_code FROM atlas_retrieval_events').all().map((row) => [row.id, row.retrieval_event_code])),
    custody: new Map(database.prepare('SELECT id,custody_event_code FROM atlas_artifact_custody_events').all().map((row) => [row.id, row.custody_event_code])),
    run: new Map(database.prepare('SELECT id,processing_run_code FROM atlas_processing_runs').all().map((row) => [row.id, row.processing_run_code])),
    output: new Map(database.prepare('SELECT id,processing_output_code FROM atlas_processing_outputs').all().map((row) => [row.id, row.processing_output_code])),
    candidate: new Map(database.prepare('SELECT id,candidate_record_code FROM atlas_unverified_candidate_occurrences').all().map((row) => [row.id, row.candidate_record_code])),
  }
  const identityKind = {
    atlas_evidence_bundle_receipts: ['receipt', 'bundle_code'],
    atlas_retrieval_locations: ['location', 'location_code'],
    atlas_artifacts: ['artifact', 'artifact_code'],
    atlas_retrieval_events: ['retrieval', 'retrieval_event_code'],
    atlas_retrieval_redirects: [null, 'redirect_code'],
    atlas_artifact_custody_events: ['custody', 'custody_event_code'],
    atlas_processing_runs: ['run', 'processing_run_code'],
    atlas_processing_outputs: ['output', 'processing_output_code'],
    atlas_unverified_candidate_occurrences: ['candidate', 'candidate_record_code'],
  }
  const foreignKinds = {
    evidence_bundle_receipt_id: 'receipt', submitted_by_principal_id: 'principal', imported_by_principal_id: 'principal', recorded_by_principal_id: 'principal', collector_principal_id: 'principal', processor_principal_id: 'principal', eligibility_declared_by_principal_id: 'principal',
    requested_location_id: 'location', last_attempted_location_id: 'location', resolved_location_id: 'location', from_location_id: 'location', to_location_id: 'location',
    artifact_id: 'artifact', input_artifact_id: 'artifact', conditional_basis_retrieval_event_id: 'retrieval', retrieval_event_id: 'retrieval', predecessor_custody_event_id: 'custody', processing_run_id: 'run', processing_output_id: 'output', corrects_candidate_occurrence_id: 'candidate',
  }
  const normalize = (table, row) => {
    assert.ok(row.id > 0, `${table} has nonpositive local ID`)
    const result = {}
    for (const column of persistedProjectionColumns[table]) {
      if (column === 'id') {
        const [kind, codeColumn] = identityKind[table]
        result.id = kind ? codeMaps[kind].get(row.id) : row[codeColumn]
      } else if (foreignKinds[column]) result[column] = row[column] === null ? null : codeMaps[foreignKinds[column]].get(row[column])
      else result[column] = row[column]
    }
    return result
  }
  const expected = {
    atlas_evidence_bundle_receipts: [{
      id: manifest.bundle_id, bundle_sequence: manifest.bundle_sequence, bundle_code: manifest.bundle_id, format_version_code: manifest.format_version,
      bundle_digest_sha256: manifest.bundle_digest_sha256, manifest_path: manifest.manifest_path, bundle_created_at: manifest.bundle_created_at,
      submitted_by_principal_id: manifest.submitter_principal_code, imported_by_principal_id: manifest.expected_importer_principal_code,
      importer_software_code: manifest.expected_importer_software_code, importer_version: manifest.expected_importer_version,
      recorded_by_principal_id: manifest.submitter_principal_code, recorded_at: manifest.bundle_created_at,
    }],
    atlas_retrieval_locations: manifest.retrieval_locations.map((row) => ({
      id: row.record_code, location_code: row.record_code, location_url: row.url, evidence_bundle_receipt_id: manifest.bundle_id,
      recorded_by_principal_id: row.recorded_by_principal_code, recorded_at: row.recorded_at,
    })),
    atlas_artifacts: manifest.artifacts.map((row) => ({
      id: row.record_code, artifact_code: row.record_code, byte_layer_code: row.byte_layer_code, hash_algorithm_code: row.hash_algorithm_code,
      sha256: row.sha256, byte_length: row.byte_length, evidence_bundle_receipt_id: manifest.bundle_id,
      recorded_by_principal_id: row.recorded_by_principal_code, recorded_at: row.recorded_at,
    })),
    atlas_retrieval_events: manifest.retrieval_events.map((row) => ({
      id: row.record_code, retrieval_event_code: row.record_code, requested_location_id: row.requested_location_code,
      last_attempted_location_id: row.last_attempted_location_code, resolved_location_id: row.resolved_location_code,
      conditional_basis_retrieval_event_id: row.conditional_basis_retrieval_event_code,
      conditional_validator_kind_code: row.conditional_validator_kind_code, conditional_validator_value: row.conditional_validator_value,
      artifact_id: row.artifact_code, outcome_code: row.outcome_code, request_method_code: row.request_method_code,
      request_profile_code: row.request_profile_code, request_accept: row.request_headers.accept,
      request_accept_language: row.request_headers.accept_language, request_accept_encoding: row.request_headers.accept_encoding,
      started_at: row.started_at, completed_at: row.completed_at, captured_at: row.captured_at, http_status_code: row.http_status_code,
      response_etag: row.response_metadata.etag ?? null, response_last_modified: row.response_metadata.last_modified ?? null,
      response_content_type: row.response_metadata.content_type ?? null, response_content_length: row.response_metadata.content_length ?? null,
      response_content_encoding: row.response_metadata.content_encoding ?? null, response_vary: row.response_metadata.vary ?? null,
      detected_media_type: row.detected_media_type, observed_sha256: row.observed_sha256, observed_byte_length: row.observed_byte_length,
      collector_principal_id: row.collector_principal_code, collector_software_code: row.collector_software_code, collector_version: row.collector_version,
      evidence_bundle_receipt_id: manifest.bundle_id, recorded_by_principal_id: row.recorded_by_principal_code, recorded_at: row.recorded_at,
    })),
    atlas_retrieval_redirects: manifest.retrieval_events.flatMap((event) => event.redirects.map((row) => ({
      id: row.record_code, redirect_code: row.record_code, retrieval_event_id: event.record_code, hop_ordinal: row.ordinal,
      from_location_id: row.from_location_code, to_location_id: row.to_location_code, http_status_code: row.http_status_code,
      evidence_bundle_receipt_id: manifest.bundle_id, recorded_by_principal_id: event.recorded_by_principal_code, recorded_at: event.recorded_at,
    }))),
    atlas_artifact_custody_events: manifest.custody_events.map((row) => {
      const declaration = row.repository_eligibility_declaration
      return {
        id: row.record_code, custody_event_code: row.record_code, artifact_id: row.artifact_code, copy_code: row.copy_code,
        event_kind_code: row.event_kind_code, predecessor_custody_event_id: row.predecessor_custody_event_code,
        custody_class_code: row.custody_class_code, backend_code: row.backend_code, backend_reference: row.backend_reference,
        eligibility_declared_by_principal_id: declaration?.declared_by_principal_code ?? null, eligibility_declared_at: declaration?.declared_at ?? null,
        redistribution_eligible_declared: declaration?.redistribution_eligible_declared ? 1 : null,
        no_sensitive_data_declared: declaration?.no_sensitive_data_declared ? 1 : null,
        size_eligible_declared: declaration?.size_eligible_declared ? 1 : null,
        permanent_history_acknowledged: declaration?.permanent_history_acknowledged ? 1 : null,
        reason: row.reason, occurred_at: row.occurred_at, evidence_bundle_receipt_id: manifest.bundle_id,
        recorded_by_principal_id: row.recorded_by_principal_code, recorded_at: row.recorded_at,
      }
    }),
    atlas_processing_runs: manifest.processing_runs.map((row) => ({
      id: row.record_code, processing_run_code: row.record_code, run_ordinal: row.ordinal, input_artifact_id: row.input_artifact_code,
      method_code: row.method_code, processor_principal_id: row.processor_principal_code, processor_software_code: row.processor_software_code,
      processor_version: row.processor_version, configuration_sha256: row.configuration_sha256, started_at: row.started_at,
      completed_at: row.completed_at, outcome_code: row.outcome_code, failure_code: row.failure_code,
      evidence_bundle_receipt_id: manifest.bundle_id, recorded_by_principal_id: row.recorded_by_principal_code, recorded_at: row.recorded_at,
    })),
    atlas_processing_outputs: manifest.processing_runs.flatMap((run) => run.outputs.map((row) => ({
      id: row.record_code, processing_output_code: row.record_code, processing_run_id: run.record_code, artifact_id: row.artifact_code,
      output_ordinal: row.ordinal, output_kind_code: row.output_kind_code, detected_media_type: row.detected_media_type, produced_at: row.produced_at,
      evidence_bundle_receipt_id: manifest.bundle_id, recorded_by_principal_id: run.recorded_by_principal_code, recorded_at: run.recorded_at,
    }))),
    atlas_unverified_candidate_occurrences: manifest.candidate_occurrences.map((row) => ({
      id: row.record_code, candidate_record_code: row.record_code, candidate_chain_code: row.chain_code, record_kind_code: row.record_kind_code,
      corrects_candidate_occurrence_id: row.corrects_candidate_record_code, processing_run_id: row.processing_run_code,
      processing_output_id: row.processing_output_code, claim_type_code: row.claim_type_code, observed_value: row.observed_value,
      normalized_value: row.normalized_value, confidence_basis_points: row.confidence_basis_points, locator_kind_code: row.locator_kind_code,
      locator_value: row.locator_value, span_start: row.span_start, span_end: row.span_end, reason: row.reason,
      evidence_bundle_receipt_id: manifest.bundle_id, recorded_by_principal_id: row.recorded_by_principal_code, recorded_at: row.recorded_at,
    })),
  }
  for (const table of Object.keys(persistedProjectionColumns)) {
    const rows = database.prepare(`SELECT * FROM ${table} WHERE ${table === 'atlas_evidence_bundle_receipts' ? 'id' : 'evidence_bundle_receipt_id'}=?`).all(receipt.id)
    const actualRows = rows.map((row) => normalize(table, row)).toSorted((left, right) => String(left.id).localeCompare(String(right.id)))
    const expectedRows = expected[table].toSorted((left, right) => String(left.id).localeCompare(String(right.id)))
    assert.deepEqual(actualRows, expectedRows, `${table} canonical manifest projection mismatch`)
  }
  if (manifest.principal_bootstrap) {
    const expected = [manifest.principal_bootstrap.trust_root, ...manifest.principal_bootstrap.principals]
    for (const principal of expected) {
      const row = database.prepare(`SELECT p.id,p.principal_kind_code,p.created_at,c.principal_code AS created_by_principal_code
        FROM atlas_principals p JOIN atlas_principals c ON c.id=p.created_by_principal_id
        WHERE p.principal_code=?`).get(principal.principal_code)
      assert.deepEqual({ ...row }, {
        id: principal.id,
        principal_kind_code: principal.principal_kind_code,
        created_at: principal.created_at,
        created_by_principal_code: principal.created_by_principal_code,
      })
    }
  }
}

function simulateImport({
  database,
  reviewedManifestRoot,
  manifestRelativePath,
  schema,
  adapter,
  authenticatedInvokerCode,
  trustedImporterCode,
  trustedImporterSoftwareCode,
  trustedImporterVersion,
  injectFailure = false,
  beforeInjectedFailure = null,
  transactionObserver = null,
}) {
  assert.ok(safePath(manifestRelativePath), 'unsafe reviewed manifest path')
  const manifestBytes = confinedRead(reviewedManifestRoot, manifestRelativePath)
  const manifest = parseManifestBytes(manifestBytes, schema)
  assert.equal(manifest.manifest_path, manifestRelativePath, 'opened manifest path does not match manifest declaration')
  assert.equal(authenticatedInvokerCode, manifest.submitter_principal_code, 'trusted runtime submitter mismatch')
  assert.equal(trustedImporterCode, manifest.expected_importer_principal_code, 'trusted importer principal mismatch')
  assert.equal(trustedImporterSoftwareCode, manifest.expected_importer_software_code, 'trusted importer software mismatch')
  assert.equal(trustedImporterVersion, manifest.expected_importer_version, 'trusted importer version mismatch')
  assert.equal(manifest.bundle_digest_sha256, bundleDigest(manifest), 'bundle digest mismatch')
  const context = databaseContext(database)
  const existing = context.receipts.get(manifest.bundle_id)
  if (existing) {
    assert.equal(existing.bundle_digest_sha256, manifest.bundle_digest_sha256, 'bundle identity drift')
    for (const dependency of manifest.required_bundles) {
      const receipt = context.receipts.get(dependency.bundle_id)
      assert.equal(receipt?.bundle_digest_sha256, dependency.bundle_digest_sha256, `missing or changed no-op dependency: ${dependency.bundle_id}`)
    }
    assertProjectionComplete(database, manifest)
    verifyEvidenceBytes(manifest, context, adapter, { noOp: true })
    return 'no_op'
  }
  validateManifestSemantics(manifest, context)
  verifyEvidenceBytes(manifest, context, adapter)

  if (transactionObserver) transactionObserver.beginCount += 1
  database.exec('BEGIN IMMEDIATE')
  try {
    if (context.principals.size === 0) {
      const bootstrap = manifest.principal_bootstrap
      database.prepare('INSERT INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(1,?,?,1,?)')
        .run('system.bootstrap', 'service', bootstrap.trust_root.created_at)
      const principalIds = new Map([['system.bootstrap', 1]])
      for (const principal of bootstrap.principals) {
        database.prepare('INSERT INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(?,?,?,?,?)')
          .run(principal.id, principal.principal_code, principal.principal_kind_code, principalIds.get(principal.created_by_principal_code), principal.created_at)
        principalIds.set(principal.principal_code, principal.id)
      }
    }
    const principalIds = new Map(database.prepare('SELECT principal_code,id FROM atlas_principals').all().map((row) => [row.principal_code, row.id]))
    const receiptId = database.prepare(`INSERT INTO atlas_evidence_bundle_receipts(
      bundle_sequence,bundle_code,format_version_code,bundle_digest_sha256,manifest_path,bundle_created_at,
      submitted_by_principal_id,imported_by_principal_id,importer_software_code,importer_version,
      recorded_by_principal_id,recorded_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`).get(
      manifest.bundle_sequence,
      manifest.bundle_id,
      manifest.format_version,
      manifest.bundle_digest_sha256,
      manifest.manifest_path,
      manifest.bundle_created_at,
      principalIds.get(manifest.submitter_principal_code),
      principalIds.get(manifest.expected_importer_principal_code),
      manifest.expected_importer_software_code,
      manifest.expected_importer_version,
      principalIds.get(manifest.submitter_principal_code),
      manifest.bundle_created_at,
    ).id
    const refreshed = databaseContext(database)
    const locationIds = new Map(Array.from(refreshed.locations, ([key, row]) => [key, row.id]))
    const artifactIds = new Map(Array.from(refreshed.artifacts, ([key, row]) => [key, row.id]))
    const retrievalEventIds = new Map(Array.from(refreshed.retrievalEvents, ([key, row]) => [key, row.id]))
    const custodyEventIds = new Map(Array.from(refreshed.custodyEvents, ([key, row]) => [key, row.id]))
    const processingRunIds = new Map(Array.from(refreshed.processingRuns, ([key, row]) => [key, row.id]))
    const processingOutputIds = new Map(Array.from(refreshed.processingOutputs, ([key, row]) => [key, row.id]))
    const candidateIds = new Map(Array.from(refreshed.candidates, ([key, row]) => [key, row.id]))
    const submitterId = principalIds.get(manifest.submitter_principal_code)

    for (const location of manifest.retrieval_locations) {
      const id = database.prepare('INSERT INTO atlas_retrieval_locations(location_code,location_url,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?) RETURNING id')
        .get(location.record_code, location.url, receiptId, submitterId, location.recorded_at).id
      locationIds.set(location.record_code, id)
    }
    for (const artifact of manifest.artifacts) {
      const id = database.prepare('INSERT INTO atlas_artifacts(artifact_code,byte_layer_code,hash_algorithm_code,sha256,byte_length,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?,?,?,?) RETURNING id')
        .get(artifact.record_code, artifact.byte_layer_code, artifact.hash_algorithm_code, artifact.sha256, artifact.byte_length, receiptId, submitterId, artifact.recorded_at).id
      artifactIds.set(artifact.record_code, id)
    }
    for (const event of manifest.retrieval_events) {
      const metadata = event.response_metadata
      const id = database.prepare(`INSERT INTO atlas_retrieval_events(
        retrieval_event_code,requested_location_id,last_attempted_location_id,resolved_location_id,conditional_basis_retrieval_event_id,
        conditional_validator_kind_code,conditional_validator_value,artifact_id,outcome_code,
        request_method_code,request_profile_code,request_accept,request_accept_language,request_accept_encoding,
        started_at,completed_at,captured_at,http_status_code,response_etag,response_last_modified,
        response_content_type,response_content_length,response_content_encoding,response_vary,detected_media_type,observed_sha256,observed_byte_length,
        collector_principal_id,collector_software_code,collector_version,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
      )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`).get(
        event.record_code,
        locationIds.get(event.requested_location_code),
        locationIds.get(event.last_attempted_location_code),
        locationIds.get(event.resolved_location_code) ?? null,
        retrievalEventIds.get(event.conditional_basis_retrieval_event_code) ?? null,
        event.conditional_validator_kind_code,
        event.conditional_validator_value,
        artifactIds.get(event.artifact_code) ?? null,
        event.outcome_code,
        event.request_method_code,
        event.request_profile_code,
        event.request_headers.accept,
        event.request_headers.accept_language,
        event.request_headers.accept_encoding,
        event.started_at,
        event.completed_at,
        event.captured_at,
        event.http_status_code,
        metadata.etag ?? null,
        metadata.last_modified ?? null,
        metadata.content_type ?? null,
        metadata.content_length ?? null,
        metadata.content_encoding ?? null,
        metadata.vary ?? null,
        event.detected_media_type,
        event.observed_sha256,
        event.observed_byte_length,
        principalIds.get(event.collector_principal_code),
        event.collector_software_code,
        event.collector_version,
        receiptId,
        submitterId,
        event.recorded_at,
      ).id
      retrievalEventIds.set(event.record_code, id)
      for (const redirect of event.redirects) {
        database.prepare('INSERT INTO atlas_retrieval_redirects(redirect_code,retrieval_event_id,hop_ordinal,from_location_id,to_location_id,http_status_code,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?,?,?,?,?)')
          .run(redirect.record_code, id, redirect.ordinal, locationIds.get(redirect.from_location_code), locationIds.get(redirect.to_location_code), redirect.http_status_code, receiptId, submitterId, event.recorded_at)
      }
    }
    for (const custody of manifest.custody_events) {
      const declaration = custody.repository_eligibility_declaration
      const id = database.prepare(`INSERT INTO atlas_artifact_custody_events(
        custody_event_code,artifact_id,copy_code,event_kind_code,predecessor_custody_event_id,custody_class_code,
        backend_code,backend_reference,eligibility_declared_by_principal_id,eligibility_declared_at,
        redistribution_eligible_declared,no_sensitive_data_declared,size_eligible_declared,permanent_history_acknowledged,
        reason,occurred_at,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
      )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`).get(
        custody.record_code,
        artifactIds.get(custody.artifact_code),
        custody.copy_code,
        custody.event_kind_code,
        custodyEventIds.get(custody.predecessor_custody_event_code) ?? null,
        custody.custody_class_code,
        custody.backend_code,
        custody.backend_reference,
        declaration ? principalIds.get(declaration.declared_by_principal_code) : null,
        declaration?.declared_at ?? null,
        declaration?.redistribution_eligible_declared ? 1 : null,
        declaration?.no_sensitive_data_declared ? 1 : null,
        declaration?.size_eligible_declared ? 1 : null,
        declaration?.permanent_history_acknowledged ? 1 : null,
        custody.reason,
        custody.occurred_at,
        receiptId,
        submitterId,
        custody.recorded_at,
      ).id
      custodyEventIds.set(custody.record_code, id)
    }
    for (const run of manifest.processing_runs) {
      const runId = database.prepare(`INSERT INTO atlas_processing_runs(
        processing_run_code,run_ordinal,input_artifact_id,method_code,processor_principal_id,processor_software_code,processor_version,
        configuration_sha256,started_at,completed_at,outcome_code,failure_code,evidence_bundle_receipt_id,
        recorded_by_principal_id,recorded_at
      )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`).get(
        run.record_code,
        run.ordinal,
        artifactIds.get(run.input_artifact_code),
        run.method_code,
        principalIds.get(run.processor_principal_code),
        run.processor_software_code,
        run.processor_version,
        run.configuration_sha256,
        run.started_at,
        run.completed_at,
        run.outcome_code,
        run.failure_code,
        receiptId,
        submitterId,
        run.recorded_at,
      ).id
      processingRunIds.set(run.record_code, runId)
      for (const output of run.outputs) {
        const outputId = database.prepare('INSERT INTO atlas_processing_outputs(processing_output_code,processing_run_id,artifact_id,output_ordinal,output_kind_code,detected_media_type,produced_at,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id')
          .get(output.record_code, runId, artifactIds.get(output.artifact_code), output.ordinal, output.output_kind_code, output.detected_media_type, output.produced_at, receiptId, submitterId, run.recorded_at).id
        processingOutputIds.set(output.record_code, outputId)
      }
    }
    for (const candidate of manifest.candidate_occurrences) {
      const id = database.prepare(`INSERT INTO atlas_unverified_candidate_occurrences(
        candidate_record_code,candidate_chain_code,record_kind_code,corrects_candidate_occurrence_id,
        processing_run_id,processing_output_id,claim_type_code,observed_value,normalized_value,confidence_basis_points,
        locator_kind_code,locator_value,span_start,span_end,reason,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
      )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`).get(
        candidate.record_code,
        candidate.chain_code,
        candidate.record_kind_code,
        candidateIds.get(candidate.corrects_candidate_record_code) ?? null,
        processingRunIds.get(candidate.processing_run_code),
        processingOutputIds.get(candidate.processing_output_code),
        candidate.claim_type_code,
        candidate.observed_value,
        candidate.normalized_value,
        candidate.confidence_basis_points,
        candidate.locator_kind_code,
        candidate.locator_value,
        candidate.span_start,
        candidate.span_end,
        candidate.reason,
        receiptId,
        submitterId,
        candidate.recorded_at,
      ).id
      candidateIds.set(candidate.record_code, id)
    }
    assertProjectionComplete(database, manifest)
    if (injectFailure) {
      if (beforeInjectedFailure) beforeInjectedFailure(database)
      throw new Error('injected failure after complete evidence projection')
    }
    database.exec('COMMIT')
    return 'imported'
  } catch (error) {
    database.exec('ROLLBACK')
    throw error
  }
}

function assertNoOpMutationRejected({ designMigrations, schema, manifest, environment, label, trigger, mutateSql, runtime }) {
  const root = temporaryDirectory(`jedi-2a-noop-${label}-`)
  const databasePath = path.join(root, 'mutation.sqlite')
  applyMigrations({ databasePath, migrationsDirectory: designMigrations })
  const database = openDatabase(databasePath)
  const input = materializeManifest(environment, manifest)
  assert.equal(simulateImport({ database, ...input, schema, adapter: environment.adapter, ...runtime }), 'imported')
  database.exec(`DROP TRIGGER ${trigger}`)
  database.exec(mutateSql)
  assert.throws(
    () => simulateImport({ database, ...input, schema, adapter: environment.adapter, ...runtime }),
    /canonical manifest projection mismatch/,
    `${label} persisted mutation was accepted as a no-op`,
  )
  database.close()
}

function insertRow(database, verb, table, row) {
  const columns = Object.keys(row)
  const placeholders = columns.map(() => '?').join(',')
  return database.prepare(`${verb} INTO ${table}(${columns.map((column) => `"${column}"`).join(',')}) VALUES(${placeholders})`)
    .run(...columns.map((column) => row[column]))
}

function assertInsertOrReplaceRejected(database, table, label, row, pattern = /collision/) {
  const before = atlasState(database)
  assert.throws(
    () => insertRow(database, 'INSERT OR REPLACE', table, row),
    pattern,
    `${table} accepted INSERT OR REPLACE for ${label}`,
  )
  assert.deepEqual(atlasState(database), before, `${table} changed after rejected INSERT OR REPLACE for ${label}`)
}

function assertInvalidTypedIdRejected(database, table, row) {
  const before = atlasState(database)
  assert.throws(
    () => insertRow(database, 'INSERT', table, { ...row, id: 'not-an-integer' }),
    /datatype mismatch|cannot store TEXT value/i,
    `${table} accepted a non-integer ID`,
  )
  assert.deepEqual(atlasState(database), before, `${table} changed after a non-integer ID`)
  for (const id of [0, -1]) {
    assert.throws(
      () => insertRow(database, 'INSERT', table, { ...row, id }),
      /CHECK constraint failed/i,
      `${table} accepted nonpositive ID ${id}`,
    )
    assert.deepEqual(atlasState(database), before, `${table} changed after nonpositive ID ${id}`)
  }
}

function assertStrictValueRejected(database, table, row, column, value) {
  const before = atlasState(database)
  assert.throws(
    () => insertRow(database, 'INSERT', table, { ...row, [column]: value }),
    /cannot store .* value in .* column|datatype mismatch/i,
    `${table}.${column} accepted an incompatible STRICT value`,
  )
  assert.deepEqual(atlasState(database), before, `${table} changed after incompatible ${column}`)
}

function writeArtifact(root, relativePath, bytes) {
  const target = path.join(root, relativePath)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, bytes)
}

function syntheticEnvironment() {
  const manifestRoot = temporaryDirectory('jedi-2a-manifests-')
  const stagingRoot = temporaryDirectory('jedi-2a-stage-')
  const repositoryRoot = temporaryDirectory('jedi-2a-repository-')
  const restrictedRoot = temporaryDirectory('jedi-2a-restricted-')
  const adapter = {
    stagingRoot,
    backendRoots: new Map([
      ['repository_file', repositoryRoot],
      ['synthetic_store', restrictedRoot],
    ]),
  }
  return { manifestRoot, stagingRoot, repositoryRoot, restrictedRoot, adapter }
}

function finalizeManifest(manifest) {
  for (const run of manifest.processing_runs) run.configuration_sha256 = configurationDigest(run.configuration)
  manifest.bundle_digest_sha256 = bundleDigest(manifest)
  return manifest
}

function encodeManifest(manifest) {
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
}

function materializeManifest(environment, manifest, relativePath = manifest.manifest_path) {
  writeArtifact(environment.manifestRoot, relativePath, encodeManifest(manifest))
  return { reviewedManifestRoot: environment.manifestRoot, manifestRelativePath: relativePath }
}

function invalidReceiptShaInsert(database) {
  const receipt = database.prepare('SELECT * FROM atlas_evidence_bundle_receipts ORDER BY bundle_sequence DESC LIMIT 1').get()
  return database.prepare(`INSERT INTO atlas_evidence_bundle_receipts(
    id,bundle_sequence,bundle_code,format_version_code,bundle_digest_sha256,manifest_path,bundle_created_at,
    submitted_by_principal_id,imported_by_principal_id,importer_software_code,importer_version,recorded_by_principal_id,recorded_at
  )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    database.prepare('SELECT COALESCE(max(id),0)+100 AS id FROM atlas_evidence_bundle_receipts').get().id,
    receipt.bundle_sequence + 1,
    'sql.invalid.receipt.hash',
    '1.0.0',
    'g'.repeat(64),
    'invalid/receipt-hash.json',
    '2026-01-05T00:00:00.000Z',
    receipt.submitted_by_principal_id,
    receipt.imported_by_principal_id,
    receipt.importer_software_code,
    receipt.importer_version,
    receipt.submitted_by_principal_id,
    '2026-01-05T00:00:00.000Z',
  )
}

function invalidEqualTimeCandidateSuccessorInsert(database) {
  const predecessor = database.prepare(`SELECT * FROM atlas_unverified_candidate_occurrences
    WHERE candidate_chain_code='pilot-bundle-001.chain-a'
      AND NOT EXISTS(SELECT 1 FROM atlas_unverified_candidate_occurrences successor WHERE successor.corrects_candidate_occurrence_id=atlas_unverified_candidate_occurrences.id)`).get()
  return database.prepare(`INSERT INTO atlas_unverified_candidate_occurrences(
    id,candidate_record_code,candidate_chain_code,record_kind_code,corrects_candidate_occurrence_id,
    processing_run_id,processing_output_id,claim_type_code,observed_value,normalized_value,confidence_basis_points,
    locator_kind_code,locator_value,span_start,span_end,reason,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
  )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    database.prepare('SELECT COALESCE(max(id),0)+100 AS id FROM atlas_unverified_candidate_occurrences').get().id,
    'sql.invalid.candidate.equal-time',
    predecessor.candidate_chain_code,
    'correction',
    predecessor.id,
    predecessor.processing_run_id,
    predecessor.processing_output_id,
    predecessor.claim_type_code,
    'equal-time correction',
    'equal-time correction',
    5000,
    predecessor.locator_kind_code,
    predecessor.locator_value,
    predecessor.span_start,
    predecessor.span_end,
    'synthetic equal-time successor probe',
    predecessor.evidence_bundle_receipt_id,
    predecessor.recorded_by_principal_id,
    predecessor.recorded_at,
  )
}

function assertConstraintMutationBehavior({ canonicalProposal, mutantProposal, label, manifestInput, schema, adapter, runtime, probe, canonicalPattern }) {
  const canonicalRoot = temporaryDirectory(`jedi-2a-boundary-canonical-${label}-`)
  const mutantRoot = temporaryDirectory(`jedi-2a-boundary-mutant-${label}-`)
  const canonicalPath = path.join(canonicalRoot, 'canonical.sqlite')
  const mutantPath = path.join(mutantRoot, 'mutant.sqlite')
  applyMigrations({ databasePath: canonicalPath, migrationsDirectory: migrationDirectory(canonicalProposal) })
  applyMigrations({ databasePath: mutantPath, migrationsDirectory: migrationDirectory(mutantProposal) })
  const canonicalDatabase = openDatabase(canonicalPath)
  const mutantDatabase = openDatabase(mutantPath)
  try {
    assert.equal(simulateImport({ database: canonicalDatabase, ...manifestInput, schema, adapter, ...runtime }), 'imported')
    assert.equal(simulateImport({ database: mutantDatabase, ...manifestInput, schema, adapter, ...runtime }), 'imported')
    assert.throws(() => probe(canonicalDatabase), canonicalPattern, `${label} canonical boundary did not reject the invalid row`)
    assert.doesNotThrow(() => probe(mutantDatabase), `${label} mutant did not expose the intended boundary weakness`)
  } finally {
    canonicalDatabase.close()
    mutantDatabase.close()
  }
}

function syntheticFirstBundle(environment) {
  const decodedBody = Buffer.from('synthetic hostile-looking source bytes\n')
  const bytes = {
    raw: zlib.gzipSync(decodedBody, { mtime: 0 }),
    decoded: decodedBody,
    text: Buffer.from('synthetic extracted text\n'),
    json: Buffer.from('{"candidate":"synthetic"}\n'),
  }
  const artifact = (name, layer, recordedAt) => {
    const digest = sha256(bytes[name])
    const record = {
      record_code: artifactCode(layer, digest, bytes[name].length),
      byte_layer_code: layer,
      hash_algorithm_code: 'sha256',
      sha256: digest,
      byte_length: bytes[name].length,
      staged_path: `objects/sha256/${digest.slice(0, 2)}/${digest}`,
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: recordedAt,
    }
    writeArtifact(environment.stagingRoot, record.staged_path, bytes[name])
    writeArtifact(environment.repositoryRoot, custodyReference(record), bytes[name])
    writeArtifact(environment.restrictedRoot, custodyReference(record), bytes[name])
    return record
  }
  const raw = artifact('raw', 'retrieved_body', '2026-01-01T00:06:00.000Z')
  const decoded = artifact('decoded', 'derived_output', '2026-01-01T00:15:01.000Z')
  const text = artifact('text', 'derived_output', '2026-01-01T00:20:30.000Z')
  const json = artifact('json', 'derived_output', '2026-01-01T00:20:30.000Z')
  const requestedUrl = 'https://source.invalid/start'
  const resolvedUrl = 'https://source.invalid/final'
  const requestedLocation = locationCode(requestedUrl)
  const resolvedLocation = locationCode(resolvedUrl)
  const prefix = 'pilot-bundle-001.'
  const retrieval = (suffix, overrides = {}) => ({
    record_code: `${prefix}${suffix}`,
    requested_location_code: resolvedLocation,
    last_attempted_location_code: resolvedLocation,
    resolved_location_code: null,
    conditional_basis_retrieval_event_code: null,
    conditional_validator_kind_code: null,
    conditional_validator_value: null,
    artifact_code: null,
    artifact_staged_path: null,
    outcome_code: 'network_failed',
    request_method_code: 'GET',
    request_profile_code: 'http_get_representation_v1',
    request_headers: { accept: '*/*', accept_language: null, accept_encoding: 'gzip, br' },
    started_at: '2026-01-01T00:10:00.000Z',
    completed_at: '2026-01-01T00:10:01.000Z',
    captured_at: null,
    http_status_code: null,
    response_metadata: {},
    observed_sha256: null,
    observed_byte_length: null,
    detected_media_type: null,
    collector_principal_code: 'pilot.collector',
    collector_software_code: 'synthetic-collector',
    collector_version: '1.0.0',
    redirects: [],
    recorded_by_principal_code: 'pilot.researcher',
    recorded_at: '2026-01-01T00:10:02.000Z',
    ...overrides,
  })
  const manifest = {
    format: 'jedi-atlas-evidence-bundle',
    format_version: '1.0.0',
    bundle_id: 'pilot-bundle-001',
    bundle_sequence: 1,
    required_bundles: [],
    bundle_created_at: '2026-01-02T00:00:00.000Z',
    bundle_digest_sha256: '0'.repeat(64),
    manifest_path: 'docs/schema/fixtures/pilot-bundle-001.json',
    submitter_principal_code: 'pilot.researcher',
    expected_importer_principal_code: 'pilot.importer',
    expected_importer_software_code: 'atlas-fixed-importer',
    expected_importer_version: 'design-1.0.0',
    bundle_declarations: {
      contains_credentials: false,
      contains_personal_data: false,
      hostile_input_acknowledged: true,
    },
    principal_bootstrap: {
      trust_root: {
        id: 1,
        principal_code: 'system.bootstrap',
        principal_kind_code: 'service',
        created_by_principal_code: 'system.bootstrap',
        created_at: '2025-12-01T00:00:00.000Z',
      },
      principals: [
        {
          id: 2,
          principal_code: 'pilot.researcher',
          principal_kind_code: 'human',
          created_by_principal_code: 'system.bootstrap',
          created_at: '2025-12-02T00:00:00.000Z',
          runtime_role_code: 'manifest_submitter',
        },
        {
          id: 3,
          principal_code: 'pilot.collector',
          principal_kind_code: 'service',
          created_by_principal_code: 'pilot.researcher',
          created_at: '2025-12-03T00:00:00.000Z',
          runtime_role_code: 'collector',
        },
        {
          id: 4,
          principal_code: 'pilot.importer',
          principal_kind_code: 'service',
          created_by_principal_code: 'pilot.researcher',
          created_at: '2025-12-03T00:00:00.000Z',
          runtime_role_code: 'bundle_importer',
        },
      ],
    },
    retrieval_locations: [
      { record_code: requestedLocation, url: requestedUrl, recorded_by_principal_code: 'pilot.researcher', recorded_at: '2026-01-01T00:00:00.000Z' },
      { record_code: resolvedLocation, url: resolvedUrl, recorded_by_principal_code: 'pilot.researcher', recorded_at: '2026-01-01T00:00:00.000Z' },
    ],
    artifacts: [raw, decoded, text, json],
    retrieval_events: [],
    custody_events: [],
    processing_runs: [],
    candidate_occurrences: [],
  }
  manifest.retrieval_events = [
    retrieval('retrieval-1', {
      requested_location_code: requestedLocation,
      last_attempted_location_code: resolvedLocation,
      resolved_location_code: resolvedLocation,
      artifact_code: raw.record_code,
      artifact_staged_path: custodyReference(raw),
      outcome_code: 'retrieved_retained',
      started_at: '2026-01-01T00:05:00.000Z',
      completed_at: '2026-01-01T00:06:00.000Z',
      captured_at: '2026-01-01T00:05:59.000Z',
      http_status_code: 200,
      response_metadata: { etag: '"synthetic-v1"', last_modified: 'Wed, 21 Oct 2015 07:28:00 GMT', content_type: 'application/octet-stream', content_length: bytes.raw.length, content_encoding: 'gzip', vary: 'accept-encoding' },
      detected_media_type: 'application/octet-stream',
      redirects: [{ record_code: `${prefix}redirect-1`, ordinal: 1, from_location_code: requestedLocation, to_location_code: resolvedLocation, http_status_code: 302 }],
      recorded_at: '2026-01-01T00:06:01.000Z',
    }),
    retrieval('retrieval-2', {
      resolved_location_code: resolvedLocation,
      artifact_code: raw.record_code,
      artifact_staged_path: custodyReference(raw),
      outcome_code: 'retrieved_retained',
      captured_at: '2026-01-01T00:10:00.500Z',
      http_status_code: 200,
      response_metadata: { etag: '"synthetic-v1"', content_encoding: 'gzip', vary: 'accept-encoding' },
      detected_media_type: 'application/octet-stream',
    }),
    retrieval('retrieval-3', {
      resolved_location_code: resolvedLocation,
      outcome_code: 'not_modified',
      conditional_basis_retrieval_event_code: `${prefix}retrieval-2`,
      conditional_validator_kind_code: 'etag',
      conditional_validator_value: '"synthetic-v1"',
      http_status_code: 304,
      response_metadata: { etag: '"synthetic-v1"' },
      started_at: '2026-01-01T00:11:00.000Z',
      completed_at: '2026-01-01T00:11:01.000Z',
      recorded_at: '2026-01-01T00:11:02.000Z',
    }),
    retrieval('retrieval-4'),
    retrieval('retrieval-5', {
      resolved_location_code: resolvedLocation,
      outcome_code: 'http_failed',
      http_status_code: 503,
      started_at: '2026-01-01T00:12:00.000Z',
      completed_at: '2026-01-01T00:12:01.000Z',
      recorded_at: '2026-01-01T00:12:02.000Z',
    }),
    retrieval('retrieval-6', {
      resolved_location_code: resolvedLocation,
      outcome_code: 'observed_not_retained',
      captured_at: '2026-01-01T00:13:00.500Z',
      http_status_code: 200,
      observed_sha256: 'f'.repeat(64),
      observed_byte_length: 99,
      detected_media_type: 'text/plain',
      started_at: '2026-01-01T00:13:00.000Z',
      completed_at: '2026-01-01T00:13:01.000Z',
      recorded_at: '2026-01-01T00:13:02.000Z',
    }),
    retrieval('retrieval-7', {
      requested_location_code: requestedLocation,
      last_attempted_location_code: resolvedLocation,
      outcome_code: 'network_failed',
      started_at: '2026-01-01T00:14:00.000Z',
      completed_at: '2026-01-01T00:14:01.000Z',
      redirects: [{ record_code: `${prefix}redirect-network-failure`, ordinal: 1, from_location_code: requestedLocation, to_location_code: resolvedLocation, http_status_code: 302 }],
      recorded_at: '2026-01-01T00:14:02.000Z',
    }),
    retrieval('retrieval-8', {
      conditional_basis_retrieval_event_code: `${prefix}retrieval-2`,
      conditional_validator_kind_code: 'etag',
      conditional_validator_value: '"synthetic-v1"',
      outcome_code: 'network_failed',
      started_at: '2026-01-01T00:15:10.000Z',
      completed_at: '2026-01-01T00:15:11.000Z',
      recorded_at: '2026-01-01T00:15:12.000Z',
    }),
  ]
  const eligibility = (time) => ({
    declared_by_principal_code: 'pilot.researcher',
    declared_at: time,
    redistribution_eligible_declared: true,
    no_sensitive_data_declared: true,
    size_eligible_declared: true,
    permanent_history_acknowledged: true,
  })
  const custody = (suffix, artifactValue, copyCode, eventKind, predecessor, occurredAt, custodyClass = 'restricted_store', backend = 'synthetic_store', recordedAt = occurredAt) => ({
    record_code: `${prefix}${suffix}`,
    artifact_code: artifactValue.record_code,
    copy_code: copyCode,
    event_kind_code: eventKind,
    predecessor_custody_event_code: predecessor ? `${prefix}${predecessor}` : null,
    custody_class_code: custodyClass,
    backend_code: eventKind === 'tombstoned' ? null : backend,
    backend_reference: eventKind === 'tombstoned' ? null : custodyReference(artifactValue),
    repository_eligibility_declaration: eventKind !== 'tombstoned' && custodyClass === 'repository' ? eligibility(recordedAt) : null,
    reason: `synthetic ${eventKind}`,
    occurred_at: occurredAt,
    recorded_by_principal_code: 'pilot.researcher',
    recorded_at: recordedAt,
  })
  manifest.custody_events = [
    custody('raw-placed', raw, 'copy.raw', 'placed', null, '2026-01-01T00:07:00.000Z', 'repository', 'repository_file'),
    custody('raw-relocated', raw, 'copy.raw', 'relocated', 'raw-placed', '2026-01-01T00:08:00.000Z'),
    custody('raw-restricted', raw, 'copy.raw', 'restricted', 'raw-relocated', '2026-01-01T00:09:00.000Z'),
    custody('raw-restored', raw, 'copy.raw', 'restored', 'raw-restricted', '2026-01-01T00:10:30.000Z'),
    custody('raw-tombstone', raw, 'copy.raw', 'tombstoned', 'raw-restored', '2026-01-01T01:00:00.000Z'),
    custody('decoded-placed', decoded, 'copy.decoded', 'placed', null, '2026-01-01T00:15:02.000Z'),
    custody('text-placed', text, 'copy.text', 'placed', null, '2026-01-01T00:20:32.000Z'),
    custody('text-restricted', text, 'copy.text', 'restricted', 'text-placed', '2026-01-01T00:50:00.000Z'),
    custody('json-placed', json, 'copy.json', 'placed', null, '2026-01-01T00:20:32.000Z'),
  ]
  const output = (suffix, artifactValue, ordinal, kind, producedAt) => ({
    record_code: `${prefix}${suffix}`,
    artifact_code: artifactValue.record_code,
    staged_path: custodyReference(artifactValue),
    ordinal,
    output_kind_code: kind,
    detected_media_type: kind === 'structured_data' ? 'application/json' : 'text/plain',
    produced_at: producedAt,
  })
  manifest.processing_runs = [
    {
      record_code: `${prefix}run-decode`,
      ordinal: 0,
      input_artifact_code: raw.record_code,
      method_code: 'content_decoding',
      processor_principal_code: 'pilot.collector',
      processor_software_code: 'synthetic-content-decoder',
      processor_version: '1.0.0',
      configuration: { content_coding: 'gzip' },
      configuration_sha256: '0'.repeat(64),
      started_at: '2026-01-01T00:14:00.000Z',
      completed_at: '2026-01-01T00:15:00.000Z',
      outcome_code: 'succeeded',
      failure_code: null,
      outputs: [output('output-decoded', decoded, 0, 'decoded_body', '2026-01-01T00:14:30.000Z')],
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: '2026-01-01T00:15:01.000Z',
    },
    {
      record_code: `${prefix}run-success`,
      ordinal: 1,
      input_artifact_code: decoded.record_code,
      method_code: 'parser',
      processor_principal_code: 'pilot.collector',
      processor_software_code: 'synthetic-parser',
      processor_version: '1.0.0',
      configuration: { mode: 'synthetic', page_limit: 2, scripts_enabled: false },
      configuration_sha256: '0'.repeat(64),
      started_at: '2026-01-01T00:20:00.000Z',
      completed_at: '2026-01-01T00:20:30.000Z',
      outcome_code: 'succeeded',
      failure_code: null,
      outputs: [
        output('output-text', text, 0, 'extracted_text', '2026-01-01T00:20:20.000Z'),
        output('output-json', json, 1, 'structured_data', '2026-01-01T00:20:25.000Z'),
      ],
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: '2026-01-01T00:20:31.000Z',
    },
    {
      record_code: `${prefix}run-failure`,
      ordinal: 3,
      input_artifact_code: decoded.record_code,
      method_code: 'ocr',
      processor_principal_code: 'pilot.collector',
      processor_software_code: 'synthetic-ocr',
      processor_version: '1.0.0',
      configuration: { mode: 'synthetic' },
      configuration_sha256: '0'.repeat(64),
      started_at: '2026-01-01T00:23:00.000Z',
      completed_at: '2026-01-01T00:23:30.000Z',
      outcome_code: 'failed',
      failure_code: 'synthetic_parse_failure',
      outputs: [],
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: '2026-01-01T00:23:31.000Z',
    },
  ]
  manifest.processing_runs.splice(2, 0, {
    record_code: `${prefix}run-repeat-same-bundle`,
    ordinal: 2,
    input_artifact_code: decoded.record_code,
    method_code: 'parser',
    processor_principal_code: 'pilot.collector',
    processor_software_code: 'synthetic-parser',
    processor_version: '1.0.0',
    configuration: { mode: 'same-bundle-byte-repeat' },
    configuration_sha256: '0'.repeat(64),
    started_at: '2026-01-01T00:22:00.000Z',
    completed_at: '2026-01-01T00:22:30.000Z',
    outcome_code: 'succeeded',
    failure_code: null,
    outputs: [output('output-json-repeated-same-bundle', json, 0, 'structured_data', '2026-01-01T00:22:20.000Z')],
    recorded_by_principal_code: 'pilot.researcher',
    recorded_at: '2026-01-01T00:22:31.000Z',
  })
  const candidate = (suffix, chain, value, { kind = 'assertion', corrects = null, time = '2026-01-01T00:24:00.000Z', outputCode = `${prefix}output-json`, locatorKind = 'byte_span', spanStart = 0, spanEnd = 10 } = {}) => ({
    record_code: `${prefix}${suffix}`,
    chain_code: `${prefix}${chain}`,
    record_kind_code: kind,
    corrects_candidate_record_code: corrects ? `${prefix}${corrects}` : null,
    processing_run_code: `${prefix}run-success`,
    processing_output_code: outputCode,
    claim_type_code: 'suggested_title',
    observed_value: value,
    normalized_value: value,
    confidence_basis_points: value === null ? null : 5000,
    locator_kind_code: locatorKind,
    locator_value: `${locatorKind} ${spanStart}..${spanEnd}`,
    span_start: spanStart,
    span_end: spanEnd,
    reason: `synthetic ${kind}`,
    recorded_by_principal_code: 'pilot.researcher',
    recorded_at: time,
  })
  manifest.candidate_occurrences = [
    candidate('candidate-a', 'chain-a', 'Alpha'),
    candidate('candidate-b', 'chain-b', 'Beta'),
    candidate('candidate-repeat', 'chain-repeat', 'Alpha'),
    candidate('candidate-span', 'chain-span', 'synthetic', { outputCode: `${prefix}output-text`, locatorKind: 'byte_span', spanStart: 0, spanEnd: 9 }),
    candidate('candidate-text-span', 'chain-text-span', 'synthetic', { outputCode: `${prefix}output-text`, locatorKind: 'text_span', spanStart: 0, spanEnd: 9 }),
    candidate('candidate-a-correction', 'chain-a', 'Alpha corrected', { kind: 'correction', corrects: 'candidate-a', time: '2026-01-01T00:25:00.000Z' }),
    candidate('candidate-a-withdrawal', 'chain-a', null, { kind: 'withdrawal', corrects: 'candidate-a-correction', time: '2026-01-01T00:26:00.000Z' }),
  ]
  return finalizeManifest(manifest)
}

function syntheticSecondBundle(first, environment) {
  const prefix = 'pilot-bundle-002.'
  const firstPrefix = 'pilot-bundle-001.'
  const raw = first.artifacts.find((artifact) => artifact.byte_layer_code === 'retrieved_body')
  const repeatedOutput = first.artifacts.find((artifact) => artifact.record_code === first.processing_runs.find((run) => run.record_code.endsWith('.run-success')).outputs[1].artifact_code)
  const decoded = first.artifacts.find((artifact) => artifact.record_code === first.processing_runs.find((run) => run.record_code.endsWith('.run-decode')).outputs[0].artifact_code)
  const requestedLocation = first.retrieval_locations[1].record_code
  const manifest = {
    format: 'jedi-atlas-evidence-bundle',
    format_version: '1.0.0',
    bundle_id: 'pilot-bundle-002',
    bundle_sequence: 2,
    required_bundles: [{ bundle_id: first.bundle_id, bundle_digest_sha256: first.bundle_digest_sha256 }],
    bundle_created_at: '2026-01-04T00:00:00.000Z',
    bundle_digest_sha256: '0'.repeat(64),
    manifest_path: 'docs/schema/fixtures/pilot-bundle-002.json',
    submitter_principal_code: 'pilot.researcher',
    expected_importer_principal_code: 'pilot.importer',
    expected_importer_software_code: 'atlas-fixed-importer',
    expected_importer_version: 'design-1.0.0',
    bundle_declarations: {
      contains_credentials: false,
      contains_personal_data: false,
      hostile_input_acknowledged: true,
    },
    retrieval_locations: [],
    artifacts: [],
    retrieval_events: [{
      record_code: `${prefix}retrieval-1`,
      requested_location_code: requestedLocation,
      last_attempted_location_code: requestedLocation,
      resolved_location_code: requestedLocation,
      conditional_basis_retrieval_event_code: `${firstPrefix}retrieval-2`,
      conditional_validator_kind_code: 'etag',
      conditional_validator_value: '"synthetic-v1"',
      artifact_code: null,
      artifact_staged_path: null,
      outcome_code: 'not_modified',
      request_method_code: 'GET',
      request_profile_code: 'http_get_representation_v1',
      request_headers: { accept: '*/*', accept_language: null, accept_encoding: 'gzip, br' },
      started_at: '2026-01-03T00:00:00.000Z',
      completed_at: '2026-01-03T00:00:01.000Z',
      captured_at: null,
      http_status_code: 304,
      response_metadata: { etag: '"synthetic-v1"', vary: 'accept-encoding' },
      observed_sha256: null,
      observed_byte_length: null,
      detected_media_type: null,
      collector_principal_code: 'pilot.collector',
      collector_software_code: 'synthetic-collector',
      collector_version: '1.0.0',
      redirects: [],
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: '2026-01-03T00:00:02.000Z',
    }],
    custody_events: [{
      record_code: `${prefix}raw-restored`,
      artifact_code: raw.record_code,
      copy_code: 'copy.raw',
      event_kind_code: 'restored',
      predecessor_custody_event_code: `${firstPrefix}raw-tombstone`,
      custody_class_code: 'repository',
      backend_code: 'repository_file',
      backend_reference: custodyReference(raw),
      repository_eligibility_declaration: {
        declared_by_principal_code: 'pilot.researcher',
        declared_at: '2026-01-03T00:01:00.000Z',
        redistribution_eligible_declared: true,
        no_sensitive_data_declared: true,
        size_eligible_declared: true,
        permanent_history_acknowledged: true,
      },
      reason: 'synthetic reinstatement after tombstone',
      occurred_at: '2026-01-03T00:01:00.000Z',
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: '2026-01-03T00:01:00.000Z',
    }, {
      record_code: `${prefix}decoded-restriction-discovered-late`,
      artifact_code: decoded.record_code,
      copy_code: 'copy.decoded',
      event_kind_code: 'restricted',
      predecessor_custody_event_code: `${firstPrefix}decoded-placed`,
      custody_class_code: 'restricted_store',
      backend_code: 'synthetic_store',
      backend_reference: custodyReference(decoded),
      repository_eligibility_declaration: null,
      reason: 'synthetic late-discovered historical restriction',
      occurred_at: '2026-01-01T00:18:00.000Z',
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: '2026-01-03T00:01:30.000Z',
    }],
    processing_runs: [{
      record_code: `${prefix}run-repeated-output`,
      ordinal: 0,
      input_artifact_code: raw.record_code,
      method_code: 'parser',
      processor_principal_code: 'pilot.collector',
      processor_software_code: 'synthetic-parser',
      processor_version: '1.0.0',
      configuration: { mode: 'synthetic-repeat' },
      configuration_sha256: '0'.repeat(64),
      started_at: '2026-01-03T00:03:00.000Z',
      completed_at: '2026-01-03T00:04:00.000Z',
      outcome_code: 'succeeded',
      failure_code: null,
      outputs: [{
        record_code: `${prefix}output-repeated-json`,
        artifact_code: repeatedOutput.record_code,
        staged_path: custodyReference(repeatedOutput),
        ordinal: 0,
        output_kind_code: 'structured_data',
        detected_media_type: 'application/json',
        produced_at: '2026-01-03T00:03:30.000Z',
      }],
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: '2026-01-03T00:04:01.000Z',
    }],
    candidate_occurrences: [{
      record_code: `${prefix}candidate-a-reinstated`,
      chain_code: `${firstPrefix}chain-a`,
      record_kind_code: 'correction',
      corrects_candidate_record_code: `${firstPrefix}candidate-a-withdrawal`,
      processing_run_code: `${firstPrefix}run-success`,
      processing_output_code: `${firstPrefix}output-json`,
      claim_type_code: 'suggested_title',
      observed_value: 'Alpha reinstated',
      normalized_value: 'Alpha reinstated',
      confidence_basis_points: 5000,
      locator_kind_code: 'byte_span',
      locator_value: 'byte_span 0..10',
      span_start: 0,
      span_end: 10,
      reason: 'synthetic correction after mistaken withdrawal',
      recorded_by_principal_code: 'pilot.researcher',
      recorded_at: '2026-01-03T00:02:00.000Z',
    }],
  }
  return finalizeManifest(manifest)
}

function mutateManifest(source, mutation, { recomputeConfigurations = true } = {}) {
  const manifest = structuredClone(source)
  mutation(manifest)
  if (recomputeConfigurations) {
    for (const run of manifest.processing_runs) run.configuration_sha256 = configurationDigest(run.configuration)
  }
  manifest.bundle_digest_sha256 = bundleDigest(manifest)
  return manifest
}

function runBySuffix(manifest, suffix) {
  return manifest.processing_runs.find((run) => run.record_code.endsWith(suffix))
}

const importerRuntime = {
  authenticatedInvokerCode: 'pilot.researcher',
  trustedImporterCode: 'pilot.importer',
  trustedImporterSoftwareCode: 'atlas-fixed-importer',
  trustedImporterVersion: 'design-1.0.0',
}

try {
  const proposal = fs.readFileSync(proposalPath, 'utf8')
  assert.doesNotMatch(proposal, /^\s*(BEGIN|COMMIT|ROLLBACK)\b/im)
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'))
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema')
  assertIndependentCanonicalGoldenVectors(schema)
  for (const name of migrationNames) {
    assert.equal(sha256(fs.readFileSync(path.join(migrations, name))), migrationHashes[name], `${name} changed`)
  }

  const designMigrations = migrationDirectory()
  const freshRoot = temporaryDirectory('jedi-2a-fresh-')
  const freshDatabasePath = path.join(freshRoot, 'fresh.sqlite')
  assert.deepEqual(
    applyMigrations({ databasePath: freshDatabasePath, migrationsDirectory: designMigrations }).appliedNow,
    [...migrationNames, '005_tranche_2a_design.sql'],
  )
  assert.deepEqual(applyMigrations({ databasePath: freshDatabasePath, migrationsDirectory: designMigrations }).appliedNow, [])
  let freshDatabase = openDatabase(freshDatabasePath)
  assertPhysicalSchema(freshDatabase)
  assert.equal(freshDatabase.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
  assert.deepEqual(freshDatabase.prepare('PRAGMA foreign_key_check').all(), [])
  freshDatabase.close()

  const upgradeRoot = temporaryDirectory('jedi-2a-upgrade-')
  const upgradeDatabasePath = path.join(upgradeRoot, 'upgrade.sqlite')
  applyMigrations({ databasePath: upgradeDatabasePath, migrationsDirectory: migrations })
  const legacyBefore = legacyDigests(upgradeDatabasePath)
  let database = openDatabase(upgradeDatabasePath)
  const inventoryBefore = schemaInventory(database)
  const definitionsBefore = schemaDefinitionSnapshot(database)
  database.close()
  assert.deepEqual(
    applyMigrations({ databasePath: upgradeDatabasePath, migrationsDirectory: designMigrations }).appliedNow,
    ['005_tranche_2a_design.sql'],
  )
  assert.deepEqual(legacyDigests(upgradeDatabasePath), legacyBefore)
  database = openDatabase(upgradeDatabasePath)
  const inventoryAfter = schemaInventory(database)
  const definitionsAfter = schemaDefinitionSnapshot(database)
  assertPriorSchemaPreserved(definitionsBefore, definitionsAfter)
  const delta = inventoryDelta(inventoryBefore, inventoryAfter)
  assert.deepEqual(delta, { table: tables, index: indexes.toSorted(), trigger: triggers, view: [] })
  assertPhysicalSchema(database)
  assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
  assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])

  const schemaMutationMatrix = [
    [
      'receipt-sha-check',
      "CHECK (length(CAST(bundle_digest_sha256 AS BLOB))=64 AND instr(bundle_digest_sha256,char(0))=0 AND bundle_digest_sha256=lower(bundle_digest_sha256) AND bundle_digest_sha256 NOT GLOB '*[^0-9a-f]*'),",
      'CHECK (length(CAST(bundle_digest_sha256 AS BLOB))=64),',
      /table atlas_evidence_bundle_receipts normalized definition drift/,
    ],
    [
      'candidate-successor-chronology',
      ' AND p.recorded_at<NEW.recorded_at AND NOT EXISTS(SELECT 1 FROM atlas_unverified_candidate_occurrences s',
      ' AND NOT EXISTS(SELECT 1 FROM atlas_unverified_candidate_occurrences s',
      /trigger atlas_candidate_occurrences_validate_insert normalized definition drift/,
    ],
    [
      'retrieval-outcome-state',
      "captured_at IS NOT NULL AND http_status_code=200 AND observed_sha256 IS NULL AND detected_media_type IS NOT NULL)",
      "captured_at IS NOT NULL AND http_status_code BETWEEN 200 AND 299 AND observed_sha256 IS NULL AND detected_media_type IS NOT NULL)",
      /table atlas_retrieval_events normalized definition drift/,
    ],
    [
      'retrieval-location-collision',
      ' OR location_url=NEW.location_url',
      '',
      /trigger atlas_retrieval_locations_validate_insert normalized definition drift/,
    ],
    [
      'processing-cycle-guard',
      'WHERE q.artifact_id=p.input_artifact_id',
      'WHERE q.artifact_id=-1',
      /trigger atlas_processing_outputs_validate_insert normalized definition drift/,
    ],
    [
      'custody-transition-guard',
      '(NEW.backend_code<>p.backend_code OR NEW.custody_class_code<>p.custody_class_code)',
      '(1=1)',
      /trigger atlas_artifact_custody_events_validate_insert normalized definition drift/,
    ],
    [
      'append-only-update-guard',
      "CREATE TRIGGER atlas_artifacts_immutable_update BEFORE UPDATE ON atlas_artifacts BEGIN SELECT RAISE(ABORT,'artifact identities are immutable'); END;",
      '',
      /table\/trigger definition inventory drift/,
    ],
    [
      'retrieval-location-chronology',
      " OR NOT EXISTS(SELECT 1 FROM atlas_retrieval_locations l WHERE l.id=NEW.last_attempted_location_id AND l.recorded_at<=NEW.completed_at)",
      '',
      /trigger atlas_retrieval_events_validate_insert normalized definition drift/,
    ],
    [
      'candidate-lineage-composite-fk',
      '  FOREIGN KEY (processing_output_id,processing_run_id) REFERENCES atlas_processing_outputs(id,processing_run_id) ON UPDATE RESTRICT ON DELETE RESTRICT,\n',
      '',
      /atlas_unverified_candidate_occurrences foreign keys drift/,
    ],
  ]
  const schemaMutants = new Map()
  for (const mutation of schemaMutationMatrix) {
    schemaMutants.set(mutation[0], assertSchemaDefinitionMutationDetected(proposal, ...mutation))
  }

  const legacySchemaMutationRoot = temporaryDirectory('jedi-2a-legacy-schema-mutant-')
  const legacySchemaMutationPath = path.join(legacySchemaMutationRoot, 'mutant.sqlite')
  applyMigrations({ databasePath: legacySchemaMutationPath, migrationsDirectory: migrations })
  const legacySchemaMutationDigests = legacyDigests(legacySchemaMutationPath)
  let legacySchemaMutationDatabase = openDatabase(legacySchemaMutationPath)
  const legacySchemaMutationBefore = schemaDefinitionSnapshot(legacySchemaMutationDatabase)
  legacySchemaMutationDatabase.close()
  applyMigrations({
    databasePath: legacySchemaMutationPath,
    migrationsDirectory: migrationDirectory(`${proposal}\nDROP INDEX requirements_status_idx;\n`),
  })
  legacySchemaMutationDatabase = openDatabase(legacySchemaMutationPath)
  assert.throws(
    () => assertPriorSchemaPreserved(legacySchemaMutationBefore, schemaDefinitionSnapshot(legacySchemaMutationDatabase)),
    /pre-existing schema object was deleted: index requirements_status_idx/,
    'deleted legacy index escaped schema-preservation validation',
  )
  assert.deepEqual(legacyDigests(legacySchemaMutationPath), legacySchemaMutationDigests, 'legacy schema mutation unexpectedly changed legacy rows')
  legacySchemaMutationDatabase.close()

  const environment = syntheticEnvironment()
  const first = syntheticFirstBundle(environment)
  assertEveryManifestLeafAffectsDigest(first)
  assertManifestArrayOrderAffectsDigest(first)
  const optionalFieldAbsent = structuredClone(first)
  delete optionalFieldAbsent.retrieval_events[0].response_metadata.last_modified
  assert.notEqual(bundleDigest(optionalFieldAbsent), bundleDigest(first), 'optional-field presence must remain digest-covered')
  const firstBytes = encodeManifest(first)
  const firstInput = materializeManifest(environment, first)
  const parsedFirst = parseManifestBytes(firstBytes, schema)
  validateManifestSemantics(parsedFirst, databaseContext(database))
  const bootstrapTrustRootCollision = mutateManifest(first, (manifest) => {
    manifest.principal_bootstrap.principals.push({
      id: 5,
      principal_code: 'system.bootstrap',
      principal_kind_code: 'service',
      runtime_role_code: 'collector',
      created_by_principal_code: 'system.bootstrap',
      created_at: '2026-01-01T00:00:03.000Z',
    })
  })
  assert.throws(
    () => validateManifestSemantics(parseManifestBytes(encodeManifest(bootstrapTrustRootCollision), schema), databaseContext(database)),
    /collides with the trust root/,
  )
  assertConstraintMutationBehavior({
    canonicalProposal: proposal,
    mutantProposal: schemaMutants.get('receipt-sha-check'),
    label: 'receipt-sha-check',
    manifestInput: firstInput,
    schema,
    adapter: environment.adapter,
    runtime: importerRuntime,
    probe: invalidReceiptShaInsert,
    canonicalPattern: /CHECK constraint failed/,
  })
  assertConstraintMutationBehavior({
    canonicalProposal: proposal,
    mutantProposal: schemaMutants.get('candidate-successor-chronology'),
    label: 'candidate-successor-chronology',
    manifestInput: firstInput,
    schema,
    adapter: environment.adapter,
    runtime: importerRuntime,
    probe: invalidEqualTimeCandidateSuccessorInsert,
    canonicalPattern: /invalid candidate correction successor/,
  })

  assert.throws(() => parseManifestBytes(Buffer.from('{"format":"a","format":"b"}'), schema), /duplicate key/)
  assert.throws(() => parseManifestBytes(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), firstBytes]), schema), /BOM/)
  assert.throws(() => parseManifestBytes(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d]), schema), /encoded data|UTF-8/i)
  for (const token of ['1e0', '1.0', '-0']) {
    const raw = firstBytes.toString('utf8').replace('"bundle_sequence": 1', `"bundle_sequence": ${token}`)
    assert.throws(() => parseManifestBytes(Buffer.from(raw), schema), /noncanonical number/)
  }
  const unknownProperty = mutateManifest(first, (manifest) => { manifest.unexpected = 'rejected' })
  assert.throws(() => parseManifestBytes(encodeManifest(unknownProperty), schema), /unknown property/)
  const nulText = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].collector_version = 'bad\0value' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(nulText), schema), databaseContext(database)))
  const multibyteOverflow = mutateManifest(first, (manifest) => { manifest.custody_events[0].reason = 'é'.repeat(501) })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(multibyteOverflow), schema), databaseContext(database)))
  const secretUrl = mutateManifest(first, (manifest) => {
    const url = 'https://source.invalid/path?x-goog-signature=redacted'
    manifest.retrieval_locations[0].url = url
    manifest.retrieval_locations[0].record_code = locationCode(url)
    manifest.retrieval_events[0].requested_location_code = manifest.retrieval_locations[0].record_code
    manifest.retrieval_events[0].redirects[0].from_location_code = manifest.retrieval_locations[0].record_code
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(secretUrl), schema), databaseContext(database)))
  const controlCharacterUrl = mutateManifest(first, (manifest) => { manifest.retrieval_locations[0].url = 'https://source.invalid/\u0001hidden' })
  assert.throws(() => parseManifestBytes(encodeManifest(controlCharacterUrl), schema))
  const missingRedirectEvidence = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].redirects = [] })
  assert.throws(
    () => validateManifestSemantics(parseManifestBytes(encodeManifest(missingRedirectEvidence), schema), databaseContext(database)),
    /last attempted location differs without redirect evidence/,
  )
  const lateLocation = mutateManifest(first, (manifest) => { manifest.retrieval_locations[0].recorded_at = '2026-01-03T00:00:00.000Z' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(lateLocation), schema), databaseContext(database)))
  const wrongRecorder = mutateManifest(first, (manifest) => { manifest.retrieval_locations[0].recorded_by_principal_code = 'pilot.collector' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(wrongRecorder), schema), databaseContext(database)))
  const importerAsCollector = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].collector_principal_code = 'pilot.importer' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(importerAsCollector), schema), databaseContext(database)), /collector and technical importer must be distinct/)
  const badPath = mutateManifest(first, (manifest) => { manifest.artifacts[0].staged_path = '../escape' })
  assert.throws(() => parseManifestBytes(encodeManifest(badPath), schema))
  const badTimestamp = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].started_at = '2026-01-01 00:00:00' })
  assert.throws(() => parseManifestBytes(encodeManifest(badTimestamp), schema))
  const badHash = mutateManifest(first, (manifest) => { manifest.artifacts[0].sha256 = 'A'.repeat(64) })
  assert.throws(() => parseManifestBytes(encodeManifest(badHash), schema))
  const badConfiguration = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-success').configuration.mode = 'changed' }, { recomputeConfigurations: false })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(badConfiguration), schema), databaseContext(database)), /configuration digest/)
  const secretConfiguration = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-success').configuration.api_token = 'redacted' })
  assert.throws(() => parseManifestBytes(encodeManifest(secretConfiguration), schema))
  const missingSpan = mutateManifest(first, (manifest) => {
    const candidate = manifest.candidate_occurrences.find((row) => row.locator_kind_code === 'byte_span')
    candidate.span_start = null
    candidate.span_end = null
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(missingSpan), schema), databaseContext(database)))
  const manualNote = mutateManifest(first, (manifest) => { manifest.candidate_occurrences[0].locator_kind_code = 'manual_note' })
  assert.throws(() => parseManifestBytes(encodeManifest(manualNote), schema))
  const malformedCode = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].record_code = 'Bad' })
  assert.throws(() => parseManifestBytes(encodeManifest(malformedCode), schema))
  const duplicateCode = mutateManifest(first, (manifest) => { manifest.retrieval_events[1].record_code = manifest.retrieval_events[0].record_code })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(duplicateCode), schema), databaseContext(database)), /collision|duplicate/)
  const missingPlacement = mutateManifest(first, (manifest) => { manifest.custody_events = manifest.custody_events.filter((event) => event.artifact_code !== manifest.artifacts[1].record_code) })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(missingPlacement), schema), databaseContext(database)), /lacks initial durable placement/)
  const missingArtifactOrigin = mutateManifest(first, (manifest) => {
    const run = runBySuffix(manifest, '.run-success')
    run.outputs[0].artifact_code = run.outputs[1].artifact_code
    run.outputs[0].staged_path = run.outputs[1].staged_path
  })
  assert.throws(
    () => validateManifestSemantics(parseManifestBytes(encodeManifest(missingArtifactOrigin), schema), databaseContext(database)),
    /new artifact lacks an acyclic grounded processing origin/,
  )
  const prematureArtifactIdentity = mutateManifest(first, (manifest) => {
    const run = runBySuffix(manifest, '.run-success')
    manifest.artifacts.find((artifact) => artifact.record_code === run.outputs[0].artifact_code).recorded_at = '2026-01-01T00:20:00.000Z'
  })
  assert.throws(
    () => validateManifestSemantics(parseManifestBytes(encodeManifest(prematureArtifactIdentity), schema), databaseContext(database)),
    /new derived artifact identity predates its origin/,
  )
  const retainedWithoutCustody = mutateManifest(first, (manifest) => {
    manifest.custody_events = manifest.custody_events.filter((event) => !event.record_code.endsWith('.raw-restored') && !event.record_code.endsWith('.raw-tombstone'))
  })
  assert.throws(
    () => validateManifestSemantics(parseManifestBytes(encodeManifest(retainedWithoutCustody), schema), databaseContext(database)),
    /retained retrieval has no custody interval at or after capture/,
  )
  const unretainedProcessing = mutateManifest(first, (manifest) => {
    runBySuffix(manifest, '.run-decode').input_artifact_code = artifactCode('retrieved_body', 'f'.repeat(64), 99)
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(unretainedProcessing), schema), databaseContext(database)), /unknown processing input/)
  const nonhumanEligibility = mutateManifest(first, (manifest) => {
    manifest.custody_events[0].repository_eligibility_declaration.declared_by_principal_code = 'pilot.collector'
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(nonhumanEligibility), schema), databaseContext(database)), /authenticated submitter/)
  const producedAfterRun = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-success').outputs[0].produced_at = '2026-01-01T00:20:31.000Z' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(producedAfterRun), schema), databaseContext(database)))
  const wrongOutputPath = mutateManifest(first, (manifest) => {
    runBySuffix(manifest, '.run-success').outputs[0].staged_path = manifest.artifacts.find((artifact) => artifact.byte_layer_code === 'retrieved_body').staged_path
  })
  assert.throws(
    () => validateManifestSemantics(parseManifestBytes(encodeManifest(wrongOutputPath), schema), databaseContext(database)),
    /staged output path is not content addressed/,
  )
  const serviceManualTranscription = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-success').method_code = 'manual_transcription' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(serviceManualTranscription), schema), databaseContext(database)))
  const humanParser = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-success').processor_principal_code = 'pilot.researcher' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(humanParser), schema), databaseContext(database)))
  const importerAsProcessor = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-success').processor_principal_code = 'pilot.importer' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(importerAsProcessor), schema), databaseContext(database)), /processor and technical importer must be distinct/)
  const spanOutOfBounds = mutateManifest(first, (manifest) => {
    const candidate = manifest.candidate_occurrences.find((row) => row.locator_kind_code === 'byte_span')
    candidate.span_end = 999
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(spanOutOfBounds), schema), databaseContext(database)), /span exceeds/)
  const invalidCustodySuccessor = mutateManifest(first, (manifest) => {
    manifest.custody_events.push({
      ...structuredClone(manifest.custody_events[1]),
      record_code: 'pilot-bundle-001.invalid-custody-successor',
      predecessor_custody_event_code: 'pilot-bundle-001.raw-placed',
      recorded_at: '2026-01-01T00:59:00.000Z',
      reason: 'invalid branch from a non-leaf',
    })
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(invalidCustodySuccessor), schema), databaseContext(database)), /current leaf/)
  const relocationClearsRestriction = mutateManifest(first, (manifest) => {
    const restored = manifest.custody_events.find((event) => event.record_code.endsWith('.raw-restored'))
    restored.event_kind_code = 'relocated'
  })
  assert.throws(
    () => validateManifestSemantics(parseManifestBytes(encodeManifest(relocationClearsRestriction), schema), databaseContext(database)),
    /relocation cannot clear/,
  )
  const invalidCandidateSuccessor = mutateManifest(first, (manifest) => {
    manifest.candidate_occurrences.push({
      ...structuredClone(manifest.candidate_occurrences[3]),
      record_code: 'pilot-bundle-001.invalid-candidate-successor',
      chain_code: 'pilot-bundle-001.chain-a',
      record_kind_code: 'correction',
      corrects_candidate_record_code: 'pilot-bundle-001.candidate-a',
      observed_value: 'invalid branch',
      normalized_value: 'invalid branch',
      recorded_at: '2026-01-01T00:27:00.000Z',
    })
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(invalidCandidateSuccessor), schema), databaseContext(database)), /current leaf/)
  const candidateCycle = mutateManifest(first, (manifest) => {
    manifest.candidate_occurrences[0].record_kind_code = 'correction'
    manifest.candidate_occurrences[0].corrects_candidate_record_code = manifest.candidate_occurrences[0].record_code
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(candidateCycle), schema), databaseContext(database)), /unknown candidate predecessor/)
  const wrongCandidateSubject = mutateManifest(first, (manifest) => {
    manifest.candidate_occurrences[1].record_kind_code = 'correction'
    manifest.candidate_occurrences[1].corrects_candidate_record_code = manifest.candidate_occurrences[0].record_code
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(wrongCandidateSubject), schema), databaseContext(database)))
  const duplicateCandidateRoot = mutateManifest(first, (manifest) => {
    manifest.candidate_occurrences[1].chain_code = manifest.candidate_occurrences[0].chain_code
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(duplicateCandidateRoot), schema), databaseContext(database)), /candidate chain already has root/)
  const custodyCycle = mutateManifest(first, (manifest) => {
    manifest.custody_events[0].event_kind_code = 'relocated'
    manifest.custody_events[0].predecessor_custody_event_code = manifest.custody_events[0].record_code
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(custodyCycle), schema), databaseContext(database)), /unknown custody predecessor/)

  for (const forbiddenKey of [
    'api_key', 'api-key', 'apikey', 'prefix.api__key.suffix',
    'private_key', 'private-key', 'privatekey', 'prefix.private..key.suffix',
    'signing_key', 'prefix.signing--key.suffix', 'access.key', 'client_secret',
  ]) {
    const forbiddenConfiguration = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-success').configuration[forbiddenKey] = 'redacted' })
    assert.throws(() => parseManifestBytes(encodeManifest(forbiddenConfiguration), schema), /pattern mismatch/)
  }
  const benignConfiguration = mutateManifest(first, (manifest) => {
    runBySuffix(manifest, '.run-success').configuration.monkey_mode = true
    runBySuffix(manifest, '.run-success').configuration.keyboard_layout = 'synthetic'
  })
  validateManifestSemantics(parseManifestBytes(encodeManifest(benignConfiguration), schema), databaseContext(database))
  const personalDataDeclaration = mutateManifest(first, (manifest) => { manifest.bundle_declarations.contains_personal_data = true })
  assert.throws(() => parseManifestBytes(encodeManifest(personalDataDeclaration), schema), /const mismatch/)
  for (const locator of ['page_region', 'json_pointer', 'xpath']) {
    const unsupportedLocator = mutateManifest(first, (manifest) => { manifest.candidate_occurrences[0].locator_kind_code = locator })
    assert.throws(() => parseManifestBytes(encodeManifest(unsupportedLocator), schema), /enum mismatch/)
  }
  const postAttempt = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].request_method_code = 'POST' })
  assert.throws(() => parseManifestBytes(encodeManifest(postAttempt), schema), /const mismatch/)
  for (const [outcome, eventIndex, status] of [
    ['retained partial response', 0, 206],
    ['observed partial response', 5, 206],
    ['retained non-200 success', 0, 204],
    ['observed non-200 success', 5, 205],
  ]) {
    const partialOrIncomplete = mutateManifest(first, (manifest) => { manifest.retrieval_events[eventIndex].http_status_code = status })
    assert.throws(
      () => validateManifestSemantics(parseManifestBytes(encodeManifest(partialOrIncomplete), schema), databaseContext(database)),
      /requires HTTP 200|rejects partial content/,
      `${outcome} was accepted`,
    )
  }
  for (const status of [300, 305]) {
    const unsupportedRedirect = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].redirects[0].http_status_code = status })
    assert.throws(() => parseManifestBytes(encodeManifest(unsupportedRedirect), schema), /enum mismatch/)
  }
  const headerMutators = [
    (manifest, value) => { manifest.retrieval_events[0].request_headers.accept = value },
    (manifest, value) => { manifest.retrieval_events[0].request_headers.accept_language = value },
    (manifest, value) => { manifest.retrieval_events[0].request_headers.accept_encoding = value },
    (manifest, value) => { manifest.retrieval_events[0].response_metadata.etag = value },
    (manifest, value) => { manifest.retrieval_events[0].response_metadata.last_modified = value },
    (manifest, value) => { manifest.retrieval_events[0].response_metadata.content_type = value },
    (manifest, value) => { manifest.retrieval_events[0].response_metadata.content_encoding = value },
    (manifest, value) => { manifest.retrieval_events[0].response_metadata.vary = value },
    (manifest, value) => { manifest.retrieval_events[2].conditional_validator_value = value },
  ]
  for (const control of ['\r', '\n', '\u0001', '\u007f']) {
    for (const mutateHeader of headerMutators) {
      const unsafeHeader = mutateManifest(first, (manifest) => mutateHeader(manifest, `safe${control}unsafe`))
      assert.throws(() => parseManifestBytes(encodeManifest(unsafeHeader), schema))
    }
  }
  for (const invalidEtag of ['*', 'unquoted', 'w/"lowercase-weak"', '"contains space"']) {
    const malformedEtag = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].response_metadata.etag = invalidEtag })
    assert.throws(() => parseManifestBytes(encodeManifest(malformedEtag), schema))
  }
  for (const invalidHttpDate of [
    'Tue, 21 Oct 2015 07:28:00 GMT',
    'Fri, 30 Feb 2024 07:28:00 GMT',
    'Wednesday, 21-Oct-15 07:28:00 GMT',
    'Wed, 21 Oct 2015 07:28:00 UTC',
  ]) {
    const malformedDate = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].response_metadata.last_modified = invalidHttpDate })
    assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(malformedDate), schema), databaseContext(database)))
  }
  for (const validEtagValue of ['""', 'W/"synthetic-weak"']) {
    const validEtagManifest = mutateManifest(first, (manifest) => {
      manifest.retrieval_events[1].response_metadata.etag = validEtagValue
      for (const event of manifest.retrieval_events.filter((row) => row.conditional_basis_retrieval_event_code?.endsWith('.retrieval-2'))) {
        event.conditional_validator_value = validEtagValue
        if (event.outcome_code === 'not_modified') event.response_metadata.etag = validEtagValue
      }
    })
    validateManifestSemantics(parseManifestBytes(encodeManifest(validEtagManifest), schema), databaseContext(database))
  }
  const validLastModifiedConditional = mutateManifest(first, (manifest) => {
    const lastModified = 'Wed, 21 Oct 2015 07:28:00 GMT'
    manifest.retrieval_events[1].response_metadata.last_modified = lastModified
    for (const event of manifest.retrieval_events.filter((row) => row.conditional_basis_retrieval_event_code?.endsWith('.retrieval-2'))) {
      event.conditional_validator_kind_code = 'last_modified'
      event.conditional_validator_value = lastModified
      if (event.outcome_code === 'not_modified') event.response_metadata.last_modified = lastModified
    }
  })
  validateManifestSemantics(parseManifestBytes(encodeManifest(validLastModifiedConditional), schema), databaseContext(database))
  for (const [method, invalidKind] of [
    ['parser', 'decoded_body'],
    ['ocr', 'extracted_text'],
    ['normalization', 'structured_data'],
    ['manual_transcription', 'ocr_text'],
    ['content_decoding', 'extracted_text'],
  ]) {
    const invalidMethodOutput = mutateManifest(first, (manifest) => {
      const run = runBySuffix(manifest, '.run-success')
      run.method_code = method
      run.outputs = [run.outputs[0]]
      run.outputs[0].output_kind_code = invalidKind
      if (method === 'manual_transcription') run.processor_principal_code = 'pilot.researcher'
      if (method === 'content_decoding') {
        run.input_artifact_code = manifest.artifacts.find((artifact) => artifact.byte_layer_code === 'retrieved_body').record_code
        run.configuration = { content_coding: 'gzip' }
      }
    })
    assert.throws(
      () => validateManifestSemantics(parseManifestBytes(encodeManifest(invalidMethodOutput), schema), databaseContext(database)),
      /processing method\/output kind mismatch/,
    )
  }
  const decodingWrongInput = mutateManifest(first, (manifest) => {
    const run = runBySuffix(manifest, '.run-decode')
    run.input_artifact_code = run.outputs[0].artifact_code
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(decodingWrongInput), schema), databaseContext(database)), /earlier grounded|retrieved-body input/)
  for (const configuration of [{}, { content_coding: 'gzip', extra: true }, { content_coding: 'br' }]) {
    const invalidDecodingConfiguration = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-decode').configuration = configuration })
    assert.throws(
      () => validateManifestSemantics(parseManifestBytes(encodeManifest(invalidDecodingConfiguration), schema), databaseContext(database)),
      /missing content_coding|exactly the pinned|not observed/,
    )
  }
  const missingConditionalValidator = mutateManifest(first, (manifest) => { manifest.retrieval_events[2].conditional_validator_value = null })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(missingConditionalValidator), schema), databaseContext(database)), /incomplete conditional/)
  const mismatchedConditionalValidator = mutateManifest(first, (manifest) => { manifest.retrieval_events[2].conditional_validator_value = '"other"' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(mismatchedConditionalValidator), schema), databaseContext(database)), /does not match basis/)
  const mismatchedRepresentationProfile = mutateManifest(first, (manifest) => { manifest.retrieval_events[2].request_headers.accept = 'text/plain' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(mismatchedRepresentationProfile), schema), databaseContext(database)), /representation profile differs/)
  const mismatchedConditionalResolvedLocation = mutateManifest(first, (manifest) => {
    const event = manifest.retrieval_events[2]
    event.last_attempted_location_code = manifest.retrieval_locations[0].record_code
    event.resolved_location_code = manifest.retrieval_locations[0].record_code
    event.redirects = [{
      record_code: 'pilot-bundle-001.redirect-conditional-mismatch',
      ordinal: 1,
      from_location_code: event.requested_location_code,
      to_location_code: event.resolved_location_code,
      http_status_code: 302,
    }]
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(mismatchedConditionalResolvedLocation), schema), databaseContext(database)), /conditional attempt target differs from basis/)
  const unsafeVaryBasis = mutateManifest(first, (manifest) => { manifest.retrieval_events[1].response_metadata.vary = '*' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(unsafeVaryBasis), schema), databaseContext(database)), /unsupported Vary/)
  const unsupportedVaryBasis = mutateManifest(first, (manifest) => { manifest.retrieval_events[1].response_metadata.vary = 'user-agent' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(unsupportedVaryBasis), schema), databaseContext(database)), /unsupported Vary/)
  const noncanonicalVary = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].response_metadata.vary = 'accept-language, accept' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(noncanonicalVary), schema), databaseContext(database)), /noncanonical Vary/)
  const duplicateVary = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].response_metadata.vary = 'accept, accept' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(duplicateVary), schema), databaseContext(database)), /noncanonical Vary/)
  for (const value of ['GZIP', 'gzip,br', 'gzip , br']) {
    const noncanonicalContentEncoding = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].response_metadata.content_encoding = value })
    assert.throws(() => parseManifestBytes(encodeManifest(noncanonicalContentEncoding), schema), /pattern mismatch/)
  }
  const changed304Vary = mutateManifest(first, (manifest) => { manifest.retrieval_events[2].response_metadata.vary = 'accept' })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(changed304Vary), schema), databaseContext(database)), /304 Vary differs/)
  const unchangedRelocation = mutateManifest(first, (manifest) => {
    const placed = manifest.custody_events.find((event) => event.record_code.endsWith('.raw-placed'))
    const relocated = manifest.custody_events.find((event) => event.record_code.endsWith('.raw-relocated'))
    relocated.custody_class_code = placed.custody_class_code
    relocated.backend_code = placed.backend_code
    relocated.repository_eligibility_declaration = structuredClone(placed.repository_eligibility_declaration)
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(unchangedRelocation), schema), databaseContext(database)), /relocation must change/)

  const selfOrigin = mutateManifest(first, (manifest) => {
    const run = runBySuffix(manifest, '.run-decode')
    run.input_artifact_code = run.outputs[0].artifact_code
  })
  const multiRunCycle = mutateManifest(first, (manifest) => {
    const decode = runBySuffix(manifest, '.run-decode')
    const parser = runBySuffix(manifest, '.run-success')
    decode.input_artifact_code = parser.outputs[0].artifact_code
    parser.input_artifact_code = decode.outputs[0].artifact_code
    decode.started_at = parser.started_at
    decode.completed_at = parser.completed_at
    decode.recorded_at = parser.recorded_at
    decode.outputs[0].produced_at = parser.outputs[0].produced_at
  })
  const ancestorReoutputCycle = mutateManifest(first, (manifest) => {
    const failed = runBySuffix(manifest, '.run-failure')
    const parser = runBySuffix(manifest, '.run-success')
    const decoded = runBySuffix(manifest, '.run-decode').outputs[0]
    failed.input_artifact_code = parser.outputs[1].artifact_code
    failed.method_code = 'parser'
    failed.outcome_code = 'succeeded'
    failed.failure_code = null
    failed.outputs = [{
      record_code: 'pilot-bundle-001.output-ancestor-cycle',
      artifact_code: decoded.artifact_code,
      staged_path: decoded.staged_path,
      ordinal: 0,
      output_kind_code: 'extracted_text',
      detected_media_type: decoded.detected_media_type,
      produced_at: '2026-01-01T00:23:15.000Z',
    }]
  })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(selfOrigin), schema), databaseContext(database)), /earlier grounded/)
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(multiRunCycle), schema), databaseContext(database)), /earlier grounded/)
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(ancestorReoutputCycle), schema), databaseContext(database)), /processing lineage cycle/)

  const decodedArtifact = first.artifacts.find((artifact) => artifact.record_code === runBySuffix(first, '.run-decode').outputs[0].artifact_code)
  const rawArtifact = first.artifacts.find((artifact) => artifact.byte_layer_code === 'retrieved_body')
  const rawBodyBytes = fs.readFileSync(path.join(environment.stagingRoot, rawArtifact.staged_path))
  const decodedBodyBytes = fs.readFileSync(path.join(environment.stagingRoot, decodedArtifact.staged_path))
  assert.notEqual(rawArtifact.sha256, decodedArtifact.sha256, 'content-coded and decoded bytes must have distinct identities')
  assert.deepEqual(zlib.gunzipSync(rawBodyBytes), decodedBodyBytes, 'content decoding lineage fixture is invalid')

  const preflightRoot = temporaryDirectory('jedi-2a-preflight-')
  const preflightDatabasePath = path.join(preflightRoot, 'preflight.sqlite')
  applyMigrations({ databasePath: preflightDatabasePath, migrationsDirectory: designMigrations })
  const preflightDatabase = openDatabase(preflightDatabasePath)
  const locationAfterAttemptStart = mutateManifest(first, (manifest) => { manifest.retrieval_locations[0].recorded_at = '2026-01-01T00:05:30.000Z' })
  const preflightRetained206 = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].http_status_code = 206 })
  const preflightObserved206 = mutateManifest(first, (manifest) => { manifest.retrieval_events[5].http_status_code = 206 })
  const preflightUnsafeHeader = mutateManifest(first, (manifest) => { manifest.retrieval_events[0].request_headers.accept = 'text/plain\rhidden' })
  const preflightInvalidMethodOutput = mutateManifest(first, (manifest) => { runBySuffix(manifest, '.run-success').outputs[0].output_kind_code = 'decoded_body' })
  const preflightUnexpectedObservedFields = []
  for (const outcome of ['not_modified', 'network_failed', 'http_failed']) {
    for (const [field, value] of [['observed_sha256', 'f'.repeat(64)], ['observed_byte_length', 1]]) {
      preflightUnexpectedObservedFields.push([`${outcome}-${field}`, mutateManifest(first, (manifest) => {
        manifest.retrieval_events.find((event) => event.outcome_code === outcome)[field] = value
      })])
    }
  }
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: locationAfterAttemptStart, environment, schema, runtime: importerRuntime, pattern: /recorded after attempt start/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: preflightRetained206, environment, schema, runtime: importerRuntime, pattern: /requires HTTP 200/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: preflightObserved206, environment, schema, runtime: importerRuntime, pattern: /requires HTTP 200/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: preflightUnsafeHeader, environment, schema, runtime: importerRuntime, pattern: /anyOf branch|pattern mismatch/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: preflightInvalidMethodOutput, environment, schema, runtime: importerRuntime, pattern: /processing method\/output kind mismatch/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: bootstrapTrustRootCollision, environment, schema, runtime: importerRuntime, pattern: /collides with the trust root/ })
  for (const [label, manifest] of preflightUnexpectedObservedFields) {
    assertRejectedBeforeBegin({ database: preflightDatabase, manifest, environment, schema, runtime: importerRuntime, pattern: /cannot carry an observed body/, label })
  }
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: selfOrigin, environment, schema, runtime: importerRuntime, pattern: /earlier grounded/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: multiRunCycle, environment, schema, runtime: importerRuntime, pattern: /earlier grounded/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: ancestorReoutputCycle, environment, schema, runtime: importerRuntime, pattern: /processing lineage cycle/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: wrongRecorder, environment, schema, runtime: importerRuntime, pattern: /strictly equal/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: duplicateCode, environment, schema, runtime: importerRuntime, pattern: /collision|duplicate/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: missingPlacement, environment, schema, runtime: importerRuntime, pattern: /lacks initial durable placement/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: invalidCustodySuccessor, environment, schema, runtime: importerRuntime, pattern: /current leaf/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: invalidCandidateSuccessor, environment, schema, runtime: importerRuntime, pattern: /current leaf/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: duplicateCandidateRoot, environment, schema, runtime: importerRuntime, pattern: /candidate chain already has root/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: importerAsCollector, environment, schema, runtime: importerRuntime, pattern: /collector and technical importer/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: importerAsProcessor, environment, schema, runtime: importerRuntime, pattern: /processor and technical importer/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: mismatchedConditionalResolvedLocation, environment, schema, runtime: importerRuntime, pattern: /conditional attempt target differs from basis/ })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: unsupportedVaryBasis, environment, schema, runtime: importerRuntime, pattern: /unsupported Vary/ })
  const mismatchPath = 'reviewed/manifests/path-mismatch.json'
  writeArtifact(environment.manifestRoot, mismatchPath, firstBytes)
  const mismatchObserver = { beginCount: 0 }
  assert.throws(() => simulateImport({ database: preflightDatabase, reviewedManifestRoot: environment.manifestRoot, manifestRelativePath: mismatchPath, schema, adapter: environment.adapter, ...importerRuntime, transactionObserver: mismatchObserver }), /does not match manifest declaration/)
  assert.equal(mismatchObserver.beginCount, 0)
  for (const unsafeInputPath of ['/absolute.json', '../escape.json']) {
    const observer = { beginCount: 0 }
    assert.throws(() => simulateImport({ database: preflightDatabase, reviewedManifestRoot: environment.manifestRoot, manifestRelativePath: unsafeInputPath, schema, adapter: environment.adapter, ...importerRuntime, transactionObserver: observer }), /unsafe reviewed manifest path/)
    assert.equal(observer.beginCount, 0)
  }
  const manifestSymlink = 'reviewed/manifests/symlink.json'
  const symlinkTarget = path.join(environment.manifestRoot, first.manifest_path)
  const symlinkPath = path.join(environment.manifestRoot, manifestSymlink)
  fs.mkdirSync(path.dirname(symlinkPath), { recursive: true })
  fs.symlinkSync(symlinkTarget, symlinkPath)
  const symlinkObserver = { beginCount: 0 }
  assert.throws(() => simulateImport({ database: preflightDatabase, reviewedManifestRoot: environment.manifestRoot, manifestRelativePath: manifestSymlink, schema, adapter: environment.adapter, ...importerRuntime, transactionObserver: symlinkObserver }), /symbolic link/)
  assert.equal(symlinkObserver.beginCount, 0)
  materializeManifest(environment, first)
  assert.equal(simulateImport({ database: preflightDatabase, ...materializeManifest(environment, first), schema, adapter: environment.adapter, ...importerRuntime }), 'imported')
  const preflightSecond = syntheticSecondBundle(first, environment)
  const existingBundleIdentityDrift = mutateManifest(first, (manifest) => { manifest.custody_events[0].reason = 'synthetic identity drift probe' })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: existingBundleIdentityDrift, environment, schema, runtime: importerRuntime, pattern: /bundle identity drift/ })
  materializeManifest(environment, first)
  const pathCollision = mutateManifest(preflightSecond, (manifest) => { manifest.manifest_path = first.manifest_path })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: pathCollision, environment, schema, runtime: importerRuntime, pattern: /manifest path collision/ })
  materializeManifest(environment, first)
  const nonmonotonicBundle = mutateManifest(preflightSecond, (manifest) => { manifest.bundle_created_at = '2026-01-01T23:59:59.000Z' })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: nonmonotonicBundle, environment, schema, runtime: importerRuntime, pattern: /chronology must be monotonic/ })
  const wrongBundleSequence = mutateManifest(preflightSecond, (manifest) => { manifest.bundle_sequence = 3 })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: wrongBundleSequence, environment, schema, runtime: importerRuntime, pattern: /sequence must be contiguous/ })
  const existingLocationCollision = mutateManifest(preflightSecond, (manifest) => {
    manifest.retrieval_locations.push(structuredClone(first.retrieval_locations[0]))
  })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: existingLocationCollision, environment, schema, runtime: importerRuntime, pattern: /location declaration collides|location URL already exists/ })
  const existingArtifactCollision = mutateManifest(preflightSecond, (manifest) => {
    manifest.artifacts.push(structuredClone(first.artifacts[0]))
  })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: existingArtifactCollision, environment, schema, runtime: importerRuntime, pattern: /artifact declaration collides|artifact identity already exists/ })
  const existingCustodyRoot = mutateManifest(preflightSecond, (manifest) => {
    const event = manifest.custody_events[0]
    event.event_kind_code = 'placed'
    event.predecessor_custody_event_code = null
  })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: existingCustodyRoot, environment, schema, runtime: importerRuntime, pattern: /custody copy already has a root/ })
  const duplicateRunOrdinal = mutateManifest(preflightSecond, (manifest) => {
    const duplicate = structuredClone(manifest.processing_runs[0])
    duplicate.record_code = 'pilot-bundle-002.run-duplicate-ordinal'
    duplicate.outputs = []
    manifest.processing_runs.push(duplicate)
  })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: duplicateRunOrdinal, environment, schema, runtime: importerRuntime, pattern: /duplicate processing run ordinal/ })
  const duplicateOutputOrdinal = mutateManifest(preflightSecond, (manifest) => {
    const duplicate = structuredClone(manifest.processing_runs[0].outputs[0])
    duplicate.record_code = 'pilot-bundle-002.output-duplicate-ordinal'
    manifest.processing_runs[0].outputs.push(duplicate)
  })
  assertRejectedBeforeBegin({ database: preflightDatabase, manifest: duplicateOutputOrdinal, environment, schema, runtime: importerRuntime, pattern: /duplicate processing output ordinal/ })
  preflightDatabase.close()

  const digestCollisionRoot = temporaryDirectory('jedi-2a-preflight-digest-collision-')
  const digestCollisionDatabasePath = path.join(digestCollisionRoot, 'digest-collision.sqlite')
  applyMigrations({ databasePath: digestCollisionDatabasePath, migrationsDirectory: designMigrations })
  const digestCollisionDatabase = openDatabase(digestCollisionDatabasePath)
  materializeManifest(environment, first)
  assert.equal(simulateImport({ database: digestCollisionDatabase, ...materializeManifest(environment, first), schema, adapter: environment.adapter, ...importerRuntime }), 'imported')
  const digestCollisionManifest = mutateManifest(preflightSecond, (manifest) => { manifest.required_bundles = [] })
  digestCollisionDatabase.exec('DROP TRIGGER atlas_evidence_bundle_receipts_immutable_update')
  digestCollisionDatabase.prepare('UPDATE atlas_evidence_bundle_receipts SET bundle_digest_sha256=? WHERE bundle_sequence=1').run(digestCollisionManifest.bundle_digest_sha256)
  assertRejectedBeforeBegin({ database: digestCollisionDatabase, manifest: digestCollisionManifest, environment, schema, runtime: importerRuntime, pattern: /bundle digest collision/ })
  digestCollisionDatabase.close()
  materializeManifest(environment, first)

  const stagedTarget = path.join(environment.stagingRoot, rawArtifact.staged_path)
  const originalBytes = fs.readFileSync(stagedTarget)
  fs.writeFileSync(stagedTarget, Buffer.concat([originalBytes, Buffer.from('x')]))
  assert.throws(() => verifyEvidenceBytes(first, emptyContext(database), environment.adapter), /byte-length mismatch/)
  fs.writeFileSync(stagedTarget, Buffer.concat([Buffer.from('X'), originalBytes.subarray(1)]))
  assert.throws(() => verifyEvidenceBytes(first, emptyContext(database), environment.adapter), /SHA-256 mismatch/)
  fs.writeFileSync(stagedTarget, originalBytes)
  const custodyTarget = path.join(environment.repositoryRoot, custodyReference(rawArtifact))
  fs.writeFileSync(custodyTarget, Buffer.concat([Buffer.from('X'), originalBytes.subarray(1)]))
  assert.throws(() => verifyEvidenceBytes(first, emptyContext(database), environment.adapter), /custody copy .* SHA-256 mismatch/)
  fs.writeFileSync(custodyTarget, originalBytes)
  const symlinkTargetRoot = temporaryDirectory('jedi-2a-symlink-target-')
  fs.writeFileSync(path.join(symlinkTargetRoot, 'outside.bin'), 'outside')
  fs.symlinkSync(path.join(symlinkTargetRoot, 'outside.bin'), path.join(environment.stagingRoot, 'linked.bin'))
  assert.throws(() => confinedRead(environment.stagingRoot, 'linked.bin'), /symbolic link/)

  assert.throws(() => simulateImport({
    database,
    ...firstInput,
    schema,
    adapter: environment.adapter,
    authenticatedInvokerCode: 'pilot.collector',
    trustedImporterCode: 'pilot.importer',
    trustedImporterSoftwareCode: 'atlas-fixed-importer',
    trustedImporterVersion: 'design-1.0.0',
  }), /submitter mismatch/)
  assert.equal(simulateImport({ database, ...firstInput, schema, adapter: environment.adapter, ...importerRuntime }), 'imported')
  assert.equal(simulateImport({ database, ...firstInput, schema, adapter: environment.adapter, ...importerRuntime }), 'no_op')

  const alternateOutputArtifactCode = runBySuffix(first, '.run-success').outputs[1].artifact_code
  const noOpMutations = [
    ['missing-etag', 'atlas_retrieval_events_immutable_update', "UPDATE atlas_retrieval_events SET response_etag=NULL WHERE retrieval_event_code='pilot-bundle-001.retrieval-1'"],
    ['changed-outcome', 'atlas_retrieval_events_immutable_update', "PRAGMA ignore_check_constraints=ON; UPDATE atlas_retrieval_events SET outcome_code='observed_not_retained' WHERE retrieval_event_code='pilot-bundle-001.retrieval-1'"],
    ['changed-timestamp', 'atlas_retrieval_events_immutable_update', "UPDATE atlas_retrieval_events SET recorded_at='2026-01-01T00:06:02.000Z' WHERE retrieval_event_code='pilot-bundle-001.retrieval-1'"],
    ['changed-custody', 'atlas_artifact_custody_events_immutable_update', "UPDATE atlas_artifact_custody_events SET reason='tampered custody reason' WHERE custody_event_code='pilot-bundle-001.raw-relocated'"],
    ['changed-run-configuration', 'atlas_processing_runs_immutable_update', `UPDATE atlas_processing_runs SET configuration_sha256='${'d'.repeat(64)}' WHERE processing_run_code='pilot-bundle-001.run-success'`],
    ['changed-candidate-value', 'atlas_candidate_occurrences_immutable_update', "UPDATE atlas_unverified_candidate_occurrences SET observed_value='tampered' WHERE candidate_record_code='pilot-bundle-001.candidate-a'"],
    ['changed-output-relationship', 'atlas_processing_outputs_immutable_update', `UPDATE atlas_processing_outputs SET artifact_id=(SELECT id FROM atlas_artifacts WHERE artifact_code='${alternateOutputArtifactCode}') WHERE processing_output_code='pilot-bundle-001.output-text'`],
  ]
  for (const [label, trigger, mutateSql] of noOpMutations) {
    assertNoOpMutationRejected({ designMigrations, schema, manifest: first, environment, label, trigger, mutateSql, runtime: importerRuntime })
  }

  const identityDrift = mutateManifest(first, (manifest) => { manifest.custody_events[0].reason = 'different content under same bundle identity' })
  assert.throws(() => simulateImport({ database, ...materializeManifest(environment, identityDrift), schema, adapter: environment.adapter, ...importerRuntime }), /identity drift/)
  materializeManifest(environment, first)

  const second = syntheticSecondBundle(first, environment)
  assertEveryManifestLeafAffectsDigest(second)
  const repeatedBootstrap = mutateManifest(second, (manifest) => { manifest.principal_bootstrap = structuredClone(first.principal_bootstrap) })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(repeatedBootstrap), schema), databaseContext(database)), /one-time/)
  const missingDependency = mutateManifest(second, (manifest) => { manifest.required_bundles = [] })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(missingDependency), schema), databaseContext(database)), /predecessor|unpinned/)
  const wrongDependencyDigest = mutateManifest(second, (manifest) => { manifest.required_bundles[0].bundle_digest_sha256 = '0'.repeat(64) })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(wrongDependencyDigest), schema), databaseContext(database)), /digest mismatch/)
  const wrongSequence = mutateManifest(second, (manifest) => { manifest.bundle_sequence = 3 })
  assert.throws(() => validateManifestSemantics(parseManifestBytes(encodeManifest(wrongSequence), schema), databaseContext(database)), /sequence/)
  const nonRestoringTombstoneSuccessor = mutateManifest(second, (manifest) => {
    const custody = manifest.custody_events[0]
    custody.event_kind_code = 'restricted'
    custody.custody_class_code = 'restricted_store'
    custody.backend_code = 'synthetic_store'
    custody.repository_eligibility_declaration = null
  })
  assert.throws(
    () => validateManifestSemantics(parseManifestBytes(encodeManifest(nonRestoringTombstoneSuccessor), schema), databaseContext(database)),
    /only restoration may reverse a tombstone/,
  )
  const secondBytes = encodeManifest(second)
  const secondInput = materializeManifest(environment, second)
  const repeatedOutputPath = path.join(environment.stagingRoot, second.processing_runs[0].outputs[0].staged_path)
  const repeatedOutputBytes = fs.readFileSync(repeatedOutputPath)
  fs.writeFileSync(repeatedOutputPath, Buffer.concat([repeatedOutputBytes, Buffer.from('x')]))
  assert.throws(
    () => simulateImport({ database, ...secondInput, schema, adapter: environment.adapter, ...importerRuntime }),
    /staged processing output .* byte-length mismatch/,
  )
  fs.writeFileSync(repeatedOutputPath, repeatedOutputBytes)
  assert.equal(simulateImport({ database, ...secondInput, schema, adapter: environment.adapter, ...importerRuntime }), 'imported')
  assert.equal(simulateImport({ database, ...secondInput, schema, adapter: environment.adapter, ...importerRuntime }), 'no_op')
  const supersededRawCustodyPath = path.join(environment.restrictedRoot, custodyReference(rawArtifact))
  const supersededRawCustodyBytes = fs.readFileSync(supersededRawCustodyPath)
  fs.unlinkSync(supersededRawCustodyPath)
  assert.equal(simulateImport({ database, ...firstInput, schema, adapter: environment.adapter, ...importerRuntime }), 'no_op')
  fs.writeFileSync(supersededRawCustodyPath, supersededRawCustodyBytes)

  assert.equal(database.prepare('SELECT count(*) AS count FROM atlas_retrieval_events WHERE artifact_id=(SELECT id FROM atlas_artifacts WHERE artifact_code=?)').get(rawArtifact.record_code).count, 2)
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_artifacts WHERE byte_layer_code='retrieved_body'").get().count, 1)
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_retrieval_events WHERE outcome_code='not_modified'").get().count, 2)
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_retrieval_events WHERE outcome_code='not_modified' AND artifact_id IS NULL AND conditional_basis_retrieval_event_id IS NOT NULL").get().count, 2)
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_retrieval_events WHERE outcome_code IN ('network_failed','http_failed') AND artifact_id IS NULL").get().count, 4)
  assert.deepEqual({ ...database.prepare(`SELECT requested.location_code AS requested_code,
      attempted.location_code AS last_attempted_code,resolved.location_code AS resolved_code,
      event.outcome_code,count(redirect.id) AS redirect_count
    FROM atlas_retrieval_events event
    JOIN atlas_retrieval_locations requested ON requested.id=event.requested_location_id
    JOIN atlas_retrieval_locations attempted ON attempted.id=event.last_attempted_location_id
    LEFT JOIN atlas_retrieval_locations resolved ON resolved.id=event.resolved_location_id
    LEFT JOIN atlas_retrieval_redirects redirect ON redirect.retrieval_event_id=event.id
    WHERE event.retrieval_event_code='pilot-bundle-001.retrieval-7'
    GROUP BY event.id`).get() }, {
    requested_code: first.retrieval_locations[0].record_code,
    last_attempted_code: first.retrieval_locations[1].record_code,
    resolved_code: null,
    outcome_code: 'network_failed',
    redirect_count: 1,
  })
  assert.deepEqual({ ...database.prepare(`SELECT attempted.location_code AS last_attempted_code,
      event.resolved_location_id,basis.retrieval_event_code AS basis_code,event.conditional_validator_kind_code,
      event.conditional_validator_value,event.outcome_code,count(redirect.id) AS redirect_count
    FROM atlas_retrieval_events event
    JOIN atlas_retrieval_locations attempted ON attempted.id=event.last_attempted_location_id
    JOIN atlas_retrieval_events basis ON basis.id=event.conditional_basis_retrieval_event_id
    LEFT JOIN atlas_retrieval_redirects redirect ON redirect.retrieval_event_id=event.id
    WHERE event.retrieval_event_code='pilot-bundle-001.retrieval-8'
    GROUP BY event.id`).get() }, {
    last_attempted_code: first.retrieval_locations[1].record_code,
    resolved_location_id: null,
    basis_code: 'pilot-bundle-001.retrieval-2',
    conditional_validator_kind_code: 'etag',
    conditional_validator_value: '"synthetic-v1"',
    outcome_code: 'network_failed',
    redirect_count: 0,
  })
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_retrieval_events WHERE outcome_code='observed_not_retained' AND artifact_id IS NULL").get().count, 1)
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_processing_runs WHERE outcome_code='failed'").get().count, 1)
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_processing_outputs WHERE processing_run_id=(SELECT id FROM atlas_processing_runs WHERE processing_run_code LIKE '%.run-success')").get().count, 2)
  assert.deepEqual(database.prepare(`SELECT run.processing_run_code,receipt.bundle_sequence
    FROM atlas_processing_outputs output
    JOIN atlas_processing_runs run ON run.id=output.processing_run_id
    JOIN atlas_evidence_bundle_receipts receipt ON receipt.id=run.evidence_bundle_receipt_id
    WHERE output.artifact_id=(SELECT id FROM atlas_artifacts WHERE artifact_code=?)
    ORDER BY receipt.bundle_sequence,run.run_ordinal`).all(runBySuffix(first, '.run-success').outputs[1].artifact_code).map((row) => ({ ...row })), [
    { processing_run_code: 'pilot-bundle-001.run-success', bundle_sequence: 1 },
    { processing_run_code: 'pilot-bundle-001.run-repeat-same-bundle', bundle_sequence: 1 },
    { processing_run_code: 'pilot-bundle-002.run-repeated-output', bundle_sequence: 2 },
  ])
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_unverified_candidate_occurrences WHERE observed_value IN ('Alpha','Beta')").get().count, 3)
  assert.equal(database.prepare("SELECT record_kind_code FROM atlas_unverified_candidate_occurrences WHERE candidate_record_code LIKE 'pilot-bundle-002.%'").get().record_kind_code, 'correction')
  assert.equal(database.prepare("SELECT event_kind_code FROM atlas_artifact_custody_events WHERE custody_event_code='pilot-bundle-002.raw-restored'").get().event_kind_code, 'restored')
  assert.deepEqual({ ...custodyLeafAt(database, 'copy.raw', '2026-01-01T00:30:00.000Z', 1) }, {
    event_kind_code: 'restored',
    occurred_at: '2026-01-01T00:10:30.000Z',
    recorded_at: '2026-01-01T00:10:30.000Z',
    bundle_sequence: 1,
  })
  assert.deepEqual({ ...custodyLeafAt(database, 'copy.raw', '2026-01-02T00:00:00.000Z', 1) }, {
    event_kind_code: 'tombstoned',
    occurred_at: '2026-01-01T01:00:00.000Z',
    recorded_at: '2026-01-01T01:00:00.000Z',
    bundle_sequence: 1,
  })
  assert.deepEqual({ ...custodyLeafAt(database, 'copy.raw', '2026-01-04T00:00:00.000Z', 2) }, {
    event_kind_code: 'restored',
    occurred_at: '2026-01-03T00:01:00.000Z',
    recorded_at: '2026-01-03T00:01:00.000Z',
    bundle_sequence: 2,
  })
  assert.equal(custodyLeafAt(database, 'copy.decoded', '2026-01-01T00:20:00.000Z', 1).event_kind_code, 'placed')
  assert.equal(custodyLeafAt(database, 'copy.decoded', '2026-01-01T00:20:00.000Z', 2).event_kind_code, 'restricted')
  const acceptedRunKnowledgeSequence = database.prepare(`SELECT receipt.bundle_sequence
    FROM atlas_processing_runs run JOIN atlas_evidence_bundle_receipts receipt ON receipt.id=run.evidence_bundle_receipt_id
    WHERE run.processing_run_code='pilot-bundle-001.run-success'`).get().bundle_sequence
  assert.equal(acceptedRunKnowledgeSequence, 1)
  assert.equal(custodyLeafAt(database, 'copy.decoded', '2026-01-01T00:20:00.000Z', acceptedRunKnowledgeSequence).event_kind_code, 'placed')
  assert.deepEqual({ ...candidateLeafAt(database, 'pilot-bundle-001.chain-a', '2026-01-01T00:25:30.000Z') }, {
    record_kind_code: 'correction',
    observed_value: 'Alpha corrected',
    recorded_at: '2026-01-01T00:25:00.000Z',
  })
  assert.deepEqual({ ...candidateLeafAt(database, 'pilot-bundle-001.chain-a', '2026-01-02T00:00:00.000Z') }, {
    record_kind_code: 'withdrawal',
    observed_value: null,
    recorded_at: '2026-01-01T00:26:00.000Z',
  })
  assert.deepEqual({ ...candidateLeafAt(database, 'pilot-bundle-001.chain-a', '2026-01-04T00:00:00.000Z') }, {
    record_kind_code: 'correction',
    observed_value: 'Alpha reinstated',
    recorded_at: '2026-01-03T00:02:00.000Z',
  })
  const secondReceiptId = database.prepare("SELECT id FROM atlas_evidence_bundle_receipts WHERE bundle_code='pilot-bundle-002'").get().id
  assert.equal(database.prepare("SELECT count(*) AS count FROM atlas_retrieval_events WHERE outcome_code IN ('retrieved_retained','observed_not_retained') AND http_status_code=200").get().count, 3)
  assert.throws(() => invalidReceiptShaInsert(database), /CHECK constraint failed/, 'raw SQL accepted a malformed receipt digest')

  let directSqlSequence = 0
  const directRetrievalBase = (codeValue) => ({ ...database.prepare('SELECT * FROM atlas_retrieval_events WHERE retrieval_event_code=?').get(codeValue) })
  const assertDirectRetrievalRejected = (label, row, pattern = /CHECK constraint failed/) => {
    const before = atlasState(database)
    const candidate = {
      ...row,
      id: database.prepare('SELECT max(id)+1000 AS id FROM atlas_retrieval_events').get().id + (++directSqlSequence),
      retrieval_event_code: `sql.direct.${label}.${directSqlSequence}`,
    }
    assert.throws(() => insertRow(database, 'INSERT', 'atlas_retrieval_events', candidate), pattern, `raw SQL accepted ${label}`)
    assert.deepEqual(atlasState(database), before, `${label} direct-SQL rejection changed evidence state`)
  }
  assertDirectRetrievalRejected('retained-206', { ...directRetrievalBase('pilot-bundle-001.retrieval-2'), http_status_code: 206 })
  assertDirectRetrievalRejected('observed-206', { ...directRetrievalBase('pilot-bundle-001.retrieval-6'), http_status_code: 206 })
  assertDirectRetrievalRejected('resolved-target-mismatch', {
    ...directRetrievalBase('pilot-bundle-001.retrieval-2'),
    resolved_location_id: database.prepare("SELECT id FROM atlas_retrieval_locations WHERE location_url='https://source.invalid/start'").get().id,
  })
  for (const [column, value] of [
    ['request_accept', 'text/plain\rhidden'],
    ['request_accept_language', 'en\nhidden'],
    ['request_accept_encoding', 'gzip' + String.fromCharCode(127)],
    ['response_etag', 'unquoted'],
    ['response_last_modified', 'Wed, 99 Oct 2015 07:28:00 GMT'],
    ['response_content_type', 'text/plain' + String.fromCharCode(1)],
    ['response_content_encoding', 'gzip\rbr'],
    ['response_vary', 'accept\nencoding'],
    ['detected_media_type', 'text/plain' + String.fromCharCode(127)],
  ]) {
    assertDirectRetrievalRejected(`unsafe-${column.replaceAll('_', '-')}`, { ...directRetrievalBase('pilot-bundle-001.retrieval-2'), [column]: value })
  }
  assertDirectRetrievalRejected('unsafe-conditional-validator', {
    ...directRetrievalBase('pilot-bundle-001.retrieval-4'),
    conditional_validator_kind_code: 'etag',
    conditional_validator_value: '"synthetic-v1"\n',
  })

  assert.throws(
    () => database.prepare('INSERT INTO atlas_retrieval_locations(location_code,location_url,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?)')
      .run('location.bootstrap.invalid', 'https://source.invalid/bootstrap', secondReceiptId, 1, '2026-01-03T01:00:00.000Z'),
    /invalid retrieval location attribution or chronology/,
  )
  assert.throws(
    () => database.prepare('INSERT INTO atlas_retrieval_locations(location_code,location_url,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?)')
      .run('location.chronology.invalid', 'https://source.invalid/chronology', secondReceiptId, 2, '2025-12-01T12:00:00.000Z'),
    /invalid retrieval location attribution or chronology/,
  )
  const rawArtifactId = database.prepare('SELECT id FROM atlas_artifacts WHERE artifact_code=?').get(rawArtifact.record_code).id
  const invalidProcessorKindInsert = database.prepare(`INSERT INTO atlas_processing_runs(
    processing_run_code,run_ordinal,input_artifact_id,method_code,processor_principal_id,processor_software_code,processor_version,
    configuration_sha256,started_at,completed_at,outcome_code,failure_code,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
  )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
  assert.throws(
    () => invalidProcessorKindInsert.run(
      'sql.invalid-manual-service', 1, rawArtifactId, 'manual_transcription', 3, 'synthetic', '1.0.0', 'a'.repeat(64),
      '2026-01-03T01:00:00.000Z', '2026-01-03T01:00:01.000Z', 'failed', 'wrong_principal_kind', secondReceiptId, 2, '2026-01-03T01:00:02.000Z',
    ),
    /invalid processing attribution or chronology/,
  )
  assert.throws(() => invalidEqualTimeCandidateSuccessorInsert(database), /invalid candidate correction successor/, 'raw SQL accepted an equal-time candidate successor')
  const currentRawCustody = database.prepare(`SELECT * FROM atlas_artifact_custody_events c
    WHERE c.copy_code='copy.raw'
      AND NOT EXISTS(SELECT 1 FROM atlas_artifact_custody_events successor WHERE successor.predecessor_custody_event_id=c.id)`).get()
  const invalidUnchangedRelocation = {
    ...currentRawCustody,
    id: database.prepare('SELECT max(id)+1000 AS id FROM atlas_artifact_custody_events').get().id,
    custody_event_code: 'sql.invalid.unchanged-relocation',
    event_kind_code: 'relocated',
    predecessor_custody_event_id: currentRawCustody.id,
    reason: 'synthetic unchanged relocation probe',
    occurred_at: '2026-01-03T12:10:00.000Z',
    recorded_at: '2026-01-03T12:10:00.000Z',
  }
  assert.throws(
    () => insertRow(database, 'INSERT', 'atlas_artifact_custody_events', invalidUnchangedRelocation),
    /invalid custody successor/,
    'raw SQL accepted a relocation that changed neither backend nor custody class',
  )

  const beforeDirectMethodMatrix = atlasState(database)
  database.exec('BEGIN IMMEDIATE')
  try {
    const outputArtifactId = database.prepare("SELECT artifact_id FROM atlas_processing_outputs WHERE processing_output_code='pilot-bundle-001.output-text'").get().artifact_id
    const runRows = [
      database.prepare("SELECT * FROM atlas_processing_runs WHERE processing_run_code='pilot-bundle-001.run-decode'").get(),
      database.prepare("SELECT * FROM atlas_processing_runs WHERE processing_run_code='pilot-bundle-001.run-success'").get(),
    ]
    const createRun = (methodCode, ordinal, processorPrincipalId) => database.prepare(`INSERT INTO atlas_processing_runs(
      processing_run_code,run_ordinal,input_artifact_id,method_code,processor_principal_id,processor_software_code,processor_version,
      configuration_sha256,started_at,completed_at,outcome_code,failure_code,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
    )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *`).get(
      `sql.matrix.${methodCode}`, ordinal, rawArtifactId, methodCode, processorPrincipalId, 'synthetic-matrix', '1.0.0', sha256('{}'),
      '2026-01-03T12:20:00.000Z', '2026-01-03T12:20:01.000Z', 'succeeded', null, secondReceiptId, 2, '2026-01-03T12:20:02.000Z',
    )
    runRows.push(createRun('ocr', 1, 3), createRun('normalization', 2, 3), createRun('manual_transcription', 3, 2))
    const invalidKinds = new Map([
      ['content_decoding', 'extracted_text'],
      ['parser', 'decoded_body'],
      ['ocr', 'extracted_text'],
      ['normalization', 'structured_data'],
      ['manual_transcription', 'ocr_text'],
    ])
    for (const [ordinal, run] of runRows.entries()) {
      assert.throws(
        () => database.prepare(`INSERT INTO atlas_processing_outputs(
          processing_output_code,processing_run_id,artifact_id,output_ordinal,output_kind_code,detected_media_type,
          produced_at,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
        )VALUES(?,?,?,?,?,?,?,?,?,?)`).run(
          `sql.matrix.invalid-output.${run.method_code}`, run.id, outputArtifactId, 900 + ordinal, invalidKinds.get(run.method_code), 'text/plain',
          run.started_at, run.evidence_bundle_receipt_id, run.recorded_by_principal_id, run.recorded_at,
        ),
        /processing method\/output kind mismatch/,
        `raw SQL accepted an invalid ${run.method_code} output kind`,
      )
    }
  } finally {
    database.exec('ROLLBACK')
  }
  assert.deepEqual(atlasState(database), beforeDirectMethodMatrix, 'direct processing method/output probes changed evidence state')
  assert.throws(
    () => invalidProcessorKindInsert.run(
      'sql.invalid-parser-human', 1, rawArtifactId, 'parser', 2, 'synthetic', '1.0.0', 'b'.repeat(64),
      '2026-01-03T01:00:00.000Z', '2026-01-03T01:00:01.000Z', 'failed', 'wrong_principal_kind', secondReceiptId, 2, '2026-01-03T01:00:02.000Z',
    ),
    /invalid processing attribution or chronology/,
  )
  assert.throws(
    () => invalidProcessorKindInsert.run(
      'sql.invalid-importer-processor', 1, rawArtifactId, 'parser', 4, 'synthetic', '1.0.0', 'c'.repeat(64),
      '2026-01-03T01:00:00.000Z', '2026-01-03T01:00:01.000Z', 'failed', 'wrong_principal_role', secondReceiptId, 2, '2026-01-03T01:00:02.000Z',
    ),
    /invalid processing attribution or chronology/,
  )
  const beforeDirectCycle = atlasState(database)
  database.exec('BEGIN IMMEDIATE')
  try {
    const jsonArtifactId = database.prepare("SELECT id FROM atlas_artifacts WHERE artifact_code=(SELECT a.artifact_code FROM atlas_artifacts a JOIN atlas_processing_outputs o ON o.artifact_id=a.id WHERE o.processing_output_code='pilot-bundle-001.output-json')").get().id
    const decodedArtifactId = database.prepare("SELECT id FROM atlas_artifacts WHERE artifact_code=(SELECT a.artifact_code FROM atlas_artifacts a JOIN atlas_processing_outputs o ON o.artifact_id=a.id WHERE o.processing_output_code='pilot-bundle-001.output-decoded')").get().id
    const cycleTime = '2026-01-03T02:00:00.000Z'
    const cycleRunId = database.prepare(`INSERT INTO atlas_processing_runs(
      processing_run_code,run_ordinal,input_artifact_id,method_code,processor_principal_id,processor_software_code,processor_version,
      configuration_sha256,started_at,completed_at,outcome_code,failure_code,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
    )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`).get(
      'sql.ancestor-cycle-run', 1, jsonArtifactId, 'parser', 3, 'synthetic-parser', '1.0.0', sha256('{}'),
      cycleTime, cycleTime, 'succeeded', null, secondReceiptId, 2, cycleTime,
    ).id
    assert.throws(
      () => database.prepare(`INSERT INTO atlas_processing_outputs(
        processing_output_code,processing_run_id,artifact_id,output_ordinal,output_kind_code,detected_media_type,
        produced_at,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
      )VALUES(?,?,?,?,?,?,?,?,?,?)`).run(
        'sql.ancestor-cycle-output', cycleRunId, decodedArtifactId, 0, 'extracted_text', 'application/octet-stream',
        cycleTime, secondReceiptId, 2, cycleTime,
      ),
      /processing lineage cycle/,
    )
  } finally {
    database.exec('ROLLBACK')
  }
  assert.deepEqual(atlasState(database), beforeDirectCycle, 'direct SQL cycle probe changed evidence state')
  assert.deepEqual(legacyDigests(upgradeDatabasePath), legacyBefore)
  assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok')
  assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(), [])

  const atlasTables = ['atlas_principals', 'atlas_languages', 'atlas_jurisdictions', 'atlas_jurisdiction_versions', ...tables]
  const canonicalAtlasDigests = Object.fromEntries(atlasTables.map((table) => [table, digestTable(database, table)]))
  const rebuildDatabasePath = path.join(freshRoot, 'deterministic-rebuild.sqlite')
  applyMigrations({ databasePath: rebuildDatabasePath, migrationsDirectory: designMigrations })
  const rebuildDatabase = openDatabase(rebuildDatabasePath)
  assert.equal(simulateImport({ database: rebuildDatabase, ...firstInput, schema, adapter: environment.adapter, ...importerRuntime }), 'imported')
  assert.equal(simulateImport({ database: rebuildDatabase, ...secondInput, schema, adapter: environment.adapter, ...importerRuntime }), 'imported')
  assert.deepEqual(
    Object.fromEntries(atlasTables.map((table) => [table, digestTable(rebuildDatabase, table)])),
    canonicalAtlasDigests,
  )
  rebuildDatabase.close()

  database.close()
  database = openDatabase(upgradeDatabasePath, false)
  for (const table of tables) {
    assert.throws(() => database.exec(`UPDATE ${table} SET id=id WHERE id=(SELECT min(id) FROM ${table})`), /immutable/)
    assert.throws(() => database.exec(`DELETE FROM ${table} WHERE id=(SELECT min(id) FROM ${table})`), /immutable/)
    assert.throws(() => database.exec(`INSERT OR REPLACE INTO ${table} SELECT * FROM ${table} WHERE id=(SELECT min(id) FROM ${table})`), /collision/)
  }

  let adversarialSequence = 0
  const adversarialToken = (prefix) => `${prefix}.${String(++adversarialSequence).padStart(3, '0')}`
  const nextId = (table) => database.prepare(`SELECT max(id)+1000 AS id FROM ${table}`).get().id + adversarialSequence
  const one = (table, where = '1', ...parameters) => ({ ...database.prepare(`SELECT * FROM ${table} WHERE ${where} ORDER BY id LIMIT 1`).get(...parameters) })
  const receipt2 = one('atlas_evidence_bundle_receipts', 'bundle_sequence=2')
  const freshReceipt = (label) => {
    const token = adversarialToken(label)
    const created = '2026-01-05T00:00:00.000Z'
    return {
      ...receipt2,
      id: nextId('atlas_evidence_bundle_receipts'),
      bundle_sequence: 3,
      bundle_code: `replace.bundle.${token}`,
      bundle_digest_sha256: sha256(`replace receipt ${token}`),
      manifest_path: `replace/${token}.json`,
      bundle_created_at: created,
      recorded_at: created,
    }
  }
  const freshLocation = (label) => {
    const token = adversarialToken(label)
    return {
      ...one('atlas_retrieval_locations'),
      id: nextId('atlas_retrieval_locations'),
      location_code: `replace.location.${token}`,
      location_url: `https://replace.invalid/${token}`,
      evidence_bundle_receipt_id: receipt2.id,
      recorded_by_principal_id: receipt2.submitted_by_principal_id,
      recorded_at: '2026-01-03T12:00:00.000Z',
    }
  }
  const freshArtifact = (label) => {
    const token = adversarialToken(label)
    const digest = sha256(`replace artifact ${token}`)
    const length = Buffer.byteLength(token)
    return {
      ...one('atlas_artifacts'),
      id: nextId('atlas_artifacts'),
      artifact_code: artifactCode('derived_output', digest, length),
      byte_layer_code: 'derived_output',
      hash_algorithm_code: 'sha256',
      sha256: digest,
      byte_length: length,
      evidence_bundle_receipt_id: receipt2.id,
      recorded_by_principal_id: receipt2.submitted_by_principal_id,
      recorded_at: '2026-01-03T12:00:00.000Z',
    }
  }
  const freshRetrieval = (label) => ({
    ...one('atlas_retrieval_events', "outcome_code='network_failed'"),
    id: nextId('atlas_retrieval_events'),
    retrieval_event_code: `replace.retrieval.${adversarialToken(label)}`,
  })
  const freshRedirect = (label) => ({
    ...one('atlas_retrieval_redirects'),
    id: nextId('atlas_retrieval_redirects'),
    redirect_code: `replace.redirect.${adversarialToken(label)}`,
    hop_ordinal: 99,
  })
  const freshCustodyRoot = (label) => ({
    ...one('atlas_artifact_custody_events', "event_kind_code='placed'"),
    id: nextId('atlas_artifact_custody_events'),
    custody_event_code: `replace.custody.${adversarialToken(label)}`,
    copy_code: `replace.copy.${adversarialSequence}`,
  })
  const freshRun = (label) => ({
    ...one('atlas_processing_runs', "outcome_code='failed'"),
    id: nextId('atlas_processing_runs'),
    processing_run_code: `replace.run.${adversarialToken(label)}`,
    run_ordinal: database.prepare('SELECT COALESCE(max(run_ordinal),-1)+1 AS ordinal FROM atlas_processing_runs WHERE evidence_bundle_receipt_id=?').get(receipt2.id).ordinal,
    input_artifact_id: one('atlas_artifacts', "byte_layer_code='retrieved_body'").id,
    method_code: 'parser',
    evidence_bundle_receipt_id: receipt2.id,
    recorded_by_principal_id: receipt2.submitted_by_principal_id,
    started_at: '2026-01-03T12:00:00.000Z',
    completed_at: '2026-01-03T12:00:01.000Z',
    recorded_at: '2026-01-03T12:00:02.000Z',
  })
  const freshOutput = (label) => ({
    ...one('atlas_processing_outputs'),
    id: nextId('atlas_processing_outputs'),
    processing_output_code: `replace.output.${adversarialToken(label)}`,
    output_ordinal: 99,
  })
  const freshCandidateRoot = (label) => ({
    ...one('atlas_unverified_candidate_occurrences', "record_kind_code='assertion'"),
    id: nextId('atlas_unverified_candidate_occurrences'),
    candidate_record_code: `replace.candidate.${adversarialToken(label)}`,
    candidate_chain_code: `replace.chain.${adversarialSequence}`,
  })

  const freshRows = {
    atlas_evidence_bundle_receipts: freshReceipt,
    atlas_retrieval_locations: freshLocation,
    atlas_artifacts: freshArtifact,
    atlas_retrieval_events: freshRetrieval,
    atlas_retrieval_redirects: freshRedirect,
    atlas_artifact_custody_events: freshCustodyRoot,
    atlas_processing_runs: freshRun,
    atlas_processing_outputs: freshOutput,
    atlas_unverified_candidate_occurrences: freshCandidateRoot,
  }

  for (const [table, factory] of Object.entries(freshRows)) {
    const existingId = database.prepare(`SELECT min(id) AS id FROM ${table}`).get().id
    assertInsertOrReplaceRejected(database, table, 'primary-key collision', { ...factory(`${table}.pk`), id: existingId })
    assertInvalidTypedIdRejected(database, table, factory(`${table}.typed-id`))
  }
  assertStrictValueRejected(database, 'atlas_evidence_bundle_receipts', freshReceipt('receipt.integer-type'), 'bundle_sequence', 'not-an-integer')
  assertStrictValueRejected(database, 'atlas_evidence_bundle_receipts', freshReceipt('receipt.text-type'), 'bundle_code', Buffer.from('not-text'))

  const receiptSource = one('atlas_evidence_bundle_receipts')
  assertInsertOrReplaceRejected(database, 'atlas_evidence_bundle_receipts', 'bundle_code unique key', { ...freshReceipt('receipt.code'), bundle_code: receiptSource.bundle_code })
  assertInsertOrReplaceRejected(database, 'atlas_evidence_bundle_receipts', 'bundle_sequence unique key', { ...freshReceipt('receipt.sequence'), bundle_sequence: receiptSource.bundle_sequence })
  assertInsertOrReplaceRejected(database, 'atlas_evidence_bundle_receipts', 'bundle_digest unique key', { ...freshReceipt('receipt.digest'), bundle_digest_sha256: receiptSource.bundle_digest_sha256 })
  assertInsertOrReplaceRejected(database, 'atlas_evidence_bundle_receipts', 'manifest_path unique key', { ...freshReceipt('receipt.path'), manifest_path: receiptSource.manifest_path })

  const locationSource = one('atlas_retrieval_locations')
  assertInsertOrReplaceRejected(database, 'atlas_retrieval_locations', 'location_code unique key', { ...freshLocation('location.code'), location_code: locationSource.location_code })
  assertInsertOrReplaceRejected(database, 'atlas_retrieval_locations', 'location_url unique key', { ...freshLocation('location.url'), location_url: locationSource.location_url })

  const artifactSource = one('atlas_artifacts')
  assertInsertOrReplaceRejected(database, 'atlas_artifacts', 'artifact_code unique key', { ...freshArtifact('artifact.code'), artifact_code: artifactSource.artifact_code })
  const artifactIdentityCollision = freshArtifact('artifact.identity')
  Object.assign(artifactIdentityCollision, {
    byte_layer_code: artifactSource.byte_layer_code,
    hash_algorithm_code: artifactSource.hash_algorithm_code,
    sha256: artifactSource.sha256,
    byte_length: artifactSource.byte_length,
  })
  assertInsertOrReplaceRejected(database, 'atlas_artifacts', 'byte-layer/hash/length unique key', artifactIdentityCollision)

  const retrievalSource = one('atlas_retrieval_events')
  assertInsertOrReplaceRejected(database, 'atlas_retrieval_events', 'retrieval_event_code unique key', { ...freshRetrieval('retrieval.code'), retrieval_event_code: retrievalSource.retrieval_event_code })

  const redirectSource = one('atlas_retrieval_redirects')
  assertInsertOrReplaceRejected(database, 'atlas_retrieval_redirects', 'redirect_code unique key', { ...freshRedirect('redirect.code'), redirect_code: redirectSource.redirect_code })
  assertInsertOrReplaceRejected(database, 'atlas_retrieval_redirects', 'retrieval-event/ordinal unique key', { ...freshRedirect('redirect.ordinal'), retrieval_event_id: redirectSource.retrieval_event_id, hop_ordinal: redirectSource.hop_ordinal })

  const custodyRootSource = one('atlas_artifact_custody_events', 'predecessor_custody_event_id IS NULL')
  const custodySuccessorSource = one('atlas_artifact_custody_events', 'predecessor_custody_event_id IS NOT NULL')
  assertInsertOrReplaceRejected(database, 'atlas_artifact_custody_events', 'custody_event_code unique key', { ...freshCustodyRoot('custody.code'), custody_event_code: custodyRootSource.custody_event_code })
  assertInsertOrReplaceRejected(database, 'atlas_artifact_custody_events', 'custody root partial unique key', { ...freshCustodyRoot('custody.root'), artifact_id: custodyRootSource.artifact_id, copy_code: custodyRootSource.copy_code })
  assertInsertOrReplaceRejected(database, 'atlas_artifact_custody_events', 'custody predecessor partial unique key', {
    ...custodySuccessorSource,
    id: nextId('atlas_artifact_custody_events'),
    custody_event_code: `replace.custody.${adversarialToken('custody.predecessor')}`,
  })

  const runSource = one('atlas_processing_runs')
  assertInsertOrReplaceRejected(database, 'atlas_processing_runs', 'processing_run_code unique key', { ...freshRun('run.code'), processing_run_code: runSource.processing_run_code })
  assertInsertOrReplaceRejected(database, 'atlas_processing_runs', 'receipt/ordinal unique key', { ...freshRun('run.ordinal'), evidence_bundle_receipt_id: runSource.evidence_bundle_receipt_id, run_ordinal: runSource.run_ordinal })

  const outputSource = one('atlas_processing_outputs')
  assertInsertOrReplaceRejected(database, 'atlas_processing_outputs', 'processing_output_code unique key', { ...freshOutput('output.code'), processing_output_code: outputSource.processing_output_code })
  assertInsertOrReplaceRejected(database, 'atlas_processing_outputs', 'run/ordinal unique key', { ...freshOutput('output.ordinal'), processing_run_id: outputSource.processing_run_id, output_ordinal: outputSource.output_ordinal })
  assertInsertOrReplaceRejected(database, 'atlas_processing_outputs', 'id/run supporting unique key (subsumed by PK)', { ...freshOutput('output.id-run'), id: outputSource.id, processing_run_id: outputSource.processing_run_id })

  const candidateSource = one('atlas_unverified_candidate_occurrences')
  const candidateRootSource = one('atlas_unverified_candidate_occurrences', 'corrects_candidate_occurrence_id IS NULL')
  const candidateSuccessorSource = one('atlas_unverified_candidate_occurrences', 'corrects_candidate_occurrence_id IS NOT NULL')
  assertInsertOrReplaceRejected(database, 'atlas_unverified_candidate_occurrences', 'candidate_record_code unique key', { ...freshCandidateRoot('candidate.code'), candidate_record_code: candidateSource.candidate_record_code })
  assertInsertOrReplaceRejected(database, 'atlas_unverified_candidate_occurrences', 'candidate root partial unique key', { ...freshCandidateRoot('candidate.root'), candidate_chain_code: candidateRootSource.candidate_chain_code })
  assertInsertOrReplaceRejected(database, 'atlas_unverified_candidate_occurrences', 'candidate predecessor partial unique key', {
    ...candidateSuccessorSource,
    id: nextId('atlas_unverified_candidate_occurrences'),
    candidate_record_code: `replace.candidate.${adversarialToken('candidate.predecessor')}`,
  })
  database.close()

  const rollbackRoot = temporaryDirectory('jedi-2a-rollback-')
  const rollbackDatabasePath = path.join(rollbackRoot, 'rollback.sqlite')
  applyMigrations({ databasePath: rollbackDatabasePath, migrationsDirectory: designMigrations })
  const rollbackEnvironment = syntheticEnvironment()
  const rollbackManifest = syntheticFirstBundle(rollbackEnvironment)
  const rollbackInput = materializeManifest(rollbackEnvironment, rollbackManifest)
  database = openDatabase(rollbackDatabasePath)
  const rollbackBefore = atlasState(database)
  let observedCompleteTransactionalProjection = false
  assert.throws(() => simulateImport({
    database,
    ...rollbackInput,
    schema,
    adapter: rollbackEnvironment.adapter,
    ...importerRuntime,
    injectFailure: true,
    beforeInjectedFailure: (openTransactionDatabase) => {
      const inTransaction = atlasState(openTransactionDatabase)
      for (const [table, state] of Object.entries(inTransaction)) {
        assert.ok(state.count > rollbackBefore[table].count, `${table} had no inserted row at the failure point`)
        assert.notEqual(state.digest, rollbackBefore[table].digest, `${table} digest was unchanged at the failure point`)
      }
      observedCompleteTransactionalProjection = true
    },
  }), /injected failure after complete evidence projection/)
  assert.equal(observedCompleteTransactionalProjection, true, 'rollback injection did not observe all evidence tables')
  assert.deepEqual(atlasState(database), rollbackBefore, 'failed bundle did not restore every pre-transaction count and digest')
  database.close()

  console.log(JSON.stringify({
    scope: 'design validator only; no production importer, adapter, authentication, or authorization guarantee',
    fresh_install: 'passed',
    upgrade_from_004: 'passed',
    no_op_migration_rerun: 'passed',
    migrations_001_004_unchanged: 'passed',
    legacy_digests_preserved: legacyTables.length,
    legacy_schema_definitions_preserved: 'passed',
    deleted_legacy_index_mutation_rejected: 'passed',
    actual_json_schema_execution: 'passed',
    raw_utf8_duplicate_key_and_number_profile: 'passed',
    manifest_redirect_attribution_and_chronology: 'passed',
    sqlite_bootstrap_exclusion_and_chronology: 'passed',
    independent_canonical_golden_vectors_and_mutations: 'passed',
    canonical_bundle_and_configuration_digests: 'passed',
    cross_bundle_dependency_and_sequence: 'passed',
    exact_get_representation_and_304_guards: 'passed',
    cross_bundle_304_custody_and_candidate_successors: 'passed',
    acyclic_retrieval_grounded_processing_lineage: 'passed',
    direct_sql_ancestor_cycle_guard: 'passed',
    repeated_derived_artifact_lineage: 'passed',
    staged_and_custody_bytes_verified: 'passed',
    processing_input_and_locator_bytes_verified: 'passed',
    content_address_and_symlink_confinement: 'passed',
    retrieval_outcome_boundaries: 'passed',
    redirected_and_conditional_network_failures: 'passed',
    http_200_304_etag_date_content_coding_vary_profile: 'passed',
    processing_method_output_configuration_matrix: 'passed',
    event_time_and_receipt_sequence_custody_projection: 'passed',
    candidate_knowledge_time_projection: 'passed',
    correction_cycle_and_wrong_subject_rejection: 'passed',
    custody_access_state_transitions: 'passed',
    processing_principal_kind_rules: 'passed',
    collector_processor_importer_separation: 'passed',
    deterministic_two_bundle_rebuild: 'passed',
    complete_nine_table_projection_before_commit_and_no_op: 'passed',
    persisted_drift_mutation_matrix: 'passed',
    semantic_preflight_before_begin_matrix: 'passed',
    tombstoned_historical_copy_not_required_for_no_op: 'passed',
    non_vacuous_all_table_transactional_rollback: 'passed',
    exact_physical_schema_introspection: 'passed',
    fixed_table_and_trigger_definition_hashes: 'passed',
    schema_definition_mutants_rejected: schemaMutationMatrix.map(([label]) => label),
    behavioral_sql_mutants_rejected: ['receipt-sha-check', 'candidate-successor-chronology'],
    strict_types_and_positive_ids: 'passed',
    recursive_triggers_off_all_unique_key_replace_protection: 'passed',
    no_op_persisted_drift_mutations_rejected: noOpMutations.map(([label]) => label),
    integrity_check: 'ok',
    foreign_key_check: 'clean',
    objects: { tables, indexes: indexes.toSorted(), triggers },
  }, null, 2))
} finally {
  for (const directory of cleanup) fs.rmSync(directory, { recursive: true, force: true })
}
