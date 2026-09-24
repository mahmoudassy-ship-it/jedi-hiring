import fs from 'node:fs'
import path from 'node:path'
import { createHash, randomUUID } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { assertCanonicalBcp47 } from '../../docs/schema/bcp47.mjs'

export const RESEARCH_SCHEMA_VERSION = '1.0.0'
export const RESEARCH_STATUSES = Object.freeze([
  'discovered_unverified',
  'metadata_checked_single_researcher',
  'draft_proposition_unreviewed',
  'awaiting_independent_review',
])

export const RESEARCH_TABLES = Object.freeze([
  'research_automation_suggestions',
  'research_builds',
  'research_editorial_notes',
  'research_expected_identifiers',
  'research_manifests',
  'research_monitoring_candidates',
  'research_proposition_citations',
  'research_proposition_drafts',
  'research_sources',
])

const SOURCE_STATUSES = new Set(RESEARCH_STATUSES.slice(0, 2))
const PROPOSITION_STATUSES = new Set(RESEARCH_STATUSES.slice(2))
const EFFECTS = new Set(['obligation', 'prohibition', 'permission', 'right', 'exception', 'defence'])
const EDITORIAL_KINDS = new Set(['legal_interpretation', 'operational_recommendation', 'inclusion_opportunity'])
const LOCATOR_KINDS = new Set(['article', 'paragraph', 'section', 'annex', 'recital', 'page', 'other'])
const DISCOVERY_METHODS = new Set(['manual_official_site', 'manual_official_registry', 'automated_suggestion'])
const MONITOR_METHODS = new Set(['manual_landing_page_check', 'manual_identifier_search'])
const CHANGE_SIGNALS = new Set(['metadata_change', 'new_version', 'corrigendum', 'amendment', 'repeal', 'new_guidance', 'unknown_change'])
const AUTOMATION_SCOPES = new Set(['source_discovery', 'metadata_suggestion', 'proposition_draft', 'editorial_draft', 'monitoring_suggestion'])
const AUTOMATION_DISPOSITIONS = new Set(['unreviewed_suggestion', 'human_incorporated_into_unreviewed_draft', 'rejected'])
const STABLE_CODE = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])$/
const DATE = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$/
const TIMESTAMP = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/
const SHA256 = /^[0-9a-f]{64}$/
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i
const PHONE = /(?:^|[^a-z0-9])\+?\d[\d .()/-]{7,}\d(?:$|[^a-z0-9])/i
const IPV4 = /(?:^|[^\d])(?:\d{1,3}\.){3}\d{1,3}(?:$|[^\d])/
const SECRET_VALUE = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]+=*|\b(?:api[_-]?key|private[_-]?key|signing[_-]?key|access[_-]?token|refresh[_-]?token|password)\s*[:=]\s*\S+|\bgh[pousr]_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16})/i
const EMBEDDED_BYTES = /(?:\bdata:[^,]{0,100};base64,|\b[A-Za-z0-9+/]{160,}={0,2}\b)/
const manifestSchema = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../schema/research-candidate-manifest-v1.schema.json'), 'utf8'))

const DDL = `
CREATE TABLE research_builds (
  build_code TEXT PRIMARY KEY CHECK (build_code = 'manifest_projection_v1'),
  schema_version TEXT NOT NULL CHECK (schema_version = '1.0.0'),
  manifest_set_sha256 TEXT NOT NULL CHECK (length(manifest_set_sha256) = 64 AND manifest_set_sha256 = lower(manifest_set_sha256)),
  manifest_count INTEGER NOT NULL CHECK (manifest_count >= 0)
) STRICT;
CREATE TABLE research_manifests (
  manifest_code TEXT PRIMARY KEY,
  manifest_path TEXT NOT NULL UNIQUE,
  manifest_sha256 TEXT NOT NULL UNIQUE CHECK (length(manifest_sha256) = 64 AND manifest_sha256 = lower(manifest_sha256)),
  recorded_at TEXT NOT NULL,
  synthetic_fixture INTEGER NOT NULL CHECK (synthetic_fixture IN (0, 1)),
  prepared_by_role_code TEXT NOT NULL CHECK (prepared_by_role_code = 'single_operator_researcher'),
  preparation_mode_code TEXT NOT NULL CHECK (preparation_mode_code IN ('human_only', 'human_with_automation'))
) STRICT;
CREATE TABLE research_sources (
  source_candidate_code TEXT PRIMARY KEY,
  manifest_code TEXT NOT NULL UNIQUE REFERENCES research_manifests(manifest_code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  status_code TEXT NOT NULL CHECK (status_code IN ('discovered_unverified', 'metadata_checked_single_researcher')),
  official_landing_url_candidate TEXT NOT NULL,
  jurisdiction_candidate_code TEXT NOT NULL,
  document_family_code TEXT NOT NULL,
  language_tag TEXT NOT NULL,
  discovered_on TEXT NOT NULL,
  notes TEXT NOT NULL,
  discovery_method_code TEXT NOT NULL CHECK (discovery_method_code IN ('manual_official_site', 'manual_official_registry', 'automated_suggestion')),
  source_scope_note TEXT NOT NULL,
  limitations_json TEXT NOT NULL,
  personal_data_declaration_code TEXT NOT NULL CHECK (personal_data_declaration_code = 'none_present')
) STRICT;
CREATE TABLE research_expected_identifiers (
  source_candidate_code TEXT NOT NULL REFERENCES research_sources(source_candidate_code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
  scheme_code TEXT NOT NULL,
  expected_value TEXT NOT NULL,
  PRIMARY KEY (source_candidate_code, ordinal),
  UNIQUE (source_candidate_code, scheme_code, expected_value)
) STRICT;
CREATE TABLE research_proposition_drafts (
  proposition_code TEXT PRIMARY KEY,
  manifest_code TEXT NOT NULL REFERENCES research_manifests(manifest_code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  status_code TEXT NOT NULL CHECK (status_code IN ('draft_proposition_unreviewed', 'awaiting_independent_review')),
  normative_effect_code TEXT NOT NULL CHECK (normative_effect_code IN ('obligation', 'prohibition', 'permission', 'right', 'exception', 'defence')),
  actor_text TEXT NOT NULL,
  normative_action_text TEXT NOT NULL,
  subject_text TEXT NOT NULL,
  jurisdiction_candidate_code TEXT NOT NULL,
  proposition_paraphrase TEXT NOT NULL,
  applicability_conditions_json TEXT NOT NULL,
  uncertainty_note TEXT NOT NULL
) STRICT;
CREATE TABLE research_proposition_citations (
  proposition_code TEXT PRIMARY KEY REFERENCES research_proposition_drafts(proposition_code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  source_candidate_code TEXT NOT NULL REFERENCES research_sources(source_candidate_code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  locator_kind_code TEXT NOT NULL CHECK (locator_kind_code IN ('article', 'paragraph', 'section', 'annex', 'recital', 'page', 'other')),
  locator_value TEXT NOT NULL
) STRICT;
CREATE TABLE research_editorial_notes (
  editorial_note_code TEXT PRIMARY KEY,
  proposition_code TEXT NOT NULL REFERENCES research_proposition_drafts(proposition_code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  kind_code TEXT NOT NULL CHECK (kind_code IN ('legal_interpretation', 'operational_recommendation', 'inclusion_opportunity')),
  note_text TEXT NOT NULL,
  status_code TEXT NOT NULL CHECK (status_code = 'unreviewed_editorial')
) STRICT;
CREATE TABLE research_monitoring_candidates (
  monitoring_candidate_code TEXT PRIMARY KEY,
  source_candidate_code TEXT NOT NULL REFERENCES research_sources(source_candidate_code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  method_code TEXT NOT NULL CHECK (method_code IN ('manual_landing_page_check', 'manual_identifier_search')),
  target_url_candidate TEXT NOT NULL,
  cadence_note TEXT NOT NULL,
  change_signal_codes_json TEXT NOT NULL,
  limitations TEXT NOT NULL
) STRICT;
CREATE TABLE research_automation_suggestions (
  suggestion_code TEXT PRIMARY KEY,
  manifest_code TEXT NOT NULL REFERENCES research_manifests(manifest_code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  tool_code TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  scope_code TEXT NOT NULL CHECK (scope_code IN ('source_discovery', 'metadata_suggestion', 'proposition_draft', 'editorial_draft', 'monitoring_suggestion')),
  disposition_code TEXT NOT NULL CHECK (disposition_code IN ('unreviewed_suggestion', 'human_incorporated_into_unreviewed_draft', 'rejected'))
) STRICT;
`

export class ResearchTrackError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'ResearchTrackError'
    this.code = code
  }
}

function reject(code, message) {
  throw new ResearchTrackError(code, message)
}

function validateAgainstManifestSchema(value, rule, root = manifestSchema, location = '$') {
  if (rule.$ref) {
    const target = rule.$ref.split('/').slice(1).reduce((current, segment) => current?.[segment.replaceAll('~1', '/').replaceAll('~0', '~')], root)
    if (!target) reject('SCHEMA_INVALID', `unresolved schema reference ${rule.$ref}`)
    return validateAgainstManifestSchema(value, target, root, location)
  }
  if (Object.hasOwn(rule, 'const') && value !== rule.const) reject('SCHEMA_REJECTED', `${location} violates const`)
  if (rule.enum && !rule.enum.includes(value)) reject('SCHEMA_REJECTED', `${location} violates enum`)
  if (rule.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) reject('SCHEMA_REJECTED', `${location} must be object`)
    for (const required of rule.required ?? []) if (!Object.hasOwn(value, required)) reject('SCHEMA_REJECTED', `${location}.${required} is required`)
    if (rule.additionalProperties === false) {
      for (const key of Object.keys(value)) if (!Object.hasOwn(rule.properties ?? {}, key)) reject('SCHEMA_REJECTED', `${location}.${key} is unknown`)
    }
    for (const [key, child] of Object.entries(rule.properties ?? {})) {
      if (Object.hasOwn(value, key)) validateAgainstManifestSchema(value[key], child, root, `${location}.${key}`)
    }
  } else if (rule.type === 'array') {
    if (!Array.isArray(value)) reject('SCHEMA_REJECTED', `${location} must be array`)
    if (rule.minItems !== undefined && value.length < rule.minItems) reject('SCHEMA_REJECTED', `${location} has too few items`)
    if (rule.maxItems !== undefined && value.length > rule.maxItems) reject('SCHEMA_REJECTED', `${location} has too many items`)
    value.forEach((item, index) => validateAgainstManifestSchema(item, rule.items, root, `${location}[${index}]`))
  } else if (rule.type === 'string') {
    if (typeof value !== 'string') reject('SCHEMA_REJECTED', `${location} must be string`)
    if (rule.minLength !== undefined && value.length < rule.minLength) reject('SCHEMA_REJECTED', `${location} is too short`)
    if (rule.maxLength !== undefined && value.length > rule.maxLength) reject('SCHEMA_REJECTED', `${location} is too long`)
    if (rule.pattern && !new RegExp(rule.pattern, 'u').test(value)) reject('SCHEMA_REJECTED', `${location} violates pattern`)
  } else if (rule.type === 'boolean' && typeof value !== 'boolean') {
    reject('SCHEMA_REJECTED', `${location} must be boolean`)
  }
}

export function canonicalize(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
  }
  reject('CANONICAL_VALUE_INVALID', `Unsupported canonical value type: ${typeof value}`)
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

export function manifestDigest(manifest) {
  const { canonical_digest_sha256: _excluded, ...payload } = manifest
  return sha256(Buffer.from(canonicalize(payload), 'utf8'))
}

// The repository intentionally has no JSON dependency. This small parser
// rejects duplicate object keys before semantic validation.
export function parseJsonNoDuplicateKeys(text, label = 'JSON') {
  let offset = 0
  const fail = (message) => reject('JSON_INVALID', `${label}: ${message} at byte ${Buffer.byteLength(text.slice(0, offset), 'utf8')}`)
  const whitespace = () => { while ([' ', '\t', '\r', '\n'].includes(text[offset])) offset += 1 }
  const string = () => {
    if (text[offset] !== '"') fail('expected string')
    const start = offset
    offset += 1
    let escaped = false
    while (offset < text.length) {
      const character = text[offset]
      if (!escaped && character === '"') {
        offset += 1
        try { return JSON.parse(text.slice(start, offset)) } catch { fail('invalid string') }
      }
      if (!escaped && character.charCodeAt(0) < 0x20) fail('unescaped control character')
      if (!escaped && character === '\\') escaped = true
      else escaped = false
      offset += 1
    }
    fail('unterminated string')
  }
  const value = () => {
    whitespace()
    if (text[offset] === '"') return string()
    if (text[offset] === '{') {
      offset += 1
      whitespace()
      const result = {}
      const keys = new Set()
      if (text[offset] === '}') { offset += 1; return result }
      while (true) {
        whitespace()
        const key = string()
        if (keys.has(key)) fail(`duplicate object key ${JSON.stringify(key)}`)
        keys.add(key)
        whitespace()
        if (text[offset] !== ':') fail('expected colon')
        offset += 1
        result[key] = value()
        whitespace()
        if (text[offset] === '}') { offset += 1; return result }
        if (text[offset] !== ',') fail('expected comma')
        offset += 1
      }
    }
    if (text[offset] === '[') {
      offset += 1
      whitespace()
      const result = []
      if (text[offset] === ']') { offset += 1; return result }
      while (true) {
        result.push(value())
        whitespace()
        if (text[offset] === ']') { offset += 1; return result }
        if (text[offset] !== ',') fail('expected comma')
        offset += 1
      }
    }
    for (const [literal, parsed] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(literal, offset)) { offset += literal.length; return parsed }
    }
    fail('numbers and unknown literals are prohibited')
  }
  const parsed = value()
  whitespace()
  if (offset !== text.length) fail('trailing content')
  return parsed
}

function exactKeys(value, required, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject('SHAPE_INVALID', `${label} must be an object`)
  const actual = Object.keys(value).sort()
  const expected = [...required].sort()
  if (canonicalize(actual) !== canonicalize(expected)) reject('UNKNOWN_OR_MISSING_FIELD', `${label} fields must be exactly: ${expected.join(', ')}`)
}

function text(value, label, maximum = 2000) {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0') || Buffer.byteLength(value, 'utf8') > maximum) {
    reject('TEXT_INVALID', `${label} must be nonblank, NUL-free and at most ${maximum} UTF-8 bytes`)
  }
  if (SECRET_VALUE.test(value)) reject('SECRET_DETECTED', `${label} appears to contain a credential or secret`)
  if (EMBEDDED_BYTES.test(value)) reject('EMBEDDED_BYTES_PROHIBITED', `${label} appears to contain embedded source bytes`)
  if (EMAIL.test(value) || PHONE.test(` ${value} `) || IPV4.test(` ${value} `)) {
    reject('PERSONAL_DATA_DETECTED', `${label} contains a prohibited personal-data pattern`)
  }
  return value
}

function code(value, label, maximum = 100, minimum = 3) {
  text(value, label, maximum)
  if (value.length < minimum || !STABLE_CODE.test(value)) reject('CODE_INVALID', `${label} is not a canonical lowercase stable code`)
  return value
}

function oneOf(value, allowed, label) {
  if (!allowed.has(value)) reject('ENUM_INVALID', `${label} is not an allowed value`)
  return value
}

function date(value, label) {
  if (typeof value !== 'string' || !DATE.test(value)) reject('DATE_INVALID', `${label} must be canonical YYYY-MM-DD`)
  const parsed = new Date(`${value}T00:00:00Z`)
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) reject('DATE_INVALID', `${label} is not a calendar date`)
  return value
}

function timestamp(value, label) {
  if (typeof value !== 'string' || !TIMESTAMP.test(value) || new Date(value).toISOString().replace('.000Z', 'Z') !== value) {
    reject('TIMESTAMP_INVALID', `${label} must be a canonical whole-second UTC timestamp`)
  }
  return value
}

function url(value, label) {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0') || Buffer.byteLength(value, 'utf8') > 2048) {
    reject('URL_INVALID', `${label} must be a bounded, nonblank, NUL-free URL`)
  }
  let parsed
  try { parsed = new URL(value) } catch { reject('URL_INVALID', `${label} is not a URL`) }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || parsed.hostname === '') {
    reject('URL_INVALID', `${label} must be a credential-free HTTPS landing URL without a fragment`)
  }
  text(value, label, 2048)
  for (const name of parsed.searchParams.keys()) {
    if (/(?:token|secret|key|password|auth|signature)/i.test(name)) reject('SECRET_DETECTED', `${label} has a prohibited query parameter`)
  }
  return value
}

function stringArray(value, label, { minimum = 0, maximum = 20, allowed } = {}) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) reject('ARRAY_INVALID', `${label} has an invalid item count`)
  const result = value.map((item, index) => allowed ? oneOf(item, allowed, `${label}[${index}]`) : text(item, `${label}[${index}]`, 500))
  if (new Set(result).size !== result.length) reject('ARRAY_INVALID', `${label} contains duplicates`)
  return result
}

export function validateResearchManifest(manifest, { expectedDigest = true } = {}) {
  exactKeys(manifest, ['schema_version', 'manifest_code', 'recorded_at', 'synthetic_fixture', 'personal_data_declaration_code', 'preparation', 'source_candidate', 'proposition_drafts', 'editorial_notes', 'monitoring_candidates', 'canonical_digest_sha256'], 'manifest')
  if (manifest.schema_version !== RESEARCH_SCHEMA_VERSION) reject('VERSION_UNSUPPORTED', 'manifest schema_version is unsupported')
  code(manifest.manifest_code, 'manifest_code')
  timestamp(manifest.recorded_at, 'recorded_at')
  if (typeof manifest.synthetic_fixture !== 'boolean') reject('SHAPE_INVALID', 'synthetic_fixture must be boolean')
  if (manifest.personal_data_declaration_code !== 'none_present') reject('PERSONAL_DATA_PROHIBITED', 'research manifests must declare that no personal data is present')
  if (typeof manifest.canonical_digest_sha256 !== 'string' || !SHA256.test(manifest.canonical_digest_sha256)) reject('HASH_INVALID', 'canonical_digest_sha256 must be lowercase SHA-256')
  if (expectedDigest && manifestDigest(manifest) !== manifest.canonical_digest_sha256) reject('HASH_MISMATCH', 'manifest canonical digest does not match its payload')

  const preparation = manifest.preparation
  exactKeys(preparation, ['prepared_by_role_code', 'preparation_mode_code', 'automation_suggestions'], 'preparation')
  if (preparation.prepared_by_role_code !== 'single_operator_researcher') reject('ATTRIBUTION_INVALID', 'only the non-personal single-operator role code is allowed')
  if (!['human_only', 'human_with_automation'].includes(preparation.preparation_mode_code)) reject('ENUM_INVALID', 'preparation_mode_code is invalid')
  if (!Array.isArray(preparation.automation_suggestions) || preparation.automation_suggestions.length > 50) reject('ARRAY_INVALID', 'automation_suggestions is invalid')
  if (preparation.preparation_mode_code === 'human_only' && preparation.automation_suggestions.length !== 0) reject('AUTOMATION_LABEL_INVALID', 'human_only cannot contain automation suggestions')
  if (preparation.preparation_mode_code === 'human_with_automation' && preparation.automation_suggestions.length === 0) reject('AUTOMATION_LABEL_INVALID', 'human_with_automation requires labelled suggestions')
  const automationCodes = new Set()
  for (const [index, suggestion] of preparation.automation_suggestions.entries()) {
    exactKeys(suggestion, ['suggestion_code', 'tool_code', 'tool_version', 'scope_code', 'disposition_code'], `automation_suggestions[${index}]`)
    code(suggestion.suggestion_code, 'suggestion_code')
    if (automationCodes.has(suggestion.suggestion_code)) reject('CODE_COLLISION', 'automation suggestion code is duplicated')
    automationCodes.add(suggestion.suggestion_code)
    code(suggestion.tool_code, 'tool_code', 64, 2)
    text(suggestion.tool_version, 'tool_version', 500)
    oneOf(suggestion.scope_code, AUTOMATION_SCOPES, 'scope_code')
    oneOf(suggestion.disposition_code, AUTOMATION_DISPOSITIONS, 'disposition_code')
  }

  const source = manifest.source_candidate
  exactKeys(source, ['source_candidate_code', 'status_code', 'official_landing_url_candidate', 'expected_identifiers', 'jurisdiction_candidate_code', 'document_family_code', 'language_tag', 'discovered_on', 'notes', 'provenance_candidate'], 'source_candidate')
  code(source.source_candidate_code, 'source_candidate_code')
  oneOf(source.status_code, SOURCE_STATUSES, 'source status_code')
  url(source.official_landing_url_candidate, 'official_landing_url_candidate')
  code(source.jurisdiction_candidate_code, 'jurisdiction_candidate_code', 64, 2)
  code(source.document_family_code, 'document_family_code', 64, 2)
  try { assertCanonicalBcp47(source.language_tag) } catch (error) { reject('LANGUAGE_INVALID', error.message) }
  date(source.discovered_on, 'discovered_on')
  if (source.discovered_on > manifest.recorded_at.slice(0, 10)) reject('CHRONOLOGY_INVALID', 'discovered_on cannot be later than the manifest recorded_at date')
  text(source.notes, 'source notes')
  if (!Array.isArray(source.expected_identifiers) || source.expected_identifiers.length < 1 || source.expected_identifiers.length > 20) reject('ARRAY_INVALID', 'expected_identifiers must contain 1–20 items')
  const identifiers = new Set()
  for (const [index, identifier] of source.expected_identifiers.entries()) {
    exactKeys(identifier, ['scheme_code', 'expected_value'], `expected_identifiers[${index}]`)
    code(identifier.scheme_code, 'identifier scheme_code', 64, 2)
    text(identifier.expected_value, 'identifier expected_value', 500)
    const identity = `${identifier.scheme_code}\0${identifier.expected_value}`
    if (identifiers.has(identity)) reject('CODE_COLLISION', 'expected identifier is duplicated')
    identifiers.add(identity)
  }
  const provenance = source.provenance_candidate
  exactKeys(provenance, ['discovery_method_code', 'source_scope_note', 'limitations'], 'provenance_candidate')
  oneOf(provenance.discovery_method_code, DISCOVERY_METHODS, 'discovery_method_code')
  text(provenance.source_scope_note, 'source_scope_note')
  stringArray(provenance.limitations, 'provenance limitations', { minimum: 1 })
  if (provenance.discovery_method_code === 'automated_suggestion' && preparation.automation_suggestions.every(({ scope_code }) => scope_code !== 'source_discovery')) {
    reject('AUTOMATION_LABEL_INVALID', 'automated source discovery requires a labelled source_discovery suggestion')
  }

  if (!Array.isArray(manifest.proposition_drafts) || manifest.proposition_drafts.length > 50) reject('ARRAY_INVALID', 'proposition_drafts is invalid')
  const propositions = new Set()
  for (const [index, proposition] of manifest.proposition_drafts.entries()) {
    exactKeys(proposition, ['proposition_code', 'status_code', 'normative_effect_code', 'actor_text', 'normative_action_text', 'subject_text', 'jurisdiction_candidate_code', 'proposition_paraphrase', 'applicability_conditions', 'uncertainty_note', 'citation'], `proposition_drafts[${index}]`)
    code(proposition.proposition_code, 'proposition_code')
    if (propositions.has(proposition.proposition_code)) reject('CODE_COLLISION', 'proposition_code is duplicated')
    propositions.add(proposition.proposition_code)
    oneOf(proposition.status_code, PROPOSITION_STATUSES, 'proposition status_code')
    oneOf(proposition.normative_effect_code, EFFECTS, 'normative_effect_code')
    text(proposition.actor_text, 'actor_text', 500)
    text(proposition.normative_action_text, 'normative_action_text', 500)
    text(proposition.subject_text, 'subject_text', 500)
    code(proposition.jurisdiction_candidate_code, 'proposition jurisdiction_candidate_code', 64, 2)
    text(proposition.proposition_paraphrase, 'proposition_paraphrase')
    stringArray(proposition.applicability_conditions, 'applicability_conditions', { minimum: 1 })
    text(proposition.uncertainty_note, 'uncertainty_note')
    exactKeys(proposition.citation, ['source_candidate_code', 'locator_kind_code', 'locator_value'], 'citation')
    if (proposition.citation.source_candidate_code !== source.source_candidate_code) reject('REFERENCE_INVALID', 'citation must reference the manifest source candidate')
    oneOf(proposition.citation.locator_kind_code, LOCATOR_KINDS, 'locator_kind_code')
    text(proposition.citation.locator_value, 'locator_value', 500)
  }

  if (!Array.isArray(manifest.editorial_notes) || manifest.editorial_notes.length > 100) reject('ARRAY_INVALID', 'editorial_notes is invalid')
  const noteCodes = new Set()
  for (const [index, note] of manifest.editorial_notes.entries()) {
    exactKeys(note, ['editorial_note_code', 'proposition_code', 'kind_code', 'text', 'status_code'], `editorial_notes[${index}]`)
    code(note.editorial_note_code, 'editorial_note_code')
    if (noteCodes.has(note.editorial_note_code)) reject('CODE_COLLISION', 'editorial_note_code is duplicated')
    noteCodes.add(note.editorial_note_code)
    if (!propositions.has(note.proposition_code)) reject('REFERENCE_INVALID', 'editorial note references an unknown proposition')
    oneOf(note.kind_code, EDITORIAL_KINDS, 'editorial kind_code')
    text(note.text, 'editorial note text')
    if (note.status_code !== 'unreviewed_editorial') reject('EDITORIAL_STATUS_INVALID', 'editorial notes must remain unreviewed')
  }

  if (!Array.isArray(manifest.monitoring_candidates) || manifest.monitoring_candidates.length > 20) reject('ARRAY_INVALID', 'monitoring_candidates is invalid')
  const monitorCodes = new Set()
  for (const [index, monitor] of manifest.monitoring_candidates.entries()) {
    exactKeys(monitor, ['monitoring_candidate_code', 'source_candidate_code', 'method_code', 'target_url_candidate', 'cadence_note', 'change_signal_codes', 'limitations'], `monitoring_candidates[${index}]`)
    code(monitor.monitoring_candidate_code, 'monitoring_candidate_code')
    if (monitorCodes.has(monitor.monitoring_candidate_code)) reject('CODE_COLLISION', 'monitoring_candidate_code is duplicated')
    monitorCodes.add(monitor.monitoring_candidate_code)
    if (monitor.source_candidate_code !== source.source_candidate_code) reject('REFERENCE_INVALID', 'monitoring candidate references an unknown source')
    oneOf(monitor.method_code, MONITOR_METHODS, 'monitor method_code')
    url(monitor.target_url_candidate, 'target_url_candidate')
    text(monitor.cadence_note, 'cadence_note', 500)
    stringArray(monitor.change_signal_codes, 'change_signal_codes', { minimum: 1, allowed: CHANGE_SIGNALS })
    text(monitor.limitations, 'monitor limitations')
  }
  validateAgainstManifestSchema(manifest, manifestSchema)
  return manifest
}

function assertConfined(candidate, root, label) {
  const resolvedRoot = path.resolve(root)
  const resolved = path.resolve(candidate)
  const relative = path.relative(resolvedRoot, resolved)
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) reject('PATH_ESCAPE', `${label} must be beneath ${resolvedRoot}`)
  let cursor = resolved
  while (cursor !== resolvedRoot) {
    if (fs.existsSync(cursor) && fs.lstatSync(cursor).isSymbolicLink()) reject('PATH_SYMLINK', `${label} contains a symbolic link`)
    cursor = path.dirname(cursor)
  }
  return resolved
}

export function loadResearchManifests({ manifestDirectory, allowedManifestRoot }) {
  const directory = assertConfined(manifestDirectory, allowedManifestRoot, 'manifest directory')
  const stat = fs.lstatSync(directory)
  if (!stat.isDirectory() || stat.isSymbolicLink()) reject('PATH_INVALID', 'manifest directory must be a non-symlink directory')
  const files = fs.readdirSync(directory).filter((name) => name.endsWith('.research.json')).sort()
  const manifests = []
  for (const file of files) {
    const absolute = assertConfined(path.join(directory, file), allowedManifestRoot, 'manifest file')
    const fileStat = fs.lstatSync(absolute)
    if (!fileStat.isFile() || fileStat.isSymbolicLink() || fileStat.size > 512 * 1024) reject('PATH_INVALID', `${file} must be a bounded regular non-symlink file`)
    const raw = fs.readFileSync(absolute, 'utf8')
    const manifest = validateResearchManifest(parseJsonNoDuplicateKeys(raw, file))
    manifests.push({ file, absolute, manifest, digest: manifest.canonical_digest_sha256 })
  }
  const identities = new Set()
  const sourceCodes = new Set()
  const propositionCodes = new Set()
  const secondaryCodes = new Set()
  for (const entry of manifests) {
    if (identities.has(entry.manifest.manifest_code)) reject('CODE_COLLISION', 'manifest_code is duplicated across files')
    identities.add(entry.manifest.manifest_code)
    const sourceCode = entry.manifest.source_candidate.source_candidate_code
    if (sourceCodes.has(sourceCode)) reject('CODE_COLLISION', 'source_candidate_code is duplicated across manifests')
    sourceCodes.add(sourceCode)
    for (const proposition of entry.manifest.proposition_drafts) {
      if (propositionCodes.has(proposition.proposition_code)) reject('CODE_COLLISION', 'proposition_code is duplicated across manifests')
      propositionCodes.add(proposition.proposition_code)
    }
    for (const item of [...entry.manifest.editorial_notes, ...entry.manifest.monitoring_candidates, ...entry.manifest.preparation.automation_suggestions]) {
      const itemCode = item.editorial_note_code ?? item.monitoring_candidate_code ?? item.suggestion_code
      if (secondaryCodes.has(itemCode)) reject('CODE_COLLISION', 'secondary record code is duplicated across manifests')
      secondaryCodes.add(itemCode)
    }
  }
  return manifests
}

function insertManifest(database, entry) {
  const manifest = entry.manifest
  const source = manifest.source_candidate
  database.prepare('INSERT INTO research_manifests VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    manifest.manifest_code, entry.file, entry.digest, manifest.recorded_at, manifest.synthetic_fixture ? 1 : 0,
    manifest.preparation.prepared_by_role_code, manifest.preparation.preparation_mode_code,
  )
  database.prepare('INSERT INTO research_sources VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
    source.source_candidate_code, manifest.manifest_code, source.status_code, source.official_landing_url_candidate,
    source.jurisdiction_candidate_code, source.document_family_code, source.language_tag, source.discovered_on, source.notes,
    source.provenance_candidate.discovery_method_code, source.provenance_candidate.source_scope_note,
    canonicalize(source.provenance_candidate.limitations), manifest.personal_data_declaration_code,
  )
  const identifierInsert = database.prepare('INSERT INTO research_expected_identifiers VALUES (?, ?, ?, ?)')
  source.expected_identifiers.forEach((identifier, index) => identifierInsert.run(source.source_candidate_code, index + 1, identifier.scheme_code, identifier.expected_value))
  const propositionInsert = database.prepare('INSERT INTO research_proposition_drafts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
  const citationInsert = database.prepare('INSERT INTO research_proposition_citations VALUES (?, ?, ?, ?)')
  for (const proposition of manifest.proposition_drafts) {
    propositionInsert.run(
      proposition.proposition_code, manifest.manifest_code, proposition.status_code, proposition.normative_effect_code,
      proposition.actor_text, proposition.normative_action_text, proposition.subject_text, proposition.jurisdiction_candidate_code,
      proposition.proposition_paraphrase, canonicalize(proposition.applicability_conditions), proposition.uncertainty_note,
    )
    citationInsert.run(proposition.proposition_code, proposition.citation.source_candidate_code, proposition.citation.locator_kind_code, proposition.citation.locator_value)
  }
  const noteInsert = database.prepare('INSERT INTO research_editorial_notes VALUES (?, ?, ?, ?, ?)')
  for (const note of manifest.editorial_notes) noteInsert.run(note.editorial_note_code, note.proposition_code, note.kind_code, note.text, note.status_code)
  const monitorInsert = database.prepare('INSERT INTO research_monitoring_candidates VALUES (?, ?, ?, ?, ?, ?, ?)')
  for (const monitor of manifest.monitoring_candidates) monitorInsert.run(
    monitor.monitoring_candidate_code, monitor.source_candidate_code, monitor.method_code, monitor.target_url_candidate,
    monitor.cadence_note, canonicalize(monitor.change_signal_codes), monitor.limitations,
  )
  const automationInsert = database.prepare('INSERT INTO research_automation_suggestions VALUES (?, ?, ?, ?, ?, ?)')
  for (const suggestion of manifest.preparation.automation_suggestions) automationInsert.run(
    suggestion.suggestion_code, manifest.manifest_code, suggestion.tool_code, suggestion.tool_version, suggestion.scope_code, suggestion.disposition_code,
  )
}

export function inspectResearchDatabase(databasePath) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    database.exec('PRAGMA foreign_keys = ON; PRAGMA query_only = ON')
    const integrity = database.prepare('PRAGMA integrity_check').get().integrity_check
    const foreignKeys = database.prepare('PRAGMA foreign_key_check').all()
    const tables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name COLLATE BINARY").all().map(({ name }) => name)
    if (canonicalize(tables) !== canonicalize(RESEARCH_TABLES)) reject('SCHEMA_INVALID', 'generated research database has an unexpected table inventory')
    const projection = {}
    for (const table of RESEARCH_TABLES) {
      const columns = database.prepare(`PRAGMA table_info("${table}")`).all().map(({ name }) => name)
      const order = columns.map((column) => `"${column}" COLLATE BINARY`).join(', ')
      projection[table] = database.prepare(`SELECT * FROM "${table}" ORDER BY ${order}`).all()
    }
    return { integrity, foreignKeys, tables, projection, logicalSha256: sha256(canonicalize(projection)) }
  } finally {
    database.close()
  }
}

export function buildResearchDatabase({ manifestDirectory, outputPath, allowedManifestRoot, allowedOutputRoot }) {
  const manifests = loadResearchManifests({ manifestDirectory, allowedManifestRoot })
  fs.mkdirSync(allowedOutputRoot, { recursive: true, mode: 0o700 })
  const output = assertConfined(outputPath, allowedOutputRoot, 'research database output')
  const parent = path.dirname(output)
  if (!fs.lstatSync(parent).isDirectory() || fs.lstatSync(parent).isSymbolicLink()) reject('PATH_INVALID', 'output parent must be a non-symlink directory')
  if (fs.existsSync(output)) {
    const existing = fs.lstatSync(output)
    if (!existing.isFile() || existing.isSymbolicLink()) reject('PATH_INVALID', 'existing output must be a regular non-symlink file')
  }
  const temporary = path.join(parent, `.${path.basename(output)}.${process.pid}.${randomUUID()}.tmp`)
  const manifestSet = manifests.map(({ file, manifest, digest }) => ({ manifest_code: manifest.manifest_code, manifest_path: file, manifest_sha256: digest }))
  const manifestSetSha256 = sha256(canonicalize(manifestSet))
  let database
  try {
    database = new DatabaseSync(temporary)
    database.exec('PRAGMA page_size = 4096; PRAGMA journal_mode = DELETE; PRAGMA auto_vacuum = NONE; PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON; PRAGMA trusted_schema = OFF;')
    database.exec('BEGIN IMMEDIATE')
    try {
      database.exec(DDL)
      database.prepare('INSERT INTO research_builds VALUES (?, ?, ?, ?)').run('manifest_projection_v1', RESEARCH_SCHEMA_VERSION, manifestSetSha256, manifests.length)
      for (const entry of manifests) insertManifest(database, entry)
      database.exec('COMMIT')
    } catch (error) {
      database.exec('ROLLBACK')
      throw error
    }
    database.exec('VACUUM')
    database.close()
    database = undefined
    fs.chmodSync(temporary, 0o600)
    const inspection = inspectResearchDatabase(temporary)
    if (inspection.integrity !== 'ok' || inspection.foreignKeys.length !== 0) reject('DATABASE_INVALID', 'generated research database failed integrity checks')
    fs.renameSync(temporary, output)
    return { outputPath: output, manifestCount: manifests.length, manifestSetSha256, logicalSha256: inspection.logicalSha256 }
  } finally {
    if (database) database.close()
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary)
  }
}

export function repositoryPaths(projectRoot) {
  const researchRoot = path.join(projectRoot, 'research')
  return {
    researchRoot,
    manifestRoot: path.join(researchRoot, 'candidates'),
    generatedRoot: path.join(researchRoot, 'generated'),
    defaultOutput: path.join(researchRoot, 'generated', 'research-candidates.sqlite'),
  }
}
