#!/usr/bin/env node

import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import {
  RESEARCH_STATUSES,
  RESEARCH_TABLES,
  buildResearchDatabase,
  canonicalize,
  inspectResearchDatabase,
  manifestDigest,
  parseJsonNoDuplicateKeys,
  validateResearchManifest,
} from './lib/research-track.mjs'

const projectRoot = path.resolve(import.meta.dirname, '..')
const fixturePath = path.join(projectRoot, 'research/candidates/synthetic-official-source.example.research.json')
const schemaPath = path.join(projectRoot, 'research/schema/research-candidate-manifest-v1.schema.json')
const EXPECTED_FIXTURE_DIGEST = '78c08836286094faaf544557c2c7ab550184ef4030311c91e1d9dd0972af10de'
const CANONICAL_MICRO_VECTOR = '{"a":["é",null],"z":true}'
const CANONICAL_MICRO_SHA256 = '163db4e5c4be3505d8068a4a0df79d7f6b4a9e0f3b5ffa14bb689dee4266bc4c'

function hashFile(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex')
}

function clone(value) {
  return structuredClone(value)
}

function validateAgainstSchema(value, rule, root, location = '$') {
  if (rule.$ref) {
    const target = rule.$ref.split('/').slice(1).reduce((current, segment) => current[segment.replaceAll('~1', '/').replaceAll('~0', '~')], root)
    assert.ok(target, `unresolved schema reference ${rule.$ref}`)
    return validateAgainstSchema(value, target, root, location)
  }
  if (Object.hasOwn(rule, 'const')) assert.deepEqual(value, rule.const, `${location} violates const`)
  if (rule.enum) assert.ok(rule.enum.includes(value), `${location} violates enum`)
  if (rule.type === 'object') {
    assert.ok(value && typeof value === 'object' && !Array.isArray(value), `${location} must be object`)
    for (const required of rule.required ?? []) assert.ok(Object.hasOwn(value, required), `${location}.${required} is required`)
    if (rule.additionalProperties === false) {
      for (const key of Object.keys(value)) assert.ok(Object.hasOwn(rule.properties ?? {}, key), `${location}.${key} is unknown`)
    }
    for (const [key, child] of Object.entries(rule.properties ?? {})) {
      if (Object.hasOwn(value, key)) validateAgainstSchema(value[key], child, root, `${location}.${key}`)
    }
  } else if (rule.type === 'array') {
    assert.ok(Array.isArray(value), `${location} must be array`)
    if (rule.minItems !== undefined) assert.ok(value.length >= rule.minItems, `${location} has too few items`)
    if (rule.maxItems !== undefined) assert.ok(value.length <= rule.maxItems, `${location} has too many items`)
    value.forEach((item, index) => validateAgainstSchema(item, rule.items, root, `${location}[${index}]`))
  } else if (rule.type === 'string') {
    assert.equal(typeof value, 'string', `${location} must be string`)
    if (rule.minLength !== undefined) assert.ok(value.length >= rule.minLength, `${location} is too short`)
    if (rule.maxLength !== undefined) assert.ok(value.length <= rule.maxLength, `${location} is too long`)
    if (rule.pattern) assert.match(value, new RegExp(rule.pattern, 'u'), `${location} violates pattern`)
  } else if (rule.type === 'boolean') {
    assert.equal(typeof value, 'boolean', `${location} must be boolean`)
  }
}

function seal(manifest) {
  manifest.canonical_digest_sha256 = manifestDigest(manifest)
  return manifest
}

function expectManifestFailure(base, transform, expectedCode) {
  const candidate = clone(base)
  transform(candidate)
  seal(candidate)
  assert.throws(() => validateResearchManifest(candidate), (error) => error?.code === expectedCode)
}

function copyFixture(directory, name = 'candidate.research.json') {
  fs.mkdirSync(directory, { recursive: true })
  fs.copyFileSync(fixturePath, path.join(directory, name))
}

function buildIn(root, manifestDirectory, outputName = 'research.sqlite') {
  const outputRoot = path.join(root, 'generated')
  return buildResearchDatabase({
    manifestDirectory,
    outputPath: path.join(outputRoot, outputName),
    allowedManifestRoot: root,
    allowedOutputRoot: outputRoot,
  })
}

function snapshotDatabase(databasePath) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    const tables = database.prepare("SELECT name, sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name COLLATE BINARY").all()
    const strict = database.prepare('PRAGMA table_list').all().filter(({ name }) => RESEARCH_TABLES.includes(name)).map(({ name, strict: isStrict }) => [name, isStrict])
    return { tables, strict }
  } finally {
    database.close()
  }
}

function assertNoApplicationConsumer() {
  for (const root of ['backend/src', 'frontend/src']) {
    const absoluteRoot = path.join(projectRoot, root)
    const pending = [absoluteRoot]
    while (pending.length) {
      const current = pending.pop()
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const absolute = path.join(current, entry.name)
        if (entry.isDirectory()) pending.push(absolute)
        else if (entry.isFile()) {
          const contents = fs.readFileSync(absolute, 'utf8')
          assert.doesNotMatch(contents, /research-candidates\.sqlite|research\/candidates|research\/generated/)
          for (const table of RESEARCH_TABLES) assert.equal(contents.includes(table), false, `${root} must not consume ${table}`)
        }
      }
    }
  }
}

const rawFixture = fs.readFileSync(fixturePath, 'utf8')
const fixture = parseJsonNoDuplicateKeys(rawFixture, path.basename(fixturePath))
validateResearchManifest(fixture)
assert.equal(fixture.canonical_digest_sha256, EXPECTED_FIXTURE_DIGEST)
assert.equal(manifestDigest(fixture), EXPECTED_FIXTURE_DIGEST)
assert.equal(canonicalize({ z: true, a: ['é', null] }), CANONICAL_MICRO_VECTOR)
assert.equal(createHash('sha256').update(Buffer.from(CANONICAL_MICRO_VECTOR, 'utf8')).digest('hex'), CANONICAL_MICRO_SHA256)
assert.equal(canonicalize(parseJsonNoDuplicateKeys('{\r\n  "z": true,\r\n  "a": ["é", null]\r\n}')), CANONICAL_MICRO_VECTOR)
assert.notEqual(canonicalize({ a: ['é', null], z: true }), canonicalize({ a: ['é', null], z: true }), 'Unicode must not be normalized')
const alternateDigestField = clone(fixture)
alternateDigestField.canonical_digest_sha256 = 'f'.repeat(64)
assert.equal(manifestDigest(alternateDigestField), EXPECTED_FIXTURE_DIGEST, 'only the top-level digest field is excluded')
const digestCoveredMutation = clone(fixture)
digestCoveredMutation.source_candidate.notes = 'Digest-covered mutation.'
assert.notEqual(manifestDigest(digestCoveredMutation), EXPECTED_FIXTURE_DIGEST)

const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'))
assert.equal(schema.additionalProperties, false)
assert.deepEqual(schema.$defs.sourceCandidate.properties.status_code.enum, RESEARCH_STATUSES.slice(0, 2))
assert.deepEqual(schema.$defs.propositionDraft.properties.status_code.enum, RESEARCH_STATUSES.slice(2))
assert.equal(schema.$defs.editorialNote.properties.status_code.const, 'unreviewed_editorial')
validateAgainstSchema(fixture, schema, schema)

assert.throws(
  () => parseJsonNoDuplicateKeys('{"schema_version":"1.0.0","schema_version":"1.0.0"}', 'duplicate-key'),
  (error) => error?.code === 'JSON_INVALID',
)
assert.throws(() => parseJsonNoDuplicateKeys(`{\u00a0"a":true}`, 'non-json-whitespace'), (error) => error?.code === 'JSON_INVALID')
expectManifestFailure(fixture, (value) => { value.manifest_code = 'ab' }, 'CODE_INVALID')
expectManifestFailure(fixture, (value) => { delete value.source_candidate.official_landing_url_candidate }, 'UNKNOWN_OR_MISSING_FIELD')
expectManifestFailure(fixture, (value) => { value.source_candidate.official_landing_url_candidate = 'http://official.example.invalid/source' }, 'URL_INVALID')
expectManifestFailure(fixture, (value) => { value.source_candidate.official_landing_url_candidate = 'https://user:pass@official.example.invalid/source' }, 'URL_INVALID')
expectManifestFailure(fixture, (value) => { value.source_candidate.official_landing_url_candidate = 'https://official.example.invalid/source?access_token=synthetic' }, 'SECRET_DETECTED')
expectManifestFailure(fixture, (value) => { value.source_candidate.status_code = 'verified_authority' }, 'ENUM_INVALID')
expectManifestFailure(fixture, (value) => { value.proposition_drafts[0].status_code = 'reviewed' }, 'ENUM_INVALID')
expectManifestFailure(fixture, (value) => { value.proposition_drafts[0].normative_effect_code = 'recommended_practice' }, 'ENUM_INVALID')
expectManifestFailure(fixture, (value) => { value.personal_data_declaration_code = 'present' }, 'PERSONAL_DATA_PROHIBITED')
expectManifestFailure(fixture, (value) => { value.source_candidate.notes = 'Contact researcher@example.invalid for details.' }, 'PERSONAL_DATA_DETECTED')
expectManifestFailure(fixture, (value) => { value.source_candidate.notes = 'api_key=synthetic-but-prohibited-value' }, 'SECRET_DETECTED')
expectManifestFailure(fixture, (value) => { value.source_candidate.notes = `data:application/pdf;base64,${'A'.repeat(200)}` }, 'EMBEDDED_BYTES_PROHIBITED')
expectManifestFailure(fixture, (value) => { value.publication_eligible = true }, 'UNKNOWN_OR_MISSING_FIELD')
expectManifestFailure(fixture, (value) => { value.source_candidate.officiality_verified = true }, 'UNKNOWN_OR_MISSING_FIELD')
expectManifestFailure(fixture, (value) => { value.proposition_drafts[0].operational_recommendation = 'Merged guidance' }, 'UNKNOWN_OR_MISSING_FIELD')
expectManifestFailure(fixture, (value) => { delete value.proposition_drafts[0].citation }, 'UNKNOWN_OR_MISSING_FIELD')
expectManifestFailure(fixture, (value) => { value.source_candidate.language_tag = 'EN-us' }, 'LANGUAGE_INVALID')
expectManifestFailure(fixture, (value) => { value.source_candidate.discovered_on = '2026-09-25' }, 'CHRONOLOGY_INVALID')
expectManifestFailure(fixture, (value) => { value.preparation.preparation_mode_code = 'human_only' }, 'AUTOMATION_LABEL_INVALID')
const digestMutation = clone(fixture)
digestMutation.source_candidate.notes = 'A changed but unsealed note.'
assert.throws(() => validateResearchManifest(digestMutation), (error) => error?.code === 'HASH_MISMATCH')

const discovered = clone(fixture)
discovered.source_candidate.status_code = 'discovered_unverified'
discovered.proposition_drafts = []
discovered.editorial_notes = []
seal(discovered)
validateResearchManifest(discovered)
const awaiting = clone(fixture)
awaiting.proposition_drafts[0].status_code = 'awaiting_independent_review'
seal(awaiting)
validateResearchManifest(awaiting)

const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-research-track-'))
try {
  const manifestDirectory = path.join(temporaryRoot, 'manifests')
  copyFixture(manifestDirectory)
  const first = buildIn(temporaryRoot, manifestDirectory, 'first.sqlite')
  const second = buildIn(temporaryRoot, manifestDirectory, 'second.sqlite')
  assert.equal(first.logicalSha256, second.logicalSha256)
  assert.equal(hashFile(first.outputPath), hashFile(second.outputPath), 'disposable SQLite builds must be byte-reproducible')
  const inspection = inspectResearchDatabase(first.outputPath)
  assert.equal(inspection.integrity, 'ok')
  assert.deepEqual(inspection.foreignKeys, [])
  assert.deepEqual(inspection.tables, RESEARCH_TABLES)
  assert.equal(Object.keys(inspection.projection).some((name) => name.startsWith('atlas_')), false)
  const physical = snapshotDatabase(first.outputPath)
  assert.equal(physical.tables.length, RESEARCH_TABLES.length)
  assert.deepEqual(physical.strict.map(([name]) => name).sort(), [...RESEARCH_TABLES].sort())
  assert.equal(physical.strict.every(([, isStrict]) => isStrict === 1), true)

  const sentinelPath = path.join(temporaryRoot, 'canonical-sentinel.sqlite')
  const sentinel = new DatabaseSync(sentinelPath)
  sentinel.exec('CREATE TABLE atlas_sentinel (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT; INSERT INTO atlas_sentinel VALUES (1, \'unchanged\');')
  sentinel.close()
  const sentinelBefore = hashFile(sentinelPath)
  fs.unlinkSync(path.join(manifestDirectory, 'candidate.research.json'))
  const empty = buildIn(temporaryRoot, manifestDirectory, 'empty.sqlite')
  const emptyInspection = inspectResearchDatabase(empty.outputPath)
  assert.equal(emptyInspection.projection.research_manifests.length, 0)
  assert.equal(emptyInspection.projection.research_sources.length, 0)
  assert.equal(emptyInspection.projection.research_proposition_drafts.length, 0)
  assert.equal(hashFile(sentinelPath), sentinelBefore, 'research candidate deletion must not touch canonical state')

  assert.throws(() => buildResearchDatabase({
    manifestDirectory,
    outputPath: sentinelPath,
    allowedManifestRoot: temporaryRoot,
    allowedOutputRoot: path.join(temporaryRoot, 'generated'),
  }), (error) => error?.code === 'PATH_ESCAPE')

  const symlinkDirectory = path.join(temporaryRoot, 'symlink-manifests')
  fs.mkdirSync(symlinkDirectory)
  fs.symlinkSync(fixturePath, path.join(symlinkDirectory, 'linked.research.json'))
  assert.throws(() => buildIn(temporaryRoot, symlinkDirectory, 'symlink.sqlite'), (error) => error?.code === 'PATH_SYMLINK')

  copyFixture(manifestDirectory, 'one.research.json')
  copyFixture(manifestDirectory, 'two.research.json')
  assert.throws(() => buildIn(temporaryRoot, manifestDirectory, 'duplicate.sqlite'), (error) => error?.code === 'CODE_COLLISION')
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true })
}

assertNoApplicationConsumer()

console.log(JSON.stringify({
  manifest_schema: '1.0.0',
  fixture_digest: EXPECTED_FIXTURE_DIGEST,
  independent_canonical_vector_sha256: CANONICAL_MICRO_SHA256,
  status_vocabulary: RESEARCH_STATUSES,
  generated_tables: RESEARCH_TABLES,
  manifest_validation: 'passed',
  structural_authority_and_publication_field_rejection: 'passed',
  source_url_and_citation_requirements: 'passed',
  automation_labelling: 'passed',
  structural_and_pattern_secret_personal_data_embedded_bytes_safeguards: 'passed',
  discovery_recording_chronology: 'passed',
  json_whitespace_and_duplicate_key_profile: 'passed',
  deterministic_sqlite_projection: 'passed',
  candidate_deletion_isolation: 'passed',
  canonical_path_escape_rejection: 'passed',
  symlink_rejection: 'passed',
  public_consumer_absence: 'passed',
}, null, 2))
