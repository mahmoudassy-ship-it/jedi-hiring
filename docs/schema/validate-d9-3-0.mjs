import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  canonicalize,
  canonicalSha256,
  parseStrictJson,
  sha256Bytes,
} from '../../d9/control-plane/canonical.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const project = path.resolve(here, '../..')
const root = path.join(here, 'd9-3-0')
const frozenRoot = path.join(here, 'd9-0')
const fixtureRoot = path.join(root, 'fixtures')

const frozenMigrations = {
  '001_schema.sql': 'b941b0baa346d85207d55b62545bfe09d39970e725fa8707e233766223912094',
  '002_reference_data.sql': '6ba08988489399c677d853e0394c52f22d72e03def967b8209ca6173db5d1923',
  '003_seed_eu_core.sql': 'a11a3f47715e31d9518288058f21fd730cf5a47f132da7f9a42d7c4c9c579700',
  '004_tranche_1a_foundations.sql': '0702aca05253c7f96ad82bfcb35661b151ec0d409b441e2ffefac67a1995a9c2',
  '005_tranche_2a_source_quarantine.sql': '1f83b484ca998be3bf5756492d4dffd958e2a6b37dbcc837e399226fdf41026b',
}

const frozenD901 = {
  catalog: 'e0a5663b378453a00626f02961465a60a474e145dd5160bf85a1797cd9316d2a',
  classification: '8d7b64822663edf09dac0d613ed9da30de0569acb8a1258a84e1850af656deef',
  global_handles: '68c54bc683be3b3ff8ffba615fc850045c75a42539606858bffd42a881470f7e',
  operation_scopes: '9c2c9fd552bfdaac26448feace4de8f729c5b0587fa904ba65647b21c4de897e',
}

// Updated only after the exact proposal inventory is frozen.
const expected = {
  catalog: 'cd91f67c25941a472b89fe2fa6f19b012714dec96661b65b76ecfacf7f48e87c',
  classification: 'b61fff46a6094aeb23dfcfb0d02f808b9ac83d345a832a9d914d8de8b641a5e8',
  digest_profiles: 'c8532cd78032dba55add0b9d17d6d5625aaae887c4b2bbe3fea87c286b31e920',
  field_registry: '04293fb9885ed792516c04b11ef4608fd82cec9f4223be75b9fa8d9a93392a96',
  root_inventory: 'cf073b571a70b347ba3ea8e0e851d5d44013fe701fd9f77a235673302b423ba3',
  resolver_projection: '6276a2785d6693477755717dc27819a07b326a455b004b89a18d7a058cb276d7',
  custody_profile_commitment: '9b1d68cf65887d9e88e3d6e37a47d1f471fe479fdbbd6232595ba89e3a9242e3',
  journal_profile_commitment: '76278dd1ccc3216bc41269d2bc97d8b8067b6a195fc6c7b3dbf2952a7fbde97f',
  primary_receipt_golden: 'b48325f9c6fb1fa68cd995f0a45d0a4e12e6edf200d87d5c035173df36b62c6f',
}

const schemaFiles = [
  'operational-profile-v1.schema.json',
  'custody-adapter-message-v2.schema.json',
  'integrity-access-lifecycle-record-v1.schema.json',
  'primary-durability-receipt-v1.schema.json',
  'durability-receipt-broker-message-v1.schema.json',
  'operation-journal-semantic-v1.schema.json',
  'operation-journal-broker-message-v1.schema.json',
  'operation-journal-event-v2.schema.json',
]

function clone(value) {
  return structuredClone(value)
}

function readJson(file) {
  return parseStrictJson(fs.readFileSync(file), {
    maximumBytes: 4 * 1024 * 1024,
    maximumDepth: 96,
    maximumMembers: 50000,
  })
}

function rawSha(file) {
  return sha256Bytes(fs.readFileSync(file))
}

function recordDigest(record) {
  return canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' })
}

function semanticDigest(value) {
  return canonicalSha256(value)
}

function parseCanonicalContractBytes(bytes) {
  const text = Buffer.from(bytes).toString('utf8')
  const parsed = parseStrictJson(bytes, {
    maximumBytes: 4 * 1024 * 1024,
    maximumDepth: 96,
    maximumMembers: 50000,
  })
  if (canonicalize(parsed) !== text) fail('NONCANONICAL_CONTRACT_BYTES')
  return parsed
}

function fail(code, detail = '') {
  throw new Error(`${code}${detail ? `: ${detail}` : ''}`)
}

function assertThrowsCode(fn, code) {
  assert.throws(fn, (error) => String(error.message).includes(code), `expected ${code}`)
}

function validateCatalogLifecycle(catalogRecord) {
  if (catalogRecord.status_code !== 'design_only_contract_freeze') {
    fail('CATALOG_LIFECYCLE_STATE_REJECTED', String(catalogRecord.status_code))
  }
}

function pointerSet(value, pointer, replacement) {
  const result = clone(value)
  const segments = pointer.split('/').slice(1).map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'))
  let current = result
  for (const segment of segments.slice(0, -1)) current = current[segment]
  current[segments.at(-1)] = clone(replacement)
  return result
}

function primitiveLeaves(value, prefix = '') {
  if (value === null || typeof value !== 'object') return [[prefix, value]]
  if (Array.isArray(value)) return value.flatMap((item, index) => primitiveLeaves(item, `${prefix}/${index}`))
  return Object.entries(value).flatMap(([key, item]) => primitiveLeaves(item, `${prefix}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`))
}

function mutatedPrimitive(value) {
  if (value === null) return 'synthetic.mutation'
  if (typeof value === 'boolean') return !value
  if (typeof value === 'number') return value + 1
  if (typeof value === 'string') return `${value}x`
  throw new Error('not primitive')
}

function inventoryDigest() {
  const inventory = []
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) walk(absolute)
      else if (entry.isFile()) inventory.push({
        path: path.relative(root, absolute).split(path.sep).join('/'),
        raw_sha256: rawSha(absolute),
      })
      else fail('INVENTORY_SPECIAL_FILE', entry.name)
    }
  }
  walk(root)
  inventory.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
  return canonicalSha256(inventory)
}

function isCanonicalTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false
  const date = new Date(value)
  return !Number.isNaN(date.valueOf()) && date.toISOString() === value
}

function validateAllTimestamps(value, pointer = '') {
  if (value === null || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    const next = `${pointer}/${key}`
    if (key.endsWith('_at') && child !== null && !isCanonicalTimestamp(child)) fail('TIMESTAMP_REJECTED', next)
    validateAllTimestamps(child, next)
  }
}

function bindingRole(bindingCode) {
  const syntheticBindings = new Map([
    ['trusted.launcher.synthetic', 'trusted_launcher'],
    ['bundle.importer.synthetic', 'bundle_importer'],
    ['importer.synthetic', 'bundle_importer'],
    ['custody.adapter.synthetic', 'custody_adapter'],
    ['journal.broker.synthetic', 'journal_broker'],
    ['backup.adapter.synthetic', 'backup_adapter'],
    ['database.writer.synthetic', 'database_writer'],
    ['independent.verifier.synthetic', 'independent_verifier'],
    ['cloner.promoter.synthetic', 'cloner_promoter'],
    ['scanner.synthetic', 'scanner'],
    ['clearance.broker.synthetic', 'clearance_broker'],
    ['binding.backup-adapter', 'backup_adapter'],
    ['binding.importer', 'bundle_importer'],
    ['binding.custody-adapter', 'custody_adapter'],
    ['binding.database-writer', 'database_writer'],
    ['binding.verifier', 'independent_verifier'],
    ['binding.cloner-promoter', 'cloner_promoter'],
    ['binding.journal-broker', 'journal_broker'],
    ['binding.scanner', 'scanner'],
    ['binding.clearance-broker', 'clearance_broker'],
    ['binding.launcher', 'trusted_launcher'],
  ])
  return syntheticBindings.get(bindingCode) ?? null
}

function assertExactBackendReference(artifact, backendReference) {
  const expectedReference = `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}`
  if (backendReference !== expectedReference) fail('BACKEND_REFERENCE_MISMATCH', backendReference)
}

const catalog = readJson(path.join(root, 'contract-catalog-v1.json'))
const classifications = readJson(path.join(root, 'classifications-v1.json'))
const digestProfiles = readJson(path.join(root, 'digest-profiles-v1.json'))
const fieldRegistry = readJson(path.join(root, 'field-registry-v1.json'))
const validFixtures = readJson(path.join(fixtureRoot, 'valid-contracts-v1.json'))
const invalidFixtures = readJson(path.join(fixtureRoot, 'invalid-contracts-v1.json'))
const golden = readJson(path.join(fixtureRoot, 'golden-vectors-v1.json'))
const frozenClassifications = readJson(path.join(frozenRoot, 'classifications-v1.json'))
const frozenCatalog = readJson(path.join(frozenRoot, 'contract-catalog-v1.json'))
const frozenCommon = readJson(path.join(frozenRoot, 'common-v1.schema.json'))
const frozenCapabilitySchema = readJson(path.join(frozenRoot, 'custody-capability-control-v1.schema.json'))
const frozenDigestProfiles = readJson(path.join(frozenRoot, 'digest-profiles-v1.json'))
const frozenBootstrapControlSchema = readJson(path.join(frozenRoot, 'bootstrap-control-v1.schema.json'))
const frozenCollectorHandoffSchema = readJson(path.join(frozenRoot, 'collector-handoff-v1.schema.json'))
const frozenJournalEventSchema = readJson(path.join(frozenRoot, 'operation-journal-event-v1.schema.json'))
const frozenRuntimeProfileSchema = readJson(path.join(frozenRoot, 'runtime-profile-v1.schema.json'))
const frozenIdentityBindingsSchema = readJson(path.join(frozenRoot, 'identity-bindings-v1.schema.json'))
const frozenFixtures = readJson(path.join(frozenRoot, 'fixtures/valid-contracts-v1.json'))
const extensionCommon = readJson(path.join(root, 'common-v1.schema.json'))
const schemas = new Map(schemaFiles.map((file) => [file, readJson(path.join(root, file))]))

const ajv = new Ajv2020({ allErrors: true, strict: false })
ajv.addSchema(frozenCommon)
ajv.addSchema(frozenCapabilitySchema)
ajv.addSchema(frozenBootstrapControlSchema)
ajv.addSchema(frozenCollectorHandoffSchema)
ajv.addSchema(frozenJournalEventSchema)
ajv.addSchema(frozenRuntimeProfileSchema)
ajv.addSchema(frozenIdentityBindingsSchema)
ajv.addSchema(extensionCommon)
for (const schema of schemas.values()) ajv.addSchema(schema)

const schemaByFormat = new Map(schemaFiles.map((file) => {
  const schema = schemas.get(file)
  return [`${schema.properties.format.const}/${schema.properties.format_version.const}`, file]
}))

function validateSchema(record) {
  const file = schemaByFormat.get(`${record.format}/${record.format_version}`)
  if (!file) fail('UNSUPPORTED_CONTRACT', `${record.format}/${record.format_version}`)
  const validator = ajv.getSchema(schemas.get(file).$id)
  if (!validator(record)) fail('SCHEMA_REJECTED', ajv.errorsText(validator.errors))
}

function validateRecord(record) {
  validateSchema(record)
  validateAllTimestamps(record)
  if (Object.hasOwn(record, 'record_digest_sha256') && recordDigest(record) !== record.record_digest_sha256) fail('DIGEST_MISMATCH', record.record_code)
}

function validateFrozenCapability(record) {
  const validator = ajv.getSchema(frozenCapabilitySchema.$id)
  if (!validator(record)) fail('FROZEN_CAPABILITY_SCHEMA_REJECTED', ajv.errorsText(validator.errors))
  validateAllTimestamps(record)
  if (recordDigest(record) !== record.record_digest_sha256) fail('DIGEST_MISMATCH', record.record_code)
}

function frozenFixture(fixtureCode) {
  const fixture = frozenFixtures.fixtures.find((entry) => entry.fixture_code === fixtureCode)
  if (!fixture) fail('FROZEN_FIXTURE_MISSING', fixtureCode)
  return clone(fixture.value)
}

function validateFrozenD90Record(record, schema) {
  const validator = ajv.getSchema(schema.$id)
  if (!validator(record)) fail('FROZEN_D90_SCHEMA_REJECTED', ajv.errorsText(validator.errors))
  validateAllTimestamps(record)
  if (recordDigest(record) !== record.record_digest_sha256) fail('DIGEST_MISMATCH', record.record_code)
}

function assertFrozenInputs() {
  for (const [file, digest] of Object.entries(frozenMigrations)) {
    assert.equal(rawSha(path.join(project, 'data/migrations', file)), digest, `${file} changed`)
  }
  assert.equal(rawSha(path.join(frozenRoot, 'contract-catalog-v1.json')), frozenD901.catalog)
  assert.equal(recordDigest(frozenClassifications), frozenD901.classification)
  for (const entry of frozenCatalog.schemas) assert.equal(rawSha(path.join(frozenRoot, entry.schema_file)), entry.raw_sha256, `frozen ${entry.schema_file}`)
  for (const key of ['classifications', 'digest_profiles', 'field_registry']) assert.equal(rawSha(path.join(frozenRoot, frozenCatalog[key].file)), frozenCatalog[key].raw_sha256, `frozen ${key}`)
  assert.deepEqual(catalog.base_contract, {
    d90_catalog_sha256: frozenD901.catalog,
    d90_classification_fingerprint_sha256: frozenD901.classification,
    d90_global_handles_fingerprint_sha256: frozenD901.global_handles,
    d90_operation_scopes_fingerprint_sha256: frozenD901.operation_scopes,
  })
  assert.deepEqual(catalog.migration_sha256, frozenMigrations)
}

function assertCatalog() {
  validateCatalogLifecycle(catalog)
  for (const statusCode of ['design_only_unapproved', 'approved', 'active']) {
    const substituted = clone(catalog)
    substituted.status_code = statusCode
    assertThrowsCode(() => validateCatalogLifecycle(substituted), 'CATALOG_LIFECYCLE_STATE_REJECTED')
  }
  assert.equal(rawSha(path.join(root, 'contract-catalog-v1.json')), expected.catalog)
  const expectedSchemaFiles = ['common-v1.schema.json', ...schemaFiles]
  assert.deepEqual(catalog.schemas.map((entry) => entry.schema_file).sort(), expectedSchemaFiles.slice().sort())
  assert.equal(new Set(catalog.schemas.map((entry) => entry.schema_file)).size, expectedSchemaFiles.length)
  for (const entry of catalog.schemas) {
    assert.equal(rawSha(path.join(root, entry.schema_file)), entry.raw_sha256, entry.schema_file)
    const schema = readJson(path.join(root, entry.schema_file))
    assert.equal(entry.schema_id, schema.$id)
    if (entry.schema_file !== 'common-v1.schema.json') {
      assert.equal(entry.contract_format, schema.properties.format.const)
      assert.equal(entry.contract_version, schema.properties.format_version.const)
    }
  }
  for (const key of ['classifications', 'digest_profiles', 'field_registry']) {
    assert.equal(rawSha(path.join(root, catalog[key].file)), catalog[key].raw_sha256)
  }
  assert.equal(recordDigest(classifications), expected.classification)
  assert.equal(recordDigest(digestProfiles), expected.digest_profiles)
  assert.equal(recordDigest(fieldRegistry), expected.field_registry)
  assert.equal(classifications.record_digest_sha256, expected.classification)
  assert.equal(digestProfiles.record_digest_sha256, expected.digest_profiles)
  assert.equal(fieldRegistry.record_digest_sha256, expected.field_registry)
  assert.equal(validFixtures.fixture_set_code, 'd930.synthetic.contracts.v1')
  assert.equal(validFixtures.records.custody_profile.record_digest_sha256, expected.custody_profile_commitment)
  assert.equal(validFixtures.records.journal_profile.record_digest_sha256, expected.journal_profile_commitment)
  assert.equal(golden.complete_primary_receipt.raw_sha256, expected.primary_receipt_golden)
  assert.equal(inventoryDigest(), expected.root_inventory)
}

function assertFieldRegistry() {
  const entries = new Map(fieldRegistry.contracts.map((entry) => [entry.schema_file, entry]))
  assert.deepEqual([...entries.keys()].sort(), schemaFiles.slice().sort())
  for (const file of schemaFiles) {
    assert.deepEqual(entries.get(file).field_codes.slice().sort(), Object.keys(schemas.get(file).properties).sort(), `${file} field registry`)
    assert.ok(entries.get(file).producer_role_codes.length)
    assert.ok(entries.get(file).consumer_role_codes.length)
    assert.ok(entries.get(file).storage_code)
    const entry = entries.get(file)
    for (const override of entry.field_overrides ?? []) {
      assert.ok(override.producer_role_codes.length)
      assert.ok(override.consumer_role_codes.length)
      for (const pointer of override.json_pointer_patterns) assert.ok(entry.field_codes.includes(pointer.slice(1)), `${file} unknown override ${pointer}`)
    }
    const selectorCode = schemas.get(file).properties.message_kind_code?.enum
      ? 'message_kind_code'
      : schemas.get(file).properties.record_kind_code?.enum
        ? 'record_kind_code'
        : null
    const variantCodes = selectorCode ? schemas.get(file).properties[selectorCode].enum : null
    if (variantCodes) {
      assert.deepEqual((entry.variant_rules ?? []).map((rule) => rule.selector[selectorCode]).sort(), variantCodes.slice().sort(), `${file} variant coverage`)
      for (const rule of entry.variant_rules) {
        assert.deepEqual(Object.keys(rule.selector), [selectorCode])
        assert.ok(rule.producer_role_codes.length)
        assert.ok(rule.consumer_role_codes.length)
      }
    }
  }
  assert.equal(fieldRegistry.mapping_semantics.unmapped_property_rule, 'reject')
  assert.equal(fieldRegistry.mapping_semantics.variant_selection_rule, 'exactly_one_selector_for_each_closed_contract_discriminator_value')
  assert.equal(fieldRegistry.mapping_semantics.nested_pattern_grammar, '/**/<literal> or /**/*<suffix>; terminal property names only; JSON Pointer escaping applies')
  assert.equal(fieldRegistry.mapping_semantics.nested_pattern_precedence, 'exact_literal_before_suffix; equal_specificity_overlap_rejected')
  const effectiveMapping = effectiveFieldMapping(fieldRegistry)
  assert.equal(canonicalSha256(effectiveMapping), fieldRegistry.effective_mapping_sha256)
  const staleFamily = clone(fieldRegistry)
  staleFamily.nested_field_families[0].json_pointer_pattern = '/**/field_that_does_not_exist'
  assertThrowsCode(() => effectiveFieldMapping(staleFamily), 'FIELD_FAMILY_STALE')
  const overlappingFamily = clone(fieldRegistry)
  overlappingFamily.nested_field_families.push({ ...clone(overlappingFamily.nested_field_families.at(-1)), json_pointer_pattern: '/**/*sha256' })
  assertThrowsCode(() => effectiveFieldMapping(overlappingFamily), 'FIELD_FAMILY_OVERLAP')
  const staleProjection = clone(fieldRegistry)
  staleProjection.effective_mapping_sha256 = sample.sha('fb')
  assert.notEqual(canonicalSha256(effectiveFieldMapping(staleProjection)), staleProjection.effective_mapping_sha256)
  assert.deepEqual(fieldRegistry.ephemeral_transport.fields, ['capability_bearer_bytes', 'scm_rights_descriptors'])
  const serialized = canonicalize({ classifications, fieldRegistry, validFixtures })
  for (const tokenName of ['source_handle_token', 'preparation_token', 'sealed_capability_token']) assert.ok(!serialized.includes(tokenName), tokenName)
}

function schemaPointerGet(document, fragment) {
  if (!fragment) return document
  return fragment.split('/').slice(1).reduce((current, segment) => current?.[segment.replaceAll('~1', '/').replaceAll('~0', '~')], document)
}

function collectSchemaPropertyOccurrences() {
  const documents = new Map([
    [frozenCommon.$id, frozenCommon],
    [frozenCapabilitySchema.$id, frozenCapabilitySchema],
    [extensionCommon.$id, extensionCommon],
    ...[...schemas.values()].map((schema) => [schema.$id, schema]),
  ])
  const occurrences = new Map()
  const walk = (node, currentDocument, schemaFile, instancePointer, refStack) => {
    if (!node || typeof node !== 'object') return
    if (node.$ref) {
      const [documentId, fragment = ''] = node.$ref.split('#')
      const targetDocument = documentId ? documents.get(documentId) : currentDocument
      if (!targetDocument) fail('FIELD_SCHEMA_REFERENCE_UNKNOWN', node.$ref)
      const refKey = `${targetDocument.$id}#${fragment}@${instancePointer}`
      if (refStack.includes(refKey)) return
      walk(schemaPointerGet(targetDocument, fragment), targetDocument, schemaFile, instancePointer, [...refStack, refKey])
      return
    }
    for (const [fieldCode, property] of Object.entries(node.properties ?? {})) {
      const pointer = `${instancePointer}/${fieldCode.replaceAll('~', '~0').replaceAll('/', '~1')}`
      occurrences.set(`${schemaFile}:${pointer}`, { schema_file: schemaFile, json_pointer: pointer, field_code: fieldCode })
      walk(property, currentDocument, schemaFile, pointer, refStack)
    }
    if (node.items) walk(node.items, currentDocument, schemaFile, `${instancePointer}/*`, refStack)
    for (const keyword of ['oneOf', 'anyOf', 'allOf']) for (const branch of node[keyword] ?? []) walk(branch, currentDocument, schemaFile, instancePointer, refStack)
    if (node.if) walk(node.if, currentDocument, schemaFile, instancePointer, refStack)
    if (node.then) walk(node.then, currentDocument, schemaFile, instancePointer, refStack)
    if (node.else) walk(node.else, currentDocument, schemaFile, instancePointer, refStack)
  }
  for (const file of schemaFiles) walk(schemas.get(file), schemas.get(file), file, '', [])
  return [...occurrences.values()].sort((left, right) => `${left.schema_file}:${left.json_pointer}`.localeCompare(`${right.schema_file}:${right.json_pointer}`))
}

function fieldFamilyMatch(pattern, occurrence) {
  const segments = occurrence.json_pointer.split('/').slice(1)
  if (!segments.length || !pattern.startsWith('/**/')) return false
  const terminal = segments.at(-1).replaceAll('~1', '/').replaceAll('~0', '~')
  const matcher = pattern.slice(4)
  if (!matcher || matcher.includes('/') || matcher === '*') return false
  return matcher.startsWith('*') ? terminal.endsWith(matcher.slice(1)) : terminal === matcher
}

function effectiveFieldMapping(registry) {
  const contractEntries = new Map(registry.contracts.map((entry) => [entry.schema_file, entry]))
  const matchCounts = new Map(registry.nested_field_families.map((family) => [family.json_pointer_pattern, 0]))
  const projection = []
  for (const occurrence of collectSchemaPropertyOccurrences()) {
    const contract = contractEntries.get(occurrence.schema_file)
    if (!contract) fail('FIELD_CONTRACT_UNMAPPED', occurrence.schema_file)
    const topLevelFieldCode = occurrence.json_pointer.split('/')[1].replaceAll('~1', '/').replaceAll('~0', '~')
    if (!contract.field_codes.includes(topLevelFieldCode)) fail('FIELD_PROPERTY_UNMAPPED', `${occurrence.schema_file}${occurrence.json_pointer}`)
    const matches = registry.nested_field_families.filter((family) => fieldFamilyMatch(family.json_pointer_pattern, occurrence))
    const ranked = matches.map((family) => ({ family, specificity: family.json_pointer_pattern.slice(4).startsWith('*') ? 1 : 2 }))
    const maximum = ranked.length ? Math.max(...ranked.map((entry) => entry.specificity)) : 0
    const selected = ranked.filter((entry) => entry.specificity === maximum)
    if (selected.length > 1) fail('FIELD_FAMILY_OVERLAP', `${occurrence.schema_file}${occurrence.json_pointer}`)
    const family = selected[0]?.family ?? null
    if (family) matchCounts.set(family.json_pointer_pattern, matchCounts.get(family.json_pointer_pattern) + 1)
    projection.push({
      schema_file: occurrence.schema_file,
      json_pointer: occurrence.json_pointer,
      top_level_field_code: topLevelFieldCode,
      nested_family_pattern: family?.json_pointer_pattern ?? null,
    })
  }
  for (const [pattern, count] of matchCounts) if (count === 0) fail('FIELD_FAMILY_STALE', pattern)
  return projection
}

function collectDigestOccurrences() {
  return collectSchemaPropertyOccurrences().filter(({ field_code: fieldCode }) => fieldCode === 'sha256' || fieldCode === 'backend_reference' || fieldCode.endsWith('_sha256') || fieldCode.endsWith('_digest_sha256'))
}

function occurrenceContext(registry, occurrence) {
  const rules = (registry.pointer_context_rules ?? []).filter((rule) => rule.field_code === occurrence.field_code && (rule.json_pointer_contains === '*' || occurrence.json_pointer.includes(rule.json_pointer_contains)))
  if (!rules.length) {
    const declared = [...registry.field_bindings, ...registry.content_hash_fields].filter((entry) => entry.field_code === occurrence.field_code)
    const contexts = [...new Set(declared.map((entry) => entry.context_code ?? null))]
    return contexts.length === 1 ? contexts[0] : null
  }
  const specific = rules.filter((rule) => rule.json_pointer_contains !== '*')
  if (specific.length > 1) fail('RESOLVER_CONTEXT_OVERLAP', `${occurrence.schema_file}${occurrence.json_pointer}`)
  return specific[0]?.context_code ?? rules[0].context_code
}

function validateResolverInventory(registry) {
  const capabilityLeafResolver = registry.resolvers.find((entry) => entry.resolver_code === 'd90_capability_leaf')
  if (capabilityLeafResolver?.selection_code !== 'exact_leaf_for_issuance_current_at_authenticated_request_acceptance_identified_by_basis_request_digest') fail('RESOLVER_SELECTION_REJECTED', 'capability leaf time boundary')
  const resolverCodes = new Set(registry.resolvers.map((entry) => entry.resolver_code))
  const profileCodes = new Set([...frozenDigestProfiles.payload_profiles, ...registry.payload_profiles].map((entry) => entry.profile_code))
  for (const entry of registry.field_bindings) {
    assert.ok(resolverCodes.has(entry.resolver_code), entry.resolver_code)
    assert.ok(profileCodes.has(entry.payload_profile_code), entry.payload_profile_code)
  }
  for (const entry of registry.content_hash_fields) {
    assert.ok(resolverCodes.has(entry.resolver_code), entry.resolver_code)
    if (!profileCodes.has(entry.profile_code)) fail('RESOLVER_PROFILE_UNKNOWN', entry.profile_code)
  }
  const usedBindings = new Set()
  const projection = []
  for (const occurrence of collectDigestOccurrences()) {
    const contextCode = occurrenceContext(registry, occurrence)
    const fieldCandidates = registry.field_bindings.filter((entry) => entry.field_code === occurrence.field_code && (entry.context_code ?? null) === contextCode).map((entry) => ({ ...entry, binding_kind_code: 'contract_digest', profile_code: entry.payload_profile_code }))
    const contentCandidates = registry.content_hash_fields.filter((entry) => entry.field_code === occurrence.field_code && (entry.context_code ?? null) === contextCode).map((entry) => ({ ...entry, binding_kind_code: 'content_hash' }))
    const candidates = [...fieldCandidates, ...contentCandidates]
    if (candidates.length !== 1) fail('RESOLVER_BINDING_CARDINALITY', `${occurrence.schema_file}${occurrence.json_pointer} (${candidates.length})`)
    const source = candidates[0].binding_kind_code === 'contract_digest'
      ? registry.field_bindings.find((entry) => entry.field_code === candidates[0].field_code && (entry.context_code ?? null) === contextCode && entry.resolver_code === candidates[0].resolver_code && entry.payload_profile_code === candidates[0].profile_code)
      : registry.content_hash_fields.find((entry) => entry.field_code === candidates[0].field_code && (entry.context_code ?? null) === contextCode && entry.resolver_code === candidates[0].resolver_code && entry.profile_code === candidates[0].profile_code)
    usedBindings.add(source)
    projection.push({
      schema_file: occurrence.schema_file,
      json_pointer: occurrence.json_pointer,
      field_code: occurrence.field_code,
      binding_kind_code: candidates[0].binding_kind_code,
      profile_code: candidates[0].profile_code,
      resolver_code: candidates[0].resolver_code,
    })
  }
  for (const binding of [...registry.field_bindings, ...registry.content_hash_fields]) if (!usedBindings.has(binding)) fail('RESOLVER_BINDING_STALE', `${binding.field_code}/${binding.context_code ?? 'default'}`)
  for (const rule of registry.pointer_context_rules ?? []) {
    if (!collectDigestOccurrences().some((occurrence) => occurrence.field_code === rule.field_code && (rule.json_pointer_contains === '*' || occurrence.json_pointer.includes(rule.json_pointer_contains)))) fail('RESOLVER_CONTEXT_STALE', `${rule.field_code}/${rule.json_pointer_contains}`)
  }
  projection.sort((left, right) => `${left.schema_file}:${left.json_pointer}`.localeCompare(`${right.schema_file}:${right.json_pointer}`))
  const projectionDigest = canonicalSha256(projection)
  if (projectionDigest !== expected.resolver_projection) fail('RESOLVER_PROJECTION_DRIFT', projectionDigest)
  return projection
}

function assertResolverInventory() {
  validateResolverInventory(digestProfiles)
  const supportingAckResolver = digestProfiles.resolvers.find((entry) => entry.resolver_code === 'd930_supporting_persistence_ack')
  assert.deepEqual(supportingAckResolver, {
    resolver_code: 'd930_supporting_persistence_ack',
    storage_code: 'protected_operation_journal',
    selection_code: 'exact_persist_supporting_response_digest_persisted_record_digest_operation_nonce_and_journal_code',
  })
  const supportingAckFields = ['request_persistence_ack_record_digest_sha256', 'response_persistence_ack_record_digest_sha256', 'descriptor_delivery_persistence_ack_record_digest_sha256', 'verifier_result_persistence_ack_record_digest_sha256', 'receiver_termination_persistence_ack_record_digest_sha256']
  for (const field of supportingAckFields) assert.equal(digestProfiles.field_bindings.find((entry) => entry.field_code === field)?.resolver_code, 'd930_supporting_persistence_ack')
  const requestResolver = digestProfiles.resolvers.find((entry) => entry.resolver_code === 'contextual_request_chain')
  assert.deepEqual(requestResolver.selection_variants.map((entry) => entry.contract_format), [
    'jedi-atlas-custody-adapter-message',
    'jedi-atlas-durability-receipt-broker-message',
    'jedi-atlas-operation-journal-broker-message',
  ])
  assert.ok(requestResolver.selection_variants.slice(0, 2).every((entry) => entry.required_context_fields.includes('request_sequence')))
  assert.ok(!requestResolver.selection_variants[2].required_context_fields.includes('request_sequence'))
  const removed = clone(digestProfiles)
  removed.field_bindings = removed.field_bindings.filter((entry) => entry.field_code !== 'append_request_record_digest_sha256')
  assertThrowsCode(() => validateResolverInventory(removed), 'RESOLVER_BINDING_CARDINALITY')
  const overlapping = clone(digestProfiles)
  overlapping.field_bindings.push(clone(overlapping.field_bindings.find((entry) => entry.field_code === 'append_request_record_digest_sha256')))
  assertThrowsCode(() => validateResolverInventory(overlapping), 'RESOLVER_BINDING_CARDINALITY')
  const stale = clone(digestProfiles)
  stale.field_bindings.push({ field_code: 'stale_digest_sha256', payload_profile_code: 'canonical_contract_record_excluding_self_digest_v1', resolver_code: 'self' })
  assertThrowsCode(() => validateResolverInventory(stale), 'RESOLVER_BINDING_STALE')
  const wrongContext = clone(digestProfiles)
  wrongContext.pointer_context_rules.find((entry) => entry.context_code === 'artifact_backup_receipt_reference').context_code = 'final_backup_receipt_reference'
  assertThrowsCode(() => validateResolverInventory(wrongContext), 'RESOLVER_BINDING_STALE')
  const wrongExistingResolver = clone(digestProfiles)
  wrongExistingResolver.field_bindings.find((entry) => entry.field_code === 'runtime_profile_record_digest_sha256').resolver_code = 'd90_identity_bindings'
  assertThrowsCode(() => validateResolverInventory(wrongExistingResolver), 'RESOLVER_PROJECTION_DRIFT')
  const reassignedPointerContext = clone(digestProfiles)
  reassignedPointerContext.pointer_context_rules.find((entry) => entry.json_pointer_contains === '/artifact_backup_receipt/' && entry.field_code === 'receipt_raw_sha256').context_code = 'primary_receipt_reference'
  assertThrowsCode(() => validateResolverInventory(reassignedPointerContext), 'RESOLVER_PROJECTION_DRIFT')
  const wrongContentProfile = clone(digestProfiles)
  wrongContentProfile.content_hash_fields.find((entry) => entry.field_code === 'component_executable_sha256').profile_code = 'exact_artifact_bytes'
  assertThrowsCode(() => validateResolverInventory(wrongContentProfile), 'RESOLVER_PROJECTION_DRIFT')
}

function assertGoldenVectors() {
  for (const vector of golden.vectors) {
    const input = vector.excluded_top_level_field
      ? Object.fromEntries(Object.entries(vector.input).filter(([key]) => key !== vector.excluded_top_level_field))
      : vector.input
    assert.equal(canonicalize(input), vector.canonical_utf8, vector.vector_code)
    assert.equal(sha256Bytes(Buffer.from(vector.canonical_utf8, 'utf8')), vector.sha256, vector.vector_code)
  }
  const receipt = validFixtures.records.primary_receipt
  assert.equal(canonicalize(receipt), golden.complete_primary_receipt.canonical_utf8)
  assert.equal(sha256Bytes(Buffer.from(golden.complete_primary_receipt.canonical_utf8, 'utf8')), golden.complete_primary_receipt.raw_sha256)
  assert.equal(golden.complete_primary_receipt.raw_sha256, sha256Bytes(Buffer.from(canonicalize(receipt), 'utf8')))
  const reversedTopLevel = Object.fromEntries(Object.entries(receipt).reverse())
  assert.equal(canonicalize(reversedTopLevel), golden.complete_primary_receipt.canonical_utf8)
  assert.notEqual(JSON.stringify(reversedTopLevel), golden.complete_primary_receipt.canonical_utf8)
  assert.deepEqual(parseCanonicalContractBytes(Buffer.from(golden.complete_primary_receipt.canonical_utf8, 'utf8')), receipt)
  assertThrowsCode(() => parseCanonicalContractBytes(Buffer.from(JSON.stringify(reversedTopLevel), 'utf8')), 'NONCANONICAL_CONTRACT_BYTES')
  assertThrowsCode(() => parseCanonicalContractBytes(Buffer.from(`${golden.complete_primary_receipt.canonical_utf8}\r\n`, 'utf8')), 'NONCANONICAL_CONTRACT_BYTES')
}

function assertEveryLeafDigestSensitivity() {
  for (const [name, record] of Object.entries(validFixtures.records)) {
    const base = Object.hasOwn(record, 'record_digest_sha256')
      ? recordDigest(record)
      : sha256Bytes(Buffer.from(canonicalize(record), 'utf8'))
    for (const [pointer, value] of primitiveLeaves(record)) {
      if (pointer === '/record_digest_sha256') continue
      const changed = pointerSet(record, pointer, mutatedPrimitive(value))
      const next = Object.hasOwn(changed, 'record_digest_sha256')
        ? recordDigest(changed)
        : sha256Bytes(Buffer.from(canonicalize(changed), 'utf8'))
      assert.notEqual(next, base, `${name}${pointer} not digest-covered`)
    }
  }
}

function validateProfile(profile) {
  validateRecord(profile)
  if (profile.d930_contract_catalog_sha256 !== expected.catalog || profile.d930_classification_fingerprint_sha256 !== expected.classification) fail('PROFILE_FINGERPRINT_MISMATCH')
  if (profile.profile_kind_code !== profile.settings.settings_kind_code) fail('PROFILE_KIND_MISMATCH')
  if (profile.activation_state_code !== 'design_only_unactivated') fail('PROFILE_ACTIVATION_REJECTED')
}

function assertResolvedJournalProfile(digest) {
  const profile = validFixtures.records.journal_profile
  validateProfile(profile)
  if (digest !== profile.record_digest_sha256 || profile.profile_kind_code !== 'journal') fail('BROKER_PROFILE_REJECTED', 'unresolved journal profile')
}

const sample = {
  sha: (pair) => pair.repeat(32),
  artifact: { byte_layer_code: 'retrieved_body', hash_algorithm_code: 'sha256', sha256: '66'.repeat(32), byte_length: 16 },
  bundle: { bundle_id: 'bundle.synthetic.matrix', bundle_sequence: 2, bundle_digest_sha256: '44'.repeat(32) },
  state: { state_seal_code: 'state.synthetic.matrix', state_seal_record_digest_sha256: 'ab'.repeat(32), logical_state_sha256: 'cd'.repeat(32) },
}

sample.intent = {
  bundle: sample.bundle,
  bundle_seal_record_digest_sha256: sample.sha('55'),
  custody_event_code: 'placement',
  artifact: sample.artifact,
  copy_code: 'copy.synthetic.primary',
  custody_class_code: 'restricted_store',
  backend_code: 'pilot_local_cas_v1',
  backend_reference: `objects/sha256/${sample.artifact.sha256.slice(0, 2)}/${sample.artifact.sha256}`,
}

const adapterPayloadKeys = Object.keys(schemas.get('custody-adapter-message-v2.schema.json').properties.payload.properties)

function payloadValue(field, outcome = null) {
  const values = {
    staging_root_slot_code: 'staging_root',
    relative_path: 'synthetic/document.bin',
    collector_handoff_record_digest_sha256: sample.sha('21'),
    bundle_seal_record_digest_sha256: sample.intent.bundle_seal_record_digest_sha256,
    staging_snapshot_code: 'snapshot.synthetic.001',
    custody_intent: sample.intent,
    artifact: sample.artifact,
    source_capability_record_digest_sha256: sample.sha('22'),
    source_capability_leaf_record_digest_sha256: sample.sha('23'),
    preparation_capability_record_digest_sha256: sample.sha('24'),
    preparation_capability_leaf_record_digest_sha256: sample.sha('25'),
    copy_code: sample.intent.copy_code,
    backend_code: sample.intent.backend_code,
    backend_reference: sample.intent.backend_reference,
    purpose_code: 'integrity',
    custody_evaluated_at: '2030-01-01T00:08:00.000Z',
    known_through_bundle_sequence: 1,
    clearance_decision_record_digest_sha256: sample.sha('26'),
    clearance_scope_sha256: sample.sha('27'),
    custody_leaf_projection_sha256: sample.sha('28'),
    sealed_capability_record_digest_sha256: sample.sha('29'),
    sealed_capability_leaf_record_digest_sha256: sample.sha('2a'),
    primary_receipt: { format: 'jedi-atlas-primary-durability-receipt', format_version: '1.0.0', record_code: 'receipt.synthetic.matrix', receipt_raw_sha256: sample.sha('2b') },
    receipt_broker_ack_record_digest_sha256: sample.sha('2c'),
    outcome_code: outcome,
    error_code: null,
  }
  return clone(values[field])
}

function descriptor(roleCode) {
  return [{ ordinal: 1, role_code: roleCode, access_code: 'read_only', file_type_code: 'regular_file' }]
}

function makeAdapterMessage(operationCode, messageKindCode, outcomeCode = null) {
  const rule = classifications.custody_message_rules.find((entry) => entry.operation_code === operationCode)
  assert.ok(rule)
  const streamRules = classifications.adapter_request_stream_rules.filter((entry) => entry.operation_codes.includes(operationCode))
  assert.equal(streamRules.length, 1)
  const requestSequence = streamRules[0].operation_codes.indexOf(operationCode) + 1
  const success = messageKindCode === 'response' && rule.success_outcomes.includes(outcomeCode)
  const failure = messageKindCode === 'response' && rule.failure_outcomes.includes(outcomeCode)
  const requiredFields = messageKindCode === 'request'
    ? rule.request_nonnull_fields
    : success
      ? rule.success_nonnull_fields
      : failure
        ? ['outcome_code', 'error_code']
        : []
  const payload = Object.fromEntries(adapterPayloadKeys.map((key) => [key, null]))
  for (const field of requiredFields) payload[field] = payloadValue(field, outcomeCode)
  if (failure) {
    const failureRule = classifications.custody_failure_error_rules.find((entry) => entry.outcome_code === outcomeCode)
    payload.error_code = failureRule.allowed_error_codes[0]
  }
  const descriptorRoles = messageKindCode === 'request'
    ? rule.request_descriptor_roles
    : success
      ? rule.success_descriptor_roles
      : []
  const message = {
    format: 'jedi-atlas-custody-adapter-message',
    format_version: '2.0.0',
    record_code: `adapter.${operationCode}.${messageKindCode}.${outcomeCode ?? 'request'}`,
    message_kind_code: messageKindCode,
    operation_code: operationCode,
    operation_id: 'operation.synthetic.matrix',
    request_id: `request.${operationCode}.001`,
    request_sequence: requestSequence,
    operation_nonce: sample.sha('33'),
    sender_binding_code: messageKindCode === 'request' ? 'bundle.importer.synthetic' : 'custody.adapter.synthetic',
    recipient_binding_code: messageKindCode === 'request' ? 'custody.adapter.synthetic' : 'bundle.importer.synthetic',
    runtime_profile_record_digest_sha256: sample.sha('11'),
    identity_bindings_record_digest_sha256: sample.sha('22'),
    d930_operational_profile_record_digest_sha256: validFixtures.records.custody_profile.record_digest_sha256,
    request_record_digest_sha256: messageKindCode === 'request' ? null : sample.sha('14'),
    created_at: '2030-01-01T00:09:00.000Z',
    ancillary_descriptors: descriptorRoles.flatMap(descriptor),
    payload,
    record_digest_sha256: sample.sha('15'),
  }
  message.record_digest_sha256 = recordDigest(message)
  return message
}

function validateAdapterMessage(message) {
  validateRecord(message)
  validateProfile(validFixtures.records.custody_profile)
  if (message.d930_operational_profile_record_digest_sha256 !== validFixtures.records.custody_profile.record_digest_sha256) fail('CUSTODY_PROFILE_REJECTED')
  const rule = classifications.custody_message_rules.find((entry) => entry.operation_code === message.operation_code)
  if (!rule) fail('CUSTODY_MATRIX_REJECTED', 'operation')
  const roleRule = classifications.custody_message_role_rule
  const senderRole = bindingRole(message.sender_binding_code)
  const recipientRole = bindingRole(message.recipient_binding_code)
  const expectedSender = message.message_kind_code === 'request' ? roleRule.request_sender_role_code : roleRule.response_sender_role_code
  const expectedRecipient = message.message_kind_code === 'request' ? roleRule.request_recipient_role_code : roleRule.response_recipient_role_code
  if (senderRole !== expectedSender || recipientRole !== expectedRecipient) fail('CUSTODY_ROLE_REJECTED')
  if ((message.message_kind_code === 'request') !== (message.request_record_digest_sha256 === null)) fail('CUSTODY_REQUEST_CHAIN_REJECTED')
  const outcome = message.payload.outcome_code
  const success = message.message_kind_code === 'response' && rule.success_outcomes.includes(outcome)
  const failure = message.message_kind_code === 'response' && rule.failure_outcomes.includes(outcome)
  const expectedFields = message.message_kind_code === 'request'
    ? rule.request_nonnull_fields
    : success
      ? rule.success_nonnull_fields
      : failure
        ? ['error_code', 'outcome_code']
        : null
  if (!expectedFields) fail('CUSTODY_MATRIX_REJECTED', 'outcome')
  if (failure) {
    const failureRule = classifications.custody_failure_error_rules.find((entry) => entry.outcome_code === outcome)
    if (!failureRule || !failureRule.allowed_error_codes.includes(message.payload.error_code)) fail('CUSTODY_FAILURE_ERROR_REJECTED')
  }
  const nonnull = Object.entries(message.payload).filter(([, value]) => value !== null).map(([key]) => key).sort()
  if (canonicalize(nonnull) !== canonicalize(expectedFields.slice().sort())) fail('CUSTODY_MATRIX_REJECTED', 'field set')
  const expectedDescriptors = message.message_kind_code === 'request'
    ? rule.request_descriptor_roles
    : success
      ? rule.success_descriptor_roles
      : []
  if (canonicalize(message.ancillary_descriptors.map((entry) => entry.role_code)) !== canonicalize(expectedDescriptors)) fail('CUSTODY_DESCRIPTOR_REJECTED')
  const ordinals = message.ancillary_descriptors.map((entry) => entry.ordinal)
  if (canonicalize(ordinals) !== canonicalize(ordinals.map((_, index) => index + 1))) fail('CUSTODY_DESCRIPTOR_REJECTED', 'ordinals')
  if (message.payload.custody_intent) {
    assert.equal(message.payload.custody_intent.custody_event_code, 'placement')
    assertExactBackendReference(message.payload.custody_intent.artifact, message.payload.custody_intent.backend_reference)
  }
  if (message.payload.artifact && message.payload.backend_reference) assertExactBackendReference(message.payload.artifact, message.payload.backend_reference)
  const serialized = canonicalize(message)
  for (const prohibited of ['source_handle_token', 'preparation_token', 'sealed_capability_token']) if (serialized.includes(prohibited)) fail('SECRET_CAPABILITY_PERSISTENCE_REJECTED')
  if (message.message_kind_code === 'response' && success) {
    const initialPair = classifications.capability_leaf_rules.initial_issuance_leaf_pairs.find(([operation]) => operation === message.operation_code)
    if (initialPair && message.payload[initialPair[1]] !== message.payload[initialPair[2]]) fail('CAPABILITY_INITIAL_LEAF_REJECTED')
  }
}

function bindAdapterResponse(request, response) {
  for (const key of ['operation_code', 'operation_id', 'request_id', 'request_sequence', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256']) response[key] = clone(request[key])
  response.sender_binding_code = request.recipient_binding_code
  response.recipient_binding_code = request.sender_binding_code
  response.request_record_digest_sha256 = request.record_digest_sha256
  response.created_at = new Date(Date.parse(request.created_at) + 1).toISOString()
  const rule = classifications.custody_message_rules.find((entry) => entry.operation_code === request.operation_code)
  if (rule.success_outcomes.includes(response.payload.outcome_code)) {
    const pairRule = classifications.custody_message_pair_rules.find((entry) => entry.operation_code === request.operation_code)
    for (const field of pairRule.exact_echo_fields) response.payload[field] = clone(request.payload[field])
    const initialPair = classifications.capability_leaf_rules.initial_issuance_leaf_pairs.find(([operation]) => operation === request.operation_code)
    if (initialPair) response.payload[initialPair[2]] = response.payload[initialPair[1]]
  }
  response.record_digest_sha256 = recordDigest(response)
  return response
}

function validateAdapterPair(request, response) {
  validateAdapterMessage(request)
  validateAdapterMessage(response)
  if (request.message_kind_code !== 'request' || response.message_kind_code !== 'response') fail('CUSTODY_PAIR_REJECTED', 'kinds')
  for (const key of ['operation_code', 'operation_id', 'request_id', 'request_sequence', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256']) {
    if (canonicalize(request[key]) !== canonicalize(response[key])) fail('CUSTODY_PAIR_REJECTED', key)
  }
  if (request.sender_binding_code !== response.recipient_binding_code || request.recipient_binding_code !== response.sender_binding_code) fail('CUSTODY_PAIR_REJECTED', 'roles')
  if (response.request_record_digest_sha256 !== request.record_digest_sha256) fail('CUSTODY_PAIR_REJECTED', 'request digest')
  if (response.created_at < request.created_at) fail('CUSTODY_PAIR_REJECTED', 'chronology')
  const rule = classifications.custody_message_rules.find((entry) => entry.operation_code === request.operation_code)
  if (rule.success_outcomes.includes(response.payload.outcome_code)) {
    const pairRule = classifications.custody_message_pair_rules.find((entry) => entry.operation_code === request.operation_code)
    if (!pairRule) fail('CUSTODY_PAIR_REJECTED', 'missing rule')
    for (const field of pairRule.exact_echo_fields) {
      if (canonicalize(request.payload[field]) !== canonicalize(response.payload[field])) fail('CUSTODY_PAIR_REJECTED', field)
    }
  }
}

function makeProtectedAdapterStreamState() {
  return { streams: new Map(), requestKeys: new Map(), acceptedByRequestDigest: new Map() }
}

function acceptAdapterExchange(request, response, protectedState) {
  validateAdapterPair(request, response)
  const streamRules = classifications.adapter_request_stream_rules.filter((entry) => entry.operation_codes.includes(request.operation_code))
  if (streamRules.length !== 1) fail('CUSTODY_STREAM_REJECTED', 'operation')
  const streamRule = streamRules[0]
  const streamKey = [request.operation_id, request.operation_nonce, request.sender_binding_code, request.recipient_binding_code, request.runtime_profile_record_digest_sha256, request.identity_bindings_record_digest_sha256, request.d930_operational_profile_record_digest_sha256].join(':')
  const requestKey = `${streamKey}:${request.request_id}`
  const priorRequestDigest = protectedState.requestKeys.get(requestKey)
  if (priorRequestDigest && priorRequestDigest !== request.record_digest_sha256) fail('CUSTODY_STREAM_REPLAY_REJECTED', 'request id')
  const prior = protectedState.acceptedByRequestDigest.get(request.record_digest_sha256)
  if (prior) {
    if (prior.response_record_digest_sha256 !== response.record_digest_sha256 || prior.stream_key !== streamKey) fail('CUSTODY_STREAM_REPLAY_REJECTED', 'response')
    return false
  }
  const stream = protectedState.streams.get(streamKey) ?? { stream_code: streamRule.stream_code, accepted_count: 0, terminal: false }
  if (stream.stream_code !== streamRule.stream_code) fail('CUSTODY_STREAM_REJECTED', 'stream substitution')
  if (stream.terminal) fail('CUSTODY_STREAM_REJECTED', 'terminal failure')
  const expectedIndex = stream.accepted_count
  if (streamRule.operation_codes[expectedIndex] !== request.operation_code || request.request_sequence !== expectedIndex + 1) fail('CUSTODY_STREAM_REJECTED', 'sequence')
  const operationRule = classifications.custody_message_rules.find((entry) => entry.operation_code === request.operation_code)
  const success = operationRule.success_outcomes.includes(response.payload.outcome_code)
  protectedState.streams.set(streamKey, { stream_code: stream.stream_code, accepted_count: expectedIndex + 1, terminal: !success })
  protectedState.requestKeys.set(requestKey, request.record_digest_sha256)
  protectedState.acceptedByRequestDigest.set(request.record_digest_sha256, { response_record_digest_sha256: response.record_digest_sha256, stream_key: streamKey })
  return true
}

function assertAdapterMatrix() {
  let variants = 0
  for (const rule of classifications.custody_message_rules) {
    const request = makeAdapterMessage(rule.operation_code, 'request')
    validateAdapterMessage(request)
    variants += 1
    for (const outcome of [...rule.success_outcomes, ...rule.failure_outcomes]) {
      const response = bindAdapterResponse(request, makeAdapterMessage(rule.operation_code, 'response', outcome))
      validateAdapterPair(request, response)
      variants += 1
      if (response.ancillary_descriptors.length) {
        const wrongOrdinal = clone(response)
        wrongOrdinal.ancillary_descriptors[0].ordinal = 8
        wrongOrdinal.record_digest_sha256 = recordDigest(wrongOrdinal)
        assertThrowsCode(() => validateAdapterPair(request, wrongOrdinal), 'CUSTODY_DESCRIPTOR_REJECTED')
      }
      const peerSwap = clone(response)
      peerSwap.sender_binding_code = 'bundle.importer.synthetic'
      peerSwap.record_digest_sha256 = recordDigest(peerSwap)
      assertThrowsCode(() => validateAdapterPair(request, peerSwap), 'CUSTODY_ROLE_REJECTED')
    }
    for (const field of rule.request_nonnull_fields) {
      const missing = clone(request)
      missing.payload[field] = null
      missing.record_digest_sha256 = recordDigest(missing)
      assertThrowsCode(() => validateAdapterMessage(missing), 'CUSTODY_MATRIX_REJECTED')
    }
    const extra = clone(request)
    const extraField = adapterPayloadKeys.find((key) => extra.payload[key] === null && key !== 'outcome_code' && key !== 'error_code')
    extra.payload[extraField] = payloadValue(extraField)
    extra.record_digest_sha256 = recordDigest(extra)
    assertThrowsCode(() => validateAdapterMessage(extra), 'CUSTODY_MATRIX_REJECTED')
    const wrongDescriptor = clone(request)
    wrongDescriptor.ancillary_descriptors = descriptor('custody_source')
    wrongDescriptor.record_digest_sha256 = recordDigest(wrongDescriptor)
    assertThrowsCode(() => validateAdapterMessage(wrongDescriptor), 'CUSTODY_DESCRIPTOR_REJECTED')
  }
  const expectedVariants = classifications.custody_message_rules.reduce((sum, rule) => sum + 1 + rule.success_outcomes.length + rule.failure_outcomes.length, 0)
  assert.equal(variants, expectedVariants)
  const wrongFailure = bindAdapterResponse(makeAdapterMessage('prepare', 'request'), makeAdapterMessage('prepare', 'response', 'rejected'))
  wrongFailure.payload.error_code = 'CUSTODY_TIMEOUT'
  wrongFailure.record_digest_sha256 = recordDigest(wrongFailure)
  assertThrowsCode(() => validateAdapterMessage(wrongFailure), 'CUSTODY_FAILURE_ERROR_REJECTED')
  const withSecret = clone(makeAdapterMessage('prepare', 'request'))
  withSecret.payload.source_handle_token = { token: 'synthetic-secret' }
  assertThrowsCode(() => validateSchema(withSecret), 'SCHEMA_REJECTED')
  const request = makeAdapterMessage('publish_no_replace', 'request')
  const response = bindAdapterResponse(request, makeAdapterMessage('publish_no_replace', 'response', 'published'))
  const drift = clone(response)
  drift.payload.backend_reference = `objects/sha256/77/${sample.artifact.sha256}`
  drift.record_digest_sha256 = recordDigest(drift)
  assertThrowsCode(() => validateAdapterPair(request, drift), 'BACKEND_REFERENCE_MISMATCH')
  for (const streamRule of classifications.adapter_request_stream_rules) {
    const state = makeProtectedAdapterStreamState()
    let first = null
    for (const operation of streamRule.operation_codes) {
      const streamRequest = makeAdapterMessage(operation, 'request')
      const outcome = classifications.custody_message_rules.find((entry) => entry.operation_code === operation).success_outcomes[0]
      const streamResponse = bindAdapterResponse(streamRequest, makeAdapterMessage(operation, 'response', outcome))
      assert.equal(acceptAdapterExchange(streamRequest, streamResponse, state), true)
      if (!first) first = { request: streamRequest, response: streamResponse }
    }
    assert.equal(acceptAdapterExchange(first.request, first.response, state), false)
    const rewritten = clone(first.response)
    rewritten.created_at = new Date(Date.parse(rewritten.created_at) + 1).toISOString()
    rewritten.record_digest_sha256 = recordDigest(rewritten)
    assertThrowsCode(() => acceptAdapterExchange(first.request, rewritten, state), 'CUSTODY_STREAM_REPLAY_REJECTED')
    const skippedState = makeProtectedAdapterStreamState()
    const skippedOperation = streamRule.operation_codes[1]
    const skippedRequest = makeAdapterMessage(skippedOperation, 'request')
    const skippedOutcome = classifications.custody_message_rules.find((entry) => entry.operation_code === skippedOperation).success_outcomes[0]
    const skippedResponse = bindAdapterResponse(skippedRequest, makeAdapterMessage(skippedOperation, 'response', skippedOutcome))
    assertThrowsCode(() => acceptAdapterExchange(skippedRequest, skippedResponse, skippedState), 'CUSTODY_STREAM_REJECTED')
    const duplicateIdState = makeProtectedAdapterStreamState()
    assert.equal(acceptAdapterExchange(first.request, first.response, duplicateIdState), true)
    const nextOperation = streamRule.operation_codes[1]
    const duplicateIdRequest = makeAdapterMessage(nextOperation, 'request')
    duplicateIdRequest.request_id = first.request.request_id
    duplicateIdRequest.record_digest_sha256 = recordDigest(duplicateIdRequest)
    const duplicateIdOutcome = classifications.custody_message_rules.find((entry) => entry.operation_code === nextOperation).success_outcomes[0]
    const duplicateIdResponse = bindAdapterResponse(duplicateIdRequest, makeAdapterMessage(nextOperation, 'response', duplicateIdOutcome))
    assertThrowsCode(() => acceptAdapterExchange(duplicateIdRequest, duplicateIdResponse, duplicateIdState), 'CUSTODY_STREAM_REPLAY_REJECTED')
    const failedState = makeProtectedAdapterStreamState()
    const failedOutcome = classifications.custody_message_rules.find((entry) => entry.operation_code === first.request.operation_code).failure_outcomes[0]
    const failedResponse = bindAdapterResponse(first.request, makeAdapterMessage(first.request.operation_code, 'response', failedOutcome))
    assert.equal(acceptAdapterExchange(first.request, failedResponse, failedState), true)
    assert.equal(acceptAdapterExchange(first.request, failedResponse, failedState), false)
    const afterFailureRequest = makeAdapterMessage(nextOperation, 'request')
    const afterFailureResponse = bindAdapterResponse(afterFailureRequest, makeAdapterMessage(nextOperation, 'response', duplicateIdOutcome))
    assertThrowsCode(() => acceptAdapterExchange(afterFailureRequest, afterFailureResponse, failedState), 'CUSTODY_STREAM_REJECTED')
  }
}

const lifecycleVariantFields = {
  descriptor_delivery: [
    'transport_code',
    'descriptor_role_code',
    'access_code',
    'file_type_code',
    'peer_credentials_verified',
    'pidfd_supervision_active',
  ],
  verifier_result: [
    'descriptor_delivery_record_digest_sha256',
    'verification_outcome_code',
    'recomputed_artifact',
  ],
  access_closed_and_receiver_terminated: [
    'descriptor_delivery_record_digest_sha256',
    'verifier_result_record_digest_sha256',
    'sender_close_state_code',
    'sender_closed_at',
    'receiver_termination_state_code',
    'receiver_terminated_at',
    'termination_disposition_code',
    'receiver_descriptor_closed_by_termination',
    'lifecycle_outcome_code',
  ],
}

const lifecycleVariantFieldsAll = new Set(Object.values(lifecycleVariantFields).flat())

function validateIntegrityLifecycle(record, context = {}) {
  validateRecord(record)
  const required = lifecycleVariantFields[record.record_kind_code]
  if (!required) fail('LIFECYCLE_MATRIX_REJECTED', 'kind')
  for (const field of lifecycleVariantFieldsAll) {
    const shouldBePresent = required.includes(field)
    if (shouldBePresent !== (record[field] !== null)) fail('LIFECYCLE_MATRIX_REJECTED', field)
  }
  const producerRole = bindingRole(record.producer_binding_code)
  const expectedProducer = record.record_kind_code === 'verifier_result' ? 'independent_verifier' : 'trusted_launcher'
  if (producerRole !== expectedProducer || bindingRole(record.sender_binding_code) !== 'bundle_importer' || bindingRole(record.receiver_binding_code) !== 'independent_verifier' || record.receiver_binding_code !== record.verifier_binding_code) fail('LIFECYCLE_ROLE_REJECTED')
  if (record.record_kind_code === 'verifier_result' && record.producer_binding_code !== record.verifier_binding_code) fail('LIFECYCLE_IDENTITY_REJECTED', 'verifier producer identity')
  assertExactBackendReference(record.artifact, record.backend_reference)
  if (record.record_kind_code === 'verifier_result') {
    if (record.verification_outcome_code === 'passed' && canonicalize(record.recomputed_artifact) !== canonicalize(record.artifact)) fail('LIFECYCLE_IDENTITY_REJECTED')
    if (record.verification_outcome_code !== 'passed' && record.recomputed_artifact !== null) fail('LIFECYCLE_IDENTITY_REJECTED')
  }
  if (record.record_kind_code === 'access_closed_and_receiver_terminated') {
    const completed = record.lifecycle_outcome_code === 'completed_verified'
    const closureComplete = record.sender_close_state_code === 'confirmed'
      && record.receiver_termination_state_code === 'confirmed'
      && record.receiver_descriptor_closed_by_termination === true
      && ['clean_exit_reaped', 'signaled_reaped', 'forced_kill_reaped'].includes(record.termination_disposition_code)
    if (completed && !closureComplete) fail('LIFECYCLE_TERMINATION_REJECTED')
    if (completed && context.verifierResult && context.verifierResult.verification_outcome_code !== 'passed') fail('LIFECYCLE_TERMINATION_REJECTED', 'verification not passed')
    if (record.sender_closed_at > record.event_at || record.receiver_terminated_at > record.event_at) fail('CHRONOLOGY_REJECTED', 'lifecycle terminal')
  }
  const serialized = canonicalize(record)
  for (const prohibited of ['raw_descriptor', 'bearer', 'token', 'socket_path', 'credential', 'absolute_path']) if (serialized.includes(`\"${prohibited}`)) fail('LIFECYCLE_SECRET_REJECTED', prohibited)
}

function makeSourceCapability(openRequest) {
  const record = {
    format: 'jedi-atlas-custody-capability-control',
    format_version: '1.0.0',
    record_kind_code: 'capability_issuance',
    record_code: 'capability.source.synthetic.001',
    capability_kind_code: 'source_handle',
    issued_by_binding_code: 'custody.adapter.synthetic',
    requester_binding_code: 'bundle.importer.synthetic',
    adapter_binding_code: 'custody.adapter.synthetic',
    operation_id: openRequest.operation_id,
    operation_nonce: openRequest.operation_nonce,
    runtime_profile_record_digest_sha256: openRequest.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: openRequest.identity_bindings_record_digest_sha256,
    artifact: sample.artifact,
    allowed_consumer_operation_codes: ['prepare'],
    replay_policy_code: 'single_consume_prepare',
    grant_scope: {
      scope_kind_code: 'source_handle',
      basis_request_record_digest_sha256: openRequest.record_digest_sha256,
      collector_handoff_record_digest_sha256: openRequest.payload.collector_handoff_record_digest_sha256,
      bundle_seal_record_digest_sha256: openRequest.payload.bundle_seal_record_digest_sha256,
      staging_snapshot_code: openRequest.payload.staging_snapshot_code,
      staging_root_slot_code: 'staging_root',
      relative_path: openRequest.payload.relative_path,
      descriptor_role_code: 'staged_source',
      staged_source_descriptor_ordinal: 1,
    },
    issued_at: new Date(Date.parse(openRequest.created_at) + 1).toISOString(),
    expires_at: new Date(Date.parse(openRequest.created_at) + 30001).toISOString(),
    record_digest_sha256: sample.sha('01'),
  }
  record.record_digest_sha256 = recordDigest(record)
  validateFrozenCapability(record)
  return record
}

function makePreparationCapability(prepareRequest, sourceCapability) {
  const record = {
    format: 'jedi-atlas-custody-capability-control',
    format_version: '1.0.0',
    record_kind_code: 'capability_issuance',
    record_code: 'capability.preparation.synthetic.001',
    capability_kind_code: 'preparation',
    issued_by_binding_code: 'custody.adapter.synthetic',
    requester_binding_code: 'bundle.importer.synthetic',
    adapter_binding_code: 'custody.adapter.synthetic',
    operation_id: prepareRequest.operation_id,
    operation_nonce: prepareRequest.operation_nonce,
    runtime_profile_record_digest_sha256: prepareRequest.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: prepareRequest.identity_bindings_record_digest_sha256,
    artifact: sample.artifact,
    allowed_consumer_operation_codes: ['verify_prepared', 'publish_no_replace', 'abandon_temp'],
    replay_policy_code: 'ordered_verify_then_publish_or_abandon',
    grant_scope: {
      scope_kind_code: 'preparation',
      basis_request_record_digest_sha256: prepareRequest.record_digest_sha256,
      source_capability_record_digest_sha256: sourceCapability.record_digest_sha256,
      pending_object_code: 'pending.synthetic.001',
    },
    issued_at: new Date(Date.parse(prepareRequest.created_at) + 1).toISOString(),
    expires_at: new Date(Date.parse(prepareRequest.created_at) + 30001).toISOString(),
    record_digest_sha256: sample.sha('02'),
  }
  record.record_digest_sha256 = recordDigest(record)
  validateFrozenCapability(record)
  return record
}

function makeCapabilityTransition(capability, {
  recordCode,
  sequence,
  previous = null,
  from,
  to,
  transition,
  requestDigest,
  responseDigest = null,
  occurredAt,
  reason,
}) {
  const record = {
    format: 'jedi-atlas-custody-capability-control',
    format_version: '1.0.0',
    record_kind_code: 'capability_transition',
    record_code: recordCode,
    capability_kind_code: capability.capability_kind_code,
    capability_record_digest_sha256: capability.record_digest_sha256,
    transition_sequence: sequence,
    previous_transition_record_digest_sha256: previous,
    from_state_code: from,
    to_state_code: to,
    transition_code: transition,
    request_record_digest_sha256: requestDigest,
    response_record_digest_sha256: responseDigest,
    recorded_by_binding_code: 'custody.adapter.synthetic',
    occurred_at: occurredAt,
    reason_code: reason,
    record_digest_sha256: sample.sha('03'),
  }
  record.record_digest_sha256 = recordDigest(record)
  validateFrozenCapability(record)
  return record
}

function validateCapabilityIssuance(issuance, recordsByDigest) {
  const policy = frozenClassifications.custody_capability_rules.find((entry) => entry.capability_kind_code === issuance.capability_kind_code)
  if (!policy) fail('CAPABILITY_ISSUANCE_REJECTED', 'unknown capability kind')
  if (bindingRole(issuance.issued_by_binding_code) !== policy.issued_by_runtime_role_code
    || bindingRole(issuance.requester_binding_code) !== policy.requester_runtime_role_code
    || bindingRole(issuance.adapter_binding_code) !== policy.adapter_runtime_role_code) fail('CAPABILITY_ISSUANCE_REJECTED', 'roles')
  if (canonicalize(issuance.allowed_consumer_operation_codes) !== canonicalize(policy.allowed_consumer_operation_codes)
    || issuance.replay_policy_code !== policy.replay_policy_code) fail('CAPABILITY_ISSUANCE_REJECTED', 'scope')
  const lifetimeMs = Date.parse(issuance.expires_at) - Date.parse(issuance.issued_at)
  if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs <= 0 || lifetimeMs > policy.lifetime_ms_max) fail('CAPABILITY_ISSUANCE_REJECTED', 'lifetime')
  const basis = recordsByDigest.get(issuance.grant_scope.basis_request_record_digest_sha256)
  if (!basis || basis.format !== 'jedi-atlas-custody-adapter-message' || basis.message_kind_code !== 'request' || basis.operation_code !== policy.issuance_operation_code) fail('CAPABILITY_ISSUANCE_REJECTED', 'basis request')
  validateAdapterMessage(basis)
  for (const key of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) if (basis[key] !== issuance[key]) fail('CAPABILITY_ISSUANCE_REJECTED', key)
  if (basis.sender_binding_code !== issuance.requester_binding_code || basis.recipient_binding_code !== issuance.adapter_binding_code || basis.created_at >= issuance.issued_at) fail('CAPABILITY_ISSUANCE_REJECTED', 'basis chronology or actors')
  const responses = [...recordsByDigest.values()].filter((record) => record.format === 'jedi-atlas-custody-adapter-message'
    && record.message_kind_code === 'response'
    && record.request_record_digest_sha256 === basis.record_digest_sha256)
  if (responses.length !== 1) fail('CAPABILITY_ISSUANCE_REJECTED', 'issuance response')
  const response = responses[0]
  validateAdapterPair(basis, response)
  if (response.payload.outcome_code !== policy.issuance_outcome_code || response.created_at !== issuance.issued_at) fail('CAPABILITY_ISSUANCE_REJECTED', 'issuance outcome or chronology')
  const recordField = `${issuance.capability_kind_code === 'sealed_custody_access' ? 'sealed_capability' : issuance.capability_kind_code === 'source_handle' ? 'source_capability' : 'preparation_capability'}_record_digest_sha256`
  const leafField = recordField.replace('_record_digest_', '_leaf_record_digest_')
  if (response.payload[recordField] !== issuance.record_digest_sha256 || response.payload[leafField] !== issuance.record_digest_sha256) fail('CAPABILITY_ISSUANCE_REJECTED', 'response capability binding')
  const artifact = basis.payload.artifact ?? response.payload.artifact
  if (!artifact || canonicalize(artifact) !== canonicalize(issuance.artifact)) fail('CAPABILITY_ISSUANCE_REJECTED', 'artifact')
  if (issuance.capability_kind_code === 'source_handle') {
    const bindings = {
      collector_handoff_record_digest_sha256: basis.payload.collector_handoff_record_digest_sha256,
      bundle_seal_record_digest_sha256: basis.payload.bundle_seal_record_digest_sha256,
      staging_snapshot_code: basis.payload.staging_snapshot_code,
      staging_root_slot_code: basis.payload.staging_root_slot_code,
      relative_path: basis.payload.relative_path,
    }
    for (const [field, value] of Object.entries(bindings)) if (canonicalize(issuance.grant_scope[field]) !== canonicalize(value)) fail('CAPABILITY_ISSUANCE_REJECTED', `source ${field}`)
    const sourceDescriptors = response.ancillary_descriptors.filter((entry) => entry.role_code === 'staged_source')
    if (sourceDescriptors.length !== 1
      || issuance.grant_scope.descriptor_role_code !== sourceDescriptors[0].role_code
      || issuance.grant_scope.staged_source_descriptor_ordinal !== sourceDescriptors[0].ordinal) fail('CAPABILITY_ISSUANCE_REJECTED', 'source descriptor binding')
  } else if (issuance.capability_kind_code === 'preparation') {
    if (issuance.grant_scope.source_capability_record_digest_sha256 !== basis.payload.source_capability_record_digest_sha256
      || basis.payload.source_capability_leaf_record_digest_sha256 !== basis.payload.source_capability_record_digest_sha256) fail('CAPABILITY_ISSUANCE_REJECTED', 'preparation source capability')
  } else {
    for (const field of ['clearance_decision_record_digest_sha256', 'clearance_scope_sha256', 'backend_code', 'backend_reference', 'copy_code', 'purpose_code']) if (canonicalize(issuance.grant_scope[field]) !== canonicalize(basis.payload[field])) fail('CAPABILITY_ISSUANCE_REJECTED', `sealed ${field}`)
    for (const field of ['custody_leaf_projection_sha256', 'custody_evaluated_at', 'known_through_bundle_sequence']) if (canonicalize(issuance.grant_scope[field]) !== canonicalize(response.payload[field])) fail('CAPABILITY_ISSUANCE_REJECTED', `sealed ${field}`)
  }
}

function validateCapabilityLineage(issuance, transitions, relatedRecords) {
  validateFrozenCapability(issuance)
  if (!(issuance.issued_at < issuance.expires_at)) fail('CAPABILITY_LINEAGE_REJECTED', 'issuance chronology')
  if (bindingRole(issuance.issued_by_binding_code) !== 'custody_adapter' || bindingRole(issuance.adapter_binding_code) !== 'custody_adapter' || bindingRole(issuance.requester_binding_code) !== 'bundle_importer') fail('CAPABILITY_LINEAGE_REJECTED', 'issuance roles')
  const recordsByDigest = new Map()
  for (const record of relatedRecords ?? []) {
    if (!record.record_digest_sha256 || recordsByDigest.has(record.record_digest_sha256)) fail('CAPABILITY_LINEAGE_REJECTED', 'related record collision')
    recordsByDigest.set(record.record_digest_sha256, record)
  }
  validateCapabilityIssuance(issuance, recordsByDigest)
  const ordered = transitions.slice().sort((left, right) => left.transition_sequence - right.transition_sequence)
  let previous = null
  let currentState = 'ready'
  for (let index = 0; index < ordered.length; index += 1) {
    const transition = ordered[index]
    validateFrozenCapability(transition)
    if (transition.capability_record_digest_sha256 !== issuance.record_digest_sha256 || transition.capability_kind_code !== issuance.capability_kind_code) fail('CAPABILITY_LINEAGE_REJECTED', 'issuance')
    if (transition.transition_sequence !== index + 1 || transition.previous_transition_record_digest_sha256 !== (previous?.record_digest_sha256 ?? null)) fail('CAPABILITY_LINEAGE_REJECTED', 'chain')
    if (transition.from_state_code !== currentState) fail('CAPABILITY_LINEAGE_REJECTED', 'state continuity')
    if (transition.recorded_by_binding_code !== issuance.adapter_binding_code) fail('CAPABILITY_LINEAGE_REJECTED', 'recorder')
    if (transition.occurred_at <= issuance.issued_at || transition.occurred_at >= issuance.expires_at || (previous && previous.occurred_at >= transition.occurred_at)) fail('CAPABILITY_LINEAGE_REJECTED', 'chronology')
    const rules = frozenClassifications.custody_capability_transition_rules.filter((rule) => rule.capability_kind_code === transition.capability_kind_code
      && rule.from_state_code === transition.from_state_code
      && rule.to_state_code === transition.to_state_code
      && rule.transition_code === transition.transition_code
      && rule.reason_code === transition.reason_code)
    if (rules.length !== 1) fail('CAPABILITY_LINEAGE_REJECTED', 'transition rule')
    const rule = rules[0]
    const request = recordsByDigest.get(transition.request_record_digest_sha256)
    if (!request || request.format !== 'jedi-atlas-custody-adapter-message' || request.message_kind_code !== 'request' || request.operation_code !== rule.consumer_operation_code) fail('CAPABILITY_LINEAGE_REJECTED', 'request resolution')
    validateAdapterMessage(request)
    const capabilityPrefix = issuance.capability_kind_code === 'sealed_custody_access' ? 'sealed_capability' : issuance.capability_kind_code === 'source_handle' ? 'source_capability' : 'preparation_capability'
    const capabilityRecordField = `${capabilityPrefix}_record_digest_sha256`
    const capabilityLeafField = `${capabilityPrefix}_leaf_record_digest_sha256`
    if (request.payload[capabilityRecordField] !== issuance.record_digest_sha256
      || request.payload[capabilityLeafField] !== (previous?.record_digest_sha256 ?? issuance.record_digest_sha256)) fail('CAPABILITY_LINEAGE_REJECTED', 'request capability leaf')
    for (const key of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) if (request[key] !== issuance[key]) fail('CAPABILITY_LINEAGE_REJECTED', key)
    if (request.sender_binding_code !== issuance.requester_binding_code || request.recipient_binding_code !== issuance.adapter_binding_code || request.created_at <= issuance.issued_at || request.created_at > transition.occurred_at) fail('CAPABILITY_LINEAGE_REJECTED', 'request context')
    const response = transition.response_record_digest_sha256 === null ? null : recordsByDigest.get(transition.response_record_digest_sha256)
    if (rule.response_policy_code === 'must_be_null') {
      if (response !== null) fail('CAPABILITY_LINEAGE_REJECTED', 'forbidden response')
      const requestResponses = [...recordsByDigest.values()].filter((record) => record.format === 'jedi-atlas-custody-adapter-message'
        && record.message_kind_code === 'response'
        && record.request_record_digest_sha256 === request.record_digest_sha256)
      if (requestResponses.length !== 1) fail('CAPABILITY_LINEAGE_REJECTED', 'atomic request claim response window')
      validateAdapterPair(request, requestResponses[0])
      if (transition.occurred_at < request.created_at || transition.occurred_at > requestResponses[0].created_at) fail('CAPABILITY_LINEAGE_REJECTED', 'atomic request claim chronology')
    } else {
      if (!response) fail('CAPABILITY_LINEAGE_REJECTED', 'response resolution')
      validateAdapterPair(request, response)
      if (response.created_at !== transition.occurred_at) fail('CAPABILITY_LINEAGE_REJECTED', 'response chronology')
      const operationRule = classifications.custody_message_rules.find((entry) => entry.operation_code === request.operation_code)
      const outcome = response.payload.outcome_code
      if (rule.response_policy_code === 'required' && !operationRule.success_outcomes.includes(outcome)) fail('CAPABILITY_LINEAGE_REJECTED', 'successful response')
      if (rule.response_policy_code === 'required_corrupt' && outcome !== 'corrupt') fail('CAPABILITY_LINEAGE_REJECTED', 'corrupt response')
    }
    previous = transition
    currentState = transition.to_state_code
  }
  return previous ?? issuance
}

function assertCustodyTransitions() {
  const transitions = classifications.custody_state_transition_rules
  const tupleKeys = transitions.flatMap((entry) => entry.outcome_codes.map((outcome) => `${entry.from_state_code}\0${entry.trigger_record_kind_code}\0${entry.operation_code}\0${outcome}`))
  assert.equal(new Set(tupleKeys).size, tupleKeys.length, 'duplicate custody transition tuple')
  const pathStates = ['none', 'staged_opened', 'prepared', 'verified', 'primary_receipt_persisted', 'adapter_response_emitted', 'journal_linked']
  for (let index = 0; index < pathStates.length - 1; index += 1) {
    assert.ok(transitions.some((entry) => entry.from_state_code === pathStates[index] && entry.to_state_code === pathStates[index + 1]))
  }
  const apply = (state, trigger, operation, outcome) => {
    const matches = transitions.filter((entry) => entry.from_state_code === state && entry.trigger_record_kind_code === trigger && entry.operation_code === operation && entry.outcome_codes.includes(outcome))
    if (matches.length !== 1) fail('CUSTODY_TRANSITION_REJECTED')
    return matches[0].to_state_code
  }
  let state = 'none'
  const triggerFacts = [
    ['adapter_response', 'open_staged', 'opened'],
    ['adapter_response', 'prepare', 'prepared'],
    ['adapter_response', 'verify_prepared', 'verified'],
    ['receipt_broker_response', 'persist_primary_receipt', 'persisted'],
    ['adapter_response', 'publish_no_replace', 'published'],
    ['journal_broker_response', 'journal_append', 'persisted'],
  ]
  for (const [trigger, operation, outcome] of triggerFacts) state = apply(state, trigger, operation, outcome)
  assert.equal(state, 'journal_linked')
  assertThrowsCode(() => apply('prepared', 'adapter_response', 'publish_no_replace', 'published'), 'CUSTODY_TRANSITION_REJECTED')
  assertThrowsCode(() => apply('verified', 'adapter_response', 'prepare', 'prepared'), 'CUSTODY_TRANSITION_REJECTED')
  assertThrowsCode(() => apply('journal_linked', 'adapter_response', 'publish_no_replace', 'published'), 'CUSTODY_TRANSITION_REJECTED')
  assertThrowsCode(() => apply('primary_receipt_persisted', 'receipt_broker_response', 'publish_no_replace', 'published'), 'CUSTODY_TRANSITION_REJECTED')
  const states = new Set(['none', ...transitions.flatMap((entry) => [entry.from_state_code, entry.to_state_code])])
  const triggers = new Set(transitions.map((entry) => entry.trigger_record_kind_code))
  const operations = new Set(transitions.map((entry) => entry.operation_code))
  const outcomes = new Set(transitions.flatMap((entry) => entry.outcome_codes))
  for (const stateCode of states) {
    for (const triggerCode of triggers) {
      for (const operationCode of operations) {
        for (const outcomeCode of outcomes) {
          const expectedMatches = transitions.filter((entry) => entry.from_state_code === stateCode && entry.trigger_record_kind_code === triggerCode && entry.operation_code === operationCode && entry.outcome_codes.includes(outcomeCode))
          if (expectedMatches.length === 1) assert.equal(apply(stateCode, triggerCode, operationCode, outcomeCode), expectedMatches[0].to_state_code)
          else assertThrowsCode(() => apply(stateCode, triggerCode, operationCode, outcomeCode), 'CUSTODY_TRANSITION_REJECTED')
        }
      }
    }
  }
}

function receiptBytesSha(receipt) {
  return sha256Bytes(Buffer.from(canonicalize(receipt), 'utf8'))
}

function validatePrimaryReceipt(receipt, context = {}) {
  validateSchema(receipt)
  validateAllTimestamps(receipt)
  if (receipt.semantic_payload_sha256 !== semanticDigest(receipt.semantic)) fail('RECEIPT_SEMANTIC_DIGEST_MISMATCH')
  if (receipt.persisted_by_binding_code !== 'journal.broker.synthetic') fail('RECEIPT_BROKER_REJECTED')
  if (receipt.semantic.adapter_binding_code !== 'custody.adapter.synthetic') fail('RECEIPT_ADAPTER_REJECTED')
  if (receipt.semantic.completed_at > receipt.persisted_at) fail('CHRONOLOGY_REJECTED', 'receipt')
  if (context.persistence_request_created_at && receipt.semantic.completed_at > context.persistence_request_created_at) fail('CHRONOLOGY_REJECTED', 'receipt request')
  assertExactBackendReference(receipt.semantic.artifact, receipt.semantic.backend_reference)
  const rule = classifications.primary_receipt_rules.find((entry) => entry.finalization_outcome_code === receipt.semantic.finalization_outcome_code)
  if (!rule || rule.no_replace_disposition_code !== receipt.semantic.no_replace_disposition_code) fail('RECEIPT_MATRIX_REJECTED')
  for (const claim of rule.required_claims) if (receipt.semantic[claim] !== true) fail('RECEIPT_MATRIX_REJECTED', claim)
  const pairs = [
    ['operation_id', receipt.semantic.operation_id],
    ['operation_nonce', receipt.semantic.operation_nonce],
    ['bundle', receipt.semantic.bundle],
    ['artifact', receipt.semantic.artifact],
    ['copy_code', receipt.semantic.copy_code],
    ['backend_code', receipt.semantic.backend_code],
    ['backend_reference', receipt.semantic.backend_reference],
    ['runtime_profile_record_digest_sha256', receipt.runtime_profile_record_digest_sha256],
    ['identity_bindings_record_digest_sha256', receipt.identity_bindings_record_digest_sha256],
    ['d930_operational_profile_record_digest_sha256', receipt.d930_operational_profile_record_digest_sha256],
    ['persistence_request_record_digest_sha256', receipt.persistence_request_record_digest_sha256],
  ]
  for (const [key, value] of pairs) {
    if (Object.hasOwn(context, key) && canonicalize(value) !== canonicalize(context[key])) fail('RECEIPT_BINDING_MISMATCH', key)
  }
  return receiptBytesSha(receipt)
}

function validateReceiptBrokerMessage(message) {
  validateRecord(message)
  const rules = classifications.receipt_broker_rules
  const request = message.message_kind_code === 'persist_request'
  const senderRole = bindingRole(message.sender_binding_code)
  const recipientRole = bindingRole(message.recipient_binding_code)
  if (request && (senderRole !== rules.request_sender_role_code || recipientRole !== rules.request_recipient_role_code)) fail('BROKER_ROLE_REJECTED')
  if (!request && (senderRole !== rules.response_sender_role_code || recipientRole !== rules.response_recipient_role_code)) fail('BROKER_ROLE_REJECTED')
  if (request !== (message.request_record_digest_sha256 === null)) fail('BROKER_PAIR_REJECTED', 'request chain')
  const outcome = message.payload.outcome_code
  const fields = request
    ? rules.request_nonnull_fields
    : rules.success_outcome_codes.includes(outcome)
      ? rules.success_nonnull_fields
      : rules.failure_outcome_codes.includes(outcome)
        ? rules.failure_nonnull_fields
        : null
  if (!fields) fail('BROKER_MATRIX_REJECTED', 'outcome')
  if (!request && rules.failure_outcome_codes.includes(outcome)) {
    const failureRule = rules.failure_error_rules.find((entry) => entry.outcome_code === outcome)
    if (!failureRule || message.payload.error_code !== failureRule.error_code) fail('BROKER_FAILURE_ERROR_REJECTED', 'receipt')
  }
  const nonnull = Object.entries(message.payload).filter(([, value]) => value !== null).map(([key]) => key).sort()
  if (canonicalize(nonnull) !== canonicalize(fields.slice().sort())) fail('BROKER_MATRIX_REJECTED', 'field set')
}

function validateReceiptSupportingPrerequisites(receipt, supportingPairs) {
  if (!Array.isArray(supportingPairs) || supportingPairs.length !== 7) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE')
  const records = new Map()
  for (const pair of supportingPairs) {
    validateSupportingBrokerPair(pair.request, pair.response, pair.record)
    for (const field of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256']) {
      const receiptValue = Object.hasOwn(receipt.semantic, field) ? receipt.semantic[field] : receipt[field]
      if (canonicalize(pair.record[field]) !== canonicalize(receiptValue)) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `context ${field}`)
    }
    if (records.has(pair.record.record_digest_sha256)) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'duplicate')
    records.set(pair.record.record_digest_sha256, pair)
  }
  const responseRequirements = [
    ['open_staged_response_record_digest_sha256', 'open_staged', 'opened'],
    ['prepare_response_record_digest_sha256', 'prepare', 'prepared'],
    ['verify_prepared_response_record_digest_sha256', 'verify_prepared', 'verified'],
  ]
  const exactRecordDigests = new Set()
  const expectedArtifactContext = {
    artifact: receipt.semantic.artifact,
    copy_code: receipt.semantic.copy_code,
    backend_code: receipt.semantic.backend_code,
    backend_reference: receipt.semantic.backend_reference,
  }
  for (const [field, operationCode, outcomeCode] of responseRequirements) {
    const digest = receipt.semantic[field]
    const responsePair = records.get(digest)
    if (!responsePair || responsePair.record.message_kind_code !== 'response' || responsePair.record.operation_code !== operationCode || responsePair.record.payload.outcome_code !== outcomeCode) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', field)
    const requestPair = records.get(responsePair.record.request_record_digest_sha256)
    if (!requestPair || requestPair.record.message_kind_code !== 'request' || requestPair.record.operation_code !== operationCode) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${field} request`)
    validateAdapterPair(requestPair.record, responsePair.record)
    if (operationCode === 'open_staged') {
      if (canonicalize(responsePair.record.payload.artifact) !== canonicalize(receipt.semantic.artifact)
        || requestPair.record.payload.bundle_seal_record_digest_sha256 !== receipt.semantic.bundle_seal_record_digest_sha256
        || canonicalize(requestPair.record.payload.custody_intent) !== canonicalize({
          bundle: receipt.semantic.bundle,
          bundle_seal_record_digest_sha256: receipt.semantic.bundle_seal_record_digest_sha256,
          custody_event_code: 'placement',
          ...expectedArtifactContext,
          custody_class_code: 'restricted_store',
        })) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${field} artifact, seal, or intent`)
    } else {
      if (canonicalize(requestPair.record.payload.artifact) !== canonicalize(receipt.semantic.artifact)
        || canonicalize(requestPair.record.payload.custody_intent) !== canonicalize({
          bundle: receipt.semantic.bundle,
          bundle_seal_record_digest_sha256: receipt.semantic.bundle_seal_record_digest_sha256,
          custody_event_code: 'placement',
          ...expectedArtifactContext,
          custody_class_code: 'restricted_store',
        })) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `${field} artifact or intent`)
    }
    if (responsePair.record.created_at > receipt.semantic.completed_at) fail('CHRONOLOGY_REJECTED', `${field} completion`)
    exactRecordDigests.add(requestPair.record.record_digest_sha256)
    exactRecordDigests.add(responsePair.record.record_digest_sha256)
  }
  const publishRequestPair = records.get(receipt.semantic.publish_request_record_digest_sha256)
  if (!publishRequestPair || publishRequestPair.record.operation_code !== 'publish_no_replace' || publishRequestPair.record.message_kind_code !== 'request') fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'publish request')
  if (publishRequestPair.record.created_at > receipt.semantic.completed_at) fail('CHRONOLOGY_REJECTED', 'publish request completion')
  for (const [field, value] of Object.entries(expectedArtifactContext)) if (canonicalize(publishRequestPair.record.payload[field]) !== canonicalize(value)) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', `publish ${field}`)
  if (canonicalize(publishRequestPair.record.payload.custody_intent) !== canonicalize({
    bundle: receipt.semantic.bundle,
    bundle_seal_record_digest_sha256: receipt.semantic.bundle_seal_record_digest_sha256,
    custody_event_code: 'placement',
    ...expectedArtifactContext,
    custody_class_code: 'restricted_store',
  })) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'publish intent')
  exactRecordDigests.add(publishRequestPair.record.record_digest_sha256)
  if (exactRecordDigests.size !== 7 || records.size !== exactRecordDigests.size || [...records.keys()].some((digest) => !exactRecordDigests.has(digest))) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'non-bijective records')
  const journalCodes = new Set(supportingPairs.map((pair) => pair.request.payload.journal_code))
  if (journalCodes.size !== 1) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'journal context')
  return { lastSupportingAt: Math.max(...supportingPairs.map((pair) => Date.parse(pair.response.created_at))), journalCode: [...journalCodes][0] }
}

function validateReceiptBrokerPair(request, response, receipt, supportingPairs, context = {}) {
  validateReceiptBrokerMessage(request)
  validateReceiptBrokerMessage(response)
  const rules = classifications.receipt_broker_rules
  if (request.d930_operational_profile_record_digest_sha256 !== validFixtures.records.custody_profile.record_digest_sha256 || request.d930_journal_profile_record_digest_sha256 !== validFixtures.records.journal_profile.record_digest_sha256) fail('BROKER_PROFILE_REJECTED')
  for (const key of ['operation_id', 'operation_nonce', 'request_id', 'request_sequence', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256', 'd930_journal_profile_record_digest_sha256']) if (canonicalize(request[key]) !== canonicalize(response[key])) fail('BROKER_PAIR_REJECTED', key)
  if (request.sender_binding_code !== response.recipient_binding_code || request.recipient_binding_code !== response.sender_binding_code) fail('BROKER_PAIR_REJECTED', 'peers')
  if (request.request_record_digest_sha256 !== null || response.request_record_digest_sha256 !== request.record_digest_sha256) fail('BROKER_PAIR_REJECTED', 'request chain')
  if (response.created_at < request.created_at) fail('CHRONOLOGY_REJECTED', 'broker')
  if (!rules.success_outcome_codes.includes(response.payload.outcome_code)) fail('BROKER_MATRIX_REJECTED', 'outcome')
  if (request.payload.receipt_record_code !== receipt.record_code || canonicalize(request.payload.receipt_semantic) !== canonicalize(receipt.semantic)) fail('BROKER_RECEIPT_MISMATCH')
  if (request.sender_binding_code !== receipt.semantic.adapter_binding_code || response.sender_binding_code !== receipt.persisted_by_binding_code) fail('BROKER_RECEIPT_MISMATCH', 'actors')
  if (request.payload.receipt_semantic_sha256 !== semanticDigest(request.payload.receipt_semantic) || request.payload.receipt_semantic_sha256 !== receipt.semantic_payload_sha256) fail('BROKER_RECEIPT_MISMATCH', 'semantic')
  if (receipt.persistence_request_record_digest_sha256 !== request.record_digest_sha256) fail('BROKER_RECEIPT_MISMATCH', 'request')
  if (receipt.persisted_at < request.created_at) fail('CHRONOLOGY_REJECTED', 'receipt persistence')
  if (response.payload.receipt_record_code !== receipt.record_code || response.payload.receipt_raw_sha256 !== receiptBytesSha(receipt) || response.payload.receipt_persisted_at !== receipt.persisted_at) fail('BROKER_RECEIPT_MISMATCH', 'response')
  if (response.created_at < receipt.persisted_at) fail('CHRONOLOGY_REJECTED', 'broker response')
  const { lastSupportingAt, journalCode } = validateReceiptSupportingPrerequisites(receipt, supportingPairs)
  if (context.journalCode && journalCode !== context.journalCode) fail('RECEIPT_SUPPORTING_RECORDS_INCOMPLETE', 'operation journal')
  if (lastSupportingAt > Date.parse(request.created_at)) fail('CHRONOLOGY_REJECTED', 'receipt supporting records')
  validatePrimaryReceipt(receipt, { ...request, persistence_request_created_at: request.created_at })
}

function makeProtectedBrokerState() {
  return {
    requestKeyDigests: new Map(),
    acceptedByRequestDigest: new Map(),
    persistedRecordDigests: new Map(),
  }
}

function acceptProtectedBrokerExchange(request, response, persistedRecordCode, persistedRecordDigest, protectedState) {
  const requestKey = `${request.format}:${request.message_kind_code}:${request.operation_id}:${request.operation_nonce}:${request.request_id}`
  const priorRequestDigest = protectedState.requestKeyDigests.get(requestKey)
  if (priorRequestDigest && priorRequestDigest !== request.record_digest_sha256) fail('BROKER_REPLAY_CONFLICT_REJECTED', 'request key')
  const priorRecordDigest = protectedState.persistedRecordDigests.get(persistedRecordCode)
  if (priorRecordDigest && priorRecordDigest !== persistedRecordDigest) fail('BROKER_REPLAY_CONFLICT_REJECTED', 'persisted record code')
  const prior = protectedState.acceptedByRequestDigest.get(request.record_digest_sha256)
  if (prior) {
    if (prior.response_record_digest_sha256 !== response.record_digest_sha256
      || prior.persisted_record_code !== persistedRecordCode
      || prior.persisted_record_digest !== persistedRecordDigest) fail('BROKER_REPLAY_CONFLICT_REJECTED', 'response bytes')
    return false
  }
  if (response.payload.outcome_code !== 'persisted') fail('BROKER_REPLAY_CONFLICT_REJECTED', 'unrecorded existing_exact')
  protectedState.requestKeyDigests.set(requestKey, request.record_digest_sha256)
  protectedState.persistedRecordDigests.set(persistedRecordCode, persistedRecordDigest)
  protectedState.acceptedByRequestDigest.set(request.record_digest_sha256, {
    response_record_digest_sha256: response.record_digest_sha256,
    persisted_record_code: persistedRecordCode,
    persisted_record_digest: persistedRecordDigest,
  })
  return true
}

function acceptReceiptBrokerExchange(request, response, receipt, supportingPairs, protectedState, context = {}) {
  validateReceiptBrokerPair(request, response, receipt, supportingPairs, context)
  return acceptProtectedBrokerExchange(request, response, receipt.record_code, receiptBytesSha(receipt), protectedState)
}

function acceptSupportingBrokerExchange(request, response, supportingRecord, protectedState) {
  validateSupportingBrokerPair(request, response, supportingRecord)
  return acceptProtectedBrokerExchange(request, response, supportingRecord.record_code, supportingRecord.record_digest_sha256, protectedState)
}

function recomputeReceiptSet(set) {
  const request = set.receipt_broker_request
  request.payload.receipt_semantic_sha256 = semanticDigest(request.payload.receipt_semantic)
  request.record_digest_sha256 = recordDigest(request)
  const receipt = set.primary_receipt
  receipt.semantic = clone(request.payload.receipt_semantic)
  receipt.semantic_payload_sha256 = request.payload.receipt_semantic_sha256
  receipt.persistence_request_record_digest_sha256 = request.record_digest_sha256
  const raw = receiptBytesSha(receipt)
  const response = set.receipt_broker_response
  response.request_record_digest_sha256 = request.record_digest_sha256
  response.payload.receipt_record_code = receipt.record_code
  response.payload.receipt_semantic_sha256 = null
  response.payload.receipt_raw_sha256 = raw
  response.payload.receipt_persisted_at = receipt.persisted_at
  response.record_digest_sha256 = recordDigest(response)
  return raw
}

function assertReceiptsAndBroker() {
  const records = validFixtures.records
  assert.equal(records.receipt_broker_request.d930_operational_profile_record_digest_sha256, records.custody_profile.record_digest_sha256)
  assert.equal(records.receipt_broker_request.d930_journal_profile_record_digest_sha256, records.journal_profile.record_digest_sha256)
  const raw = validatePrimaryReceipt(records.primary_receipt, {
    operation_id: records.receipt_broker_request.operation_id,
    operation_nonce: records.receipt_broker_request.operation_nonce,
    runtime_profile_record_digest_sha256: records.receipt_broker_request.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: records.receipt_broker_request.identity_bindings_record_digest_sha256,
    d930_operational_profile_record_digest_sha256: records.receipt_broker_request.d930_operational_profile_record_digest_sha256,
    persistence_request_record_digest_sha256: records.receipt_broker_request.record_digest_sha256,
  })
  assert.equal(raw, golden.complete_primary_receipt.raw_sha256)
  validateReceiptBrokerMessage(records.receipt_broker_request)
  validateReceiptBrokerMessage(records.receipt_broker_response)
  assertThrowsCode(() => validateReceiptBrokerPair(records.receipt_broker_request, records.receipt_broker_response, records.primary_receipt, []), 'RECEIPT_SUPPORTING_RECORDS_INCOMPLETE')
  const existingExact = clone(records.receipt_broker_response)
  existingExact.payload.outcome_code = 'existing_exact'
  existingExact.record_digest_sha256 = recordDigest(existingExact)
  assertThrowsCode(() => validateReceiptBrokerMessage(existingExact), 'SCHEMA_REJECTED')
  for (const outcome of classifications.receipt_broker_rules.failure_outcome_codes) {
    const failure = clone(records.receipt_broker_response)
    failure.payload = Object.fromEntries(Object.keys(failure.payload).map((key) => [key, null]))
    failure.payload.outcome_code = outcome
    failure.payload.error_code = classifications.receipt_broker_rules.failure_error_rules.find((entry) => entry.outcome_code === outcome).error_code
    failure.record_digest_sha256 = recordDigest(failure)
    validateReceiptBrokerMessage(failure)
  }
  const wrongFailure = clone(records.receipt_broker_response)
  wrongFailure.payload = Object.fromEntries(Object.keys(wrongFailure.payload).map((key) => [key, null]))
  wrongFailure.payload.outcome_code = 'rejected'
  wrongFailure.payload.error_code = 'D930_RECEIPT_STORE_UNAVAILABLE'
  wrongFailure.record_digest_sha256 = recordDigest(wrongFailure)
  assertThrowsCode(() => validateReceiptBrokerMessage(wrongFailure), 'BROKER_FAILURE_ERROR_REJECTED')
  const wrongJournalProfile = clone(records.receipt_broker_request)
  wrongJournalProfile.d930_journal_profile_record_digest_sha256 = sample.sha('ef')
  wrongJournalProfile.record_digest_sha256 = recordDigest(wrongJournalProfile)
  assertThrowsCode(() => validateReceiptBrokerPair(wrongJournalProfile, records.receipt_broker_response, records.primary_receipt), 'BROKER_PROFILE_REJECTED')
  const second = {
    receipt_broker_request: clone(records.receipt_broker_request),
    receipt_broker_response: clone(records.receipt_broker_response),
    primary_receipt: clone(records.primary_receipt),
  }
  second.receipt_broker_request.record_code = 'broker.receipt.request.002'
  second.receipt_broker_request.request_id = 'broker.receipt.002'
  second.receipt_broker_request.operation_id = 'operation.synthetic.002'
  second.receipt_broker_request.operation_nonce = sample.sha('42')
  second.receipt_broker_request.payload.receipt_record_code = 'receipt.primary.002'
  second.receipt_broker_request.payload.receipt_semantic.operation_id = second.receipt_broker_request.operation_id
  second.receipt_broker_request.payload.receipt_semantic.operation_nonce = second.receipt_broker_request.operation_nonce
  second.primary_receipt.record_code = 'receipt.primary.002'
  second.receipt_broker_response.record_code = 'broker.receipt.response.002'
  second.receipt_broker_response.request_id = second.receipt_broker_request.request_id
  second.receipt_broker_response.operation_id = second.receipt_broker_request.operation_id
  second.receipt_broker_response.operation_nonce = second.receipt_broker_request.operation_nonce
  recomputeReceiptSet(second)
  validatePrimaryReceipt(second.primary_receipt, {
    operation_id: second.receipt_broker_request.operation_id,
    operation_nonce: second.receipt_broker_request.operation_nonce,
    persistence_request_record_digest_sha256: second.receipt_broker_request.record_digest_sha256,
  })
  assert.notEqual(receiptBytesSha(second.primary_receipt), raw)
  const crossContext = clone(second.primary_receipt)
  assertThrowsCode(() => validatePrimaryReceipt(crossContext, { operation_id: records.primary_receipt.semantic.operation_id }), 'RECEIPT_BINDING_MISMATCH')
  const wrongFanout = clone(records.primary_receipt)
  wrongFanout.semantic.backend_reference = `objects/sha256/77/${wrongFanout.semantic.artifact.sha256}`
  wrongFanout.semantic_payload_sha256 = semanticDigest(wrongFanout.semantic)
  assertThrowsCode(() => validatePrimaryReceipt(wrongFanout), 'BACKEND_REFERENCE_MISMATCH')
  const replay = new Map()
  const accept = (code, digest) => {
    if (replay.has(code) && replay.get(code) !== digest) fail('CONFLICTING_REPLAY')
    replay.set(code, digest)
  }
  accept(records.primary_receipt.record_code, raw)
  accept(records.primary_receipt.record_code, raw)
  assertThrowsCode(() => accept(records.primary_receipt.record_code, receiptBytesSha(second.primary_receipt)), 'CONFLICTING_REPLAY')
}

let validatedFinalizationReceiptGraph = null

function assertFinalizationResolverGraph() {
  const at = (seconds, millis = 0) => new Date(Date.parse('2030-01-01T00:09:00.000Z') + seconds * 1000 + millis).toISOString()
  const finalizationJournalCode = 'journal.operation.synthetic.graph'
  const makeRequest = (operation, seconds, overrides = {}) => {
    const request = makeAdapterMessage(operation, 'request')
    request.operation_id = 'operation.synthetic.graph'
    request.operation_nonce = sample.sha('b0')
    request.request_id = `request.graph.${operation}`
    request.created_at = at(seconds)
    Object.assign(request.payload, clone(overrides))
    request.record_digest_sha256 = recordDigest(request)
    validateAdapterMessage(request)
    return request
  }
  const makeResponse = (request, outcome, overrides = {}, createdAt = null) => {
    const response = makeAdapterMessage(request.operation_code, 'response', outcome)
    Object.assign(response.payload, clone(overrides))
    bindAdapterResponse(request, response)
    if (createdAt) {
      response.created_at = createdAt
      response.record_digest_sha256 = recordDigest(response)
    }
    validateAdapterPair(request, response)
    return response
  }

  const openRequest = makeRequest('open_staged', 0)
  const sourceIssuance = makeSourceCapability(openRequest)
  const openResponse = makeResponse(openRequest, 'opened', {
    artifact: sample.artifact,
    source_capability_record_digest_sha256: sourceIssuance.record_digest_sha256,
    source_capability_leaf_record_digest_sha256: sourceIssuance.record_digest_sha256,
  })

  const prepareRequest = makeRequest('prepare', 5, {
    artifact: sample.artifact,
    custody_intent: sample.intent,
    source_capability_record_digest_sha256: sourceIssuance.record_digest_sha256,
    source_capability_leaf_record_digest_sha256: sourceIssuance.record_digest_sha256,
  })
  const sourceConsumed = makeCapabilityTransition(sourceIssuance, {
    recordCode: 'capability.source.consumed.synthetic.001',
    sequence: 1,
    from: 'ready',
    to: 'consumed',
    transition: 'consumer_succeeded',
    requestDigest: prepareRequest.record_digest_sha256,
    occurredAt: prepareRequest.created_at,
    reason: 'request_claimed',
  })
  const preparationIssuance = makePreparationCapability(prepareRequest, sourceIssuance)
  const prepareResponse = makeResponse(prepareRequest, 'prepared', {
    source_capability_record_digest_sha256: sourceIssuance.record_digest_sha256,
    source_capability_leaf_record_digest_sha256: sourceIssuance.record_digest_sha256,
    preparation_capability_record_digest_sha256: preparationIssuance.record_digest_sha256,
    preparation_capability_leaf_record_digest_sha256: preparationIssuance.record_digest_sha256,
  })

  const verifyRequest = makeRequest('verify_prepared', 10, {
    artifact: sample.artifact,
    custody_intent: sample.intent,
    preparation_capability_record_digest_sha256: preparationIssuance.record_digest_sha256,
    preparation_capability_leaf_record_digest_sha256: preparationIssuance.record_digest_sha256,
  })
  const verifyResponse = makeResponse(verifyRequest, 'verified')
  const preparationVerified = makeCapabilityTransition(preparationIssuance, {
    recordCode: 'capability.preparation.verified.synthetic.001',
    sequence: 1,
    from: 'ready',
    to: 'verified',
    transition: 'verification_succeeded',
    requestDigest: verifyRequest.record_digest_sha256,
    responseDigest: verifyResponse.record_digest_sha256,
    occurredAt: verifyResponse.created_at,
    reason: 'verified_response',
  })

  const publishRequest = makeRequest('publish_no_replace', 15, {
    artifact: sample.artifact,
    copy_code: sample.intent.copy_code,
    backend_code: sample.intent.backend_code,
    backend_reference: sample.intent.backend_reference,
    custody_intent: sample.intent,
    preparation_capability_record_digest_sha256: preparationIssuance.record_digest_sha256,
    preparation_capability_leaf_record_digest_sha256: preparationVerified.record_digest_sha256,
  })
  const preReceiptSupporting = [openRequest, openResponse, prepareRequest, prepareResponse, verifyRequest, verifyResponse, publishRequest].map((record) => {
    const pair = makeSupportingBrokerPair(record, 0, finalizationJournalCode)
    validateSupportingBrokerPair(pair.request, pair.response, record)
    return { ...pair, record }
  })
  const receiptSet = {
    receipt_broker_request: clone(validFixtures.records.receipt_broker_request),
    receipt_broker_response: clone(validFixtures.records.receipt_broker_response),
    primary_receipt: clone(validFixtures.records.primary_receipt),
  }
  const semantic = receiptSet.receipt_broker_request.payload.receipt_semantic
  Object.assign(semantic, {
    operation_id: publishRequest.operation_id,
    operation_nonce: publishRequest.operation_nonce,
    bundle: clone(sample.bundle),
    bundle_seal_record_digest_sha256: sample.intent.bundle_seal_record_digest_sha256,
    artifact: clone(sample.artifact),
    copy_code: sample.intent.copy_code,
    backend_code: sample.intent.backend_code,
    backend_reference: sample.intent.backend_reference,
    open_staged_response_record_digest_sha256: openResponse.record_digest_sha256,
    prepare_response_record_digest_sha256: prepareResponse.record_digest_sha256,
    verify_prepared_response_record_digest_sha256: verifyResponse.record_digest_sha256,
    publish_request_record_digest_sha256: publishRequest.record_digest_sha256,
    source_capability_consumed_transition_digest_sha256: sourceConsumed.record_digest_sha256,
    preparation_capability_issuance_digest_sha256: preparationIssuance.record_digest_sha256,
    preparation_capability_verified_transition_digest_sha256: preparationVerified.record_digest_sha256,
    completed_at: at(15, 100),
  })
  Object.assign(receiptSet.receipt_broker_request, {
    operation_id: publishRequest.operation_id,
    operation_nonce: publishRequest.operation_nonce,
    request_id: 'receipt.persist.graph.001',
    created_at: at(15, 200),
  })
  receiptSet.receipt_broker_request.payload.receipt_record_code = 'receipt.primary.graph.001'
  Object.assign(receiptSet.primary_receipt, {
    record_code: 'receipt.primary.graph.001',
    persisted_at: at(15, 300),
  })
  Object.assign(receiptSet.receipt_broker_response, {
    operation_id: publishRequest.operation_id,
    operation_nonce: publishRequest.operation_nonce,
    request_id: receiptSet.receipt_broker_request.request_id,
    created_at: at(15, 400),
  })
  const receiptRawSha = recomputeReceiptSet(receiptSet)
  validateReceiptBrokerPair(receiptSet.receipt_broker_request, receiptSet.receipt_broker_response, receiptSet.primary_receipt, preReceiptSupporting, { journalCode: finalizationJournalCode })
  const receiptBrokerState = makeProtectedBrokerState()
  assert.equal(acceptReceiptBrokerExchange(receiptSet.receipt_broker_request, receiptSet.receipt_broker_response, receiptSet.primary_receipt, preReceiptSupporting, receiptBrokerState, { journalCode: finalizationJournalCode }), true)
  assert.equal(acceptReceiptBrokerExchange(receiptSet.receipt_broker_request, receiptSet.receipt_broker_response, receiptSet.primary_receipt, preReceiptSupporting, receiptBrokerState, { journalCode: finalizationJournalCode }), false)
  const rewrittenReplayResponse = clone(receiptSet.receipt_broker_response)
  rewrittenReplayResponse.created_at = new Date(Date.parse(rewrittenReplayResponse.created_at) + 1).toISOString()
  rewrittenReplayResponse.record_digest_sha256 = recordDigest(rewrittenReplayResponse)
  assertThrowsCode(() => acceptReceiptBrokerExchange(receiptSet.receipt_broker_request, rewrittenReplayResponse, receiptSet.primary_receipt, preReceiptSupporting, receiptBrokerState, { journalCode: finalizationJournalCode }), 'BROKER_REPLAY_CONFLICT_REJECTED')
  const wrongNamedResponse = clone(receiptSet)
  wrongNamedResponse.receipt_broker_request.payload.receipt_semantic.open_staged_response_record_digest_sha256 = prepareResponse.record_digest_sha256
  recomputeReceiptSet(wrongNamedResponse)
  assertThrowsCode(() => validateReceiptBrokerPair(wrongNamedResponse.receipt_broker_request, wrongNamedResponse.receipt_broker_response, wrongNamedResponse.primary_receipt, preReceiptSupporting, { journalCode: finalizationJournalCode }), 'RECEIPT_SUPPORTING_RECORDS_INCOMPLETE')
  const backdatedCompletion = clone(receiptSet)
  backdatedCompletion.receipt_broker_request.payload.receipt_semantic.completed_at = at(1)
  recomputeReceiptSet(backdatedCompletion)
  assertThrowsCode(() => validateReceiptBrokerPair(backdatedCompletion.receipt_broker_request, backdatedCompletion.receipt_broker_response, backdatedCompletion.primary_receipt, preReceiptSupporting, { journalCode: finalizationJournalCode }), 'CHRONOLOGY_REJECTED')
  const persistedBeforeRequest = clone(receiptSet)
  persistedBeforeRequest.primary_receipt.persisted_at = at(15, 150)
  recomputeReceiptSet(persistedBeforeRequest)
  assertThrowsCode(() => validateReceiptBrokerPair(persistedBeforeRequest.receipt_broker_request, persistedBeforeRequest.receipt_broker_response, persistedBeforeRequest.primary_receipt, preReceiptSupporting, { journalCode: finalizationJournalCode }), 'CHRONOLOGY_REJECTED')

  const publishResponse = makeResponse(publishRequest, 'published', {
    primary_receipt: {
      format: 'jedi-atlas-primary-durability-receipt',
      format_version: '1.0.0',
      record_code: receiptSet.primary_receipt.record_code,
      receipt_raw_sha256: receiptRawSha,
    },
    receipt_broker_ack_record_digest_sha256: receiptSet.receipt_broker_response.record_digest_sha256,
  }, at(15, 500))
  const preparationConsumed = makeCapabilityTransition(preparationIssuance, {
    recordCode: 'capability.preparation.consumed.synthetic.001',
    sequence: 2,
    previous: preparationVerified.record_digest_sha256,
    from: 'verified',
    to: 'consumed',
    transition: 'consumer_succeeded',
    requestDigest: publishRequest.record_digest_sha256,
    responseDigest: publishResponse.record_digest_sha256,
    occurredAt: publishResponse.created_at,
    reason: 'successful_response',
  })
  const supporting = makeSupportingBrokerPair(publishResponse, 0, finalizationJournalCode)
  validateSupportingBrokerPair(supporting.request, supporting.response, publishResponse)
  const allExchangeSupporting = new Map([...preReceiptSupporting, { ...supporting, record: publishResponse }].map((entry) => [entry.record.record_digest_sha256, entry]))

  const history = classifications.journal_history_rules.find((entry) => entry.history_code === 'document_imported')
  const journalSemantic = makeSemantic(history, 'custody_object_durable@custody_prepare', 20, {})
  journalSemantic.operation_id = publishRequest.operation_id
  journalSemantic.operation_nonce = publishRequest.operation_nonce
  journalSemantic.component_binding_code = receiptSet.primary_receipt.semantic.adapter_binding_code
  journalSemantic.component_executable_sha256 = receiptSet.primary_receipt.semantic.adapter_executable_sha256
  journalSemantic.authorization_bundle_seal_record_digest_sha256 = sample.intent.bundle_seal_record_digest_sha256
  journalSemantic.bundle = clone(sample.bundle)
  journalSemantic.custody_finalization = {
    artifact: clone(sample.artifact),
    copy_code: sample.intent.copy_code,
    backend_code: sample.intent.backend_code,
    backend_reference: sample.intent.backend_reference,
    exchanges: [
      [openRequest, openResponse, 'opened'],
      [prepareRequest, prepareResponse, 'prepared'],
      [verifyRequest, verifyResponse, 'verified'],
      [publishRequest, publishResponse, 'published'],
    ].map(([request, response, outcome]) => ({
      operation_code: request.operation_code,
      request_record_digest_sha256: request.record_digest_sha256,
      request_persistence_ack_record_digest_sha256: allExchangeSupporting.get(request.record_digest_sha256).response.record_digest_sha256,
      response_record_digest_sha256: response.record_digest_sha256,
      response_persistence_ack_record_digest_sha256: allExchangeSupporting.get(response.record_digest_sha256).response.record_digest_sha256,
      success_outcome_code: outcome,
    })),
    primary_receipt: clone(publishResponse.payload.primary_receipt),
    preparation_capability_consumed_transition_digest_sha256: preparationConsumed.record_digest_sha256,
  }
  journalSemantic.record_digest_sha256 = recordDigest(journalSemantic)
  const rootSemantic = makeSemantic(history, 'operation_started@startup', -121, {})
  rootSemantic.operation_id = publishRequest.operation_id
  rootSemantic.operation_nonce = publishRequest.operation_nonce
  rootSemantic.authorization_bundle_seal_record_digest_sha256 = sample.intent.bundle_seal_record_digest_sha256
  rootSemantic.bundle = clone(sample.bundle)
  rootSemantic.record_digest_sha256 = recordDigest(rootSemantic)
  const rootJournalExchange = wrapJournalSemantic(rootSemantic, 1, null, -121)
  const journalExchange = wrapJournalSemantic(journalSemantic, 2, rootJournalExchange.event.record_digest_sha256, 20)
  validateJournalBrokerPair(journalExchange.request, journalExchange.response, journalExchange.event)
  if (journalExchange.event.journal_code !== finalizationJournalCode) fail('RESOLVER_GRAPH_JOURNAL_CONTEXT_REJECTED')
  if (rootJournalExchange.event.persisted_at >= openRequest.created_at) fail('RESOLVER_GRAPH_JOURNAL_CONTEXT_REJECTED', 'operation root chronology')
  const journalState = makeProtectedJournalState()
  const journalContext = { bundle_kind_code: 'single_document', permit_kind_code: 'none' }
  assert.equal(acceptJournalAppend(rootJournalExchange.request, rootJournalExchange.response, rootJournalExchange.event, journalContext, journalState), true)
  assert.equal(acceptJournalAppend(journalExchange.request, journalExchange.response, journalExchange.event, journalContext, journalState), true)

  const records = [
    ...preReceiptSupporting.flatMap((entry) => [entry.request, entry.response]),
    openRequest,
    sourceIssuance,
    openResponse,
    prepareRequest,
    sourceConsumed,
    preparationIssuance,
    prepareResponse,
    verifyRequest,
    verifyResponse,
    preparationVerified,
    publishRequest,
    receiptSet.receipt_broker_request,
    receiptSet.primary_receipt,
    receiptSet.receipt_broker_response,
    publishResponse,
    preparationConsumed,
    supporting.request,
    supporting.response,
    journalSemantic,
    journalExchange.request,
    journalExchange.event,
    journalExchange.response,
  ]
  const digestIndex = new Map()
  for (const record of records) {
    const digest = Object.hasOwn(record, 'record_digest_sha256')
      ? record.record_digest_sha256
      : receiptBytesSha(record)
    if (digestIndex.has(digest)) fail('RESOLVER_GRAPH_COLLISION')
    digestIndex.set(digest, record)
  }
  const requireResolved = (digest, predicate, label) => {
    const record = digestIndex.get(digest)
    if (!record || !predicate(record)) fail('RESOLVER_GRAPH_UNRESOLVED', label)
  }
  requireResolved(sourceIssuance.grant_scope.basis_request_record_digest_sha256, (record) => record === openRequest, 'source basis')
  requireResolved(sourceConsumed.request_record_digest_sha256, (record) => record === prepareRequest, 'source consume request')
  requireResolved(preparationIssuance.grant_scope.basis_request_record_digest_sha256, (record) => record === prepareRequest, 'preparation basis')
  requireResolved(preparationVerified.response_record_digest_sha256, (record) => record === verifyResponse, 'verification response')
  requireResolved(receiptSet.primary_receipt.semantic.open_staged_response_record_digest_sha256, (record) => record === openResponse, 'receipt open response')
  requireResolved(receiptSet.primary_receipt.semantic.prepare_response_record_digest_sha256, (record) => record === prepareResponse, 'receipt prepare response')
  requireResolved(receiptSet.primary_receipt.semantic.verify_prepared_response_record_digest_sha256, (record) => record === verifyResponse, 'receipt verify response')
  requireResolved(receiptSet.primary_receipt.semantic.publish_request_record_digest_sha256, (record) => record === publishRequest, 'receipt publish request')
  requireResolved(receiptSet.primary_receipt.semantic.source_capability_consumed_transition_digest_sha256, (record) => record === sourceConsumed, 'receipt source consumed')
  requireResolved(receiptSet.primary_receipt.semantic.preparation_capability_issuance_digest_sha256, (record) => record === preparationIssuance, 'receipt preparation issuance')
  requireResolved(receiptSet.primary_receipt.semantic.preparation_capability_verified_transition_digest_sha256, (record) => record === preparationVerified, 'receipt preparation verified')
  requireResolved(receiptSet.primary_receipt.persistence_request_record_digest_sha256, (record) => record === receiptSet.receipt_broker_request, 'receipt persistence request')
  requireResolved(publishResponse.payload.receipt_broker_ack_record_digest_sha256, (record) => record === receiptSet.receipt_broker_response, 'receipt acknowledgement')
  requireResolved(preparationConsumed.response_record_digest_sha256, (record) => record === publishResponse, 'publish response')
  requireResolved(journalSemantic.custody_finalization.preparation_capability_consumed_transition_digest_sha256, (record) => record === preparationConsumed, 'consumed transition')
  const validateFinalizationProjection = (semanticRecord) => {
    const finalization = semanticRecord.custody_finalization
    const expectedOperations = ['open_staged', 'prepare', 'verify_prepared', 'publish_no_replace']
    if (canonicalize(finalization.exchanges.map((entry) => entry.operation_code)) !== canonicalize(expectedOperations)) fail('RESOLVER_GRAPH_EXCHANGE_REJECTED', 'operation sequence')
    for (const exchange of finalization.exchanges) {
      const request = digestIndex.get(exchange.request_record_digest_sha256)
      const response = digestIndex.get(exchange.response_record_digest_sha256)
      if (!request || !response || request.message_kind_code !== 'request' || response.message_kind_code !== 'response' || request.operation_code !== exchange.operation_code || response.operation_code !== exchange.operation_code) fail('RESOLVER_GRAPH_EXCHANGE_REJECTED', exchange.operation_code)
      validateAdapterPair(request, response)
      if (request.recipient_binding_code !== receiptSet.primary_receipt.semantic.adapter_binding_code || response.sender_binding_code !== receiptSet.primary_receipt.semantic.adapter_binding_code) fail('RESOLVER_GRAPH_EXCHANGE_REJECTED', `${exchange.operation_code} adapter identity`)
      if (response.payload.outcome_code !== exchange.success_outcome_code) fail('RESOLVER_GRAPH_EXCHANGE_REJECTED', `${exchange.operation_code} outcome`)
      for (const key of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) if (request[key] !== semanticRecord[key]) fail('RESOLVER_GRAPH_EXCHANGE_REJECTED', `${exchange.operation_code} ${key}`)
      const requestPair = allExchangeSupporting.get(request.record_digest_sha256)
      const responsePair = allExchangeSupporting.get(response.record_digest_sha256)
      if (!requestPair || !responsePair) fail('RESOLVER_GRAPH_UNRESOLVED', `${exchange.operation_code} persistence pair`)
      if (requestPair.request.payload.journal_code !== journalExchange.event.journal_code || responsePair.request.payload.journal_code !== journalExchange.event.journal_code) fail('RESOLVER_GRAPH_JOURNAL_CONTEXT_REJECTED', exchange.operation_code)
      validateSupportingBrokerPair(requestPair.request, requestPair.response, request)
      validateSupportingBrokerPair(responsePair.request, responsePair.response, response)
      if (requestPair.response.record_digest_sha256 !== exchange.request_persistence_ack_record_digest_sha256 || responsePair.response.record_digest_sha256 !== exchange.response_persistence_ack_record_digest_sha256) fail('RESOLVER_GRAPH_EXCHANGE_REJECTED', `${exchange.operation_code} acknowledgement`)
      if (requestPair.response.created_at > semanticRecord.event_at || responsePair.response.created_at > semanticRecord.event_at
        || requestPair.response.payload.persisted_at > semanticRecord.event_at || responsePair.response.payload.persisted_at > semanticRecord.event_at) fail('RESOLVER_GRAPH_EXCHANGE_REJECTED', `${exchange.operation_code} persistence chronology`)
    }
    const receipt = receiptSet.primary_receipt
    const publish = digestIndex.get(finalization.exchanges.at(-1).response_record_digest_sha256)
    if (canonicalize(finalization.primary_receipt) !== canonicalize(publish?.payload.primary_receipt)
      || finalization.primary_receipt.record_code !== receipt.record_code
      || finalization.primary_receipt.receipt_raw_sha256 !== receiptBytesSha(receipt)) fail('RESOLVER_GRAPH_RECEIPT_REJECTED')
    for (const key of ['artifact', 'copy_code', 'backend_code', 'backend_reference']) if (canonicalize(finalization[key]) !== canonicalize(receipt.semantic[key])) fail('RESOLVER_GRAPH_RECEIPT_REJECTED', key)
    if (canonicalize(semanticRecord.bundle) !== canonicalize(receipt.semantic.bundle)) fail('RESOLVER_GRAPH_RECEIPT_REJECTED', 'bundle')
    if (semanticRecord.component_binding_code !== receipt.semantic.adapter_binding_code
      || semanticRecord.component_executable_sha256 !== receipt.semantic.adapter_executable_sha256
      || receiptSet.receipt_broker_request.sender_binding_code !== receipt.semantic.adapter_binding_code) fail('RESOLVER_GRAPH_RECEIPT_REJECTED', 'adapter identity')
    if (receipt.semantic.preparation_capability_verified_transition_digest_sha256 !== publishRequest.payload.preparation_capability_leaf_record_digest_sha256
      || finalization.preparation_capability_consumed_transition_digest_sha256 !== preparationConsumed.record_digest_sha256
      || preparationConsumed.response_record_digest_sha256 !== publish.record_digest_sha256) fail('RESOLVER_GRAPH_CAPABILITY_REJECTED')
    if (publish.payload.receipt_broker_ack_record_digest_sha256 !== receiptSet.receipt_broker_response.record_digest_sha256
      || publish.created_at < receiptSet.receipt_broker_response.created_at) fail('RESOLVER_GRAPH_RECEIPT_REJECTED', 'publish acknowledgement chronology')
  }
  validateFinalizationProjection(journalSemantic)
  requireResolved(journalExchange.event.append_request_record_digest_sha256, (record) => record === journalExchange.request, 'journal append request')
  assert.equal(journalSemantic.custody_finalization.primary_receipt.receipt_raw_sha256, receiptRawSha)
  assert.equal(publishRequest.payload.preparation_capability_leaf_record_digest_sha256, preparationVerified.record_digest_sha256)
  assert.equal(publishResponse.payload.preparation_capability_leaf_record_digest_sha256, preparationVerified.record_digest_sha256)
  assert.equal(validateCapabilityLineage(sourceIssuance, [sourceConsumed], [openRequest, openResponse, prepareRequest, prepareResponse]).record_digest_sha256, sourceConsumed.record_digest_sha256)
  assert.equal(validateCapabilityLineage(preparationIssuance, [preparationVerified, preparationConsumed], [prepareRequest, prepareResponse, verifyRequest, verifyResponse, publishRequest, publishResponse]).record_digest_sha256, preparationConsumed.record_digest_sha256)

  const mislabeledExchange = clone(journalSemantic)
  mislabeledExchange.custody_finalization.exchanges[1].success_outcome_code = 'verified'
  assertThrowsCode(() => validateFinalizationProjection(mislabeledExchange), 'RESOLVER_GRAPH_EXCHANGE_REJECTED')
  const substitutedExchange = clone(journalSemantic)
  substitutedExchange.custody_finalization.exchanges[1].response_record_digest_sha256 = openResponse.record_digest_sha256
  assertThrowsCode(() => validateFinalizationProjection(substitutedExchange), 'RESOLVER_GRAPH_EXCHANGE_REJECTED')
  const substitutedReceipt = clone(journalSemantic)
  substitutedReceipt.custody_finalization.primary_receipt.receipt_raw_sha256 = sample.sha('fc')
  assertThrowsCode(() => validateFinalizationProjection(substitutedReceipt), 'RESOLVER_GRAPH_RECEIPT_REJECTED')
  const substitutedAdapterAuthor = clone(journalSemantic)
  substitutedAdapterAuthor.component_binding_code = 'custody.adapter.alternate'
  assertThrowsCode(() => validateFinalizationProjection(substitutedAdapterAuthor), 'RESOLVER_GRAPH_RECEIPT_REJECTED')
  const substitutedAdapterBuild = clone(journalSemantic)
  substitutedAdapterBuild.component_executable_sha256 = sample.sha('f5')
  assertThrowsCode(() => validateFinalizationProjection(substitutedAdapterBuild), 'RESOLVER_GRAPH_RECEIPT_REJECTED')
  const crossBundleReceipt = clone(journalSemantic)
  crossBundleReceipt.bundle.bundle_id = 'bundle.synthetic.cross-context'
  assertThrowsCode(() => validateFinalizationProjection(crossBundleReceipt), 'RESOLVER_GRAPH_RECEIPT_REJECTED')

  const cyclicResponse = clone(publishResponse)
  cyclicResponse.payload.preparation_capability_leaf_record_digest_sha256 = preparationConsumed.record_digest_sha256
  cyclicResponse.record_digest_sha256 = recordDigest(cyclicResponse)
  assertThrowsCode(() => validateAdapterPair(publishRequest, cyclicResponse), 'CUSTODY_PAIR_REJECTED')
  const missingConsumed = clone(journalSemantic)
  missingConsumed.custody_finalization.preparation_capability_consumed_transition_digest_sha256 = sample.sha('ff')
  missingConsumed.record_digest_sha256 = recordDigest(missingConsumed)
  assertThrowsCode(() => requireResolved(missingConsumed.custody_finalization.preparation_capability_consumed_transition_digest_sha256, () => true, 'consumed transition'), 'RESOLVER_GRAPH_UNRESOLVED')
  const missingReceiptSource = clone(receiptSet.primary_receipt)
  missingReceiptSource.semantic.source_capability_consumed_transition_digest_sha256 = sample.sha('fe')
  missingReceiptSource.semantic_payload_sha256 = semanticDigest(missingReceiptSource.semantic)
  assertThrowsCode(() => requireResolved(missingReceiptSource.semantic.source_capability_consumed_transition_digest_sha256, () => true, 'receipt source consumed'), 'RESOLVER_GRAPH_UNRESOLVED')
  const brokenPreparationLineage = clone(preparationConsumed)
  brokenPreparationLineage.previous_transition_record_digest_sha256 = sample.sha('fd')
  brokenPreparationLineage.record_digest_sha256 = recordDigest(brokenPreparationLineage)
  assertThrowsCode(() => validateCapabilityLineage(preparationIssuance, [preparationVerified, brokenPreparationLineage], [prepareRequest, prepareResponse, verifyRequest, verifyResponse, publishRequest, publishResponse]), 'CAPABILITY_LINEAGE_REJECTED')
  const wrongPreparationState = clone(preparationConsumed)
  wrongPreparationState.from_state_code = 'ready'
  wrongPreparationState.record_digest_sha256 = recordDigest(wrongPreparationState)
  assertThrowsCode(() => validateCapabilityLineage(preparationIssuance, [preparationVerified, wrongPreparationState], [prepareRequest, prepareResponse, verifyRequest, verifyResponse, publishRequest, publishResponse]), 'CAPABILITY_LINEAGE_REJECTED')
  const preIssuanceSourceClaim = clone(sourceConsumed)
  preIssuanceSourceClaim.occurred_at = new Date(Date.parse(sourceIssuance.issued_at) - 1).toISOString()
  preIssuanceSourceClaim.record_digest_sha256 = recordDigest(preIssuanceSourceClaim)
  assertThrowsCode(() => validateCapabilityLineage(sourceIssuance, [preIssuanceSourceClaim], [openRequest, openResponse, prepareRequest, prepareResponse]), 'CAPABILITY_LINEAGE_REJECTED')
  const wrongSourceDescriptorScope = clone(sourceIssuance)
  wrongSourceDescriptorScope.grant_scope.staged_source_descriptor_ordinal = 8
  wrongSourceDescriptorScope.record_digest_sha256 = recordDigest(wrongSourceDescriptorScope)
  assertThrowsCode(() => validateCapabilityLineage(wrongSourceDescriptorScope, [], [openRequest, openResponse]), 'FROZEN_CAPABILITY_SCHEMA_REJECTED')
  const missingSupporting = clone(preReceiptSupporting).slice(1)
  assertThrowsCode(() => validateReceiptBrokerPair(receiptSet.receipt_broker_request, receiptSet.receipt_broker_response, receiptSet.primary_receipt, missingSupporting, { journalCode: finalizationJournalCode }), 'RECEIPT_SUPPORTING_RECORDS_INCOMPLETE')
  validatedFinalizationReceiptGraph = {
    primaryReceipt: clone(receiptSet.primary_receipt),
    receiptBrokerRequest: clone(receiptSet.receipt_broker_request),
    receiptBrokerResponse: clone(receiptSet.receipt_broker_response),
    supportingPairs: clone(preReceiptSupporting),
    journalCode: finalizationJournalCode,
  }
}

function makeSealedCapability(sealRequest) {
  const issuedAt = new Date(Date.parse(sealRequest.created_at) + 1).toISOString()
  const record = {
    format: 'jedi-atlas-custody-capability-control',
    format_version: '1.0.0',
    record_kind_code: 'capability_issuance',
    record_code: 'capability.sealed.synthetic.001',
    capability_kind_code: 'sealed_custody_access',
    issued_by_binding_code: 'custody.adapter.synthetic',
    requester_binding_code: 'bundle.importer.synthetic',
    adapter_binding_code: 'custody.adapter.synthetic',
    operation_id: sealRequest.operation_id,
    operation_nonce: sealRequest.operation_nonce,
    runtime_profile_record_digest_sha256: sealRequest.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: sealRequest.identity_bindings_record_digest_sha256,
    artifact: clone(sealRequest.payload.artifact),
    allowed_consumer_operation_codes: ['open_custody'],
    replay_policy_code: 'single_consume_open_custody',
    grant_scope: {
      scope_kind_code: 'sealed_custody_access',
      basis_request_record_digest_sha256: sealRequest.record_digest_sha256,
      clearance_decision_record_digest_sha256: sealRequest.payload.clearance_decision_record_digest_sha256,
      clearance_scope_sha256: sealRequest.payload.clearance_scope_sha256,
      custody_leaf_projection_sha256: sample.sha('b1'),
      backend_code: sealRequest.payload.backend_code,
      backend_reference: sealRequest.payload.backend_reference,
      copy_code: sealRequest.payload.copy_code,
      purpose_code: sealRequest.payload.purpose_code,
      custody_evaluated_at: issuedAt,
      known_through_bundle_sequence: 2,
    },
    issued_at: issuedAt,
    expires_at: new Date(Date.parse(issuedAt) + 30000).toISOString(),
    record_digest_sha256: sample.sha('b2'),
  }
  record.record_digest_sha256 = recordDigest(record)
  validateFrozenCapability(record)
  return record
}

function lifecycleRecord(kind, context, at, overrides = {}) {
  const nullFields = Object.fromEntries([...lifecycleVariantFieldsAll].map((field) => [field, null]))
  const record = {
    format: 'jedi-atlas-integrity-access-lifecycle-record',
    format_version: '1.0.0',
    record_kind_code: kind,
    record_code: `lifecycle.${kind}.synthetic.001`,
    operation_id: context.openRequest.operation_id,
    operation_nonce: context.openRequest.operation_nonce,
    bundle: clone(sample.bundle),
    artifact: clone(sample.artifact),
    copy_code: sample.intent.copy_code,
    backend_code: sample.intent.backend_code,
    backend_reference: sample.intent.backend_reference,
    purpose_code: 'integrity',
    runtime_profile_record_digest_sha256: context.openRequest.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: context.openRequest.identity_bindings_record_digest_sha256,
    d930_operational_profile_record_digest_sha256: context.openRequest.d930_operational_profile_record_digest_sha256,
    open_custody_request_record_digest_sha256: context.openRequest.record_digest_sha256,
    open_custody_response_record_digest_sha256: context.openResponse.record_digest_sha256,
    sealed_capability_record_digest_sha256: context.sealedIssuance.record_digest_sha256,
    sealed_capability_consumed_transition_digest_sha256: context.sealedConsumed.record_digest_sha256,
    producer_binding_code: kind === 'verifier_result' ? 'independent.verifier.synthetic' : 'trusted.launcher.synthetic',
    sender_binding_code: 'bundle.importer.synthetic',
    receiver_binding_code: 'independent.verifier.synthetic',
    verifier_binding_code: 'independent.verifier.synthetic',
    verifier_executable_sha256: sample.sha('b3'),
    receiver_process: {
      process_instance_code: 'process.verifier.synthetic.001',
      pid: 4101,
      uid: 4100,
      gid: 4100,
      start_time_ticks: 90001,
      executable_device: 2049,
      executable_inode: 90002,
    },
    ...nullFields,
    event_at: at,
    record_digest_sha256: sample.sha('b4'),
    ...clone(overrides),
  }
  record.record_digest_sha256 = recordDigest(record)
  validateIntegrityLifecycle(record)
  return record
}

function validateIntegritySemanticProducer(evidence, receiverProcess, terminalPersistedAt, appendRequestCreatedAt) {
  const producer = evidence.semantic_producer_process
  if (!producer) fail('INTEGRITY_GRAPH_SEMANTIC_PRODUCER_REJECTED', 'missing')
  const sameDeclaredInstance = producer.process_instance_code === receiverProcess.process_instance_code
  const sameKernelProcess = producer.pid === receiverProcess.pid && producer.start_time_ticks === receiverProcess.start_time_ticks
  if (sameDeclaredInstance
    || sameKernelProcess
    || producer.authenticated_at < terminalPersistedAt
    || producer.authenticated_at !== appendRequestCreatedAt
    || producer.peer_credentials_verified !== true
    || producer.custody_descriptor_absent !== true) fail('INTEGRITY_GRAPH_SEMANTIC_PRODUCER_REJECTED')
}

function validateIntegrityResolverGraph(graph) {
  const { primaryReceipt, primaryReceiptBrokerRequest, primaryReceiptBrokerResponse, primaryReceiptSupportingPairs, primaryReceiptJournalCode, sealRequest, sealResponse, sealedIssuance, openRequest, openResponse, sealedConsumed, descriptorDelivery, verifierResult, terminalLifecycle, evidence, supportingPairs, journalHistoryRule, journalExchanges } = graph
  const primaryReceiptRawSha = validatePrimaryReceipt(primaryReceipt)
  validateReceiptBrokerPair(primaryReceiptBrokerRequest, primaryReceiptBrokerResponse, primaryReceipt, primaryReceiptSupportingPairs, { journalCode: primaryReceiptJournalCode })
  if (primaryReceipt.persistence_request_record_digest_sha256 !== primaryReceiptBrokerRequest.record_digest_sha256
    || primaryReceiptBrokerResponse.payload.receipt_raw_sha256 !== primaryReceiptRawSha) fail('INTEGRITY_GRAPH_RECEIPT_REJECTED', 'receipt broker graph')
  validateAdapterPair(sealRequest, sealResponse)
  validateAdapterPair(openRequest, openResponse)
  validateFrozenCapability(sealedIssuance)
  validateFrozenCapability(sealedConsumed)
  validateIntegrityLifecycle(descriptorDelivery)
  validateIntegrityLifecycle(verifierResult)
  validateIntegrityLifecycle(terminalLifecycle, { verifierResult })
  const stableLifecycleFields = ['operation_id', 'operation_nonce', 'bundle', 'artifact', 'copy_code', 'backend_code', 'backend_reference', 'purpose_code', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_operational_profile_record_digest_sha256', 'open_custody_request_record_digest_sha256', 'open_custody_response_record_digest_sha256', 'sealed_capability_record_digest_sha256', 'sealed_capability_consumed_transition_digest_sha256', 'sender_binding_code', 'receiver_binding_code', 'verifier_binding_code', 'verifier_executable_sha256', 'receiver_process']
  for (const record of [verifierResult, terminalLifecycle]) for (const field of stableLifecycleFields) if (canonicalize(record[field]) !== canonicalize(descriptorDelivery[field])) fail('INTEGRITY_GRAPH_CONTEXT_DRIFT', field)
  if (sealedIssuance.grant_scope.basis_request_record_digest_sha256 !== sealRequest.record_digest_sha256 || sealResponse.payload.sealed_capability_record_digest_sha256 !== sealedIssuance.record_digest_sha256 || sealResponse.payload.sealed_capability_leaf_record_digest_sha256 !== sealedIssuance.record_digest_sha256) fail('INTEGRITY_GRAPH_CAPABILITY_REJECTED', 'issuance')
  if (openRequest.payload.sealed_capability_record_digest_sha256 !== sealedIssuance.record_digest_sha256 || openRequest.payload.sealed_capability_leaf_record_digest_sha256 !== sealedIssuance.record_digest_sha256 || openResponse.payload.sealed_capability_record_digest_sha256 !== sealedIssuance.record_digest_sha256 || openResponse.payload.sealed_capability_leaf_record_digest_sha256 !== sealedIssuance.record_digest_sha256) fail('INTEGRITY_GRAPH_CAPABILITY_REJECTED', 'open')
  if (sealedConsumed.capability_record_digest_sha256 !== sealedIssuance.record_digest_sha256 || sealedConsumed.request_record_digest_sha256 !== openRequest.record_digest_sha256 || sealedConsumed.response_record_digest_sha256 !== null || sealedConsumed.to_state_code !== 'consumed') fail('INTEGRITY_GRAPH_CAPABILITY_REJECTED', 'consume')
  if (validateCapabilityLineage(sealedIssuance, [sealedConsumed], [sealRequest, sealResponse, openRequest, openResponse]).record_digest_sha256 !== sealedConsumed.record_digest_sha256) fail('INTEGRITY_GRAPH_CAPABILITY_REJECTED', 'current leaf')
  for (const lifecycle of [descriptorDelivery, verifierResult, terminalLifecycle]) {
    if (lifecycle.open_custody_request_record_digest_sha256 !== openRequest.record_digest_sha256 || lifecycle.open_custody_response_record_digest_sha256 !== openResponse.record_digest_sha256 || lifecycle.sealed_capability_record_digest_sha256 !== sealedIssuance.record_digest_sha256 || lifecycle.sealed_capability_consumed_transition_digest_sha256 !== sealedConsumed.record_digest_sha256) fail('INTEGRITY_GRAPH_LIFECYCLE_REJECTED', 'resolved references')
  }
  if (verifierResult.descriptor_delivery_record_digest_sha256 !== descriptorDelivery.record_digest_sha256 || terminalLifecycle.descriptor_delivery_record_digest_sha256 !== descriptorDelivery.record_digest_sha256 || terminalLifecycle.verifier_result_record_digest_sha256 !== verifierResult.record_digest_sha256) fail('INTEGRITY_GRAPH_LIFECYCLE_REJECTED', 'chain')
  if (!(sealRequest.created_at < sealResponse.created_at && sealResponse.created_at < openRequest.created_at && openRequest.created_at < openResponse.created_at && openResponse.created_at < descriptorDelivery.event_at && descriptorDelivery.event_at < verifierResult.event_at && verifierResult.event_at < terminalLifecycle.event_at)) fail('INTEGRITY_GRAPH_CHRONOLOGY_REJECTED')
  if (terminalLifecycle.sender_closed_at < descriptorDelivery.event_at
    || terminalLifecycle.receiver_terminated_at < verifierResult.event_at
    || terminalLifecycle.sender_closed_at > terminalLifecycle.event_at
    || terminalLifecycle.receiver_terminated_at > terminalLifecycle.event_at) fail('INTEGRITY_GRAPH_CHRONOLOGY_REJECTED', 'descriptor lifecycle')
  const byDigest = new Map()
  for (const pair of supportingPairs) {
    validateSupportingBrokerPair(pair.request, pair.response, pair.record)
    byDigest.set(pair.record.record_digest_sha256, pair)
  }
  const exactAck = (recordDigestValue, ackDigest) => {
    const pair = byDigest.get(recordDigestValue)
    if (!pair || pair.response.record_digest_sha256 !== ackDigest || pair.response.payload.persisted_record_digest_sha256 !== recordDigestValue) fail('INTEGRITY_GRAPH_PERSISTENCE_REJECTED')
  }
  const exchangeRecords = new Map([sealRequest, sealResponse, openRequest, openResponse].map((record) => [record.record_digest_sha256, record]))
  const expectedOperations = ['seal_custody_access', 'open_custody']
  if (canonicalize(evidence.exchanges.map((entry) => entry.operation_code)) !== canonicalize(expectedOperations)) fail('INTEGRITY_GRAPH_EXCHANGE_REJECTED', 'operation sequence')
  for (const exchange of evidence.exchanges) {
    const request = exchangeRecords.get(exchange.request_record_digest_sha256)
    const response = exchangeRecords.get(exchange.response_record_digest_sha256)
    if (!request || !response || request.message_kind_code !== 'request' || response.message_kind_code !== 'response' || request.operation_code !== exchange.operation_code || response.operation_code !== exchange.operation_code) fail('INTEGRITY_GRAPH_EXCHANGE_REJECTED', exchange.operation_code)
    validateAdapterPair(request, response)
    if (response.payload.outcome_code !== exchange.success_outcome_code) fail('INTEGRITY_GRAPH_EXCHANGE_REJECTED', `${exchange.operation_code} outcome`)
    exactAck(exchange.request_record_digest_sha256, exchange.request_persistence_ack_record_digest_sha256)
    exactAck(exchange.response_record_digest_sha256, exchange.response_persistence_ack_record_digest_sha256)
  }
  exactAck(evidence.descriptor_delivery_record_digest_sha256, evidence.descriptor_delivery_persistence_ack_record_digest_sha256)
  exactAck(evidence.verifier_result_record_digest_sha256, evidence.verifier_result_persistence_ack_record_digest_sha256)
  exactAck(evidence.receiver_termination_record_digest_sha256, evidence.receiver_termination_persistence_ack_record_digest_sha256)
  if (!journalHistoryRule || !Array.isArray(journalExchanges) || journalExchanges.length !== 3) fail('INTEGRITY_GRAPH_JOURNAL_REJECTED', 'history')
  for (const exchange of journalExchanges) validateJournalBrokerPair(exchange.request, exchange.response, exchange.event)
  const journalEvents = journalExchanges.map((entry) => entry.event)
  validateHistory(journalHistoryRule, journalEvents)
  const integrityExchange = journalExchanges[1]
  for (const field of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) {
    if (canonicalize(integrityExchange.event.semantic_assertion[field]) !== canonicalize(sealRequest[field])) fail('INTEGRITY_GRAPH_CONTEXT_DRIFT', `journal ${field}`)
  }
  if (integrityExchange.event.semantic_assertion.event_kind_code !== 'stage_succeeded'
    || integrityExchange.event.semantic_assertion.stage_code !== 'independent_verification'
    || canonicalize(integrityExchange.event.semantic_assertion.integrity_access) !== canonicalize(evidence)) fail('INTEGRITY_GRAPH_JOURNAL_REJECTED', 'semantic evidence')
  if (canonicalize(primaryReceipt.semantic.bundle) !== canonicalize(descriptorDelivery.bundle)
    || canonicalize(primaryReceipt.semantic.bundle) !== canonicalize(integrityExchange.event.semantic_assertion.bundle)) fail('INTEGRITY_GRAPH_RECEIPT_REJECTED', 'bundle')
  if (descriptorDelivery.sender_binding_code !== openRequest.sender_binding_code
    || verifierResult.sender_binding_code !== openRequest.sender_binding_code
    || terminalLifecycle.sender_binding_code !== openRequest.sender_binding_code
    || descriptorDelivery.producer_binding_code !== terminalLifecycle.producer_binding_code
    || integrityExchange.event.semantic_assertion.component_binding_code !== verifierResult.verifier_binding_code
    || integrityExchange.event.semantic_assertion.component_executable_sha256 !== verifierResult.verifier_executable_sha256) fail('INTEGRITY_GRAPH_CONTEXT_DRIFT', 'supervision or verifier identity')
  const terminalAckPair = byDigest.get(terminalLifecycle.record_digest_sha256)
  const verifierAckPair = byDigest.get(verifierResult.record_digest_sha256)
  if (!terminalAckPair || !verifierAckPair) fail('INTEGRITY_GRAPH_PERSISTENCE_REJECTED', 'verifier lifecycle')
  if (verifierAckPair.request.created_at > terminalLifecycle.receiver_terminated_at
    || verifierAckPair.response.payload.persisted_at > terminalLifecycle.receiver_terminated_at
    || verifierAckPair.response.created_at > terminalLifecycle.receiver_terminated_at) fail('INTEGRITY_GRAPH_CHRONOLOGY_REJECTED', 'verifier persistence after receiver termination')
  validateIntegritySemanticProducer(evidence, verifierResult.receiver_process, terminalAckPair.response.payload.persisted_at, integrityExchange.request.created_at)
  for (const pair of supportingPairs) {
    if (pair.request.payload.journal_code !== integrityExchange.event.journal_code) fail('INTEGRITY_GRAPH_JOURNAL_REJECTED', 'support namespace')
    if (pair.response.created_at > integrityExchange.event.semantic_assertion.event_at
      || pair.response.payload.persisted_at > integrityExchange.event.semantic_assertion.event_at) fail('INTEGRITY_GRAPH_JOURNAL_REJECTED', 'support chronology')
  }
  if (evidence.sealed_capability_consumed_transition_digest_sha256 !== sealedConsumed.record_digest_sha256 || evidence.descriptor_delivery_record_digest_sha256 !== descriptorDelivery.record_digest_sha256 || evidence.verifier_result_record_digest_sha256 !== verifierResult.record_digest_sha256 || evidence.receiver_termination_record_digest_sha256 !== terminalLifecycle.record_digest_sha256 || canonicalize(evidence.verifier_recomputed_artifact) !== canonicalize(verifierResult.recomputed_artifact) || evidence.verifier_binding_code !== verifierResult.verifier_binding_code || evidence.verifier_executable_sha256 !== verifierResult.verifier_executable_sha256) fail('INTEGRITY_GRAPH_EVIDENCE_REJECTED')
  if (evidence.primary_receipt.record_code !== primaryReceipt.record_code
    || evidence.primary_receipt.receipt_raw_sha256 !== primaryReceiptRawSha
    || primaryReceipt.persisted_at > sealRequest.created_at) fail('INTEGRITY_GRAPH_RECEIPT_REJECTED')
  for (const field of ['artifact', 'copy_code', 'backend_code', 'backend_reference']) if (canonicalize(evidence[field]) !== canonicalize(primaryReceipt.semantic[field])) fail('INTEGRITY_GRAPH_RECEIPT_REJECTED', field)
  for (const message of [sealRequest, sealResponse, openRequest, openResponse]) {
    if (canonicalize(message.payload.primary_receipt) !== canonicalize(evidence.primary_receipt)) fail('INTEGRITY_GRAPH_RECEIPT_REJECTED', `${message.operation_code} receipt`)
    for (const field of ['artifact', 'copy_code', 'backend_code', 'backend_reference', 'purpose_code']) if (canonicalize(message.payload[field]) !== canonicalize(evidence[field])) fail('INTEGRITY_GRAPH_EVIDENCE_REJECTED', `${message.operation_code} ${field}`)
  }
  for (const field of ['clearance_decision_record_digest_sha256', 'clearance_scope_sha256', 'custody_leaf_projection_sha256', 'backend_code', 'backend_reference', 'copy_code', 'purpose_code', 'custody_evaluated_at', 'known_through_bundle_sequence']) if (canonicalize(sealedIssuance.grant_scope[field]) !== canonicalize(sealResponse.payload[field])) fail('INTEGRITY_GRAPH_CAPABILITY_REJECTED', `sealed scope ${field}`)
  if (openResponse.payload.custody_evaluated_at !== openResponse.created_at) fail('INTEGRITY_GRAPH_CAPABILITY_REJECTED', 'open evaluation time')
  for (const field of ['clearance_decision_record_digest_sha256', 'clearance_scope_sha256', 'custody_leaf_projection_sha256', 'backend_code', 'backend_reference', 'copy_code', 'purpose_code', 'known_through_bundle_sequence']) {
    if (canonicalize(openResponse.payload[field]) !== canonicalize(sealedIssuance.grant_scope[field])) fail('INTEGRITY_GRAPH_CAPABILITY_REJECTED', `open scope ${field}`)
  }
  const claimLifetime = Date.parse(sealedConsumed.occurred_at) - Date.parse(sealedIssuance.issued_at)
  if (evidence.claim_lifetime_ms !== claimLifetime || claimLifetime <= 0 || claimLifetime > classifications.integrity_access_policy.claim_lifetime_ms_max) fail('INTEGRITY_GRAPH_LIFETIME_REJECTED')
}

function assertIntegrityResolverGraph() {
  const setTime = (record, createdAt) => {
    record.created_at = createdAt
    record.record_digest_sha256 = recordDigest(record)
    return record
  }
  if (!validatedFinalizationReceiptGraph) fail('INTEGRITY_GRAPH_RECEIPT_REJECTED', 'missing finalization receipt graph')
  const primaryReceipt = clone(validatedFinalizationReceiptGraph.primaryReceipt)
  const primaryReceiptReference = { format: 'jedi-atlas-primary-durability-receipt', format_version: '1.0.0', record_code: primaryReceipt.record_code, receipt_raw_sha256: receiptBytesSha(primaryReceipt) }
  const sealRequest = setTime(makeAdapterMessage('seal_custody_access', 'request'), '2030-01-01T00:12:00.000Z')
  sealRequest.payload.primary_receipt = clone(primaryReceiptReference)
  sealRequest.record_digest_sha256 = recordDigest(sealRequest)
  const sealedIssuance = makeSealedCapability(sealRequest)
  const sealResponse = bindAdapterResponse(sealRequest, makeAdapterMessage('seal_custody_access', 'response', 'sealed'))
  Object.assign(sealResponse.payload, {
    known_through_bundle_sequence: 2,
    custody_evaluated_at: sealedIssuance.grant_scope.custody_evaluated_at,
    custody_leaf_projection_sha256: sealedIssuance.grant_scope.custody_leaf_projection_sha256,
    sealed_capability_record_digest_sha256: sealedIssuance.record_digest_sha256,
    sealed_capability_leaf_record_digest_sha256: sealedIssuance.record_digest_sha256,
  })
  sealResponse.record_digest_sha256 = recordDigest(sealResponse)
  const openRequest = setTime(makeAdapterMessage('open_custody', 'request'), '2030-01-01T00:12:00.005Z')
  openRequest.payload.primary_receipt = clone(primaryReceiptReference)
  openRequest.payload.sealed_capability_record_digest_sha256 = sealedIssuance.record_digest_sha256
  openRequest.payload.sealed_capability_leaf_record_digest_sha256 = sealedIssuance.record_digest_sha256
  openRequest.record_digest_sha256 = recordDigest(openRequest)
  const openResponse = bindAdapterResponse(openRequest, makeAdapterMessage('open_custody', 'response', 'available'))
  Object.assign(openResponse.payload, {
    known_through_bundle_sequence: 2,
    custody_evaluated_at: openResponse.created_at,
    clearance_decision_record_digest_sha256: sealedIssuance.grant_scope.clearance_decision_record_digest_sha256,
    clearance_scope_sha256: sealedIssuance.grant_scope.clearance_scope_sha256,
    custody_leaf_projection_sha256: sealedIssuance.grant_scope.custody_leaf_projection_sha256,
  })
  openResponse.record_digest_sha256 = recordDigest(openResponse)
  const sealedConsumed = makeCapabilityTransition(sealedIssuance, {
    recordCode: 'capability.sealed.consumed.synthetic.001',
    sequence: 1,
    from: 'ready',
    to: 'consumed',
    transition: 'consumer_succeeded',
    requestDigest: openRequest.record_digest_sha256,
    occurredAt: openRequest.created_at,
    reason: 'request_claimed',
  })
  const lifecycleContext = { openRequest, openResponse, sealedIssuance, sealedConsumed }
  const descriptorDelivery = lifecycleRecord('descriptor_delivery', lifecycleContext, '2030-01-01T00:12:00.007Z', {
    transport_code: 'launcher_supervised_scm_rights', descriptor_role_code: 'custody_source', access_code: 'read_only', file_type_code: 'regular_file', peer_credentials_verified: true, pidfd_supervision_active: true,
  })
  const verifierResult = lifecycleRecord('verifier_result', lifecycleContext, '2030-01-01T00:12:00.160Z', {
    descriptor_delivery_record_digest_sha256: descriptorDelivery.record_digest_sha256, verification_outcome_code: 'passed', recomputed_artifact: clone(sample.artifact),
  })
  const terminalLifecycle = lifecycleRecord('access_closed_and_receiver_terminated', lifecycleContext, '2030-01-01T00:12:00.350Z', {
    descriptor_delivery_record_digest_sha256: descriptorDelivery.record_digest_sha256,
    verifier_result_record_digest_sha256: verifierResult.record_digest_sha256,
    sender_close_state_code: 'confirmed', sender_closed_at: '2030-01-01T00:12:00.340Z',
    receiver_termination_state_code: 'confirmed', receiver_terminated_at: '2030-01-01T00:12:00.350Z',
    termination_disposition_code: 'clean_exit_reaped', receiver_descriptor_closed_by_termination: true, lifecycle_outcome_code: 'completed_verified',
  })
  const supportingRecords = [sealRequest, sealResponse, openRequest, openResponse, descriptorDelivery, verifierResult, terminalLifecycle]
  const integrityJournalCode = `journal.${sealRequest.operation_id}`
  const supportingPairs = supportingRecords.map((record, index) => ({ ...makeSupportingBrokerPair(record, index * 30, integrityJournalCode), record }))
  const ack = (record) => supportingPairs.find((entry) => entry.record === record).response.record_digest_sha256
  const evidence = {
    artifact: clone(sample.artifact), copy_code: sample.intent.copy_code, backend_code: sample.intent.backend_code, backend_reference: sample.intent.backend_reference, purpose_code: 'integrity',
    claim_lifetime_ms: Date.parse(sealedConsumed.occurred_at) - Date.parse(sealedIssuance.issued_at),
    exchanges: [
      { operation_code: 'seal_custody_access', request_record_digest_sha256: sealRequest.record_digest_sha256, request_persistence_ack_record_digest_sha256: ack(sealRequest), response_record_digest_sha256: sealResponse.record_digest_sha256, response_persistence_ack_record_digest_sha256: ack(sealResponse), success_outcome_code: 'sealed' },
      { operation_code: 'open_custody', request_record_digest_sha256: openRequest.record_digest_sha256, request_persistence_ack_record_digest_sha256: ack(openRequest), response_record_digest_sha256: openResponse.record_digest_sha256, response_persistence_ack_record_digest_sha256: ack(openResponse), success_outcome_code: 'available' },
    ],
    primary_receipt: clone(primaryReceiptReference),
    sealed_capability_consumed_transition_digest_sha256: sealedConsumed.record_digest_sha256,
    verifier_binding_code: verifierResult.verifier_binding_code,
    verifier_executable_sha256: verifierResult.verifier_executable_sha256,
    semantic_producer_process: {
      process_instance_code: 'process.verifier.coordinator.synthetic.001',
      pid: 4201,
      uid: 4100,
      gid: 4100,
      start_time_ticks: 89900,
      executable_device: 2049,
      executable_inode: 90003,
      peer_credentials_verified: true,
      custody_descriptor_absent: true,
      authenticated_at: '2030-01-01T00:12:01.100Z',
    },
    descriptor_delivery_record_digest_sha256: descriptorDelivery.record_digest_sha256,
    descriptor_delivery_persistence_ack_record_digest_sha256: ack(descriptorDelivery),
    verifier_result_record_digest_sha256: verifierResult.record_digest_sha256,
    verifier_result_persistence_ack_record_digest_sha256: ack(verifierResult),
    receiver_termination_record_digest_sha256: terminalLifecycle.record_digest_sha256,
    receiver_termination_persistence_ack_record_digest_sha256: ack(terminalLifecycle),
    verifier_recomputed_artifact: clone(verifierResult.recomputed_artifact),
  }
  const journalHistoryRule = classifications.journal_history_rules.find((entry) => entry.history_code === 'accepted_document_no_op')
  const contextualize = (semantic) => {
    semantic.operation_id = sealRequest.operation_id
    semantic.operation_nonce = sealRequest.operation_nonce
    semantic.runtime_profile_record_digest_sha256 = sealRequest.runtime_profile_record_digest_sha256
    semantic.identity_bindings_record_digest_sha256 = sealRequest.identity_bindings_record_digest_sha256
    semantic.d930_journal_profile_record_digest_sha256 = validFixtures.records.journal_profile.record_digest_sha256
    semantic.bundle = clone(sample.bundle)
    semantic.target_logical_state = clone(sample.state)
    semantic.record_digest_sha256 = recordDigest(semantic)
    return semantic
  }
  const rootSemantic = contextualize(makeSemantic(journalHistoryRule, 'operation_started@startup', 59, {}))
  const rootExchange = wrapJournalSemantic(rootSemantic, 1, null, 59)
  const integritySemantic = contextualize(makeSemantic(journalHistoryRule, 'stage_succeeded@independent_verification', 61, {}))
  integritySemantic.component_binding_code = verifierResult.verifier_binding_code
  integritySemantic.component_executable_sha256 = verifierResult.verifier_executable_sha256
  integritySemantic.integrity_access = clone(evidence)
  integritySemantic.record_digest_sha256 = recordDigest(integritySemantic)
  const integrityExchange = wrapJournalSemantic(integritySemantic, 2, rootExchange.event.record_digest_sha256, 61)
  const terminalSemantic = contextualize(makeSemantic(journalHistoryRule, 'operation_completed@completion', 62, {}))
  const terminalExchange = wrapJournalSemantic(terminalSemantic, 3, integrityExchange.event.record_digest_sha256, 62)
  const journalExchanges = [rootExchange, integrityExchange, terminalExchange]
  const graph = {
    ...lifecycleContext,
    primaryReceipt,
    primaryReceiptBrokerRequest: clone(validatedFinalizationReceiptGraph.receiptBrokerRequest),
    primaryReceiptBrokerResponse: clone(validatedFinalizationReceiptGraph.receiptBrokerResponse),
    primaryReceiptSupportingPairs: clone(validatedFinalizationReceiptGraph.supportingPairs),
    primaryReceiptJournalCode: validatedFinalizationReceiptGraph.journalCode,
    sealRequest,
    sealResponse,
    descriptorDelivery,
    verifierResult,
    terminalLifecycle,
    evidence,
    supportingPairs,
    journalHistoryRule,
    journalExchanges,
  }
  validateIntegrityResolverGraph(graph)
  const terminalPersistedAt = supportingPairs.find((pair) => pair.record === terminalLifecycle).response.payload.persisted_at
  const sameReceiverProducer = clone(evidence)
  sameReceiverProducer.semantic_producer_process = {
    ...clone(verifierResult.receiver_process),
    peer_credentials_verified: true,
    custody_descriptor_absent: true,
    authenticated_at: evidence.semantic_producer_process.authenticated_at,
  }
  assertThrowsCode(() => validateIntegritySemanticProducer(sameReceiverProducer, verifierResult.receiver_process, terminalPersistedAt, integrityExchange.request.created_at), 'INTEGRITY_GRAPH_SEMANTIC_PRODUCER_REJECTED')
  const prematureProducer = clone(evidence)
  prematureProducer.semantic_producer_process.authenticated_at = new Date(Date.parse(terminalPersistedAt) - 1).toISOString()
  assertThrowsCode(() => validateIntegritySemanticProducer(prematureProducer, verifierResult.receiver_process, terminalPersistedAt, integrityExchange.request.created_at), 'INTEGRITY_GRAPH_SEMANTIC_PRODUCER_REJECTED')
  const descriptorHoldingProducer = clone(evidence)
  descriptorHoldingProducer.semantic_producer_process.custody_descriptor_absent = false
  assertThrowsCode(() => validateIntegritySemanticProducer(descriptorHoldingProducer, verifierResult.receiver_process, terminalPersistedAt, integrityExchange.request.created_at), 'INTEGRITY_GRAPH_SEMANTIC_PRODUCER_REJECTED')
  const disconnectedLifecycle = clone(graph)
  for (const record of [disconnectedLifecycle.descriptorDelivery, disconnectedLifecycle.verifierResult, disconnectedLifecycle.terminalLifecycle]) {
    record.open_custody_request_record_digest_sha256 = sample.sha('ec')
    record.open_custody_response_record_digest_sha256 = sample.sha('ed')
    record.sealed_capability_record_digest_sha256 = sample.sha('ee')
    record.sealed_capability_consumed_transition_digest_sha256 = sample.sha('ef')
    record.record_digest_sha256 = recordDigest(record)
  }
  assertThrowsCode(() => validateIntegrityResolverGraph(disconnectedLifecycle), 'INTEGRITY_GRAPH_LIFECYCLE_REJECTED')
  const brokenCapabilityLineage = clone(graph)
  brokenCapabilityLineage.sealedConsumed.previous_transition_record_digest_sha256 = sample.sha('eb')
  brokenCapabilityLineage.sealedConsumed.record_digest_sha256 = recordDigest(brokenCapabilityLineage.sealedConsumed)
  assertThrowsCode(() => validateIntegrityResolverGraph(brokenCapabilityLineage), 'CAPABILITY_LINEAGE_REJECTED')
  const failedVerifier = clone(graph)
  failedVerifier.verifierResult = clone(verifierResult)
  failedVerifier.verifierResult.verification_outcome_code = 'read_failed'
  failedVerifier.verifierResult.recomputed_artifact = null
  failedVerifier.verifierResult.record_digest_sha256 = recordDigest(failedVerifier.verifierResult)
  assertThrowsCode(() => validateIntegrityLifecycle(terminalLifecycle, { verifierResult: failedVerifier.verifierResult }), 'LIFECYCLE_TERMINATION_REJECTED')
  const substitutedVerifierProducer = clone(verifierResult)
  substitutedVerifierProducer.producer_binding_code = 'binding.verifier'
  substitutedVerifierProducer.record_digest_sha256 = recordDigest(substitutedVerifierProducer)
  assertThrowsCode(() => validateIntegrityLifecycle(substitutedVerifierProducer), 'LIFECYCLE_IDENTITY_REJECTED')
  const missingAck = clone(graph)
  missingAck.evidence.exchanges[0].request_persistence_ack_record_digest_sha256 = sample.sha('ff')
  assertThrowsCode(() => validateIntegrityResolverGraph(missingAck), 'INTEGRITY_GRAPH_PERSISTENCE_REJECTED')
  const descriptorPair = graph.supportingPairs.find((pair) => pair.record.record_kind_code === 'descriptor_delivery')
  const substitutedLifecycleSender = clone(descriptorPair)
  substitutedLifecycleSender.request.sender_binding_code = substitutedLifecycleSender.record.sender_binding_code
  substitutedLifecycleSender.response.recipient_binding_code = substitutedLifecycleSender.request.sender_binding_code
  substitutedLifecycleSender.request.record_digest_sha256 = recordDigest(substitutedLifecycleSender.request)
  substitutedLifecycleSender.response.request_record_digest_sha256 = substitutedLifecycleSender.request.record_digest_sha256
  substitutedLifecycleSender.response.record_digest_sha256 = recordDigest(substitutedLifecycleSender.response)
  assertThrowsCode(() => validateSupportingBrokerPair(substitutedLifecycleSender.request, substitutedLifecycleSender.response, substitutedLifecycleSender.record), 'BROKER_ROLE_REJECTED')
  const wrongJournalNamespace = clone(graph)
  wrongJournalNamespace.supportingPairs[0].request.payload.journal_code = 'journal.substituted'
  wrongJournalNamespace.supportingPairs[0].request.record_digest_sha256 = recordDigest(wrongJournalNamespace.supportingPairs[0].request)
  assertThrowsCode(() => validateIntegrityResolverGraph(wrongJournalNamespace), 'BROKER_SUPPORTING_RECORD_MISMATCH')
  const lateSupportingAck = clone(graph)
  lateSupportingAck.supportingPairs[0].response.created_at = new Date(Date.parse(integrityExchange.event.semantic_assertion.event_at) + 1).toISOString()
  lateSupportingAck.supportingPairs[0].response.record_digest_sha256 = recordDigest(lateSupportingAck.supportingPairs[0].response)
  assertThrowsCode(() => validateIntegrityResolverGraph(lateSupportingAck), 'INTEGRITY_GRAPH_PERSISTENCE_REJECTED')
  const detachedJournalEvidence = clone(graph)
  detachedJournalEvidence.journalExchanges[1].event.semantic_assertion.integrity_access.claim_lifetime_ms += 1
  detachedJournalEvidence.journalExchanges[1].event.semantic_assertion.record_digest_sha256 = recordDigest(detachedJournalEvidence.journalExchanges[1].event.semantic_assertion)
  detachedJournalEvidence.journalExchanges[1].event.semantic_assertion_record_digest_sha256 = detachedJournalEvidence.journalExchanges[1].event.semantic_assertion.record_digest_sha256
  detachedJournalEvidence.journalExchanges[1].event.record_digest_sha256 = recordDigest(detachedJournalEvidence.journalExchanges[1].event)
  assertThrowsCode(() => validateIntegrityResolverGraph(detachedJournalEvidence), 'DIGEST_MISMATCH')
  const crossOperation = clone(graph)
  crossOperation.verifierResult.operation_id = 'operation.synthetic.other'
  crossOperation.verifierResult.record_digest_sha256 = recordDigest(crossOperation.verifierResult)
  assertThrowsCode(() => validateIntegrityResolverGraph(crossOperation), 'INTEGRITY_GRAPH_CONTEXT_DRIFT')
  const expired = clone(graph)
  expired.sealedIssuance.expires_at = '2030-01-01T00:09:00.008Z'
  expired.sealedIssuance.record_digest_sha256 = recordDigest(expired.sealedIssuance)
  assertThrowsCode(() => validateIntegrityResolverGraph(expired), 'INTEGRITY_GRAPH_CAPABILITY_REJECTED')
  const staleOpenEvaluation = clone(graph)
  staleOpenEvaluation.openResponse.payload.custody_evaluated_at = new Date(Date.parse(staleOpenEvaluation.openResponse.created_at) - 1).toISOString()
  staleOpenEvaluation.openResponse.record_digest_sha256 = recordDigest(staleOpenEvaluation.openResponse)
  assertThrowsCode(() => validateIntegrityResolverGraph(staleOpenEvaluation), 'INTEGRITY_GRAPH_LIFECYCLE_REJECTED')
  const substitutedClearance = clone(graph)
  substitutedClearance.openResponse.payload.clearance_scope_sha256 = sample.sha('f9')
  substitutedClearance.openResponse.record_digest_sha256 = recordDigest(substitutedClearance.openResponse)
  assertThrowsCode(() => validateIntegrityResolverGraph(substitutedClearance), 'INTEGRITY_GRAPH_LIFECYCLE_REJECTED')
  const mislabeledExchange = clone(graph)
  mislabeledExchange.evidence.exchanges[0].success_outcome_code = 'available'
  assertThrowsCode(() => validateIntegrityResolverGraph(mislabeledExchange), 'INTEGRITY_GRAPH_EXCHANGE_REJECTED')
  const swappedExchange = clone(graph)
  swappedExchange.evidence.exchanges[0].response_record_digest_sha256 = openResponse.record_digest_sha256
  assertThrowsCode(() => validateIntegrityResolverGraph(swappedExchange), 'INTEGRITY_GRAPH_EXCHANGE_REJECTED')
  const backdatedClose = clone(graph)
  backdatedClose.terminalLifecycle.sender_closed_at = '2030-01-01T00:09:00.006Z'
  backdatedClose.terminalLifecycle.record_digest_sha256 = recordDigest(backdatedClose.terminalLifecycle)
  assertThrowsCode(() => validateIntegrityResolverGraph(backdatedClose), 'INTEGRITY_GRAPH_CHRONOLOGY_REJECTED')
  const backdatedTermination = clone(graph)
  backdatedTermination.terminalLifecycle.receiver_terminated_at = '2030-01-01T00:09:00.007Z'
  backdatedTermination.terminalLifecycle.record_digest_sha256 = recordDigest(backdatedTermination.terminalLifecycle)
  assertThrowsCode(() => validateIntegrityResolverGraph(backdatedTermination), 'INTEGRITY_GRAPH_CHRONOLOGY_REJECTED')
  const arbitraryReceipt = clone(graph)
  arbitraryReceipt.evidence.primary_receipt.record_code = 'receipt.unresolved.synthetic'
  arbitraryReceipt.evidence.primary_receipt.receipt_raw_sha256 = sample.sha('fa')
  assertThrowsCode(() => validateIntegrityResolverGraph(arbitraryReceipt), 'INTEGRITY_GRAPH_JOURNAL_REJECTED')
  const substitutedVerifierBinding = clone(graph)
  substitutedVerifierBinding.evidence.verifier_binding_code = 'independent.verifier.alternate'
  assertThrowsCode(() => validateIntegrityResolverGraph(substitutedVerifierBinding), 'INTEGRITY_GRAPH_JOURNAL_REJECTED')
  const substitutedVerifierBuild = clone(graph)
  substitutedVerifierBuild.evidence.verifier_executable_sha256 = sample.sha('f8')
  assertThrowsCode(() => validateIntegrityResolverGraph(substitutedVerifierBuild), 'INTEGRITY_GRAPH_JOURNAL_REJECTED')
  const crossBundleLifecycle = clone(graph)
  for (const record of [crossBundleLifecycle.descriptorDelivery, crossBundleLifecycle.verifierResult, crossBundleLifecycle.terminalLifecycle]) {
    record.bundle.bundle_id = 'bundle.synthetic.cross-context'
    record.record_digest_sha256 = recordDigest(record)
  }
  assertThrowsCode(() => validateIntegrityResolverGraph(crossBundleLifecycle), 'INTEGRITY_GRAPH_LIFECYCLE_REJECTED')
  const crossBundleJournal = clone(graph)
  const crossBundleEvent = crossBundleJournal.journalExchanges[1].event
  crossBundleEvent.semantic_assertion.bundle.bundle_id = 'bundle.synthetic.cross-context'
  crossBundleEvent.semantic_assertion.record_digest_sha256 = recordDigest(crossBundleEvent.semantic_assertion)
  crossBundleEvent.semantic_assertion_record_digest_sha256 = crossBundleEvent.semantic_assertion.record_digest_sha256
  crossBundleEvent.record_digest_sha256 = recordDigest(crossBundleEvent)
  crossBundleJournal.journalExchanges[2].event.previous_event_record_digest_sha256 = crossBundleEvent.record_digest_sha256
  crossBundleJournal.journalExchanges[2].event.record_digest_sha256 = recordDigest(crossBundleJournal.journalExchanges[2].event)
  assertThrowsCode(() => validateIntegrityResolverGraph(crossBundleJournal), 'DIGEST_MISMATCH')
}

function validateJournalBrokerMessage(message) {
  validateRecord(message)
  const rules = classifications.journal_broker_rules
  const request = message.message_kind_code.endsWith('_request')
  if (request && bindingRole(message.recipient_binding_code) !== rules.request_recipient_role_code) fail('BROKER_ROLE_REJECTED')
  if (!request && bindingRole(message.sender_binding_code) !== rules.response_sender_role_code) fail('BROKER_ROLE_REJECTED')
  if (request !== (message.request_record_digest_sha256 === null)) fail('BROKER_PAIR_REJECTED', 'request chain')
  const success = !request && rules.success_outcome_codes.includes(message.payload.outcome_code)
  const failure = !request && rules.failure_outcome_codes.includes(message.payload.outcome_code)
  let expectedFields
  if (message.message_kind_code === 'persist_supporting_request') expectedFields = rules.supporting_request_required_fields
  else if (message.message_kind_code === 'append_request') expectedFields = rules.append_request_required_fields.filter((field) => field !== 'expected_previous_event_record_digest_sha256' || message.payload[field] !== null)
  else if (message.message_kind_code === 'persist_supporting_response' && success) expectedFields = rules.supporting_response_required_fields
  else if (message.message_kind_code === 'append_response' && success) expectedFields = rules.append_response_required_fields.filter((field) => field !== 'expected_previous_event_record_digest_sha256' || message.payload[field] !== null)
  else if (failure) {
    expectedFields = rules.failure_nonnull_fields
    const errorRules = message.message_kind_code === 'persist_supporting_response' ? rules.supporting_failure_error_rules : rules.append_failure_error_rules
    const errorRule = errorRules.find((entry) => entry.outcome_code === message.payload.outcome_code)
    if (!errorRule || errorRule.error_code !== message.payload.error_code) fail('BROKER_FAILURE_ERROR_REJECTED', 'journal')
  }
  else fail('BROKER_MATRIX_REJECTED', 'journal outcome')
  const nonnull = Object.entries(message.payload).filter(([, value]) => value !== null).map(([key]) => key).sort()
  if (canonicalize(nonnull) !== canonicalize(expectedFields.slice().sort())) fail('BROKER_MATRIX_REJECTED', 'journal field set')
}

function validateJournalBrokerPair(request, response, event) {
  validateJournalBrokerMessage(request)
  validateJournalBrokerMessage(response)
  validateRecord(event)
  const rules = classifications.journal_broker_rules
  if (request.message_kind_code !== 'append_request' || bindingRole(request.recipient_binding_code) !== rules.request_recipient_role_code) fail('BROKER_ROLE_REJECTED')
  if (response.message_kind_code !== 'append_response' || bindingRole(response.sender_binding_code) !== rules.response_sender_role_code || response.recipient_binding_code !== request.sender_binding_code || response.sender_binding_code !== request.recipient_binding_code) fail('BROKER_ROLE_REJECTED')
  if (request.sender_binding_code !== request.payload.semantic_assertion.component_binding_code) fail('BROKER_SEMANTIC_ORIGIN_REJECTED')
  for (const key of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_journal_profile_record_digest_sha256']) if (request[key] !== request.payload.semantic_assertion[key]) fail('BROKER_SEMANTIC_CONTEXT_REJECTED', key)
  assertResolvedJournalProfile(request.d930_journal_profile_record_digest_sha256)
  for (const key of ['operation_id', 'operation_nonce', 'request_id', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_journal_profile_record_digest_sha256']) if (canonicalize(request[key]) !== canonicalize(response[key])) fail('BROKER_PAIR_REJECTED', key)
  if (request.request_record_digest_sha256 !== null || response.request_record_digest_sha256 !== request.record_digest_sha256) fail('BROKER_PAIR_REJECTED', 'chain')
  if (request.payload.semantic_assertion_record_digest_sha256 !== recordDigest(request.payload.semantic_assertion)) fail('BROKER_SEMANTIC_DIGEST_MISMATCH')
  for (const key of ['journal_code', 'expected_event_sequence', 'expected_previous_event_record_digest_sha256', 'semantic_assertion_record_digest_sha256']) if (canonicalize(response.payload[key]) !== canonicalize(request.payload[key])) fail('BROKER_ACK_SUBSTITUTION_REJECTED', key)
  if (event.semantic_assertion_record_digest_sha256 !== request.payload.semantic_assertion_record_digest_sha256 || canonicalize(event.semantic_assertion) !== canonicalize(request.payload.semantic_assertion)) fail('BROKER_EVENT_MISMATCH', 'semantic')
  if (event.append_request_record_digest_sha256 !== request.record_digest_sha256) fail('BROKER_EVENT_MISMATCH', 'request')
  if (event.journal_code !== request.payload.journal_code || event.event_sequence !== request.payload.expected_event_sequence || event.previous_event_record_digest_sha256 !== request.payload.expected_previous_event_record_digest_sha256) fail('BROKER_EVENT_MISMATCH', 'head')
  if (event.persisted_by_binding_code !== response.sender_binding_code) fail('BROKER_EVENT_MISMATCH', 'broker')
  if (response.payload.persisted_record_code !== event.record_code || response.payload.persisted_record_digest_sha256 !== event.record_digest_sha256 || response.payload.persisted_at !== event.persisted_at) fail('BROKER_EVENT_MISMATCH', 'response')
  if (response.payload.outcome_code !== 'persisted') fail('BROKER_MATRIX_REJECTED')
  if (event.semantic_assertion.event_at > request.created_at || request.created_at > event.persisted_at || event.persisted_at > response.created_at) fail('CHRONOLOGY_REJECTED', 'journal broker')
}

function makeProtectedJournalState() {
  return {
    heads: new Map(),
    eventsByDigest: new Map(),
    operationJournals: new Map(),
    acceptedByRequestDigest: new Map(),
    requestKeyDigests: new Map(),
    recoveryHeads: new Map(),
    operationRecoveryChains: new Map(),
    recordIdentities: new Map(),
  }
}

function assertRegisteredJournalHistoryPrefix(current, nextEvent, context, protectedState) {
  const reverse = []
  let cursor = current
  while (cursor) {
    reverse.push(cursor)
    cursor = cursor.previous_event_record_digest_sha256 === null ? null : protectedState.eventsByDigest.get(cursor.previous_event_record_digest_sha256)
    if (cursor === undefined) fail('JOURNAL_HISTORY_PREFIX_REJECTED', 'unresolved predecessor')
  }
  const actual = [...reverse.reverse(), nextEvent].map((entry) => `${entry.semantic_assertion.event_kind_code}@${entry.semantic_assertion.stage_code}`)
  const mode = nextEvent.semantic_assertion.operation_mode_code
  const comparableActual = mode === 'recovery'
    ? actual.filter((milestone, index) => milestone !== 'stage_succeeded@reconciliation' || index === 0 || actual[index - 1] !== milestone)
    : actual
  const permitKind = mode === 'bootstrap' ? 'bootstrap' : mode === 'recovery' ? 'post_promotion_completion' : 'none'
  const bundleKind = context.bundle_kind_code
  const registered = [
    ...classifications.journal_history_rules.map((rule) => ({ rule, failure: false })),
    ...classifications.journal_failure_history_rules.map((rule) => ({ rule, failure: true })),
  ].filter(({ rule }) => rule.base_selector.operation_mode_code === mode
    && rule.permit_kind_code === permitKind
    && (rule.bundle_kind_code === bundleKind || rule.bundle_kind_code === 'any'))
  const shapes = registered.flatMap(({ rule, failure }) => {
    const base = [rule.milestones]
    if (!failure) return base
    const terminal = rule.milestones.at(-1)
    const terminalStage = terminal.split('@')[1]
    return [rule.milestones, [...rule.milestones.slice(0, -1), `stage_failed@${terminalStage}`, terminal]]
  })
  const isPrefix = shapes.some((shape) => comparableActual.length <= shape.length && comparableActual.every((milestone, index) => milestone === shape[index]))
  if (!isPrefix) fail('JOURNAL_HISTORY_PREFIX_REJECTED', actual.join(' -> '))
}

function journalRequestKey(request) {
  return `${request.operation_id}:${request.operation_nonce}:${request.message_kind_code}:${request.request_id}`
}

function acceptJournalAppend(request, response, event, context, protectedState) {
  validateJournalBrokerPair(request, response, event)
  const prospectiveIdentities = new Map(protectedState.recordIdentities)
  for (const record of [request, response, event.semantic_assertion, event]) {
    const identityKey = `${record.format}:${record.record_code}`
    const priorIdentityDigest = prospectiveIdentities.get(identityKey)
    if (priorIdentityDigest && priorIdentityDigest !== record.record_digest_sha256) fail('JOURNAL_REPLAY_CONFLICT_REJECTED', identityKey)
    prospectiveIdentities.set(identityKey, record.record_digest_sha256)
  }
  const requestKey = journalRequestKey(request)
  const operationKey = `${request.operation_id}:${request.operation_nonce}`
  const boundJournal = protectedState.operationJournals.get(operationKey)
  if (boundJournal && boundJournal !== event.journal_code) fail('JOURNAL_OPERATION_FORK_REJECTED', operationKey)
  const requestKeyDigest = protectedState.requestKeyDigests.get(requestKey)
  if (requestKeyDigest && requestKeyDigest !== request.record_digest_sha256) fail('JOURNAL_REPLAY_CONFLICT_REJECTED', requestKey)
  const priorResult = protectedState.acceptedByRequestDigest.get(request.record_digest_sha256)
  if (priorResult) {
    if (priorResult.event_record_digest_sha256 !== event.record_digest_sha256 || priorResult.journal_code !== event.journal_code || priorResult.event_sequence !== event.event_sequence || priorResult.previous_event_record_digest_sha256 !== event.previous_event_record_digest_sha256) fail('JOURNAL_REPLAY_CONFLICT_REJECTED', 'persisted result')
    if (priorResult.response_record_digest_sha256 !== response.record_digest_sha256) fail('JOURNAL_REPLAY_CONFLICT_REJECTED', 'response bytes')
    return false
  }
  const current = protectedState.heads.get(event.journal_code) ?? null
  validateJournalEvent(event, { ...context, journal_code: event.journal_code, previous_event: current })
  assertRegisteredJournalHistoryPrefix(current, event, context, protectedState)
  const expectedSequence = current ? current.event_sequence + 1 : 1
  const expectedPrevious = current?.record_digest_sha256 ?? null
  if (request.payload.expected_event_sequence !== expectedSequence || request.payload.expected_previous_event_record_digest_sha256 !== expectedPrevious || event.event_sequence !== expectedSequence || event.previous_event_record_digest_sha256 !== expectedPrevious) fail('JOURNAL_COMPARE_APPEND_REJECTED', 'head')
  if (!current && event.semantic_assertion.event_kind_code !== 'operation_started') fail('JOURNAL_COMPARE_APPEND_REJECTED', 'root')
  if (current && ['operation_completed', 'recovery_required'].includes(current.semantic_assertion.event_kind_code)) fail('JOURNAL_COMPARE_APPEND_REJECTED', 'terminal')
  if (current) {
    const stableContextFields = ['operation_mode_code', 'operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_journal_profile_record_digest_sha256', 'authorization_permit_record_digest_sha256', 'authorization_bundle_seal_record_digest_sha256', 'bundle', 'target_logical_state']
    for (const field of stableContextFields) if (canonicalize(event.semantic_assertion[field]) !== canonicalize(current.semantic_assertion[field])) fail('JOURNAL_COMPARE_APPEND_REJECTED', `context ${field}`)
    if (event.semantic_assertion.event_at <= current.semantic_assertion.event_at || event.persisted_at <= current.persisted_at) fail('JOURNAL_COMPARE_APPEND_REJECTED', 'chronology')
  }
  const recovery = event.semantic_assertion.recovery
  if (recovery) {
    const boundRecoveryChain = protectedState.operationRecoveryChains.get(operationKey)
    if (boundRecoveryChain && boundRecoveryChain !== recovery.recovery_chain_code) fail('JOURNAL_RECOVERY_CHAIN_REJECTED', 'chain reset')
    const recoveryKey = `${operationKey}:${recovery.recovery_chain_code}`
    const priorRecovery = protectedState.recoveryHeads.get(recoveryKey) ?? null
    if (!priorRecovery) {
      if (recovery.recovery_attempt_sequence !== 1 || recovery.prior_attempt_terminal_record_digest_sha256 !== null || !current || current.event_sequence !== 1 || current.semantic_assertion.event_kind_code !== 'operation_started') fail('JOURNAL_RECOVERY_CHAIN_REJECTED', 'first assessment')
    } else if (current?.record_digest_sha256 !== priorRecovery.record_digest_sha256
      || recovery.recovery_attempt_sequence !== priorRecovery.semantic_assertion.recovery.recovery_attempt_sequence + 1
      || recovery.prior_attempt_terminal_record_digest_sha256 !== priorRecovery.record_digest_sha256) fail('JOURNAL_RECOVERY_CHAIN_REJECTED', 'immediate prior assessment')
    if (priorRecovery) {
      const stableRecoveryFields = ['subject_operation_id', 'subject_operation_nonce', 'subject_bundle', 'subject_artifact', 'subject_copy_code', 'subject_backend_code', 'subject_backend_reference', 'source_terminal_journal_code', 'source_terminal_journal_sequence', 'source_terminal_journal_head_record_digest_sha256', 'source_terminal_journal_persisted_at', 'source_terminal_error_code']
      for (const field of stableRecoveryFields) if (canonicalize(recovery[field]) !== canonicalize(priorRecovery.semantic_assertion.recovery[field])) fail('JOURNAL_RECOVERY_CHAIN_REJECTED', field)
    }
  }
  if (response.payload.outcome_code !== 'persisted') fail('JOURNAL_COMPARE_APPEND_REJECTED', 'outcome')
  const acceptedEvent = clone(event)
  protectedState.heads.set(event.journal_code, acceptedEvent)
  protectedState.eventsByDigest.set(event.record_digest_sha256, acceptedEvent)
  protectedState.operationJournals.set(operationKey, event.journal_code)
  protectedState.requestKeyDigests.set(requestKey, request.record_digest_sha256)
  protectedState.acceptedByRequestDigest.set(request.record_digest_sha256, {
    event_record_digest_sha256: event.record_digest_sha256,
    journal_code: event.journal_code,
    event_sequence: event.event_sequence,
    previous_event_record_digest_sha256: event.previous_event_record_digest_sha256,
    response_record_digest_sha256: response.record_digest_sha256,
  })
  for (const record of [request, response, event.semantic_assertion, event]) protectedState.recordIdentities.set(`${record.format}:${record.record_code}`, record.record_digest_sha256)
  if (recovery) {
    protectedState.operationRecoveryChains.set(operationKey, recovery.recovery_chain_code)
    protectedState.recoveryHeads.set(`${operationKey}:${recovery.recovery_chain_code}`, acceptedEvent)
  }
  return true
}

function supportingRecordKind(record) {
  if (record.format === 'jedi-atlas-custody-adapter-message') return 'custody_adapter_message'
  if (record.format === 'jedi-atlas-integrity-access-lifecycle-record') return 'integrity_access_lifecycle_record'
  fail('BROKER_SUPPORTING_RECORD_MISMATCH', 'kind')
}

function supportingRecordProducedAt(record) {
  return record.created_at ?? record.event_at
}

function supportingRecordProducer(record) {
  if (record.format === 'jedi-atlas-custody-adapter-message') return record.sender_binding_code
  if (record.format === 'jedi-atlas-integrity-access-lifecycle-record') return record.producer_binding_code
  fail('BROKER_SUPPORTING_RECORD_MISMATCH', 'producer')
}

function validateSupportingBrokerPair(request, response, supportingRecord) {
  validateJournalBrokerMessage(request)
  validateJournalBrokerMessage(response)
  if (supportingRecord.format === 'jedi-atlas-custody-adapter-message') validateAdapterMessage(supportingRecord)
  else validateIntegrityLifecycle(supportingRecord)
  if (request.message_kind_code !== 'persist_supporting_request' || response.message_kind_code !== 'persist_supporting_response') fail('BROKER_MATRIX_REJECTED')
  const producer = supportingRecordProducer(supportingRecord)
  if (request.sender_binding_code !== producer || bindingRole(request.recipient_binding_code) !== 'journal_broker') fail('BROKER_ROLE_REJECTED')
  if (bindingRole(response.sender_binding_code) !== 'journal_broker' || response.recipient_binding_code !== request.sender_binding_code) fail('BROKER_ROLE_REJECTED')
  const kind = supportingRecordKind(supportingRecord)
  if (request.payload.supporting_record_kind_code !== kind || response.payload.supporting_record_kind_code !== kind) fail('BROKER_SUPPORTING_RECORD_MISMATCH', 'kind')
  if (canonicalize(request.payload.supporting_record) !== canonicalize(supportingRecord) || request.payload.supporting_record_digest_sha256 !== supportingRecord.record_digest_sha256) fail('BROKER_SUPPORTING_RECORD_MISMATCH')
  if (response.request_record_digest_sha256 !== request.record_digest_sha256
    || response.payload.supporting_record_digest_sha256 !== request.payload.supporting_record_digest_sha256
    || response.payload.supporting_record_digest_sha256 !== supportingRecord.record_digest_sha256
    || response.payload.persisted_record_digest_sha256 !== supportingRecord.record_digest_sha256
    || response.payload.persisted_record_code !== supportingRecord.record_code) fail('BROKER_SUPPORTING_RECORD_MISMATCH')
  if (response.payload.journal_code !== request.payload.journal_code) fail('BROKER_ACK_SUBSTITUTION_REJECTED', 'journal_code')
  for (const key of ['operation_id', 'operation_nonce', 'request_id', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_journal_profile_record_digest_sha256']) if (canonicalize(request[key]) !== canonicalize(response[key])) fail('BROKER_PAIR_REJECTED', key)
  assertResolvedJournalProfile(request.d930_journal_profile_record_digest_sha256)
  if (request.sender_binding_code !== response.recipient_binding_code || request.recipient_binding_code !== response.sender_binding_code) fail('BROKER_PAIR_REJECTED', 'peers')
  if (request.operation_id !== supportingRecord.operation_id || request.operation_nonce !== supportingRecord.operation_nonce) fail('BROKER_SUPPORTING_RECORD_MISMATCH', 'operation')
  for (const key of ['runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) {
    if (request[key] !== supportingRecord[key]) fail('BROKER_SUPPORTING_RECORD_MISMATCH', key)
  }
  if (supportingRecordProducedAt(supportingRecord) > request.created_at || request.created_at > response.payload.persisted_at || response.payload.persisted_at > response.created_at) fail('CHRONOLOGY_REJECTED', 'supporting broker')
}

const extensionReferenceFields = ['custody_finalization', 'integrity_access', 'artifact_backup_receipt', 'prior_database_backup_receipt', 'final_backup_receipt', 'recovery']

function bundleKindFromContext(context) {
  return context.bundle_kind_code ?? 'single_document'
}

function findReferenceRule(semantic, context) {
  const candidates = classifications.journal_reference_rules.filter((rule) => {
    if (rule.event_kind_code !== semantic.event_kind_code && rule.event_kind_code !== 'default') return false
    if (rule.stage_code !== semantic.stage_code && rule.stage_code !== 'any') return false
    if (rule.operation_mode_code && rule.operation_mode_code !== semantic.operation_mode_code) return false
    if (rule.bundle_kind_code && rule.bundle_kind_code !== bundleKindFromContext(context)) return false
    return true
  })
  candidates.sort((left, right) => Number(right.event_kind_code !== 'default') - Number(left.event_kind_code !== 'default') || Number(Boolean(right.operation_mode_code)) - Number(Boolean(left.operation_mode_code)))
  return candidates[0]
}

function countSum(value) {
  return value ? Object.values(value).reduce((sum, item) => sum + item, 0) : null
}

function assertPolicy(value, policy, label) {
  if (policy === 'forbidden' && value !== null) fail('D90_EVENT_POLICY_REJECTED', label)
  if (policy === 'required' && value === null) fail('D90_EVENT_POLICY_REJECTED', label)
  if (policy === 'required_zero' && (value === null || countSum(value) !== 0)) fail('D90_EVENT_POLICY_REJECTED', label)
  if (policy === 'required_nonzero' && (value === null || countSum(value) <= 0)) fail('D90_EVENT_POLICY_REJECTED', label)
}

function expectedSemanticRole(semantic) {
  const extension = classifications.journal_composition_policy.semantic_origin_extension.find((entry) => entry.event_kind_code === semantic.event_kind_code)
  if (extension) return extension.runtime_role_code
  const origin = frozenClassifications.journal_event_origin_rules.find((entry) => entry.event_kind_code === semantic.event_kind_code)
  if (!origin) fail('D90_ORIGIN_REJECTED', semantic.event_kind_code)
  if (origin.origin_policy_code === 'exact_role') return origin.runtime_role_code
  return frozenClassifications.journal_stage_origin_rules.find((entry) => entry.stage_code === semantic.stage_code)?.runtime_role_code ?? null
}

function validateD90BaseSemantics(semantic, context = {}) {
  const extensionKind = classifications.journal_composition_policy.extension_event_kinds.includes(semantic.event_kind_code)
  const expectedRole = expectedSemanticRole(semantic)
  if (!expectedRole || bindingRole(semantic.component_binding_code) !== expectedRole) fail('D90_ORIGIN_REJECTED', `${semantic.event_kind_code}/${semantic.stage_code}`)
  const authorization = frozenClassifications.journal_authorization_rules.find((entry) => entry.operation_mode_code === semantic.operation_mode_code)
  if (!authorization) fail('D90_AUTHORIZATION_REJECTED')
  const hasPermit = semantic.authorization_permit_record_digest_sha256 !== null
  const hasSeal = semantic.authorization_bundle_seal_record_digest_sha256 !== null
  if (semantic.operation_mode_code === 'bootstrap' && (!hasPermit || hasSeal)) fail('D90_AUTHORIZATION_REJECTED')
  if (semantic.operation_mode_code === 'document_import' && (hasPermit || !hasSeal)) fail('D90_AUTHORIZATION_REJECTED')
  if (['dry_run', 'no_op_verification'].includes(semantic.operation_mode_code) && (hasPermit || hasSeal)) fail('D90_AUTHORIZATION_REJECTED')
  if (semantic.operation_mode_code === 'recovery' && (!hasPermit || hasSeal)) fail('D90_AUTHORIZATION_REJECTED')
  if (semantic.operation_mode_code === 'recovery') resolveRecoveryPermitForSemantic(semantic, context)
  if (semantic.bundle && context.bundle_kind_code === 'principal_bootstrap' && semantic.bundle.bundle_sequence !== 1) fail('D90_EVENT_POLICY_REJECTED', 'bootstrap bundle sequence')
  if (semantic.bundle && context.bundle_kind_code === 'single_document' && semantic.bundle.bundle_sequence < 2) fail('D90_EVENT_POLICY_REJECTED', 'document bundle sequence')
  const prepromotionRequired = semantic.operation_mode_code === 'document_import' && semantic.event_kind_code === 'promotion_started'
  if (prepromotionRequired !== (semantic.prepromotion_authorization_record_digest_sha256 !== null)) fail('D90_AUTHORIZATION_REJECTED', 'prepromotion')
  const rule = extensionKind
    ? classifications.journal_composition_policy.extension_event_rules.find((entry) => entry.event_kind_code === semantic.event_kind_code)
    : frozenClassifications.journal_event_rules.find((entry) => entry.event_kind_code === semantic.event_kind_code)
  if (!rule) fail('D90_EVENT_POLICY_REJECTED', 'missing rule')
  if (extensionKind && semantic.stage_code !== rule.stage_code) fail('D90_EVENT_POLICY_REJECTED', 'extension stage')
  if (!extensionKind) {
    const stageMatches = {
      startup_only: semantic.stage_code === 'startup',
      custody_prepare_only: semantic.stage_code === 'custody_prepare',
      database_transaction_only: semantic.stage_code === 'database_transaction',
      independent_verification_only: semantic.stage_code === 'independent_verification',
      promotion_only: semantic.stage_code === 'promotion',
      post_promotion_only: semantic.stage_code === 'post_promotion_verification',
      completion_only: semantic.stage_code === 'completion',
      any_registered: true,
      matches_error: semantic.error_code !== null && baseErrorSemantics(semantic.error_code).stage_code === semantic.stage_code,
    }
    if (!stageMatches[rule.stage_policy]) fail('D90_EVENT_POLICY_REJECTED', 'stage')
  }
  if (!rule.allowed_canonical_effects.includes(semantic.canonical_effect_code) || !rule.allowed_dispositions.includes(semantic.object_disposition_code)) fail('D90_EVENT_POLICY_REJECTED', 'effect/disposition')
  assertPolicy(semantic.rows_delta, rule.rows_policy, 'rows')
  assertPolicy(semantic.objects_delta, rule.objects_policy, 'objects')
  assertPolicy(semantic.candidate_file_sha256, rule.candidate_hash_policy, 'candidate')
  assertPolicy(semantic.backup_inventory_sha256, rule.backup_hash_policy, 'backup')
  if (rule.observed_state_policy === 'forbidden' && semantic.observed_logical_state !== null) fail('D90_EVENT_POLICY_REJECTED', 'observed')
  if (rule.observed_state_policy === 'required' && semantic.observed_logical_state === null) fail('D90_EVENT_POLICY_REJECTED', 'observed')
  if (rule.error_policy === 'forbidden' && semantic.error_code !== null) fail('D90_EVENT_POLICY_REJECTED', 'error')
  if (rule.error_policy === 'required' && semantic.error_code === null) fail('D90_EVENT_POLICY_REJECTED', 'error')
  if (rule.result_policy === 'forbidden' && semantic.result_outcome_code !== null) fail('D90_EVENT_POLICY_REJECTED', 'result')
  if (rule.result_policy.includes('required') && semantic.result_outcome_code === null) fail('D90_EVENT_POLICY_REJECTED', 'result')
  if (semantic.event_kind_code === 'recovery_required' && semantic.result_outcome_code !== 'recovery_required') fail('D90_EVENT_POLICY_REJECTED', 'recovery result')
  if (semantic.event_kind_code === 'operation_completed' && semantic.result_outcome_code === 'recovery_required') fail('D90_EVENT_POLICY_REJECTED', 'terminal kind')
  if (semantic.error_code !== null) {
    const baseError = frozenClassifications.error_rules.find((entry) => entry.code === semantic.error_code)
    const baseEffect = frozenClassifications.error_effect_rules.find((entry) => entry.error_code === semantic.error_code)
    const extensionError = classifications.new_error_rules.find((entry) => entry.error_code === semantic.error_code)
    const error = extensionError ?? (baseError && baseEffect ? {
      stage_code: baseError.stage,
      retryability_code: baseError.retryability_code,
      recovery_class_code: baseError.recovery_class_code,
      result_outcome_code: baseEffect.result_outcome_code,
      canonical_effect_code: baseEffect.canonical_effect_code,
      object_disposition_code: baseEffect.object_disposition_code,
      observed_state_policy_code: baseEffect.observed_state_policy_code,
    } : null)
    if (!error) fail('D90_EVENT_POLICY_REJECTED', 'unregistered error')
    const errorStageMustMatch = semantic.event_kind_code !== 'operation_completed'
    if ((errorStageMustMatch && semantic.stage_code !== error.stage_code) || semantic.retryability_code !== error.retryability_code || semantic.recovery_class_code !== error.recovery_class_code || semantic.canonical_effect_code !== error.canonical_effect_code || semantic.object_disposition_code !== error.object_disposition_code) fail('D90_EVENT_POLICY_REJECTED', 'error semantics')
    if (semantic.result_outcome_code !== null && semantic.result_outcome_code !== error.result_outcome_code) fail('D90_EVENT_POLICY_REJECTED', 'error result')
    if (extensionError?.terminal_event_kind_code && ['operation_completed', 'recovery_required'].includes(semantic.event_kind_code) && semantic.event_kind_code !== extensionError.terminal_event_kind_code) fail('D90_EVENT_POLICY_REJECTED', 'extension terminal')
    if (error.observed_state_policy_code === 'forbidden' && semantic.observed_logical_state !== null) fail('D90_EVENT_POLICY_REJECTED', 'error observed state')
    if (error.observed_state_policy_code === 'required' && semantic.observed_logical_state === null) fail('D90_EVENT_POLICY_REJECTED', 'error observed state')
    const bundlePolicy = extensionError?.bundle_reference_policy_code ?? frozenClassifications.error_bundle_reference_rules.find((entry) => entry.error_code === semantic.error_code)?.bundle_reference_policy_code
    if (!bundlePolicy || (bundlePolicy === 'forbidden' && semantic.bundle !== null) || (bundlePolicy === 'required' && semantic.bundle === null)) fail('D90_EVENT_POLICY_REJECTED', 'error bundle reference')
    const resultErrors = frozenClassifications.result_error_rules.find((entry) => entry.result_outcome_code === semantic.result_outcome_code)
    if (!extensionError && semantic.result_outcome_code !== null && !resultErrors?.allowed_error_codes.includes(semantic.error_code)) fail('D90_EVENT_POLICY_REJECTED', 'result/error pair')
  } else {
    if (semantic.retryability_code !== 'never' || semantic.recovery_class_code !== 'none') fail('D90_EVENT_POLICY_REJECTED', 'non-error recovery metadata')
    if (semantic.event_kind_code === 'operation_completed' && semantic.observed_logical_state === null) fail('D90_EVENT_POLICY_REJECTED', 'successful observed state')
  }
  if (semantic.event_kind_code === 'operation_completed' || semantic.event_kind_code === 'recovery_required') {
    const bundleKind = semantic.bundle === null ? 'null' : context.bundle_kind_code
    const resultRules = frozenClassifications.result_rules.filter((entry) => entry.outcome === semantic.result_outcome_code && entry.allowed_operation_modes.includes(semantic.operation_mode_code) && entry.allowed_bundle_kinds.includes(bundleKind))
    if (resultRules.length !== 1) fail('D90_EVENT_POLICY_REJECTED', 'result tuple')
    const resultRule = resultRules[0]
    if (!resultRule.allowed_canonical_effects.includes(semantic.canonical_effect_code) || resultRule.error_required !== (semantic.error_code !== null)) fail('D90_EVENT_POLICY_REJECTED', 'result semantics')
    validateTerminalCounts(semantic, resultRule.count_policy)
    if (semantic.result_outcome_code === 'recovered') {
      const permitKind = semantic.operation_mode_code === 'recovery' ? resolveRecoveryPermitForSemantic(semantic, context).permit.permit_kind_code : context.permit_kind_code
      const recovered = frozenClassifications.recovered_result_authorization_rules.filter((entry) => entry.bundle_kind_code === bundleKind && entry.permit_kind_code === permitKind)
      if (recovered.length !== 1) fail('D90_AUTHORIZATION_REJECTED', 'recovered result')
      validateTerminalCounts(semantic, recovered[0].count_policy_code)
    }
  }
}

function validateTerminalCounts(semantic, countPolicy) {
  const rowsKnown = semantic.rows_delta !== null
  const objectsKnown = semantic.objects_delta !== null
  const allKnown = rowsKnown && objectsKnown
  const rowsZero = rowsKnown && Object.values(semantic.rows_delta).every((value) => value === 0)
  const objectsZero = objectsKnown && Object.values(semantic.objects_delta).every((value) => value === 0)
  if (countPolicy === 'all_zero' && !(rowsZero && objectsZero)) fail('D90_EVENT_POLICY_REJECTED', 'all-zero counts')
  if (countPolicy === 'known' && !allKnown) fail('D90_EVENT_POLICY_REJECTED', 'known counts')
  if (countPolicy === 'rows_zero_objects_orphan_only' && (!allKnown || !rowsZero || semantic.objects_delta.prepared !== 0 || semantic.objects_delta.reused !== 0)) fail('D90_EVENT_POLICY_REJECTED', 'rejected counts')
  if (countPolicy === 'bootstrap_exact' && (!allKnown || semantic.rows_delta.atlas_evidence_bundle_receipts !== 1 || Object.entries(semantic.rows_delta).some(([key, value]) => key !== 'atlas_evidence_bundle_receipts' && value !== 0) || !objectsZero)) fail('D90_EVENT_POLICY_REJECTED', 'bootstrap counts')
  if (countPolicy === 'document_exact' && (!allKnown || semantic.rows_delta.atlas_evidence_bundle_receipts !== 1 || semantic.rows_delta.atlas_retrieval_locations !== 1 || semantic.rows_delta.atlas_artifacts !== 1 || semantic.rows_delta.atlas_retrieval_events !== 1 || semantic.rows_delta.atlas_retrieval_redirects !== 0 || semantic.rows_delta.atlas_artifact_custody_events !== 1 || semantic.rows_delta.atlas_processing_runs !== 0 || semantic.rows_delta.atlas_processing_outputs !== 0 || semantic.rows_delta.atlas_unverified_candidate_occurrences !== 0 || semantic.objects_delta.prepared !== 1 || semantic.objects_delta.reused !== 0 || semantic.objects_delta.orphaned !== 0)) fail('D90_EVENT_POLICY_REJECTED', 'document counts')
  if (countPolicy === 'unknown_allowed' && (rowsKnown !== objectsKnown)) fail('D90_EVENT_POLICY_REJECTED', 'partial unknown counts')
}

function validateBackupChronology(reference, semanticEventAt, journalPersistedAt) {
  if (!reference) return
  if (reference.completed_at > reference.persisted_at || reference.persisted_at > semanticEventAt || semanticEventAt > journalPersistedAt) fail('BACKUP_REFERENCE_CHRONOLOGY_REJECTED')
  const rule = classifications.backup_reference_rules.find((entry) => entry.receipt_kind_code === reference.receipt_kind_code)
  if (!rule || rule.scope_profile_code !== reference.scope_profile_code) fail('BACKUP_REFERENCE_TYPE_REJECTED')
  if (bindingRole(reference.produced_by_binding_code) !== 'backup_adapter') fail('BACKUP_REFERENCE_PRODUCER_REJECTED')
}

function validateSemantic(semantic, context = {}) {
  validateRecord(semantic)
  validateD90BaseSemantics(semantic, context)
  const referenceRule = findReferenceRule(semantic, context)
  if (!referenceRule) fail('JOURNAL_REFERENCE_MATRIX', 'no rule')
  for (const field of referenceRule.required) if (semantic[field] === null) fail('JOURNAL_REFERENCE_MATRIX', `missing ${field}`)
  for (const field of referenceRule.forbidden) if (semantic[field] !== null) fail('JOURNAL_REFERENCE_MATRIX', `forbidden ${field}`)
  if (semantic.custody_finalization) {
    const evidence = semantic.custody_finalization
    assertExactBackendReference(evidence.artifact, evidence.backend_reference)
    const expectedOps = ['open_staged', 'prepare', 'verify_prepared', 'publish_no_replace']
    assert.deepEqual(evidence.exchanges.map((entry) => entry.operation_code), expectedOps)
    const expectedOutcomes = ['opened', 'prepared', 'verified']
    assert.deepEqual(evidence.exchanges.slice(0, 3).map((entry) => entry.success_outcome_code), expectedOutcomes)
    if (!['published', 'reused_verified'].includes(evidence.exchanges[3].success_outcome_code)) fail('JOURNAL_EXCHANGE_MATRIX')
  }
  if (semantic.integrity_access) {
    const evidence = semantic.integrity_access
    assertExactBackendReference(evidence.artifact, evidence.backend_reference)
    assert.deepEqual(evidence.exchanges.map((entry) => `${entry.operation_code}:${entry.success_outcome_code}`), ['seal_custody_access:sealed', 'open_custody:available'])
    assert.deepEqual(evidence.verifier_recomputed_artifact, evidence.artifact)
    if (evidence.claim_lifetime_ms > classifications.integrity_access_policy.claim_lifetime_ms_max) fail('INTEGRITY_ACCESS_REJECTED')
    if (bindingRole(evidence.verifier_binding_code) !== 'independent_verifier') fail('INTEGRITY_ACCESS_REJECTED')
  }
  if (semantic.recovery) validateRecoveryPayloadShape(semantic, context)
  return semantic
}

function validateJournalEvent(event, context = {}) {
  validateRecord(event)
  assertResolvedJournalProfile(event.semantic_assertion.d930_journal_profile_record_digest_sha256)
  if (event.semantic_assertion_record_digest_sha256 !== recordDigest(event.semantic_assertion)) fail('JOURNAL_SEMANTIC_DIGEST_MISMATCH')
  if (event.semantic_assertion.event_at > event.persisted_at) fail('CHRONOLOGY_REJECTED', 'journal')
  if (bindingRole(event.persisted_by_binding_code) !== 'journal_broker') fail('JOURNAL_BROKER_REJECTED')
  validateSemantic(event.semantic_assertion, { ...context, persisted_at: event.persisted_at, persisted_by_binding_code: event.persisted_by_binding_code, event_record_digest_sha256: event.record_digest_sha256 })
  validateBackupChronology(event.semantic_assertion.artifact_backup_receipt, event.semantic_assertion.event_at, event.persisted_at)
  validateBackupChronology(event.semantic_assertion.prior_database_backup_receipt, event.semantic_assertion.event_at, event.persisted_at)
  validateBackupChronology(event.semantic_assertion.final_backup_receipt, event.semantic_assertion.event_at, event.persisted_at)
}

function validateJournalChain(events, context = {}) {
  assert.ok(events.length)
  const first = events[0]
  if (first.event_sequence !== 1 || first.previous_event_record_digest_sha256 !== null || first.semantic_assertion.event_kind_code !== 'operation_started') fail('JOURNAL_CHAIN_REJECTED', 'invalid root')
  const fixed = {
    journal_code: first.journal_code,
    operation_id: first.semantic_assertion.operation_id,
    operation_nonce: first.semantic_assertion.operation_nonce,
    operation_mode_code: first.semantic_assertion.operation_mode_code,
    runtime_profile_record_digest_sha256: first.semantic_assertion.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: first.semantic_assertion.identity_bindings_record_digest_sha256,
    d930_journal_profile_record_digest_sha256: first.semantic_assertion.d930_journal_profile_record_digest_sha256,
    authorization_permit_record_digest_sha256: first.semantic_assertion.authorization_permit_record_digest_sha256,
    authorization_bundle_seal_record_digest_sha256: first.semantic_assertion.authorization_bundle_seal_record_digest_sha256,
    bundle: first.semantic_assertion.bundle,
    target_logical_state: first.semantic_assertion.target_logical_state,
  }
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]
    const previousEvent = index === 0 ? null : events[index - 1]
    validateJournalEvent(event, { ...context, journal_code: first.journal_code, previous_event: previousEvent })
    if (event.event_sequence !== index + 1) fail('JOURNAL_CHAIN_REJECTED', 'gap')
    const predecessor = previousEvent?.record_digest_sha256 ?? null
    if (event.previous_event_record_digest_sha256 !== predecessor) fail('JOURNAL_CHAIN_REJECTED', 'fork')
    if (previousEvent && ['operation_completed', 'recovery_required'].includes(previousEvent.semantic_assertion.event_kind_code)) fail('JOURNAL_CHAIN_REJECTED', 'successor after terminal')
    if (index && events[index - 1].persisted_at >= event.persisted_at) fail('JOURNAL_CHAIN_REJECTED', 'persistence')
    if (index && events[index - 1].semantic_assertion.event_at >= event.semantic_assertion.event_at) fail('JOURNAL_CHAIN_REJECTED', 'event chronology')
    for (const [key, value] of Object.entries(fixed)) if (canonicalize(key === 'journal_code' ? event.journal_code : event.semantic_assertion[key]) !== canonicalize(value)) fail('JOURNAL_CONTEXT_DRIFT', key)
  }
}

function zeroRows(nonzero = false) {
  const keys = ['atlas_evidence_bundle_receipts', 'atlas_retrieval_locations', 'atlas_artifacts', 'atlas_retrieval_events', 'atlas_retrieval_redirects', 'atlas_artifact_custody_events', 'atlas_processing_runs', 'atlas_processing_outputs', 'atlas_unverified_candidate_occurrences']
  return Object.fromEntries(keys.map((key, index) => [key, nonzero && index === 0 ? 1 : 0]))
}

function backupReference(kind, timestamp) {
  const rule = classifications.backup_reference_rules.find((entry) => entry.receipt_kind_code === kind)
  return {
    receipt_kind_code: kind,
    receipt_contract_format: 'jedi-atlas-backup-durability-receipt',
    receipt_contract_version: '1.0.0',
    receipt_raw_sha256: sample.sha(kind === 'artifact_copy' ? '71' : kind === 'prior_database' ? '72' : '73'),
    scope_profile_code: rule.scope_profile_code,
    scope_sha256: sample.sha(kind === 'artifact_copy' ? '74' : kind === 'prior_database' ? '75' : '76'),
    backup_profile_record_digest_sha256: sample.sha('77'),
    produced_by_binding_code: 'backup.adapter.synthetic',
    completed_at: timestamp,
    persisted_at: timestamp,
  }
}

function custodyEvidence() {
  return {
    artifact: sample.artifact,
    copy_code: sample.intent.copy_code,
    backend_code: sample.intent.backend_code,
    backend_reference: sample.intent.backend_reference,
    exchanges: [
      ['open_staged', 'opened', '31', '32'],
      ['prepare', 'prepared', '33', '34'],
      ['verify_prepared', 'verified', '35', '36'],
      ['publish_no_replace', 'published', '37', '38'],
    ].map(([operation_code, success_outcome_code, request, response], index) => ({
      operation_code,
      request_record_digest_sha256: sample.sha(request),
      request_persistence_ack_record_digest_sha256: sample.sha(`5${index}`),
      response_record_digest_sha256: sample.sha(response),
      response_persistence_ack_record_digest_sha256: sample.sha(`6${index}`),
      success_outcome_code,
    })),
    primary_receipt: { format: 'jedi-atlas-primary-durability-receipt', format_version: '1.0.0', record_code: 'receipt.synthetic.matrix', receipt_raw_sha256: sample.sha('39') },
    preparation_capability_consumed_transition_digest_sha256: sample.sha('3a'),
  }
}

function integrityEvidence() {
  return {
    artifact: sample.artifact,
    copy_code: sample.intent.copy_code,
    backend_code: sample.intent.backend_code,
    backend_reference: sample.intent.backend_reference,
    purpose_code: 'integrity',
    claim_lifetime_ms: 30000,
    exchanges: [
      { operation_code: 'seal_custody_access', request_record_digest_sha256: sample.sha('41'), request_persistence_ack_record_digest_sha256: sample.sha('51'), response_record_digest_sha256: sample.sha('42'), response_persistence_ack_record_digest_sha256: sample.sha('52'), success_outcome_code: 'sealed' },
      { operation_code: 'open_custody', request_record_digest_sha256: sample.sha('43'), request_persistence_ack_record_digest_sha256: sample.sha('53'), response_record_digest_sha256: sample.sha('45'), response_persistence_ack_record_digest_sha256: sample.sha('54'), success_outcome_code: 'available' },
    ],
    primary_receipt: { format: 'jedi-atlas-primary-durability-receipt', format_version: '1.0.0', record_code: 'receipt.synthetic.matrix', receipt_raw_sha256: sample.sha('39') },
    sealed_capability_consumed_transition_digest_sha256: sample.sha('44'),
    verifier_binding_code: 'independent.verifier.synthetic',
    verifier_executable_sha256: sample.sha('46'),
    semantic_producer_process: {
      process_instance_code: 'process.verifier.coordinator.synthetic.matrix',
      pid: 4201,
      uid: 4100,
      gid: 4100,
      start_time_ticks: 89900,
      executable_device: 2049,
      executable_inode: 90003,
      peer_credentials_verified: true,
      custody_descriptor_absent: true,
      authenticated_at: '2030-01-01T00:12:01.100Z',
    },
    descriptor_delivery_record_digest_sha256: sample.sha('47'),
    descriptor_delivery_persistence_ack_record_digest_sha256: sample.sha('57'),
    verifier_result_record_digest_sha256: sample.sha('49'),
    verifier_result_persistence_ack_record_digest_sha256: sample.sha('59'),
    receiver_termination_record_digest_sha256: sample.sha('48'),
    receiver_termination_persistence_ack_record_digest_sha256: sample.sha('58'),
    verifier_recomputed_artifact: sample.artifact,
  }
}

function getPath(value, dotted) {
  return dotted.split('.').reduce((current, key) => current?.[key], value)
}

function matchRecoveryPredicate(knowledge, observation, predicate) {
  return Object.entries(predicate).every(([pathCode, expectedValue]) => {
    const rootValue = pathCode.startsWith('knowledge.') ? knowledge : observation
    const localPath = pathCode.replace(/^(knowledge|observation)\./, '')
    return canonicalize(getPath(rootValue, localPath)) === canonicalize(expectedValue)
  })
}

function validateRecoveryObservationConsistency(observation) {
  for (const rule of classifications.recovery_observation_consistency_rules) {
    if (getPath(observation, rule.when.path_code) !== rule.when.value) continue
    for (const [pathCode, allowedValues] of Object.entries(rule.require_all)) {
      if (!allowedValues.includes(getPath(observation, pathCode))) fail('RECOVERY_OBSERVATION_CONTRADICTION', `${rule.rule_code}/${pathCode}`)
    }
  }
}

function evaluateRecovery(knowledge, observation) {
  for (const guard of classifications.recovery_fail_closed_guards) {
    const rootValue = guard.path_code.startsWith('knowledge.') ? knowledge : observation
    const localPath = guard.path_code.replace(/^(knowledge|observation)\./, '')
    if (guard.unsafe_values.some((value) => canonicalize(value) === canonicalize(getPath(rootValue, localPath)))) {
      return classifications.recovery_decision_rules.find((rule) => rule.decision_rule_code === guard.decision_rule_code)
    }
  }
  validateRecoveryObservationConsistency(observation)
  const ordered = classifications.recovery_decision_rules.slice().sort((left, right) => left.priority - right.priority)
  const matches = ordered.filter((rule) => rule.match_any.some((predicate) => matchRecoveryPredicate(knowledge, observation, predicate)))
  if (matches.length === 0) fail('RECOVERY_MATRIX_NOT_TOTAL')
  return matches[0]
}

const syntheticRecoveryResolverBrand = new WeakSet()

function requireSyntheticRecoveryResolver(context) {
  const resolver = context.recovery_resolution
  if (!resolver || !syntheticRecoveryResolverBrand.has(resolver)) fail('RECOVERY_RESOLVER_UNTRUSTED')
  return resolver
}

function activeBinding(identityBindings, bindingCode, roleCode, fromAt, throughAt = fromAt, principalKindCode = null, throughIsExclusive = false, requiredOperationMode = 'recovery') {
  const matches = identityBindings.bindings.filter((binding) => binding.binding_code === bindingCode)
  if (matches.length !== 1) fail('RECOVERY_PERMIT_INVALID', `binding ${bindingCode}`)
  const binding = matches[0]
  if (binding.runtime_role_code !== roleCode
    || (principalKindCode && binding.principal_kind_code !== principalKindCode)
    || !binding.allowed_operation_modes.includes(requiredOperationMode)
    || binding.valid_from > fromAt
    || binding.valid_until <= fromAt
    || (throughIsExclusive ? binding.valid_until < throughAt : binding.valid_until <= throughAt)) fail('RECOVERY_PERMIT_INVALID', `inactive or wrong-role binding ${bindingCode}`)
  const roleRule = frozenClassifications.runtime_role_binding_rules.find((entry) => entry.runtime_role_code === roleCode)
  if (!roleRule || roleRule.principal_kind_code !== binding.principal_kind_code || !roleRule.allowed_operation_modes.includes(requiredOperationMode)) fail('RECOVERY_PERMIT_INVALID', `role policy ${bindingCode}`)
  return binding
}

function validateFrozenPermitClaim(permit, claim, runtimeProfile, identityBindings) {
  validateFrozenD90Record(permit, frozenBootstrapControlSchema)
  validateFrozenD90Record(claim, frozenBootstrapControlSchema)
  validateFrozenD90Record(runtimeProfile, frozenRuntimeProfileSchema)
  validateFrozenD90Record(identityBindings, frozenIdentityBindingsSchema)
  const policy = frozenClassifications.post_promotion_completion_permit_policy
  const scopeRule = frozenClassifications.permit_scope_execution_rules.find((entry) => entry.permit_kind_code === 'post_promotion_completion')
  if (permit.record_kind_code !== 'post_promotion_completion_permit' || permit.permit_kind_code !== 'post_promotion_completion' || permit.scope_code !== policy.scope_code || permit.scope_code !== scopeRule.scope_code) fail('RECOVERY_PERMIT_INVALID', 'kind or scope')
  if (permit.canonical_write_code !== policy.canonical_write_code
    || permit.canonical_write_code !== scopeRule.canonical_write_code
    || permit.allowed_canonical_effect_code !== policy.allowed_canonical_effect_code
    || !scopeRule.allowed_canonical_effect_codes.includes(permit.allowed_canonical_effect_code)
    || canonicalize(permit.allowed_actions) !== canonicalize(policy.allowed_actions)
    || !policy.required_bundle_kind_codes.includes(permit.target_bundle_kind_code)) fail('RECOVERY_PERMIT_INVALID', 'authority')
  const lifetimeMs = Date.parse(permit.expires_at) - Date.parse(permit.issued_at)
  if (permit.issued_at > permit.not_before || permit.not_before >= permit.expires_at || lifetimeMs <= 0 || lifetimeMs > policy.maximum_lifetime_ms) fail('RECOVERY_PERMIT_INVALID', 'issuance chronology')
  if (permit.runtime_profile_record_digest_sha256 !== runtimeProfile.record_digest_sha256
    || permit.identity_bindings_record_digest_sha256 !== identityBindings.record_digest_sha256
    || identityBindings.runtime_profile_record_digest_sha256 !== runtimeProfile.record_digest_sha256
    || identityBindings.runtime_domain_sha256 !== runtimeProfile.runtime_domain_sha256
    || identityBindings.issued_at > permit.issued_at
    || identityBindings.expires_at < permit.expires_at) fail('RECOVERY_PERMIT_INVALID', 'resolved runtime identity')
  const importer = activeBinding(identityBindings, permit.importer_binding_code, 'bundle_importer', permit.issued_at, permit.expires_at, 'service', true)
  const operator = activeBinding(identityBindings, permit.operator_binding_code, 'recovery_operator', permit.issued_at, permit.expires_at, 'human', true)
  const witness = activeBinding(identityBindings, permit.witness_binding_code, 'operational_witness', permit.issued_at, permit.expires_at, 'human', true)
  const issuer = activeBinding(identityBindings, permit.issuer_binding_code, 'recovery_authority', permit.issued_at, permit.expires_at, 'human', true)
  if (new Set([operator.binding_code, witness.binding_code, issuer.binding_code]).size !== 3
    || new Set([operator.unix_uid, witness.unix_uid, issuer.unix_uid]).size !== 3
    || importer.principal_kind_code !== 'service') fail('RECOVERY_PERMIT_INVALID', 'human separation')
  if (claim.record_kind_code !== 'permit_transition' || claim.permit_kind_code !== permit.permit_kind_code || claim.permit_code !== permit.permit_code || claim.permit_issuance_record_digest_sha256 !== permit.record_digest_sha256) fail('RECOVERY_PERMIT_INVALID', 'claim identity')
  const transitionRule = frozenClassifications.permit_transition_rules.find((entry) => entry.permit_kind_code === permit.permit_kind_code
    && entry.from_state_code === claim.from_state_code
    && entry.to_state_code === claim.to_state_code
    && entry.transition_code === claim.transition_code
    && entry.reason_code === claim.reason_code)
  if (!transitionRule || claim.transition_sequence !== 1 || claim.previous_transition_record_digest_sha256 !== null || claim.from_state_code !== 'ready' || claim.to_state_code !== 'in_progress' || claim.transition_code !== 'operation_claimed' || claim.reason_code !== 'operation_claimed') fail('RECOVERY_PERMIT_INVALID', 'claim state')
  if (claim.operation_id !== permit.operation_id || claim.operation_nonce !== permit.operation_nonce || claim.completion_journal_head_record_digest_sha256 !== null || claim.recovery_permit_record_digest_sha256 !== null) fail('RECOVERY_PERMIT_INVALID', 'claim operation')
  if (canonicalize(claim.observed_logical_state) !== canonicalize(permit.verified_canonical_logical_state)) fail('RECOVERY_PERMIT_INVALID', 'claim observed state')
  if (claim.recorded_by_runtime_role_code !== transitionRule.recorder_runtime_role_code
    || claim.recorded_by_binding_code !== claim.persisted_by_binding_code) fail('RECOVERY_PERMIT_INVALID', 'claim persistence actors')
  activeBinding(identityBindings, claim.recorded_by_binding_code, 'trusted_launcher', claim.occurred_at, claim.persisted_at, 'service')
  for (const binding of [importer, identityBindings.bindings.find((entry) => entry.binding_code === claim.recorded_by_binding_code)]) {
    const release = runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === binding.runtime_role_code)
    if (!release || release.executable_sha256 !== binding.executable_sha256) fail('RECOVERY_PERMIT_INVALID', `release ${binding.binding_code}`)
  }
  if (claim.occurred_at < permit.not_before || claim.occurred_at >= permit.expires_at || claim.persisted_at < claim.occurred_at || claim.persisted_at >= permit.expires_at
    || Date.parse(permit.expires_at) - Date.parse(claim.occurred_at) < frozenClassifications.permit_claim_policy.minimum_remaining_lifetime_ms) fail('RECOVERY_PERMIT_INVALID', 'claim chronology')
}

function resolveRecoveryPermitForSemantic(semantic, context) {
  const resolver = requireSyntheticRecoveryResolver(context)
  if (!context.persisted_at) fail('RECOVERY_RESOLVER_TIME_MISSING')
  const permit = resolver.resolvePermit(semantic.authorization_permit_record_digest_sha256)
  if (!permit) fail('RECOVERY_PERMIT_INVALID', 'unresolved')
  const claim = resolver.resolvePermitHead(permit.record_digest_sha256)
  if (!claim) fail('RECOVERY_PERMIT_INVALID', 'current claim unresolved')
  const runtimeProfile = resolver.resolveRuntimeProfile(permit.runtime_profile_record_digest_sha256)
  const identityBindings = resolver.resolveIdentityBindings(permit.identity_bindings_record_digest_sha256)
  if (!runtimeProfile || !identityBindings) fail('RECOVERY_PERMIT_INVALID', 'runtime or identity unresolved')
  validateFrozenPermitClaim(permit, claim, runtimeProfile, identityBindings)
  if (semantic.authorization_permit_record_digest_sha256 !== permit.record_digest_sha256 || semantic.operation_id !== permit.operation_id || semantic.operation_nonce !== permit.operation_nonce) fail('RECOVERY_PERMIT_INVALID', 'operation binding')
  if (semantic.runtime_profile_record_digest_sha256 !== permit.runtime_profile_record_digest_sha256 || semantic.identity_bindings_record_digest_sha256 !== permit.identity_bindings_record_digest_sha256) fail('RECOVERY_PERMIT_INVALID', 'runtime binding')
  if (canonicalize(semantic.bundle) !== canonicalize(permit.target_bundle) || canonicalize(semantic.target_logical_state) !== canonicalize(permit.verified_canonical_logical_state)) fail('RECOVERY_PERMIT_INVALID', 'target')
  if (context.bundle_kind_code !== permit.target_bundle_kind_code) fail('RECOVERY_PERMIT_INVALID', 'bundle kind')
  const scopeRule = frozenClassifications.permit_scope_execution_rules.find((entry) => entry.permit_kind_code === permit.permit_kind_code && entry.scope_code === permit.scope_code)
  const semanticRole = bindingRole(semantic.component_binding_code)
  if (!scopeRule
    || !scopeRule.allowed_journal_event_kind_codes.includes(semantic.event_kind_code)
    || !scopeRule.allowed_stage_codes.includes(semantic.stage_code)
    || !scopeRule.allowed_canonical_effect_codes.includes(semantic.canonical_effect_code)
    || !scopeRule.allowed_origin_runtime_role_codes.includes(semanticRole)) fail('RECOVERY_PERMIT_INVALID', 'semantic scope')
  const semanticBindingCode = semantic.component_binding_code
  const semanticBinding = activeBinding(identityBindings, semanticBindingCode, semanticRole, semantic.event_at, semantic.event_at, 'service')
  const release = runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === semanticRole)
  if (!release || release.executable_sha256 !== semantic.component_executable_sha256 || semanticBinding.executable_sha256 !== release.executable_sha256) fail('RECOVERY_PERMIT_INVALID', 'semantic executable')
  if (!context.persisted_by_binding_code) fail('RECOVERY_PERMIT_INVALID', 'journal persistence binding missing')
  const journalBrokerBinding = activeBinding(identityBindings, context.persisted_by_binding_code, 'journal_broker', context.persisted_at, context.persisted_at, 'service')
  const journalBrokerRelease = runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === 'journal_broker')
  if (!journalBrokerRelease || journalBrokerBinding.executable_sha256 !== journalBrokerRelease.executable_sha256) fail('RECOVERY_PERMIT_INVALID', 'journal broker executable')
  if (claim.persisted_at > semantic.event_at || semantic.event_at > context.persisted_at || semantic.event_at < permit.not_before || context.persisted_at >= permit.expires_at) fail('RECOVERY_PERMIT_INVALID', 'protected time')
  return { resolver, permit, claim, identityBindings, runtimeProfile }
}

function validateFrozenSourceEventSemantics(event) {
  const rule = frozenClassifications.journal_event_rules.find((entry) => entry.event_kind_code === event.event_kind_code)
  if (!rule || !rule.allowed_canonical_effects.includes(event.canonical_effect_code) || !rule.allowed_dispositions.includes(event.object_disposition_code)) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'event policy')
  const prepromotionAuthorizationRequired = event.operation_mode_code === 'document_import' && event.event_kind_code === 'promotion_started'
  if (prepromotionAuthorizationRequired !== (event.prepromotion_authorization_record_digest_sha256 !== null)) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'prepromotion authorization')
  const stageMatches = rule.stage_policy === 'any_registered'
    || (rule.stage_policy === 'startup_only' && event.stage_code === 'startup')
    || (rule.stage_policy === 'custody_prepare_only' && event.stage_code === 'custody_prepare')
    || (rule.stage_policy === 'database_transaction_only' && event.stage_code === 'database_transaction')
    || (rule.stage_policy === 'independent_verification_only' && event.stage_code === 'independent_verification')
    || (rule.stage_policy === 'promotion_only' && event.stage_code === 'promotion')
    || (rule.stage_policy === 'post_promotion_only' && event.stage_code === 'post_promotion_verification')
    || (rule.stage_policy === 'completion_only' && event.stage_code === 'completion')
    || (rule.stage_policy === 'matches_error' && event.error_code && frozenClassifications.error_rules.find((entry) => entry.code === event.error_code)?.stage === event.stage_code)
  if (!stageMatches) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'event stage policy')
  const presence = (policy, value, label, aggregate = false) => {
    if (policy === 'forbidden' && value !== null) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', label)
    if (policy === 'required' && value === null) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', label)
    if (policy === 'required_zero' && (value === null || !aggregate || Object.values(value).some((count) => count !== 0))) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', label)
    if (policy === 'required_nonzero' && (value === null || !aggregate || Object.values(value).every((count) => count === 0))) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', label)
  }
  presence(rule.rows_policy, event.rows_delta, 'rows policy', true)
  presence(rule.objects_policy, event.objects_delta, 'objects policy', true)
  presence(rule.candidate_hash_policy, event.candidate_file_sha256, 'candidate hash policy')
  presence(rule.backup_hash_policy, event.backup_inventory_sha256, 'backup hash policy')
  if (rule.observed_state_policy !== 'required_when_error_absent_else_error_policy') presence(rule.observed_state_policy, event.observed_logical_state, 'observed state policy')
  if (rule.error_policy === 'required' && event.error_code === null) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'required error')
  if (rule.error_policy === 'forbidden' && event.error_code !== null) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'forbidden error')
  if (rule.result_policy === 'forbidden' && event.result_outcome_code !== null) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'forbidden result')
  if (rule.result_policy === 'recovery_required_only' && event.result_outcome_code !== 'recovery_required') fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'recovery result')
  if (rule.result_policy === 'required_terminal' && event.result_outcome_code === null) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'required result')
  if (rule.terminal !== ['operation_completed', 'recovery_required'].includes(event.event_kind_code)) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'terminal policy')
  if (event.error_code !== null) {
    const error = frozenClassifications.error_rules.find((entry) => entry.code === event.error_code)
    const effect = frozenClassifications.error_effect_rules.find((entry) => entry.error_code === event.error_code)
    if (!error || !effect || (event.event_kind_code !== 'operation_completed' && event.stage_code !== error.stage) || event.retryability_code !== error.retryability_code || event.recovery_class_code !== error.recovery_class_code || event.canonical_effect_code !== effect.canonical_effect_code || event.object_disposition_code !== effect.object_disposition_code) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'error tuple')
    if (effect.observed_state_policy_code === 'required' && event.observed_logical_state === null) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'error observed state')
    if (effect.observed_state_policy_code === 'forbidden' && event.observed_logical_state !== null) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'error observed state')
  } else if (event.retryability_code !== 'never' || event.recovery_class_code !== 'none') fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'non-error recovery metadata')
}

function validateFrozenSourceMilestoneContinuity(sourceHistory) {
  const byEventKind = new Map(sourceHistory.map((record) => [record.event_kind_code, record]))
  const candidateMilestones = ['candidate_committed', 'candidate_sealed', 'promotion_started', 'promotion_observed'].map((kind) => byEventKind.get(kind)).filter(Boolean)
  if (candidateMilestones.length > 0) {
    const candidateHashes = candidateMilestones.map((record) => record.candidate_file_sha256)
    if (candidateHashes.some((digest) => digest === null) || new Set(candidateHashes).size !== 1) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'candidate file continuity')
  }
  const promotionMilestones = ['promotion_started', 'promotion_observed'].map((kind) => byEventKind.get(kind)).filter(Boolean)
  if (promotionMilestones.length > 0) {
    const backupHashes = promotionMilestones.map((record) => record.backup_inventory_sha256)
    if (backupHashes.some((digest) => digest === null) || new Set(backupHashes).size !== 1) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'backup inventory continuity')
  }
  const sealed = byEventKind.get('candidate_sealed')
  if (sealed) {
    const observed = byEventKind.get('promotion_observed')?.observed_logical_state ?? sourceHistory.at(-1)?.observed_logical_state
    if (sealed.observed_logical_state === null || observed === null || canonicalize(sealed.observed_logical_state) !== canonicalize(observed)) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'candidate state continuity')
  }
}

function validateResolvedRecoverySource(semantic, payload, resolver, permit, identityBindings, runtimeProfile) {
  const source = resolver.resolveSourceJournalHead(payload.source_terminal_journal_code)
  if (!source) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'unresolved current head')
  validateFrozenD90Record(source, frozenJournalEventSchema)
  if (source.runtime_profile_record_digest_sha256 !== permit.runtime_profile_record_digest_sha256
    || source.identity_bindings_record_digest_sha256 !== permit.identity_bindings_record_digest_sha256) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'runtime identity')
  const sourceHistory = resolver.resolveSourceJournalHistory(payload.source_terminal_journal_code)
  if (!Array.isArray(sourceHistory) || sourceHistory.length !== source.event_sequence || sourceHistory.at(-1)?.record_digest_sha256 !== source.record_digest_sha256) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'history resolution')
  let previous = null
  for (let index = 0; index < sourceHistory.length; index += 1) {
    const record = sourceHistory[index]
    validateFrozenD90Record(record, frozenJournalEventSchema)
    validateFrozenSourceEventSemantics(record)
    const originRule = frozenClassifications.journal_event_origin_rules.find((entry) => entry.event_kind_code === record.event_kind_code)
    const componentRole = originRule?.origin_policy_code === 'exact_role'
      ? originRule.runtime_role_code
      : frozenClassifications.journal_stage_origin_rules.find((entry) => entry.stage_code === record.stage_code)?.runtime_role_code
    const componentRoleRule = frozenClassifications.runtime_role_binding_rules.find((entry) => entry.runtime_role_code === componentRole)
    if (!componentRoleRule) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'component role')
    const componentBinding = activeBinding(identityBindings, record.component_binding_code, componentRole, record.event_at, record.event_at, componentRoleRule.principal_kind_code, false, record.operation_mode_code)
    const componentRelease = runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === componentRole)
    if (!componentRelease || componentBinding.executable_sha256 !== componentRelease.executable_sha256 || record.component_executable_sha256 !== componentRelease.executable_sha256) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'component executable')
    const sourceBroker = activeBinding(identityBindings, record.recorded_by_binding_code, 'journal_broker', record.persisted_at, record.persisted_at, 'service', false, record.operation_mode_code)
    const sourceBrokerRelease = runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === 'journal_broker')
    if (!sourceBrokerRelease || sourceBroker.executable_sha256 !== sourceBrokerRelease.executable_sha256 || componentBinding.binding_code === sourceBroker.binding_code) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'journal broker')
    if (record.journal_code !== source.journal_code
      || record.event_sequence !== index + 1
      || record.previous_event_record_digest_sha256 !== (previous?.record_digest_sha256 ?? null)
      || record.operation_id !== source.operation_id
      || record.operation_nonce !== source.operation_nonce
      || record.operation_mode_code !== source.operation_mode_code
      || record.runtime_profile_record_digest_sha256 !== permit.runtime_profile_record_digest_sha256
      || record.identity_bindings_record_digest_sha256 !== permit.identity_bindings_record_digest_sha256
      || canonicalize(record.bundle) !== canonicalize(source.bundle)
      || canonicalize(record.target_logical_state) !== canonicalize(source.target_logical_state)
      || record.authorization_permit_record_digest_sha256 !== source.authorization_permit_record_digest_sha256
      || record.authorization_bundle_seal_record_digest_sha256 !== source.authorization_bundle_seal_record_digest_sha256
      || record.event_at > record.persisted_at
      || (previous && (record.event_at <= previous.event_at || record.persisted_at <= previous.persisted_at))) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'history chain')
    previous = record
  }
  if (sourceHistory[0].event_kind_code !== 'operation_started' || sourceHistory.at(-1).event_kind_code !== 'recovery_required') fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'history boundaries')
  if (source.record_digest_sha256 !== permit.source_recovery_journal_event_record_digest_sha256) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'permit source')
  if (source.operation_id !== payload.subject_operation_id || source.operation_nonce !== payload.subject_operation_nonce) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'subject operation')
  const sourceTuple = {
    source_terminal_journal_code: source.journal_code,
    source_terminal_journal_sequence: source.event_sequence,
    source_terminal_journal_head_record_digest_sha256: source.record_digest_sha256,
    source_terminal_journal_persisted_at: source.persisted_at,
    source_terminal_error_code: source.error_code,
  }
  for (const [field, value] of Object.entries(sourceTuple)) if (payload[field] !== value) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', field)
  const sourceRule = frozenClassifications.post_promotion_source_error_rules.find((entry) => entry.error_code === source.error_code)
  if (!sourceRule || !sourceRule.allowed_bundle_kind_codes.includes(permit.target_bundle_kind_code)) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'error or bundle kind')
  const sourceError = frozenClassifications.error_rules.find((entry) => entry.code === source.error_code)
  const sourceEffect = frozenClassifications.error_effect_rules.find((entry) => entry.error_code === source.error_code)
  if (!sourceError || !sourceEffect
    || source.event_kind_code !== 'recovery_required'
    || source.stage_code !== sourceError.stage
    || source.result_outcome_code !== 'recovery_required'
    || source.retryability_code !== sourceError.retryability_code
    || source.recovery_class_code !== sourceError.recovery_class_code
    || canonicalize(source.bundle) !== canonicalize(payload.subject_bundle)) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'semantic tuple')
  const sourceObservedMustMatch = sourceRule.observed_state_policy_code === 'required' || source.observed_logical_state !== null
  if (sourceObservedMustMatch && canonicalize(source.observed_logical_state) !== canonicalize(permit.verified_canonical_logical_state)) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'observed state')
  if (source.canonical_effect_code !== sourceRule.canonical_effect_code
    || source.canonical_effect_code !== sourceEffect.canonical_effect_code
    || source.object_disposition_code !== sourceRule.object_disposition_code
    || source.object_disposition_code !== sourceEffect.object_disposition_code) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'frozen source semantics')
  const expectedSourceMode = permit.target_bundle_kind_code === 'single_document' ? 'document_import' : 'bootstrap'
  const expectedSourcePermitKind = permit.target_bundle_kind_code === 'single_document' ? 'none' : 'bootstrap'
  if (source.operation_mode_code !== expectedSourceMode) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'operation mode')
  const historyRules = frozenClassifications.journal_history_rules.filter((entry) => entry.operation_mode_code === source.operation_mode_code
    && entry.result_outcome_code === source.result_outcome_code
    && entry.canonical_effect_code === source.canonical_effect_code
    && entry.permit_kind_code === expectedSourcePermitKind
    && entry.terminal_error_code === source.error_code)
  if (historyRules.length !== 1) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'history selector')
  const historyRule = historyRules[0]
  const actualMilestones = sourceHistory.map((record) => `${record.event_kind_code}@${record.stage_code}`)
  const expectedMilestones = historyRule.required_ordered_milestones.map((entry) => `${entry.event_kind_code}@${entry.stage_code}`)
  const withoutOptionalFailure = actualMilestones.filter((milestone, index) => !(index === actualMilestones.length - 2 && milestone === `stage_failed@${source.stage_code}`))
  if (canonicalize(withoutOptionalFailure) !== canonicalize(expectedMilestones)
    || actualMilestones.some((milestone) => historyRule.forbidden_event_kind_codes.includes(milestone.split('@')[0]))) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'required history')
  const optionalFailure = sourceHistory.length > 1 && sourceHistory.at(-2).event_kind_code === 'stage_failed' ? sourceHistory.at(-2) : null
  if (optionalFailure && (optionalFailure.stage_code !== source.stage_code
    || optionalFailure.error_code !== source.error_code
    || optionalFailure.retryability_code !== source.retryability_code
    || optionalFailure.recovery_class_code !== source.recovery_class_code
    || optionalFailure.canonical_effect_code !== source.canonical_effect_code
    || optionalFailure.object_disposition_code !== source.object_disposition_code
    || canonicalize(optionalFailure.observed_logical_state) !== canonicalize(source.observed_logical_state))) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'stage-failure context')
  validateFrozenSourceMilestoneContinuity(sourceHistory)
  const sourceResultRule = frozenClassifications.result_rules.find((entry) => entry.outcome === source.result_outcome_code && entry.allowed_operation_modes.includes(source.operation_mode_code))
  if (!sourceResultRule) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'result rule')
  validateTerminalCounts(source, sourceResultRule.count_policy)
  if ((historyRule.terminal_backup_policy_code === 'required' && source.backup_inventory_sha256 === null)
    || (historyRule.terminal_backup_policy_code === 'forbidden' && source.backup_inventory_sha256 !== null)) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'terminal backup')
  if (source.persisted_at > permit.issued_at || source.persisted_at > payload.knowledge_snapshot.scan_started_at) fail('RECOVERY_SOURCE_TERMINAL_REJECTED', 'knowledge chronology')
  const sourceAuthorization = resolver.resolveSourceAuthorization(permit.source_authorization_record_digest_sha256)
  if (!sourceAuthorization) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'unresolved')
  if (permit.target_bundle_kind_code === 'single_document') {
    validateFrozenD90Record(sourceAuthorization, frozenCollectorHandoffSchema)
    if (sourceAuthorization.record_kind_code !== 'bundle_seal'
      || sourceAuthorization.bundle_kind_code !== 'single_document'
      || sourceAuthorization.record_digest_sha256 !== source.authorization_bundle_seal_record_digest_sha256
      || source.authorization_permit_record_digest_sha256 !== null
      || permit.source_terminal_transition_record_digest_sha256 !== null
      || canonicalize(sourceAuthorization.bundle) !== canonicalize(permit.target_bundle)
      || sourceAuthorization.operation_id !== source.operation_id
      || sourceAuthorization.operation_nonce !== source.operation_nonce
      || sourceAuthorization.runtime_profile_record_digest_sha256 !== permit.runtime_profile_record_digest_sha256
      || sourceAuthorization.identity_bindings_record_digest_sha256 !== permit.identity_bindings_record_digest_sha256
      || canonicalize(sourceAuthorization.target_logical_state) !== canonicalize(source.target_logical_state)
      || sourceAuthorization.sealed_at > sourceHistory[0].event_at
      || source.persisted_at >= sourceAuthorization.expires_at) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'document source')
    const submitter = activeBinding(identityBindings, sourceAuthorization.submitter_binding_code, 'human_submitter', sourceAuthorization.sealed_at, source.persisted_at, 'human', false, 'document_import')
    const importer = activeBinding(identityBindings, sourceAuthorization.importer_binding_code, 'bundle_importer', sourceAuthorization.sealed_at, source.persisted_at, 'service', false, 'document_import')
    const launcher = activeBinding(identityBindings, sourceAuthorization.launcher_binding_code, 'trusted_launcher', sourceAuthorization.sealed_at, source.persisted_at, 'service', false, 'document_import')
    if (new Set([submitter.binding_code, importer.binding_code, launcher.binding_code]).size !== 3) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'document actor separation')
    for (const binding of [importer, launcher]) {
      const release = runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === binding.runtime_role_code)
      if (!release || release.executable_sha256 !== binding.executable_sha256) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'document actor executable')
    }
  } else {
    validateFrozenD90Record(sourceAuthorization, frozenBootstrapControlSchema)
    if (sourceAuthorization.record_kind_code !== 'permit_issuance' || sourceAuthorization.permit_kind_code !== 'bootstrap' || sourceAuthorization.scope_code !== 'canonical_first_acceptance_only' || sourceAuthorization.record_digest_sha256 !== source.authorization_permit_record_digest_sha256 || source.authorization_bundle_seal_record_digest_sha256 !== null || canonicalize(sourceAuthorization.bootstrap_bundle) !== canonicalize(permit.target_bundle)
      || sourceAuthorization.operation_nonce !== source.operation_nonce
      || sourceAuthorization.runtime_profile_record_digest_sha256 !== permit.runtime_profile_record_digest_sha256
      || sourceAuthorization.identity_bindings_record_digest_sha256 !== permit.identity_bindings_record_digest_sha256
      || sourceAuthorization.issued_at > source.event_at
      || sourceAuthorization.issued_at > sourceAuthorization.not_before
      || sourceAuthorization.not_before >= sourceAuthorization.expires_at
      || Date.parse(sourceAuthorization.expires_at) - Date.parse(sourceAuthorization.issued_at) > frozenClassifications.bootstrap_permit_policy.maximum_lifetime_ms
      || source.persisted_at >= sourceAuthorization.expires_at) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap source')
    const bootstrapActors = [
      activeBinding(identityBindings, sourceAuthorization.submitter_binding_code, 'human_submitter', sourceAuthorization.issued_at, sourceAuthorization.expires_at, 'human', true, 'bootstrap'),
      activeBinding(identityBindings, sourceAuthorization.witness_binding_code, 'operational_witness', sourceAuthorization.issued_at, sourceAuthorization.expires_at, 'human', true, 'bootstrap'),
      activeBinding(identityBindings, sourceAuthorization.issuer_binding_code, 'bootstrap_authority', sourceAuthorization.issued_at, sourceAuthorization.expires_at, 'human', true, 'bootstrap'),
    ]
    if (new Set(bootstrapActors.map((binding) => binding.binding_code)).size !== 3 || new Set(bootstrapActors.map((binding) => binding.unix_uid)).size !== 3) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap human separation')
    const bootstrapImporter = activeBinding(identityBindings, sourceAuthorization.importer_binding_code, 'bundle_importer', sourceAuthorization.issued_at, sourceAuthorization.expires_at, 'service', true, 'bootstrap')
    const importerRelease = runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === 'bundle_importer')
    if (!importerRelease || bootstrapImporter.executable_sha256 !== importerRelease.executable_sha256 || sourceAuthorization.importer_release_sha256 !== importerRelease.executable_sha256) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap importer')
    const terminal = resolver.resolvePermitHead(sourceAuthorization.record_digest_sha256)
    if (!terminal) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap terminal unresolved')
    validateFrozenD90Record(terminal, frozenBootstrapControlSchema)
    if (terminal.record_digest_sha256 !== permit.source_terminal_transition_record_digest_sha256 || terminal.permit_issuance_record_digest_sha256 !== sourceAuthorization.record_digest_sha256 || terminal.transition_code !== 'verified_effect' || terminal.to_state_code !== 'spent' || canonicalize(terminal.observed_logical_state) !== canonicalize(permit.verified_canonical_logical_state) || terminal.operation_id !== source.operation_id || terminal.operation_nonce !== source.operation_nonce || terminal.persisted_at <= source.persisted_at || terminal.persisted_at > permit.issued_at) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap terminal')
    const permitHistory = resolver.resolvePermitHistory(sourceAuthorization.record_digest_sha256)
    if (!Array.isArray(permitHistory) || permitHistory.length !== 2 || permitHistory.at(-1)?.record_digest_sha256 !== terminal.record_digest_sha256) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap transition history')
    let priorTransition = null
    for (let index = 0; index < permitHistory.length; index += 1) {
      const transition = permitHistory[index]
      validateFrozenD90Record(transition, frozenBootstrapControlSchema)
      const transitionRule = frozenClassifications.permit_transition_rules.find((entry) => entry.permit_kind_code === 'bootstrap' && entry.from_state_code === transition.from_state_code && entry.to_state_code === transition.to_state_code && entry.transition_code === transition.transition_code && entry.reason_code === transition.reason_code)
      if (!transitionRule
        || transition.transition_sequence !== index + 1
        || transition.previous_transition_record_digest_sha256 !== (priorTransition?.record_digest_sha256 ?? null)
        || transition.permit_issuance_record_digest_sha256 !== sourceAuthorization.record_digest_sha256
        || transition.permit_code !== sourceAuthorization.permit_code
        || transition.operation_id !== source.operation_id
        || transition.operation_nonce !== sourceAuthorization.operation_nonce
        || transition.recorded_by_runtime_role_code !== transitionRule.recorder_runtime_role_code
        || transition.recovery_permit_record_digest_sha256 !== null
        || transition.completion_journal_head_record_digest_sha256 !== null
        || transition.occurred_at < sourceAuthorization.not_before
        || transition.occurred_at >= sourceAuthorization.expires_at
        || transition.persisted_at < transition.occurred_at
        || transition.persisted_at >= sourceAuthorization.expires_at
        || (priorTransition && (transition.occurred_at <= priorTransition.occurred_at || transition.persisted_at <= priorTransition.persisted_at))) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap transition')
      const recorder = activeBinding(identityBindings, transition.recorded_by_binding_code, transitionRule.recorder_runtime_role_code, transition.occurred_at, transition.occurred_at, 'service', false, 'bootstrap')
      const persister = activeBinding(identityBindings, transition.persisted_by_binding_code, 'trusted_launcher', transition.persisted_at, transition.persisted_at, 'service', false, 'bootstrap')
      if (recorder.binding_code !== persister.binding_code) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap transition actor')
      priorTransition = transition
    }
    if (permitHistory[0].persisted_at > sourceHistory[0].event_at) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap claim visibility')
    if (canonicalize(permitHistory[0].observed_logical_state) !== canonicalize(sourceAuthorization.target_empty_logical_state)) fail('RECOVERY_SOURCE_AUTHORIZATION_REJECTED', 'bootstrap initial state')
  }
  return source
}

function validateResolvedRecoveryLock(semantic, knowledge, resolver, context, claim, identityBindings) {
  const lockHead = resolver.resolveRecoveryLockHead(semantic.operation_id, semantic.operation_nonce)
  if (!lockHead) fail('RECOVERY_LOCK_REJECTED', 'unresolved')
  const expectedKeys = ['is_current', 'projection', 'record_digest_sha256', 'record_kind_code']
  if (canonicalize(Object.keys(lockHead).sort()) !== canonicalize(expectedKeys)) fail('RECOVERY_LOCK_REJECTED', 'shape')
  if (lockHead.record_kind_code !== 'synthetic_protected_recovery_lock_head' || lockHead.is_current !== true || recordDigest(lockHead) !== lockHead.record_digest_sha256) fail('RECOVERY_LOCK_REJECTED', 'head')
  const projection = recoveryLockProjection(knowledge)
  if (knowledge.recovery_lock_projection_sha256 !== canonicalSha256(projection) || canonicalize(lockHead.projection) !== canonicalize(projection)) fail('RECOVERY_LOCK_REJECTED', 'projection')
  if (projection.storage_handle_slot_code !== 'permit_control_store' || projection.state_code !== 'held' || bindingRole(projection.owner_binding_code) !== 'trusted_launcher' || projection.operation_id !== semantic.operation_id || projection.operation_nonce !== semantic.operation_nonce) fail('RECOVERY_LOCK_REJECTED', 'authority')
  if (claim.persisted_at > projection.acquired_at || projection.acquired_at >= knowledge.scan_started_at || knowledge.scan_completed_at > semantic.event_at || semantic.event_at >= projection.expires_at || !context.persisted_at || context.persisted_at >= projection.expires_at) fail('RECOVERY_LOCK_REJECTED', 'chronology')
  if (projection.owner_binding_code !== claim.recorded_by_binding_code || projection.owner_binding_code !== claim.persisted_by_binding_code) fail('RECOVERY_LOCK_REJECTED', 'claim launcher')
  activeBinding(identityBindings, projection.owner_binding_code, 'trusted_launcher', projection.acquired_at, context.persisted_at, 'service')
  return lockHead
}

function validateRecoveryPayloadShape(semantic, context = {}) {
  const payload = semantic.recovery
  if (semantic.event_kind_code !== 'stage_succeeded' || semantic.stage_code !== 'reconciliation' || semantic.operation_mode_code !== 'recovery') fail('RECOVERY_CHAIN_REJECTED', 'base semantic')
  const { resolver, permit, claim, identityBindings, runtimeProfile } = resolveRecoveryPermitForSemantic(semantic, context)
  if (payload.record_kind_code !== 'classification_only_recovery_assessment') fail('RECOVERY_CHAIN_REJECTED', 'kind')
  if (canonicalize(payload.subject_bundle) !== canonicalize(semantic.bundle)) fail('RECOVERY_SUBJECT_REJECTED', 'bundle')
  if (!Number.isSafeInteger(payload.recovery_attempt_sequence) || payload.recovery_attempt_sequence < 1) fail('RECOVERY_CHAIN_REJECTED', 'attempt sequence')
  if ((payload.recovery_attempt_sequence === 1) !== (payload.prior_attempt_terminal_record_digest_sha256 === null)) fail('RECOVERY_CHAIN_REJECTED', 'attempt predecessor')
  const artifactFields = [payload.subject_artifact, payload.subject_copy_code, payload.subject_backend_code, payload.subject_backend_reference]
  const documentSubject = permit.target_bundle_kind_code === 'single_document'
  if (documentSubject && artifactFields.some((value) => value === null)) fail('RECOVERY_SUBJECT_REJECTED', 'document subject incomplete')
  if (!documentSubject && artifactFields.some((value) => value !== null)) fail('RECOVERY_SUBJECT_REJECTED', 'bootstrap subject has custody')
  if (payload.subject_artifact) assertExactBackendReference(payload.subject_artifact, payload.subject_backend_reference)
  const knowledge = payload.knowledge_snapshot
  validateResolvedRecoverySource(semantic, payload, resolver, permit, identityBindings, runtimeProfile)
  if (knowledge.subject_operation_id !== payload.subject_operation_id || knowledge.subject_operation_nonce !== payload.subject_operation_nonce || knowledge.recovery_operation_id !== semantic.operation_id || knowledge.recovery_operation_nonce !== semantic.operation_nonce) fail('RECOVERY_CHAIN_REJECTED', 'snapshot subject')
  if (knowledge.recovery_lock_acquired_at >= knowledge.scan_started_at || knowledge.scan_started_at > knowledge.scan_completed_at || knowledge.scan_completed_at > semantic.event_at || semantic.event_at >= knowledge.recovery_lock_expires_at) fail('RECOVERY_CHAIN_REJECTED', 'snapshot chronology')
  if (knowledge.recovery_lock_storage_slot_code !== 'permit_control_store' || bindingRole(knowledge.recovery_lock_owner_binding_code) !== 'trusted_launcher') fail('RECOVERY_CHAIN_REJECTED', 'lock authority')
  if (knowledge.recovery_lock_projection_sha256 !== recoveryLockProjectionSha(knowledge)) fail('RECOVERY_CHAIN_REJECTED', 'lock projection')
  validateResolvedRecoveryLock(semantic, knowledge, resolver, context, claim, identityBindings)
  if (payload.source_terminal_journal_persisted_at > knowledge.scan_started_at) fail('RECOVERY_CHAIN_REJECTED', 'source chronology')
  if (!context.previous_event || knowledge.known_through_journal_code !== context.journal_code || knowledge.known_through_journal_sequence !== context.previous_event.event_sequence || knowledge.known_through_journal_head_record_digest_sha256 !== context.previous_event.record_digest_sha256 || knowledge.known_through_journal_head_persisted_at !== context.previous_event.persisted_at || context.previous_event.persisted_at > knowledge.scan_started_at) fail('RECOVERY_CHAIN_REJECTED', 'preappend journal head')
  for (const name of ['operation_control_inventory', 'capability_inventory', 'primary_receipt_inventory', 'custody_inventory', 'candidate_inventory', 'canonical_state_inventory', 'reference_inventory', 'hold_inventory', 'backup_inventory']) {
    const inventory = knowledge[name]
    const complete = ['complete_empty', 'complete_nonempty'].includes(inventory.state_code)
    if ((inventory.state_code === 'complete_nonempty') !== (inventory.head_digest_sha256 !== null)) fail('RECOVERY_CHAIN_REJECTED', `${name} head`)
    if (!complete && inventory.head_digest_sha256 !== null) fail('RECOVERY_CHAIN_REJECTED', `${name} unavailable head`)
  }
  if (knowledge.snapshot_completeness_code === 'complete') {
    for (const name of ['operation_control_inventory', 'capability_inventory', 'primary_receipt_inventory', 'custody_inventory', 'candidate_inventory', 'canonical_state_inventory', 'reference_inventory', 'hold_inventory']) if (knowledge[name].state_code === 'unavailable') fail('RECOVERY_CHAIN_REJECTED', `${name} incomplete`)
    if (!['complete_empty', 'complete_nonempty', 'unavailable_d9_5'].includes(knowledge.backup_inventory.state_code)) fail('RECOVERY_CHAIN_REJECTED', 'backup inventory incomplete')
  }
  if (payload.observation.lock_state_code !== 'held_by_recovery_operation') fail('RECOVERY_CHAIN_REJECTED', 'lock ownership')
  const selected = evaluateRecovery(knowledge, payload.observation)
  for (const field of ['decision_rule_code', 'classification_code', 'next_step_code', 'classification_outcome_code', 'action_execution_code']) if (payload[field] !== selected[field]) fail('RECOVERY_DECISION_MISMATCH', field)
  if (canonicalize(payload.blocking_reason_codes) !== canonicalize(selected.blocking_reason_codes)) fail('RECOVERY_DECISION_MISMATCH', 'blocking reasons')
  if (!classifications.recovery_action_outcome_rules.some((entry) => entry.next_step_code === payload.next_step_code && entry.classification_outcome_code === payload.classification_outcome_code)) fail('RECOVERY_OUTCOME_MISMATCH')
}

function inventoryCommitment(stateCode = 'complete_nonempty', seed = '82') {
  return { state_code: stateCode, head_digest_sha256: stateCode === 'complete_nonempty' ? sample.sha(seed) : null }
}

function recoveryLockProjectionSha(knowledge) {
  return canonicalSha256(recoveryLockProjection(knowledge))
}

function recoveryLockProjection(knowledge) {
  return {
    storage_handle_slot_code: knowledge.recovery_lock_storage_slot_code,
    operation_id: knowledge.recovery_operation_id,
    operation_nonce: knowledge.recovery_operation_nonce,
    owner_binding_code: knowledge.recovery_lock_owner_binding_code,
    acquired_at: knowledge.recovery_lock_acquired_at,
    expires_at: knowledge.recovery_lock_expires_at,
    state_code: 'held',
  }
}

function makeKnowledgeSnapshot(overrides = {}) {
  const knowledge = {
    subject_operation_id: 'operation.subject.synthetic',
    subject_operation_nonce: sample.sha('96'),
    recovery_operation_id: 'operation.recovery.synthetic',
    recovery_operation_nonce: sample.sha('91'),
    recovery_lock_storage_slot_code: 'permit_control_store',
    recovery_lock_owner_binding_code: 'trusted.launcher.synthetic',
    recovery_lock_projection_sha256: sample.sha('80'),
    recovery_lock_acquired_at: '2030-01-01T00:00:59.000Z',
    recovery_lock_expires_at: '2030-01-01T00:02:00.000Z',
    scan_started_at: '2030-01-01T00:01:00.000Z',
    scan_completed_at: '2030-01-01T00:01:01.000Z',
    snapshot_completeness_code: 'complete',
    known_through_journal_code: 'journal.operation.recovery.synthetic',
    known_through_journal_sequence: 1,
    known_through_journal_head_record_digest_sha256: sample.sha('81'),
    known_through_journal_head_persisted_at: '2030-01-01T00:00:58.000Z',
    operation_control_inventory: inventoryCommitment('complete_nonempty', '82'),
    capability_inventory: inventoryCommitment('complete_nonempty', '83'),
    primary_receipt_inventory: inventoryCommitment('complete_nonempty', '84'),
    custody_inventory: inventoryCommitment('complete_nonempty', '85'),
    candidate_inventory: inventoryCommitment('complete_nonempty', '86'),
    canonical_state_inventory: inventoryCommitment('complete_nonempty', '87'),
    reference_inventory: inventoryCommitment('complete_empty'),
    hold_inventory: inventoryCommitment('complete_empty'),
    backup_inventory: inventoryCommitment('unavailable_d9_5'),
    ...overrides,
  }
  knowledge.recovery_lock_projection_sha256 = recoveryLockProjectionSha(knowledge)
  return knowledge
}

function baselineObservation() {
  return {
    operation_state_code: 'terminal',
    lock_state_code: 'held_by_recovery_operation',
    temporary_state_code: 'absent',
    final_object_state_code: 'absent',
    primary_receipt_state_code: 'absent',
    adapter_response_state_code: 'absent',
    journal_link_state_code: 'absent',
    artifact_backup_state_code: 'unavailable_d9_5',
    candidate_state_code: 'absent',
    prior_backup_state_code: 'unavailable_d9_5',
    promotion_state_code: 'not_started',
    canonical_state_code: 'prior_exact',
    final_backup_state_code: 'unavailable_d9_5',
    completion_state_code: 'absent',
    reference_scan_code: 'complete_none',
    hold_scan_code: 'complete_none',
    bytes_state_code: 'not_applicable',
  }
}

function setObservationPath(knowledge, observation, dotted, value) {
  const target = dotted.startsWith('knowledge.') ? knowledge : observation
  const segments = dotted.replace(/^(knowledge|observation)\./, '').split('.')
  let current = target
  for (const segment of segments.slice(0, -1)) current = current[segment]
  current[segments.at(-1)] = value
}

function observationForRule(rule, predicate = rule.match_any[0]) {
  const knowledge = makeKnowledgeSnapshot()
  const observation = baselineObservation()
  for (const [field, value] of Object.entries(predicate)) setObservationPath(knowledge, observation, field, value)
  if (observation.primary_receipt_state_code === 'exact') observation.final_object_state_code = 'exact'
  if (observation.adapter_response_state_code === 'exact_resolvable') {
    observation.primary_receipt_state_code = 'exact'
    observation.final_object_state_code = 'exact'
  }
  if (observation.journal_link_state_code === 'exact') {
    observation.adapter_response_state_code = 'exact_resolvable'
    observation.primary_receipt_state_code = 'exact'
    observation.final_object_state_code = 'exact'
  }
  if (observation.artifact_backup_state_code === 'reference_exact') {
    observation.journal_link_state_code = 'exact'
    observation.adapter_response_state_code = 'exact_resolvable'
    observation.primary_receipt_state_code = 'exact'
    observation.final_object_state_code = 'exact'
  }
  if (observation.candidate_state_code !== 'absent' && observation.candidate_state_code !== 'unknown') {
    observation.artifact_backup_state_code = 'reference_exact'
    observation.journal_link_state_code = 'exact'
    observation.adapter_response_state_code = 'exact_resolvable'
    observation.primary_receipt_state_code = 'exact'
    observation.final_object_state_code = 'exact'
  }
  if (observation.promotion_state_code === 'target_verified') {
    observation.candidate_state_code = 'sealed'
    observation.prior_backup_state_code = 'reference_exact'
  }
  if (observation.completion_state_code === 'exact') {
    observation.promotion_state_code = 'target_verified'
    observation.canonical_state_code = 'target_exact'
    observation.final_backup_state_code = 'reference_exact'
    observation.candidate_state_code = 'sealed'
    observation.prior_backup_state_code = 'reference_exact'
  }
  // Close implications introduced by the promotion/completion branches above.
  if (observation.candidate_state_code !== 'absent' && observation.candidate_state_code !== 'unknown') {
    observation.artifact_backup_state_code = 'reference_exact'
  }
  if (observation.artifact_backup_state_code === 'reference_exact') {
    observation.journal_link_state_code = 'exact'
    observation.adapter_response_state_code = 'exact_resolvable'
    observation.primary_receipt_state_code = 'exact'
    observation.final_object_state_code = 'exact'
  }
  return { knowledge, observation }
}

function assertRecoveryDecisionMatrix() {
  const priorities = classifications.recovery_decision_rules.map((rule) => rule.priority)
  assert.deepEqual(priorities, priorities.slice().sort((left, right) => left - right))
  assert.equal(new Set(priorities).size, priorities.length)
  assert.equal(classifications.recovery_decision_rules.at(-1).decision_rule_code, 'default_ambiguous')
  assert.deepEqual(classifications.orphan_precedence, classifications.recovery_decision_rules.map((rule) => rule.decision_rule_code))
  assert.equal(new Set(classifications.recovery_observation_consistency_rules.map((rule) => rule.rule_code)).size, classifications.recovery_observation_consistency_rules.length)
  for (const rule of classifications.recovery_observation_consistency_rules) {
    const observation = baselineObservation()
    observation[rule.when.path_code] = rule.when.value
    for (let pass = 0; pass < classifications.recovery_observation_consistency_rules.length; pass += 1) {
      for (const closureRule of classifications.recovery_observation_consistency_rules) {
        if (observation[closureRule.when.path_code] !== closureRule.when.value) continue
        for (const [pathCode, allowedValues] of Object.entries(closureRule.require_all)) observation[pathCode] = allowedValues[0]
      }
    }
    validateRecoveryObservationConsistency(observation)
    const [requiredPath, allowedValues] = Object.entries(rule.require_all)[0]
    const contradicted = clone(observation)
    contradicted[requiredPath] = allowedValues.includes('unknown') ? 'synthetic_invalid' : 'unknown'
    assertThrowsCode(() => validateRecoveryObservationConsistency(contradicted), 'RECOVERY_OBSERVATION_CONTRADICTION')
  }
  const retroactivePromotion = baselineObservation()
  retroactivePromotion.operation_state_code = 'not_started'
  retroactivePromotion.promotion_state_code = 'target_verified'
  retroactivePromotion.candidate_state_code = 'sealed'
  retroactivePromotion.prior_backup_state_code = 'reference_exact'
  retroactivePromotion.canonical_state_code = 'target_exact'
  assertThrowsCode(() => evaluateRecovery(makeKnowledgeSnapshot(), retroactivePromotion), 'RECOVERY_OBSERVATION_CONTRADICTION')
  for (const rule of classifications.recovery_decision_rules) {
    for (const [branchIndex, predicate] of rule.match_any.entries()) {
      const { knowledge, observation } = observationForRule(rule, predicate)
      const selected = evaluateRecovery(knowledge, observation)
      assert.equal(selected.decision_rule_code, rule.decision_rule_code, `${rule.decision_rule_code}/${branchIndex}`)
    }
    assert.ok(classifications.recovery_action_outcome_rules.some((entry) => entry.next_step_code === rule.next_step_code && entry.classification_outcome_code === rule.classification_outcome_code))
  }
  for (const guard of classifications.recovery_fail_closed_guards) {
    for (const unsafe of guard.unsafe_values) {
      const knowledge = makeKnowledgeSnapshot()
      const observation = baselineObservation()
      setObservationPath(knowledge, observation, guard.path_code, unsafe)
      assert.equal(evaluateRecovery(knowledge, observation).decision_rule_code, guard.decision_rule_code, `${guard.guard_code}/${unsafe}`)
    }
  }
  const precedenceKnowledge = makeKnowledgeSnapshot({ snapshot_completeness_code: 'incomplete' })
  const precedenceObservation = baselineObservation()
  precedenceObservation.completion_state_code = 'exact'
  precedenceObservation.canonical_state_code = 'target_exact'
  precedenceObservation.final_backup_state_code = 'reference_exact'
  assert.equal(evaluateRecovery(precedenceKnowledge, precedenceObservation).decision_rule_code, 'incomplete_or_unknown')
  const boundaryNextSteps = {
    none_classification_only: 'none',
    retain_wait_for_d9_4: 'wait_for_d9_4',
    retain_and_hold: 'retain_and_hold',
    classify_new_exact_operation_required: 'new_exact_operation_required',
    retain_wait_for_d9_5: 'wait_for_d9_5',
    classify_post_promotion_authority_required: 'post_promotion_completion_authority_required',
  }
  for (const boundary of classifications.crash_boundary_rules) {
    const rule = classifications.recovery_decision_rules.find((entry) => entry.decision_rule_code === boundary.decision_rule_code)
    assert.ok(rule, boundary.boundary_code)
    assert.equal(rule.next_step_code, boundaryNextSteps[boundary.safe_direct_action_code], `${boundary.boundary_code} next step`)
    assert.equal(rule.action_execution_code, 'none_classification_only', `${boundary.boundary_code} action`)
    const { knowledge, observation } = observationForRule(rule, rule.match_any[0])
    const selected = evaluateRecovery(knowledge, observation)
    assert.equal(selected.decision_rule_code, boundary.decision_rule_code, `${boundary.boundary_code} classification`)
    assert.equal(selected.classification_code, rule.classification_code, `${boundary.boundary_code} class`)
    assert.equal(selected.next_step_code, boundaryNextSteps[boundary.safe_direct_action_code], `${boundary.boundary_code} projected next step`)
    assert.deepEqual(selected.blocking_reason_codes, rule.blocking_reason_codes, `${boundary.boundary_code} blockers`)
    assert.equal(selected.action_execution_code, 'none_classification_only', `${boundary.boundary_code} projected action`)
  }
  const contradiction = baselineObservation()
  contradiction.primary_receipt_state_code = 'exact'
  assertThrowsCode(() => evaluateRecovery(makeKnowledgeSnapshot(), contradiction), 'RECOVERY_OBSERVATION_CONTRADICTION')
}

const syntheticEpoch = Date.parse('2030-01-01T00:11:00.000Z')

function atTick(tick, offset = 0) {
  return new Date(syntheticEpoch + tick * 1000 + offset).toISOString()
}

function baseErrorSemantics(errorCode) {
  const error = frozenClassifications.error_rules.find((entry) => entry.code === errorCode)
  const effect = frozenClassifications.error_effect_rules.find((entry) => entry.error_code === errorCode)
  const extension = classifications.new_error_rules.find((entry) => entry.error_code === errorCode)
  if (extension) return extension
  if (!error || !effect) fail('UNREGISTERED_ERROR', errorCode)
  return {
    error_code: errorCode,
    stage_code: error.stage,
    result_outcome_code: effect.result_outcome_code,
    canonical_effect_code: effect.canonical_effect_code,
    object_disposition_code: effect.object_disposition_code,
    observed_state_policy_code: effect.observed_state_policy_code,
    retryability_code: error.retryability_code,
    recovery_class_code: error.recovery_class_code,
  }
}

function bindingForRole(role) {
  const values = {
    trusted_launcher: 'trusted.launcher.synthetic',
    bundle_importer: 'bundle.importer.synthetic',
    custody_adapter: 'custody.adapter.synthetic',
    backup_adapter: 'backup.adapter.synthetic',
    database_writer: 'database.writer.synthetic',
    independent_verifier: 'independent.verifier.synthetic',
    cloner_promoter: 'cloner.promoter.synthetic',
    journal_broker: 'journal.broker.synthetic',
    scanner: 'scanner.synthetic',
    clearance_broker: 'clearance.broker.synthetic',
  }
  return values[role] ?? fail('ROLE_BINDING_MISSING', role)
}

function frozenBindingForRole(role) {
  const values = {
    backup_adapter: 'binding.backup-adapter',
    bundle_importer: 'binding.importer',
    custody_adapter: 'binding.custody-adapter',
    database_writer: 'binding.database-writer',
    independent_verifier: 'binding.verifier',
    cloner_promoter: 'binding.cloner-promoter',
    journal_broker: 'binding.journal-broker',
    trusted_launcher: 'binding.launcher',
  }
  return values[role] ?? fail('ROLE_BINDING_MISSING', role)
}

function semanticDefaults(history, milestone, tick) {
  const [eventKind, stageCode] = milestone.split('@')
  const operationMode = history.base_selector.operation_mode_code
  const role = expectedSemanticRole({ event_kind_code: eventKind, stage_code: stageCode })
  return {
    format: 'jedi-atlas-operation-journal-semantic-assertion',
    format_version: '1.0.0',
    record_code: `semantic.${history.history_code}.${tick}`,
    operation_mode_code: operationMode,
    operation_id: `operation.${history.history_code}`,
    operation_nonce: sample.sha('91'),
    event_kind_code: eventKind,
    stage_code: stageCode,
    component_binding_code: bindingForRole(role),
    component_executable_sha256: sample.sha('92'),
    runtime_profile_record_digest_sha256: sample.sha('11'),
    identity_bindings_record_digest_sha256: sample.sha('22'),
    d930_journal_profile_record_digest_sha256: validFixtures.records.journal_profile.record_digest_sha256,
    authorization_permit_record_digest_sha256: ['bootstrap', 'recovery'].includes(operationMode) ? sample.sha('93') : null,
    authorization_bundle_seal_record_digest_sha256: operationMode === 'document_import' ? sample.sha('55') : null,
    prepromotion_authorization_record_digest_sha256: null,
    bundle: history.base_selector.terminal_error_code && frozenClassifications.error_bundle_reference_rules.find((entry) => entry.error_code === history.base_selector.terminal_error_code)?.bundle_reference_policy_code === 'forbidden'
      ? null
      : { ...sample.bundle, bundle_sequence: history.bundle_kind_code === 'single_document' ? 2 : 1 },
    target_logical_state: sample.state,
    observed_logical_state: null,
    canonical_effect_code: 'none_verified',
    result_outcome_code: null,
    error_code: null,
    retryability_code: 'never',
    recovery_class_code: 'none',
    rows_delta: null,
    objects_delta: null,
    object_disposition_code: 'none',
    candidate_file_sha256: null,
    candidate_file_seal_record_digest_sha256: null,
    backup_inventory_sha256: null,
    custody_finalization: null,
    integrity_access: null,
    artifact_backup_receipt: null,
    prior_database_backup_receipt: null,
    final_backup_receipt: null,
    recovery: null,
    event_at: atTick(tick),
    record_digest_sha256: sample.sha('94'),
  }
}

function recoveryAuthorityFixture(history) {
  const shared = {
    runtimeProfile: frozenFixture('runtime_profile'),
    identityBindings: frozenFixture('identity_bindings'),
  }
  if (history.bundle_kind_code === 'single_document') {
    return {
      ...shared,
      permit: frozenFixture('post_promotion_completion_permit'),
      permitClaim: frozenFixture('post_promotion_completion_transition_in_progress'),
      sourceTerminal: frozenFixture('journal_document_recovery_required'),
      sourceAuthorization: frozenFixture('document_bundle_seal'),
      sourcePermitHead: null,
      sourcePermitHistory: null,
    }
  }
  if (history.bundle_kind_code === 'principal_bootstrap') {
    return {
      ...shared,
      permit: frozenFixture('post_promotion_bootstrap_completion_permit'),
      permitClaim: frozenFixture('post_promotion_bootstrap_completion_transition_in_progress'),
      sourceTerminal: frozenFixture('journal_bootstrap_backup_recovery_required'),
      sourceAuthorization: frozenFixture('bootstrap_permit'),
      sourcePermitHead: frozenFixture('bootstrap_transition_spent'),
      sourcePermitHistory: [frozenFixture('bootstrap_transition_in_progress'), frozenFixture('bootstrap_transition_spent')],
    }
  }
  fail('RECOVERY_PERMIT_INVALID', `unsupported bundle kind ${history.bundle_kind_code}`)
}

function makeSyntheticRecoveryResolution(authority, recoveryLockProjectionValue, { lockHeadOverrides = {} } = {}) {
  const permitByDigest = new Map([[authority.permit.record_digest_sha256, clone(authority.permit)]])
  if (authority.sourceAuthorization.record_kind_code === 'permit_issuance') permitByDigest.set(authority.sourceAuthorization.record_digest_sha256, clone(authority.sourceAuthorization))
  const permitHeadByDigest = new Map([[authority.permit.record_digest_sha256, clone(authority.permitClaim)]])
  if (authority.sourcePermitHead) permitHeadByDigest.set(authority.sourceAuthorization.record_digest_sha256, clone(authority.sourcePermitHead))
  const sourceHeadByJournal = new Map([[authority.sourceTerminal.journal_code, clone(authority.sourceTerminal)]])
  const sourceAuthorizationByDigest = new Map([[authority.sourceAuthorization.record_digest_sha256, clone(authority.sourceAuthorization)]])
  const runtimeProfileByDigest = new Map([[authority.runtimeProfile.record_digest_sha256, clone(authority.runtimeProfile)]])
  const identityBindingsByDigest = new Map([[authority.identityBindings.record_digest_sha256, clone(authority.identityBindings)]])
  const allFrozenJournalRecords = frozenFixtures.fixtures.map((entry) => entry.value).filter((record) => record?.format === 'jedi-atlas-operation-journal-event')
  const journalByDigest = new Map(allFrozenJournalRecords.map((record) => [record.record_digest_sha256, clone(record)]))
  journalByDigest.set(authority.sourceTerminal.record_digest_sha256, clone(authority.sourceTerminal))
  const sourceHistory = []
  const seenSourceDigests = new Set()
  let sourceCursor = authority.sourceTerminal
  while (sourceCursor) {
    if (seenSourceDigests.has(sourceCursor.record_digest_sha256)) break
    seenSourceDigests.add(sourceCursor.record_digest_sha256)
    sourceHistory.push(clone(sourceCursor))
    sourceCursor = sourceCursor.previous_event_record_digest_sha256 === null ? null : journalByDigest.get(sourceCursor.previous_event_record_digest_sha256)
  }
  sourceHistory.reverse()
  const lockHead = {
    record_kind_code: 'synthetic_protected_recovery_lock_head',
    is_current: true,
    projection: clone(recoveryLockProjectionValue),
    record_digest_sha256: sample.sha('aa'),
    ...clone(lockHeadOverrides),
  }
  lockHead.record_digest_sha256 = recordDigest(lockHead)
  const lockHeadByOperation = new Map([[`${recoveryLockProjectionValue.operation_id}:${recoveryLockProjectionValue.operation_nonce}`, lockHead]])
  const resolver = Object.freeze({
    resolvePermit: (digest) => clone(permitByDigest.get(digest) ?? null),
    resolvePermitHead: (digest) => clone(permitHeadByDigest.get(digest) ?? null),
    resolvePermitHistory: (digest) => digest === authority.sourceAuthorization?.record_digest_sha256 ? clone(authority.sourcePermitHistory) : null,
    resolveRuntimeProfile: (digest) => clone(runtimeProfileByDigest.get(digest) ?? null),
    resolveIdentityBindings: (digest) => clone(identityBindingsByDigest.get(digest) ?? null),
    resolveSourceJournalHead: (journalCode) => clone(sourceHeadByJournal.get(journalCode) ?? null),
    resolveSourceJournalHistory: (journalCode) => journalCode === authority.sourceTerminal.journal_code ? clone(sourceHistory) : null,
    resolveSourceAuthorization: (digest) => clone(sourceAuthorizationByDigest.get(digest) ?? null),
    resolveRecoveryLockHead: (operationId, operationNonce) => clone(lockHeadByOperation.get(`${operationId}:${operationNonce}`) ?? null),
  })
  syntheticRecoveryResolverBrand.add(resolver)
  return resolver
}

function makeRecoveryPayload(history, state, tick) {
  const documentSubject = history.bundle_kind_code === 'single_document'
  const selectedRule = classifications.recovery_decision_rules.find((entry) => entry.decision_rule_code === 'promoted_final_backup_pending')
  const { knowledge, observation } = observationForRule(selectedRule)
  const priorEvent = state.previousEvent
  if (!priorEvent) fail('RECOVERY_CHAIN_REJECTED', 'missing preappend head')
  Object.assign(knowledge, {
    subject_operation_id: state.sourceTerminal.operation_id,
    subject_operation_nonce: state.sourceTerminal.operation_nonce,
    recovery_operation_id: state.authorizationPermit.operation_id,
    recovery_operation_nonce: state.authorizationPermit.operation_nonce,
    recovery_lock_storage_slot_code: state.recoveryLockProjection.storage_handle_slot_code,
    recovery_lock_owner_binding_code: state.recoveryLockProjection.owner_binding_code,
    recovery_lock_acquired_at: state.recoveryLockProjection.acquired_at,
    recovery_lock_expires_at: state.recoveryLockProjection.expires_at,
    scan_started_at: atTick(tick, -600),
    scan_completed_at: atTick(tick, -400),
    known_through_journal_code: priorEvent.journal_code,
    known_through_journal_sequence: priorEvent.event_sequence,
    known_through_journal_head_record_digest_sha256: priorEvent.record_digest_sha256,
    known_through_journal_head_persisted_at: priorEvent.persisted_at,
  })
  knowledge.recovery_lock_projection_sha256 = recoveryLockProjectionSha(knowledge)
  const priorAssessment = state.priorRecoveryEvent?.semantic_assertion.recovery
  return {
    record_kind_code: 'classification_only_recovery_assessment',
    recovery_chain_code: state.recoveryChainCode,
    recovery_attempt_sequence: priorAssessment ? priorAssessment.recovery_attempt_sequence + 1 : 1,
    prior_attempt_terminal_record_digest_sha256: state.priorRecoveryEvent?.record_digest_sha256 ?? null,
    subject_operation_id: state.sourceTerminal.operation_id,
    subject_operation_nonce: state.sourceTerminal.operation_nonce,
    subject_bundle: clone(state.sourceTerminal.bundle),
    subject_artifact: documentSubject ? sample.artifact : null,
    subject_copy_code: documentSubject ? sample.intent.copy_code : null,
    subject_backend_code: documentSubject ? sample.intent.backend_code : null,
    subject_backend_reference: documentSubject ? sample.intent.backend_reference : null,
    source_terminal_journal_code: state.sourceTerminal.journal_code,
    source_terminal_journal_sequence: state.sourceTerminal.event_sequence,
    source_terminal_journal_head_record_digest_sha256: state.sourceTerminal.record_digest_sha256,
    source_terminal_journal_persisted_at: state.sourceTerminal.persisted_at,
    source_terminal_error_code: state.sourceTerminal.error_code,
    knowledge_snapshot: knowledge,
    observation,
    decision_rule_code: selectedRule.decision_rule_code,
    classification_code: selectedRule.classification_code,
    next_step_code: selectedRule.next_step_code,
    classification_outcome_code: selectedRule.classification_outcome_code,
    blocking_reason_codes: clone(selectedRule.blocking_reason_codes),
    action_execution_code: selectedRule.action_execution_code,
  }
}

function makeSemantic(history, milestone, tick, state) {
  const semantic = semanticDefaults(history, milestone, tick)
  const [eventKind, stageCode] = milestone.split('@')
  if (history.base_selector.operation_mode_code === 'recovery') {
    const permit = state.authorizationPermit
    const role = expectedSemanticRole(semantic)
    const runtimeProfile = state.recoveryRuntimeProfile
    semantic.operation_id = permit.operation_id
    semantic.operation_nonce = permit.operation_nonce
    semantic.runtime_profile_record_digest_sha256 = permit.runtime_profile_record_digest_sha256
    semantic.identity_bindings_record_digest_sha256 = permit.identity_bindings_record_digest_sha256
    semantic.authorization_permit_record_digest_sha256 = permit.record_digest_sha256
    semantic.bundle = clone(permit.target_bundle)
    semantic.target_logical_state = clone(permit.verified_canonical_logical_state)
    semantic.component_binding_code = frozenBindingForRole(role)
    semantic.component_executable_sha256 = runtimeProfile.component_releases.find((entry) => entry.runtime_role_code === role)?.executable_sha256 ?? fail('ROLE_RELEASE_MISSING', role)
  }
  if (eventKind === 'operation_started') {
    semantic.rows_delta = zeroRows()
    semantic.objects_delta = { prepared: 0, reused: 0, orphaned: 0 }
  } else if (eventKind === 'custody_object_durable') {
    semantic.objects_delta = { prepared: 1, reused: 0, orphaned: 0 }
    semantic.object_disposition_code = 'durable_referenced'
    semantic.custody_finalization = custodyEvidence()
  } else if (eventKind === 'stage_succeeded' && stageCode === 'custody_backup') {
    semantic.artifact_backup_receipt = backupReference('artifact_copy', atTick(tick, -100))
  } else if (eventKind === 'candidate_committed') {
    semantic.rows_delta = zeroRows(true)
    semantic.candidate_file_sha256 = sample.sha('98')
    semantic.object_disposition_code = 'candidate_only'
  } else if (eventKind === 'candidate_sealed') {
    semantic.candidate_file_sha256 = sample.sha('98')
    semantic.candidate_file_seal_record_digest_sha256 = sample.sha('99')
    semantic.observed_logical_state = sample.state
    semantic.object_disposition_code = 'candidate_only'
  } else if (eventKind === 'stage_succeeded' && stageCode === 'prior_backup') {
    semantic.prior_database_backup_receipt = backupReference('prior_database', atTick(tick, -100))
  } else if (eventKind === 'promotion_started') {
    semantic.candidate_file_sha256 = sample.sha('98')
    semantic.candidate_file_seal_record_digest_sha256 = sample.sha('99')
    semantic.backup_inventory_sha256 = sample.sha('9a')
    semantic.prior_database_backup_receipt = state.priorBackup
    if (history.base_selector.operation_mode_code === 'document_import') semantic.prepromotion_authorization_record_digest_sha256 = sample.sha('9b')
    semantic.object_disposition_code = 'candidate_only'
  } else if (eventKind === 'promotion_observed') {
    semantic.candidate_file_sha256 = sample.sha('98')
    semantic.candidate_file_seal_record_digest_sha256 = sample.sha('99')
    semantic.backup_inventory_sha256 = sample.sha('9a')
    semantic.prior_database_backup_receipt = state.priorBackup
    semantic.observed_logical_state = sample.state
    semantic.canonical_effect_code = 'promoted_verified'
    semantic.object_disposition_code = 'durable_referenced'
  } else if (eventKind === 'stage_succeeded' && stageCode === 'final_backup') {
    semantic.final_backup_receipt = backupReference('final_consistent_set', atTick(tick, -100))
  } else if (eventKind === 'stage_succeeded' && stageCode === 'independent_verification') {
    semantic.integrity_access = integrityEvidence()
  } else if (eventKind === 'stage_succeeded' && stageCode === 'reconciliation') {
    semantic.recovery = makeRecoveryPayload(history, state, tick)
  } else if (eventKind === 'operation_completed') {
    const result = history.base_selector.result_outcome_code
    semantic.result_outcome_code = result
    if (result === 'imported' && history.bundle_kind_code === 'single_document') {
      semantic.rows_delta = { ...zeroRows(), atlas_evidence_bundle_receipts: 1, atlas_retrieval_locations: 1, atlas_artifacts: 1, atlas_retrieval_events: 1, atlas_artifact_custody_events: 1 }
    } else semantic.rows_delta = result === 'imported' ? zeroRows(true) : zeroRows()
    semantic.objects_delta = { prepared: result === 'imported' && history.bundle_kind_code === 'single_document' ? 1 : 0, reused: 0, orphaned: 0 }
    semantic.observed_logical_state = sample.state
    semantic.canonical_effect_code = result === 'imported' ? 'promoted_verified' : 'none_verified'
    semantic.object_disposition_code = result === 'imported' ? 'durable_referenced' : 'none'
    if (history.base_selector.terminal_error_code) applyTerminalError(semantic, history.base_selector.terminal_error_code)
  } else if (eventKind === 'recovery_required') {
    semantic.result_outcome_code = 'recovery_required'
    semantic.rows_delta = zeroRows()
    semantic.objects_delta = { prepared: 0, reused: 0, orphaned: 1 }
    applyTerminalError(semantic, history.base_selector.terminal_error_code)
    if (history.base_selector.terminal_error_code === 'PROMOTION_STATE_AMBIGUOUS') semantic.observed_logical_state = sample.state
  }
  semantic.record_digest_sha256 = recordDigest(semantic)
  return semantic
}

function applyTerminalError(semantic, errorCode) {
  const error = baseErrorSemantics(errorCode)
  semantic.error_code = errorCode
  semantic.retryability_code = error.retryability_code
  semantic.recovery_class_code = error.recovery_class_code
  semantic.canonical_effect_code = error.canonical_effect_code
  semantic.object_disposition_code = error.object_disposition_code
  semantic.observed_logical_state = error.observed_state_policy_code === 'required' ? sample.state : null
}

const journalPayloadKeys = Object.keys(schemas.get('operation-journal-broker-message-v1.schema.json').properties.payload.properties)

function emptyJournalPayload() {
  return Object.fromEntries(journalPayloadKeys.map((key) => [key, null]))
}

function wrapJournalSemantic(semantic, sequence, previousDigest, tick) {
  semantic.record_digest_sha256 = recordDigest(semantic)
  const journalBrokerBindingCode = semantic.identity_bindings_record_digest_sha256 === frozenFixture('identity_bindings').record_digest_sha256 ? 'binding.journal-broker' : 'journal.broker.synthetic'
  const request = {
    format: 'jedi-atlas-operation-journal-broker-message',
    format_version: '1.0.0',
    record_code: `journal.append.request.${semantic.record_code}`,
    message_kind_code: 'append_request',
    operation_id: semantic.operation_id,
    operation_nonce: semantic.operation_nonce,
    request_id: `request.append.${semantic.record_code}`,
    sender_binding_code: semantic.component_binding_code,
    recipient_binding_code: journalBrokerBindingCode,
    runtime_profile_record_digest_sha256: semantic.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: semantic.identity_bindings_record_digest_sha256,
    d930_journal_profile_record_digest_sha256: semantic.d930_journal_profile_record_digest_sha256,
    request_record_digest_sha256: null,
    created_at: atTick(tick, 100),
    payload: {
      ...emptyJournalPayload(),
      journal_code: `journal.${semantic.operation_id}`,
      expected_event_sequence: sequence,
      expected_previous_event_record_digest_sha256: previousDigest,
      semantic_assertion: semantic,
      semantic_assertion_record_digest_sha256: semantic.record_digest_sha256,
    },
    record_digest_sha256: sample.sha('a1'),
  }
  request.record_digest_sha256 = recordDigest(request)
  const event = {
    format: 'jedi-atlas-operation-journal-event',
    format_version: '2.0.0',
    record_code: `journal.event.${semantic.record_code}`,
    journal_code: request.payload.journal_code,
    event_sequence: sequence,
    previous_event_record_digest_sha256: previousDigest,
    semantic_assertion: semantic,
    semantic_assertion_record_digest_sha256: semantic.record_digest_sha256,
    append_request_record_digest_sha256: request.record_digest_sha256,
    persisted_by_binding_code: journalBrokerBindingCode,
    persisted_at: atTick(tick, 200),
    record_digest_sha256: sample.sha('a2'),
  }
  event.record_digest_sha256 = recordDigest(event)
  const response = {
    format: 'jedi-atlas-operation-journal-broker-message',
    format_version: '1.0.0',
    record_code: `journal.append.response.${semantic.record_code}`,
    message_kind_code: 'append_response',
    operation_id: semantic.operation_id,
    operation_nonce: semantic.operation_nonce,
    request_id: request.request_id,
    sender_binding_code: journalBrokerBindingCode,
    recipient_binding_code: semantic.component_binding_code,
    runtime_profile_record_digest_sha256: semantic.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: semantic.identity_bindings_record_digest_sha256,
    d930_journal_profile_record_digest_sha256: semantic.d930_journal_profile_record_digest_sha256,
    request_record_digest_sha256: request.record_digest_sha256,
    created_at: atTick(tick, 300),
    payload: {
      ...emptyJournalPayload(),
      journal_code: request.payload.journal_code,
      expected_event_sequence: sequence,
      expected_previous_event_record_digest_sha256: previousDigest,
      semantic_assertion_record_digest_sha256: semantic.record_digest_sha256,
      persisted_record_code: event.record_code,
      persisted_record_digest_sha256: event.record_digest_sha256,
      persisted_at: event.persisted_at,
      outcome_code: 'persisted',
    },
    record_digest_sha256: sample.sha('a3'),
  }
  response.record_digest_sha256 = recordDigest(response)
  validateJournalBrokerPair(request, response, event)
  return { request, event, response }
}

function makeStageFailed(history, terminalSemantic, tick) {
  const error = baseErrorSemantics(terminalSemantic.error_code)
  const failed = semanticDefaults(history, `stage_failed@${error.stage_code}`, tick)
  failed.canonical_effect_code = terminalSemantic.canonical_effect_code
  failed.object_disposition_code = terminalSemantic.object_disposition_code
  failed.error_code = terminalSemantic.error_code
  failed.retryability_code = terminalSemantic.retryability_code
  failed.recovery_class_code = terminalSemantic.recovery_class_code
  failed.rows_delta = clone(terminalSemantic.rows_delta)
  failed.objects_delta = clone(terminalSemantic.objects_delta)
  failed.candidate_file_sha256 = terminalSemantic.candidate_file_sha256
  failed.backup_inventory_sha256 = terminalSemantic.backup_inventory_sha256
  failed.observed_logical_state = clone(terminalSemantic.observed_logical_state)
  failed.record_digest_sha256 = recordDigest(failed)
  return failed
}

function buildJournalHistory(history, { includeOptionalStageFailure = false, recoveryAttempts = 1, tickStart = 10 } = {}) {
  const concreteHistory = history.bundle_kind_code === 'any' ? { ...history, bundle_kind_code: 'single_document' } : history
  const events = []
  const exchanges = []
  const authority = history.base_selector.operation_mode_code === 'recovery' ? recoveryAuthorityFixture(concreteHistory) : null
  const recoveryOperationId = authority?.permit.operation_id ?? `operation.${history.history_code}`
  const recoveryOperationNonce = authority?.permit.operation_nonce ?? sample.sha('91')
  const state = {
    priorBackup: null,
    previousEvent: null,
    priorRecoveryEvent: null,
    recoveryChainCode: `recovery.chain.${history.history_code}`,
    sourceTerminal: authority?.sourceTerminal ?? null,
    authorizationPermit: authority?.permit ?? null,
    recoveryRuntimeProfile: authority?.runtimeProfile ?? null,
    recoveryLockProjection: {
      storage_handle_slot_code: 'permit_control_store',
      operation_id: recoveryOperationId,
      operation_nonce: recoveryOperationNonce,
      owner_binding_code: authority ? 'binding.launcher' : 'trusted.launcher.synthetic',
      acquired_at: atTick(tickStart, -900),
      expires_at: atTick(tickStart + 100),
      state_code: 'held',
    },
  }
  state.recoveryResolution = authority ? makeSyntheticRecoveryResolution(authority, state.recoveryLockProjection) : null
  let previousDigest = null
  let tick = tickStart
  let sequence = 1
  for (let index = 0; index < history.milestones.length; index += 1) {
    const milestone = history.milestones[index]
    const semantic = makeSemantic(concreteHistory, milestone, tick, state)
    const terminal = ['operation_completed', 'recovery_required'].includes(semantic.event_kind_code)
    if (includeOptionalStageFailure && history.optional_penultimate_stage_failed && terminal) {
      const failed = makeStageFailed(concreteHistory, semantic, tick)
      const failedExchange = wrapJournalSemantic(failed, sequence, previousDigest, tick)
      exchanges.push(failedExchange)
      events.push(failedExchange.event)
      previousDigest = failedExchange.event.record_digest_sha256
      state.previousEvent = failedExchange.event
      sequence += 1
      tick += 1
      semantic.event_at = atTick(tick)
      semantic.record_digest_sha256 = recordDigest(semantic)
    }
    const exchange = wrapJournalSemantic(semantic, sequence, previousDigest, tick)
    exchanges.push(exchange)
    events.push(exchange.event)
    previousDigest = exchange.event.record_digest_sha256
    state.previousEvent = exchange.event
    if (semantic.prior_database_backup_receipt) state.priorBackup = semantic.prior_database_backup_receipt
    if (semantic.recovery) {
      state.priorRecoveryEvent = exchange.event
      for (let attempt = 2; attempt <= recoveryAttempts; attempt += 1) {
        sequence += 1
        tick += 1
        const retrySemantic = makeSemantic(concreteHistory, milestone, tick, state)
        const retryExchange = wrapJournalSemantic(retrySemantic, sequence, previousDigest, tick)
        exchanges.push(retryExchange)
        events.push(retryExchange.event)
        previousDigest = retryExchange.event.record_digest_sha256
        state.previousEvent = retryExchange.event
        state.priorRecoveryEvent = retryExchange.event
      }
    }
    sequence += 1
    tick += 1
  }
  return {
    events,
    exchanges,
    resolutionContext: {
      recovery_resolution: state.recoveryResolution,
    },
  }
}

function validateRecoveryChain(events, context) {
  const recoveryEvents = events.filter((event) => event.semantic_assertion.recovery !== null)
  if (recoveryEvents.length === 0) return
  for (const event of recoveryEvents) {
    if (`${event.semantic_assertion.event_kind_code}@${event.semantic_assertion.stage_code}` !== 'stage_succeeded@reconciliation') fail('RECOVERY_CHAIN_REJECTED', 'milestone')
    const payload = event.semantic_assertion.recovery
    const selected = evaluateRecovery(payload.knowledge_snapshot, payload.observation)
    if (selected.decision_rule_code !== payload.decision_rule_code) fail('RECOVERY_DECISION_MISMATCH')
    if (payload.action_execution_code !== 'none_classification_only') fail('RECOVERY_ACTION_NOT_AUTHORIZED')
  }
  if (!syntheticRecoveryResolverBrand.has(context.recovery_resolution)) fail('RECOVERY_ACTION_NOT_AUTHORIZED')
  validateRecoveryAttemptChain(recoveryEvents, events)
}

function validateHistory(history, events, resolutionContext = {}) {
  const registered = [...classifications.journal_history_rules, ...classifications.journal_failure_history_rules].filter((entry) => entry.history_code === history.history_code)
  if (registered.length !== 1 || canonicalize(registered[0]) !== canonicalize(history)) fail('JOURNAL_HISTORY_REJECTED', 'unregistered or altered rule')
  const expectedMilestones = history.milestones
  const actualMilestones = events.map((event) => `${event.semantic_assertion.event_kind_code}@${event.semantic_assertion.stage_code}`)
    .filter((milestone, index, all) => milestone !== 'stage_succeeded@reconciliation' || index === 0 || all[index - 1] !== milestone)
  let normalizedActual = actualMilestones
  if (history.optional_penultimate_stage_failed && actualMilestones.at(-2)?.startsWith('stage_failed@')) normalizedActual = actualMilestones.toSpliced(-2, 1)
  if (canonicalize(normalizedActual) !== canonicalize(expectedMilestones)) fail('JOURNAL_HISTORY_REJECTED', history.history_code)
  validateJournalChain(events, { bundle_kind_code: history.bundle_kind_code === 'any' ? 'single_document' : history.bundle_kind_code, permit_kind_code: history.permit_kind_code, ...resolutionContext })
  validateRecoveryChain(events, { bundle_kind_code: history.bundle_kind_code === 'any' ? 'single_document' : history.bundle_kind_code, ...resolutionContext })
  const terminal = events.at(-1).semantic_assertion
  const penultimate = events.at(-2)?.semantic_assertion
  if (penultimate?.event_kind_code === 'stage_failed') {
    for (const field of ['error_code', 'canonical_effect_code', 'object_disposition_code', 'retryability_code', 'recovery_class_code', 'rows_delta', 'objects_delta', 'candidate_file_sha256', 'backup_inventory_sha256', 'observed_logical_state']) if (canonicalize(penultimate[field]) !== canonicalize(terminal[field])) fail('JOURNAL_HISTORY_REJECTED', `stage failure ${field}`)
  }
  if (terminal.operation_mode_code !== history.base_selector.operation_mode_code || terminal.result_outcome_code !== history.base_selector.result_outcome_code || terminal.error_code !== (history.base_selector.terminal_error_code ?? null)) fail('JOURNAL_HISTORY_REJECTED', 'terminal')
  const milestones = new Map(events.map((event, index) => [`${event.semantic_assertion.event_kind_code}@${event.semantic_assertion.stage_code}`, index]))
  const candidateIndex = milestones.get('candidate_committed@database_transaction')
  if (candidateIndex !== undefined && history.bundle_kind_code === 'single_document') {
    for (const required of classifications.candidate_promotion_rules.by_bundle_kind.find((entry) => entry.bundle_kind_code === 'single_document').candidate_write_requires_prior_milestones) if (!milestones.has(required) || milestones.get(required) >= candidateIndex) fail('CANDIDATE_GATE_REJECTED', required)
  }
  if (history.bundle_kind_code === 'principal_bootstrap' && events.some((event) => event.semantic_assertion.custody_finalization || event.semantic_assertion.integrity_access || event.semantic_assertion.artifact_backup_receipt)) fail('BOOTSTRAP_CUSTODY_REJECTED')
  const promotion = events.find((event) => event.semantic_assertion.event_kind_code === 'promotion_started')?.semantic_assertion
  if (promotion) for (const field of classifications.candidate_promotion_rules.promotion_requires) if (promotion[field] === null) fail('PROMOTION_GATE_REJECTED', field)
  if (promotion && history.base_selector.operation_mode_code === 'document_import') for (const field of classifications.candidate_promotion_rules.document_promotion_started_requires) if (promotion[field] === null) fail('PROMOTION_GATE_REJECTED', field)
  const candidateValues = events.map((event) => event.semantic_assertion.candidate_file_sha256).filter(Boolean)
  if (candidateValues.length && new Set(candidateValues).size !== 1) fail('JOURNAL_CONTEXT_DRIFT', 'candidate')
  const priorBackups = events.map((event) => event.semantic_assertion.prior_database_backup_receipt).filter(Boolean)
  if (priorBackups.length && new Set(priorBackups.map(canonicalize)).size !== 1) fail('JOURNAL_CONTEXT_DRIFT', 'prior backup')
  const promotionBackups = events.map((event) => event.semantic_assertion).filter((semantic) => ['promotion_started', 'promotion_observed'].includes(semantic.event_kind_code)).map((semantic) => semantic.backup_inventory_sha256)
  if (promotionBackups.length && (promotionBackups.some((value) => value === null) || new Set(promotionBackups).size !== 1)) fail('JOURNAL_CONTEXT_DRIFT', 'backup inventory')
  const sealedState = events.find((event) => event.semantic_assertion.event_kind_code === 'candidate_sealed')?.semantic_assertion.observed_logical_state
  const promotedState = events.find((event) => event.semantic_assertion.event_kind_code === 'promotion_observed')?.semantic_assertion.observed_logical_state
  const effectState = promotedState ?? terminal.observed_logical_state
  if (sealedState && !effectState) fail('JOURNAL_CONTEXT_DRIFT', 'missing effect state')
  if (sealedState && effectState && canonicalize(sealedState) !== canonicalize(effectState)) fail('JOURNAL_CONTEXT_DRIFT', 'candidate effect state')
  if (sealedState && promotedState && canonicalize(sealedState) !== canonicalize(promotedState)) fail('JOURNAL_CONTEXT_DRIFT', 'candidate seal state')
  if (sealedState && terminal.observed_logical_state && canonicalize(sealedState) !== canonicalize(terminal.observed_logical_state)) fail('JOURNAL_CONTEXT_DRIFT', 'terminal observed state')
  const finalBackupExpected = classifications.candidate_promotion_rules.completion_requirements.find((entry) => entry.result_outcome_code === terminal.result_outcome_code && (!entry.permit_kind_code || entry.permit_kind_code === history.permit_kind_code))?.final_backup_receipt
  if (finalBackupExpected === true && !events.some((event) => event.semantic_assertion.final_backup_receipt)) fail('COMPLETION_GATE_REJECTED', 'final backup')
  if (finalBackupExpected === false && events.some((event) => event.semantic_assertion.final_backup_receipt)) fail('COMPLETION_GATE_REJECTED', 'unexpected final backup')
  return true
}

function assertJournalHistories() {
  const histories = [...classifications.journal_history_rules, ...classifications.journal_failure_history_rules]
  assert.equal(histories.length, 13)
  for (const history of histories) {
    const built = buildJournalHistory(history)
    try { validateHistory(history, built.events, built.resolutionContext) } catch (error) { throw new Error(`history ${history.history_code}: ${error.message}`) }
    const missing = built.events.toSpliced(Math.min(1, built.events.length - 1), 1)
    assertThrowsCode(() => validateHistory(history, missing, built.resolutionContext), 'JOURNAL_HISTORY_REJECTED')
    if (history.optional_penultimate_stage_failed) {
      const optional = buildJournalHistory(history, { includeOptionalStageFailure: true })
      validateHistory(history, optional.events, optional.resolutionContext)
    }
    if (history.backup_resolution_required) assertThrowsCode(() => assertOperationalHistoryReachable(built.events), 'D9_5_RECEIPT_UNAVAILABLE')
    else assertOperationalHistoryReachable(built.events)
  }
  const originFixture = buildJournalHistory(classifications.journal_history_rules.find((entry) => entry.history_code === 'accepted_bootstrap_no_op')).events[0].semantic_assertion
  const prefixForgedOrigin = clone(originFixture)
  prefixForgedOrigin.component_binding_code = `${originFixture.component_binding_code}.forged`
  prefixForgedOrigin.record_digest_sha256 = recordDigest(prefixForgedOrigin)
  assertThrowsCode(() => validateSemantic(prefixForgedOrigin, { bundle_kind_code: 'principal_bootstrap', permit_kind_code: 'none' }), 'D90_ORIGIN_REJECTED')
}

function assertOperationalHistoryReachable(events) {
  for (const event of events) {
    const semantic = event.semantic_assertion
    if (semantic.artifact_backup_receipt || semantic.prior_database_backup_receipt || semantic.final_backup_receipt) fail('D9_5_RECEIPT_UNAVAILABLE')
  }
}

function makeSupportingBrokerPair(supportingRecord, tickOffset = 0, journalCode = 'journal.operation.synthetic.001') {
  const producedAt = supportingRecordProducedAt(supportingRecord)
  const persistedAt = new Date(Date.parse(producedAt) + 10 + tickOffset).toISOString()
  const responseAt = new Date(Date.parse(persistedAt) + 10).toISOString()
  const kind = supportingRecordKind(supportingRecord)
  const producer = supportingRecordProducer(supportingRecord)
  const request = {
    format: 'jedi-atlas-operation-journal-broker-message',
    format_version: '1.0.0',
    record_code: `journal.support.request.${supportingRecord.record_code}`,
    message_kind_code: 'persist_supporting_request',
    operation_id: supportingRecord.operation_id,
    operation_nonce: supportingRecord.operation_nonce,
    request_id: `request.support.${supportingRecord.record_code}`,
    sender_binding_code: producer,
    recipient_binding_code: 'journal.broker.synthetic',
    runtime_profile_record_digest_sha256: supportingRecord.runtime_profile_record_digest_sha256,
    identity_bindings_record_digest_sha256: supportingRecord.identity_bindings_record_digest_sha256,
    d930_journal_profile_record_digest_sha256: validFixtures.records.journal_profile.record_digest_sha256,
    request_record_digest_sha256: null,
    created_at: persistedAt,
    payload: {
      ...emptyJournalPayload(),
      journal_code: journalCode,
      supporting_record_kind_code: kind,
      supporting_record: supportingRecord,
      supporting_record_digest_sha256: supportingRecord.record_digest_sha256,
    },
    record_digest_sha256: sample.sha('a4'),
  }
  request.record_digest_sha256 = recordDigest(request)
  const response = {
    ...clone(request),
    record_code: `journal.support.response.${supportingRecord.record_code}`,
    message_kind_code: 'persist_supporting_response',
    sender_binding_code: 'journal.broker.synthetic',
    recipient_binding_code: producer,
    request_record_digest_sha256: request.record_digest_sha256,
    created_at: responseAt,
    payload: {
      ...emptyJournalPayload(),
      journal_code: request.payload.journal_code,
      supporting_record_kind_code: kind,
      supporting_record_digest_sha256: supportingRecord.record_digest_sha256,
      persisted_record_code: supportingRecord.record_code,
      persisted_record_digest_sha256: supportingRecord.record_digest_sha256,
      persisted_at: persistedAt,
      outcome_code: 'persisted',
    },
  }
  response.record_digest_sha256 = recordDigest(response)
  return { request, response }
}

function assertBrokerSurfaces() {
  const adapter = clone(validFixtures.records.adapter_publish_response)
  validateAdapterMessage(adapter)
  const supporting = makeSupportingBrokerPair(adapter)
  validateSupportingBrokerPair(supporting.request, supporting.response, adapter)
  const supportingState = makeProtectedBrokerState()
  assert.equal(acceptSupportingBrokerExchange(supporting.request, supporting.response, adapter, supportingState), true)
  assert.equal(acceptSupportingBrokerExchange(supporting.request, supporting.response, adapter, supportingState), false)
  const rewrittenSupportingReplay = clone(supporting.response)
  rewrittenSupportingReplay.created_at = new Date(Date.parse(rewrittenSupportingReplay.created_at) + 1).toISOString()
  rewrittenSupportingReplay.record_digest_sha256 = recordDigest(rewrittenSupportingReplay)
  assertThrowsCode(() => acceptSupportingBrokerExchange(supporting.request, rewrittenSupportingReplay, adapter, supportingState), 'BROKER_REPLAY_CONFLICT_REJECTED')
  for (const base of [supporting.response, buildJournalHistory(classifications.journal_history_rules.find((entry) => entry.history_code === 'accepted_bootstrap_no_op')).exchanges[0].response]) {
    for (const outcome of classifications.journal_broker_rules.failure_outcome_codes) {
      const failure = clone(base)
      failure.payload = emptyJournalPayload()
      failure.payload.journal_code = base.payload.journal_code
      failure.payload.outcome_code = outcome
      const errorRules = base.message_kind_code === 'persist_supporting_response'
        ? classifications.journal_broker_rules.supporting_failure_error_rules
        : classifications.journal_broker_rules.append_failure_error_rules
      failure.payload.error_code = errorRules.find((entry) => entry.outcome_code === outcome).error_code
      failure.record_digest_sha256 = recordDigest(failure)
      validateJournalBrokerMessage(failure)
    }
  }
  const wrongActor = clone(supporting.request)
  wrongActor.sender_binding_code = 'bundle.importer.synthetic'
  wrongActor.record_digest_sha256 = recordDigest(wrongActor)
  assertThrowsCode(() => validateSupportingBrokerPair(wrongActor, supporting.response, adapter), 'BROKER_ROLE_REJECTED')
  const extra = clone(supporting.request)
  extra.payload.expected_event_sequence = 1
  extra.record_digest_sha256 = recordDigest(extra)
  assertThrowsCode(() => validateSupportingBrokerPair(extra, supporting.response, adapter), 'BROKER_MATRIX_REJECTED')
  const supportingJournalSwap = clone(supporting.response)
  supportingJournalSwap.payload.journal_code = 'journal.substituted'
  supportingJournalSwap.record_digest_sha256 = recordDigest(supportingJournalSwap)
  assertThrowsCode(() => validateSupportingBrokerPair(supporting.request, supportingJournalSwap, adapter), 'BROKER_ACK_SUBSTITUTION_REJECTED')
  const supportingDigestSwap = clone(supporting.response)
  supportingDigestSwap.payload.supporting_record_digest_sha256 = sample.sha('ea')
  supportingDigestSwap.record_digest_sha256 = recordDigest(supportingDigestSwap)
  assertThrowsCode(() => validateSupportingBrokerPair(supporting.request, supportingDigestSwap, adapter), 'BROKER_SUPPORTING_RECORD_MISMATCH')
  for (const field of ['runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256']) {
    const request = clone(supporting.request)
    const response = clone(supporting.response)
    request[field] = sample.sha('e9')
    response[field] = request[field]
    request.record_digest_sha256 = recordDigest(request)
    response.request_record_digest_sha256 = request.record_digest_sha256
    response.record_digest_sha256 = recordDigest(response)
    assertThrowsCode(() => validateSupportingBrokerPair(request, response, adapter), 'BROKER_SUPPORTING_RECORD_MISMATCH')
  }

  const history = buildJournalHistory(classifications.journal_history_rules.find((entry) => entry.history_code === 'accepted_bootstrap_no_op'))
  const first = history.exchanges[0]
  validateJournalBrokerPair(first.request, first.response, first.event)
  const protectedState = makeProtectedJournalState()
  for (const exchange of history.exchanges) acceptJournalAppend(exchange.request, exchange.response, exchange.event, { bundle_kind_code: 'principal_bootstrap', permit_kind_code: 'none' }, protectedState)
  assert.equal(acceptJournalAppend(first.request, first.response, first.event, { bundle_kind_code: 'principal_bootstrap', permit_kind_code: 'none' }, protectedState), false)
  const existingExactResponse = clone(first.response)
  existingExactResponse.created_at = new Date(Date.parse(existingExactResponse.created_at) + 1).toISOString()
  existingExactResponse.record_digest_sha256 = recordDigest(existingExactResponse)
  assertThrowsCode(() => acceptJournalAppend(first.request, existingExactResponse, first.event, { bundle_kind_code: 'principal_bootstrap', permit_kind_code: 'none' }, protectedState), 'JOURNAL_REPLAY_CONFLICT_REJECTED')
  const conflictingRequest = clone(first.request)
  conflictingRequest.created_at = new Date(Date.parse(conflictingRequest.created_at) + 1).toISOString()
  conflictingRequest.record_digest_sha256 = recordDigest(conflictingRequest)
  const conflictingEvent = clone(first.event)
  conflictingEvent.append_request_record_digest_sha256 = conflictingRequest.record_digest_sha256
  conflictingEvent.record_digest_sha256 = recordDigest(conflictingEvent)
  const conflictingResponse = clone(first.response)
  conflictingResponse.request_record_digest_sha256 = conflictingRequest.record_digest_sha256
  conflictingResponse.payload.persisted_record_digest_sha256 = conflictingEvent.record_digest_sha256
  conflictingResponse.record_digest_sha256 = recordDigest(conflictingResponse)
  assertThrowsCode(() => acceptJournalAppend(conflictingRequest, conflictingResponse, conflictingEvent, { bundle_kind_code: 'principal_bootstrap', permit_kind_code: 'none' }, protectedState), 'JOURNAL_REPLAY_CONFLICT_REJECTED')
  const forkRequest = clone(first.request)
  forkRequest.payload.journal_code = `${first.request.payload.journal_code}.fork`
  forkRequest.record_code = `${forkRequest.record_code}.fork`
  forkRequest.request_id = `${forkRequest.request_id}.fork`
  forkRequest.record_digest_sha256 = recordDigest(forkRequest)
  const forkEvent = clone(first.event)
  forkEvent.record_code = `${forkEvent.record_code}.fork`
  forkEvent.journal_code = forkRequest.payload.journal_code
  forkEvent.append_request_record_digest_sha256 = forkRequest.record_digest_sha256
  forkEvent.record_digest_sha256 = recordDigest(forkEvent)
  const forkResponse = clone(first.response)
  forkResponse.record_code = `${forkResponse.record_code}.fork`
  forkResponse.request_id = forkRequest.request_id
  forkResponse.request_record_digest_sha256 = forkRequest.record_digest_sha256
  forkResponse.payload.journal_code = forkRequest.payload.journal_code
  forkResponse.payload.persisted_record_code = forkEvent.record_code
  forkResponse.payload.persisted_record_digest_sha256 = forkEvent.record_digest_sha256
  forkResponse.record_digest_sha256 = recordDigest(forkResponse)
  assertThrowsCode(() => acceptJournalAppend(forkRequest, forkResponse, forkEvent, { bundle_kind_code: 'principal_bootstrap', permit_kind_code: 'none' }, protectedState), 'JOURNAL_OPERATION_FORK_REJECTED')
  const documentHistory = buildJournalHistory(classifications.journal_history_rules.find((entry) => entry.history_code === 'document_imported'))
  const documentState = makeProtectedJournalState()
  acceptJournalAppend(documentHistory.exchanges[0].request, documentHistory.exchanges[0].response, documentHistory.exchanges[0].event, { bundle_kind_code: 'single_document', permit_kind_code: 'none' }, documentState)
  assertThrowsCode(() => assertRegisteredJournalHistoryPrefix(documentHistory.exchanges[0].event, documentHistory.exchanges[3].event, { bundle_kind_code: 'single_document' }, documentState), 'JOURNAL_HISTORY_PREFIX_REJECTED')
  acceptJournalAppend(documentHistory.exchanges[1].request, documentHistory.exchanges[1].response, documentHistory.exchanges[1].event, { bundle_kind_code: 'single_document', permit_kind_code: 'none' }, documentState)
  assert.equal(acceptJournalAppend(documentHistory.exchanges[1].request, documentHistory.exchanges[1].response, documentHistory.exchanges[1].event, { bundle_kind_code: 'single_document', permit_kind_code: 'none' }, documentState), false)
  const recoveryRule = classifications.journal_history_rules.find((entry) => entry.history_code === 'post_promotion_completion_document')
  const recoveryHistory = buildJournalHistory(recoveryRule, { recoveryAttempts: 2 })
  const recoveryExchanges = recoveryHistory.exchanges.filter((exchange) => exchange.event.semantic_assertion.recovery)
  const recoveryPrefixState = makeProtectedJournalState()
  for (const exchange of recoveryHistory.exchanges.slice(0, 3)) acceptJournalAppend(exchange.request, exchange.response, exchange.event, { bundle_kind_code: 'single_document', permit_kind_code: 'post_promotion_completion', recovery_resolution: recoveryHistory.resolutionContext.recovery_resolution, persisted_at: exchange.event.persisted_at, persisted_by_binding_code: exchange.event.persisted_by_binding_code }, recoveryPrefixState)
  const forgedRetry = clone(recoveryExchanges[1])
  const recoveryRoot = recoveryHistory.exchanges[0]
  const forgedSemantic = forgedRetry.event.semantic_assertion
  forgedSemantic.recovery.knowledge_snapshot.known_through_journal_code = recoveryRoot.event.journal_code
  forgedSemantic.recovery.knowledge_snapshot.known_through_journal_sequence = recoveryRoot.event.event_sequence
  forgedSemantic.recovery.knowledge_snapshot.known_through_journal_head_record_digest_sha256 = recoveryRoot.event.record_digest_sha256
  forgedSemantic.recovery.knowledge_snapshot.known_through_journal_head_persisted_at = recoveryRoot.event.persisted_at
  forgedSemantic.record_digest_sha256 = recordDigest(forgedSemantic)
  forgedRetry.request.payload.expected_event_sequence = 2
  forgedRetry.request.payload.expected_previous_event_record_digest_sha256 = recoveryRoot.event.record_digest_sha256
  forgedRetry.request.payload.semantic_assertion = clone(forgedSemantic)
  forgedRetry.request.payload.semantic_assertion_record_digest_sha256 = forgedSemantic.record_digest_sha256
  forgedRetry.request.record_digest_sha256 = recordDigest(forgedRetry.request)
  forgedRetry.event.event_sequence = 2
  forgedRetry.event.previous_event_record_digest_sha256 = recoveryRoot.event.record_digest_sha256
  forgedRetry.event.semantic_assertion = clone(forgedSemantic)
  forgedRetry.event.semantic_assertion_record_digest_sha256 = forgedSemantic.record_digest_sha256
  forgedRetry.event.append_request_record_digest_sha256 = forgedRetry.request.record_digest_sha256
  forgedRetry.event.record_digest_sha256 = recordDigest(forgedRetry.event)
  forgedRetry.response.request_record_digest_sha256 = forgedRetry.request.record_digest_sha256
  forgedRetry.response.payload.expected_event_sequence = 2
  forgedRetry.response.payload.expected_previous_event_record_digest_sha256 = recoveryRoot.event.record_digest_sha256
  forgedRetry.response.payload.semantic_assertion_record_digest_sha256 = forgedSemantic.record_digest_sha256
  forgedRetry.response.payload.persisted_record_code = forgedRetry.event.record_code
  forgedRetry.response.payload.persisted_record_digest_sha256 = forgedRetry.event.record_digest_sha256
  forgedRetry.response.payload.persisted_at = forgedRetry.event.persisted_at
  forgedRetry.response.record_digest_sha256 = recordDigest(forgedRetry.response)
  const forgedRecoveryState = makeProtectedJournalState()
  const recoveryAppendContext = { bundle_kind_code: 'single_document', permit_kind_code: recoveryRule.permit_kind_code, recovery_resolution: recoveryHistory.resolutionContext.recovery_resolution }
  acceptJournalAppend(recoveryRoot.request, recoveryRoot.response, recoveryRoot.event, recoveryAppendContext, forgedRecoveryState)
  assertThrowsCode(() => acceptJournalAppend(forgedRetry.request, forgedRetry.response, forgedRetry.event, recoveryAppendContext, forgedRecoveryState), 'JOURNAL_RECOVERY_CHAIN_REJECTED')
  const roleSwap = clone(first.request)
  roleSwap.sender_binding_code = 'custody.adapter.synthetic'
  roleSwap.record_digest_sha256 = recordDigest(roleSwap)
  const roleSwapResponse = clone(first.response)
  roleSwapResponse.recipient_binding_code = roleSwap.sender_binding_code
  roleSwapResponse.request_record_digest_sha256 = roleSwap.record_digest_sha256
  roleSwapResponse.record_digest_sha256 = recordDigest(roleSwapResponse)
  assertThrowsCode(() => validateJournalBrokerPair(roleSwap, roleSwapResponse, first.event), 'BROKER_SEMANTIC_ORIGIN_REJECTED')
  const headSwap = clone(first.event)
  headSwap.event_sequence = 2
  headSwap.record_digest_sha256 = recordDigest(headSwap)
  assertThrowsCode(() => validateJournalBrokerPair(first.request, first.response, headSwap), 'BROKER_EVENT_MISMATCH')
  for (const field of ['operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_journal_profile_record_digest_sha256']) {
    const request = clone(first.request)
    const response = clone(first.response)
    request[field] = field === 'operation_nonce' ? sample.sha('ee') : field.endsWith('_sha256') ? sample.sha('ee') : 'operation.substituted'
    response[field] = request[field]
    request.record_digest_sha256 = recordDigest(request)
    response.request_record_digest_sha256 = request.record_digest_sha256
    response.record_digest_sha256 = recordDigest(response)
    assertThrowsCode(() => validateJournalBrokerPair(request, response, first.event), field === 'd930_journal_profile_record_digest_sha256' ? 'BROKER_SEMANTIC_CONTEXT_REJECTED' : 'BROKER_SEMANTIC_CONTEXT_REJECTED')
  }
  for (const field of ['journal_code', 'expected_event_sequence', 'expected_previous_event_record_digest_sha256', 'semantic_assertion_record_digest_sha256']) {
    const response = clone(first.response)
    if (field === 'expected_event_sequence') response.payload[field] += 1
    else if (response.payload[field] === null) response.payload[field] = sample.sha('ed')
    else response.payload[field] = field === 'journal_code' ? 'journal.substituted' : sample.sha('ed')
    response.record_digest_sha256 = recordDigest(response)
    assertThrowsCode(() => validateJournalBrokerPair(first.request, response, first.event), 'BROKER_ACK_SUBSTITUTION_REJECTED')
  }
}

function matrixFingerprintPayloads(source = classifications) {
  return {
    adapter_request_stream_rules_sha256: canonicalSha256({
      adapter_request_stream_rules: source.adapter_request_stream_rules,
    }),
    custody_message_rules_sha256: canonicalSha256({
      custody_message_rules: source.custody_message_rules,
      custody_message_role_rule: source.custody_message_role_rule,
      custody_message_pair_rules: source.custody_message_pair_rules,
      capability_leaf_rules: source.capability_leaf_rules,
      primary_receipt_rules: source.primary_receipt_rules,
      receipt_broker_rules: source.receipt_broker_rules,
      journal_broker_rules: source.journal_broker_rules,
    }),
    custody_state_transition_rules_sha256: canonicalSha256({
      custody_state_transition_rules: source.custody_state_transition_rules,
      custody_terminal_rules: source.custody_terminal_rules,
    }),
    journal_rules_sha256: canonicalSha256({
      journal_composition_policy: source.journal_composition_policy,
      journal_reference_rules: source.journal_reference_rules,
      journal_history_rules: source.journal_history_rules,
      journal_failure_history_rules: source.journal_failure_history_rules,
      candidate_promotion_rules: source.candidate_promotion_rules,
      backup_reference_rules: source.backup_reference_rules,
    }),
    recovery_decision_rules_sha256: canonicalSha256({
      recovery_observation_consistency_rules: source.recovery_observation_consistency_rules,
      recovery_fail_closed_guards: source.recovery_fail_closed_guards,
      recovery_decision_rules: source.recovery_decision_rules,
      recovery_action_outcome_rules: source.recovery_action_outcome_rules,
      crash_boundary_rules: source.crash_boundary_rules,
      orphan_precedence: source.orphan_precedence,
      recovery_record_rules: source.recovery_record_rules,
    }),
  }
}

function validateFrozenCompositionCompatibility(source = classifications, semanticSchema = schemas.get('operation-journal-semantic-v1.schema.json')) {
  const policy = source.journal_composition_policy
  const requiredInheritedSections = [
    'journal_stage_origin_rules',
    'journal_event_origin_rules',
    'journal_event_rules',
    'journal_authorization_rules',
    'runtime_role_binding_rules',
    'permit_scope_execution_rules',
    'result_rules',
    'outcome_rules',
    'result_error_rules',
    'error_rules',
    'recovered_result_authorization_rules',
    'post_promotion_source_error_rules',
    'error_effect_rules',
    'error_bundle_reference_rules',
  ]
  if (canonicalize(policy.inherited_sections) !== canonicalize(requiredInheritedSections)) fail('D90_COMPOSITION_REJECTED', 'inherited sections')
  for (const section of policy.inherited_sections) if (!Object.hasOwn(frozenClassifications, section)) fail('D90_COMPOSITION_REJECTED', `missing frozen section ${section}`)
  if (canonicalize(policy.superseded_sections) !== canonicalize(['journal_history_rules'])) fail('D90_COMPOSITION_REJECTED', 'superseded sections')
  for (const field of ['extension_event_kinds', 'semantic_origin_extension', 'extension_event_rules']) if (policy[field].length !== 0) fail('D90_COMPOSITION_REJECTED', field)
  if (canonicalize(semanticSchema.properties.event_kind_code.enum) !== canonicalize(frozenClassifications.journal_event_kinds)) fail('D90_COMPOSITION_REJECTED', 'event kinds')

  const histories = [...source.journal_history_rules, ...source.journal_failure_history_rules]
  const historyCodes = histories.map((history) => history.history_code)
  if (new Set(historyCodes).size !== historyCodes.length) fail('D90_COMPOSITION_REJECTED', 'duplicate history code')
  const selectors = histories.map((history) => canonicalize({
    base_selector: history.base_selector,
    bundle_kind_code: history.bundle_kind_code,
    permit_kind_code: history.permit_kind_code,
  }))
  if (new Set(selectors).size !== selectors.length) fail('D90_COMPOSITION_REJECTED', 'duplicate history selector')
  for (const history of histories) {
    if (history.milestones[0] !== 'operation_started@startup') fail('D90_COMPOSITION_REJECTED', `${history.history_code} root`)
    const terminal = history.milestones.at(-1)
    const expectedTerminalKind = history.base_selector.result_outcome_code === 'recovery_required' ? 'recovery_required' : 'operation_completed'
    if (!terminal.startsWith(`${expectedTerminalKind}@`)) fail('D90_COMPOSITION_REJECTED', `${history.history_code} terminal`)
    for (const milestone of history.milestones) {
      const [eventKind, stageCode, extra] = milestone.split('@')
      if (extra !== undefined || !frozenClassifications.journal_event_kinds.includes(eventKind) || !frozenClassifications.stages.includes(stageCode)) fail('D90_COMPOSITION_REJECTED', `${history.history_code}/${milestone}`)
    }
  }
  if (source.handle_scope_compatibility.storage_handle_slot_code !== 'operation_journal'
    || source.handle_scope_compatibility.storage_holder_role_code !== 'journal_broker'
    || source.handle_scope_compatibility.storage_access_code !== 'append_intended'
    || source.handle_scope_compatibility.additional_storage_handle_slots.length !== 0
    || source.handle_scope_compatibility.additional_handle_grants.length !== 0) fail('D90_COMPOSITION_REJECTED', 'handle widening')
}

function assertClassificationRegistry() {
  validateFrozenCompositionCompatibility()
  assert.deepEqual(classifications.matrix_fingerprints, matrixFingerprintPayloads())
  assert.equal(recordDigest(classifications), expected.classification)
  assert.equal(classifications.handle_scope_compatibility.storage_handle_slot_code, 'operation_journal')
  assert.equal(classifications.handle_scope_compatibility.storage_holder_role_code, 'journal_broker')
  assert.deepEqual(classifications.handle_scope_compatibility.additional_storage_handle_slots, [])
  assert.deepEqual(classifications.handle_scope_compatibility.additional_handle_grants, [])
  assert.equal(classifications.custody_message_rules.length, 6)
  assert.deepEqual(classifications.custody_message_pair_rules.map((entry) => entry.operation_code).sort(), classifications.custody_message_rules.map((entry) => entry.operation_code).sort())
  assert.equal(classifications.adapter_request_stream_rules.length, 2)
  const streamOperations = classifications.adapter_request_stream_rules.flatMap((entry) => entry.operation_codes)
  assert.deepEqual(streamOperations.slice().sort(), classifications.custody_message_rules.map((entry) => entry.operation_code).sort())
  assert.equal(new Set(streamOperations).size, streamOperations.length)
  for (const stream of classifications.adapter_request_stream_rules) {
    assert.match(stream.stream_code, /^[a-z][a-z0-9_]{0,63}$/)
    assert.ok(stream.operation_codes.length > 0)
  }
  assert.equal(classifications.capability_leaf_rules.response_triggered_transition_is_never_embedded_in_its_own_response, true)
  assert.equal(classifications.custody_state_transition_rules.length, 6)
  assert.equal(classifications.crash_boundary_rules.length, 14)
  assert.equal(classifications.recovery_decision_rules.length, 19)
  assert.equal(classifications.backup_reference_rules.length, 3)
  const altered = clone(classifications)
  altered.recovery_decision_rules[0].priority = 11
  assert.notDeepEqual(matrixFingerprintPayloads(altered), classifications.matrix_fingerprints)
  const matrixMutations = [
    (value) => { value.adapter_request_stream_rules[0].operation_codes.reverse() },
    (value) => { value.custody_message_rules[0].success_outcomes[0] = 'mutated' },
    (value) => { value.custody_state_transition_rules[0].to_state_code = 'mutated' },
    (value) => { value.journal_history_rules[0].milestones[0] = 'mutated@startup' },
    (value) => { value.recovery_decision_rules[0].priority = 11 },
  ]
  for (const mutate of matrixMutations) {
    const changed = clone(classifications)
    mutate(changed)
    assert.notDeepEqual(matrixFingerprintPayloads(changed), classifications.matrix_fingerprints)
  }
  const widened = clone(classifications)
  widened.handle_scope_compatibility.additional_handle_grants.push('recovery_store')
  assertThrowsCode(() => validateFrozenCompositionCompatibility(widened), 'D90_COMPOSITION_REJECTED')
  assert.notEqual(recordDigest(widened), expected.classification)

  const extraEvent = clone(classifications)
  extraEvent.journal_composition_policy.extension_event_kinds.push('recovery_reconciliation')
  assertThrowsCode(() => validateFrozenCompositionCompatibility(extraEvent), 'D90_COMPOSITION_REJECTED')
  const extraSupersession = clone(classifications)
  extraSupersession.journal_composition_policy.superseded_sections.push('error_rules')
  assertThrowsCode(() => validateFrozenCompositionCompatibility(extraSupersession), 'D90_COMPOSITION_REJECTED')
  const duplicateSelector = clone(classifications)
  duplicateSelector.journal_failure_history_rules[1].base_selector = clone(duplicateSelector.journal_failure_history_rules[0].base_selector)
  duplicateSelector.journal_failure_history_rules[1].bundle_kind_code = duplicateSelector.journal_failure_history_rules[0].bundle_kind_code
  duplicateSelector.journal_failure_history_rules[1].permit_kind_code = duplicateSelector.journal_failure_history_rules[0].permit_kind_code
  assertThrowsCode(() => validateFrozenCompositionCompatibility(duplicateSelector), 'D90_COMPOSITION_REJECTED')
  const invalidRoot = clone(classifications)
  invalidRoot.journal_history_rules[0].milestones[0] = 'stage_entered@startup'
  assertThrowsCode(() => validateFrozenCompositionCompatibility(invalidRoot), 'D90_COMPOSITION_REJECTED')
  const invalidTerminal = clone(classifications)
  invalidTerminal.journal_failure_history_rules[1].milestones[invalidTerminal.journal_failure_history_rules[1].milestones.length - 1] = 'operation_completed@completion'
  assertThrowsCode(() => validateFrozenCompositionCompatibility(invalidTerminal), 'D90_COMPOSITION_REJECTED')
}

function assertProfileContracts() {
  validateProfile(validFixtures.records.custody_profile)
  validateProfile(validFixtures.records.journal_profile)
  const mismatched = clone(validFixtures.records.custody_profile)
  mismatched.profile_kind_code = 'journal'
  mismatched.record_digest_sha256 = recordDigest(mismatched)
  assertThrowsCode(() => validateProfile(mismatched), 'SCHEMA_REJECTED')
  const activated = clone(validFixtures.records.custody_profile)
  activated.activation_state_code = 'active'
  activated.record_digest_sha256 = recordDigest(activated)
  assertThrowsCode(() => validateProfile(activated), 'SCHEMA_REJECTED')
  const wrongCatalog = clone(validFixtures.records.custody_profile)
  wrongCatalog.d930_contract_catalog_sha256 = sample.sha('af')
  wrongCatalog.record_digest_sha256 = recordDigest(wrongCatalog)
  assertThrowsCode(() => validateProfile(wrongCatalog), 'PROFILE_FINGERPRINT_MISMATCH')
}

function assertBackupReferenceBoundaries() {
  for (const kind of ['artifact_copy', 'prior_database', 'final_consistent_set']) {
    const reference = backupReference(kind, '2030-01-02T00:00:05.000Z')
    validateBackupChronology(reference, '2030-01-02T00:00:05.500Z', '2030-01-02T00:00:06.000Z')
    const wrongKind = clone(reference)
    wrongKind.scope_profile_code = 'wrong.scope'
    assertThrowsCode(() => validateBackupChronology(wrongKind, '2030-01-02T00:00:05.500Z', '2030-01-02T00:00:06.000Z'), 'BACKUP_REFERENCE_TYPE_REJECTED')
    const wrongRole = clone(reference)
    wrongRole.produced_by_binding_code = 'bundle.importer.synthetic'
    assertThrowsCode(() => validateBackupChronology(wrongRole, '2030-01-02T00:00:05.500Z', '2030-01-02T00:00:06.000Z'), 'BACKUP_REFERENCE_PRODUCER_REJECTED')
    const late = clone(reference)
    late.persisted_at = '2030-01-02T00:00:07.000Z'
    assertThrowsCode(() => validateBackupChronology(late, '2030-01-02T00:00:05.500Z', '2030-01-02T00:00:06.000Z'), 'BACKUP_REFERENCE_CHRONOLOGY_REJECTED')
  }
  assert.ok(!catalog.schemas.some((entry) => entry.contract_format === 'jedi-atlas-backup-durability-receipt'))
}

function validateFixtureRecords() {
  for (const [name, record] of Object.entries(validFixtures.records)) {
    try { validateRecord(record) } catch (error) { throw new Error(`fixture ${name}: ${error.message}`) }
  }
  assertReceiptsAndBroker()
  validateAdapterMessage(validFixtures.records.adapter_publish_response)
  validateSemantic(validFixtures.records.journal_semantic, { bundle_kind_code: 'single_document' })
  validateJournalEvent(validFixtures.records.journal_event, { bundle_kind_code: 'single_document' })
  validateJournalBrokerPair(validFixtures.records.journal_broker_request, validFixtures.records.journal_broker_response, validFixtures.records.journal_event)
  const direct = validFixtures.records.journal_semantic.custody_finalization
  assert.equal(direct.primary_receipt.receipt_raw_sha256, receiptBytesSha(validFixtures.records.primary_receipt))
  assert.equal(direct.exchanges.at(-1).response_record_digest_sha256, validFixtures.records.adapter_publish_response.record_digest_sha256)
  assert.equal(validFixtures.records.adapter_publish_response.payload.primary_receipt.receipt_raw_sha256, receiptBytesSha(validFixtures.records.primary_receipt))
  assert.equal(validFixtures.records.adapter_publish_response.payload.receipt_broker_ack_record_digest_sha256, validFixtures.records.receipt_broker_response.record_digest_sha256)
  for (const [name, record] of Object.entries(validFixtures.records)) {
    const extra = clone(record)
    extra.unapproved_field = true
    assertThrowsCode(() => validateSchema(extra), 'SCHEMA_REJECTED')
    const malformedTime = primitiveLeaves(record).find(([pointer]) => pointer.endsWith('_at'))
    if (malformedTime) {
      const changed = pointerSet(record, malformedTime[0], '2030-01-01T00:00:00Z')
      if (Object.hasOwn(changed, 'record_digest_sha256')) changed.record_digest_sha256 = recordDigest(changed)
      assert.throws(() => validateRecord(changed), /SCHEMA_REJECTED|TIMESTAMP_REJECTED/)
    }
    assert.ok(name.length > 0)
  }
}

function validateInvalidFixtureCases() {
  assert.equal(invalidFixtures.mutations.length, 11)
  for (const mutation of invalidFixtures.mutations) {
    const target = clone(validFixtures.records[mutation.target_code])
    const changed = pointerSet(target, mutation.pointer, mutation.replacement)
    if (mutation.target_code === 'primary_receipt') changed.semantic_payload_sha256 = semanticDigest(changed.semantic)
    if (Object.hasOwn(changed, 'record_digest_sha256')) changed.record_digest_sha256 = recordDigest(changed)
    const context = {
      operation_id: validFixtures.records.receipt_broker_request.operation_id,
      operation_nonce: validFixtures.records.receipt_broker_request.operation_nonce,
      bundle: validFixtures.records.receipt_broker_request.payload.receipt_semantic.bundle,
      artifact: validFixtures.records.receipt_broker_request.payload.receipt_semantic.artifact,
      copy_code: validFixtures.records.receipt_broker_request.payload.receipt_semantic.copy_code,
      backend_code: validFixtures.records.receipt_broker_request.payload.receipt_semantic.backend_code,
      backend_reference: validFixtures.records.receipt_broker_request.payload.receipt_semantic.backend_reference,
      runtime_profile_record_digest_sha256: validFixtures.records.receipt_broker_request.runtime_profile_record_digest_sha256,
      identity_bindings_record_digest_sha256: validFixtures.records.receipt_broker_request.identity_bindings_record_digest_sha256,
      d930_operational_profile_record_digest_sha256: validFixtures.records.receipt_broker_request.d930_operational_profile_record_digest_sha256,
      persistence_request_record_digest_sha256: validFixtures.records.receipt_broker_request.record_digest_sha256,
    }
    const invoke = () => {
      if (mutation.target_code === 'primary_receipt') return validatePrimaryReceipt(changed, context)
      if (mutation.target_code === 'adapter_publish_response') return validateAdapterMessage(changed)
      if (mutation.target_code === 'journal_semantic') return validateSemantic(changed, { bundle_kind_code: 'single_document' })
      if (mutation.target_code === 'journal_event') return validateJournalEvent(changed, { bundle_kind_code: 'single_document' })
      if (mutation.target_code === 'journal_broker_request') return validateJournalBrokerPair(changed, validFixtures.records.journal_broker_response, validFixtures.records.journal_event)
      fail('FIXTURE_TARGET_UNKNOWN', mutation.target_code)
    }
    assertThrowsCode(invoke, mutation.expected_error_code)
  }
}

function assertReplayAndRecoveryChains() {
  const replay = new Map()
  const accept = (record) => {
    const digest = Object.hasOwn(record, 'record_digest_sha256') ? record.record_digest_sha256 : sha256Bytes(Buffer.from(canonicalize(record), 'utf8'))
    const keys = [`record:${record.format}:${record.record_code}`]
    if (record.request_id) keys.push(`request:${record.format}:${record.message_kind_code ?? record.operation_code ?? 'record'}:${record.operation_id}:${record.operation_nonce}:${record.request_id}`)
    if (record.journal_code && record.event_sequence) keys.push(`journal:${record.journal_code}:${record.event_sequence}`)
    for (const key of keys) {
      if (replay.has(key) && replay.get(key) !== digest) fail('CONFLICTING_REPLAY', key)
      replay.set(key, digest)
    }
    return digest
  }
  for (const record of Object.values(validFixtures.records)) {
    accept(record)
    accept(record)
    const replayKeyPointers = new Set(['/format', '/format_version', '/record_code', '/operation_id', '/operation_nonce', '/request_id', '/journal_code', '/event_sequence', '/record_digest_sha256'])
    const [pointer, value] = primitiveLeaves(record).find(([candidate]) => !replayKeyPointers.has(candidate))
    const conflicting = pointerSet(record, pointer, mutatedPrimitive(value))
    if (Object.hasOwn(conflicting, 'record_digest_sha256')) conflicting.record_digest_sha256 = recordDigest(conflicting)
    assertThrowsCode(() => accept(conflicting), 'CONFLICTING_REPLAY')
  }
  const request = validFixtures.records.receipt_broker_request
  const sameRequestFreshCode = clone(request)
  sameRequestFreshCode.record_code = `${request.record_code}.fresh`
  sameRequestFreshCode.created_at = new Date(Date.parse(request.created_at) + 1).toISOString()
  sameRequestFreshCode.record_digest_sha256 = recordDigest(sameRequestFreshCode)
  assertThrowsCode(() => accept(sameRequestFreshCode), 'CONFLICTING_REPLAY')

  const historyRule = classifications.journal_history_rules.find((entry) => entry.history_code === 'post_promotion_completion_document')
  const retryHistory = buildJournalHistory(historyRule, { recoveryAttempts: 2 })
  validateHistory(historyRule, retryHistory.events, retryHistory.resolutionContext)
  const [firstAssessment, laterAssessment] = retryHistory.events.filter((event) => event.semantic_assertion.recovery)
  const recoveryContext = {
    bundle_kind_code: 'single_document',
    recovery_resolution: retryHistory.resolutionContext.recovery_resolution,
    previous_event: firstAssessment,
    journal_code: laterAssessment.journal_code,
    persisted_at: laterAssessment.persisted_at,
    persisted_by_binding_code: laterAssessment.persisted_by_binding_code,
  }
  validateRecoveryPayloadShape(laterAssessment.semantic_assertion, recoveryContext)
  const rawContext = { ...recoveryContext, recovery_resolution: { resolvePermit: () => frozenFixture('post_promotion_completion_permit') } }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, rawContext), 'RECOVERY_RESOLVER_UNTRUSTED')
  const missingPromotionAuthorization = frozenFixture('journal_document_promotion_started')
  missingPromotionAuthorization.prepromotion_authorization_record_digest_sha256 = null
  assertThrowsCode(() => validateFrozenSourceEventSemantics(missingPromotionAuthorization), 'RECOVERY_SOURCE_TERMINAL_REJECTED')
  const forgedNonpromotionAuthorization = frozenFixture('journal_document_started')
  forgedNonpromotionAuthorization.prepromotion_authorization_record_digest_sha256 = sample.sha('fb')
  assertThrowsCode(() => validateFrozenSourceEventSemantics(forgedNonpromotionAuthorization), 'RECOVERY_SOURCE_TERMINAL_REJECTED')
  const candidateContinuity = [
    frozenFixture('journal_bootstrap_candidate_committed'),
    frozenFixture('journal_bootstrap_candidate_sealed'),
    frozenFixture('journal_bootstrap_promotion_started'),
    frozenFixture('journal_bootstrap_promotion_observed'),
  ]
  validateFrozenSourceMilestoneContinuity(candidateContinuity)
  const driftedCandidateContinuity = clone(candidateContinuity)
  driftedCandidateContinuity[1].candidate_file_sha256 = sample.sha('fa')
  assertThrowsCode(() => validateFrozenSourceMilestoneContinuity(driftedCandidateContinuity), 'RECOVERY_SOURCE_TERMINAL_REJECTED')
  const driftedCandidateState = clone(candidateContinuity)
  driftedCandidateState[1].observed_logical_state = clone(driftedCandidateState[1].observed_logical_state)
  driftedCandidateState[1].observed_logical_state.logical_state_sha256 = sample.sha('f7')
  assertThrowsCode(() => validateFrozenSourceMilestoneContinuity(driftedCandidateState), 'RECOVERY_SOURCE_TERMINAL_REJECTED')
  const backupContinuity = [frozenFixture('journal_bootstrap_promotion_started'), frozenFixture('journal_bootstrap_promotion_observed')]
  validateFrozenSourceMilestoneContinuity(backupContinuity)
  const driftedBackupContinuity = clone(backupContinuity)
  driftedBackupContinuity[1].backup_inventory_sha256 = sample.sha('f9')
  assertThrowsCode(() => validateFrozenSourceMilestoneContinuity(driftedBackupContinuity), 'RECOVERY_SOURCE_TERMINAL_REJECTED')
  const wrongSourceAuthority = recoveryAuthorityFixture(historyRule)
  wrongSourceAuthority.sourceTerminal = frozenFixture('journal_bootstrap_backup_recovery_required')
  const recoveryLock = recoveryLockProjection(laterAssessment.semantic_assertion.recovery.knowledge_snapshot)
  const wrongSource = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(wrongSourceAuthority, recoveryLock) }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, wrongSource), 'RECOVERY_SOURCE_TERMINAL_REJECTED')
  const wrongLockProjection = { ...recoveryLock, owner_binding_code: 'trusted.launcher.synthetic' }
  const wrongLock = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(recoveryAuthorityFixture(historyRule), wrongLockProjection) }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, wrongLock), 'RECOVERY_LOCK_REJECTED')
  const aliasLockSemantic = clone(laterAssessment.semantic_assertion)
  aliasLockSemantic.recovery.knowledge_snapshot.recovery_lock_owner_binding_code = 'trusted.launcher.synthetic'
  aliasLockSemantic.recovery.knowledge_snapshot.recovery_lock_projection_sha256 = recoveryLockProjectionSha(aliasLockSemantic.recovery.knowledge_snapshot)
  aliasLockSemantic.record_digest_sha256 = recordDigest(aliasLockSemantic)
  const aliasLockProjection = recoveryLockProjection(aliasLockSemantic.recovery.knowledge_snapshot)
  const aliasLockContext = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(recoveryAuthorityFixture(historyRule), aliasLockProjection) }
  assertThrowsCode(() => validateRecoveryPayloadShape(aliasLockSemantic, aliasLockContext), 'RECOVERY_LOCK_REJECTED')
  const aliasBrokerContext = { ...recoveryContext, persisted_by_binding_code: 'journal.broker.synthetic' }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, aliasBrokerContext), 'RECOVERY_PERMIT_INVALID')
  const wrongPermitAuthority = recoveryAuthorityFixture(historyRule)
  wrongPermitAuthority.permit = frozenFixture('post_promotion_bootstrap_completion_permit')
  const wrongPermit = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(wrongPermitAuthority, recoveryLock) }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, wrongPermit), 'RECOVERY_PERMIT_INVALID')
  const revokedClaimAuthority = recoveryAuthorityFixture(historyRule)
  Object.assign(revokedClaimAuthority.permitClaim, { to_state_code: 'revoked', transition_code: 'authority_withdrawal', reason_code: 'authority_withdrawal' })
  revokedClaimAuthority.permitClaim.record_digest_sha256 = recordDigest(revokedClaimAuthority.permitClaim)
  const revokedClaim = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(revokedClaimAuthority, recoveryLock) }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, revokedClaim), 'RECOVERY_PERMIT_INVALID')
  const noncurrentSourceAuthority = recoveryAuthorityFixture(historyRule)
  noncurrentSourceAuthority.sourceTerminal.previous_event_record_digest_sha256 = noncurrentSourceAuthority.sourceTerminal.record_digest_sha256
  noncurrentSourceAuthority.sourceTerminal.event_sequence += 1
  noncurrentSourceAuthority.sourceTerminal.record_code = `${noncurrentSourceAuthority.sourceTerminal.record_code}.successor`
  noncurrentSourceAuthority.sourceTerminal.persisted_at = new Date(Date.parse(noncurrentSourceAuthority.sourceTerminal.persisted_at) + 1).toISOString()
  noncurrentSourceAuthority.sourceTerminal.event_at = noncurrentSourceAuthority.sourceTerminal.persisted_at
  noncurrentSourceAuthority.sourceTerminal.record_digest_sha256 = recordDigest(noncurrentSourceAuthority.sourceTerminal)
  const noncurrentSource = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(noncurrentSourceAuthority, recoveryLock) }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, noncurrentSource), 'RECOVERY_SOURCE_TERMINAL_REJECTED')
  const crossSubjectAuthority = recoveryAuthorityFixture(historyRule)
  crossSubjectAuthority.sourceTerminal.operation_id = 'operation.source.substituted'
  crossSubjectAuthority.sourceTerminal.record_digest_sha256 = recordDigest(crossSubjectAuthority.sourceTerminal)
  crossSubjectAuthority.permit.source_recovery_journal_event_record_digest_sha256 = crossSubjectAuthority.sourceTerminal.record_digest_sha256
  crossSubjectAuthority.permit.record_digest_sha256 = recordDigest(crossSubjectAuthority.permit)
  crossSubjectAuthority.permitClaim.permit_issuance_record_digest_sha256 = crossSubjectAuthority.permit.record_digest_sha256
  crossSubjectAuthority.permitClaim.record_digest_sha256 = recordDigest(crossSubjectAuthority.permitClaim)
  const crossSubjectSemantic = clone(laterAssessment.semantic_assertion)
  crossSubjectSemantic.authorization_permit_record_digest_sha256 = crossSubjectAuthority.permit.record_digest_sha256
  crossSubjectSemantic.recovery.source_terminal_journal_head_record_digest_sha256 = crossSubjectAuthority.sourceTerminal.record_digest_sha256
  crossSubjectSemantic.record_digest_sha256 = recordDigest(crossSubjectSemantic)
  const crossSubject = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(crossSubjectAuthority, recoveryLock) }
  assertThrowsCode(() => validateRecoveryPayloadShape(crossSubjectSemantic, crossSubject), 'RECOVERY_SOURCE_TERMINAL_REJECTED')
  const noncurrentLock = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(recoveryAuthorityFixture(historyRule), recoveryLock, { lockHeadOverrides: { is_current: false } }) }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, noncurrentLock), 'RECOVERY_LOCK_REJECTED')
  const expiredAuthority = recoveryAuthorityFixture(historyRule)
  expiredAuthority.permit.expires_at = '2030-01-01T00:11:00.001Z'
  expiredAuthority.permit.record_digest_sha256 = recordDigest(expiredAuthority.permit)
  expiredAuthority.permitClaim.permit_issuance_record_digest_sha256 = expiredAuthority.permit.record_digest_sha256
  expiredAuthority.permitClaim.record_digest_sha256 = recordDigest(expiredAuthority.permitClaim)
  const expiredSemantic = clone(laterAssessment.semantic_assertion)
  expiredSemantic.authorization_permit_record_digest_sha256 = expiredAuthority.permit.record_digest_sha256
  expiredSemantic.record_digest_sha256 = recordDigest(expiredSemantic)
  const expiredContext = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(expiredAuthority, recoveryLock) }
  assertThrowsCode(() => validateRecoveryPayloadShape(expiredSemantic, expiredContext), 'RECOVERY_PERMIT_INVALID')
  const bindingBoundaryAuthority = recoveryAuthorityFixture(historyRule)
  const boundaryLauncher = bindingBoundaryAuthority.identityBindings.bindings.find((binding) => binding.binding_code === bindingBoundaryAuthority.permitClaim.recorded_by_binding_code)
  boundaryLauncher.valid_until = bindingBoundaryAuthority.permitClaim.persisted_at
  assertThrowsCode(() => activeBinding(bindingBoundaryAuthority.identityBindings, boundaryLauncher.binding_code, 'trusted_launcher', bindingBoundaryAuthority.permitClaim.occurred_at, bindingBoundaryAuthority.permitClaim.persisted_at, 'service'), 'RECOVERY_PERMIT_INVALID')
  const exclusiveCoverageBindings = clone(bindingBoundaryAuthority.identityBindings)
  const exclusiveLauncher = exclusiveCoverageBindings.bindings.find((binding) => binding.binding_code === boundaryLauncher.binding_code)
  exclusiveLauncher.valid_until = bindingBoundaryAuthority.permit.expires_at
  activeBinding(exclusiveCoverageBindings, exclusiveLauncher.binding_code, 'trusted_launcher', bindingBoundaryAuthority.permit.issued_at, bindingBoundaryAuthority.permit.expires_at, 'service', true)
  const preclaimLockAuthority = recoveryAuthorityFixture(historyRule)
  preclaimLockAuthority.permitClaim.persisted_at = new Date(Date.parse(recoveryLock.acquired_at) + 1).toISOString()
  preclaimLockAuthority.permitClaim.record_digest_sha256 = recordDigest(preclaimLockAuthority.permitClaim)
  const preclaimLockContext = { ...recoveryContext, recovery_resolution: makeSyntheticRecoveryResolution(preclaimLockAuthority, recoveryLock) }
  assertThrowsCode(() => validateRecoveryPayloadShape(laterAssessment.semantic_assertion, preclaimLockContext), 'RECOVERY_LOCK_REJECTED')
  const wrongBundle = clone(laterAssessment.semantic_assertion)
  wrongBundle.recovery.subject_bundle.bundle_sequence = 3
  assertThrowsCode(() => validateRecoveryPayloadShape(wrongBundle, recoveryContext), 'RECOVERY_SUBJECT_REJECTED')
  const recoveredTerminal = retryHistory.events.at(-1).semantic_assertion
  const recoveredTerminalEvent = retryHistory.events.at(-1)
  const nonzeroRecovered = clone(recoveredTerminal)
  nonzeroRecovered.rows_delta.atlas_artifacts = 1
  nonzeroRecovered.record_digest_sha256 = recordDigest(nonzeroRecovered)
  assertThrowsCode(() => validateSemantic(nonzeroRecovered, { bundle_kind_code: 'single_document', recovery_resolution: retryHistory.resolutionContext.recovery_resolution, persisted_at: recoveredTerminalEvent.persisted_at, persisted_by_binding_code: recoveredTerminalEvent.persisted_by_binding_code }), 'D90_EVENT_POLICY_REJECTED')
  const projection = {
    recovery_chain_code: firstAssessment.semantic_assertion.recovery.recovery_chain_code,
    subject_operation_id: firstAssessment.semantic_assertion.recovery.subject_operation_id,
    subject_operation_nonce: firstAssessment.semantic_assertion.recovery.subject_operation_nonce,
  }
  const projectionEvents = retryHistory.events
  const replaceLaterAssessment = (replacement) => projectionEvents.map((event) => event.record_digest_sha256 === laterAssessment.record_digest_sha256 ? replacement : event)
  assert.equal(activeRecoveryAssessment(projectionEvents, projection, 1, atTick(0), retryHistory.resolutionContext), null)
  const beforeRetry = activeRecoveryAssessment(projectionEvents, projection, 1, firstAssessment.persisted_at, retryHistory.resolutionContext)
  assert.equal(beforeRetry.record_digest_sha256, firstAssessment.record_digest_sha256)
  assert.equal(activeRecoveryAssessment(projectionEvents, projection, 2, laterAssessment.persisted_at, retryHistory.resolutionContext).record_digest_sha256, laterAssessment.record_digest_sha256)
  assert.equal(activeRecoveryAssessment(projectionEvents, projection, 2, firstAssessment.persisted_at, retryHistory.resolutionContext).record_digest_sha256, firstAssessment.record_digest_sha256)
  const unrelated = clone(laterAssessment)
  unrelated.journal_code = 'journal.operation.recovery.unrelated'
  unrelated.record_code = `${unrelated.record_code}.unrelated`
  unrelated.semantic_assertion.record_code = `${unrelated.semantic_assertion.record_code}.unrelated`
  unrelated.semantic_assertion.recovery.recovery_chain_code = 'recovery.chain.unrelated'
  unrelated.semantic_assertion.recovery.subject_operation_id = 'operation.subject.unrelated'
  unrelated.semantic_assertion.recovery.recovery_attempt_sequence = 99
  unrelated.semantic_assertion.record_digest_sha256 = recordDigest(unrelated.semantic_assertion)
  unrelated.semantic_assertion_record_digest_sha256 = unrelated.semantic_assertion.record_digest_sha256
  unrelated.record_digest_sha256 = recordDigest(unrelated)
  assert.equal(activeRecoveryAssessment([...projectionEvents, unrelated], projection, 99, unrelated.persisted_at, retryHistory.resolutionContext).record_digest_sha256, laterAssessment.record_digest_sha256)
  const backdatedSemantic = clone(laterAssessment)
  backdatedSemantic.semantic_assertion.event_at = atTick(1)
  backdatedSemantic.semantic_assertion.record_digest_sha256 = recordDigest(backdatedSemantic.semantic_assertion)
  backdatedSemantic.semantic_assertion_record_digest_sha256 = backdatedSemantic.semantic_assertion.record_digest_sha256
  backdatedSemantic.record_digest_sha256 = recordDigest(backdatedSemantic)
  assertThrowsCode(() => activeRecoveryAssessment(replaceLaterAssessment(backdatedSemantic), projection, 2, backdatedSemantic.persisted_at, retryHistory.resolutionContext), 'RECOVERY_CHAIN_REJECTED')
  const forked = clone(laterAssessment)
  forked.semantic_assertion.recovery.prior_attempt_terminal_record_digest_sha256 = sample.sha('fe')
  forked.semantic_assertion.record_digest_sha256 = recordDigest(forked.semantic_assertion)
  forked.semantic_assertion_record_digest_sha256 = forked.semantic_assertion.record_digest_sha256
  forked.record_digest_sha256 = recordDigest(forked)
  assertThrowsCode(() => validateRecoveryAttemptChain([firstAssessment, forked], replaceLaterAssessment(forked)), 'RECOVERY_CHAIN_REJECTED')
  const journalPredecessorSwap = clone(laterAssessment)
  journalPredecessorSwap.previous_event_record_digest_sha256 = sample.sha('fb')
  journalPredecessorSwap.record_digest_sha256 = recordDigest(journalPredecessorSwap)
  assertThrowsCode(() => activeRecoveryAssessment(replaceLaterAssessment(journalPredecessorSwap), projection, 2, journalPredecessorSwap.persisted_at, retryHistory.resolutionContext), 'JOURNAL_CHAIN_REJECTED')
  const knowledgeHeadSwap = clone(laterAssessment)
  knowledgeHeadSwap.semantic_assertion.recovery.knowledge_snapshot.known_through_journal_head_record_digest_sha256 = sample.sha('fa')
  knowledgeHeadSwap.semantic_assertion.record_digest_sha256 = recordDigest(knowledgeHeadSwap.semantic_assertion)
  knowledgeHeadSwap.semantic_assertion_record_digest_sha256 = knowledgeHeadSwap.semantic_assertion.record_digest_sha256
  knowledgeHeadSwap.record_digest_sha256 = recordDigest(knowledgeHeadSwap)
  assertThrowsCode(() => activeRecoveryAssessment(replaceLaterAssessment(knowledgeHeadSwap), projection, 2, knowledgeHeadSwap.persisted_at, retryHistory.resolutionContext), 'RECOVERY_CHAIN_REJECTED')
  assertThrowsCode(() => validateRecoveryAttemptChain([firstAssessment, laterAssessment, clone(laterAssessment)], [...projectionEvents, clone(laterAssessment)]), 'RECOVERY_CHAIN_REJECTED')
  for (const field of ['authorization_permit_record_digest_sha256', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'bundle', 'target_logical_state', 'component_binding_code', 'component_executable_sha256']) {
    const substituted = clone(laterAssessment)
    substituted.semantic_assertion[field] = field.endsWith('_sha256') || field.endsWith('_digest_sha256')
      ? sample.sha('f7')
      : field === 'bundle'
        ? { ...substituted.semantic_assertion.bundle, bundle_id: 'bundle.synthetic.recovery-substitution' }
        : field === 'target_logical_state'
          ? { ...substituted.semantic_assertion.target_logical_state, logical_state_code: 'state.synthetic.recovery-substitution' }
          : 'binding.synthetic.recovery-substitution'
    substituted.semantic_assertion.record_digest_sha256 = recordDigest(substituted.semantic_assertion)
    substituted.semantic_assertion_record_digest_sha256 = substituted.semantic_assertion.record_digest_sha256
    substituted.record_digest_sha256 = recordDigest(substituted)
    const expectedError = field === 'target_logical_state' ? 'SCHEMA_REJECTED' : field === 'component_binding_code' ? 'D90_ORIGIN_REJECTED' : 'RECOVERY_PERMIT_INVALID'
    assertThrowsCode(() => activeRecoveryAssessment(replaceLaterAssessment(substituted), projection, 2, substituted.persisted_at, retryHistory.resolutionContext), expectedError)
  }
  const detachedFirst = clone(firstAssessment)
  detachedFirst.event_sequence = 42
  detachedFirst.previous_event_record_digest_sha256 = sample.sha('f6')
  detachedFirst.semantic_assertion.recovery.knowledge_snapshot.known_through_journal_sequence = 41
  detachedFirst.semantic_assertion.recovery.knowledge_snapshot.known_through_journal_head_record_digest_sha256 = detachedFirst.previous_event_record_digest_sha256
  detachedFirst.semantic_assertion.record_digest_sha256 = recordDigest(detachedFirst.semantic_assertion)
  detachedFirst.semantic_assertion_record_digest_sha256 = detachedFirst.semantic_assertion.record_digest_sha256
  detachedFirst.record_digest_sha256 = recordDigest(detachedFirst)
  assertThrowsCode(() => activeRecoveryAssessment([detachedFirst], projection, 1, detachedFirst.persisted_at, retryHistory.resolutionContext), 'JOURNAL_CHAIN_REJECTED')
}

function validateRecoveryAttemptChain(events, journalEvents) {
  const successors = new Set()
  const stable = ['recovery_chain_code', 'subject_operation_id', 'subject_operation_nonce', 'subject_bundle', 'subject_artifact', 'subject_copy_code', 'subject_backend_code', 'subject_backend_reference', 'source_terminal_journal_code', 'source_terminal_journal_sequence', 'source_terminal_journal_head_record_digest_sha256', 'source_terminal_journal_persisted_at', 'source_terminal_error_code']
  const stableSemantic = ['operation_id', 'operation_nonce', 'authorization_permit_record_digest_sha256', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_journal_profile_record_digest_sha256', 'bundle', 'target_logical_state', 'component_binding_code', 'component_executable_sha256']
  const recordIdentities = new Map()
  for (const journalEvent of journalEvents) {
    validateRecord(journalEvent.semantic_assertion)
    validateRecord(journalEvent)
    if (journalEvent.semantic_assertion_record_digest_sha256 !== journalEvent.semantic_assertion.record_digest_sha256) fail('RECOVERY_CHAIN_REJECTED', 'journal semantic envelope')
    if (journalEvent.semantic_assertion.event_at > journalEvent.persisted_at) fail('RECOVERY_CHAIN_REJECTED', 'journal event persistence chronology')
    for (const record of [journalEvent.semantic_assertion, journalEvent]) {
      const key = `${record.format}:${record.record_code}`
      const priorDigest = recordIdentities.get(key)
      if (priorDigest && priorDigest !== record.record_digest_sha256) fail('RECOVERY_CHAIN_REJECTED', 'record identity collision')
      recordIdentities.set(key, record.record_digest_sha256)
    }
  }
  if (events.length) {
    const maximumRelevantSequence = Math.max(...events.map((event) => event.event_sequence))
    const prefix = journalEvents.filter((event) => event.journal_code === events[0].journal_code && event.event_sequence <= maximumRelevantSequence).sort((left, right) => left.event_sequence - right.event_sequence)
    if (!prefix.length || prefix[0].event_sequence !== 1 || prefix.length !== maximumRelevantSequence) fail('RECOVERY_CHAIN_REJECTED', 'journal prefix gap')
    if (prefix[0].semantic_assertion.event_kind_code !== 'operation_started') fail('RECOVERY_CHAIN_REJECTED', 'journal root')
    const stableContextFields = ['operation_mode_code', 'operation_id', 'operation_nonce', 'runtime_profile_record_digest_sha256', 'identity_bindings_record_digest_sha256', 'd930_journal_profile_record_digest_sha256', 'authorization_permit_record_digest_sha256', 'authorization_bundle_seal_record_digest_sha256', 'bundle', 'target_logical_state']
    for (let index = 0; index < prefix.length; index += 1) {
      const predecessor = index === 0 ? null : prefix[index - 1]
      if (prefix[index].event_sequence !== index + 1) fail('RECOVERY_CHAIN_REJECTED', 'journal sequence')
      if (prefix[index].previous_event_record_digest_sha256 !== (predecessor?.record_digest_sha256 ?? null)) fail('RECOVERY_CHAIN_REJECTED', 'journal prefix predecessor')
      if (predecessor && (predecessor.persisted_at >= prefix[index].persisted_at || predecessor.semantic_assertion.event_at >= prefix[index].semantic_assertion.event_at)) fail('RECOVERY_CHAIN_REJECTED', 'journal prefix chronology')
      if (predecessor && ['operation_completed', 'recovery_required'].includes(predecessor.semantic_assertion.event_kind_code)) fail('RECOVERY_CHAIN_REJECTED', 'journal terminal successor')
      if (predecessor) for (const field of stableContextFields) if (canonicalize(prefix[index].semantic_assertion[field]) !== canonicalize(prefix[0].semantic_assertion[field])) fail('RECOVERY_CHAIN_REJECTED', `journal context ${field}`)
    }
  }
  const journalByDigest = new Map(journalEvents.map((event) => [event.record_digest_sha256, event]))
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]
    validateRecord(event.semantic_assertion)
    validateRecord(event)
    if (event.semantic_assertion_record_digest_sha256 !== event.semantic_assertion.record_digest_sha256) fail('RECOVERY_CHAIN_REJECTED', 'semantic envelope')
    const payload = event.semantic_assertion.recovery
    if (event.semantic_assertion.event_kind_code !== 'stage_succeeded' || event.semantic_assertion.stage_code !== 'reconciliation' || event.semantic_assertion.operation_mode_code !== 'recovery') fail('RECOVERY_CHAIN_REJECTED', 'assessment semantic')
    if (!payload || payload.recovery_attempt_sequence !== index + 1) fail('RECOVERY_CHAIN_REJECTED', 'attempt gap')
    if (event.semantic_assertion.event_at > event.persisted_at) fail('RECOVERY_CHAIN_REJECTED', 'event persistence chronology')
    const selected = evaluateRecovery(payload.knowledge_snapshot, payload.observation)
    for (const field of ['decision_rule_code', 'classification_code', 'next_step_code', 'classification_outcome_code', 'blocking_reason_codes', 'action_execution_code']) if (canonicalize(payload[field]) !== canonicalize(selected[field])) fail('RECOVERY_DECISION_MISMATCH', field)
    if (payload.record_kind_code !== 'classification_only_recovery_assessment' || payload.action_execution_code !== 'none_classification_only') fail('RECOVERY_ACTION_NOT_AUTHORIZED')
    if (event.semantic_assertion.operation_id !== events[0].semantic_assertion.operation_id || event.semantic_assertion.operation_nonce !== events[0].semantic_assertion.operation_nonce || event.journal_code !== events[0].journal_code) fail('RECOVERY_CHAIN_REJECTED', 'operation or journal drift')
    const predecessor = index === 0 ? null : events[index - 1]
    const journalPredecessor = journalByDigest.get(event.previous_event_record_digest_sha256)
    if (!journalPredecessor || journalPredecessor.journal_code !== event.journal_code || journalPredecessor.event_sequence + 1 !== event.event_sequence || journalPredecessor.persisted_at >= event.persisted_at) fail('RECOVERY_CHAIN_REJECTED', 'detached journal predecessor')
    if (index === 0 && (journalPredecessor.event_sequence !== 1 || journalPredecessor.semantic_assertion.event_kind_code !== 'operation_started')) fail('RECOVERY_CHAIN_REJECTED', 'first assessment predecessor')
    const knowledge = payload.knowledge_snapshot
    if (knowledge.known_through_journal_code !== event.journal_code
      || knowledge.known_through_journal_sequence !== event.event_sequence - 1
      || knowledge.known_through_journal_head_record_digest_sha256 !== event.previous_event_record_digest_sha256
      || knowledge.known_through_journal_head_persisted_at !== journalPredecessor.persisted_at
      || knowledge.known_through_journal_head_persisted_at > knowledge.scan_started_at
      || knowledge.known_through_journal_head_persisted_at >= event.persisted_at) fail('RECOVERY_CHAIN_REJECTED', 'knowledge head')
    if (payload.prior_attempt_terminal_record_digest_sha256 !== (predecessor?.record_digest_sha256 ?? null)) fail('RECOVERY_CHAIN_REJECTED', 'attempt predecessor')
    if (predecessor) {
      if (event.previous_event_record_digest_sha256 !== predecessor.record_digest_sha256
        || knowledge.known_through_journal_head_persisted_at !== predecessor.persisted_at) fail('RECOVERY_CHAIN_REJECTED', 'journal predecessor')
      if (successors.has(payload.prior_attempt_terminal_record_digest_sha256)) fail('RECOVERY_CHAIN_REJECTED', 'attempt fork')
      successors.add(payload.prior_attempt_terminal_record_digest_sha256)
      if (predecessor.persisted_at >= event.persisted_at || predecessor.semantic_assertion.event_at >= event.semantic_assertion.event_at) fail('RECOVERY_CHAIN_REJECTED', 'attempt chronology')
      if (event.event_sequence !== predecessor.event_sequence + 1) fail('RECOVERY_CHAIN_REJECTED', 'journal attempt gap')
      for (const field of stable) if (canonicalize(predecessor.semantic_assertion.recovery[field]) !== canonicalize(payload[field])) fail('RECOVERY_CHAIN_REJECTED', field)
      for (const field of stableSemantic) if (canonicalize(predecessor.semantic_assertion[field]) !== canonicalize(event.semantic_assertion[field])) fail('RECOVERY_CHAIN_REJECTED', field)
      if (predecessor.persisted_by_binding_code !== event.persisted_by_binding_code) fail('RECOVERY_CHAIN_REJECTED', 'persistence actor')
    }
  }
}

function activeRecoveryAssessment(events, subject, knownThroughAttemptSequence, knownThroughPersistedAt, resolutionContext) {
  const chain = events.filter((event) => {
    const recovery = event?.semantic_assertion?.recovery
    if (!recovery) return false
    return recovery.recovery_chain_code === subject.recovery_chain_code
      && recovery.subject_operation_id === subject.subject_operation_id
      && recovery.subject_operation_nonce === subject.subject_operation_nonce
  })
  if (chain.length) {
    const maximumRelevantSequence = Math.max(...chain.map((event) => event.event_sequence))
    const prefix = events.filter((event) => event.journal_code === chain[0].journal_code && event.event_sequence <= maximumRelevantSequence).sort((left, right) => left.event_sequence - right.event_sequence)
    const bundleKindCode = chain[0].semantic_assertion.recovery.subject_artifact === null ? 'principal_bootstrap' : 'single_document'
    validateJournalChain(prefix, { bundle_kind_code: bundleKindCode, permit_kind_code: 'post_promotion_completion', recovery_resolution: resolutionContext?.recovery_resolution })
    validateRecoveryAttemptChain(chain, events)
    const journalByDigest = new Map(events.map((event) => [event.record_digest_sha256, event]))
    for (const event of chain) {
      const payload = event.semantic_assertion.recovery
      validateRecoveryPayloadShape(event.semantic_assertion, {
        bundle_kind_code: payload.subject_artifact === null ? 'principal_bootstrap' : 'single_document',
        recovery_resolution: resolutionContext?.recovery_resolution,
        previous_event: journalByDigest.get(event.previous_event_record_digest_sha256),
        journal_code: event.journal_code,
        persisted_at: event.persisted_at,
        persisted_by_binding_code: event.persisted_by_binding_code,
      })
    }
  }
  const visible = chain.filter((event) => event.semantic_assertion.recovery.recovery_attempt_sequence <= knownThroughAttemptSequence && event.persisted_at <= knownThroughPersistedAt)
  if (!visible.length) return null
  return visible.sort((left, right) => left.semantic_assertion.recovery.recovery_attempt_sequence - right.semantic_assertion.recovery.recovery_attempt_sequence || left.persisted_at.localeCompare(right.persisted_at)).at(-1)
}

let mutatedSchemaCounter = 0

function compileMutatedSchema(schemaFile, mutate) {
  const schema = clone(schemas.get(schemaFile))
  mutatedSchemaCounter += 1
  schema.$id = `${schema.$id}?mutation=${mutatedSchemaCounter}`
  mutate(schema)
  return new Ajv2020({ allErrors: true, strict: false }).addSchema(frozenCommon).addSchema(extensionCommon).compile(schema)
}

function assertSchemaAndCatalogMutations() {
  const receiptWithoutTime = clone(validFixtures.records.primary_receipt)
  delete receiptWithoutTime.persisted_at
  assertThrowsCode(() => validateSchema(receiptWithoutTime), 'SCHEMA_REJECTED')
  const weakenedReceipt = compileMutatedSchema('primary-durability-receipt-v1.schema.json', (schema) => {
    schema.required = schema.required.filter((field) => field !== 'persisted_at')
  })
  assert.ok(weakenedReceipt(receiptWithoutTime), 'weakened receipt schema mutation did not demonstrate sensitivity')

  const adapterUnknownOperation = clone(validFixtures.records.adapter_publish_response)
  adapterUnknownOperation.operation_code = 'overwrite'
  adapterUnknownOperation.record_digest_sha256 = recordDigest(adapterUnknownOperation)
  assertThrowsCode(() => validateSchema(adapterUnknownOperation), 'SCHEMA_REJECTED')
  const widenedAdapter = compileMutatedSchema('custody-adapter-message-v2.schema.json', (schema) => {
    schema.properties.operation_code.enum.push('overwrite')
  })
  assert.ok(widenedAdapter(adapterUnknownOperation), 'widened adapter schema mutation did not demonstrate sensitivity')

  for (const entry of catalog.schemas) {
    const changedSchema = `${fs.readFileSync(path.join(root, entry.schema_file), 'utf8')} `
    assert.notEqual(sha256Bytes(Buffer.from(changedSchema)), entry.raw_sha256, entry.schema_file)
  }
  const catalogMutation = clone(catalog)
  catalogMutation.status_code = 'active'
  assert.notEqual(sha256Bytes(Buffer.from(`${JSON.stringify(catalogMutation, null, 2)}\n`)), expected.catalog)
}

function assertNoForbiddenScopeOrSecrets() {
  const allRootText = fs.readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => fs.readFileSync(path.join(entry.parentPath ?? entry.path, entry.name), 'utf8'))
    .join('\n')
  for (const field of ['source_handle_token', 'preparation_token', 'sealed_capability_token']) assert.ok(!allRootText.includes(`\"${field}\"`), `${field} persisted in D9.3.0`)
  for (const marker of ['BEGIN PRIVATE KEY', 'Authorization: Bearer', 'aws_secret_access_key']) assert.ok(!allRootText.includes(marker))
  for (const field of ['final_object_deletion_actions', 'temporary_cleanup_actions', 'candidate_cleanup_actions', 'restriction_or_tombstone_actions', 'backup_creation_actions', 'canonical_write_actions']) assert.deepEqual(classifications.recovery_record_rules[field], [], field)
  assert.equal(classifications.handle_scope_compatibility.ipc_is_not_backing_store_handle, true)
  assert.equal(classifications.handle_scope_compatibility.d90_scope_widening, 'forbidden')
  assert.deepEqual(classifications.handle_scope_compatibility.additional_storage_handle_slots, [])
  assert.deepEqual(classifications.handle_scope_compatibility.additional_handle_grants, [])
  assert.equal(classifications.handle_scope_compatibility.receipt_namespace_code, 'd930_primary_receipts_within_operation_journal')
  assert.equal(classifications.handle_scope_compatibility.supporting_record_namespace_code, 'd930_secret_free_supporting_records_within_operation_journal')
  assert.equal(classifications.handle_scope_compatibility.recovery_namespace_code, 'd930_recovery_within_operation_journal')
  assert.equal(classifications.authority_boundary.physical_custody_implies_accepted_evidence, false)
  assert.equal(classifications.authority_boundary.accepted_evidence_implies_legal_authority, false)
}

function report() {
  const historyCount = classifications.journal_history_rules.length + classifications.journal_failure_history_rules.length
  const optionalHistoryShapes = classifications.journal_failure_history_rules.filter((history) => history.optional_penultimate_stage_failed).length
  const adapterVariantCount = classifications.custody_message_rules.reduce((count, rule) => count + 1 + rule.success_outcomes.length + rule.failure_outcomes.length, 0)
  return {
    status: 'D9.3.0 custody/durability contract design validated offline; no runtime guarantee claimed.',
    frozen_migrations: Object.keys(frozenMigrations).length,
    frozen_d901_fingerprints: Object.keys(frozenD901).length,
    top_level_schemas: schemaFiles.length,
    adapter_matrix_variants: adapterVariantCount,
    custody_state_transitions: classifications.custody_state_transition_rules.length,
    journal_histories: historyCount,
    journal_history_shapes_exercised: historyCount + optionalHistoryShapes,
    recovery_decision_rules: classifications.recovery_decision_rules.length,
    recovery_predicate_branches_exercised: classifications.recovery_decision_rules.reduce((count, rule) => count + rule.match_any.length, 0),
    recovery_fail_closed_guard_values_exercised: classifications.recovery_fail_closed_guards.reduce((count, guard) => count + guard.unsafe_values.length, 0),
    crash_boundaries: classifications.crash_boundary_rules.length,
    backup_receipt_payloads_defined: 0,
    runtime_components_created: 0,
    catalog_lifecycle_substitutions_rejected: ['design_only_unapproved', 'approved', 'active'],
    fingerprints: expected,
  }
}

assertFrozenInputs()
assertCatalog()
assertFieldRegistry()
assertResolverInventory()
assertGoldenVectors()
assertEveryLeafDigestSensitivity()
assertClassificationRegistry()
assertProfileContracts()
assertAdapterMatrix()
assertCustodyTransitions()
validateFixtureRecords()
assertFinalizationResolverGraph()
assertIntegrityResolverGraph()
validateInvalidFixtureCases()
assertBrokerSurfaces()
assertBackupReferenceBoundaries()
assertRecoveryDecisionMatrix()
assertJournalHistories()
assertReplayAndRecoveryChains()
assertSchemaAndCatalogMutations()
assertNoForbiddenScopeOrSecrets()
console.log(JSON.stringify(report(), null, 2))
