import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  D9JsonError,
  canonicalSha256,
  canonicalize,
  parseStrictJson,
  readFileBytes,
  sha256Bytes,
  sha256File,
} from './canonical.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const defaultContractRoot = path.resolve(here, '../../docs/schema/d9-0')

export const APPROVED_D9_FINGERPRINTS = Object.freeze({
  catalog_sha256: 'e0a5663b378453a00626f02961465a60a474e145dd5160bf85a1797cd9316d2a',
  classification_semantic_sha256: '8d7b64822663edf09dac0d613ed9da30de0569acb8a1258a84e1850af656deef',
  global_handles_semantic_sha256: '68c54bc683be3b3ff8ffba615fc850045c75a42539606858bffd42a881470f7e',
  operation_scopes_semantic_sha256: '9c2c9fd552bfdaac26448feace4de8f729c5b0587fa904ba65647b21c4de897e',
})

const schemaFiles = [
  'bootstrap-control-v1.schema.json',
  'clearance-record-v1.schema.json',
  'collector-handoff-v1.schema.json',
  'common-v1.schema.json',
  'custody-adapter-message-v1.schema.json',
  'custody-capability-control-v1.schema.json',
  'identity-bindings-v1.schema.json',
  'importer-result-v1.schema.json',
  'logical-state-seal-v1.schema.json',
  'operation-journal-event-v1.schema.json',
  'runtime-profile-v1.schema.json',
]

const migrationNames = [
  '001_schema.sql',
  '002_reference_data.sql',
  '003_seed_eu_core.sql',
  '004_tranche_1a_foundations.sql',
  '005_tranche_2a_source_quarantine.sql',
]

const componentReleaseRoles = [
  'backup_adapter',
  'bundle_importer',
  'clearance_broker',
  'cloner_promoter',
  'collector',
  'custody_adapter',
  'database_writer',
  'handoff_broker',
  'independent_verifier',
  'journal_broker',
  'scanner',
  'trusted_launcher',
]

const runtimeRoles = [
  'backup_adapter',
  'bootstrap_authority',
  'bundle_importer',
  'clearance_broker',
  'clearance_checker',
  'clearance_decider',
  'cloner_promoter',
  'collector',
  'custody_adapter',
  'database_writer',
  'handoff_broker',
  'human_submitter',
  'independent_verifier',
  'journal_broker',
  'operational_witness',
  'recovery_authority',
  'recovery_operator',
  'scanner',
  'trusted_launcher',
]

const operationalProfileKinds = ['backup', 'clearance', 'custody_adapter', 'handoff', 'journal', 'scanner_registry']
const scannerCodes = ['malware', 'personal_data', 'secrets']
const humanRoles = new Set([
  'bootstrap_authority',
  'clearance_checker',
  'clearance_decider',
  'human_submitter',
  'operational_witness',
  'recovery_authority',
  'recovery_operator',
])
const attributedRoles = new Set(['bundle_importer', 'collector', 'human_submitter'])

const expectedDatabaseContract = Object.freeze({
  complete_schema_sha256: 'f8a4704c7d4da558d58969dd28517f61a6c6a81309f23aae9578fdb9d1dd43d0',
  legacy_schema_sha256: '42dc540434eaf6ca5f41e48395d6d9d73b296a88e6384c69c9dc78e35988e9e0',
  exact_object_inventory_sha256: '8f7d5c5b119e4033b8585f1cbf874c43ee26186be4aeca319b72dcd5e785c7b7',
  prohibited_surfaces_sha256: '69d812ce6d942341ee8f13960b3dc8ca9246f9dff4b1cfa1166bdb8ed531ff00',
})

const approvedSets = new WeakMap()
const verifiedProfiles = new WeakSet()
const verifiedBindingSets = new WeakSet()
const verifiedGenerations = new WeakSet()
const verifiedApprovedRecords = new WeakMap()

export class D9ContractError extends Error {
  constructor(code, message, options) {
    super(`${code}: ${message}`, options)
    this.name = 'D9ContractError'
    this.code = code
  }
}

function fail(code, message, options) {
  throw new D9ContractError(code, message, options)
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function exactKeys(value, expected, code, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code, `${label} must be an object`)
  const actual = Object.keys(value).toSorted()
  if (canonicalize(actual) !== canonicalize([...expected].toSorted())) fail(code, `${label} has unknown or missing fields`)
}

function exactOrder(actual, expected, code, label) {
  if (!Array.isArray(actual) || canonicalize(actual) !== canonicalize(expected)) fail(code, `${label} order or membership is not approved`)
}

function unique(values, code, label) {
  if (new Set(values).size !== values.length) fail(code, `duplicate ${label}`)
}

function canonicalTimestamp(value, code, label) {
  if (
    typeof value !== 'string'
    || !/^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u.test(value)
    || Number.isNaN(Date.parse(value))
    || new Date(value).toISOString() !== value
  ) fail(code, `${label} is not a canonical real UTC timestamp`)
  return value
}

function assertSemanticTimestamps(value, code, pointer = '$') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertSemanticTimestamps(item, code, `${pointer}/${index}`))
    return
  }
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if ((key.endsWith('_at') || ['valid_from', 'valid_until', 'not_before', 'expires_at'].includes(key)) && child !== null) {
      canonicalTimestamp(child, code, `${pointer}/${key}`)
    }
    assertSemanticTimestamps(child, code, `${pointer}/${key}`)
  }
}

function assertAsOf(value) {
  if (value instanceof Date) value = value.toISOString()
  return canonicalTimestamp(value, 'RUNTIME_PROFILE_MISMATCH', 'asOf')
}

function loadJsonAndDigest(filePath, maximumBytes = 262144) {
  let bytes
  try {
    bytes = readFileBytes(filePath, { maximumBytes })
    return {
      bytes,
      digest: sha256Bytes(bytes),
      value: parseStrictJson(bytes, { maximumBytes, maximumDepth: 32, maximumMembers: 4096, contractNumbers: true }),
    }
  } catch (error) {
    if (error instanceof D9ContractError) throw error
    if (error instanceof D9JsonError) fail('INCOMPATIBLE_CONTRACT_VERSION', `invalid protected JSON at ${path.basename(filePath)}`, { cause: error })
    throw error
  }
}

function schemaTypeMatches(value, type) {
  if (type === 'null') return value === null
  if (type === 'array') return Array.isArray(value)
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value)
  if (type === 'integer') return typeof value === 'number' && Number.isSafeInteger(value)
  if (type === 'number') return typeof value === 'number' && Number.isFinite(value)
  return typeof value === type
}

function jsonPointer(root, fragment) {
  if (fragment === '' || fragment === '#') return root
  const value = fragment.startsWith('#') ? fragment.slice(1) : fragment
  if (!value.startsWith('/')) fail('INCOMPATIBLE_CONTRACT_VERSION', `unsupported schema reference ${fragment}`)
  return value.slice(1).split('/').reduce((node, part) => {
    const key = decodeURIComponent(part).replaceAll('~1', '/').replaceAll('~0', '~')
    if (!node || !Object.hasOwn(node, key)) fail('INCOMPATIBLE_CONTRACT_VERSION', `unresolved schema reference ${fragment}`)
    return node[key]
  }, root)
}

function createSchemaRegistry(entries) {
  const byId = new Map()
  const byFile = new Map()
  for (const [file, schema] of entries) {
    if (!schema || typeof schema !== 'object' || Array.isArray(schema) || typeof schema.$id !== 'string' || byId.has(schema.$id)) {
      fail('INCOMPATIBLE_CONTRACT_VERSION', `schema ${file} has a missing or duplicate identity`)
    }
    byId.set(schema.$id, schema)
    byFile.set(file, schema)
  }
  return { byId, byFile }
}

function resolveReference(reference, rootSchema, registry) {
  if (reference.startsWith('#')) return { schema: jsonPointer(rootSchema, reference), root: rootSchema }
  const hash = reference.indexOf('#')
  const id = hash === -1 ? reference : reference.slice(0, hash)
  const fragment = hash === -1 ? '' : reference.slice(hash)
  const externalRoot = registry.byId.get(id)
  if (!externalRoot) fail('INCOMPATIBLE_CONTRACT_VERSION', `unresolved external schema reference ${reference}`)
  return { schema: jsonPointer(externalRoot, fragment), root: externalRoot }
}

function validateSchemaValue(value, schema, registry, rootSchema = schema, pointer = '$') {
  if (schema.$ref) {
    const resolved = resolveReference(schema.$ref, rootSchema, registry)
    validateSchemaValue(value, resolved.schema, registry, resolved.root, pointer)
  }
  if (schema.oneOf) {
    let matches = 0
    for (const branch of schema.oneOf) {
      try {
        validateSchemaValue(value, branch, registry, rootSchema, pointer)
        matches += 1
      } catch (error) {
        if (!(error instanceof D9ContractError)) throw error
      }
    }
    if (matches !== 1) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} matched ${matches} schema branches`)
  }
  if (Object.hasOwn(schema, 'const') && !Object.is(value, schema.const)) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} differs from its required value`)
  if (schema.enum && !schema.enum.some((entry) => Object.is(entry, value))) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} is outside its closed vocabulary`)
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    if (!types.some((type) => schemaTypeMatches(value, type))) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} has the wrong type`)
  }
  if (typeof value === 'string') {
    const length = Array.from(value).length
    if (schema.minLength !== undefined && length < schema.minLength) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} is too short`)
    if (schema.maxLength !== undefined && length > schema.maxLength) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} is too long`)
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} has an invalid lexical form`)
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} is below its minimum`)
    if (schema.maximum !== undefined && value > schema.maximum) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} is above its maximum`)
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} has too few items`)
    if (schema.maxItems !== undefined && value.length > schema.maxItems) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} has too many items`)
    if (schema.uniqueItems && new Set(value.map(canonicalize)).size !== value.length) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} has duplicate items`)
    if (schema.items) value.forEach((item, index) => validateSchemaValue(item, schema.items, registry, rootSchema, `${pointer}/${index}`))
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const required of schema.required || []) {
      if (!Object.hasOwn(value, required)) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} lacks ${required}`)
    }
    for (const [key, child] of Object.entries(value)) {
      if (schema.properties?.[key]) validateSchemaValue(child, schema.properties[key], registry, rootSchema, `${pointer}/${key}`)
      else if (schema.additionalProperties === false) fail('INCOMPATIBLE_CONTRACT_VERSION', `${pointer} has unknown property ${key}`)
    }
  }
}

function assertRecordDigest(value, code) {
  if (value.record_digest_sha256 !== canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' })) {
    fail(code, 'record digest differs from its canonical payload')
  }
}

function assertClassification(classification) {
  if (classification.format !== 'jedi-atlas-d90-classifications' || classification.format_version !== '1.0.1') {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'classification identity is not D9.0.1')
  }
  assertRecordDigest(classification, 'RUNTIME_PROFILE_MISMATCH')
  if (classification.record_digest_sha256 !== APPROVED_D9_FINGERPRINTS.classification_semantic_sha256) {
    fail('RUNTIME_PROFILE_MISMATCH', 'classification semantic fingerprint is not approved')
  }
  if (canonicalSha256(classification.logical_handle_slot_rules) !== APPROVED_D9_FINGERPRINTS.global_handles_semantic_sha256) {
    fail('RUNTIME_PROFILE_MISMATCH', 'global logical-handle fingerprint is not approved')
  }
  if (canonicalSha256(classification.operation_handle_scope_rules) !== APPROVED_D9_FINGERPRINTS.operation_scopes_semantic_sha256) {
    fail('RUNTIME_PROFILE_MISMATCH', 'operation-scope fingerprint is not approved')
  }

  const grantKey = (grant) => `${grant.slot_code}|${grant.runtime_role_code}|${grant.access_code}`
  const globalGrants = classification.logical_handle_slot_rules.flatMap((slot) => slot.recipients.map((recipient) => ({ slot_code: slot.slot_code, ...recipient })))
  if (classification.logical_handle_slot_rules.length !== 13 || globalGrants.length !== 33) fail('RUNTIME_PROFILE_MISMATCH', 'global logical-handle universe is not the approved 13-slot/33-grant set')
  unique(globalGrants.map(grantKey), 'RUNTIME_PROFILE_MISMATCH', 'global logical-handle grant')
  if (classification.operation_handle_scope_rules.length !== 7) fail('RUNTIME_PROFILE_MISMATCH', 'operation-scope registry does not contain seven partitions')

  const globalKeys = globalGrants.map(grantKey).toSorted()
  const selectorKeys = classification.operation_handle_scope_policy.selector_fields
  exactOrder(selectorKeys, ['operation_mode_code', 'bundle_kind_code', 'source_authorization_code', 'permit_kind_code', 'permit_scope_code'], 'RUNTIME_PROFILE_MISMATCH', 'scope selector fields')
  unique(classification.operation_handle_scope_rules.map((rule) => canonicalize(Object.fromEntries(selectorKeys.map((key) => [key, rule[key]])))), 'RUNTIME_PROFILE_MISMATCH', 'operation-scope selector')
  for (const rule of classification.operation_handle_scope_rules) {
    const required = rule.required_handle_grants.map(grantKey)
    const forbidden = rule.forbidden_handle_grants.map(grantKey)
    unique([...required, ...forbidden], 'RUNTIME_PROFILE_MISMATCH', `${rule.operation_scope_code} partition grant`)
    exactOrder([...required, ...forbidden].toSorted(), globalKeys, 'RUNTIME_PROFILE_MISMATCH', `${rule.operation_scope_code} grant partition`)
  }
}

export function loadApprovedContractSet({ contractRoot = defaultContractRoot } = {}) {
  if (typeof contractRoot !== 'string' || contractRoot.length === 0) fail('INCOMPATIBLE_CONTRACT_VERSION', 'contract root must be a nonempty path')
  const catalogFile = path.join(contractRoot, 'contract-catalog-v1.json')
  const catalogRecord = loadJsonAndDigest(catalogFile)
  if (catalogRecord.digest !== APPROVED_D9_FINGERPRINTS.catalog_sha256) fail('RUNTIME_PROFILE_MISMATCH', 'contract catalog fingerprint is not approved')
  const catalog = catalogRecord.value
  if (catalog.format !== 'jedi-atlas-d90-contract-catalog' || catalog.format_version !== '1.0.1' || catalog.hash_profile !== 'sha256-over-exact-file-bytes') {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'contract catalog identity is not D9.0.1')
  }

  const actualSchemaFiles = fs.readdirSync(contractRoot, { withFileTypes: true })
    .filter((entry) => entry.name.endsWith('.schema.json'))
  if (actualSchemaFiles.some((entry) => !entry.isFile())) fail('INCOMPATIBLE_CONTRACT_VERSION', 'contract schema inventory contains a non-regular file')
  exactOrder(actualSchemaFiles.map((entry) => entry.name).toSorted(), schemaFiles, 'INCOMPATIBLE_CONTRACT_VERSION', 'contract schema inventory')
  exactOrder(catalog.schemas.map((entry) => entry.schema_file).toSorted(), schemaFiles, 'INCOMPATIBLE_CONTRACT_VERSION', 'catalog schema inventory')
  unique(catalog.schemas.map((entry) => entry.schema_id), 'INCOMPATIBLE_CONTRACT_VERSION', 'catalog schema identity')

  const loadedSchemas = []
  for (const entry of catalog.schemas) {
    const record = loadJsonAndDigest(path.join(contractRoot, entry.schema_file))
    if (record.digest !== entry.raw_sha256 || record.value.$id !== entry.schema_id) {
      fail('INCOMPATIBLE_CONTRACT_VERSION', `schema bytes or identity drifted for ${entry.schema_file}`)
    }
    const expectedVersion = entry.schema_file === 'runtime-profile-v1.schema.json' ? '1.0.1' : '1.0.0'
    if (entry.schema_role !== 'shared_definitions' && entry.contract_version !== expectedVersion) {
      fail('INCOMPATIBLE_CONTRACT_VERSION', `schema version drifted for ${entry.schema_file}`)
    }
    loadedSchemas.push([entry.schema_file, record.value])
  }

  const registryDefinitions = [
    ['classifications', 'classifications-v1.json', 'jedi-atlas-d90-classifications', '1.0.1'],
    ['field_registry', 'field-registry-v1.json', 'jedi-atlas-d90-field-registry', '1.0.0'],
    ['digest_profiles', 'digest-profiles-v1.json', 'jedi-atlas-d90-digest-profiles', '1.0.0'],
  ]
  const registries = {}
  for (const [catalogKey, expectedFile, expectedFormat, expectedVersion] of registryDefinitions) {
    const entry = catalog[catalogKey]
    if (!entry || entry.file !== expectedFile || entry.format !== expectedFormat || entry.format_version !== expectedVersion) {
      fail('INCOMPATIBLE_CONTRACT_VERSION', `${catalogKey} catalog entry is incompatible`)
    }
    const record = loadJsonAndDigest(path.join(contractRoot, expectedFile))
    if (record.digest !== entry.raw_sha256 || record.value.format !== expectedFormat || record.value.format_version !== expectedVersion) {
      fail('INCOMPATIBLE_CONTRACT_VERSION', `${catalogKey} bytes or identity drifted`)
    }
    registries[catalogKey] = record.value
  }
  assertClassification(registries.classifications)

  const result = deepFreeze({
    contractRoot: path.resolve(contractRoot),
    fingerprints: { ...APPROVED_D9_FINGERPRINTS },
    catalog,
    classification: registries.classifications,
    fieldRegistry: registries.field_registry,
    digestProfiles: registries.digest_profiles,
  })
  approvedSets.set(result, { schemaRegistry: createSchemaRegistry(loadedSchemas) })
  return result
}

export function assertApprovedContractSet(value) {
  if (!approvedSets.has(value)) fail('RUNTIME_PROFILE_MISMATCH', 'contract set was not loaded from approved D9.0.1 bytes')
  return value
}

function contractPrivate(contractSet) {
  assertApprovedContractSet(contractSet)
  return approvedSets.get(contractSet)
}

function parseProtectedRecord(bytes, schemaFile, contractSet, code) {
  let value
  try {
    value = parseStrictJson(bytes, { maximumBytes: 262144, maximumDepth: 32, maximumMembers: 4096, contractNumbers: true })
  } catch (error) {
    if (error instanceof D9JsonError) fail(code, 'protected record is not strict bounded D9 JSON', { cause: error })
    throw error
  }
  const registry = contractPrivate(contractSet).schemaRegistry
  const schema = registry.byFile.get(schemaFile)
  if (!schema) fail('INCOMPATIBLE_CONTRACT_VERSION', `missing approved schema ${schemaFile}`)
  try {
    validateSchemaValue(value, schema, registry)
  } catch (error) {
    if (error instanceof D9ContractError && error.code === 'INCOMPATIBLE_CONTRACT_VERSION') fail(code, 'protected record differs from its approved closed schema', { cause: error })
    throw error
  }
  let canonicalBytes
  try {
    canonicalBytes = Buffer.from(canonicalize(value), 'utf8')
  } catch (error) {
    fail(code, 'protected record is outside the D9 canonical value domain', { cause: error })
  }
  if (!Buffer.from(bytes).equals(canonicalBytes)) fail(code, 'protected record transport bytes are not canonical UTF-8')
  return value
}

export function validateApprovedRecord({ contractSet, schemaFile, recordBytes, record }) {
  assertApprovedContractSet(contractSet)
  if (typeof schemaFile !== 'string' || !contractSet.catalog.schemas.some((entry) => entry.schema_file === schemaFile && entry.schema_role !== 'shared_definitions')) {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'record schema is not an approved addressable D9.0.1 schema')
  }
  const suppliedSources = Number(recordBytes !== undefined) + Number(record !== undefined)
  if (suppliedSources !== 1) fail('INCOMPATIBLE_CONTRACT_VERSION', 'supply exactly one of recordBytes or record')

  let bytes = recordBytes
  if (record !== undefined) {
    try {
      bytes = Buffer.from(canonicalize(record), 'utf8')
    } catch (error) {
      fail('INCOMPATIBLE_CONTRACT_VERSION', 'parsed record is outside the D9 canonical value domain', { cause: error })
    }
  }
  const value = parseProtectedRecord(bytes, schemaFile, contractSet, 'INCOMPATIBLE_CONTRACT_VERSION')
  let canonicalBytes
  try {
    canonicalBytes = Buffer.from(canonicalize(value), 'utf8')
  } catch (error) {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'protected record is outside the D9 canonical value domain', { cause: error })
  }
  if (!Buffer.from(bytes).equals(canonicalBytes)) {
    fail('INCOMPATIBLE_CONTRACT_VERSION', 'protected record transport bytes are not canonical UTF-8')
  }
  assertSemanticTimestamps(value, 'INCOMPATIBLE_CONTRACT_VERSION')
  if (Object.hasOwn(value, 'record_digest_sha256')) assertRecordDigest(value, 'INCOMPATIBLE_CONTRACT_VERSION')
  deepFreeze(value)
  verifiedApprovedRecords.set(value, { contractSet, schemaFile })
  return value
}

export function assertVerifiedApprovedRecord(value, { contractSet, schemaFile } = {}) {
  const verification = verifiedApprovedRecords.get(value)
  if (!verification) fail('INCOMPATIBLE_CONTRACT_VERSION', 'record has not passed approved schema and digest verification')
  if (contractSet !== undefined && verification.contractSet !== contractSet) fail('INCOMPATIBLE_CONTRACT_VERSION', 'record was verified against a different contract set')
  if (schemaFile !== undefined && verification.schemaFile !== schemaFile) fail('INCOMPATIBLE_CONTRACT_VERSION', 'record was verified against a different schema')
  return value
}

function assertFileMap(value, keys, entryKeys, code, label) {
  exactKeys(value, keys, code, label)
  for (const key of keys) exactKeys(value[key], entryKeys, code, `${label}.${key}`)
}

function assertFileDigest(filePath, expected, code, label) {
  let actual
  try {
    actual = sha256File(filePath)
  } catch (error) {
    fail(code, `${label} is unavailable or not a stable regular file`, { cause: error })
  }
  if (actual !== expected) fail(code, `${label} digest mismatch`)
}

export function verifyRuntimeProfile({
  contractSet,
  runtimeProfileBytes,
  expectedGeneration,
  asOf,
  migrationsDirectory,
  evidenceBundleSchemaPath,
  componentFiles,
  runtimeDomainFile,
  operationalProfileFiles,
  scannerFiles,
}) {
  assertApprovedContractSet(contractSet)
  if (!Number.isSafeInteger(expectedGeneration) || expectedGeneration < 1) fail('RUNTIME_PROFILE_MISMATCH', 'expected runtime-profile generation is invalid')
  const evaluationTime = assertAsOf(asOf)
  const runtime = parseProtectedRecord(runtimeProfileBytes, 'runtime-profile-v1.schema.json', contractSet, 'RUNTIME_PROFILE_MISMATCH')
  assertRecordDigest(runtime, 'RUNTIME_PROFILE_MISMATCH')
  canonicalTimestamp(runtime.issued_at, 'RUNTIME_PROFILE_MISMATCH', 'runtime profile issued_at')
  if (runtime.issued_at > evaluationTime) fail('RUNTIME_PROFILE_MISMATCH', 'runtime profile is not yet active')
  if (runtime.profile_generation !== expectedGeneration) fail('RUNTIME_PROFILE_MISMATCH', 'runtime-profile generation differs from protected selection')
  if (runtime.contract_catalog_sha256 !== APPROVED_D9_FINGERPRINTS.catalog_sha256) fail('RUNTIME_PROFILE_MISMATCH', 'runtime profile does not pin the approved catalog')
  if (canonicalize(runtime.logical_handle_slots) !== canonicalize(contractSet.classification.logical_handle_slot_rules)) {
    fail('RUNTIME_PROFILE_MISMATCH', 'runtime logical-handle matrix differs from the approved classification')
  }
  if (canonicalize(runtime.database_contract) !== canonicalize(expectedDatabaseContract)) fail('RUNTIME_PROFILE_MISMATCH', 'database contract digests differ from the approved pilot schema')

  exactOrder(runtime.migration_hashes.map((entry) => entry.migration_name), migrationNames, 'RUNTIME_PROFILE_MISMATCH', 'migration')
  exactOrder(runtime.component_releases.map((entry) => entry.runtime_role_code), componentReleaseRoles, 'RUNTIME_PROFILE_MISMATCH', 'component release')
  exactOrder(runtime.operational_profiles.map((entry) => entry.profile_kind_code), operationalProfileKinds, 'RUNTIME_PROFILE_MISMATCH', 'operational profile')
  exactOrder(runtime.scanner_policy.required_scanners.map((entry) => entry.scanner_code), scannerCodes, 'RUNTIME_PROFILE_MISMATCH', 'scanner')

  if (typeof migrationsDirectory !== 'string' || migrationsDirectory.length === 0) fail('RUNTIME_PROFILE_MISMATCH', 'migrations directory is missing')
  const actualMigrations = fs.readdirSync(migrationsDirectory, { withFileTypes: true }).filter((entry) => entry.name.endsWith('.sql'))
  if (actualMigrations.some((entry) => !entry.isFile())) fail('RUNTIME_PROFILE_MISMATCH', 'migration inventory contains a non-regular file')
  exactOrder(actualMigrations.map((entry) => entry.name).toSorted(), migrationNames, 'RUNTIME_PROFILE_MISMATCH', 'migration file inventory')
  for (const migration of runtime.migration_hashes) {
    assertFileDigest(path.join(migrationsDirectory, migration.migration_name), migration.sha256, 'RUNTIME_PROFILE_MISMATCH', `migration ${migration.migration_name}`)
  }

  assertFileDigest(evidenceBundleSchemaPath, runtime.evidence_bundle_contract.schema_sha256, 'RUNTIME_PROFILE_MISMATCH', 'evidence-bundle schema')
  assertFileDigest(runtimeDomainFile, runtime.runtime_domain_sha256, 'RUNTIME_PROFILE_MISMATCH', 'runtime-domain marker')

  assertFileMap(componentFiles, componentReleaseRoles, ['executable', 'dependencyLock'], 'RUNTIME_PROFILE_MISMATCH', 'componentFiles')
  for (const release of runtime.component_releases) {
    const files = componentFiles[release.runtime_role_code]
    assertFileDigest(files.executable, release.executable_sha256, 'RUNTIME_PROFILE_MISMATCH', `${release.runtime_role_code} executable`)
    assertFileDigest(files.dependencyLock, release.dependency_lock_sha256, 'RUNTIME_PROFILE_MISMATCH', `${release.runtime_role_code} dependency lock`)
  }

  exactKeys(operationalProfileFiles, operationalProfileKinds, 'RUNTIME_PROFILE_MISMATCH', 'operationalProfileFiles')
  for (const profile of runtime.operational_profiles) {
    assertFileDigest(operationalProfileFiles[profile.profile_kind_code], profile.profile_sha256, 'RUNTIME_PROFILE_MISMATCH', `${profile.profile_kind_code} operational profile`)
  }

  assertFileMap(scannerFiles, scannerCodes, ['build', 'rules'], 'RUNTIME_PROFILE_MISMATCH', 'scannerFiles')
  for (const scanner of runtime.scanner_policy.required_scanners) {
    assertFileDigest(scannerFiles[scanner.scanner_code].build, scanner.build_sha256, 'RUNTIME_PROFILE_MISMATCH', `${scanner.scanner_code} scanner build`)
    assertFileDigest(scannerFiles[scanner.scanner_code].rules, scanner.rules_sha256, 'RUNTIME_PROFILE_MISMATCH', `${scanner.scanner_code} scanner rules`)
  }

  deepFreeze(runtime)
  verifiedProfiles.add(runtime)
  return runtime
}

export function verifyIdentityBindings({
  contractSet,
  runtimeProfile,
  identityBindingsBytes,
  expectedGeneration,
  asOf,
}) {
  assertApprovedContractSet(contractSet)
  if (!verifiedProfiles.has(runtimeProfile)) fail('IDENTITY_BINDING_MISMATCH', 'runtime profile was not verified against actual files')
  if (!Number.isSafeInteger(expectedGeneration) || expectedGeneration < 1) fail('IDENTITY_BINDING_MISMATCH', 'expected binding generation is invalid')
  const evaluationTime = assertAsOf(asOf)
  const identity = parseProtectedRecord(identityBindingsBytes, 'identity-bindings-v1.schema.json', contractSet, 'IDENTITY_BINDING_MISMATCH')
  assertRecordDigest(identity, 'IDENTITY_BINDING_MISMATCH')
  for (const [value, label] of [[identity.issued_at, 'identity issued_at'], [identity.expires_at, 'identity expires_at']]) {
    canonicalTimestamp(value, 'IDENTITY_BINDING_MISMATCH', label)
  }
  if (!(identity.issued_at < identity.expires_at) || !(identity.issued_at <= evaluationTime && evaluationTime < identity.expires_at)) {
    fail('IDENTITY_BINDING_MISMATCH', 'identity-binding generation is not active at the protected evaluation time')
  }
  if (runtimeProfile.issued_at > identity.issued_at) fail('IDENTITY_BINDING_MISMATCH', 'identity bindings predate their runtime profile')
  if (identity.binding_generation !== expectedGeneration) fail('IDENTITY_BINDING_MISMATCH', 'binding generation differs from protected selection')
  if (identity.runtime_profile_record_digest_sha256 !== runtimeProfile.record_digest_sha256 || identity.runtime_domain_sha256 !== runtimeProfile.runtime_domain_sha256) {
    fail('IDENTITY_BINDING_MISMATCH', 'identity bindings do not pin the verified runtime profile and domain')
  }

  exactOrder(identity.bindings.map((binding) => binding.runtime_role_code), runtimeRoles, 'IDENTITY_BINDING_MISMATCH', 'runtime-role binding')
  unique(identity.bindings.map((binding) => binding.binding_code), 'IDENTITY_BINDING_MISMATCH', 'binding code')
  unique(identity.bindings.map((binding) => binding.unix_uid), 'IDENTITY_BINDING_MISMATCH', 'Unix subject')
  const releaseByRole = new Map(runtimeProfile.component_releases.map((release) => [release.runtime_role_code, release]))
  const roleRules = new Map(contractSet.classification.runtime_role_binding_rules.map((rule) => [rule.runtime_role_code, rule]))

  for (const binding of identity.bindings) {
    for (const [value, label] of [[binding.valid_from, `${binding.binding_code} valid_from`], [binding.valid_until, `${binding.binding_code} valid_until`]]) {
      canonicalTimestamp(value, 'IDENTITY_BINDING_MISMATCH', label)
    }
    if (!(identity.issued_at <= binding.valid_from && binding.valid_from <= evaluationTime && evaluationTime < binding.valid_until && binding.valid_until <= identity.expires_at)) {
      fail('IDENTITY_BINDING_MISMATCH', `${binding.binding_code} is not active within the selected generation`)
    }
    const rule = roleRules.get(binding.runtime_role_code)
    if (
      !rule
      || binding.subject_kind_code !== 'unix_uid'
      || binding.principal_kind_code !== rule.principal_kind_code
      || binding.ipc_endpoint_code !== rule.ipc_endpoint_code
      || canonicalize(binding.allowed_operation_modes) !== canonicalize(rule.allowed_operation_modes)
    ) fail('IDENTITY_BINDING_MISMATCH', `${binding.binding_code} differs from its closed role, peer, or mode rule`)

    const human = humanRoles.has(binding.runtime_role_code)
    if (human !== (binding.principal_kind_code === 'human')) fail('IDENTITY_BINDING_MISMATCH', `${binding.binding_code} has the wrong principal kind`)
    if (human && binding.executable_sha256 !== null) fail('IDENTITY_BINDING_MISMATCH', `${binding.binding_code} gives a human an executable identity`)
    if (!human && binding.executable_sha256 !== releaseByRole.get(binding.runtime_role_code)?.executable_sha256) {
      fail('IDENTITY_BINDING_MISMATCH', `${binding.binding_code} does not bind the verified service build`)
    }
    if (attributedRoles.has(binding.runtime_role_code) !== (binding.atlas_principal_code !== null)) {
      fail('IDENTITY_BINDING_MISMATCH', `${binding.binding_code} has Atlas attribution on the wrong role`)
    }
    if (binding.atlas_principal_code === 'system.bootstrap') fail('IDENTITY_BINDING_MISMATCH', 'system.bootstrap cannot authenticate an operational role')
  }

  const byRole = new Map(identity.bindings.map((binding) => [binding.runtime_role_code, binding]))
  unique(['human_submitter', 'collector', 'bundle_importer'].map((role) => byRole.get(role).atlas_principal_code), 'IDENTITY_BINDING_MISMATCH', 'attributed Atlas principal')
  exactOrder(contractSet.classification.bootstrap_distinct_human_roles, ['human_submitter', 'operational_witness', 'bootstrap_authority'], 'IDENTITY_BINDING_MISMATCH', 'bootstrap human roles')
  unique(contractSet.classification.bootstrap_distinct_human_roles.map((role) => byRole.get(role).unix_uid), 'IDENTITY_BINDING_MISMATCH', 'bootstrap human subject')

  deepFreeze(identity)
  verifiedBindingSets.add(identity)
  return identity
}

export function verifyRuntimeGeneration({
  contractSet,
  runtimeProfileBytes,
  identityBindingsBytes,
  selection,
  asOf,
  migrationsDirectory,
  evidenceBundleSchemaPath,
  componentFiles,
  runtimeDomainFile,
  operationalProfileFiles,
  scannerFiles,
}) {
  exactKeys(selection, [
    'profile_code',
    'profile_generation',
    'runtime_profile_record_digest_sha256',
    'binding_set_code',
    'binding_generation',
    'identity_bindings_record_digest_sha256',
  ], 'RUNTIME_PROFILE_MISMATCH', 'active-generation selection')

  const runtimeProfile = verifyRuntimeProfile({
    contractSet,
    runtimeProfileBytes,
    expectedGeneration: selection.profile_generation,
    asOf,
    migrationsDirectory,
    evidenceBundleSchemaPath,
    componentFiles,
    runtimeDomainFile,
    operationalProfileFiles,
    scannerFiles,
  })
  if (runtimeProfile.profile_code !== selection.profile_code || runtimeProfile.record_digest_sha256 !== selection.runtime_profile_record_digest_sha256) {
    fail('RUNTIME_PROFILE_MISMATCH', 'runtime profile differs from the protected active-generation selection')
  }

  const identityBindings = verifyIdentityBindings({
    contractSet,
    runtimeProfile,
    identityBindingsBytes,
    expectedGeneration: selection.binding_generation,
    asOf,
  })
  if (identityBindings.binding_set_code !== selection.binding_set_code || identityBindings.record_digest_sha256 !== selection.identity_bindings_record_digest_sha256) {
    fail('IDENTITY_BINDING_MISMATCH', 'identity bindings differ from the protected active-generation selection')
  }

  const generation = deepFreeze({ selection: { ...selection }, runtimeProfile, identityBindings })
  verifiedGenerations.add(generation)
  return generation
}

export function assertVerifiedRuntimeGeneration(value) {
  if (!verifiedGenerations.has(value) || !verifiedProfiles.has(value.runtimeProfile) || !verifiedBindingSets.has(value.identityBindings)) {
    fail('RUNTIME_PROFILE_MISMATCH', 'runtime generation has not passed complete trust verification')
  }
  return value
}
