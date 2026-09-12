import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  canonicalSha256,
  canonicalize,
  parseStrictJson,
  sha256Bytes,
} from '../control-plane/canonical.mjs'
import {
  APPROVED_D9_FINGERPRINTS,
  assertApprovedContractSet,
  validateApprovedRecord,
} from '../control-plane/contracts.mjs'
import { failD931 } from './errors.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const defaultRoot = path.resolve(here, '../../docs/schema/d9-3-0')
const frozenRoot = path.resolve(here, '../../docs/schema/d9-0')

export const APPROVED_D930_FINGERPRINTS = Object.freeze({
  catalog_sha256: 'cd91f67c25941a472b89fe2fa6f19b012714dec96661b65b76ecfacf7f48e87c',
  classification_semantic_sha256: 'b61fff46a6094aeb23dfcfb0d02f808b9ac83d345a832a9d914d8de8b641a5e8',
  digest_profiles_semantic_sha256: 'c8532cd78032dba55add0b9d17d6d5625aaae887c4b2bbe3fea87c286b31e920',
  field_registry_semantic_sha256: '04293fb9885ed792516c04b11ef4608fd82cec9f4223be75b9fa8d9a93392a96',
  root_inventory_sha256: 'cf073b571a70b347ba3ea8e0e851d5d44013fe701fd9f77a235673302b423ba3',
})

const schemaFiles = Object.freeze([
  'common-v1.schema.json',
  'custody-adapter-message-v2.schema.json',
  'durability-receipt-broker-message-v1.schema.json',
  'integrity-access-lifecycle-record-v1.schema.json',
  'operation-journal-broker-message-v1.schema.json',
  'operation-journal-event-v2.schema.json',
  'operation-journal-semantic-v1.schema.json',
  'operational-profile-v1.schema.json',
  'primary-durability-receipt-v1.schema.json',
])

const approvedSets = new WeakSet()
const validatorsBySet = new WeakMap()

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

function readProtectedJson(file, maximumBytes = 4 * 1024 * 1024) {
  const stat = fs.lstatSync(file, { bigint: true })
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size > BigInt(maximumBytes)) {
    failD931('D930_CONTRACT_UNPROTECTED', `contract is not a bounded single-link regular file: ${path.basename(file)}`)
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
  try {
    const before = fs.fstatSync(descriptor, { bigint: true })
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor, { bigint: true })
    for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
      if (before[key] !== after[key]) failD931('D930_CONTRACT_CHANGED', `${path.basename(file)} changed while open`)
    }
    const value = parseStrictJson(bytes, { maximumBytes, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
    return { bytes, rawSha256: sha256Bytes(bytes), value }
  } finally {
    fs.closeSync(descriptor)
  }
}

function exactArray(actual, expected, code, label) {
  if (canonicalize(actual) !== canonicalize(expected)) failD931(code, `${label} differs from the approved contract`)
}

function rootInventorySha256(contractRoot) {
  const inventory = []
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) walk(absolute)
      else if (entry.isFile()) inventory.push({ path: path.relative(contractRoot, absolute).split(path.sep).join('/'), raw_sha256: sha256Bytes(fs.readFileSync(absolute)) })
      else failD931('D930_CONTRACT_UNPROTECTED', `special file in contract root: ${entry.name}`)
    }
  }
  walk(contractRoot)
  inventory.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
  return canonicalSha256(inventory)
}

function checkRecordDigest(record) {
  if (Object.hasOwn(record, 'record_digest_sha256') &&
      record.record_digest_sha256 !== canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' })) {
    failD931('D930_RECORD_DIGEST_MISMATCH', `${record.record_code ?? record.format} has a mismatched canonical digest`)
  }
}

function roleOf(bindingResolver, code) {
  const role = bindingResolver(code)
  if (typeof role !== 'string') failD931('D930_BINDING_UNRESOLVED', `binding is not admitted: ${code}`)
  return role
}

export function loadApprovedD930ContractSet({ contractRoot = defaultRoot, baseContractSet } = {}) {
  assertApprovedContractSet(baseContractSet)
  if (rootInventorySha256(contractRoot) !== APPROVED_D930_FINGERPRINTS.root_inventory_sha256) failD931('D930_ROOT_INVENTORY_MISMATCH', 'complete D9.3.0 contract-root inventory differs from approval')
  const catalogRecord = readProtectedJson(path.join(contractRoot, 'contract-catalog-v1.json'))
  if (catalogRecord.rawSha256 !== APPROVED_D930_FINGERPRINTS.catalog_sha256) failD931('D930_CATALOG_MISMATCH', 'catalog bytes are not approved')
  const catalog = catalogRecord.value
  if (catalog.format !== 'jedi-atlas-d930-contract-catalog' || catalog.format_version !== '1.0.0' || catalog.status_code !== 'design_only_contract_freeze') {
    failD931('D930_CATALOG_MISMATCH', 'catalog identity or lifecycle boundary is not approved')
  }
  const base = catalog.base_contract
  const expectedBase = {
    d90_catalog_sha256: APPROVED_D9_FINGERPRINTS.catalog_sha256,
    d90_classification_fingerprint_sha256: APPROVED_D9_FINGERPRINTS.classification_semantic_sha256,
    d90_global_handles_fingerprint_sha256: APPROVED_D9_FINGERPRINTS.global_handles_semantic_sha256,
    d90_operation_scopes_fingerprint_sha256: APPROVED_D9_FINGERPRINTS.operation_scopes_semantic_sha256,
  }
  if (canonicalize(base) !== canonicalize(expectedBase)) failD931('D930_BASE_CONTRACT_MISMATCH', 'D9.0.1 predecessor fingerprints differ')

  const schemas = new Map()
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  for (const file of ['common-v1.schema.json', 'custody-capability-control-v1.schema.json']) {
    const schema = readProtectedJson(path.join(frozenRoot, file)).value
    ajv.addSchema(schema)
  }
  exactArray(catalog.schemas.map((entry) => entry.schema_file).toSorted(), schemaFiles, 'D930_SCHEMA_INVENTORY_MISMATCH', 'schema inventory')
  for (const entry of catalog.schemas) {
    const loaded = readProtectedJson(path.join(contractRoot, entry.schema_file))
    if (loaded.rawSha256 !== entry.raw_sha256 || loaded.value.$id !== entry.schema_id) {
      failD931('D930_SCHEMA_MISMATCH', `${entry.schema_file} differs from its catalog entry`)
    }
    schemas.set(entry.schema_file, loaded.value)
    if (entry.schema_file !== 'common-v1.schema.json') ajv.addSchema(loaded.value)
    else ajv.addSchema(loaded.value)
  }
  const classificationsRecord = readProtectedJson(path.join(contractRoot, catalog.classifications.file))
  const digestProfilesRecord = readProtectedJson(path.join(contractRoot, catalog.digest_profiles.file))
  const fieldRegistryRecord = readProtectedJson(path.join(contractRoot, catalog.field_registry.file))
  const checks = [
    [classificationsRecord, catalog.classifications, APPROVED_D930_FINGERPRINTS.classification_semantic_sha256],
    [digestProfilesRecord, catalog.digest_profiles, APPROVED_D930_FINGERPRINTS.digest_profiles_semantic_sha256],
    [fieldRegistryRecord, catalog.field_registry, APPROVED_D930_FINGERPRINTS.field_registry_semantic_sha256],
  ]
  for (const [loaded, entry, semantic] of checks) {
    if (loaded.rawSha256 !== entry.raw_sha256 || loaded.value.record_digest_sha256 !== semantic) failD931('D930_REGISTRY_MISMATCH', `${entry.file} differs from its approved fingerprints`)
    checkRecordDigest(loaded.value)
  }

  const validators = new Map()
  for (const [file, schema] of schemas) {
    if (file === 'common-v1.schema.json') continue
    validators.set(`${schema.properties.format.const}/${schema.properties.format_version.const}`, ajv.getSchema(schema.$id))
  }
  const result = deepFreeze({
    baseContractSet,
    catalog: structuredClone(catalog),
    classifications: structuredClone(classificationsRecord.value),
    digestProfiles: structuredClone(digestProfilesRecord.value),
    fieldRegistry: structuredClone(fieldRegistryRecord.value),
  })
  approvedSets.add(result)
  validatorsBySet.set(result, validators)
  return result
}

export function assertApprovedD930ContractSet(value) {
  if (!approvedSets.has(value)) failD931('D930_CONTRACT_SET_UNTRUSTED', 'contract set was not produced by the approved loader')
  return value
}

export function validateD930Record({ contractSet, record, bindingRoleResolver = null }) {
  assertApprovedD930ContractSet(contractSet)
  const validator = validatorsBySet.get(contractSet).get(`${record?.format}/${record?.format_version}`)
  if (!validator || !validator(record)) failD931('D930_SCHEMA_REJECTED', validator ? validator.errorsText?.() ?? JSON.stringify(validator.errors) : 'unsupported format/version')
  checkRecordDigest(record)
  if (record.format === 'jedi-atlas-d930-operational-profile') {
    if (record.activation_state_code !== 'design_only_unactivated') failD931('D930_PROFILE_ACTIVATION_REJECTED', 'D9.3.1 accepts only the frozen unactivated profile')
    if (record.d930_contract_catalog_sha256 !== APPROVED_D930_FINGERPRINTS.catalog_sha256 ||
        record.d930_classification_fingerprint_sha256 !== APPROVED_D930_FINGERPRINTS.classification_semantic_sha256) {
      failD931('D930_PROFILE_FINGERPRINT_MISMATCH', 'operational profile does not pin D9.3.0')
    }
  }
  if (record.format === 'jedi-atlas-custody-adapter-message') validateAdapterSemantics(contractSet, record, bindingRoleResolver)
  return deepFreeze(structuredClone(record))
}

export function validateD90CustodyRecord({ contractSet, schemaFile = 'custody-capability-control-v1.schema.json', recordBytes, record }) {
  assertApprovedD930ContractSet(contractSet)
  return validateApprovedRecord({ contractSet: contractSet.baseContractSet, schemaFile, recordBytes, record })
}

export function validateAdapterSemantics(contractSet, message, bindingRoleResolver) {
  const rules = contractSet.classifications
  const rule = rules.custody_message_rules.find((entry) => entry.operation_code === message.operation_code)
  if (!rule) failD931('D930_ADAPTER_OPERATION_REJECTED', 'operation is outside the approved matrix')
  const request = message.message_kind_code === 'request'
  if (request !== (message.request_record_digest_sha256 === null)) failD931('D930_ADAPTER_CHAIN_REJECTED', 'request chain field is inconsistent')
  if (bindingRoleResolver) {
    const sender = roleOf(bindingRoleResolver, message.sender_binding_code)
    const recipient = roleOf(bindingRoleResolver, message.recipient_binding_code)
    const expectedSender = request ? rules.custody_message_role_rule.request_sender_role_code : rules.custody_message_role_rule.response_sender_role_code
    const expectedRecipient = request ? rules.custody_message_role_rule.request_recipient_role_code : rules.custody_message_role_rule.response_recipient_role_code
    if (sender !== expectedSender || recipient !== expectedRecipient) failD931('D930_ADAPTER_ROLE_REJECTED', 'adapter roles do not match the closed direction')
  }
  const outcome = message.payload.outcome_code
  const failure = !request && rule.failure_outcomes.includes(outcome)
  const success = !request && rule.success_outcomes.includes(outcome)
  if (!request && !failure && !success) failD931('D930_ADAPTER_OUTCOME_REJECTED', `${message.operation_code} response outcome is outside its frozen matrix`)
  const expected = request ? rule.request_nonnull_fields : failure ? ['outcome_code', 'error_code'] : rule.success_nonnull_fields
  const nonnull = Object.entries(message.payload).filter(([, value]) => value !== null).map(([key]) => key).toSorted()
  exactArray(nonnull, [...expected].toSorted(), 'D930_ADAPTER_FIELD_SET_REJECTED', `${message.operation_code}/${message.message_kind_code}/${outcome}`)
  const expectedDescriptors = request ? rule.request_descriptor_roles : failure ? [] : rule.success_descriptor_roles
  exactArray(message.ancillary_descriptors.map((entry) => entry.role_code), expectedDescriptors, 'D930_ADAPTER_DESCRIPTOR_REJECTED', 'ancillary descriptor roles')
  exactArray(message.ancillary_descriptors.map((entry) => entry.ordinal), message.ancillary_descriptors.map((_, index) => index + 1), 'D930_ADAPTER_DESCRIPTOR_REJECTED', 'ancillary descriptor ordinals')
  const exactBackendReference = (artifact, backendReference) => {
    if (backendReference !== `objects/sha256/${artifact.sha256.slice(0, 2)}/${artifact.sha256}`) failD931('D930_ADAPTER_BACKEND_REFERENCE_REJECTED', 'backend reference does not project the exact artifact identity')
  }
  if (message.payload.custody_intent) {
    if (message.payload.custody_intent.custody_event_code !== 'placement') failD931('D930_ADAPTER_CUSTODY_INTENT_REJECTED', 'Tranche 2A placement is the only reachable custody intent')
    exactBackendReference(message.payload.custody_intent.artifact, message.payload.custody_intent.backend_reference)
  }
  if (message.operation_code === 'open_staged' && message.payload.custody_intent && message.payload.bundle_seal_record_digest_sha256 !== message.payload.custody_intent.bundle_seal_record_digest_sha256) failD931('D930_ADAPTER_CUSTODY_INTENT_REJECTED', 'opened bundle seal differs from the custody intent')
  if (message.payload.artifact && message.payload.backend_reference) exactBackendReference(message.payload.artifact, message.payload.backend_reference)
  if (success) {
    const initialPair = contractSet.classifications.capability_leaf_rules.initial_issuance_leaf_pairs.find(([operationCode]) => operationCode === message.operation_code)
    if (initialPair && message.payload[initialPair[1]] !== message.payload[initialPair[2]]) failD931('D930_ADAPTER_CAPABILITY_LEAF_REJECTED', 'initial capability record and leaf digests differ')
  }
  if (failure) {
    const error = rules.custody_failure_error_rules.find((entry) => entry.outcome_code === outcome)
    if (!error?.allowed_error_codes.includes(message.payload.error_code)) failD931('D930_ADAPTER_ERROR_REJECTED', 'failure error is not approved')
  }
  return true
}

export function canonicalRecord(record) {
  const clone = structuredClone(record)
  clone.record_digest_sha256 = canonicalSha256(clone, { excludedTopLevelField: 'record_digest_sha256' })
  return deepFreeze(clone)
}
