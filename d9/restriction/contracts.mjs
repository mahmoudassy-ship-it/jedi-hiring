import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import { canonicalSha256, canonicalize, parseStrictJson, sha256Bytes } from '../control-plane/canonical.mjs'
import {
  APPROVED_D9_FINGERPRINTS,
  assertApprovedContractSet,
  assertVerifiedRuntimeGeneration,
} from '../control-plane/contracts.mjs'
import { APPROVED_D930_FINGERPRINTS, assertApprovedD930ContractSet } from '../custody/contracts.mjs'
import { failD941 } from './errors.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const defaultRoot = path.resolve(here, '../../docs/schema/d9-4-0')
const d90Root = path.resolve(here, '../../docs/schema/d9-0')

export const APPROVED_D940_FINGERPRINTS = Object.freeze({
  catalog_sha256: '12da4237efade65cf6e2cc19d2df936e98caf505c8f6d30b38e7df8c4d349ad7',
  classification_semantic_sha256: 'be5b45a512538c50a6779566174304666c7b91b33aefed08940b3e8d9123e69d',
  digest_profiles_semantic_sha256: '86734fdc8add20399615d1d9f5d455118577509636e38f9fca20f955989eed90',
  field_registry_semantic_sha256: '0dc62b99be6e879e2c5df8416ed8b9411902f7e6af4322a4aef95ed1ba2e6ef1',
  root_inventory_sha256: '764a79a61d5a8a774f6727106305b36f12c9d6269443e152ce0fcb98e2fe4269',
})

const schemaFiles = Object.freeze([
  'access-revocation-record-v1.schema.json',
  'authority-identity-extension-v1.schema.json',
  'authority-roster-adoption-v1.schema.json',
  'authority-roster-v1.schema.json',
  'backup-coordination-record-v1.schema.json',
  'common-v1.schema.json',
  'custody-control-record-v1.schema.json',
  'deletion-execution-record-v1.schema.json',
  'deletion-receipt-v1.schema.json',
  'journal-append-receipt-v1.schema.json',
  'operational-profile-v1.schema.json',
  'recovery-assessment-v1.schema.json',
])

const approvedSets = new WeakSet()
const validatorsBySet = new WeakMap()
const approvedAuthorities = new WeakSet()

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item)
    Object.freeze(value)
  }
  return value
}

function readProtectedJson(file, maximumBytes = 4 * 1024 * 1024) {
  let descriptor
  try {
    const before = fs.lstatSync(file, { bigint: true })
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > BigInt(maximumBytes) || (before.mode & 0o022n) !== 0n) {
      failD941('D941_CONTRACT_UNPROTECTED', `${path.basename(file)} is not a protected regular file`)
    }
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
    const openedBefore = fs.fstatSync(descriptor, { bigint: true })
    const bytes = fs.readFileSync(descriptor)
    const openedAfter = fs.fstatSync(descriptor, { bigint: true })
    for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
      if (before[key] !== openedBefore[key] || openedBefore[key] !== openedAfter[key]) {
        failD941('D941_CONTRACT_CHANGED', `${path.basename(file)} changed while open`)
      }
    }
    return {
      bytes,
      rawSha256: sha256Bytes(bytes),
      value: parseStrictJson(bytes, { maximumBytes, maximumDepth: 128, maximumMembers: 100_000, contractNumbers: true }),
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

function rootInventorySha256(contractRoot) {
  const inventory = []
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) walk(absolute)
      else if (entry.isFile()) inventory.push({
        path: path.relative(contractRoot, absolute).split(path.sep).join('/'),
        raw_sha256: sha256Bytes(fs.readFileSync(absolute)),
      })
      else failD941('D941_CONTRACT_UNPROTECTED', `special file in contract root: ${entry.name}`)
    }
  }
  walk(contractRoot)
  inventory.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
  return canonicalSha256(inventory)
}

function recordDigest(record) {
  return canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' })
}

function assertRecordDigest(record) {
  if (record.record_digest_sha256 !== recordDigest(record)) {
    failD941('D941_RECORD_DIGEST_MISMATCH', `${record.record_code ?? record.format} has a mismatched digest`)
  }
}

function same(left, right) {
  return canonicalize(left) === canonicalize(right)
}

function unique(values, code, label) {
  if (new Set(values).size !== values.length) failD941(code, `duplicate ${label}`)
}

function validAt(start, end, at) {
  return start <= at && at < end
}

export function loadApprovedD940ContractSet({ contractRoot = defaultRoot, baseContractSet, d930ContractSet } = {}) {
  assertApprovedContractSet(baseContractSet)
  assertApprovedD930ContractSet(d930ContractSet)
  if (rootInventorySha256(contractRoot) !== APPROVED_D940_FINGERPRINTS.root_inventory_sha256) {
    failD941('D941_ROOT_INVENTORY_MISMATCH', 'D9.4.0 contract-root inventory differs from approval')
  }
  const loadedCatalog = readProtectedJson(path.join(contractRoot, 'contract-catalog-v1.json'))
  if (loadedCatalog.rawSha256 !== APPROVED_D940_FINGERPRINTS.catalog_sha256) {
    failD941('D941_CATALOG_MISMATCH', 'D9.4.0 catalog bytes differ from approval')
  }
  const catalog = loadedCatalog.value
  if (catalog.status_code !== 'design_only_contract_freeze') {
    failD941('D941_CATALOG_LIFECYCLE_MISMATCH', 'D9.4.0 lifecycle boundary must remain design_only_contract_freeze')
  }
  if (catalog.base_contracts.d901_catalog_sha256 !== APPROVED_D9_FINGERPRINTS.catalog_sha256 ||
      catalog.base_contracts.d930_catalog_sha256 !== APPROVED_D930_FINGERPRINTS.catalog_sha256) {
    failD941('D941_PREDECESSOR_MISMATCH', 'frozen predecessor fingerprints differ')
  }
  if (!same(catalog.schemas.map((entry) => entry.schema_file).toSorted(), [...schemaFiles].toSorted())) {
    failD941('D941_SCHEMA_INVENTORY_MISMATCH', 'D9.4.0 schema inventory differs from approval')
  }

  const ajv = new Ajv2020({ allErrors: true, strict: false })
  for (const file of ['common-v1.schema.json', 'custody-capability-control-v1.schema.json']) {
    ajv.addSchema(readProtectedJson(path.join(d90Root, file)).value)
  }
  const schemas = new Map()
  for (const entry of catalog.schemas) {
    const loaded = readProtectedJson(path.join(contractRoot, entry.schema_file))
    if (loaded.rawSha256 !== entry.raw_sha256 || loaded.value.$id !== entry.schema_id) {
      failD941('D941_SCHEMA_MISMATCH', `${entry.schema_file} differs from its catalog entry`)
    }
    schemas.set(entry.schema_file, loaded.value)
    ajv.addSchema(loaded.value)
  }
  const classifications = readProtectedJson(path.join(contractRoot, catalog.classifications.file))
  const digestProfiles = readProtectedJson(path.join(contractRoot, catalog.digest_profiles.file))
  const fieldRegistry = readProtectedJson(path.join(contractRoot, catalog.field_registry.file))
  for (const [loaded, entry, expected, label] of [
    [classifications, catalog.classifications, APPROVED_D940_FINGERPRINTS.classification_semantic_sha256, 'classification'],
    [digestProfiles, catalog.digest_profiles, APPROVED_D940_FINGERPRINTS.digest_profiles_semantic_sha256, 'digest profiles'],
    [fieldRegistry, catalog.field_registry, APPROVED_D940_FINGERPRINTS.field_registry_semantic_sha256, 'field registry'],
  ]) {
    if (loaded.rawSha256 !== entry.raw_sha256 || loaded.value.record_digest_sha256 !== expected || recordDigest(loaded.value) !== expected) {
      failD941('D941_REGISTRY_MISMATCH', `${label} differs from approval`)
    }
  }
  const validators = new Map()
  for (const [file, schema] of schemas) {
    if (file === 'common-v1.schema.json') continue
    validators.set(`${schema.properties.format.const}/${schema.properties.format_version.const}`, ajv.getSchema(schema.$id))
  }
  const result = deepFreeze({
    baseContractSet,
    d930ContractSet,
    catalog: structuredClone(catalog),
    classifications: structuredClone(classifications.value),
    digestProfiles: structuredClone(digestProfiles.value),
    fieldRegistry: structuredClone(fieldRegistry.value),
  })
  approvedSets.add(result)
  validatorsBySet.set(result, validators)
  return result
}

export function assertApprovedD940ContractSet(value) {
  if (!approvedSets.has(value)) failD941('D941_CONTRACT_SET_UNTRUSTED', 'contract set was not loaded through the approved D9.4.0 path')
  return value
}

export function validateD940Record({ contractSet, record }) {
  assertApprovedD940ContractSet(contractSet)
  const validator = validatorsBySet.get(contractSet).get(`${record?.format}/${record?.format_version}`)
  if (!validator || !validator(record)) {
    failD941('D941_SCHEMA_REJECTED', validator ? JSON.stringify(validator.errors) : 'unsupported format/version')
  }
  assertRecordDigest(record)
  if (record.subject) {
    const computed = canonicalSha256({
      subject_kind_code: record.subject.subject_kind_code,
      subject_payload: record.subject.subject_payload,
    })
    if (computed !== record.subject.subject_identity_sha256) failD941('D941_SUBJECT_IDENTITY_MISMATCH', record.record_code)
  }
  return deepFreeze(structuredClone(record))
}

function rosterAdoptionScope(roster, generation) {
  return canonicalSha256({
    authority_roster_record_digest_sha256: roster.record_digest_sha256,
    identity_bindings_record_digest_sha256: generation.identityBindings.record_digest_sha256,
    binding_set_code: generation.identityBindings.binding_set_code,
    binding_generation: generation.identityBindings.binding_generation,
    authority_identity_extension_record_digest_sha256: roster.authority_identity_extension_record_digest_sha256,
    authority_identity_extension_generation: roster.authority_identity_extension_generation,
    roster_generation: roster.roster_generation,
  })
}

export function verifyD940AuthorityContext({
  contractSet,
  verifiedGeneration,
  operationalProfile,
  authorityIdentityExtension,
  authorityRoster,
  authorityRosterAdoption,
  asOf,
}) {
  assertApprovedD940ContractSet(contractSet)
  assertVerifiedRuntimeGeneration(verifiedGeneration)
  for (const record of [operationalProfile, authorityIdentityExtension, authorityRoster, authorityRosterAdoption]) {
    validateD940Record({ contractSet, record })
  }
  const identity = verifiedGeneration.identityBindings
  if (operationalProfile.activation_state_code !== 'design_only_unactivated' ||
      operationalProfile.settings.operational_execution_code !== 'unimplemented' ||
      operationalProfile.d940_catalog_sha256 !== APPROVED_D940_FINGERPRINTS.catalog_sha256 ||
      operationalProfile.d940_classification_fingerprint_sha256 !== APPROVED_D940_FINGERPRINTS.classification_semantic_sha256) {
    failD941('D941_PROFILE_BOUNDARY_MISMATCH', 'D9.4.1 accepts only the approved synthetic/unactivated design profile')
  }
  for (const record of [authorityIdentityExtension, authorityRoster, authorityRosterAdoption]) {
    if (record.activation_state_code !== 'design_only_unactivated') {
      failD941('D941_AUTHORITY_BOUNDARY_MISMATCH', 'approved authority records must remain design_only_unactivated')
    }
  }
  const pinned = [
    authorityIdentityExtension.identity_bindings_record_digest_sha256,
    authorityRoster.identity_bindings_record_digest_sha256,
    authorityRosterAdoption.identity_bindings_record_digest_sha256,
  ]
  if (pinned.some((digest) => digest !== identity.record_digest_sha256) ||
      authorityIdentityExtension.binding_set_code !== identity.binding_set_code ||
      authorityIdentityExtension.binding_generation !== identity.binding_generation) {
    failD941('D941_IDENTITY_GENERATION_MISMATCH', 'D9.4 authority records do not pin the verified D9.0.1 generation')
  }
  const extensionBinding = authorityIdentityExtension.bindings[0]
  if (!extensionBinding || authorityIdentityExtension.bindings.length !== 1 ||
      extensionBinding.extension_role_code !== 'd940_roster_adopter' ||
      extensionBinding.principal_kind_code !== 'human' || extensionBinding.subject_kind_code !== 'unix_uid' ||
      identity.bindings.some((binding) => binding.binding_code === extensionBinding.binding_code || binding.unix_uid === extensionBinding.unix_uid || binding.atlas_principal_code === extensionBinding.principal_code)) {
    failD941('D941_AUTHORITY_EXTENSION_INVALID', 'roster-adopter extension is invalid or collides with D9.0.1')
  }
  if (!validAt(identity.issued_at, identity.expires_at, authorityIdentityExtension.issued_at) ||
      authorityIdentityExtension.expires_at > identity.expires_at ||
      !validAt(authorityIdentityExtension.issued_at, authorityIdentityExtension.expires_at, extensionBinding.valid_from) ||
      extensionBinding.valid_until > authorityIdentityExtension.expires_at) {
    failD941('D941_AUTHORITY_EXTENSION_CHRONOLOGY', 'roster-adopter extension interval is not contained')
  }
  if (authorityRoster.authority_identity_extension_record_digest_sha256 !== authorityIdentityExtension.record_digest_sha256 ||
      authorityRoster.authority_identity_extension_generation !== authorityIdentityExtension.extension_generation ||
      authorityRoster.binding_set_code !== identity.binding_set_code || authorityRoster.binding_generation !== identity.binding_generation ||
      !validAt(identity.issued_at, identity.expires_at, authorityRoster.valid_from) || authorityRoster.valid_until > identity.expires_at ||
      !validAt(authorityIdentityExtension.issued_at, authorityIdentityExtension.expires_at, authorityRoster.valid_from) || authorityRoster.valid_until > authorityIdentityExtension.expires_at) {
    failD941('D941_ROSTER_GENERATION_MISMATCH', 'authority roster is not contained by its exact identity generations')
  }

  const expectedHumanRoles = ['bootstrap_authority', 'clearance_checker', 'clearance_decider', 'human_submitter', 'operational_witness', 'recovery_authority', 'recovery_operator']
  if (!same(authorityRoster.human_identity_mappings.map((item) => item.d901_runtime_role_code), expectedHumanRoles)) {
    failD941('D941_ROSTER_HUMAN_ORDER', 'human identity mapping must preserve the frozen seven-role order')
  }
  unique(authorityRoster.human_identity_mappings.map((item) => item.binding_code), 'D941_ROSTER_HUMAN_COLLISION', 'human binding')
  unique(authorityRoster.human_identity_mappings.map((item) => item.principal_code), 'D941_ROSTER_HUMAN_COLLISION', 'human principal')
  const humanByBinding = new Map()
  for (const mapping of authorityRoster.human_identity_mappings) {
    const binding = identity.bindings.find((item) => item.binding_code === mapping.binding_code)
    if (!binding || binding.runtime_role_code !== mapping.d901_runtime_role_code || binding.principal_kind_code !== 'human' ||
        (binding.atlas_principal_code !== null && binding.atlas_principal_code !== mapping.principal_code)) {
      failD941('D941_ROSTER_HUMAN_UNRESOLVED', mapping.binding_code)
    }
    humanByBinding.set(mapping.binding_code, mapping)
  }
  if (humanByBinding.has(extensionBinding.binding_code) || [...humanByBinding.values()].some((item) => item.principal_code === extensionBinding.principal_code)) {
    failD941('D941_AUTHORITY_EXTENSION_COLLISION', 'extension identity collides with the roster generation')
  }
  const rules = contractSet.classifications.role_assignment_rules
  const expectedRoles = rules.flatMap((rule) => Array(rule.assignment_count).fill(rule.role_code))
  if (!same(authorityRoster.assignments.map((item) => item.role_code), expectedRoles)) {
    failD941('D941_ROSTER_ROLE_ORDER', 'authority assignments differ from the approved role order')
  }
  const reuseGroups = new Map()
  for (const assignment of authorityRoster.assignments) {
    const rule = rules.find((item) => item.role_code === assignment.role_code)
    const binding = identity.bindings.find((item) => item.binding_code === assignment.binding_code)
    if (!rule || !binding || assignment.actor_kind_code !== rule.actor_kind_code ||
        !rule.allowed_d901_runtime_role_codes.includes(assignment.d901_runtime_role_code) ||
        binding.runtime_role_code !== assignment.d901_runtime_role_code || binding.principal_kind_code !== assignment.actor_kind_code) {
      failD941('D941_ROSTER_ASSIGNMENT_UNRESOLVED', `${assignment.role_code}/${assignment.binding_code}`)
    }
    if (assignment.actor_kind_code === 'human') {
      const mapping = humanByBinding.get(assignment.binding_code)
      if (!mapping || assignment.principal_code !== mapping.principal_code) failD941('D941_ROSTER_PRINCIPAL_MISMATCH', assignment.binding_code)
    } else if (assignment.principal_code !== null) failD941('D941_ROSTER_SERVICE_PRINCIPAL', assignment.binding_code)
    const prior = reuseGroups.get(assignment.binding_code)
    if (prior !== undefined && prior !== rule.binding_reuse_group_code) failD941('D941_ROSTER_BINDING_REUSE', assignment.binding_code)
    reuseGroups.set(assignment.binding_code, rule.binding_reuse_group_code)
  }
  for (const rule of rules.filter((item) => item.assignment_count > 1)) {
    const assignments = authorityRoster.assignments.filter((item) => item.role_code === rule.role_code)
    unique(assignments.map((item) => item.binding_code), 'D941_ROSTER_DISTINCT_REQUIRED', `${rule.role_code} binding`)
    unique(assignments.map((item) => item.principal_code), 'D941_ROSTER_DISTINCT_REQUIRED', `${rule.role_code} principal`)
    if (rule.required_d901_runtime_role_codes && !same(assignments.map((item) => item.d901_runtime_role_code), rule.required_d901_runtime_role_codes)) {
      failD941('D941_ROSTER_EXACT_RUNTIME_SET', rule.role_code)
    }
  }
  const separated = ['deletion_executor', 'independent_verifier', 'journal_broker', 'backup_operator']
    .map((role) => authorityRoster.assignments.find((item) => item.role_code === role)?.binding_code)
  unique(separated, 'D941_SERVICE_SEPARATION', 'separated service binding')

  const scope = rosterAdoptionScope(authorityRoster, verifiedGeneration)
  if (authorityRosterAdoption.authority_roster_record_digest_sha256 !== authorityRoster.record_digest_sha256 ||
      authorityRosterAdoption.authority_identity_extension_record_digest_sha256 !== authorityIdentityExtension.record_digest_sha256 ||
      authorityRosterAdoption.identity_bindings_record_digest_sha256 !== identity.record_digest_sha256 ||
      authorityRosterAdoption.binding_set_code !== identity.binding_set_code ||
      authorityRosterAdoption.binding_generation !== identity.binding_generation ||
      authorityRosterAdoption.authority_identity_extension_generation !== authorityIdentityExtension.extension_generation ||
      authorityRosterAdoption.scope_sha256 !== scope || authorityRosterAdoption.decisions.length < 2) {
    failD941('D941_ROSTER_ADOPTION_SCOPE', 'roster adoption does not cover the exact authority context')
  }
  const decisionBindings = new Set()
  const decisionPrincipals = new Set()
  for (const decision of authorityRosterAdoption.decisions) {
    const source = decision.identity_source_code === 'd901_generation'
      ? identity.bindings.find((item) => item.binding_code === decision.binding_code)
      : authorityIdentityExtension.bindings.find((item) => item.binding_code === decision.binding_code)
    const expectedRole = decision.identity_source_code === 'd901_generation' ? source?.runtime_role_code : source?.extension_role_code
    const expectedPrincipal = decision.identity_source_code === 'd901_generation'
      ? authorityRoster.human_identity_mappings.find((item) => item.binding_code === source?.binding_code)?.principal_code
      : source?.principal_code
    if (!source || source.principal_kind_code !== 'human' || expectedRole !== decision.runtime_role_code || expectedPrincipal !== decision.principal_code ||
        decision.scope_sha256 !== scope || decision.decision_digest_sha256 !== canonicalSha256(Object.fromEntries(Object.entries(decision).filter(([key]) => key !== 'decision_digest_sha256'))) ||
        authorityRoster.assignments.some((item) => item.binding_code === decision.binding_code || (item.principal_code !== null && item.principal_code === decision.principal_code))) {
      failD941('D941_ROSTER_ADOPTION_INVALID', decision.binding_code)
    }
    if (!validAt(source.valid_from, source.valid_until, decision.decided_at) || decision.decided_at > authorityRosterAdoption.adopted_at) {
      failD941('D941_ROSTER_ADOPTION_CHRONOLOGY', decision.binding_code)
    }
    decisionBindings.add(decision.binding_code)
    decisionPrincipals.add(decision.principal_code)
  }
  if (decisionBindings.size !== authorityRosterAdoption.decisions.length || decisionPrincipals.size !== authorityRosterAdoption.decisions.length ||
      !validAt(authorityRoster.valid_from, authorityRoster.valid_until, authorityRosterAdoption.adopted_at) ||
      !validAt(authorityRoster.valid_from, authorityRoster.valid_until, asOf) || !validAt(identity.issued_at, identity.expires_at, asOf)) {
    failD941('D941_ROSTER_ADOPTION_INDEPENDENCE', 'roster adoption or active evaluation boundary is invalid')
  }
  const result = deepFreeze({
    contractSet,
    verifiedGeneration,
    operationalProfile: structuredClone(operationalProfile),
    authorityIdentityExtension: structuredClone(authorityIdentityExtension),
    authorityRoster: structuredClone(authorityRoster),
    authorityRosterAdoption: structuredClone(authorityRosterAdoption),
    verifiedAt: asOf,
  })
  approvedAuthorities.add(result)
  return result
}

export function assertVerifiedD940AuthorityContext(value) {
  if (!approvedAuthorities.has(value)) failD941('D941_AUTHORITY_CONTEXT_UNTRUSTED', 'authority context was not produced by the fixed verifier')
  return value
}

export function sealD940Record(record) {
  const result = structuredClone(record)
  result.record_digest_sha256 = recordDigest(result)
  return result
}
