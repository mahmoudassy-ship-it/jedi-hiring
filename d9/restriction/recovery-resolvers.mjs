import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import { canonicalSha256, canonicalize, parseStrictJson, sha256Bytes } from '../control-plane/canonical.mjs'
import { createDurableNamespaceStore, durableJsonBytes } from '../custody/durable-store.mjs'
import { assertD941AuthenticatedSession } from './admin-launcher.mjs'
import { assertD941LedgerBroker } from './ledger.mjs'
import { assertD941SyntheticCustodyEvidence } from './custody-evidence.mjs'
import { assertD941AuthorityRegistry } from './authority.mjs'
import { validateD940Record } from './contracts.mjs'
import { failD941 } from './errors.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const contractRoot = path.resolve(here, '../../docs/schema/d9-recovery-resolvers')
const durabilityContractRoot = path.resolve(here, '../../docs/schema/d9-recovery-resolvers-v1-1')
const progressionContractRoot = path.resolve(here, '../../docs/schema/d9-recovery-resolvers-v1-2')
const durabilityRootInventorySha256 = 'b3711db55ed73a1a74621a808014aae35b2e05319e5cf0aeba5df0d62b1933bf'
const progressionRootInventorySha256 = '3bc242bbd7147597e9b34aad16293d8e397cb23d4b7b7a6ca3578b371403c1ad'
const progressionSemanticVerifierSha256 = '4708ae4c43fe8bfd83e13e216b1d5fc8fc15077e6ec38e24eda78f0b859f5ad7'
const semanticVerifierSha256 = 'bc36de4475ee6d8b9fd354f80163799f431496ae91765b5dd4903fdde9763ef5'
const expectedFingerprints = Object.freeze({
  'contract-catalog-v1.json': 'df33cbf575f8f4b430ef22384f0d73350e521abed6443f07006d13bb3b968ba3',
  'classifications-v1.json': '9f137c1ca9905b5a02754292a1b828bbdd7174af78bd385b3b4a3584fd1abe04',
  'digest-profiles-v1.json': 'b7adfc736b04ef5c657e94bf2a621a602e518165cbf9b08f2b3c0653963abf90',
  'field-source-registry-v1.json': 'd6f9ec22ae8fdb6bbb998374680f13a89f02ffef2431d9eb8c6003294a3db1d8',
  'projection-profiles-v1.json': 'c9c7a09c4a29814b1a6b55112e9b11075f1e1cc654e393561e6e3d79ad1ae6ff',
  'root-inventory-v1.json': '93832dc8a6f12ae030515781169fd8ac9dd5431aa68f62699168469da3da6f31',
  'fixtures/synthetic-source-state-v1.json': '5f70546d53327940af8fd27f347745d2c8177ba3c194a9cf36397e564a6b75a4',
})

const namespaces = Object.freeze([
  'd901.capability-state.v1',
  'd901.control-state.v1',
  'd920.accepted-evidence.v1',
  'd930.custody-journal.v1',
  'd930.primary-receipts.v1',
  'd940.global.control-journal.v1',
])
const namespaceSets = Object.freeze({
  d901_control_access: Object.freeze(['d901.capability-state.v1', 'd901.control-state.v1', 'd930.custody-journal.v1', 'd940.global.control-journal.v1']),
  d920_accepted_evidence: Object.freeze(['d920.accepted-evidence.v1']),
  d930_custody: Object.freeze(['d930.custody-journal.v1', 'd930.primary-receipts.v1']),
  d940_composite_snapshot: namespaces,
})
const routes = Object.freeze({
  d901_control_access: Object.freeze(['independent_verifier', 'trusted_launcher']),
  d920_accepted_evidence: Object.freeze(['trusted_launcher', 'independent_verifier']),
  d930_custody: Object.freeze(['independent_verifier', 'journal_broker']),
  d940_composite_snapshot: Object.freeze(['trusted_launcher', 'independent_verifier']),
})
const endpoints = Object.freeze({ trusted_launcher: 'ipc.launcher', independent_verifier: 'ipc.verifier', journal_broker: 'ipc.journal' })
const runtimes = new WeakSet()
const runtimeInternals = new WeakMap()
const durabilityStores = new WeakSet()
const durabilityWriters = new WeakMap()
const syntheticTrustedClocks = new WeakSet()

export const D941_RESOLVER_NAMESPACES = Object.freeze([
  'd9.resolver.records.v1.1',
  'd9.resolver.checkpoints.v1.1',
  'd9.resolver.assessment-links.v1.1',
  'd9.resolver.progression-intents.v1.2',
  'd9.resolver.checkpoint-transitions.v1.2',
])

export function createD941SyntheticResolverClock({ authorityRegistry, launcherSession, clock }) {
  assertD941AuthorityRegistry(authorityRegistry)
  assertD941AuthenticatedSession(launcherSession, 'recovery_progression')
  if (typeof clock !== 'function') failD941('D941_RESOLVER_CONFIGURATION_INVALID', 'synthetic resolver clock requires one fixed time source')
  const trustedClock = () => {
    const value = timestamp(clock(), 'synthetic trusted resolver clock')
    const authorityHead = authorityRegistry.head()
    if (authorityHead.persistedAt !== null && value < authorityHead.persistedAt) failD941('D941_RESOLVER_TIME_ROLLBACK', 'synthetic resolver clock precedes the latest protected authority event')
    authorityRegistry.revalidateSession(launcherSession, value)
    return value
  }
  syntheticTrustedClocks.add(trustedClock)
  return trustedClock
}

function resolverAppendCode(sequence) { return `append-${String(sequence).padStart(12, '0')}` }

function assertResolverAppendEnvelope(envelope, namespaceCode, expectedSequence, expectedPredecessor) {
  const keys = [
    'format', 'format_version', 'namespace_code', 'sequence',
    'predecessor_commit_sha256', 'records', 'append_receipt', 'commit_sha256',
  ]
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
      !same(Object.keys(envelope).sort(), keys.sort()) ||
      envelope.format !== 'jedi-atlas-recovery-resolver-protected-append' ||
      envelope.format_version !== (namespaceCode.endsWith('.v1.2') ? '1.2.0' : '1.1.0') || envelope.namespace_code !== namespaceCode ||
      envelope.sequence !== expectedSequence ||
      envelope.predecessor_commit_sha256 !== expectedPredecessor ||
      !Array.isArray(envelope.records) || envelope.records.length === 0 ||
      !envelope.append_receipt || typeof envelope.append_receipt !== 'object' ||
      envelope.commit_sha256 !== canonicalSha256(envelope, { excludedTopLevelField: 'commit_sha256' })) {
    failD941('D941_RESOLVER_DURABLE_COMMIT_INVALID', 'protected resolver append envelope is malformed, gapped, forked, or corrupt')
  }
  return envelope
}

export function createD941ResolverDurabilityStore({ rootPath, expectedUid = process.getuid(), faultInjector = null } = {}) {
  const rawStore = createDurableNamespaceStore({
    rootPath,
    expectedUid,
    namespaceCodes: D941_RESOLVER_NAMESPACES,
    faultInjector,
  })
  let closed = false

  function assertOpen() {
    if (closed) failD941('D941_RESOLVER_DURABLE_STORE_CLOSED', 'protected resolver store is closed')
  }

  function entries(namespaceCode) {
    assertOpen()
    if (!D941_RESOLVER_NAMESPACES.includes(namespaceCode)) failD941('D941_RESOLVER_NAMESPACE_INVALID', 'resolver namespace is outside the closed inventory')
    const inventory = rawStore.inventory().projection[namespaceCode]
    let predecessor = null
    return inventory.map(({ record_code: code }, index) => {
      const expectedCode = resolverAppendCode(index + 1)
      if (code !== expectedCode) failD941('D941_RESOLVER_DURABLE_CHAIN_INVALID', 'protected resolver append filenames are gapped or unexpected')
      let envelope
      let retainedBytes
      try {
        retainedBytes = rawStore.read({ namespaceCode, recordCode: code })
        envelope = parseStrictJson(retainedBytes, {
          maximumBytes: 8 * 1024 * 1024,
          maximumDepth: 192,
          maximumMembers: 200_000,
          contractNumbers: true,
        })
      } catch (error) {
        failD941('D941_RESOLVER_DURABLE_COMMIT_INVALID', 'protected resolver append cannot be parsed canonically', { cause: error.message })
      }
      if (!retainedBytes.equals(durableJsonBytes(envelope))) failD941('D941_RESOLVER_DURABLE_COMMIT_INVALID', 'protected resolver append bytes are not the exact canonical UTF-8 representation')
      assertResolverAppendEnvelope(envelope, namespaceCode, index + 1, predecessor)
      predecessor = envelope.commit_sha256
      return envelope
    })
  }

  function head(namespaceCode) {
    const envelope = entries(namespaceCode).at(-1) ?? null
    const payload = envelope?.records.at(-1) ?? null
    return Object.freeze({
      namespace_code: namespaceCode,
      sequence: envelope?.sequence ?? 0,
      record_digest_sha256: payload?.record_digest_sha256 ?? null,
      commit_sha256: envelope?.commit_sha256 ?? null,
    })
  }

  function appendAtomic({ namespaceCode, expectedHead, records, appendReceipt }) {
    assertOpen()
    const current = head(namespaceCode)
    if (!same(current, expectedHead)) failD941('D941_RESOLVER_DURABLE_HEAD_MISMATCH', 'protected resolver namespace head differs from the authenticated expected head')
    const sequence = current.sequence + 1
    const envelope = {
      format: 'jedi-atlas-recovery-resolver-protected-append',
      format_version: namespaceCode.endsWith('.v1.2') ? '1.2.0' : '1.1.0',
      namespace_code: namespaceCode,
      sequence,
      predecessor_commit_sha256: current.commit_sha256,
      records: structuredClone(records),
      append_receipt: structuredClone(appendReceipt),
      commit_sha256: null,
    }
    envelope.commit_sha256 = canonicalSha256(envelope, { excludedTopLevelField: 'commit_sha256' })
    const code = resolverAppendCode(sequence)
    const result = rawStore.append({ namespaceCode, recordCode: code, bytes: durableJsonBytes(envelope), replayKey: code })
    const retained = entries(namespaceCode).at(-1)
    if (!same(retained, envelope)) failD941('D941_RESOLVER_DURABLE_REPLAY_COLLISION', 'protected resolver append replay differs from retained bytes')
    return Object.freeze({ created: result.created, envelope: structuredClone(retained), head: head(namespaceCode) })
  }

  function close() {
    if (closed) return
    closed = true
    durabilityStores.delete(store)
    durabilityWriters.delete(store)
    rawStore.close()
  }

  const store = Object.freeze({ entries, head, inventory: () => rawStore.inventory(), close })
  durabilityStores.add(store)
  durabilityWriters.set(store, appendAtomic)
  return store
}

function assertD941ResolverDurabilityStore(value) {
  if (!durabilityStores.has(value)) failD941('D941_RESOLVER_DURABLE_STORE_UNTRUSTED', 'resolver durability store was not produced by the fixed constructor')
  return value
}

function readFrozen(relativePath) {
  const absolute = path.join(contractRoot, relativePath)
  const stat = fs.lstatSync(absolute)
  if (!stat.isFile() || stat.isSymbolicLink()) failD941('D941_RESOLVER_CONTRACT_UNPROTECTED', `${relativePath} is not a regular file`)
  const bytes = fs.readFileSync(absolute)
  const expected = expectedFingerprints[relativePath]
  if (expected && sha256Bytes(bytes) !== expected) failD941('D941_RESOLVER_CONTRACT_CHANGED', `${relativePath} differs from the approved recovery-resolver freeze`)
  return parseStrictJson(bytes, { maximumBytes: 4 * 1024 * 1024, maximumDepth: 128, maximumMembers: 100_000, contractNumbers: true })
}

function readDurabilityFrozen(relativePath, expectedSha256 = null) {
  const absolute = path.join(durabilityContractRoot, relativePath)
  const stat = fs.lstatSync(absolute)
  if (!stat.isFile() || stat.isSymbolicLink()) failD941('D941_RESOLVER_CONTRACT_UNPROTECTED', `${relativePath} is not a regular v1.1 contract file`)
  const bytes = fs.readFileSync(absolute)
  if (expectedSha256 !== null && sha256Bytes(bytes) !== expectedSha256) failD941('D941_RESOLVER_CONTRACT_CHANGED', `${relativePath} differs from the approved recovery-resolver v1.1 freeze`)
  return parseStrictJson(bytes, { maximumBytes: 4 * 1024 * 1024, maximumDepth: 128, maximumMembers: 100_000, contractNumbers: true })
}

function readProgressionFrozen(relativePath, expectedSha256 = null) {
  const absolute = path.join(progressionContractRoot, relativePath)
  const stat = fs.lstatSync(absolute)
  if (!stat.isFile() || stat.isSymbolicLink()) failD941('D941_RESOLVER_CONTRACT_UNPROTECTED', `${relativePath} is not a regular v1.2 contract file`)
  const bytes = fs.readFileSync(absolute)
  if (expectedSha256 !== null && sha256Bytes(bytes) !== expectedSha256) failD941('D941_RESOLVER_CONTRACT_CHANGED', `${relativePath} differs from the approved recovery-resolver v1.2 freeze`)
  return parseStrictJson(bytes, { maximumBytes: 4 * 1024 * 1024, maximumDepth: 128, maximumMembers: 100_000, contractNumbers: true })
}

function clone(value) { return structuredClone(value) }
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child)
    Object.freeze(value)
  }
  return value
}
function same(left, right) { return canonicalize(left) === canonicalize(right) }
function plus(timestamp, deltaMs) { return new Date(Date.parse(timestamp) + deltaMs).toISOString() }
function recordDigest(record) { return canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' }) }
function projectionDigest(record) { return canonicalSha256(record, { excludedTopLevelField: 'projection_sha256' }) }
function sorted(values) { return [...values].sort((left, right) => left < right ? -1 : left > right ? 1 : 0) }
function pick(record, fields) { return Object.fromEntries(fields.map((field) => [field, record[field]])) }

function requestIdempotency(request) {
  return canonicalSha256({
    resolver_kind_code: request.resolver_kind_code, request_code: request.request_code, operation_id: request.operation_id,
    operation_nonce: request.operation_nonce, sender: request.sender, recipient: request.recipient, runtime_generation: request.runtime_generation,
    subject: request.subject, requested_at: request.requested_at, expires_at: request.expires_at, knowledge_boundary: request.knowledge_boundary,
    prior_accepted_source_heads: request.prior_accepted_source_heads, source_contract_fingerprints: request.source_contract_fingerprints,
    input_response_record_digests: request.input_response_record_digests,
  })
}

function serviceIdentity(actor) {
  return Object.fromEntries(Object.entries(actor).filter(([key]) => key !== 'binding_generation'))
}

function timestamp(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u.test(value) ||
      Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    failD941('D941_RESOLVER_TIME_INVALID', `${label} must be a canonical UTC timestamp`)
  }
  return value
}

function loadContract() {
  for (const relativePath of Object.keys(expectedFingerprints)) readFrozen(relativePath)
  const catalog = readFrozen('contract-catalog-v1.json')
  const classifications = readFrozen('classifications-v1.json')
  if (catalog.status_code !== 'design_only_contract_freeze' || catalog.instance_policy.runtime_implementation_authorized !== false || catalog.instance_policy.operational_activation_authorized !== false) {
    failD941('D941_RESOLVER_CONTRACT_BOUNDARY_INVALID', 'resolver contract does not retain its design-only, unactivated boundary')
  }
  const common = readFrozen('common-v1.schema.json')
  const request = readFrozen('resolution-request-v1.schema.json')
  const response = readFrozen('resolution-response-v1.schema.json')
  const attestation = readFrozen('append-revalidation-attestation-v1.schema.json')
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  for (const schema of [common, request, response, attestation]) ajv.addSchema(schema)
  return Object.freeze({
    catalog,
    classifications,
    sourceProfiles: new Map(classifications.source_profiles.map((item) => [item.source_namespace_code, item.source_contract_fingerprint_sha256])),
    validateRequest: ajv.getSchema(request.$id),
    validateResponse: ajv.getSchema(response.$id),
    validateAttestation: ajv.getSchema(attestation.$id),
    sourceTemplate: readFrozen('fixtures/synthetic-source-state-v1.json'),
  })
}

function loadDurabilityContract() {
  const inventory = readDurabilityFrozen('root-inventory-v1-1.json', durabilityRootInventorySha256)
  for (const file of inventory.files) readDurabilityFrozen(file.path, file.raw_sha256)
  const catalog = readDurabilityFrozen('contract-catalog-v1-1.json', 'aa846c01c5d055050c810249316d11eba7a48d1080681f9538be3e71d371bb26')
  if (catalog.status_code !== 'design_only_contract_freeze' || catalog.instance_policy.runtime_implementation_authorized !== false || catalog.instance_policy.operational_activation_authorized !== false) {
    failD941('D941_RESOLVER_CONTRACT_BOUNDARY_INVALID', 'resolver v1.1 contract does not retain its design-only, unactivated boundary')
  }
  const semanticVerifierPath = path.resolve(here, '../../docs/schema/validate-d9-recovery-resolvers.mjs')
  const semanticVerifierStat = fs.lstatSync(semanticVerifierPath)
  if (!semanticVerifierStat.isFile() || semanticVerifierStat.isSymbolicLink() || sha256Bytes(fs.readFileSync(semanticVerifierPath)) !== semanticVerifierSha256) failD941('D941_RESOLVER_DURABLE_VERIFIER_INVALID', 'approved v1 semantic verifier bytes are unavailable or changed')
  const v1Common = readFrozen('common-v1.schema.json')
  const schemas = [
    'common-v1-1.schema.json',
    'bootstrap-source-observation-v1-1.schema.json',
    'checkpoint-bootstrap-permit-v1-1.schema.json',
    'checkpoint-record-v1-1.schema.json',
    'durable-resolver-record-v1-1.schema.json',
    'append-receipt-v1-1.schema.json',
    'append-result-v1-1.schema.json',
    'recovery-assessment-link-v1-1.schema.json',
  ].map((file) => readDurabilityFrozen(file, inventory.files.find((item) => item.path === file)?.raw_sha256 ?? null))
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  ajv.addSchema(v1Common)
  for (const schema of schemas) ajv.addSchema(schema)
  return Object.freeze({
    catalog,
    inventory,
    validate: Object.freeze(Object.fromEntries(schemas.slice(1).map((schema) => [schema.$id.split('/').at(-1), ajv.getSchema(schema.$id)]))),
  })
}

function loadProgressionContract() {
  const inventory = readProgressionFrozen('root-inventory-v1-2.json', progressionRootInventorySha256)
  for (const file of inventory.files) readProgressionFrozen(file.path, file.raw_sha256)
  const catalog = readProgressionFrozen('contract-catalog-v1-2.json', 'b6fd085a5718fdccc51ae4cfbf10645aaa3a1f79929d9ebe896247350d3ddb3c')
  if (catalog.status_code !== 'design_only_contract_freeze' || catalog.instance_policy.runtime_implementation_authorized !== false || catalog.instance_policy.operational_activation_authorized !== false) {
    failD941('D941_RESOLVER_CONTRACT_BOUNDARY_INVALID', 'resolver v1.2 contract does not retain its design-only, unactivated boundary')
  }
  const verifierPath = path.resolve(here, '../../docs/schema/validate-d9-recovery-resolvers-v1-2.mjs')
  const verifierStat = fs.lstatSync(verifierPath)
  if (!verifierStat.isFile() || verifierStat.isSymbolicLink() || sha256Bytes(fs.readFileSync(verifierPath)) !== progressionSemanticVerifierSha256) failD941('D941_RESOLVER_DURABLE_VERIFIER_INVALID', 'approved v1.2 semantic verifier bytes are unavailable or changed')
  const v1Common = readFrozen('common-v1.schema.json')
  const v11Common = readDurabilityFrozen('common-v1-1.schema.json')
  const schemas = [
    'common-v1-2.schema.json',
    'assessment-append-request-v1-2.schema.json',
    'assessment-append-broker-receipt-v1-2.schema.json',
    'protected-append-receipt-v1-2.schema.json',
    'checkpoint-transition-v1-2.schema.json',
    'finalization-result-v1-2.schema.json',
  ].map((file) => readProgressionFrozen(file, inventory.files.find((item) => item.path === file)?.raw_sha256 ?? null))
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  ajv.addSchema(v1Common)
  ajv.addSchema(v11Common)
  for (const schema of schemas) ajv.addSchema(schema)
  return Object.freeze({
    catalog,
    inventory,
    validate: Object.freeze(Object.fromEntries(schemas.slice(1).map((schema) => [schema.$id.split('/').at(-1), ajv.getSchema(schema.$id)]))),
  })
}

function assertSchema(validator, value, label) {
  if (!validator(value)) failD941('D941_RESOLVER_SCHEMA_REJECTED', `${label} violates the approved schema: ${validator.errors?.map((item) => `${item.instancePath || '/'} ${item.message}`).join('; ')}`, { details: validator.errors })
}

function actorFor(authorityContext, runtimeRoleCode, at) {
  timestamp(at, `${runtimeRoleCode} evaluation time`)
  const generation = authorityContext.verifiedGeneration
  const binding = generation.identityBindings.bindings.find((item) => item.runtime_role_code === runtimeRoleCode)
  if (!binding || binding.principal_kind_code !== 'service' || !binding.allowed_operation_modes.includes('recovery') ||
      binding.ipc_endpoint_code !== endpoints[runtimeRoleCode] ||
      !(generation.identityBindings.issued_at <= at && at < generation.identityBindings.expires_at) ||
      !(binding.valid_from <= at && at < binding.valid_until)) {
    failD941('D941_RESOLVER_IDENTITY_UNAVAILABLE', `${runtimeRoleCode} is not an eligible recovery service binding`)
  }
  return Object.freeze({
    runtime_role_code: runtimeRoleCode,
    binding_code: binding.binding_code,
    endpoint_code: endpoints[runtimeRoleCode],
    executable_build_sha256: binding.executable_sha256,
  })
}

function durabilityActorFor(authorityContext, runtimeRoleCode, at) {
  const actor = actorFor(authorityContext, runtimeRoleCode, at)
  return Object.freeze({ ...actor, binding_generation: authorityContext.verifiedGeneration.identityBindings.binding_generation })
}

function runtimeGeneration(authorityContext) {
  const generation = authorityContext.verifiedGeneration
  return Object.freeze({
    runtime_profile_record_digest_sha256: generation.runtimeProfile.record_digest_sha256,
    identity_bindings_record_digest_sha256: generation.identityBindings.record_digest_sha256,
    binding_generation: generation.identityBindings.binding_generation,
  })
}

function sealRecord(record) {
  record.record_digest_sha256 = recordDigest(record)
  return record
}

function journalHead(storeHead) {
  return Object.freeze({
    namespace_code: storeHead.namespace_code,
    sequence: storeHead.sequence,
    record_digest_sha256: storeHead.record_digest_sha256,
  })
}

function assertDurabilitySchema(contract, schemaFile, value, label) {
  const validator = contract.validate[schemaFile]
  if (!validator || !validator(value)) failD941('D941_RESOLVER_DURABILITY_SCHEMA_REJECTED', `${label} violates ${schemaFile}: ${validator?.errors?.map((item) => `${item.instancePath || '/'} ${item.message}`).join('; ')}`, { details: validator?.errors })
  if (value.record_digest_sha256 !== recordDigest(value)) failD941('D941_RESOLVER_DURABILITY_DIGEST_INVALID', `${label} has an invalid self digest`)
}

function makeAppendReceipt({ namespaceCode, expectedHead, payloadRecord, persistenceActor, acceptedAt, persistedAt }) {
  return sealRecord({
    format: 'jedi-atlas-recovery-resolver-append-receipt',
    format_version: '1.1.0',
    receipt_code: `resolver.receipt.${namespaceCode.split('.').at(-2)}.${String(expectedHead.sequence + 1).padStart(8, '0')}`,
    namespace_code: namespaceCode,
    expected_predecessor: journalHead(expectedHead),
    persisted_head: { namespace_code: namespaceCode, sequence: expectedHead.sequence + 1, record_digest_sha256: payloadRecord.record_digest_sha256 },
    payload_record_digest_sha256: payloadRecord.record_digest_sha256,
    persistence_actor: persistenceActor,
    accepted_at: acceptedAt,
    persisted_at: persistedAt,
    record_digest_sha256: null,
  })
}

function receiptRecords(broker) {
  const namespaceByFormat = new Map([
    ['jedi-atlas-custody-control-record', 'control'],
    ['jedi-atlas-access-revocation-record', 'access'],
    ['jedi-atlas-deletion-execution-record', 'execution'],
    ['jedi-atlas-deletion-receipt', 'receipt'],
    ['jedi-atlas-backup-coordination-record', 'backup'],
    ['jedi-atlas-d940-recovery-assessment', 'recovery'],
  ])
  return broker.validate().map((receipt) => {
    const namespaceCode = namespaceByFormat.get(receipt.target_format)
    if (!namespaceCode) failD941('D941_RESOLVER_SOURCE_CONTRADICTORY', 'D9.4 receipt names an unknown target format')
    const record = parseStrictJson(broker.store.read({ namespaceCode, recordCode: receipt.target_record_code }), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 128, maximumMembers: 100_000, contractNumbers: true })
    if (record.record_digest_sha256 !== receipt.target_record_digest_sha256) failD941('D941_RESOLVER_SOURCE_CONTRADICTORY', 'D9.4 receipt target digest differs from protected bytes')
    return { receipt, record }
  })
}

function dynamicSourceState(template, broker, subject, custodyEvidence) {
  const state = clone(template)
  const sources = state.sources
  const subjectIdentitySha256 = subject.subject_identity_sha256
  state.subject_identity_sha256 = subjectIdentitySha256
  const lineage = sources.lineage_store
  const oldSubject = lineage.target_subject_identity_sha256
  const oldArtifact = lineage.nodes.find((node) => node.subject_identity_sha256 !== oldSubject)?.subject_identity_sha256
  const artifactIdentity = canonicalSha256({ subject_kind_code: 'artifact', artifact: subject.subject_payload.artifact })
  lineage.target_subject_identity_sha256 = subjectIdentitySha256
  for (const node of lineage.nodes) if (node.subject_identity_sha256 === oldSubject) node.subject_identity_sha256 = subjectIdentitySha256
  for (const node of lineage.nodes) if (node.subject_identity_sha256 === oldArtifact) node.subject_identity_sha256 = artifactIdentity
  for (const edge of lineage.edges) {
    if (edge.from_subject_identity_sha256 === oldSubject) edge.from_subject_identity_sha256 = subjectIdentitySha256
    if (edge.to_subject_identity_sha256 === oldSubject) edge.to_subject_identity_sha256 = subjectIdentitySha256
    if (edge.from_subject_identity_sha256 === oldArtifact) edge.from_subject_identity_sha256 = artifactIdentity
    if (edge.to_subject_identity_sha256 === oldArtifact) edge.to_subject_identity_sha256 = artifactIdentity
  }
  lineage.nodes.sort((a, b) => a.subject_identity_sha256 < b.subject_identity_sha256 ? -1 : 1)
  lineage.edges.sort((a, b) => `${a.from_subject_identity_sha256}\0${a.to_subject_identity_sha256}` < `${b.from_subject_identity_sha256}\0${b.to_subject_identity_sha256}` ? -1 : 1)
  lineage.store_snapshot.node_store_head_sha256 = canonicalSha256(lineage.nodes)
  lineage.store_snapshot.edge_store_head_sha256 = canonicalSha256(lineage.edges)
  const receipt = sources.primary_receipts.records[0]
  receipt.subject_identity_sha256 = subjectIdentitySha256
  receipt.d930_operational_profile_record_digest_sha256 = custodyEvidence.d930OperationalProfileSha256
  receipt.artifact = clone(subject.subject_payload.artifact)
  receipt.copy_code = subject.subject_payload.copy_code
  receipt.backend_code = subject.subject_payload.backend_code
  receipt.backend_reference = subject.subject_payload.backend_reference
  receipt.receipt_digest_sha256 = canonicalSha256(Object.fromEntries(Object.entries(receipt).filter(([key]) => key !== 'receipt_digest_sha256')))
  const candidate = sources.custody_candidates.records[0]
  candidate.subject_identity_sha256 = subjectIdentitySha256
  candidate.d930_operational_profile_record_digest_sha256 = custodyEvidence.d930OperationalProfileSha256
  candidate.d930_primary_durability_receipt_sha256 = receipt.receipt_digest_sha256
  candidate.artifact = clone(subject.subject_payload.artifact)
  candidate.copy_code = subject.subject_payload.copy_code
  candidate.backend_code = subject.subject_payload.backend_code
  candidate.backend_reference = subject.subject_payload.backend_reference

  const protectedRecords = receiptRecords(broker)
  const head = broker.head()
  const controls = protectedRecords
    .filter(({ record }) => record.format === 'jedi-atlas-custody-control-record')
    .map(({ receipt: journalReceipt, record }) => ({
      receipt_sequence: journalReceipt.receipt_sequence,
      record_kind_code: record.record_kind_code,
      record_digest_sha256: record.record_digest_sha256,
    }))
  sources.control_records = { known_through_receipt_sequence: head.sequence, records: controls }
  const d940Boundary = sources.source_boundaries.find((item) => item.source_namespace_code === 'd940.global.control-journal.v1')
  d940Boundary.head_sequence = head.sequence
  d940Boundary.head_persisted_at = head.persistedAt
  return state
}

function deriveD940ProtectedHead(contract, broker, sequence = broker.head().sequence) {
  const retained = receiptRecords(broker)
  if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > retained.length) failD941('D941_RESOLVER_SOURCE_HEAD_UNAVAILABLE', 'requested D9.4 receipt prefix is unavailable')
  const prefix = retained.slice(0, sequence)
  for (const [index, item] of prefix.entries()) if (item.receipt.receipt_sequence !== index + 1) failD941('D941_RESOLVER_SOURCE_CONTRADICTORY', 'D9.4 receipt prefix is not gapless')
  const last = prefix.at(-1).receipt
  const payloadCommitments = prefix.map(({ receipt, record }) => ({
    receipt_sequence: receipt.receipt_sequence,
    receipt_record_digest_sha256: receipt.record_digest_sha256,
    receipt_raw_payload_sha256: canonicalSha256(receipt),
    target_format: receipt.target_format,
    target_record_code: receipt.target_record_code,
    target_record_digest_sha256: record.record_digest_sha256,
    target_raw_payload_sha256: canonicalSha256(record),
  }))
  return Object.freeze({
    source_namespace_code: 'd940.global.control-journal.v1',
    source_contract_fingerprint_sha256: contract.sourceProfiles.get('d940.global.control-journal.v1'),
    head_sequence: sequence,
    head_digest_sha256: last.record_digest_sha256,
    head_persisted_at: last.persisted_at,
    inventory_digest_sha256: canonicalSha256({ source_namespace_code: 'd940.global.control-journal.v1', head_sequence: sequence, payload_commitments: payloadCommitments }),
  })
}

function deriveHeads(contract, sourceState, broker) {
  const heads = new Map()
  for (const boundary of sourceState.sources.source_boundaries) {
    const payloadCommitments = boundary.source_payload_codes.map((sourcePayloadCode) => ({
      source_payload_code: sourcePayloadCode,
      raw_payload_sha256: canonicalSha256(sourceState.sources[sourcePayloadCode]),
    }))
    const inventoryDigest = canonicalSha256({ source_namespace_code: boundary.source_namespace_code, head_sequence: boundary.head_sequence, payload_commitments: payloadCommitments })
    const derivedHead = canonicalSha256({ source_namespace_code: boundary.source_namespace_code, head_sequence: boundary.head_sequence, head_persisted_at: boundary.head_persisted_at, inventory_digest_sha256: inventoryDigest })
    const d940Head = boundary.source_namespace_code === 'd940.global.control-journal.v1' ? deriveD940ProtectedHead(contract, broker, boundary.head_sequence) : null
    heads.set(boundary.source_namespace_code, Object.freeze({
      source_namespace_code: boundary.source_namespace_code,
      source_contract_fingerprint_sha256: contract.sourceProfiles.get(boundary.source_namespace_code),
      head_sequence: boundary.head_sequence,
      head_digest_sha256: d940Head?.head_digest_sha256 ?? derivedHead,
      head_persisted_at: boundary.head_persisted_at,
      inventory_digest_sha256: d940Head?.inventory_digest_sha256 ?? inventoryDigest,
    }))
  }
  if (!same(sorted(heads.keys()), namespaces)) failD941('D941_RESOLVER_SOURCE_SET_INVALID', 'synthetic adapters do not expose the complete approved source set')
  return heads
}

function deriveOutputs(sourceState, heads) {
  const sources = sourceState.sources
  const control = sources.control_records.records
    .map((record) => pick(record, ['receipt_sequence', 'record_kind_code', 'record_digest_sha256']))
    .sort((a, b) => a.receipt_sequence - b.receipt_sequence)
  const sourceAccess = clone(sources.source_access_state)
  sourceAccess.capabilities.sort((a, b) => a.capability_record_digest_sha256 < b.capability_record_digest_sha256 ? -1 : 1)
  sourceAccess.descriptor_lifecycle_records.sort((a, b) => canonicalize(a) < canonicalize(b) ? -1 : 1)
  sourceAccess.adapter_message_record_digests.sort()
  const sourceAccessHash = canonicalSha256(sourceAccess)
  const terminal = sources.access_shutdown_state.capability_terminal_records.map((item) => item.terminal_record_digest_sha256).sort()
  const descriptorLeaves = [...sources.access_shutdown_state.descriptor_leaves].sort((a, b) => canonicalize(a) < canonicalize(b) ? -1 : 1)
  const shutdown = { source_access_inventory_sha256: sourceAccessHash, capability_terminal_record_digests: terminal, descriptor_leaves: descriptorLeaves }
  const acceptedReceipts = sources.accepted_receipts.records
    .map((record) => pick(record, ['bundle_sequence', 'bundle_code', 'receipt_digest_sha256']))
    .sort((a, b) => a.bundle_sequence - b.bundle_sequence)
  const logical = sources.accepted_logical_records.records
    .map((record) => pick(record, ['table_code', 'stable_key', 'record_digest_sha256']))
    .sort((a, b) => `${a.table_code}\0${a.stable_key}` < `${b.table_code}\0${b.stable_key}` ? -1 : 1)
  const lineage = clone(sources.lineage_store)
  const primaryReceipts = sources.primary_receipts.records
    .map((record) => pick(record, ['receipt_sequence', 'receipt_code', 'receipt_digest_sha256']))
    .sort((a, b) => a.receipt_sequence - b.receipt_sequence)
  const custodySource = sources.custody_candidates.records.find((record) => record.subject_identity_sha256 === sourceState.subject_identity_sha256)
  if (!custodySource) failD941('D941_RESOLVER_CUSTODY_UNAVAILABLE', 'synthetic D9.3 adapter has no exact subject custody leaf')
  const custody = pick(custodySource, ['d930_operational_profile_record_digest_sha256', 'd930_primary_durability_receipt_sha256', 'artifact', 'copy_code', 'backend_code', 'backend_reference'])
  const inventory = [...heads.values()]
    .map((head) => pick(head, ['source_namespace_code', 'head_sequence', 'inventory_digest_sha256']))
    .sort((a, b) => a.source_namespace_code < b.source_namespace_code ? -1 : 1)
  return Object.freeze({
    control_head_projection_sha256: canonicalSha256(control),
    access_head_projection_sha256: canonicalSha256(shutdown),
    accepted_receipt_prefix_sha256: canonicalSha256(acceptedReceipts),
    accepted_logical_state_sha256: canonicalSha256(logical),
    subject_lineage_projection_sha256: canonicalSha256(lineage),
    primary_receipt_prefix_sha256: canonicalSha256(primaryReceipts),
    custody_leaf_projection_sha256: canonicalSha256(custody),
    inventory_snapshot_sha256: canonicalSha256(inventory),
  })
}

function makeRequest({ contract, kind, authorityContext, subject, operationId, operationNonce, requestedAt, heads, priorHeads = null, inputDigests = [] }) {
  timestamp(requestedAt, 'resolver request time')
  const [senderRole, recipientRole] = routes[kind]
  const selected = priorHeads ?? namespaceSets[kind].map((namespace) => heads.get(namespace))
  if (selected.some((head) => head.head_persisted_at > requestedAt)) failD941('D941_RESOLVER_SOURCE_HEAD_FUTURE', 'resolver source head is later than the trusted knowledge boundary')
  const request = {
    format: 'jedi-atlas-recovery-projection-resolution-request', format_version: '1.0.0', resolver_kind_code: kind,
    request_code: `resolver.request.${kind}.${canonicalSha256({ operationId, operationNonce, kind }).slice(0, 16)}`,
    operation_id: operationId, operation_nonce: operationNonce, idempotency_key_sha256: null,
    sender: actorFor(authorityContext, senderRole, requestedAt), recipient: actorFor(authorityContext, recipientRole, requestedAt),
    runtime_generation: runtimeGeneration(authorityContext), subject,
    requested_at: requestedAt, expires_at: plus(requestedAt, 5000),
    knowledge_boundary: { known_at: requestedAt, known_through_receipt_sequence: Math.max(...selected.map((head) => head.head_sequence)), trusted_clock_role_code: 'trusted_launcher' },
    prior_accepted_source_heads: selected, source_contract_fingerprints: sorted(new Set(selected.map((head) => head.source_contract_fingerprint_sha256))),
    input_response_record_digests: inputDigests, record_digest_sha256: null,
  }
  request.idempotency_key_sha256 = requestIdempotency(request)
  request.record_digest_sha256 = recordDigest(request)
  assertSchema(contract.validateRequest, request, 'resolver request')
  return deepFreeze(request)
}

function makeObservation(before, after, beforeAt, afterAt) {
  const stable = same(before, after)
  return Object.freeze({ before, after, observed_before_at: beforeAt, observed_after_at: afterAt, stability_code: stable ? 'stable' : 'moved', source_namespace_code: before.source_namespace_code })
}

function makeProjection(kind, sourceState, heads, outputs, sourceResponses = []) {
  if (kind === 'd901_control_access') {
    const head = heads.get('d940.global.control-journal.v1')
    return { projection_kind_code: kind, journal_namespace_code: head.source_namespace_code, known_through_receipt_sequence: head.head_sequence, known_through_persisted_at: head.head_persisted_at, control_ledger_head_receipt_digest_sha256: head.head_digest_sha256, control_head_projection_sha256: outputs.control_head_projection_sha256, access_head_projection_sha256: outputs.access_head_projection_sha256, projection_sha256: null }
  }
  if (kind === 'd920_accepted_evidence') return { projection_kind_code: kind, known_through_bundle_sequence: heads.get('d920.accepted-evidence.v1').head_sequence, accepted_receipt_prefix_sha256: outputs.accepted_receipt_prefix_sha256, accepted_logical_state_sha256: outputs.accepted_logical_state_sha256, subject_lineage_projection_sha256: outputs.subject_lineage_projection_sha256, projection_sha256: null }
  if (kind === 'd930_custody') {
    const head = heads.get('d930.custody-journal.v1')
    return { projection_kind_code: kind, known_through_journal_sequence: head.head_sequence, known_through_journal_persisted_at: head.head_persisted_at, custody_journal_head_digest_sha256: head.head_digest_sha256, primary_receipt_prefix_sha256: outputs.primary_receipt_prefix_sha256, custody_leaf_projection_sha256: outputs.custody_leaf_projection_sha256, projection_sha256: null }
  }
  const [control, evidence, custody] = sourceResponses.map((item) => item.projection)
  const snapshot = { journal_namespace_code: control.journal_namespace_code, known_through_receipt_sequence: control.known_through_receipt_sequence, known_through_persisted_at: control.known_through_persisted_at, control_ledger_head_receipt_digest_sha256: control.control_ledger_head_receipt_digest_sha256, control_head_projection_sha256: control.control_head_projection_sha256, access_head_projection_sha256: control.access_head_projection_sha256, subject_lineage_projection_sha256: evidence.subject_lineage_projection_sha256, inventory_snapshot_sha256: outputs.inventory_snapshot_sha256, custody_leaf_projection_sha256: custody.custody_leaf_projection_sha256 }
  return { projection_kind_code: kind, consistency_code: 'stable_double_collect_no_atomic_global_snapshot', source_response_record_digests: sourceResponses.map((item) => item.record_digest_sha256), snapshot, snapshot_digest_sha256: canonicalSha256(snapshot), projection_sha256: null }
}

function makeResponse({ contract, request, sourceState, beforeHeads, heads, outputs, observedAt, observedAfterAt, respondedAt, sourceResponses = [] }) {
  const projection = makeProjection(request.resolver_kind_code, sourceState, heads, outputs, sourceResponses)
  projection.projection_sha256 = projectionDigest(projection)
  const response = {
    format: 'jedi-atlas-recovery-projection-resolution-response', format_version: '1.0.0', resolver_kind_code: request.resolver_kind_code,
    response_code: request.request_code.replace('resolver.request.', 'resolver.response.'), operation_id: request.operation_id,
    operation_nonce: request.operation_nonce, request_record_digest_sha256: request.record_digest_sha256,
    idempotency_key_sha256: request.idempotency_key_sha256, sender: request.recipient, recipient: request.sender,
    runtime_generation: request.runtime_generation, subject: request.subject, result_code: 'resolved', error_code: null,
    observed_at: observedAt, responded_at: respondedAt, append_revalidate_by: plus(respondedAt, 1000),
    source_observations: namespaceSets[request.resolver_kind_code].map((namespace) => makeObservation(beforeHeads.get(namespace), heads.get(namespace), observedAt, observedAfterAt)),
    projection, technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
  }
  response.record_digest_sha256 = recordDigest(response)
  assertSchema(contract.validateResponse, response, 'resolver response')
  return deepFreeze(response)
}

export function createD941SyntheticRecoveryResolverRuntime({ authorityContext, authorityRegistry, broker, subject: configuredSubject, custodyEvidence, trustedClock, durabilityStore, persistenceSession, verifierSession, finalizerSession, faultInjector = null }) {
  assertD941LedgerBroker(broker)
  assertD941AuthorityRegistry(authorityRegistry)
  assertD941SyntheticCustodyEvidence(custodyEvidence)
  assertD941ResolverDurabilityStore(durabilityStore)
  if (!authorityContext?.verifiedGeneration || authorityRegistry.authorityContext !== authorityContext || !syntheticTrustedClocks.has(trustedClock) || !persistenceSession || !verifierSession || !finalizerSession || configuredSubject?.subject_kind_code !== 'custody_copy' || typeof configuredSubject?.subject_identity_sha256 !== 'string') failD941('D941_RESOLVER_CONFIGURATION_INVALID', 'synthetic resolver requires authenticated launcher, verifier, and journal-broker sessions, one exact custody subject, one protected durability store, and a branded trusted launcher clock')
  assertD941AuthenticatedSession(persistenceSession, 'recovery_classification')
  assertD941AuthenticatedSession(verifierSession, 'recovery_projection')
  assertD941AuthenticatedSession(finalizerSession, 'recovery_progression')
  const contract = loadContract()
  const durability = loadDurabilityContract()
  const progression = loadProgressionContract()
  const expectedGeneration = runtimeGeneration(authorityContext)

  const producerSessions = Object.freeze({ trusted_launcher: finalizerSession, independent_verifier: verifierSession, journal_broker: persistenceSession })

  function authenticatedActorFor(runtimeRoleCode, at) {
    const session = producerSessions[runtimeRoleCode]
    const expectedScope = { trusted_launcher: 'recovery_progression', independent_verifier: 'recovery_projection', journal_broker: 'recovery_classification' }[runtimeRoleCode]
    assertD941AuthenticatedSession(session, expectedScope)
    authorityRegistry.revalidateSession(session, at)
    const binding = authorityContext.verifiedGeneration.identityBindings.bindings.find((item) => item.binding_code === session.actor.identity_binding.binding_code)
    const expected = durabilityActorFor(authorityContext, runtimeRoleCode, at)
    if (!binding || binding.runtime_role_code !== runtimeRoleCode || expected.binding_code !== binding.binding_code || session.exchange.authenticatedEndpointCode !== expected.endpoint_code || binding.executable_sha256 !== expected.executable_build_sha256) failD941('D941_RESOLVER_PRODUCER_UNAUTHENTICATED', `${runtimeRoleCode} producer does not match its authenticated kernel/build/endpoint binding`)
    return expected
  }

  function observe(subjectIdentitySha256) {
    if (subjectIdentitySha256 !== configuredSubject.subject_identity_sha256) failD941('D941_RESOLVER_SUBJECT_SUBSTITUTED', 'resolver request differs from the configured D9.3 custody subject')
    const sourceState = dynamicSourceState(contract.sourceTemplate, broker, configuredSubject, custodyEvidence)
    const heads = deriveHeads(contract, sourceState, broker)
    const outputs = deriveOutputs(sourceState, heads)
    return deepFreeze({ sourceState, heads, outputs })
  }

  function assertAuthorityActive(at) {
    const authorityState = authorityRegistry.stateAt(at)
    if (authorityState.revoked.size !== 0) failD941('D941_RESOLVER_AUTHORITY_REVOKED', 'resolver authority generation has a revoked required target')
  }

  function assertDurabilityActor(actor, role, at) {
    const expected = authenticatedActorFor(role, at)
    if (!same(actor, expected)) failD941('D941_RESOLVER_DURABILITY_ACTOR_INVALID', `${role} does not match the active verified binding generation`)
  }

  function validateReceipt(receipt, namespaceCode, expectedHead, payload, label) {
    assertDurabilitySchema(durability, 'append-receipt-v1-1.schema.json', receipt, `${label} receipt`)
    if (receipt.namespace_code !== namespaceCode || !same(receipt.expected_predecessor, journalHead(expectedHead)) ||
        receipt.persisted_head.sequence !== expectedHead.sequence + 1 || receipt.persisted_head.record_digest_sha256 !== payload.record_digest_sha256 ||
        receipt.payload_record_digest_sha256 !== payload.record_digest_sha256 || receipt.accepted_at > receipt.persisted_at) {
      failD941('D941_RESOLVER_DURABILITY_RECEIPT_INVALID', `${label} receipt does not bind the exact append position and payload`)
    }
    assertDurabilityActor(receipt.persistence_actor, 'journal_broker', receipt.persisted_at)
  }

  function assertV1Identity(identity, role, at, label) {
    const expected = serviceIdentity(authenticatedActorFor(role, at))
    if (!same(identity, expected)) failD941('D941_RESOLVER_DURABLE_ROUTE_INVALID', `${label} does not resolve to the exact frozen route binding`)
  }

  function assertExactSourceHeads(heads, kind, knownAt, label) {
    if (!same(heads.map((head) => head.source_namespace_code), namespaceSets[kind])) failD941('D941_RESOLVER_DURABLE_SOURCE_INVALID', `${label} does not contain the exact ordered source set`)
    for (const head of heads) {
      if (contract.sourceProfiles.get(head.source_namespace_code) !== head.source_contract_fingerprint_sha256 || head.head_persisted_at > knownAt) {
        failD941('D941_RESOLVER_DURABLE_SOURCE_INVALID', `${label} has a substituted or future source head`)
      }
    }
  }

  function assertProgressionSchema(schemaFile, value, label) {
    const validator = progression.validate[schemaFile]
    if (!validator || !validator(value)) failD941('D941_RESOLVER_PROGRESSION_SCHEMA_REJECTED', `${label} violates ${schemaFile}: ${validator?.errors?.map((item) => `${item.instancePath || '/'} ${item.message}`).join('; ')}`, { details: validator?.errors })
    if (value.record_digest_sha256 !== recordDigest(value)) failD941('D941_RESOLVER_PROGRESSION_DIGEST_INVALID', `${label} has an invalid self digest`)
  }

  function progressionHead(namespaceCode, entries) {
    const payload = entries.at(-1)?.records.at(-1) ?? null
    return { namespace_code: namespaceCode, sequence: entries.length, record_digest_sha256: payload?.record_digest_sha256 ?? null }
  }

  function checkpointReference(checkpoint, receipt) {
    return {
      checkpoint_contract_version: checkpoint.format_version,
      checkpoint_namespace_code: checkpoint.format_version === '1.2.0' ? 'd9.resolver.checkpoint-transitions.v1.2' : 'd9.resolver.checkpoints.v1.1',
      checkpoint_sequence: checkpoint.transition_sequence ?? checkpoint.sequence,
      checkpoint_record_digest_sha256: checkpoint.record_digest_sha256,
      checkpoint_append_receipt_record_digest_sha256: receipt.record_digest_sha256,
      source_heads: checkpoint.post_append_source_heads ?? checkpoint.source_heads,
      source_heads_digest_sha256: checkpoint.post_append_source_heads_digest_sha256 ?? canonicalSha256(checkpoint.source_heads),
    }
  }

  function d940SourceHead(heads) { return heads.find((item) => item.source_namespace_code === 'd940.global.control-journal.v1') }

  function assertProgressionReceipt(entry, namespaceCode, predecessor, payload, currentD940Head = null) {
    if (entry.records.length !== 1) failD941('D941_RESOLVER_PROGRESSION_BATCH_INVALID', 'progression appends contain exactly one payload')
    const receipt = entry.append_receipt
    assertProgressionSchema('protected-append-receipt-v1-2.schema.json', receipt, 'progression protected receipt')
    if (receipt.namespace_code !== namespaceCode || !same(receipt.expected_predecessor, predecessor) || receipt.persisted_head.sequence !== predecessor.sequence + 1 || receipt.persisted_head.record_digest_sha256 !== payload.record_digest_sha256 || receipt.payload_record_digest_sha256 !== payload.record_digest_sha256 || receipt.accepted_at > receipt.persisted_at) {
      failD941('D941_RESOLVER_PROGRESSION_RECEIPT_INVALID', 'progression receipt does not bind its exact protected append')
    }
    assertDurabilityActor(receipt.persistence_actor, 'journal_broker', receipt.persisted_at)
    if (namespaceCode === 'd9.resolver.checkpoint-transitions.v1.2') {
      assertDurabilityActor(receipt.source_head_observer_actor, 'independent_verifier', receipt.persisted_at)
      if (currentD940Head === null || !same(receipt.source_head_compare_and_append?.expected_head, currentD940Head) || !same(receipt.source_head_compare_and_append?.observed_head_at_persist, currentD940Head)) failD941('D941_RESOLVER_PROGRESSION_SOURCE_CAS_INVALID', 'checkpoint transition lacks the exact D9.4 source-head compare-and-append proof')
    } else if (receipt.source_head_compare_and_append !== null || receipt.source_head_observer_actor !== null) failD941('D941_RESOLVER_PROGRESSION_RECEIPT_INVALID', 'intent receipt claims an unauthorized source-head CAS')
    return receipt
  }

  function expectedD940Position(priorCheckpoint, assessment) {
    const head = d940SourceHead(priorCheckpoint.source_heads)
    return {
      journal_namespace_code: 'd940.global.control-journal.v1',
      predecessor_receipt_sequence: head.head_sequence,
      predecessor_receipt_record_digest_sha256: head.head_digest_sha256,
      target_receipt_sequence: head.head_sequence + 1,
      target_format: assessment.format,
      target_record_code: assessment.record_code,
      target_record_digest_sha256: assessment.record_digest_sha256,
      target_subject_identity_sha256: assessment.subject.subject_identity_sha256,
    }
  }

  function validateRetainedRequest(request) {
    const [senderRole, recipientRole] = routes[request.resolver_kind_code]
    assertV1Identity(request.sender, senderRole, request.requested_at, 'resolver request sender')
    assertV1Identity(request.recipient, recipientRole, request.requested_at, 'resolver request recipient')
    if (request.sender.binding_code === request.recipient.binding_code || !same(request.runtime_generation, expectedGeneration) ||
        request.requested_at < request.knowledge_boundary.known_at || request.expires_at <= request.requested_at ||
        Date.parse(request.expires_at) - Date.parse(request.requested_at) > 5000 ||
        request.knowledge_boundary.known_through_receipt_sequence !== Math.max(...request.prior_accepted_source_heads.map((head) => head.head_sequence)) ||
        request.idempotency_key_sha256 !== requestIdempotency(request)) {
      failD941('D941_RESOLVER_DURABLE_REQUEST_INVALID', 'retained request violates frozen identity, chronology, knowledge-boundary, or idempotency semantics')
    }
    assertExactSourceHeads(request.prior_accepted_source_heads, request.resolver_kind_code, request.knowledge_boundary.known_at, 'resolver request')
    const fingerprints = sorted(new Set(request.prior_accepted_source_heads.map((head) => head.source_contract_fingerprint_sha256)))
    if (!same(request.source_contract_fingerprints, fingerprints) ||
        (request.resolver_kind_code === 'd940_composite_snapshot' ? request.input_response_record_digests.length !== 3 : request.input_response_record_digests.length !== 0)) {
      failD941('D941_RESOLVER_DURABLE_REQUEST_INVALID', 'retained request has an invalid profile set or composite input set')
    }
  }

  function validateRetainedResponse(response, request) {
    assertV1Identity(response.sender, request.recipient.runtime_role_code, response.responded_at, 'resolver response sender')
    assertV1Identity(response.recipient, request.sender.runtime_role_code, response.responded_at, 'resolver response recipient')
    if (response.result_code !== 'resolved' || response.error_code !== null || response.request_record_digest_sha256 !== request.record_digest_sha256 ||
        response.idempotency_key_sha256 !== request.idempotency_key_sha256 || response.operation_id !== request.operation_id || response.operation_nonce !== request.operation_nonce ||
        !same(response.runtime_generation, request.runtime_generation) || !same(response.subject, request.subject) ||
        response.observed_at < request.requested_at || response.responded_at < response.observed_at || response.responded_at > request.expires_at ||
        response.append_revalidate_by !== plus(response.responded_at, 1000) || response.projection?.projection_kind_code !== response.resolver_kind_code ||
        response.projection?.projection_sha256 !== projectionDigest(response.projection)) {
      failD941('D941_RESOLVER_DURABLE_RESPONSE_INVALID', 'retained response violates frozen request binding, route, chronology, outcome, or projection semantics')
    }
    if (!same(response.source_observations.map((item) => item.source_namespace_code), namespaceSets[response.resolver_kind_code])) failD941('D941_RESOLVER_DURABLE_SOURCE_INVALID', 'retained response does not contain the exact ordered source observation set')
    for (const [index, observation] of response.source_observations.entries()) {
      const anchor = request.prior_accepted_source_heads[index]
      if (observation.stability_code !== 'stable' || !same(observation.before, observation.after) || !same(observation.before, anchor) ||
          observation.observed_before_at < request.requested_at || observation.observed_after_at < observation.observed_before_at || observation.observed_after_at > response.responded_at) {
        failD941('D941_RESOLVER_DURABLE_SOURCE_INVALID', 'retained resolved response is not grounded in its exact stable prior source heads')
      }
    }
    if (response.resolver_kind_code === 'd940_composite_snapshot') {
      if (!same(response.projection.source_response_record_digests, request.input_response_record_digests) ||
          response.projection.snapshot_digest_sha256 !== canonicalSha256(response.projection.snapshot)) {
        failD941('D941_RESOLVER_DURABLE_RESPONSE_INVALID', 'retained composite response does not bind its exact constituent responses and snapshot')
      }
    }
  }

  function validateRetainedAttestation(attestation, request, response) {
    assertV1Identity(attestation.sender, 'independent_verifier', attestation.completed_at, 'append attestation sender')
    assertV1Identity(attestation.recipient, 'journal_broker', attestation.completed_at, 'append attestation recipient')
    if (attestation.result_code !== 'revalidated' || attestation.error_code !== null ||
        attestation.composite_response_record_digest_sha256 !== response.record_digest_sha256 ||
        attestation.operation_id !== request.operation_id || attestation.operation_nonce !== request.operation_nonce ||
        !same(attestation.runtime_generation, request.runtime_generation) || !same(attestation.subject, request.subject) ||
        attestation.observed_at !== attestation.completed_at || attestation.completed_at < response.responded_at || attestation.completed_at > response.append_revalidate_by ||
        !same(attestation.source_heads, response.source_observations.map((item) => item.after))) {
      failD941('D941_RESOLVER_DURABLE_ATTESTATION_INVALID', 'retained append attestation does not bind the exact response, source heads, route, and freshness window')
    }
    assertExactSourceHeads(attestation.source_heads, 'd940_composite_snapshot', attestation.completed_at, 'append attestation')
  }

  function validateDurableState() {
    const checkpointEntries = durabilityStore.entries('d9.resolver.checkpoints.v1.1')
    const recordEntries = durabilityStore.entries('d9.resolver.records.v1.1')
    const linkEntries = durabilityStore.entries('d9.resolver.assessment-links.v1.1')
    const intentEntries = durabilityStore.entries('d9.resolver.progression-intents.v1.2')
    const transitionEntries = durabilityStore.entries('d9.resolver.checkpoint-transitions.v1.2')
    if (checkpointEntries.length === 0 && (recordEntries.length !== 0 || linkEntries.length !== 0 || intentEntries.length !== 0 || transitionEntries.length !== 0)) failD941('D941_RESOLVER_DURABILITY_BOOTSTRAP_MISSING', 'resolver state exists without a checkpoint bootstrap')

    const checkpoints = []
    let checkpointHead = { namespace_code: 'd9.resolver.checkpoints.v1.1', sequence: 0, record_digest_sha256: null, commit_sha256: null }
    let bootstrapPermit = null
    for (const [entryIndex, entry] of checkpointEntries.entries()) {
      const checkpoint = entry.records.at(-1)
      if (entryIndex === 0) {
        if (entry.records.length !== 8) failD941('D941_RESOLVER_BOOTSTRAP_BATCH_INVALID', 'checkpoint bootstrap must contain six observations, one permit, and one checkpoint')
        const observations = entry.records.slice(0, 6)
        bootstrapPermit = entry.records[6]
        const seenNamespaces = []
        for (const observation of observations) {
          assertDurabilitySchema(durability, 'bootstrap-source-observation-v1-1.schema.json', observation, 'bootstrap source observation')
          assertDurabilityActor(observation.semantic_actor, 'independent_verifier', observation.observed_after_at)
          assertDurabilityActor(observation.persistence_actor, 'journal_broker', observation.persisted_at)
          if (!same(observation.runtime_generation, expectedGeneration) || !same(observation.source_head_before, observation.source_head_after) || observation.observed_before_at > observation.observed_after_at || observation.observed_after_at > observation.persisted_at || observation.source_head_after.head_persisted_at > observation.observed_before_at) failD941('D941_RESOLVER_BOOTSTRAP_OBSERVATION_INVALID', 'bootstrap observation is unstable, future-dated, or belongs to another generation')
          if (contract.sourceProfiles.get(observation.source_head_after.source_namespace_code) !== observation.source_head_after.source_contract_fingerprint_sha256) failD941('D941_RESOLVER_BOOTSTRAP_OBSERVATION_INVALID', 'bootstrap observation has a substituted source contract')
          seenNamespaces.push(observation.source_head_after.source_namespace_code)
        }
        if (!same(seenNamespaces, namespaces)) failD941('D941_RESOLVER_BOOTSTRAP_OBSERVATION_INVALID', 'bootstrap observations do not cover the exact ordered source set')
        assertDurabilitySchema(durability, 'checkpoint-bootstrap-permit-v1-1.schema.json', bootstrapPermit, 'bootstrap permit')
        assertDurabilityActor(bootstrapPermit.issued_by, 'trusted_launcher', bootstrapPermit.issued_at)
        assertDurabilityActor(bootstrapPermit.persisted_by, 'journal_broker', observations[0].persisted_at)
        if (!same(bootstrapPermit.runtime_generation, expectedGeneration) || bootstrapPermit.issued_at >= bootstrapPermit.expires_at ||
            !same(bootstrapPermit.expected_empty_checkpoint_head, journalHead(checkpointHead)) ||
            !same(bootstrapPermit.initial_source_heads, observations.map((item) => item.source_head_after)) ||
            !same(bootstrapPermit.bootstrap_observation_record_digests, observations.map((item) => item.record_digest_sha256)) ||
            bootstrapPermit.source_observation_set_digest_sha256 !== canonicalSha256(bootstrapPermit.initial_source_heads) ||
            observations.some((item) => item.operation_id !== bootstrapPermit.operation_id || item.operation_nonce !== bootstrapPermit.operation_nonce || item.observed_after_at > bootstrapPermit.issued_at || item.persisted_at !== checkpoint.persisted_at)) {
          failD941('D941_RESOLVER_BOOTSTRAP_PERMIT_INVALID', 'bootstrap permit does not bind the exact stable observations and empty head')
        }
      } else if (entry.records.length !== 1) failD941('D941_RESOLVER_CHECKPOINT_BATCH_INVALID', 'checkpoint advance must contain exactly one checkpoint record')

      assertDurabilitySchema(durability, 'checkpoint-record-v1-1.schema.json', checkpoint, 'checkpoint record')
      assertDurabilityActor(checkpoint.semantic_actor, 'independent_verifier', checkpoint.observed_at)
      assertDurabilityActor(checkpoint.persistence_actor, 'journal_broker', checkpoint.persisted_at)
      if (!same(checkpoint.runtime_generation, expectedGeneration) || checkpoint.sequence !== entryIndex + 1 || checkpoint.observed_at > checkpoint.persisted_at || Date.parse(checkpoint.persisted_at) - Date.parse(checkpoint.observed_at) > 1000) failD941('D941_RESOLVER_CHECKPOINT_INVALID', 'checkpoint generation, position, or freshness is invalid')
      if (entryIndex === 0) {
        if (checkpoint.checkpoint_kind_code !== 'bootstrap' || checkpoint.predecessor_record_digest_sha256 !== null || checkpoint.bootstrap_permit_record_digest_sha256 !== bootstrapPermit.record_digest_sha256 || !same(checkpoint.source_heads, bootstrapPermit.initial_source_heads) || checkpoint.persisted_at >= bootstrapPermit.expires_at) failD941('D941_RESOLVER_CHECKPOINT_INVALID', 'initial checkpoint does not resolve to the one-use bootstrap permit')
      } else {
        const previous = checkpoints.at(-1)
        if (checkpoint.checkpoint_kind_code !== 'advance' || checkpoint.predecessor_record_digest_sha256 !== previous.record_digest_sha256 || checkpoint.persisted_at < previous.persisted_at) failD941('D941_RESOLVER_CHECKPOINT_INVALID', 'checkpoint chain is gapped, forked, rolled back, or backdated')
        for (const [index, head] of checkpoint.source_heads.entries()) {
          const prior = previous.source_heads[index]
          if (head.source_namespace_code !== prior.source_namespace_code || head.head_sequence < prior.head_sequence || (head.head_sequence === prior.head_sequence && !same(head, prior))) failD941('D941_RESOLVER_CHECKPOINT_INVALID', 'checkpoint source head is reordered, rolled back, or forked')
        }
      }
      validateReceipt(entry.append_receipt, 'd9.resolver.checkpoints.v1.1', checkpointHead, checkpoint, 'checkpoint')
      checkpointHead = { namespace_code: checkpointHead.namespace_code, sequence: checkpoint.sequence, record_digest_sha256: checkpoint.record_digest_sha256, commit_sha256: entry.commit_sha256 }
      checkpoints.push(checkpoint)
    }
    if (checkpoints.length > 1) failD941('D941_RESOLVER_PRE_RECEIPT_ADVANCE_REJECTED', 'v1.2 permits only the v1.1 bootstrap anchor; post-assessment progression must use receipt-proven v1.2 transitions')

    const durableRecords = []
    let recordHead = { namespace_code: 'd9.resolver.records.v1.1', sequence: 0, record_digest_sha256: null, commit_sha256: null }
    for (const entry of recordEntries) {
      if (entry.records.length !== 1) failD941('D941_RESOLVER_DURABLE_BATCH_INVALID', 'resolver-record append must contain exactly one wrapper')
      const wrapper = entry.records[0]
      assertDurabilitySchema(durability, 'durable-resolver-record-v1-1.schema.json', wrapper, 'durable resolver record')
      if (wrapper.sequence !== recordHead.sequence + 1 || wrapper.predecessor_record_digest_sha256 !== recordHead.record_digest_sha256 || !same(wrapper.runtime_generation, expectedGeneration) || wrapper.accepted_at > wrapper.persisted_at) failD941('D941_RESOLVER_DURABLE_CHAIN_INVALID', 'durable resolver wrapper is gapped, forked, backdated, or belongs to another generation')
      assertDurabilityActor(wrapper.semantic_actor, 'independent_verifier', wrapper.accepted_at)
      assertDurabilityActor(wrapper.persistence_actor, 'journal_broker', wrapper.persisted_at)
      const checkpoint = checkpoints.find((item) => item.sequence === wrapper.checkpoint_sequence && item.record_digest_sha256 === wrapper.checkpoint_record_digest_sha256) ??
        transitionEntries.flatMap((entry) => entry.records).find((item) => item.format === 'jedi-atlas-recovery-checkpoint-transition' && item.transition_sequence === wrapper.checkpoint_sequence && item.record_digest_sha256 === wrapper.checkpoint_record_digest_sha256)
      if (!checkpoint) failD941('D941_RESOLVER_DURABLE_CHECKPOINT_INVALID', 'durable resolver wrapper references an unknown checkpoint')
      let payload
      try { payload = parseStrictJson(Buffer.from(wrapper.payload_canonical_utf8, 'utf8'), { maximumBytes: 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true }) } catch (error) { failD941('D941_RESOLVER_DURABLE_PAYLOAD_INVALID', 'durable resolver payload is not strict canonical JSON', { cause: error.message }) }
      const payloadValidator = { request: contract.validateRequest, response: contract.validateResponse, append_attestation: contract.validateAttestation }[wrapper.record_kind_code]
      assertSchema(payloadValidator, payload, 'durable v1 resolver payload')
      const payloadResolverKind = payload.resolver_kind_code ?? 'd940_composite_snapshot'
      if (canonicalize(payload) !== wrapper.payload_canonical_utf8 || payload.record_digest_sha256 !== wrapper.payload_record_digest_sha256 || recordDigest(payload) !== payload.record_digest_sha256 || payload.format !== wrapper.payload_format || payload.operation_id !== wrapper.operation_id || payload.operation_nonce !== wrapper.operation_nonce || !same(payload.subject, wrapper.subject) || !same(payload.runtime_generation, wrapper.runtime_generation) || payloadResolverKind !== wrapper.resolver_kind_code) failD941('D941_RESOLVER_DURABLE_PAYLOAD_INVALID', 'durable wrapper does not preserve the exact verified v1 payload')
      const expectedProducer = authenticatedActorFor(payload.sender.runtime_role_code, wrapper.accepted_at)
      if (!same(wrapper.payload_producer, expectedProducer) || !same(payload.sender, serviceIdentity(expectedProducer))) failD941('D941_RESOLVER_DURABLE_PRODUCER_INVALID', 'durable wrapper producer differs from the verified v1 route binding')
      if (wrapper.semantic_verifier_sha256 !== semanticVerifierSha256) failD941('D941_RESOLVER_DURABLE_VERIFIER_INVALID', 'durable wrapper names an unapproved semantic verifier')
      const operationRecords = durableRecords.filter((item) => item.wrapper.operation_id === wrapper.operation_id && item.wrapper.operation_nonce === wrapper.operation_nonce)
      const request = operationRecords.find((item) => item.wrapper.record_kind_code === 'request' && item.payload.record_digest_sha256 === wrapper.request_record_digest_sha256)
      const response = operationRecords.find((item) => item.wrapper.record_kind_code === 'response' && item.payload.record_digest_sha256 === wrapper.response_record_digest_sha256)
      if (wrapper.record_kind_code === 'request' && (wrapper.request_record_digest_sha256 !== wrapper.payload_record_digest_sha256 || wrapper.response_record_digest_sha256 !== null || wrapper.attestation_record_digest_sha256 !== null)) failD941('D941_RESOLVER_DURABLE_LINK_INVALID', 'durable request wrapper has invalid links')
      if (wrapper.record_kind_code === 'response' && (!request || payload.request_record_digest_sha256 !== request.payload.record_digest_sha256 || wrapper.request_record_digest_sha256 !== request.payload.record_digest_sha256 || wrapper.response_record_digest_sha256 !== wrapper.payload_record_digest_sha256 || wrapper.attestation_record_digest_sha256 !== null)) failD941('D941_RESOLVER_DURABLE_LINK_INVALID', 'durable response wrapper does not resolve to its exact request')
      if (wrapper.record_kind_code === 'append_attestation' && (!request || !response || payload.composite_response_record_digest_sha256 !== response.payload.record_digest_sha256 || wrapper.request_record_digest_sha256 !== request.payload.record_digest_sha256 || wrapper.response_record_digest_sha256 !== response.payload.record_digest_sha256 || wrapper.attestation_record_digest_sha256 !== wrapper.payload_record_digest_sha256)) failD941('D941_RESOLVER_DURABLE_LINK_INVALID', 'durable attestation wrapper does not resolve to its exact request and response')
      if (wrapper.record_kind_code === 'request') validateRetainedRequest(payload)
      else if (wrapper.record_kind_code === 'response') validateRetainedResponse(payload, request.payload)
      else validateRetainedAttestation(payload, request.payload, response.payload)
      validateReceipt(entry.append_receipt, 'd9.resolver.records.v1.1', recordHead, wrapper, 'resolver record')
      recordHead = { namespace_code: recordHead.namespace_code, sequence: wrapper.sequence, record_digest_sha256: wrapper.record_digest_sha256, commit_sha256: entry.commit_sha256 }
      durableRecords.push({ wrapper, payload, receipt: entry.append_receipt })
    }

    const progressionRecords = []
    let intentHead = { namespace_code: 'd9.resolver.progression-intents.v1.2', sequence: 0, record_digest_sha256: null }
    const requestIdentities = new Set()
    for (const entry of intentEntries) {
      const payload = entry.records[0]
      const schema = payload?.format === 'jedi-atlas-recovery-checkpoint-assessment-append-request'
        ? 'assessment-append-request-v1-2.schema.json'
        : payload?.format === 'jedi-atlas-recovery-checkpoint-assessment-append-broker-receipt'
          ? 'assessment-append-broker-receipt-v1-2.schema.json' : null
      if (!schema) failD941('D941_RESOLVER_PROGRESSION_RECORD_INVALID', 'intent namespace contains an unknown payload')
      assertProgressionSchema(schema, payload, 'progression intent record')
      assertProgressionReceipt(entry, intentHead.namespace_code, intentHead, payload)
      assertDurabilityActor(payload.semantic_actor ?? payload.post_head_observer_actor, 'independent_verifier', payload.authorized_at ?? payload.post_head_observed_at)
      assertDurabilityActor(payload.broker_recipient ?? payload.broker_actor, 'journal_broker', payload.authorized_at ?? payload.accepted_at)
      if (!same(payload.runtime_generation, expectedGeneration) || payload.technical_evidence_only !== true || payload.authority_granted !== false) failD941('D941_RESOLVER_PROGRESSION_RECORD_INVALID', 'progression record has a substituted generation or grants authority')
      const identity = payload.format.endsWith('append-request')
        ? [`request:${payload.request_code}`, `operation:${payload.operation_id}`, `idempotency:${payload.idempotency_key_sha256}`]
        : [`broker:${payload.receipt_code}`, `broker-operation:${payload.operation_id}`, `broker-request:${payload.append_request_record_digest_sha256}`]
      if (identity.some((item) => requestIdentities.has(item))) failD941('D941_RESOLVER_PROGRESSION_REPLAY_COLLISION', 'progression stable identity was reused')
      identity.forEach((item) => requestIdentities.add(item))
      progressionRecords.push({ payload, receipt: entry.append_receipt })
      intentHead = { namespace_code: intentHead.namespace_code, sequence: intentHead.sequence + 1, record_digest_sha256: payload.record_digest_sha256 }
    }

    const initialCheckpoint = checkpoints[0]
    const initialCheckpointReceipt = checkpointEntries[0]?.append_receipt
    let effectiveCheckpoint = initialCheckpoint && initialCheckpointReceipt ? checkpointReference(initialCheckpoint, initialCheckpointReceipt) : null
    const transitions = []
    let transitionHead = { namespace_code: 'd9.resolver.checkpoint-transitions.v1.2', sequence: 0, record_digest_sha256: null }
    const usedProgressionRecords = new Set()
    const d940ReceiptsForProgression = transitionEntries.length === 0 ? [] : broker.validate()
    for (const entry of transitionEntries) {
      const transition = entry.records[0]
      assertProgressionSchema('checkpoint-transition-v1-2.schema.json', transition, 'checkpoint transition')
      const requestEntry = progressionRecords.find((item) => item.payload.record_digest_sha256 === transition.append_request_record_digest_sha256)
      const brokerEntry = progressionRecords.find((item) => item.payload.record_digest_sha256 === transition.append_broker_receipt_record_digest_sha256)
      if (!effectiveCheckpoint || !requestEntry || !brokerEntry || usedProgressionRecords.has(requestEntry) || usedProgressionRecords.has(brokerEntry)) failD941('D941_RESOLVER_PROGRESSION_LINK_INVALID', 'transition does not resolve to one unused request and broker receipt')
      const request = requestEntry.payload
      const brokerReceipt = brokerEntry.payload
      let assessment
      let d940Receipt
      try {
        assessment = parseStrictJson(Buffer.from(request.assessment_canonical_utf8, 'utf8'), { maximumBytes: 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
        d940Receipt = parseStrictJson(Buffer.from(brokerReceipt.d940_append_receipt_canonical_utf8, 'utf8'), { maximumBytes: 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
      } catch (error) { failD941('D941_RESOLVER_PROGRESSION_LINK_INVALID', 'progression canonical evidence is unreadable', { cause: error.message }) }
      validateD940Record({ contractSet: authorityContext.contractSet, record: assessment })
      validateD940Record({ contractSet: authorityContext.contractSet, record: d940Receipt })
      const expectedPosition = expectedD940Position(effectiveCheckpoint, assessment)
      const componentDurables = request.component_resolution_attestations.map((component) => durableRecords.find((item) => item.wrapper.record_digest_sha256 === component.component_response_durable_record_digest_sha256 && item.payload.record_digest_sha256 === component.component_response_record_digest_sha256 && item.payload.resolver_kind_code === component.resolver_kind_code))
      const compositeResponse = durableRecords.find((item) => item.wrapper.record_digest_sha256 === request.composite_response_durable_record_digest_sha256 && item.payload.record_digest_sha256 === request.composite_response_record_digest_sha256)
      const compositeAttestation = durableRecords.find((item) => item.wrapper.record_digest_sha256 === request.composite_append_attestation_durable_record_digest_sha256 && item.payload.record_digest_sha256 === request.composite_append_attestation_record_digest_sha256)
      const compositeRequest = compositeResponse && durableRecords.find((item) => item.wrapper.record_kind_code === 'request' && item.payload.record_digest_sha256 === compositeResponse.payload.request_record_digest_sha256)
      const componentDigests = componentDurables.map((item) => item?.payload.record_digest_sha256)
      const componentContextExact = componentDurables.every((item) => item && item.payload.operation_id === request.operation_id && item.payload.operation_nonce === request.operation_nonce && same(item.payload.subject, request.subject) && same(item.payload.runtime_generation, request.runtime_generation) && item.wrapper.checkpoint_sequence === effectiveCheckpoint.checkpoint_sequence && item.wrapper.checkpoint_record_digest_sha256 === effectiveCheckpoint.checkpoint_record_digest_sha256)
      if (!same(request.prior_checkpoint, effectiveCheckpoint) || !same(request.pre_append_source_heads, effectiveCheckpoint.source_heads) || request.pre_append_source_heads_digest_sha256 !== canonicalSha256(effectiveCheckpoint.source_heads) || componentDurables.some((item) => !item) || !compositeResponse || !compositeAttestation ||
          !compositeRequest || !componentContextExact || !same(componentDigests, compositeRequest.payload.input_response_record_digests) || !same(componentDigests, compositeResponse.payload.projection.source_response_record_digests) ||
          canonicalize(assessment) !== request.assessment_canonical_utf8 || assessment.record_digest_sha256 !== request.assessment_record_digest_sha256 || recordDigest(assessment) !== assessment.record_digest_sha256 || assessment.snapshot_digest_sha256 !== compositeResponse.payload.projection.snapshot_digest_sha256 || !same(assessment.snapshot, compositeResponse.payload.projection.snapshot) ||
          !same(request.expected_d940_append_position, expectedPosition) || request.idempotency_key_sha256 !== canonicalSha256({ operation_id: request.operation_id, operation_nonce: request.operation_nonce, prior_checkpoint_record_digest_sha256: effectiveCheckpoint.checkpoint_record_digest_sha256, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: expectedPosition }) || request.authorized_at !== compositeAttestation.payload.completed_at || request.append_revalidate_by !== compositeResponse.payload.append_revalidate_by || request.authorized_at >= request.append_revalidate_by) {
        const diagnostics = { checkpoint: same(request.prior_checkpoint, effectiveCheckpoint), heads: same(request.pre_append_source_heads, effectiveCheckpoint.source_heads), headsDigest: request.pre_append_source_heads_digest_sha256 === canonicalSha256(effectiveCheckpoint.source_heads), components: componentDurables.map(Boolean), compositeResponse: Boolean(compositeResponse), compositeAttestation: Boolean(compositeAttestation), assessmentCanonical: canonicalize(assessment) === request.assessment_canonical_utf8, assessmentDigest: assessment.record_digest_sha256 === request.assessment_record_digest_sha256 && recordDigest(assessment) === assessment.record_digest_sha256, snapshot: Boolean(compositeResponse) && assessment.snapshot_digest_sha256 === compositeResponse.payload.projection.snapshot_digest_sha256 && same(assessment.snapshot, compositeResponse.payload.projection.snapshot), position: same(request.expected_d940_append_position, expectedPosition), idempotency: request.idempotency_key_sha256 === canonicalSha256({ operation_id: request.operation_id, operation_nonce: request.operation_nonce, prior_checkpoint_record_digest_sha256: effectiveCheckpoint.checkpoint_record_digest_sha256, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: expectedPosition }), authorizedAt: Boolean(compositeAttestation) && request.authorized_at === compositeAttestation.payload.completed_at, deadline: Boolean(compositeResponse) && request.append_revalidate_by === compositeResponse.payload.append_revalidate_by }
        failD941('D941_RESOLVER_PROGRESSION_REQUEST_INVALID', `append request is not grounded in the exact checkpoint, durable evidence, assessment, and append position: ${JSON.stringify(diagnostics)}`, { details: diagnostics })
      }
      const retainedD940Receipt = d940ReceiptsForProgression.find((item) => item.record_digest_sha256 === d940Receipt.record_digest_sha256)
      const independentlyDerivedPostD940 = deriveD940ProtectedHead(contract, broker, d940Receipt.receipt_sequence)
      if (!retainedD940Receipt || !same(retainedD940Receipt, d940Receipt) || brokerReceipt.append_request_record_digest_sha256 !== request.record_digest_sha256 || brokerReceipt.assessment_record_digest_sha256 !== assessment.record_digest_sha256 || !same(brokerReceipt.expected_d940_append_position, expectedPosition) || !same(brokerReceipt.pre_append_source_head, d940SourceHead(effectiveCheckpoint.source_heads)) || !same(brokerReceipt.post_append_source_head, independentlyDerivedPostD940) || !same(d940SourceHead(transition.post_append_source_heads), independentlyDerivedPostD940) ||
          canonicalize(d940Receipt) !== brokerReceipt.d940_append_receipt_canonical_utf8 || brokerReceipt.d940_append_receipt_record_digest_sha256 !== d940Receipt.record_digest_sha256 || d940Receipt.receipt_sequence !== expectedPosition.target_receipt_sequence || d940Receipt.previous_receipt_record_digest_sha256 !== expectedPosition.predecessor_receipt_record_digest_sha256 || d940Receipt.target_record_digest_sha256 !== assessment.record_digest_sha256 || d940Receipt.persisted_at !== brokerReceipt.assessment_persisted_at || brokerReceipt.assessment_persisted_at > brokerReceipt.post_head_observed_at || brokerReceipt.post_head_observed_at > brokerReceipt.accepted_at) {
        failD941('D941_RESOLVER_PROGRESSION_BROKER_RECEIPT_INVALID', 'broker receipt does not prove the exact authorized D9.4 append')
      }
      const postD940 = independentlyDerivedPostD940
      const priorD940 = d940SourceHead(effectiveCheckpoint.source_heads)
      assertProgressionReceipt(entry, transitionHead.namespace_code, transitionHead, transition, postD940)
      if (transition.transition_sequence !== effectiveCheckpoint.checkpoint_sequence + 1 || transition.predecessor_checkpoint_record_digest_sha256 !== effectiveCheckpoint.checkpoint_record_digest_sha256 || transition.predecessor_checkpoint_append_receipt_record_digest_sha256 !== effectiveCheckpoint.checkpoint_append_receipt_record_digest_sha256 || !same(transition.prior_checkpoint, effectiveCheckpoint) ||
          !same(transition.component_resolution_attestations, request.component_resolution_attestations) || transition.composite_response_record_digest_sha256 !== request.composite_response_record_digest_sha256 || transition.composite_response_durable_record_digest_sha256 !== request.composite_response_durable_record_digest_sha256 || transition.composite_append_attestation_record_digest_sha256 !== request.composite_append_attestation_record_digest_sha256 || transition.composite_append_attestation_durable_record_digest_sha256 !== request.composite_append_attestation_durable_record_digest_sha256 ||
          transition.append_request_protected_receipt_record_digest_sha256 !== requestEntry.receipt.record_digest_sha256 || transition.append_broker_receipt_protected_receipt_record_digest_sha256 !== brokerEntry.receipt.record_digest_sha256 || transition.d940_append_receipt_record_digest_sha256 !== d940Receipt.record_digest_sha256 || transition.assessment_record_digest_sha256 !== assessment.record_digest_sha256 || !same(transition.expected_d940_append_position, expectedPosition) || !same(transition.pre_append_source_heads, effectiveCheckpoint.source_heads) ||
          transition.post_append_source_heads_digest_sha256 !== canonicalSha256(transition.post_append_source_heads) || postD940.head_sequence !== priorD940.head_sequence + 1 || !same(transition.permitted_d940_delta?.before, priorD940) || !same(transition.permitted_d940_delta?.after, postD940) || transition.permitted_d940_delta?.delta_code !== 'single_authorized_assessment_append' || transition.attestation_completed_at > transition.assessment_persisted_at || transition.assessment_persisted_at > transition.append_authorized_until || transition.assessment_persisted_at > transition.finalizer_observed_at || transition.finalizer_observed_at > transition.persisted_at) {
        failD941('D941_RESOLVER_PROGRESSION_TRANSITION_INVALID', 'checkpoint transition is gapped, mismatched, stale, or not the exact single authorized D9.4 delta')
      }
      for (const namespace of namespaces.filter((item) => item !== 'd940.global.control-journal.v1')) {
        if (!same(effectiveCheckpoint.source_heads.find((item) => item.source_namespace_code === namespace), transition.post_append_source_heads.find((item) => item.source_namespace_code === namespace))) failD941('D941_RESOLVER_PROGRESSION_TRANSITION_INVALID', 'checkpoint transition contains an unexplained non-D9.4 source change')
      }
      assertDurabilityActor(transition.finalizer_actor, 'trusted_launcher', transition.finalizer_observed_at)
      assertDurabilityActor(transition.semantic_actor, 'independent_verifier', transition.attestation_completed_at)
      assertDurabilityActor(transition.persistence_actor, 'journal_broker', transition.persisted_at)
      usedProgressionRecords.add(requestEntry); usedProgressionRecords.add(brokerEntry)
      transitions.push({ transition, receipt: entry.append_receipt, request, requestReceipt: requestEntry.receipt, brokerReceipt, brokerStoreReceipt: brokerEntry.receipt, assessment, d940Receipt })
      transitionHead = { namespace_code: transitionHead.namespace_code, sequence: transitionHead.sequence + 1, record_digest_sha256: transition.record_digest_sha256 }
      effectiveCheckpoint = checkpointReference(transition, entry.append_receipt)
    }
    const pendingProgressionRecords = progressionRecords.filter((item) => !usedProgressionRecords.has(item))
    if (pendingProgressionRecords.length > 2 || (pendingProgressionRecords[0]?.payload.format.endsWith('broker-receipt') ?? false) || (pendingProgressionRecords.length === 2 && (pendingProgressionRecords[1].payload.format.endsWith('append-request') || pendingProgressionRecords[1].payload.append_request_record_digest_sha256 !== pendingProgressionRecords[0].payload.record_digest_sha256))) failD941('D941_RESOLVER_PROGRESSION_PENDING_INVALID', 'pending progression state is forked, reordered, or ambiguous')

    const links = []
    const d940Receipts = linkEntries.length === 0 ? [] : broker.validate()
    let linkHead = { namespace_code: 'd9.resolver.assessment-links.v1.1', sequence: 0, record_digest_sha256: null, commit_sha256: null }
    let priorLinkPersistedAt = null
    for (const entry of linkEntries) {
      if (entry.records.length !== 1) failD941('D941_RESOLVER_ASSESSMENT_LINK_BATCH_INVALID', 'assessment-link append must contain exactly one link')
      const link = entry.records[0]
      assertDurabilitySchema(durability, 'recovery-assessment-link-v1-1.schema.json', link, 'recovery assessment link')
      assertDurabilityActor(link.semantic_actor, 'independent_verifier', link.classified_at)
      assertDurabilityActor(link.persistence_actor, 'journal_broker', link.persisted_at)
      if (!same(link.runtime_generation, expectedGeneration) || link.classified_at > link.persisted_at || (priorLinkPersistedAt !== null && link.persisted_at <= priorLinkPersistedAt)) failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'assessment link generation or persistence chronology is invalid')
      let assessment
      let assessmentReceipt
      try {
        assessment = parseStrictJson(Buffer.from(link.recovery_assessment_canonical_utf8, 'utf8'), { maximumBytes: 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
        assessmentReceipt = parseStrictJson(Buffer.from(link.d940_assessment_receipt_canonical_utf8, 'utf8'), { maximumBytes: 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true })
      } catch (error) { failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'assessment link contains unreadable canonical evidence', { cause: error.message }) }
      validateD940Record({ contractSet: authorityContext.contractSet, record: assessment })
      validateD940Record({ contractSet: authorityContext.contractSet, record: assessmentReceipt })
      const request = durableRecords.find((item) => item.wrapper.record_digest_sha256 === link.request_durable_record_digest_sha256)
      const response = durableRecords.find((item) => item.wrapper.record_digest_sha256 === link.response_durable_record_digest_sha256)
      const attestation = durableRecords.find((item) => item.wrapper.record_digest_sha256 === link.attestation_durable_record_digest_sha256)
      const checkpoint = checkpoints.find((item) => item.sequence === link.checkpoint_sequence && item.record_digest_sha256 === link.checkpoint_record_digest_sha256) ?? transitions.find((item) => item.transition.transition_sequence === link.checkpoint_sequence && item.transition.record_digest_sha256 === link.checkpoint_record_digest_sha256)?.transition
      const retainedD940Receipt = d940Receipts.find((item) => item.record_digest_sha256 === assessmentReceipt.record_digest_sha256)
      let retainedAssessment = null
      try { retainedAssessment = parseStrictJson(broker.store.read({ namespaceCode: 'recovery', recordCode: assessment.record_code }), { maximumBytes: 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true }) } catch (error) { failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'linked assessment is absent from protected D9.4 storage', { cause: error.message }) }
      if (!request || !response || !attestation || !checkpoint || canonicalize(assessment) !== link.recovery_assessment_canonical_utf8 || canonicalize(assessmentReceipt) !== link.d940_assessment_receipt_canonical_utf8 || recordDigest(assessment) !== assessment.record_digest_sha256 || recordDigest(assessmentReceipt) !== assessmentReceipt.record_digest_sha256 ||
          assessment.record_digest_sha256 !== link.recovery_assessment_record_digest_sha256 || assessmentReceipt.target_record_digest_sha256 !== assessment.record_digest_sha256 || assessmentReceipt.record_digest_sha256 !== link.d940_assessment_receipt_record_digest_sha256 || assessmentReceipt.receipt_sequence !== link.d940_assessment_receipt_sequence ||
          assessmentReceipt.record_digest_sha256 !== link.d940_assessment_journal_head_digest_sha256 || assessment.operation_id !== link.operation_id || assessment.operation_nonce !== link.operation_nonce || assessment.subject.subject_identity_sha256 !== link.subject_identity_sha256 ||
          request.wrapper.record_kind_code !== 'request' || response.wrapper.record_kind_code !== 'response' || attestation.wrapper.record_kind_code !== 'append_attestation' ||
          response.payload.request_record_digest_sha256 !== request.payload.record_digest_sha256 || attestation.payload.composite_response_record_digest_sha256 !== response.payload.record_digest_sha256 ||
          [request, response, attestation].some((item) => item.payload.operation_id !== link.operation_id || item.payload.operation_nonce !== link.operation_nonce || item.payload.subject.subject_identity_sha256 !== link.subject_identity_sha256 || !same(item.payload.runtime_generation, link.runtime_generation)) ||
          response.payload.record_digest_sha256 !== link.composite_response_record_digest_sha256 || attestation.payload.record_digest_sha256 !== link.append_attestation_record_digest_sha256 ||
          (checkpoint.format_version === '1.1.0' ? checkpoint.checkpoint_kind_code !== 'advance' : checkpoint.format !== 'jedi-atlas-recovery-checkpoint-transition') || checkpoint.operation_id !== link.operation_id || checkpoint.operation_nonce !== link.operation_nonce || checkpoint.composite_response_record_digest_sha256 !== response.payload.record_digest_sha256 || (checkpoint.append_attestation_record_digest_sha256 ?? checkpoint.composite_append_attestation_record_digest_sha256) !== attestation.payload.record_digest_sha256 ||
          assessment.action_execution_code !== 'none_classification_only' || assessment.recovery_authority_present !== false ||
          assessment.snapshot_digest_sha256 !== response.payload.projection.snapshot_digest_sha256 || !same(assessment.snapshot, response.payload.projection.snapshot) ||
          !retainedD940Receipt || !same(retainedD940Receipt, assessmentReceipt) || !same(retainedAssessment, assessment) ||
          assessmentReceipt.target_format !== assessment.format || assessmentReceipt.target_record_code !== assessment.record_code || assessmentReceipt.target_subject_identity_sha256 !== assessment.subject.subject_identity_sha256 || assessmentReceipt.operation_id !== assessment.operation_id || assessmentReceipt.operation_nonce !== assessment.operation_nonce ||
          !same(assessmentReceipt.semantic_actor, assessment.semantic_actor) || !same(assessmentReceipt.persistence_actor, assessment.persistence_actor) || assessmentReceipt.semantic_recorded_at !== assessment.knowledge_boundary.recorded_at || assessmentReceipt.persisted_at !== assessment.knowledge_boundary.persisted_at) failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'assessment link does not resolve to one exact durable resolver, checkpoint, assessment, and D9.4 receipt chain')
      validateReceipt(entry.append_receipt, 'd9.resolver.assessment-links.v1.1', linkHead, link, 'assessment link')
      linkHead = { namespace_code: linkHead.namespace_code, sequence: linkHead.sequence + 1, record_digest_sha256: link.record_digest_sha256, commit_sha256: entry.commit_sha256 }
      priorLinkPersistedAt = link.persisted_at
      links.push({ link, assessment, assessmentReceipt, receipt: entry.append_receipt })
    }
    const checkpointReferences = checkpoints.map((checkpoint, index) => ({
      checkpoint_contract_version: '1.1.0',
      checkpoint_namespace_code: 'd9.resolver.checkpoints.v1.1',
      checkpoint_sequence: checkpoint.sequence,
      checkpoint_record_digest_sha256: checkpoint.record_digest_sha256,
      checkpoint_append_receipt_record_digest_sha256: checkpointEntries[index].append_receipt.record_digest_sha256,
      source_heads: checkpoint.source_heads,
      source_heads_digest_sha256: canonicalSha256(checkpoint.source_heads),
    })).concat(transitions.map((item) => checkpointReference(item.transition, item.receipt)))
    return deepFreeze({ checkpoints, transitions, pendingProgressionRecords, checkpointReferences, durableRecords, links, heads: { checkpoint: checkpointHead, records: recordHead, links: linkHead, intents: intentHead, transitions: transitionHead } })
  }

  function collectStable(kind, subjectIdentitySha256, requestedAt) {
    const observedAt = timestamp(trustedClock(), 'resolver before-observation time')
    if (observedAt < requestedAt) failD941('D941_RESOLVER_TIME_INVALID', 'resolver before-observation time precedes its request')
    const before = observe(subjectIdentitySha256)
    const after = observe(subjectIdentitySha256)
    const observedAfterAt = timestamp(trustedClock(), 'resolver after-observation time')
    if (observedAfterAt < observedAt) failD941('D941_RESOLVER_TIME_INVALID', 'resolver after-observation time precedes its before observation')
    const moved = namespaceSets[kind].filter((namespace) => !same(before.heads.get(namespace), after.heads.get(namespace)))
    if (moved.length !== 0) failD941('D941_RESOLVER_SOURCE_HEAD_MOVED', 'one or more resolver source heads moved during the required double collection', { details: { namespaces: moved } })
    const respondedAt = timestamp(trustedClock(), 'resolver response time')
    if (respondedAt < observedAfterAt) failD941('D941_RESOLVER_TIME_INVALID', 'resolver response time precedes its after observation')
    return deepFreeze({ ...after, beforeHeads: before.heads, observedAt, observedAfterAt, respondedAt })
  }

  function persistBatch(namespaceCode, records, payloadRecord, acceptedAt, persistedAt) {
    const expectedHead = durabilityStore.head(namespaceCode)
    const receipt = makeAppendReceipt({ namespaceCode, expectedHead, payloadRecord, persistenceActor: authenticatedActorFor('journal_broker', persistedAt), acceptedAt, persistedAt })
    assertDurabilitySchema(durability, 'append-receipt-v1-1.schema.json', receipt, 'append receipt')
    assertD941AuthenticatedSession(persistenceSession, 'recovery_classification')
    const receiptActor = receipt.persistence_actor
    const activeBinding = authorityContext.verifiedGeneration.identityBindings.bindings.find((item) => item.binding_code === persistenceSession.actor.identity_binding.binding_code)
    if (receiptActor.runtime_role_code !== 'journal_broker' || receiptActor.binding_code !== persistenceSession.actor.identity_binding.binding_code ||
        !activeBinding || receiptActor.endpoint_code !== persistenceSession.exchange.authenticatedEndpointCode || receiptActor.executable_build_sha256 !== activeBinding.executable_sha256) {
      failD941('D941_RESOLVER_DURABLE_WRITER_UNAUTHORIZED', 'protected resolver append is not bound to the authenticated journal-broker process')
    }
    authorityRegistry.revalidateSession(persistenceSession, receipt.persisted_at)
    const writer = durabilityWriters.get(durabilityStore)
    if (!writer) failD941('D941_RESOLVER_DURABLE_STORE_UNTRUSTED', 'resolver durability writer capability is unavailable')
    writer({ namespaceCode, expectedHead, records, appendReceipt: receipt })
    faultInjector?.('after_resolver_atomic_append_before_response', { namespaceCode, payloadRecord })
    validateDurableState()
    return receipt
  }

  function persistProgression(namespaceCode, payload, persistedAt, currentD940Head = null) {
    let state = validateDurableState()
    const retainedProgression = [...state.pendingProgressionRecords, ...state.transitions.flatMap((item) => [
      { payload: item.request, receipt: item.requestReceipt },
      { payload: item.brokerReceipt, receipt: item.brokerStoreReceipt },
      { payload: item.transition, receipt: item.receipt },
    ])]
    const existing = retainedProgression.find((item) => item.payload.record_digest_sha256 === payload.record_digest_sha256)
    if (existing) return existing
    const stableIdentities = (record) => record.format.endsWith('append-request')
      ? [`request:${record.request_code}`, `operation:${record.operation_id}`, `idempotency:${record.idempotency_key_sha256}`]
      : record.format.endsWith('broker-receipt')
        ? [`broker:${record.receipt_code}`, `broker-operation:${record.operation_id}`, `broker-request:${record.append_request_record_digest_sha256}`]
        : [`transition:${record.transition_code}`, `transition-sequence:${record.transition_sequence}`, `transition-operation:${record.operation_id}`, `transition-predecessor:${record.predecessor_checkpoint_record_digest_sha256}`]
    const claimed = new Set(stableIdentities(payload))
    if (retainedProgression.some((item) => stableIdentities(item.payload).some((identity) => claimed.has(identity)))) failD941('D941_RESOLVER_PROGRESSION_REPLAY_COLLISION', 'progression stable identity collision was rejected before durable mutation')
    const expectedHead = namespaceCode === 'd9.resolver.progression-intents.v1.2' ? state.heads.intents : state.heads.transitions
    let sourceHeadForCas = currentD940Head
    if (namespaceCode === 'd9.resolver.checkpoint-transitions.v1.2') {
      const currentBrokerHead = broker.head()
      const independentlyDerived = deriveD940ProtectedHead(contract, broker, currentBrokerHead.sequence)
      if (sourceHeadForCas === null || !same(sourceHeadForCas, independentlyDerived) || currentBrokerHead.digest !== independentlyDerived.head_digest_sha256) failD941('D941_RESOLVER_PROGRESSION_SOURCE_CAS_INVALID', 'D9.4 source head changed before the transition protected append')
      sourceHeadForCas = independentlyDerived
    }
    const receipt = sealRecord({
      format: 'jedi-atlas-recovery-checkpoint-progression-append-receipt', format_version: '1.2.0',
      receipt_code: `progression.receipt.${namespaceCode.split('.').at(-2)}.${String(expectedHead.sequence + 1).padStart(8, '0')}`,
      namespace_code: namespaceCode, expected_predecessor: expectedHead,
      persisted_head: { namespace_code: namespaceCode, sequence: expectedHead.sequence + 1, record_digest_sha256: payload.record_digest_sha256 },
      payload_record_digest_sha256: payload.record_digest_sha256,
      source_head_compare_and_append: sourceHeadForCas === null ? null : { source_namespace_code: 'd940.global.control-journal.v1', expected_head: sourceHeadForCas, observed_head_at_persist: sourceHeadForCas },
      source_head_observer_actor: sourceHeadForCas === null ? null : authenticatedActorFor('independent_verifier', persistedAt),
      persistence_actor: authenticatedActorFor('journal_broker', persistedAt), accepted_at: persistedAt, persisted_at: persistedAt,
      record_digest_sha256: null,
    })
    assertProgressionSchema('protected-append-receipt-v1-2.schema.json', receipt, 'progression protected receipt')
    assertD941AuthenticatedSession(persistenceSession, 'recovery_classification')
    assertAuthorityActive(persistedAt)
    authorityRegistry.revalidateSession(persistenceSession, persistedAt)
    const writer = durabilityWriters.get(durabilityStore)
    if (!writer) failD941('D941_RESOLVER_DURABLE_STORE_UNTRUSTED', 'resolver durability writer capability is unavailable')
    writer({ namespaceCode, expectedHead: { ...expectedHead, commit_sha256: durabilityStore.head(namespaceCode).commit_sha256 }, records: [payload], appendReceipt: receipt })
    faultInjector?.('after_progression_atomic_append_before_response', { namespaceCode, payloadRecord: payload })
    state = validateDurableState()
    return namespaceCode === 'd9.resolver.progression-intents.v1.2'
      ? state.pendingProgressionRecords.find((item) => item.payload.record_digest_sha256 === payload.record_digest_sha256) ?? state.transitions.flatMap((item) => [{ payload: item.request, receipt: item.requestReceipt }, { payload: item.brokerReceipt, receipt: item.brokerStoreReceipt }]).find((item) => item.payload.record_digest_sha256 === payload.record_digest_sha256)
      : { payload: state.transitions.find((item) => item.transition.record_digest_sha256 === payload.record_digest_sha256)?.transition, receipt: state.transitions.find((item) => item.transition.record_digest_sha256 === payload.record_digest_sha256)?.receipt }
  }

  function bootstrapDurability() {
    const checkpointHead = durabilityStore.head('d9.resolver.checkpoints.v1.1')
    if (checkpointHead.sequence !== 0) return validateDurableState()
    if (D941_RESOLVER_NAMESPACES.filter((item) => item !== 'd9.resolver.checkpoints.v1.1').some((item) => durabilityStore.head(item).sequence !== 0)) failD941('D941_RESOLVER_DURABILITY_BOOTSTRAP_MISSING', 'non-checkpoint state exists before bootstrap')
    const now = timestamp(trustedClock(), 'durability bootstrap time')
    assertAuthorityActive(now)
    const before = observe(configuredSubject.subject_identity_sha256)
    const after = observe(configuredSubject.subject_identity_sha256)
    const moved = namespaces.filter((namespace) => !same(before.heads.get(namespace), after.heads.get(namespace)))
    if (moved.length !== 0) failD941('D941_RESOLVER_SOURCE_HEAD_MOVED', 'one or more source heads moved during checkpoint bootstrap')
    const operationId = `resolver.bootstrap.${expectedGeneration.binding_generation}`
    const operationNonce = canonicalSha256({ operationId, generation: expectedGeneration })
    const observations = namespaces.map((namespace, index) => sealRecord({
      format: 'jedi-atlas-recovery-resolver-bootstrap-source-observation', format_version: '1.1.0',
      observation_code: `resolver.bootstrap.observation.${index + 1}`, operation_id: operationId, operation_nonce: operationNonce,
      runtime_generation: expectedGeneration, source_head_before: before.heads.get(namespace), source_head_after: after.heads.get(namespace),
      semantic_actor: authenticatedActorFor('independent_verifier', now), persistence_actor: authenticatedActorFor('journal_broker', now),
      observed_before_at: now, observed_after_at: now, persisted_at: now,
      checkpoint_namespace_observed_empty: true, technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
    }))
    for (const observation of observations) assertDurabilitySchema(durability, 'bootstrap-source-observation-v1-1.schema.json', observation, 'bootstrap source observation')
    const permit = sealRecord({
      format: 'jedi-atlas-recovery-resolver-checkpoint-bootstrap-permit', format_version: '1.1.0',
      permit_code: `resolver.bootstrap.permit.${expectedGeneration.binding_generation}`, operation_id: operationId, operation_nonce: operationNonce,
      runtime_generation: expectedGeneration, issued_by: authenticatedActorFor('trusted_launcher', now), persisted_by: authenticatedActorFor('journal_broker', now),
      issued_at: now, expires_at: plus(now, 1000), expected_empty_checkpoint_head: journalHead(checkpointHead),
      initial_source_heads: namespaces.map((namespace) => after.heads.get(namespace)), bootstrap_observation_record_digests: observations.map((item) => item.record_digest_sha256),
      source_observation_set_digest_sha256: canonicalSha256(namespaces.map((namespace) => after.heads.get(namespace))), one_time_no_replace: true,
      technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
    })
    assertDurabilitySchema(durability, 'checkpoint-bootstrap-permit-v1-1.schema.json', permit, 'bootstrap permit')
    const checkpoint = sealRecord({
      format: 'jedi-atlas-recovery-resolver-checkpoint-record', format_version: '1.1.0', checkpoint_code: 'resolver.checkpoint.00000001', checkpoint_kind_code: 'bootstrap', sequence: 1,
      predecessor_record_digest_sha256: null, operation_id: operationId, operation_nonce: operationNonce, runtime_generation: expectedGeneration,
      semantic_actor: authenticatedActorFor('independent_verifier', now), persistence_actor: authenticatedActorFor('journal_broker', now), observed_at: now, persisted_at: now,
      source_heads: permit.initial_source_heads, composite_response_record_digest_sha256: null, append_attestation_record_digest_sha256: null,
      bootstrap_permit_record_digest_sha256: permit.record_digest_sha256, technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
    })
    assertDurabilitySchema(durability, 'checkpoint-record-v1-1.schema.json', checkpoint, 'bootstrap checkpoint')
    persistBatch('d9.resolver.checkpoints.v1.1', [...observations, permit, checkpoint], checkpoint, now, now)
    return validateDurableState()
  }

  // These are deliberately closed, in-process synthetic adapters. They model
  // the three approved resolver boundaries without exposing arbitrary source
  // callbacks or granting a handle to any protected store.
  function createSourceAdapter(kind) {
    const ownedNamespaces = namespaceSets[kind]
    return Object.freeze({
      kind,
      resolve({ subject, operationId, operationNonce }) {
        const requestedAt = timestamp(trustedClock(), 'trusted resolver request clock')
        assertAuthorityActive(requestedAt)
        const observed = collectStable(kind, subject.subject_identity_sha256, requestedAt)
        const request = makeRequest({ contract, kind, authorityContext, subject, operationId, operationNonce, requestedAt, heads: observed.heads })
        return Object.freeze({
          request,
          response: makeResponse({ contract, request, ...observed }),
          ownedNamespaces,
        })
      },
    })
  }
  const sourceAdapters = Object.freeze([
    createSourceAdapter('d901_control_access'),
    createSourceAdapter('d920_accepted_evidence'),
    createSourceAdapter('d930_custody'),
  ])

  function persistDurablePayload(payload, recordKindCode, checkpoint) {
    const state = validateDurableState()
    const retained = state.durableRecords.filter((item) => item.wrapper.payload_record_digest_sha256 === payload.record_digest_sha256)
    if (retained.length > 1) failD941('D941_RESOLVER_DURABLE_REPLAY_COLLISION', 'multiple durable records claim the same payload digest')
    if (retained.length === 1) {
      if (retained[0].wrapper.record_kind_code !== recordKindCode || !same(retained[0].payload, payload)) failD941('D941_RESOLVER_DURABLE_REPLAY_COLLISION', 'durable payload replay carries a different kind or bytes')
      return retained[0]
    }
    const acceptedAt = timestamp(trustedClock(), 'durable resolver acceptance time')
    const persistedAt = timestamp(trustedClock(), 'durable resolver persistence time')
    if (persistedAt < acceptedAt) failD941('D941_RESOLVER_TIME_INVALID', 'durable resolver persistence precedes acceptance')
    const operationRecords = state.durableRecords.filter((item) => item.wrapper.operation_id === payload.operation_id && item.wrapper.operation_nonce === payload.operation_nonce)
    const response = operationRecords.find((item) => item.wrapper.record_kind_code === 'response' && item.payload.record_digest_sha256 === payload.composite_response_record_digest_sha256)
    const requestDigest = payload.request_record_digest_sha256 ?? response?.payload.request_record_digest_sha256 ?? payload.record_digest_sha256
    const request = operationRecords.find((item) => item.wrapper.record_kind_code === 'request' && item.payload.record_digest_sha256 === requestDigest)
    if (recordKindCode !== 'request' && !request) failD941('D941_RESOLVER_DURABLE_LINK_INVALID', 'response or attestation has no durable request')
    if (recordKindCode === 'append_attestation' && !response) failD941('D941_RESOLVER_DURABLE_LINK_INVALID', 'attestation has no durable response')
    const head = state.heads.records
    const producer = authenticatedActorFor(payload.sender.runtime_role_code, acceptedAt)
    const wrapper = sealRecord({
      format: 'jedi-atlas-recovery-resolver-durable-record', format_version: '1.1.0',
      record_code: `resolver.durable.${String(head.sequence + 1).padStart(8, '0')}`, record_kind_code: recordKindCode,
      resolver_kind_code: payload.resolver_kind_code ?? 'd940_composite_snapshot', sequence: head.sequence + 1, predecessor_record_digest_sha256: head.record_digest_sha256,
      operation_id: payload.operation_id, operation_nonce: payload.operation_nonce, runtime_generation: expectedGeneration, subject: payload.subject,
      payload_format: payload.format, payload_canonical_utf8: canonicalize(payload), payload_record_digest_sha256: payload.record_digest_sha256,
      semantic_verifier_code: 'd9_recovery_resolvers_v1_0_full_semantics', semantic_verifier_sha256: semanticVerifierSha256,
      request_record_digest_sha256: request?.payload.record_digest_sha256 ?? payload.record_digest_sha256,
      response_record_digest_sha256: recordKindCode === 'request' ? null : (response?.payload.record_digest_sha256 ?? payload.record_digest_sha256),
      attestation_record_digest_sha256: recordKindCode === 'append_attestation' ? payload.record_digest_sha256 : null,
      payload_producer: producer, semantic_actor: authenticatedActorFor('independent_verifier', acceptedAt), persistence_actor: authenticatedActorFor('journal_broker', persistedAt),
      accepted_at: acceptedAt, persisted_at: persistedAt, checkpoint_sequence: checkpoint.sequence ?? checkpoint.checkpoint_sequence, checkpoint_record_digest_sha256: checkpoint.record_digest_sha256 ?? checkpoint.checkpoint_record_digest_sha256,
      technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
    })
    assertDurabilitySchema(durability, 'durable-resolver-record-v1-1.schema.json', wrapper, 'durable resolver record')
    persistBatch('d9.resolver.records.v1.1', [wrapper], wrapper, acceptedAt, persistedAt)
    return validateDurableState().durableRecords.find((item) => item.wrapper.record_digest_sha256 === wrapper.record_digest_sha256)
  }

  function resolveComposite({ subject, operationId, operationNonce }) {
    const initialState = bootstrapDurability()
    if (subject?.subject_kind_code !== configuredSubject.subject_kind_code || subject?.subject_identity_sha256 !== configuredSubject.subject_identity_sha256) failD941('D941_RESOLVER_SUBJECT_SUBSTITUTED', 'resolver request differs from the configured D9.3 custody subject')
    const retainedRequest = initialState.durableRecords.find((item) => item.wrapper.record_kind_code === 'request' && item.wrapper.resolver_kind_code === 'd940_composite_snapshot' && item.wrapper.operation_id === operationId && item.wrapper.operation_nonce === operationNonce)
    const retainedResponse = initialState.durableRecords.find((item) => item.wrapper.record_kind_code === 'response' && item.wrapper.resolver_kind_code === 'd940_composite_snapshot' && item.wrapper.operation_id === operationId && item.wrapper.operation_nonce === operationNonce)
    if (retainedRequest || retainedResponse) {
      if (!retainedRequest || !retainedResponse || retainedRequest.payload.subject.subject_identity_sha256 !== subject.subject_identity_sha256 || retainedResponse.payload.subject.subject_identity_sha256 !== subject.subject_identity_sha256) failD941('D941_RESOLVER_DURABLE_REPLAY_COLLISION', 'retained resolver operation is incomplete or belongs to another subject')
      const checkpoint = initialState.checkpointReferences.find((item) => item.checkpoint_sequence === retainedResponse.wrapper.checkpoint_sequence && item.checkpoint_record_digest_sha256 === retainedResponse.wrapper.checkpoint_record_digest_sha256)
      if (!checkpoint) failD941('D941_RESOLVER_DURABLE_CHECKPOINT_INVALID', 'retained resolver response checkpoint is unavailable')
      const componentResponses = initialState.durableRecords.filter((item) => item.wrapper.record_kind_code === 'response' && item.wrapper.resolver_kind_code !== 'd940_composite_snapshot' && item.wrapper.operation_id === operationId && item.wrapper.operation_nonce === operationNonce)
      return deepFreeze({ requests: [], sourceResponses: componentResponses.map((item) => item.payload), componentDurability: componentResponses.map((item) => item.wrapper), compositeRequest: retainedRequest.payload, compositeResponse: retainedResponse.payload, snapshot: retainedResponse.payload.projection.snapshot, durability: { request: retainedRequest.wrapper, response: retainedResponse.wrapper, checkpoint } })
    }
    const sourceResults = sourceAdapters.map((adapter) => {
      const response = initialState.durableRecords.find((item) => item.wrapper.record_kind_code === 'response' && item.wrapper.resolver_kind_code === adapter.kind && item.wrapper.operation_id === operationId && item.wrapper.operation_nonce === operationNonce)
      const request = response && initialState.durableRecords.find((item) => item.wrapper.record_kind_code === 'request' && item.payload.record_digest_sha256 === response.payload.request_record_digest_sha256)
      if (response || request) {
        if (!response || !request) failD941('D941_RESOLVER_DURABLE_REPLAY_COLLISION', `partial durable ${adapter.kind} pair cannot be reconstructed exactly`)
        return Object.freeze({ request: request.payload, response: response.payload, ownedNamespaces: adapter.ownedNamespaces })
      }
      return adapter.resolve({ subject, operationId, operationNonce })
    })
    const requests = sourceResults.map((item) => item.request)
    const sourceResponses = sourceResults.map((item) => item.response)
    const requestedAt = timestamp(trustedClock(), 'trusted composite request clock')
    assertAuthorityActive(requestedAt)
    const observed = collectStable('d940_composite_snapshot', subject.subject_identity_sha256, requestedAt)
    for (const response of sourceResponses) for (const sourceObservation of response.source_observations) {
      if (!same(sourceObservation.after, observed.beforeHeads.get(sourceObservation.source_namespace_code))) failD941('D941_RESOLVER_MIXED_SOURCE_HEAD', 'constituent final source head differs from the composite anchor')
    }
    const checkpoint = initialState.checkpointReferences.at(-1)
    if (!checkpoint) failD941('D941_RESOLVER_DURABILITY_BOOTSTRAP_MISSING', 'composite resolution requires a current protected checkpoint')
    const currentHeads = namespaceSets.d940_composite_snapshot.map((namespace) => observed.heads.get(namespace))
    if (!same(currentHeads, checkpoint.source_heads)) failD941('D941_RESOLVER_CHECKPOINT_SOURCE_MISMATCH', 'current source heads moved beyond the protected checkpoint; a resolved v1 response cannot be fabricated')
    const compositeRequest = makeRequest({ contract, kind: 'd940_composite_snapshot', authorityContext, subject, operationId, operationNonce, requestedAt, heads: observed.heads, priorHeads: checkpoint.source_heads, inputDigests: sourceResponses.map((item) => item.record_digest_sha256) })
    const compositeResponse = makeResponse({ contract, request: compositeRequest, ...observed, sourceResponses })
    if (!checkpoint || !same(compositeRequest.prior_accepted_source_heads, checkpoint.source_heads)) failD941('D941_RESOLVER_CHECKPOINT_SOURCE_MISMATCH', 'resolver request source heads differ from the current durable checkpoint')
    const componentDurability = []
    for (const result of sourceResults) {
      persistDurablePayload(result.request, 'request', checkpoint)
      componentDurability.push(persistDurablePayload(result.response, 'response', checkpoint).wrapper)
    }
    const durableRequest = persistDurablePayload(compositeRequest, 'request', checkpoint)
    const durableResponse = persistDurablePayload(compositeResponse, 'response', checkpoint)
    return deepFreeze({ requests, sourceResponses, componentDurability, compositeRequest, compositeResponse, snapshot: compositeResponse.projection.snapshot, durability: { request: durableRequest.wrapper, response: durableResponse.wrapper, checkpoint } })
  }

  function revalidateAtAppend({ compositeResponse, assessment, completedAt }) {
    let state = validateDurableState()
    const durableResponse = state.durableRecords.find((item) => item.wrapper.record_kind_code === 'response' && item.payload.record_digest_sha256 === compositeResponse.record_digest_sha256)
    const durableRequest = state.durableRecords.find((item) => item.wrapper.record_kind_code === 'request' && item.payload.record_digest_sha256 === compositeResponse.request_record_digest_sha256)
    if (!durableRequest || !durableResponse || !same(durableResponse.payload, compositeResponse) || assessment?.format !== 'jedi-atlas-d940-recovery-assessment' || assessment.record_digest_sha256 !== recordDigest(assessment) || assessment.operation_id !== compositeResponse.operation_id || assessment.operation_nonce !== compositeResponse.operation_nonce || assessment.subject.subject_identity_sha256 !== compositeResponse.subject.subject_identity_sha256) failD941('D941_RECOVERY_RESOLVER_RESPONSE_UNTRUSTED', 'append revalidation requires the exact durable response and assessment')
    timestamp(completedAt, 'append revalidation completion time')
    const authorityState = authorityRegistry.stateAt(completedAt)
    if (authorityState.revoked.size !== 0) failD941('D941_RESOLVER_AUTHORITY_REVOKED', 'resolver authority generation has a revoked required target')
    actorFor(authorityContext, 'independent_verifier', completedAt)
    actorFor(authorityContext, 'journal_broker', completedAt)
    const priorCheckpoint = state.checkpointReferences.find((item) => item.checkpoint_sequence === durableResponse.wrapper.checkpoint_sequence && item.checkpoint_record_digest_sha256 === durableResponse.wrapper.checkpoint_record_digest_sha256)
    if (!priorCheckpoint) failD941('D941_RESOLVER_DURABLE_CHECKPOINT_INVALID', 'durable response checkpoint cannot be resolved')
    const existingAttestation = state.durableRecords.find((item) => item.wrapper.record_kind_code === 'append_attestation' && item.wrapper.operation_id === compositeResponse.operation_id && item.wrapper.operation_nonce === compositeResponse.operation_nonce)
    const existingRequestEntry = [...state.pendingProgressionRecords, ...state.transitions.map((item) => ({ payload: item.request, receipt: item.requestReceipt }))].find((item) => item.payload.assessment_record_digest_sha256 === assessment.record_digest_sha256)
    if (completedAt < compositeResponse.responded_at || completedAt > compositeResponse.append_revalidate_by) failD941('D941_RECOVERY_APPEND_REVALIDATION_EXPIRED', 'append occurs outside the resolver freshness window')
    const before = observe(compositeResponse.subject.subject_identity_sha256)
    const current = observe(compositeResponse.subject.subject_identity_sha256)
    const expected = new Map(compositeResponse.source_observations.map((item) => [item.source_namespace_code, item.after]))
    const exact = namespaces.every((namespace) => same(before.heads.get(namespace), current.heads.get(namespace)) && same(current.heads.get(namespace), expected.get(namespace)))
    const attestation = {
      format: 'jedi-atlas-recovery-projection-append-revalidation-attestation', format_version: '1.0.0',
      attestation_code: `resolver.attestation.${canonicalSha256({ response: compositeResponse.record_digest_sha256, completedAt }).slice(0, 16)}`,
      operation_id: compositeResponse.operation_id, operation_nonce: compositeResponse.operation_nonce,
      composite_response_record_digest_sha256: compositeResponse.record_digest_sha256,
      sender: actorFor(authorityContext, 'independent_verifier', completedAt), recipient: actorFor(authorityContext, 'journal_broker', completedAt),
      runtime_generation: compositeResponse.runtime_generation, subject: compositeResponse.subject,
      observed_at: completedAt, completed_at: completedAt, result_code: exact ? 'revalidated' : 'failed', error_code: exact ? null : 'append_revalidation_failed',
      source_heads: namespaces.map((namespace) => current.heads.get(namespace)), technical_evidence_only: true, authority_granted: false,
      record_digest_sha256: null,
    }
    attestation.record_digest_sha256 = recordDigest(attestation)
    assertSchema(contract.validateAttestation, attestation, 'append revalidation attestation')
    if (!exact) failD941('D941_RECOVERY_APPEND_REVALIDATION_FAILED', 'one or more resolver source heads changed before append', { details: { attestation } })
    const durableAttestation = existingAttestation ?? persistDurablePayload(attestation, 'append_attestation', priorCheckpoint)
    state = validateDurableState()
    const currentCheckpoint = state.checkpointReferences.at(-1)
    if (!same(currentCheckpoint, priorCheckpoint) || !same(durableRequest.payload.prior_accepted_source_heads, priorCheckpoint.source_heads)) failD941('D941_RESOLVER_CHECKPOINT_HEAD_MISMATCH', 'effective checkpoint advanced or source basis changed before append authorization')
    const componentResolutionAttestations = ['d901_control_access', 'd920_accepted_evidence', 'd930_custody'].map((kind) => {
      const component = state.durableRecords.find((item) => item.wrapper.record_kind_code === 'response' && item.wrapper.resolver_kind_code === kind && item.wrapper.operation_id === assessment.operation_id && item.wrapper.operation_nonce === assessment.operation_nonce)
      if (!component) failD941('D941_RESOLVER_PROGRESSION_EVIDENCE_MISSING', `missing durable ${kind} response`)
      return { resolver_kind_code: kind, component_response_record_digest_sha256: component.payload.record_digest_sha256, component_response_durable_record_digest_sha256: component.wrapper.record_digest_sha256 }
    })
    const position = expectedD940Position(priorCheckpoint, assessment)
    const progressionRequest = sealRecord({
      format: 'jedi-atlas-recovery-checkpoint-assessment-append-request', format_version: '1.2.0',
      request_code: `progression.request.${canonicalSha256({ operation_id: assessment.operation_id, operation_nonce: assessment.operation_nonce }).slice(0, 20)}`,
      operation_id: assessment.operation_id, operation_nonce: assessment.operation_nonce, idempotency_key_sha256: canonicalSha256({ operation_id: assessment.operation_id, operation_nonce: assessment.operation_nonce, prior_checkpoint_record_digest_sha256: priorCheckpoint.checkpoint_record_digest_sha256, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: position }),
      runtime_generation: expectedGeneration, subject: compositeResponse.subject, prior_checkpoint: priorCheckpoint,
      component_resolution_attestations: componentResolutionAttestations,
      composite_response_record_digest_sha256: compositeResponse.record_digest_sha256, composite_response_durable_record_digest_sha256: durableResponse.wrapper.record_digest_sha256,
      composite_append_attestation_record_digest_sha256: attestation.record_digest_sha256, composite_append_attestation_durable_record_digest_sha256: durableAttestation.wrapper.record_digest_sha256,
      assessment_format: assessment.format, assessment_record_code: assessment.record_code, assessment_canonical_utf8: canonicalize(assessment), assessment_record_digest_sha256: assessment.record_digest_sha256,
      expected_d940_append_position: position, pre_append_source_heads: priorCheckpoint.source_heads, pre_append_source_heads_digest_sha256: canonicalSha256(priorCheckpoint.source_heads), authorized_delta_namespace_code: 'd940.global.control-journal.v1',
      semantic_actor: authenticatedActorFor('independent_verifier', completedAt), broker_recipient: authenticatedActorFor('journal_broker', completedAt), authorized_at: completedAt, append_revalidate_by: compositeResponse.append_revalidate_by,
      technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
    })
    assertProgressionSchema('assessment-append-request-v1-2.schema.json', progressionRequest, 'assessment append request')
    if (existingRequestEntry && !same(existingRequestEntry.payload, progressionRequest)) failD941('D941_RESOLVER_PROGRESSION_REPLAY_COLLISION', 'retained progression request differs from the fully revalidated exact request')
    const progressionRequestEntry = existingRequestEntry ?? persistProgression('d9.resolver.progression-intents.v1.2', progressionRequest, completedAt)
    return deepFreeze({ attestation, durableRequest: durableRequest.wrapper, durableResponse: durableResponse.wrapper, durableAttestation: durableAttestation.wrapper, checkpoint: priorCheckpoint, progressionRequest, progressionRequestReceipt: progressionRequestEntry.receipt })
  }

  function finalizeProgression({ revalidation, assessment, assessmentReceipt }) {
    let state = validateDurableState()
    const existing = state.transitions.find((item) => item.assessment.record_digest_sha256 === assessment.record_digest_sha256)
    if (existing) return existing
    const requestEntry = state.pendingProgressionRecords.find((item) => item.payload.format === 'jedi-atlas-recovery-checkpoint-assessment-append-request' && item.payload.assessment_record_digest_sha256 === assessment.record_digest_sha256)
    if (!requestEntry || (revalidation != null && (!same(requestEntry.payload, revalidation.progressionRequest) || !same(requestEntry.receipt, revalidation.progressionRequestReceipt)))) failD941('D941_RESOLVER_PROGRESSION_REQUEST_INVALID', 'post-append finalization cannot resolve the exact durable progression request')
    const request = requestEntry.payload
    const durableAttestation = state.durableRecords.find((item) => item.wrapper.record_digest_sha256 === request.composite_append_attestation_durable_record_digest_sha256 && item.payload.record_digest_sha256 === request.composite_append_attestation_record_digest_sha256)
    if (!durableAttestation) failD941('D941_RESOLVER_PROGRESSION_EVIDENCE_MISSING', 'post-append finalization cannot resolve the exact append attestation')
    const attestation = durableAttestation.payload
    const retainedD940Receipt = broker.validate().find((item) => item.record_digest_sha256 === assessmentReceipt.record_digest_sha256)
    if (!retainedD940Receipt || !same(retainedD940Receipt, assessmentReceipt) || assessmentReceipt.target_record_digest_sha256 !== assessment.record_digest_sha256 || assessmentReceipt.receipt_sequence !== request.expected_d940_append_position.target_receipt_sequence || assessmentReceipt.previous_receipt_record_digest_sha256 !== request.expected_d940_append_position.predecessor_receipt_record_digest_sha256) failD941('D941_RESOLVER_PROGRESSION_D940_RECEIPT_INVALID', 'finalization requires the exact authorized durable D9.4 receipt')
    const observed = observe(assessment.subject.subject_identity_sha256)
    const postHeads = namespaces.map((namespace) => observed.heads.get(namespace))
    const postD940 = d940SourceHead(postHeads)
    const preD940 = d940SourceHead(request.pre_append_source_heads)
    if (broker.head().sequence !== assessmentReceipt.receipt_sequence || broker.head().digest !== assessmentReceipt.record_digest_sha256 || postD940.head_sequence !== preD940.head_sequence + 1 || postD940.head_sequence !== assessmentReceipt.receipt_sequence || postD940.head_digest_sha256 !== assessmentReceipt.record_digest_sha256) failD941('D941_RESOLVER_PROGRESSION_RECONCILIATION_REQUIRED', 'D9.4 source head moved beyond or differs from the exact assessment receipt')
    for (const namespace of namespaces.filter((item) => item !== 'd940.global.control-journal.v1')) if (!same(request.pre_append_source_heads.find((item) => item.source_namespace_code === namespace), postHeads.find((item) => item.source_namespace_code === namespace))) failD941('D941_RESOLVER_PROGRESSION_RECONCILIATION_REQUIRED', 'a non-D9.4 source changed before progression finalization')
    const observedAt = timestamp(trustedClock(), 'progression post-head observation time')
    if (observedAt < assessmentReceipt.persisted_at) failD941('D941_RESOLVER_PROGRESSION_FRESHNESS_INVALID', 'post-head observation precedes the durable assessment receipt')
    let brokerEntry = state.pendingProgressionRecords.find((item) => item.payload.format === 'jedi-atlas-recovery-checkpoint-assessment-append-broker-receipt' && item.payload.append_request_record_digest_sha256 === request.record_digest_sha256)
    if (!brokerEntry) {
      const brokerReceipt = sealRecord({
        format: 'jedi-atlas-recovery-checkpoint-assessment-append-broker-receipt', format_version: '1.2.0',
        receipt_code: `progression.broker.${canonicalSha256({ request: request.record_digest_sha256 }).slice(0, 20)}`,
        operation_id: assessment.operation_id, operation_nonce: assessment.operation_nonce, runtime_generation: expectedGeneration, subject: request.subject,
        append_request_record_digest_sha256: request.record_digest_sha256, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: request.expected_d940_append_position,
        pre_append_source_head: preD940, d940_append_receipt_canonical_utf8: canonicalize(assessmentReceipt), d940_append_receipt_record_digest_sha256: assessmentReceipt.record_digest_sha256,
        post_append_source_head: postD940, source_head_derivation_profile_code: 'frozen_v1_raw_payload_commitments',
        post_head_observer_actor: authenticatedActorFor('independent_verifier', observedAt), broker_actor: authenticatedActorFor('journal_broker', observedAt),
        accepted_at: observedAt, assessment_persisted_at: assessmentReceipt.persisted_at, post_head_observed_at: observedAt,
        exact_single_append: true, technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
      })
      assertProgressionSchema('assessment-append-broker-receipt-v1-2.schema.json', brokerReceipt, 'assessment append broker receipt')
      brokerEntry = persistProgression('d9.resolver.progression-intents.v1.2', brokerReceipt, observedAt)
    }
    state = validateDurableState()
    const effectiveCheckpoint = state.checkpointReferences.at(-1)
    if (!same(effectiveCheckpoint, request.prior_checkpoint)) failD941('D941_RESOLVER_PROGRESSION_RECONCILIATION_REQUIRED', 'effective checkpoint changed before transition finalization')
    const finalizedAt = timestamp(trustedClock(), 'progression finalizer observation time')
    const persistedAt = timestamp(trustedClock(), 'progression transition persistence time')
    if (finalizedAt < observedAt || persistedAt < finalizedAt) failD941('D941_RESOLVER_PROGRESSION_FRESHNESS_INVALID', 'transition finalization chronology is invalid')
    const transition = sealRecord({
      format: 'jedi-atlas-recovery-checkpoint-transition', format_version: '1.2.0',
      transition_code: `progression.transition.${canonicalSha256({ request: request.record_digest_sha256 }).slice(0, 20)}`,
      transition_sequence: effectiveCheckpoint.checkpoint_sequence + 1,
      predecessor_checkpoint_record_digest_sha256: effectiveCheckpoint.checkpoint_record_digest_sha256,
      predecessor_checkpoint_append_receipt_record_digest_sha256: effectiveCheckpoint.checkpoint_append_receipt_record_digest_sha256,
      operation_id: assessment.operation_id, operation_nonce: assessment.operation_nonce, runtime_generation: expectedGeneration, subject: request.subject,
      prior_checkpoint: effectiveCheckpoint, component_resolution_attestations: request.component_resolution_attestations,
      composite_response_record_digest_sha256: request.composite_response_record_digest_sha256, composite_response_durable_record_digest_sha256: request.composite_response_durable_record_digest_sha256,
      composite_append_attestation_record_digest_sha256: request.composite_append_attestation_record_digest_sha256, composite_append_attestation_durable_record_digest_sha256: request.composite_append_attestation_durable_record_digest_sha256,
      append_request_record_digest_sha256: request.record_digest_sha256, append_request_protected_receipt_record_digest_sha256: requestEntry.receipt.record_digest_sha256,
      append_broker_receipt_record_digest_sha256: brokerEntry.payload.record_digest_sha256, append_broker_receipt_protected_receipt_record_digest_sha256: brokerEntry.receipt.record_digest_sha256,
      assessment_record_code: assessment.record_code, assessment_record_digest_sha256: assessment.record_digest_sha256, expected_d940_append_position: request.expected_d940_append_position,
      d940_append_receipt_record_digest_sha256: assessmentReceipt.record_digest_sha256, pre_append_source_heads: request.pre_append_source_heads, post_append_source_heads: postHeads,
      unchanged_source_namespace_codes: namespaces.filter((item) => item !== 'd940.global.control-journal.v1'),
      permitted_d940_delta: { source_namespace_code: 'd940.global.control-journal.v1', before: preD940, after: postD940, delta_code: 'single_authorized_assessment_append' },
      post_append_source_heads_digest_sha256: canonicalSha256(postHeads),
      finalizer_actor: authenticatedActorFor('trusted_launcher', finalizedAt), semantic_actor: authenticatedActorFor('independent_verifier', attestation.completed_at), persistence_actor: authenticatedActorFor('journal_broker', persistedAt),
      attestation_completed_at: attestation.completed_at, append_authorized_until: request.append_revalidate_by, assessment_persisted_at: assessmentReceipt.persisted_at, finalizer_observed_at: finalizedAt, persisted_at: persistedAt,
      freshness_boundary_code: 'assessment_append_within_attestation_window_and_exact_post_head_still_current', technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
    })
    assertProgressionSchema('checkpoint-transition-v1-2.schema.json', transition, 'checkpoint transition')
    persistProgression('d9.resolver.checkpoint-transitions.v1.2', transition, persistedAt, postD940)
    return validateDurableState().transitions.find((item) => item.transition.record_digest_sha256 === transition.record_digest_sha256)
  }

  function retainedRevalidationFor(state, assessment) {
    const operationRecords = state.durableRecords.filter((item) => item.wrapper.operation_id === assessment.operation_id && item.wrapper.operation_nonce === assessment.operation_nonce)
    const request = operationRecords.find((item) => item.wrapper.record_kind_code === 'request' && item.wrapper.resolver_kind_code === 'd940_composite_snapshot')
    const response = operationRecords.find((item) => item.wrapper.record_kind_code === 'response' && item.wrapper.resolver_kind_code === 'd940_composite_snapshot')
    const attestation = operationRecords.find((item) => item.wrapper.record_kind_code === 'append_attestation')
    const checkpoint = state.transitions.find((item) => response && attestation && item.transition.operation_id === assessment.operation_id && item.transition.operation_nonce === assessment.operation_nonce &&
      item.transition.composite_response_record_digest_sha256 === response.payload.record_digest_sha256 &&
      item.transition.composite_append_attestation_record_digest_sha256 === attestation.payload.record_digest_sha256)?.transition
    if (!request || !response || !attestation || !checkpoint || response.payload.request_record_digest_sha256 !== request.payload.record_digest_sha256 ||
        attestation.payload.composite_response_record_digest_sha256 !== response.payload.record_digest_sha256 ||
        assessment.snapshot_digest_sha256 !== response.payload.projection.snapshot_digest_sha256 || !same(assessment.snapshot, response.payload.projection.snapshot)) {
      failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'no exact durable request-response-attestation-checkpoint chain supports the assessment')
    }
    return deepFreeze({ attestation: attestation.payload, durableRequest: request.wrapper, durableResponse: response.wrapper, durableAttestation: attestation.wrapper, checkpoint })
  }

  function persistAssessmentLink({ revalidation, assessment, assessmentReceipt }) {
    let state = validateDurableState()
    const existing = state.links.find((item) => item.assessment.record_digest_sha256 === assessment.record_digest_sha256)
    if (existing) {
      if (!same(existing.assessment, assessment) || !same(existing.assessmentReceipt, assessmentReceipt)) failD941('D941_RESOLVER_ASSESSMENT_LINK_COLLISION', 'assessment replay differs from the retained durable link')
      return existing
    }
    if (assessment.format !== 'jedi-atlas-d940-recovery-assessment' || assessmentReceipt.target_format !== assessment.format || assessmentReceipt.target_record_digest_sha256 !== assessment.record_digest_sha256 || assessmentReceipt.target_subject_identity_sha256 !== assessment.subject.subject_identity_sha256 || assessmentReceipt.operation_id !== assessment.operation_id || assessmentReceipt.operation_nonce !== assessment.operation_nonce) failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'D9.4 assessment receipt does not bind the exact assessment')
    finalizeProgression({ revalidation, assessment, assessmentReceipt })
    state = validateDurableState()
    const retainedRevalidation = retainedRevalidationFor(state, assessment)
    if (revalidation != null && (!same(revalidation.durableRequest, retainedRevalidation.durableRequest) || !same(revalidation.durableResponse, retainedRevalidation.durableResponse) || !same(revalidation.durableAttestation, retainedRevalidation.durableAttestation))) failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'caller revalidation context differs from the reconstructed durable chain')
    revalidation = retainedRevalidation
    const retainedReceipt = broker.validate().find((item) => item.record_digest_sha256 === assessmentReceipt.record_digest_sha256)
    let retainedAssessment
    try { retainedAssessment = parseStrictJson(broker.store.read({ namespaceCode: 'recovery', recordCode: assessment.record_code }), { maximumBytes: 1024 * 1024, maximumDepth: 96, maximumMembers: 50_000, contractNumbers: true }) } catch (error) { failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'D9.4 assessment target is not durably readable', { cause: error.message }) }
    if (!retainedReceipt || !same(retainedReceipt, assessmentReceipt) || !same(retainedAssessment, assessment)) failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'assessment link requires the exact durable D9.4 target and receipt')
    const persistedAt = timestamp(trustedClock(), 'assessment-link durable persistence time')
    const classifiedAt = assessment.knowledge_boundary.recorded_at
    if (persistedAt <= assessmentReceipt.persisted_at || (state.links.at(-1)?.link.persisted_at ?? '') >= persistedAt) failD941('D941_RESOLVER_ASSESSMENT_LINK_INVALID', 'assessment-link persistence must follow its D9.4 receipt and prior protected link')
    assertAuthorityActive(persistedAt)
    const link = sealRecord({
      format: 'jedi-atlas-recovery-assessment-resolver-link', format_version: '1.1.0',
      link_code: `resolver.assessment.link.${assessment.record_digest_sha256.slice(0, 24)}`, operation_id: assessment.operation_id, operation_nonce: assessment.operation_nonce,
      runtime_generation: expectedGeneration, subject_identity_sha256: assessment.subject.subject_identity_sha256,
      request_durable_record_digest_sha256: revalidation.durableRequest.record_digest_sha256,
      response_durable_record_digest_sha256: revalidation.durableResponse.record_digest_sha256,
      attestation_durable_record_digest_sha256: revalidation.durableAttestation.record_digest_sha256,
      composite_response_record_digest_sha256: revalidation.durableResponse.payload_record_digest_sha256,
      append_attestation_record_digest_sha256: revalidation.durableAttestation.payload_record_digest_sha256,
      checkpoint_sequence: revalidation.checkpoint.transition_sequence ?? revalidation.checkpoint.sequence, checkpoint_record_digest_sha256: revalidation.checkpoint.record_digest_sha256,
      recovery_assessment_canonical_utf8: canonicalize(assessment), recovery_assessment_record_digest_sha256: assessment.record_digest_sha256,
      d940_assessment_receipt_canonical_utf8: canonicalize(assessmentReceipt), d940_assessment_receipt_sequence: assessmentReceipt.receipt_sequence,
      d940_assessment_receipt_record_digest_sha256: assessmentReceipt.record_digest_sha256, d940_assessment_journal_head_digest_sha256: assessmentReceipt.record_digest_sha256,
      semantic_actor: authenticatedActorFor('independent_verifier', classifiedAt), persistence_actor: authenticatedActorFor('journal_broker', persistedAt),
      classified_at: classifiedAt, persisted_at: persistedAt, technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
    })
    assertDurabilitySchema(durability, 'recovery-assessment-link-v1-1.schema.json', link, 'recovery assessment link')
    persistBatch('d9.resolver.assessment-links.v1.1', [link], link, persistedAt, persistedAt)
    state = validateDurableState()
    return state.links.find((item) => item.link.record_digest_sha256 === link.record_digest_sha256)
  }

  bootstrapDurability()
  const runtime = Object.freeze({ resolveComposite, revalidateAtAppend, reconstruct: validateDurableState })
  runtimes.add(runtime)
  runtimeInternals.set(runtime, Object.freeze({ persistAssessmentLink }))
  return runtime
}

export function assertD941RecoveryResolverRuntime(value) {
  if (!runtimes.has(value)) failD941('D941_RECOVERY_RESOLVER_UNTRUSTED', 'recovery resolver was not created by the fixed synthetic factory')
  return value
}

export function persistD941ResolverAssessmentLink(runtime, input) {
  assertD941RecoveryResolverRuntime(runtime)
  const internal = runtimeInternals.get(runtime)
  if (!internal) failD941('D941_RECOVERY_RESOLVER_UNTRUSTED', 'resolver assessment-link writer is unavailable')
  return internal.persistAssessmentLink(input)
}
