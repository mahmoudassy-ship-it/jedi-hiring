import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import { canonicalSha256, canonicalize, parseStrictJson, sha256Bytes } from '../control-plane/canonical.mjs'
import { validateD940Record } from './contracts.mjs'
import { failD941 } from './errors.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const contractRoot = path.resolve(here, '../../docs/schema/d9-recovery-resolvers-v1-3')
const v1Root = path.resolve(here, '../../docs/schema/d9-recovery-resolvers')
const v11Root = path.resolve(here, '../../docs/schema/d9-recovery-resolvers-v1-1')
const d90Root = path.resolve(here, '../../docs/schema/d9-0')
const d940Root = path.resolve(here, '../../docs/schema/d9-4-0')

const rootInventorySha256 = '51d076dd244aa74c4fc7a433af6ab8121031f4b6194381477460c81ccd807fda'
const catalogSha256 = '0aa40744517d595cafca368852771345f52db4c0b2bda36751912607183bcc9a'
const validatorSha256 = '49a89a606a133f9778d2329972e94c1bc40cdee9c2a3225c4746cd29ed0f3e0f'
const d940CatalogSha256 = '12da4237efade65cf6e2cc19d2df936e98caf505c8f6d30b38e7df8c4d349ad7'
const emptyStatePersistedAt = '1970-01-01T00:00:00.000Z'

export const D941_IDENTITY_V13_NAMESPACES = Object.freeze([
  'd9.resolver.source-head-correspondence.v1.3',
  'd9.resolver.identity-corrections.v1.3',
])

const schemaFiles = Object.freeze([
  'common-v1-3.schema.json',
  'source-head-receipt-correspondence-v1-3.schema.json',
  'control-access-projection-v1-3.schema.json',
  'checkpoint-identity-v1-3.schema.json',
  'assessment-append-request-v1-3.schema.json',
  'assessment-append-broker-receipt-v1-3.schema.json',
  'checkpoint-transition-v1-3.schema.json',
  'recovery-assessment-link-v1-3.schema.json',
  'protected-append-receipt-v1-3.schema.json',
  'append-result-v1-3.schema.json',
])

const targetNamespaces = Object.freeze({
  'jedi-atlas-custody-control-record': 'control',
  'jedi-atlas-access-revocation-record': 'access',
  'jedi-atlas-deletion-execution-record': 'execution',
  'jedi-atlas-deletion-receipt': 'receipt',
  'jedi-atlas-backup-coordination-record': 'backup',
  'jedi-atlas-d940-recovery-assessment': 'recovery',
})

let cachedContract = null

function readStrict(file, expectedSha256 = null) {
  const stat = fs.lstatSync(file)
  if (!stat.isFile() || stat.isSymbolicLink()) failD941('D941_IDENTITY_V13_CONTRACT_UNPROTECTED', `${file} is not a protected regular file`)
  const bytes = fs.readFileSync(file)
  if (expectedSha256 !== null && sha256Bytes(bytes) !== expectedSha256) failD941('D941_IDENTITY_V13_CONTRACT_CHANGED', `${file} differs from the approved v1.3 freeze`)
  return parseStrictJson(bytes, { maximumBytes: 16 * 1024 * 1024, maximumDepth: 256, maximumMembers: 500_000, contractNumbers: true })
}

function same(left, right) { return canonicalize(left) === canonicalize(right) }
function recordDigest(record) { return canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' }) }

export function loadD941IdentityV13Contract() {
  if (cachedContract !== null) return cachedContract
  const inventory = readStrict(path.join(contractRoot, 'root-inventory-v1-3.json'), rootInventorySha256)
  const expectedFiles = [...inventory.files].sort((a, b) => a.path.localeCompare(b.path))
  const diskFiles = []
  const walk = (directory, prefix = '') => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const relative = path.posix.join(prefix, entry.name)
      if (entry.isDirectory()) walk(path.join(directory, entry.name), relative)
      else if (relative !== 'root-inventory-v1-3.json') diskFiles.push(relative)
    }
  }
  walk(contractRoot)
  if (!same(diskFiles.sort(), expectedFiles.map((item) => item.path))) failD941('D941_IDENTITY_V13_INVENTORY_CHANGED', 'v1.3 contract-root inventory differs from the approved freeze')
  for (const file of expectedFiles) readStrict(path.join(contractRoot, file.path), file.raw_sha256)
  const catalog = readStrict(path.join(contractRoot, 'contract-catalog-v1-3.json'), catalogSha256)
  if (catalog.status_code !== 'design_only_contract_freeze' || catalog.instance_policy.runtime_implementation_authorized !== false || catalog.instance_policy.operational_activation_authorized !== false) failD941('D941_IDENTITY_V13_BOUNDARY_INVALID', 'v1.3 contract no longer preserves its design-only unactivated boundary')
  const validatorPath = path.resolve(here, '../../docs/schema/validate-d9-recovery-resolvers-v1-3.mjs')
  if (sha256Bytes(fs.readFileSync(validatorPath)) !== validatorSha256) failD941('D941_IDENTITY_V13_VERIFIER_CHANGED', 'approved v1.3 validator bytes changed')
  if (sha256Bytes(fs.readFileSync(path.join(d940Root, 'contract-catalog-v1.json'))) !== d940CatalogSha256) failD941('D941_IDENTITY_V13_D940_CHANGED', 'approved D9.4 source contract changed')

  const dependencies = [
    [d90Root, 'common-v1.schema.json'],
    [v1Root, 'common-v1.schema.json'],
    [v11Root, 'common-v1-1.schema.json'],
    [d940Root, 'common-v1.schema.json'],
    [d940Root, 'journal-append-receipt-v1.schema.json'],
    [d940Root, 'recovery-assessment-v1.schema.json'],
  ].map(([root, file]) => readStrict(path.join(root, file)))
  const schemas = schemaFiles.map((file) => readStrict(path.join(contractRoot, file)))
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  for (const schema of [...dependencies, ...schemas]) ajv.addSchema(schema)
  const validate = Object.freeze(Object.fromEntries(schemas.slice(1).map((schema) => [schema.$id.split('/').at(-1), ajv.getSchema(schema.$id)])))
  cachedContract = Object.freeze({ catalog, inventory, validate })
  return cachedContract
}

export function assertD941IdentityV13Schema(contract, schemaFile, value, label) {
  const validator = contract?.validate?.[schemaFile]
  if (!validator || !validator(value)) failD941('D941_IDENTITY_V13_SCHEMA_REJECTED', `${label} violates ${schemaFile}: ${validator?.errors?.map((item) => `${item.instancePath || '/'} ${item.message}`).join('; ')}`, { details: validator?.errors })
  if (value.record_digest_sha256 !== recordDigest(value)) failD941('D941_IDENTITY_V13_DIGEST_INVALID', `${label} has an invalid canonical self-digest`)
  return value
}

function receiptTargetRecords(broker, authorityContext) {
  return broker.validate().map((receipt) => {
    validateD940Record({ contractSet: authorityContext.contractSet, record: receipt })
    const namespaceCode = targetNamespaces[receipt.target_format]
    if (!namespaceCode) failD941('D941_IDENTITY_V13_SOURCE_INVALID', 'D9.4 receipt has an unsupported target format')
    let record
    try {
      record = parseStrictJson(broker.store.read({ namespaceCode, recordCode: receipt.target_record_code }), { maximumBytes: 4 * 1024 * 1024, maximumDepth: 128, maximumMembers: 100_000, contractNumbers: true })
    } catch (error) {
      failD941('D941_IDENTITY_V13_SOURCE_INVALID', 'D9.4 receipt target is unreadable', { cause: error.message })
    }
    validateD940Record({ contractSet: authorityContext.contractSet, record })
    if (record.record_digest_sha256 !== receipt.target_record_digest_sha256 || record.subject?.subject_identity_sha256 !== receipt.target_subject_identity_sha256) failD941('D941_IDENTITY_V13_SOURCE_INVALID', 'D9.4 receipt does not resolve to its exact target bytes')
    return Object.freeze({ receipt, record })
  })
}

function recordKind(record) {
  return record.format === 'jedi-atlas-d940-recovery-assessment' ? 'recovery_assessment' : record.record_kind_code
}

function rawPayload(items) {
  return {
    known_through_receipt_sequence: items.length === 0 ? 0 : items.at(-1).receipt.receipt_sequence,
    records: items.map(({ receipt, record }) => ({
      receipt_sequence: receipt.receipt_sequence,
      record_kind_code: recordKind(record),
      record_digest_sha256: record.record_digest_sha256,
    })),
  }
}

function prefixEntry(receipt) {
  return {
    receipt_sequence: receipt.receipt_sequence,
    receipt_canonical_utf8: canonicalize(receipt),
    receipt_record_digest_sha256: receipt.record_digest_sha256,
    predecessor_receipt_record_digest_sha256: receipt.previous_receipt_record_digest_sha256,
    target_format: receipt.target_format,
    target_record_code: receipt.target_record_code,
    target_record_digest_sha256: receipt.target_record_digest_sha256,
    receipt_persisted_at: receipt.persisted_at,
  }
}

export function deriveD941IdentityV13Material({ broker, authorityContext, sequence = broker.head().sequence }) {
  const retained = receiptTargetRecords(broker, authorityContext)
  if (!Number.isSafeInteger(sequence) || sequence < 0 || sequence > retained.length) failD941('D941_IDENTITY_V13_SOURCE_UNAVAILABLE', 'requested D9.4 source prefix is unavailable')
  const items = retained.slice(0, sequence)
  let predecessor = null
  let priorPersistedAt = null
  for (const [index, { receipt }] of items.entries()) {
    if (receipt.receipt_sequence !== index + 1 || receipt.previous_receipt_record_digest_sha256 !== predecessor || (priorPersistedAt !== null && receipt.persisted_at <= priorPersistedAt)) failD941('D941_IDENTITY_V13_SOURCE_INVALID', 'D9.4 receipt prefix is gapped, forked, or backdated')
    predecessor = receipt.record_digest_sha256
    priorPersistedAt = receipt.persisted_at
  }
  const payload = rawPayload(items)
  const payloadCanonical = canonicalize(payload)
  const commitment = { source_payload_code: 'control_records', raw_payload_canonical_utf8: payloadCanonical, raw_payload_sha256: canonicalSha256(payload) }
  const payloadCommitments = [{ source_payload_code: commitment.source_payload_code, raw_payload_sha256: commitment.raw_payload_sha256 }]
  const inventory = canonicalSha256({ source_namespace_code: 'd940.global.control-journal.v1', head_sequence: sequence, payload_commitments: payloadCommitments })
  const tip = items.at(-1)?.receipt ?? null
  const persistedAt = tip?.persisted_at ?? emptyStatePersistedAt
  const stateDigest = canonicalSha256({ source_namespace_code: 'd940.global.control-journal.v1', head_sequence: sequence, head_persisted_at: persistedAt, inventory_digest_sha256: inventory })
  const prefix = items.map(({ receipt }) => prefixEntry(receipt))
  return Object.freeze({
    stateHead: Object.freeze({
      source_namespace_code: 'd940.global.control-journal.v1',
      source_contract_fingerprint_sha256: d940CatalogSha256,
      head_sequence: sequence,
      head_persisted_at: persistedAt,
      raw_payload_inventory_digest_sha256: inventory,
      state_head_digest_sha256: stateDigest,
      derivation_profile_code: 'frozen_v1_raw_payload_commitments',
    }),
    journalTip: Object.freeze(tip ? {
      journal_namespace_code: 'd940.global.control-journal.v1',
      receipt_sequence: tip.receipt_sequence,
      receipt_record_digest_sha256: tip.record_digest_sha256,
      target_format: tip.target_format,
      target_record_code: tip.target_record_code,
      target_record_digest_sha256: tip.target_record_digest_sha256,
      predecessor_receipt_record_digest_sha256: tip.previous_receipt_record_digest_sha256,
      receipt_persisted_at: tip.persisted_at,
    } : {
      journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: 0,
      receipt_record_digest_sha256: null, target_format: null, target_record_code: null,
      target_record_digest_sha256: null, predecessor_receipt_record_digest_sha256: null, receipt_persisted_at: null,
    }),
    authenticatedReceiptPrefix: Object.freeze(prefix),
    rawPayloadCommitments: Object.freeze([Object.freeze(commitment)]),
    rawPrefixDigestSha256: canonicalSha256(prefix.map(({ receipt_canonical_utf8: ignored, ...identity }) => identity)),
    items: Object.freeze(items),
  })
}

export function createD941IdentityV13Correspondence({ broker, authorityContext, runtimeGeneration, observedAt, semanticVerifierActor, persistenceBrokerActor, emptyOperationId, emptyOperationNonce }) {
  const material = deriveD941IdentityV13Material({ broker, authorityContext })
  const tipReceipt = material.items.at(-1)?.receipt ?? null
  const operationId = tipReceipt?.operation_id ?? emptyOperationId
  const operationNonce = tipReceipt?.operation_nonce ?? emptyOperationNonce
  if (typeof operationId !== 'string' || typeof operationNonce !== 'string') failD941('D941_IDENTITY_V13_OPERATION_INVALID', 'empty correspondence requires one deterministic bootstrap operation identity')
  const correspondence = {
    format: 'jedi-atlas-d940-source-head-receipt-correspondence', format_version: '1.3.0',
    correspondence_code: `correspondence.d940.${String(material.stateHead.head_sequence).padStart(12, '0')}.${material.stateHead.state_head_digest_sha256.slice(0, 16)}`,
    operation_id: operationId, operation_nonce: operationNonce, runtime_generation: structuredClone(runtimeGeneration),
    state_head: structuredClone(material.stateHead), journal_tip: structuredClone(material.journalTip),
    authenticated_receipt_prefix: structuredClone(material.authenticatedReceiptPrefix), raw_payload_commitments: structuredClone(material.rawPayloadCommitments),
    raw_prefix_digest_sha256: material.rawPrefixDigestSha256, semantic_verifier_actor: structuredClone(semanticVerifierActor),
    persistence_broker_actor: structuredClone(persistenceBrokerActor), observed_at: observedAt,
    technical_journal_continuity_only: true, authority_granted: false, record_digest_sha256: null,
  }
  correspondence.record_digest_sha256 = recordDigest(correspondence)
  return correspondence
}

export function d941IdentityV13CorrespondenceReference(value) {
  return {
    correspondence_code: value.correspondence_code,
    correspondence_record_digest_sha256: value.record_digest_sha256,
    state_head_digest_sha256: value.state_head.state_head_digest_sha256,
    journal_tip_receipt_record_digest_sha256: value.journal_tip.receipt_record_digest_sha256,
    receipt_sequence: value.journal_tip.receipt_sequence,
  }
}

export function d941IdentityV13SourceHead(value) {
  return {
    source_namespace_code: value.state_head.source_namespace_code,
    source_contract_fingerprint_sha256: value.state_head.source_contract_fingerprint_sha256,
    head_sequence: value.state_head.head_sequence,
    head_digest_sha256: value.state_head.state_head_digest_sha256,
    head_persisted_at: value.state_head.head_persisted_at,
    inventory_digest_sha256: value.state_head.raw_payload_inventory_digest_sha256,
  }
}

export function validateD941IdentityV13Correspondence({ contract, broker, authorityContext, value, runtimeGeneration, assertActor }) {
  assertD941IdentityV13Schema(contract, 'source-head-receipt-correspondence-v1-3.schema.json', value, 'D9.4 source-head/receipt correspondence')
  if (!same(value.runtime_generation, runtimeGeneration)) failD941('D941_IDENTITY_V13_GENERATION_INVALID', 'correspondence belongs to another runtime generation')
  assertActor(value.semantic_verifier_actor, 'independent_verifier', value.observed_at)
  assertActor(value.persistence_broker_actor, 'journal_broker', value.observed_at)
  const material = deriveD941IdentityV13Material({ broker, authorityContext, sequence: value.journal_tip.receipt_sequence })
  if (!same(value.state_head, material.stateHead) || !same(value.journal_tip, material.journalTip) || !same(value.authenticated_receipt_prefix, material.authenticatedReceiptPrefix) || !same(value.raw_payload_commitments, material.rawPayloadCommitments) || value.raw_prefix_digest_sha256 !== material.rawPrefixDigestSha256) failD941('D941_IDENTITY_V13_CORRESPONDENCE_INVALID', 'correspondence does not match the independently reconstructed D9.4 raw prefix and journal tip')
  const tip = material.items.at(-1)?.receipt ?? null
  if (tip && (value.operation_id !== tip.operation_id || value.operation_nonce !== tip.operation_nonce || value.observed_at < tip.persisted_at)) failD941('D941_IDENTITY_V13_CORRESPONDENCE_INVALID', 'correspondence operation, nonce, or observation time differs from its exact journal tip')
  if (tip && value.state_head.state_head_digest_sha256 === value.journal_tip.receipt_record_digest_sha256) failD941('D941_IDENTITY_V13_FORCED_EQUALITY', 'state-head identity must remain distinct from journal-tip receipt identity')
  return value
}

export function d941IdentityV13CheckpointCas(sequence, predecessorCheckpointDigest, reference) {
  return canonicalSha256({
    checkpoint_sequence: sequence,
    predecessor_checkpoint_identity_record_digest_sha256: predecessorCheckpointDigest,
    correspondence_record_digest_sha256: reference.correspondence_record_digest_sha256,
    state_head_digest_sha256: reference.state_head_digest_sha256,
  })
}

export function createD941IdentityV13Checkpoint({ sequence, correspondence, predecessorCheckpointDigest, predecessorTransitionReceiptDigest, createdAt }) {
  const reference = d941IdentityV13CorrespondenceReference(correspondence)
  const checkpoint = {
    format: 'jedi-atlas-recovery-checkpoint-source-identity', format_version: '1.3.0',
    checkpoint_identity_code: `checkpoint.identity.${String(sequence).padStart(12, '0')}`,
    anchor_kind_code: sequence === 0 ? 'empty_runtime_genesis' : 'receipt_proven_transition', checkpoint_sequence: sequence,
    predecessor_checkpoint_identity_record_digest_sha256: predecessorCheckpointDigest,
    predecessor_transition_receipt_record_digest_sha256: predecessorTransitionReceiptDigest,
    d940_correspondence: reference,
    checkpoint_cas_identity_sha256: d941IdentityV13CheckpointCas(sequence, predecessorCheckpointDigest, reference),
    created_at: createdAt, technical_evidence_only: true, authority_granted: false, record_digest_sha256: null,
  }
  checkpoint.record_digest_sha256 = recordDigest(checkpoint)
  return checkpoint
}

export function d941IdentityV13PayloadIdentity(value) {
  return `${value.format}:${value.request_code ?? value.receipt_code ?? value.transition_code ?? value.link_code ?? value.projection_code ?? value.checkpoint_identity_code ?? value.correspondence_code}`
}

export function d941IdentityV13CollisionKeys(value) {
  const keys = [`primary:${d941IdentityV13PayloadIdentity(value)}`]
  if (value.operation_id && value.operation_nonce) keys.push(`operation:${value.format}:${value.operation_id}:${value.operation_nonce}`)
  if (value.transition_sequence !== undefined) keys.push(`transition-sequence:${value.transition_sequence}`)
  if (value.checkpoint_sequence !== undefined) keys.push(`checkpoint-sequence:${value.checkpoint_sequence}`)
  if (value.target_receipt_sequence !== undefined) keys.push(`request-target:${value.target_receipt_sequence}`)
  return keys
}

export function sealD941IdentityV13Record(value) {
  value.record_digest_sha256 = recordDigest(value)
  return value
}

export function sameD941IdentityV13(left, right) { return same(left, right) }
