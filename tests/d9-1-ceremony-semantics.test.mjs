import assert from 'node:assert/strict'
import path from 'node:path'
import test from 'node:test'
import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import {
  assertSemanticallyVerifiedCeremonyRecord,
  validateBootstrapPermitSemantics,
  validateBundleSealSemantics,
  validateCollectorHandoffSemantics,
} from '../d9/control-plane/ceremony-semantics.mjs'
import {
  loadApprovedContractSet,
  validateApprovedRecord,
} from '../d9/control-plane/contracts.mjs'
import {
  createGenerationFixture,
  fixture,
  projectDirectory,
  reseal,
  verifyFixture,
} from './d9-1-support/runtime-fixture.mjs'

const contractRoot = path.join(projectDirectory, 'docs/schema/d9-0')

function expectCode(code) {
  return (error) => error?.code === code
}

function createEnvironment(t, mutateGeneration = () => {}) {
  const contractSet = loadApprovedContractSet({ contractRoot })
  const generationFixture = createGenerationFixture(t)
  mutateGeneration(generationFixture)
  reseal(generationFixture.identity)
  generationFixture.selection.identity_bindings_record_digest_sha256 = generationFixture.identity.record_digest_sha256
  const verifiedGeneration = verifyFixture(contractSet, generationFixture)
  return { contractSet, verifiedGeneration }
}

function approved(contractSet, schemaFile, record) {
  return validateApprovedRecord({ contractSet, schemaFile, record: reseal(record) })
}

function emptyState(contractSet, verifiedGeneration, fixtureCode = 'logical_state_empty') {
  const record = fixture(fixtureCode)
  record.state_payload.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  record.logical_state_sha256 = canonicalSha256(record.state_payload)
  return approved(contractSet, 'logical-state-seal-v1.schema.json', record)
}

function handoffRecord(contractSet, verifiedGeneration, mutate = () => {}) {
  const record = fixture('collector_handoff')
  const collector = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'collector')
  const broker = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'handoff_broker')
  record.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  record.identity_bindings_record_digest_sha256 = verifiedGeneration.identityBindings.record_digest_sha256
  record.collector_binding_code = collector.binding_code
  record.collector_principal_code = collector.atlas_principal_code
  record.collector_build_sha256 = verifiedGeneration.runtimeProfile.component_releases.find(
    (release) => release.runtime_role_code === 'collector',
  ).executable_sha256
  record.handoff_broker_binding_code = broker.binding_code
  mutate(record)
  return approved(contractSet, 'collector-handoff-v1.schema.json', record)
}

function bundleSealRecord(contractSet, verifiedGeneration, empty, {
  kind = 'principal_bootstrap',
  handoff,
  mutate = () => {},
} = {}) {
  const record = fixture(kind === 'principal_bootstrap' ? 'bootstrap_bundle_seal' : 'document_bundle_seal')
  record.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  record.identity_bindings_record_digest_sha256 = verifiedGeneration.identityBindings.record_digest_sha256
  record.submitter_binding_code = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'human_submitter').binding_code
  record.importer_binding_code = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'bundle_importer').binding_code
  record.launcher_binding_code = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'trusted_launcher').binding_code
  if (empty) {
    record.target_logical_state = {
      state_seal_code: empty.record_code,
      state_seal_record_digest_sha256: empty.record_digest_sha256,
      logical_state_sha256: empty.logical_state_sha256,
    }
  }
  if (handoff) {
    record.collector_handoffs[0].record_code = handoff.record_code
    record.collector_handoffs[0].record_digest_sha256 = handoff.record_digest_sha256
  }
  mutate(record)
  return approved(contractSet, 'collector-handoff-v1.schema.json', record)
}

function permitRecord(contractSet, verifiedGeneration, empty, mutate = () => {}) {
  const record = fixture('bootstrap_permit')
  record.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  record.identity_bindings_record_digest_sha256 = verifiedGeneration.identityBindings.record_digest_sha256
  record.importer_release_sha256 = verifiedGeneration.runtimeProfile.component_releases.find(
    (release) => release.runtime_role_code === 'bundle_importer',
  ).executable_sha256
  record.importer_binding_code = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'bundle_importer').binding_code
  record.submitter_binding_code = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'human_submitter').binding_code
  record.witness_binding_code = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'operational_witness').binding_code
  record.issuer_binding_code = verifiedGeneration.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'bootstrap_authority').binding_code
  record.target_empty_logical_state = {
    state_seal_code: empty.record_code,
    state_seal_record_digest_sha256: empty.record_digest_sha256,
    logical_state_sha256: empty.logical_state_sha256,
  }
  record.canonical_lineage_code = empty.state_payload.canonical_lineage_code
  mutate(record)
  return approved(contractSet, 'bootstrap-control-v1.schema.json', record)
}

function verifiedCeremony(t, mutateGeneration) {
  const environment = createEnvironment(t, mutateGeneration)
  const { contractSet, verifiedGeneration } = environment
  const empty = emptyState(contractSet, verifiedGeneration)
  const handoff = handoffRecord(contractSet, verifiedGeneration)
  validateCollectorHandoffSemantics({ contractSet, verifiedGeneration, collectorHandoff: handoff })
  const bootstrapSeal = bundleSealRecord(contractSet, verifiedGeneration, empty)
  validateBundleSealSemantics({ contractSet, verifiedGeneration, bundleSeal: bootstrapSeal })
  const documentSeal = bundleSealRecord(contractSet, verifiedGeneration, undefined, { kind: 'single_document', handoff })
  validateBundleSealSemantics({ contractSet, verifiedGeneration, bundleSeal: documentSeal, collectorHandoffs: [handoff] })
  const permit = permitRecord(contractSet, verifiedGeneration, empty)
  return { ...environment, empty, handoff, bootstrapSeal, documentSeal, permit }
}

test('D9.1 semantics accept the coherent handoff, bundle seals, and bootstrap permit', (t) => {
  const environment = verifiedCeremony(t)
  const result = validateBootstrapPermitSemantics({
    contractSet: environment.contractSet,
    verifiedGeneration: environment.verifiedGeneration,
    bootstrapPermit: environment.permit,
    bootstrapBundleSeals: [environment.bootstrapSeal],
    emptyLogicalStateSeal: environment.empty,
  })
  assert.equal(result, environment.permit)
  assert.equal(assertSemanticallyVerifiedCeremonyRecord(result, {
    kindCode: 'bootstrap_permit',
    verifiedGeneration: environment.verifiedGeneration,
  }), result)
})

test('collector handoff chronology, actor activity, attribution, build, and generation pins fail closed', async (t) => {
  const { contractSet, verifiedGeneration } = createEnvironment(t)
  for (const [code, mutate] of [
    ['CEREMONY_CHRONOLOGY_INVALID', (record) => { record.collection_completed_at = '2030-01-01T00:05:13.000Z' }],
    ['CEREMONY_BINDING_INACTIVE', (record) => { record.collection_started_at = '2030-01-01T00:00:58.000Z'; record.collection_completed_at = '2030-01-01T00:00:59.000Z'; record.handoff_recorded_at = '2030-01-01T00:01:00.000Z' }],
    ['CEREMONY_BINDING_MISMATCH', (record) => { record.collector_principal_code = 'synthetic.submitter' }],
    ['CEREMONY_BUILD_MISMATCH', (record) => { record.collector_build_sha256 = '17'.repeat(32) }],
    ['CEREMONY_GENERATION_MISMATCH', (record) => { record.runtime_profile_record_digest_sha256 = '18'.repeat(32) }],
  ]) {
    const handoff = handoffRecord(contractSet, verifiedGeneration, mutate)
    assert.throws(
      () => validateCollectorHandoffSemantics({ contractSet, verifiedGeneration, collectorHandoff: handoff }),
      expectCode(code),
    )
  }
})

test('bundle-seal semantics enforce bootstrap/document cardinality and current exact handoff resolution', (t) => {
  const environment = verifiedCeremony(t)
  assert.throws(
    () => validateBundleSealSemantics({
      contractSet: environment.contractSet,
      verifiedGeneration: environment.verifiedGeneration,
      bundleSeal: environment.bootstrapSeal,
      collectorHandoffs: [environment.handoff],
    }),
    expectCode('CEREMONY_HANDOFF_CARDINALITY'),
  )

  const wrongReference = bundleSealRecord(
    environment.contractSet,
    environment.verifiedGeneration,
    undefined,
    { kind: 'single_document', handoff: environment.handoff, mutate: (record) => { record.collector_handoffs[0].record_digest_sha256 = '19'.repeat(32) } },
  )
  assert.throws(
    () => validateBundleSealSemantics({
      contractSet: environment.contractSet,
      verifiedGeneration: environment.verifiedGeneration,
      bundleSeal: wrongReference,
      collectorHandoffs: [environment.handoff],
    }),
    expectCode('CEREMONY_HANDOFF_MISMATCH'),
  )

  const afterExpiry = bundleSealRecord(
    environment.contractSet,
    environment.verifiedGeneration,
    undefined,
    {
      kind: 'single_document',
      handoff: environment.handoff,
      mutate: (record) => {
        record.sealed_at = '2030-01-01T01:05:16.000Z'
        record.expires_at = '2030-01-01T01:06:16.000Z'
      },
    },
  )
  assert.throws(
    () => validateBundleSealSemantics({
      contractSet: environment.contractSet,
      verifiedGeneration: environment.verifiedGeneration,
      bundleSeal: afterExpiry,
      collectorHandoffs: [environment.handoff],
    }),
    expectCode('CEREMONY_HANDOFF_MISMATCH'),
  )
})

test('bundle seals require live, correctly typed submitter/importer/launcher bindings and increasing expiry', (t) => {
  const { contractSet, verifiedGeneration } = createEnvironment(t)
  const empty = emptyState(contractSet, verifiedGeneration)
  const expired = bundleSealRecord(contractSet, verifiedGeneration, empty, {
    mutate: (record) => { record.expires_at = record.sealed_at },
  })
  assert.throws(
    () => validateBundleSealSemantics({ contractSet, verifiedGeneration, bundleSeal: expired }),
    expectCode('CEREMONY_CHRONOLOGY_INVALID'),
  )
  const wrongRole = bundleSealRecord(contractSet, verifiedGeneration, empty, {
    mutate: (record) => { record.submitter_binding_code = 'binding.witness' },
  })
  assert.throws(
    () => validateBundleSealSemantics({ contractSet, verifiedGeneration, bundleSeal: wrongRole }),
    expectCode('CEREMONY_BINDING_MISMATCH'),
  )
})

test('bootstrap permits match exactly one current zero-handoff seal and the verified empty state', (t) => {
  const environment = verifiedCeremony(t)
  const validate = (overrides = {}) => validateBootstrapPermitSemantics({
    contractSet: environment.contractSet,
    verifiedGeneration: environment.verifiedGeneration,
    bootstrapPermit: environment.permit,
    bootstrapBundleSeals: [environment.bootstrapSeal],
    emptyLogicalStateSeal: environment.empty,
    ...overrides,
  })
  assert.throws(() => validate({ bootstrapBundleSeals: [] }), expectCode('CEREMONY_SEAL_MATCH_INVALID'))
  assert.throws(
    () => validate({ bootstrapBundleSeals: [environment.bootstrapSeal, environment.bootstrapSeal] }),
    expectCode('CEREMONY_SEAL_MATCH_INVALID'),
  )
  const nonempty = emptyState(environment.contractSet, environment.verifiedGeneration, 'logical_state_bootstrap')
  assert.throws(() => validate({ emptyLogicalStateSeal: nonempty }), expectCode('CEREMONY_TARGET_NOT_EMPTY'))
})

test('bootstrap permit chronology, seal currency, importer build, and participant lifetimes fail closed', (t) => {
  const environment = verifiedCeremony(t)
  for (const [code, mutate] of [
    ['CEREMONY_PERMIT_LIFETIME_INVALID', (record) => { record.expires_at = '2030-01-01T01:05:00.001Z' }],
    ['CEREMONY_SEAL_EXPIRED', (record) => { record.issued_at = '2030-01-01T01:04:30.000Z'; record.not_before = record.issued_at; record.expires_at = '2030-01-01T01:05:00.000Z' }],
    ['CEREMONY_BUILD_MISMATCH', (record) => { record.importer_release_sha256 = '20'.repeat(32) }],
  ]) {
    const permit = permitRecord(environment.contractSet, environment.verifiedGeneration, environment.empty, mutate)
    assert.throws(
      () => validateBootstrapPermitSemantics({
        contractSet: environment.contractSet,
        verifiedGeneration: environment.verifiedGeneration,
        bootstrapPermit: permit,
        bootstrapBundleSeals: [environment.bootstrapSeal],
        emptyLogicalStateSeal: environment.empty,
      }),
      expectCode(code),
    )
  }

  const shortBinding = verifiedCeremony(t, (generation) => {
    generation.identity.bindings.find((binding) => binding.runtime_role_code === 'operational_witness').valid_until = '2030-01-01T00:30:00.000Z'
  })
  assert.throws(
    () => validateBootstrapPermitSemantics({
      contractSet: shortBinding.contractSet,
      verifiedGeneration: shortBinding.verifiedGeneration,
      bootstrapPermit: shortBinding.permit,
      bootstrapBundleSeals: [shortBinding.bootstrapSeal],
      emptyLogicalStateSeal: shortBinding.empty,
    }),
    expectCode('CEREMONY_BINDING_LIFETIME'),
  )
})

test('expected bootstrap roster comparison is explicitly deferred to D9.2 manifest reopening', (t) => {
  const environment = verifiedCeremony(t)
  const permit = permitRecord(
    environment.contractSet,
    environment.verifiedGeneration,
    environment.empty,
    (record) => { record.expected_principal_roster_sha256 = '21'.repeat(32) },
  )
  const result = validateBootstrapPermitSemantics({
    contractSet: environment.contractSet,
    verifiedGeneration: environment.verifiedGeneration,
    bootstrapPermit: permit,
    bootstrapBundleSeals: [environment.bootstrapSeal],
    emptyLogicalStateSeal: environment.empty,
  })
  assert.equal(result, permit)
})
