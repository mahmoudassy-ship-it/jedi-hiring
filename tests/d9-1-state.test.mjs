import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  SimulatedStateCrash,
  StateStoreError,
  canonicalizeStateRecord,
  createProtectedStateStore,
  openProtectedStateStore,
  sha256Hex,
} from '../d9/control-plane/state-store.mjs'

const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const fixtures = JSON.parse(fs.readFileSync(path.join(projectDirectory, 'docs/schema/d9-0/fixtures/valid-contracts-v1.json'), 'utf8')).fixtures
const frozen = (fixtureCode) => structuredClone(fixtures.find((fixture) => fixture.fixture_code === fixtureCode).value)
const resealRecord = (record) => {
  const unsigned = structuredClone(record)
  delete unsigned.record_digest_sha256
  record.record_digest_sha256 = sha256Hex(Buffer.from(canonicalizeStateRecord(unsigned), 'utf8'))
  return record
}
const runtimeDigest = frozen('runtime_profile').record_digest_sha256
const bindingsDigest = frozen('identity_bindings').record_digest_sha256
const trustedIdentityBindingsRecord = Object.freeze(frozen('identity_bindings'))
const trustedBindings = Object.freeze({
  trusted_launcher: 'binding.launcher',
  handoff_broker: 'binding.handoff-broker',
  bootstrap_authority: 'binding.bootstrap-authority',
  recovery_authority: 'binding.recovery-authority',
  independent_verifier: 'binding.verifier',
})

function expectCode(action, code) {
  assert.throws(action, (error) => error instanceof StateStoreError && error.code === code, `expected ${code}`)
}

function workspace(prefix = 'jedi-d9-state-') {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), prefix))
  return { parent, root: path.join(parent, 'protected'), remove: () => fs.rmSync(parent, { recursive: true, force: true }) }
}

function firstPair(overrides = {}) {
  return {
    pairCode: 'synthetic.active-pair-001',
    pairGeneration: 1,
    runtimeProfile: {
      generationNumber: 1,
      generationCode: 'synthetic.runtime-profile-001',
      recordDigestSha256: runtimeDigest,
      validFrom: '2030-01-01T00:01:00.000Z',
      expiresAt: '2030-01-02T00:01:00.000Z',
    },
    identityBindings: {
      generationNumber: trustedIdentityBindingsRecord.binding_generation,
      generationCode: trustedIdentityBindingsRecord.binding_set_code,
      recordDigestSha256: bindingsDigest,
      boundRuntimeProfileRecordDigestSha256: runtimeDigest,
      validFrom: trustedIdentityBindingsRecord.issued_at,
      expiresAt: trustedIdentityBindingsRecord.expires_at,
    },
    identityBindingsRecord: trustedIdentityBindingsRecord,
    activatedAt: '2030-01-01T00:01:01.000Z',
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
    ...overrides,
  }
}

function identityGeneration({ generationNumber, generationCode, runtimeProfileDigest, issuedAt, bindingCodeSuffix = '', bindingOverrides = {} }) {
  const unsigned = structuredClone(trustedIdentityBindingsRecord)
  delete unsigned.record_digest_sha256
  unsigned.record_code = `${generationCode}.record`
  unsigned.binding_set_code = generationCode
  unsigned.binding_generation = generationNumber
  unsigned.runtime_profile_record_digest_sha256 = runtimeProfileDigest
  unsigned.issued_at = issuedAt
  unsigned.bindings = unsigned.bindings.map((binding) => ({
    ...binding,
    binding_code: `${binding.binding_code}${bindingCodeSuffix}`,
    ...(bindingOverrides[binding.runtime_role_code] ?? {}),
  }))
  return { ...unsigned, record_digest_sha256: sha256Hex(Buffer.from(canonicalizeStateRecord(unsigned), 'utf8')) }
}

function initializedStore({ faultInjector, identityRecord = trustedIdentityBindingsRecord } = {}) {
  const location = workspace()
  const store = createProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord: identityRecord, faultInjector })
  const initialPair = firstPair({
    identityBindings: {
      ...firstPair().identityBindings,
      generationNumber: identityRecord.binding_generation,
      generationCode: identityRecord.binding_set_code,
      recordDigestSha256: identityRecord.record_digest_sha256,
      boundRuntimeProfileRecordDigestSha256: identityRecord.runtime_profile_record_digest_sha256,
      validFrom: identityRecord.issued_at,
      expiresAt: identityRecord.expires_at,
    },
    identityBindingsRecord: identityRecord,
  })
  store.activateGenerationPair(initialPair)
  return { ...location, store }
}

function operation(overrides = {}) {
  return {
    operationId: 'synthetic.operation-dry-run',
    operationNonce: 'ab'.repeat(32),
    operationModeCode: 'dry_run',
    startedAt: '2030-01-01T00:02:00.000Z',
    runtimeProfileRecordDigestSha256: runtimeDigest,
    identityBindingsRecordDigestSha256: bindingsDigest,
    ...overrides,
  }
}

function registerBootstrapSeal(store) {
  const seal = frozen('bootstrap_bundle_seal')
  store.registerFixedRecord({
    record: seal,
    recordedAt: seal.sealed_at,
    authenticatedRuntimeRoleCode: 'trusted_launcher',
    authenticatedBindingCode: trustedBindings.trusted_launcher,
  })
  return seal
}

function ambiguousTransition(claim, overrides = {}) {
  return resealRecord({
    ...structuredClone(claim),
    record_code: 'synthetic.permit-transition-ambiguous',
    transition_sequence: 2,
    previous_transition_record_digest_sha256: claim.record_digest_sha256,
    from_state_code: 'in_progress',
    to_state_code: 'recovery_required',
    transition_code: 'state_ambiguous',
    observed_logical_state: null,
    occurred_at: '2030-01-01T00:05:02.000Z',
    persisted_at: '2030-01-01T00:05:02.000Z',
    reason_code: 'state_ambiguous',
    ...overrides,
  })
}

function fileTreeDigest(root) {
  const hash = crypto.createHash('sha256')
  function visit(directory, relative = '') {
    for (const name of fs.readdirSync(directory).sort()) {
      const full = path.join(directory, name)
      const next = path.join(relative, name)
      const stat = fs.lstatSync(full)
      hash.update(`${next}\0${stat.mode & 0o777}\0`)
      if (stat.isDirectory()) visit(full, next)
      else hash.update(fs.readFileSync(full))
    }
  }
  visit(root)
  return hash.digest('hex')
}

function fileDigestAndLength(filePath) {
  const bytes = fs.readFileSync(filePath)
  return { sha256: crypto.createHash('sha256').update(bytes).digest('hex'), byteLength: bytes.length }
}

test('D9.1 protected state atomically binds active runtime and identity generations', async (t) => {
  const location = workspace()
  t.after(location.remove)
  const store = createProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
  assert.deepEqual(store.inspect(), {
    sequence: 0,
    headCommitSha256: null,
    recoveryRequired: false,
    recoveryReasons: [],
    activeOperation: null,
  })

  store.activateGenerationPair(firstPair())
  assert.equal(store.inspect().sequence, 1, 'the pair is one protected commit')
  assert.equal(store.selectActiveGeneration({ generationKindCode: 'runtime_profile', asOf: '2030-01-01T00:01:02.000Z' }).record_digest_sha256, runtimeDigest)
  assert.equal(store.selectActiveGenerationPair({
    asOf: '2030-01-01T00:01:02.000Z',
    runtimeProfileRecordDigestSha256: runtimeDigest,
    identityBindingsRecordDigestSha256: bindingsDigest,
  }).identity_bindings.record_digest_sha256, bindingsDigest)

  const missingFactsLocation = workspace('jedi-d9-state-missing-bindings-')
  t.after(missingFactsLocation.remove)
  const missingBindingRecord = structuredClone(trustedIdentityBindingsRecord)
  delete missingBindingRecord.record_digest_sha256
  missingBindingRecord.bindings = missingBindingRecord.bindings.slice(1)
  missingBindingRecord.record_digest_sha256 = sha256Hex(Buffer.from(canonicalizeStateRecord(missingBindingRecord), 'utf8'))
  expectCode(() => createProtectedStateStore({ rootPath: missingFactsLocation.root, trustedIdentityBindingsRecord: missingBindingRecord }), 'STATE_BINDING_FACTS_INVALID')

  const badBinding = firstPair({ pairCode: 'synthetic.bad-pair' })
  badBinding.identityBindings = { ...badBinding.identityBindings, boundRuntimeProfileRecordDigestSha256: '00'.repeat(32) }
  expectCode(() => store.activateGenerationPair(badBinding), 'STATE_GENERATION_PAIR_MISMATCH')

  const forgedIdentityRecord = structuredClone(trustedIdentityBindingsRecord)
  delete forgedIdentityRecord.record_digest_sha256
  forgedIdentityRecord.bindings = forgedIdentityRecord.bindings.map((binding) => binding.runtime_role_code === 'recovery_authority' ? { ...binding, binding_code: 'binding.forged-recovery-authority' } : binding)
  forgedIdentityRecord.record_digest_sha256 = sha256Hex(Buffer.from(canonicalizeStateRecord(forgedIdentityRecord), 'utf8'))
  expectCode(() => store.activateGenerationPair(firstPair({
    pairCode: 'synthetic.forged-bindings-pair',
    pairGeneration: 2,
    activatedAt: '2030-01-01T00:02:00.000Z',
    identityBindingsRecord: forgedIdentityRecord,
  })), 'STATE_IDENTITY_BINDINGS_SUBSTITUTION')

  const gap = firstPair({ pairCode: 'synthetic.gap-pair', pairGeneration: 3, activatedAt: '2030-01-01T00:02:00.000Z' })
  expectCode(() => store.activateGenerationPair(gap), 'STATE_GENERATION_GAP_OR_STALE')
  const stale = firstPair({ pairCode: 'synthetic.stale-pair', pairGeneration: 1, activatedAt: '2030-01-01T00:02:00.000Z' })
  expectCode(() => store.activateGenerationPair(stale), 'STATE_GENERATION_GAP_OR_STALE')

  const secondIdentityRecord = identityGeneration({ generationNumber: 2, generationCode: 'synthetic.identity-bindings-002', runtimeProfileDigest: '54'.repeat(32), issuedAt: '2030-01-01T00:03:00.000Z' })
  const second = firstPair({
    pairCode: 'synthetic.active-pair-002',
    pairGeneration: 2,
    activatedAt: '2030-01-01T00:03:01.000Z',
    runtimeProfile: { ...firstPair().runtimeProfile, generationNumber: 2, generationCode: 'synthetic.runtime-profile-002', recordDigestSha256: '54'.repeat(32), validFrom: '2030-01-01T00:03:00.000Z' },
    identityBindings: { ...firstPair().identityBindings, generationNumber: 2, generationCode: 'synthetic.identity-bindings-002', recordDigestSha256: secondIdentityRecord.record_digest_sha256, boundRuntimeProfileRecordDigestSha256: '54'.repeat(32), validFrom: '2030-01-01T00:03:00.000Z' },
    identityBindingsRecord: secondIdentityRecord,
  })
  store.activateGenerationPair(second)
  assert.equal(store.selectActiveGenerationPair({ asOf: '2030-01-01T00:02:59.999Z' }).pair_generation, 1, 'a future activation cannot rewrite an earlier selection')
  assert.equal(store.selectActiveGenerationPair({ asOf: '2030-01-01T00:03:02.000Z' }).pair_generation, 2)
  expectCode(() => store.selectActiveGenerationPair({ asOf: '2030-01-01T00:03:02.000Z', runtimeProfileRecordDigestSha256: '00'.repeat(32) }), 'STATE_ACTIVE_GENERATION_SUBSTITUTED')

  expectCode(() => store.activateGenerationPair(firstPair({
    pairCode: 'synthetic.resurrected-pair',
    pairGeneration: 3,
    activatedAt: '2030-01-01T00:03:03.000Z',
    runtimeProfile: second.runtimeProfile,
    identityBindings: second.identityBindings,
    identityBindingsRecord: secondIdentityRecord,
  })), 'STATE_GENERATION_GAP_OR_STALE')
  const backwardIdentityRecord = identityGeneration({ generationNumber: 3, generationCode: 'synthetic.identity-bindings-003', runtimeProfileDigest: runtimeDigest, issuedAt: '2030-01-01T00:03:00.000Z' })
  expectCode(() => store.activateGenerationPair(firstPair({
    pairCode: 'synthetic.backward-pair',
    pairGeneration: 3,
    activatedAt: '2030-01-01T00:03:03.000Z',
    runtimeProfile: firstPair().runtimeProfile,
    identityBindings: { ...second.identityBindings, generationNumber: 3, generationCode: 'synthetic.identity-bindings-003', recordDigestSha256: backwardIdentityRecord.record_digest_sha256, boundRuntimeProfileRecordDigestSha256: runtimeDigest },
    identityBindingsRecord: backwardIdentityRecord,
  })), 'STATE_GENERATION_GAP_OR_STALE')

  const rotatedIdentityRecord = identityGeneration({ generationNumber: 3, generationCode: 'synthetic.identity-bindings-003', runtimeProfileDigest: '54'.repeat(32), issuedAt: '2030-01-01T00:03:00.000Z', bindingCodeSuffix: '.rotated' })
  const rotatedBindings = Object.fromEntries(rotatedIdentityRecord.bindings.map((binding) => [binding.runtime_role_code, binding.binding_code]))
  const rotatedPair = firstPair({
    pairCode: 'synthetic.rotated-bindings-pair',
    pairGeneration: 3,
    activatedAt: '2030-01-01T00:03:04.000Z',
    runtimeProfile: second.runtimeProfile,
    identityBindings: { ...second.identityBindings, generationNumber: 3, generationCode: 'synthetic.identity-bindings-003', recordDigestSha256: rotatedIdentityRecord.record_digest_sha256 },
    identityBindingsRecord: rotatedIdentityRecord,
  })
  store.activateGenerationPair(rotatedPair)
  assert.equal(store.selectActiveGenerationPair({ asOf: '2030-01-01T00:03:05.000Z' }).pair_generation, 3)
  expectCode(() => store.revokeGenerationPair({
    pairCode: rotatedPair.pairCode,
    pairGeneration: 3,
    runtimeProfileRecordDigestSha256: rotatedPair.runtimeProfile.recordDigestSha256,
    identityBindingsRecordDigestSha256: rotatedPair.identityBindings.recordDigestSha256,
    revokedAt: '2030-01-01T00:03:06.000Z',
    reasonCode: 'synthetic.spoofed-old-binding',
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_AUTHENTICATED_BINDING_MISMATCH')

  const reopened = openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
  assert.equal(reopened.selectActiveGenerationPair({ asOf: '2030-01-01T00:03:05.000Z' }).pair_generation, 3, 'historical commits replay with their own generation binding facts')
  const swappedBootstrap = structuredClone(trustedIdentityBindingsRecord)
  delete swappedBootstrap.record_digest_sha256
  ;[swappedBootstrap.bindings[0].binding_code, swappedBootstrap.bindings[1].binding_code] = [swappedBootstrap.bindings[1].binding_code, swappedBootstrap.bindings[0].binding_code]
  swappedBootstrap.record_digest_sha256 = sha256Hex(Buffer.from(canonicalizeStateRecord(swappedBootstrap), 'utf8'))
  expectCode(() => openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord: swappedBootstrap }), 'STATE_BOOTSTRAP_BINDING_MISMATCH')

  store.revokeGenerationPair({
    pairCode: rotatedPair.pairCode,
    pairGeneration: 3,
    runtimeProfileRecordDigestSha256: rotatedPair.runtimeProfile.recordDigestSha256,
    identityBindingsRecordDigestSha256: rotatedPair.identityBindings.recordDigestSha256,
    revokedAt: '2030-01-01T00:03:06.000Z',
    reasonCode: 'synthetic.revocation',
    authenticatedLauncherBindingCode: rotatedBindings.trusted_launcher,
  })
  expectCode(() => store.selectActiveGenerationPair({ asOf: '2030-01-01T00:03:07.000Z' }), 'STATE_ACTIVE_GENERATION_REVOKED')
  expectCode(() => store.revokeGenerationPair({
    pairCode: rotatedPair.pairCode,
    pairGeneration: 3,
    runtimeProfileRecordDigestSha256: rotatedPair.runtimeProfile.recordDigestSha256,
    identityBindingsRecordDigestSha256: rotatedPair.identityBindings.recordDigestSha256,
    revokedAt: '2030-01-01T00:03:07.000Z',
    reasonCode: 'synthetic.repeat',
    authenticatedLauncherBindingCode: rotatedBindings.trusted_launcher,
  }), 'STATE_GENERATION_ALREADY_REVOKED')
})

test('D9.1 fixed-function handoff registry rejects writer spoofing, collisions, expiry, and revoked records', async (t) => {
  const { store, remove } = initializedStore()
  t.after(remove)
  const handoff = frozen('collector_handoff')
  const staleDigestHandoff = { ...handoff, collector_version: 'tampered-without-resealing' }
  expectCode(() => store.registerFixedRecord({
    record: staleDigestHandoff,
    recordedAt: '2030-01-01T00:05:16.001Z',
    authenticatedRuntimeRoleCode: 'handoff_broker',
    authenticatedBindingCode: trustedBindings.handoff_broker,
  }), 'STATE_RECORD_DIGEST_MISMATCH')
  expectCode(() => store.registerFixedRecord({
    record: handoff,
    recordedAt: '2030-01-01T00:05:16.001Z',
    authenticatedRuntimeRoleCode: 'trusted_launcher',
    authenticatedBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_REGISTRY_WRITER_INVALID')
  store.registerFixedRecord({
    record: handoff,
    recordedAt: '2030-01-01T00:05:16.001Z',
    authenticatedRuntimeRoleCode: 'handoff_broker',
    authenticatedBindingCode: trustedBindings.handoff_broker,
  })
  assert.equal(store.resolveFixedRecord({ registryKindCode: 'collector_handoff', recordCode: handoff.record_code, recordDigestSha256: handoff.record_digest_sha256, asOf: '2030-01-01T00:05:17.000Z' }).record_code, handoff.record_code)
  expectCode(() => store.registerFixedRecord({
    record: handoff,
    recordedAt: '2030-01-01T00:05:18.000Z',
    authenticatedRuntimeRoleCode: 'handoff_broker',
    authenticatedBindingCode: trustedBindings.handoff_broker,
  }), 'STATE_REGISTRY_REPLAY')
  const collision = resealRecord({ ...handoff, collector_version: 'synthetic-collision-version' })
  expectCode(() => store.registerFixedRecord({ record: collision, recordedAt: '2030-01-01T00:05:18.000Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: trustedBindings.handoff_broker }), 'STATE_REGISTRY_COLLISION')
  store.revokeFixedRecord({
    registryKindCode: 'collector_handoff',
    recordCode: handoff.record_code,
    recordDigestSha256: handoff.record_digest_sha256,
    revokedAt: '2030-01-01T00:05:19.000Z',
    reasonCode: 'synthetic.integrity-hold',
    authenticatedRuntimeRoleCode: 'handoff_broker',
    authenticatedBindingCode: trustedBindings.handoff_broker,
  })
  expectCode(() => store.resolveFixedRecord({ registryKindCode: 'collector_handoff', recordCode: handoff.record_code, recordDigestSha256: handoff.record_digest_sha256, asOf: '2030-01-01T00:05:20.000Z' }), 'STATE_REGISTRY_RECORD_REVOKED')

  const seal = frozen('bootstrap_bundle_seal')
  store.registerFixedRecord({ record: seal, recordedAt: '2030-01-01T00:05:20.000Z', authenticatedRuntimeRoleCode: 'trusted_launcher', authenticatedBindingCode: trustedBindings.trusted_launcher })
  expectCode(() => store.resolveFixedRecord({ registryKindCode: 'bundle_seal', recordCode: seal.record_code, recordDigestSha256: seal.record_digest_sha256, asOf: seal.expires_at }), 'STATE_REGISTRY_RECORD_EXPIRED')
})

test('D9.1 permit control enforces one-use issue, broker attribution, claim lifetime, forks, and terminality', async (t) => {
  const { store, remove } = initializedStore()
  t.after(remove)
  const permit = frozen('bootstrap_permit')
  const missingSealLocation = initializedStore()
  t.after(missingSealLocation.remove)
  expectCode(() => missingSealLocation.store.issuePermit({ record: permit, persistedAt: permit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher }), 'STATE_BOOTSTRAP_SEAL_MISMATCH')
  registerBootstrapSeal(store)
  const staleDigestPermit = { ...permit, expected_principal_roster_sha256: 'ff'.repeat(32) }
  expectCode(() => store.issuePermit({ record: staleDigestPermit, persistedAt: permit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher }), 'STATE_RECORD_DIGEST_MISMATCH')
  const mismatchedPermit = resealRecord({ ...permit, manifest_path: 'manifests/different-bootstrap.json' })
  expectCode(() => store.issuePermit({ record: mismatchedPermit, persistedAt: permit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher }), 'STATE_BOOTSTRAP_SEAL_MISMATCH')
  expectCode(() => store.issuePermit({
    record: permit,
    persistedAt: permit.issued_at,
    authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority',
    authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority,
    authenticatedPersistenceBindingCode: trustedBindings.handoff_broker,
  }), 'STATE_AUTHENTICATED_BINDING_MISMATCH')
  store.issuePermit({
    record: permit,
    persistedAt: permit.issued_at,
    authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority',
    authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority,
    authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher,
  })
  assert.equal(store.projectPermit({ permitCode: permit.permit_code, asOf: permit.not_before }).stateCode, 'ready')
  assert.equal(store.resolvePermit({ permitCode: permit.permit_code, recordDigestSha256: permit.record_digest_sha256, asOf: permit.not_before, requiredStateCode: 'ready' }).record.record_code, permit.record_code)
  expectCode(() => store.resolvePermit({ permitCode: permit.permit_code, recordDigestSha256: '00'.repeat(32), asOf: permit.not_before }), 'STATE_PERMIT_SUBSTITUTION')
  expectCode(() => store.issuePermit({ record: permit, persistedAt: '2030-01-01T00:05:00.001Z', authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher }), 'STATE_PERMIT_COLLISION')

  const claim = frozen('bootstrap_transition_in_progress')
  const staleDigestClaim = { ...claim, reason_code: 'tampered-without-resealing' }
  expectCode(() => store.beginOperation({
    operation: { operationId: claim.operation_id, operationNonce: claim.operation_nonce, operationModeCode: 'bootstrap', startedAt: claim.persisted_at, runtimeProfileRecordDigestSha256: runtimeDigest, identityBindingsRecordDigestSha256: bindingsDigest },
    claimTransition: staleDigestClaim,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_RECORD_DIGEST_MISMATCH')
  const wrongOperation = resealRecord({ ...claim, operation_id: 'synthetic.operation-wrong' })
  expectCode(() => store.beginOperation({
    operation: { operationId: wrongOperation.operation_id, operationNonce: wrongOperation.operation_nonce, operationModeCode: 'bootstrap', startedAt: wrongOperation.persisted_at, runtimeProfileRecordDigestSha256: runtimeDigest, identityBindingsRecordDigestSha256: bindingsDigest },
    claimTransition: wrongOperation,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_BOOTSTRAP_OPERATION_MISMATCH')
  const wrongObservedState = resealRecord({ ...claim, observed_logical_state: null })
  expectCode(() => store.beginOperation({
    operation: { operationId: wrongObservedState.operation_id, operationNonce: wrongObservedState.operation_nonce, operationModeCode: 'bootstrap', startedAt: wrongObservedState.persisted_at, runtimeProfileRecordDigestSha256: runtimeDigest, identityBindingsRecordDigestSha256: bindingsDigest },
    claimTransition: wrongObservedState,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_PERMIT_OBSERVED_STATE_MISMATCH')
  expectCode(() => store.appendPermitTransition({ record: claim, authenticatedSemanticRuntimeRoleCode: 'trusted_launcher', authenticatedSemanticBindingCode: trustedBindings.trusted_launcher, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher }), 'STATE_CLAIM_NOT_ATOMIC')
  const begin = store.beginOperation({
    operation: {
      operationId: claim.operation_id,
      operationNonce: claim.operation_nonce,
      operationModeCode: 'bootstrap',
      startedAt: claim.persisted_at,
      runtimeProfileRecordDigestSha256: runtimeDigest,
      identityBindingsRecordDigestSha256: bindingsDigest,
    },
    claimTransition: claim,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  })
  assert.equal(begin.operationNonce, permit.operation_nonce)
  assert.equal(store.projectPermit({ permitCode: permit.permit_code, asOf: claim.persisted_at }).stateCode, 'in_progress')
  assert.equal(store.resolvePermitForActiveOperation({
    asOf: '2030-01-01T00:05:01.500Z',
    operationId: claim.operation_id,
    operationNonce: claim.operation_nonce,
    permitCode: permit.permit_code,
    permitRecordDigestSha256: permit.record_digest_sha256,
    permitClaimRecordDigestSha256: claim.record_digest_sha256,
    runtimeProfileRecordDigestSha256: runtimeDigest,
    identityBindingsRecordDigestSha256: bindingsDigest,
  }).stateCode, 'in_progress')
  expectCode(() => store.resolvePermitForActiveOperation({
    asOf: frozen('bootstrap_bundle_seal').expires_at,
    operationId: claim.operation_id,
    operationNonce: claim.operation_nonce,
    permitCode: permit.permit_code,
    permitRecordDigestSha256: permit.record_digest_sha256,
    permitClaimRecordDigestSha256: claim.record_digest_sha256,
    runtimeProfileRecordDigestSha256: runtimeDigest,
    identityBindingsRecordDigestSha256: bindingsDigest,
  }), 'STATE_BOOTSTRAP_SEAL_MISMATCH')
  expectCode(() => store.resolvePermitForActiveOperation({
    asOf: permit.expires_at,
    operationId: claim.operation_id,
    operationNonce: claim.operation_nonce,
    permitCode: permit.permit_code,
    permitRecordDigestSha256: permit.record_digest_sha256,
    permitClaimRecordDigestSha256: claim.record_digest_sha256,
    runtimeProfileRecordDigestSha256: runtimeDigest,
    identityBindingsRecordDigestSha256: bindingsDigest,
  }), 'STATE_PERMIT_STATE_MISMATCH')
  const competing = openProtectedStateStore({ rootPath: store.rootPath, trustedIdentityBindingsRecord })
  expectCode(() => competing.beginOperation({ operation: operation({ operationId: 'synthetic.competing-operation', operationNonce: 'cd'.repeat(32), startedAt: '2030-01-01T00:05:01.001Z' }), authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), 'STATE_RECOVERY_REQUIRED')

  const effectTransition = frozen('bootstrap_transition_spent')
  expectCode(() => store.finishNoEffect({
    operationId: claim.operation_id,
    operationNonce: claim.operation_nonce,
    recordedAt: effectTransition.persisted_at,
    beforeLogicalStateSha256: '91'.repeat(32),
    afterLogicalStateSha256: '91'.repeat(32),
    authenticatedVerifierBindingCode: trustedBindings.independent_verifier,
    terminalPermitTransition: effectTransition,
  }), 'STATE_OPERATION_PERMIT_OUTCOME_MISMATCH')
  expectCode(() => store.markRecoveryRequired({
    operationId: claim.operation_id,
    operationNonce: claim.operation_nonce,
    recordedAt: effectTransition.persisted_at,
    reasonCode: 'synthetic.state-ambiguous',
    lastKnownLogicalStateSha256: null,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
    terminalPermitTransition: effectTransition,
  }), 'STATE_OPERATION_PERMIT_OUTCOME_MISMATCH')

  const fork = ambiguousTransition(claim, { transition_sequence: 1, previous_transition_record_digest_sha256: null })
  expectCode(() => store.markRecoveryRequired({
    operationId: claim.operation_id,
    operationNonce: claim.operation_nonce,
    recordedAt: fork.persisted_at,
    reasonCode: 'synthetic.state-ambiguous',
    lastKnownLogicalStateSha256: null,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
    terminalPermitTransition: fork,
  }), 'STATE_PERMIT_FORK_OR_GAP')
  const nonadvancingOccurrence = ambiguousTransition(claim, { occurred_at: claim.occurred_at })
  expectCode(() => store.markRecoveryRequired({
    operationId: claim.operation_id,
    operationNonce: claim.operation_nonce,
    recordedAt: nonadvancingOccurrence.persisted_at,
    reasonCode: 'synthetic.state-ambiguous',
    lastKnownLogicalStateSha256: null,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
    terminalPermitTransition: nonadvancingOccurrence,
  }), 'STATE_PERMIT_CHRONOLOGY_INVALID')
  const terminal = ambiguousTransition(claim)
  store.markRecoveryRequired({
    operationId: claim.operation_id,
    operationNonce: claim.operation_nonce,
    recordedAt: terminal.persisted_at,
    reasonCode: 'synthetic.state-ambiguous',
    lastKnownLogicalStateSha256: null,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
    terminalPermitTransition: terminal,
  })
  assert.equal(store.projectPermit({ permitCode: permit.permit_code, asOf: terminal.persisted_at }).stateCode, 'recovery_required')
  assert.deepEqual(store.inspect().recoveryReasons, ['operation_recovery_hold'])
  const replayedClaim = resealRecord({ ...claim, occurred_at: '2030-01-01T00:05:03.000Z', persisted_at: '2030-01-01T00:05:03.000Z' })
  expectCode(() => store.beginOperation({
    operation: { operationId: claim.operation_id, operationNonce: claim.operation_nonce, operationModeCode: 'bootstrap', startedAt: '2030-01-01T00:05:03.000Z', runtimeProfileRecordDigestSha256: runtimeDigest, identityBindingsRecordDigestSha256: bindingsDigest },
    claimTransition: replayedClaim,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_RECOVERY_REQUIRED')
})

test('D9.1 operation nonces are one global namespace regardless of permit or operation ordering', async (t) => {
  const operationFirst = initializedStore()
  t.after(operationFirst.remove)
  const completed = operation({
    operationId: 'synthetic.operation-before-permit',
    operationNonce: frozen('bootstrap_permit').operation_nonce,
  })
  operationFirst.store.beginOperation({ operation: completed, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher })
  operationFirst.store.finishNoEffect({
    operationId: completed.operationId,
    operationNonce: completed.operationNonce,
    recordedAt: '2030-01-01T00:02:01.000Z',
    beforeLogicalStateSha256: '31'.repeat(32),
    afterLogicalStateSha256: '31'.repeat(32),
    authenticatedVerifierBindingCode: trustedBindings.independent_verifier,
  })
  registerBootstrapSeal(operationFirst.store)
  const permit = frozen('bootstrap_permit')
  expectCode(() => operationFirst.store.issuePermit({
    record: permit,
    persistedAt: permit.issued_at,
    authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority',
    authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority,
    authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_NONCE_REPLAY')

  const permitFirst = initializedStore()
  t.after(permitFirst.remove)
  registerBootstrapSeal(permitFirst.store)
  permitFirst.store.issuePermit({
    record: permit,
    persistedAt: permit.issued_at,
    authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority',
    authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority,
    authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher,
  })
  expectCode(() => permitFirst.store.beginOperation({
    operation: operation({
      operationId: 'synthetic.unclaimed-reserved-nonce',
      operationNonce: permit.operation_nonce,
      startedAt: '2030-01-01T00:05:01.000Z',
    }),
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_OPERATION_PERMIT_INVALID')
})

test('D9.1 rejects permit backdating, expiry, insufficient claim lifetime, and actor spoofing', async (t) => {
  async function scenario(mutator, expectedCode) {
    const { store, remove } = initializedStore()
    t.after(remove)
    const permit = frozen('bootstrap_permit')
    registerBootstrapSeal(store)
    store.issuePermit({ record: permit, persistedAt: permit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher })
    const claim = resealRecord(mutator(frozen('bootstrap_transition_in_progress'), permit))
    expectCode(() => store.beginOperation({
      operation: { operationId: claim.operation_id, operationNonce: claim.operation_nonce, operationModeCode: 'bootstrap', startedAt: claim.persisted_at, runtimeProfileRecordDigestSha256: runtimeDigest, identityBindingsRecordDigestSha256: bindingsDigest },
      claimTransition: claim,
      authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
    }), expectedCode)
    assert.equal(store.inspect().activeOperation, null)
  }
  await scenario((claim) => ({ ...claim, occurred_at: '2030-01-01T00:04:59.999Z', persisted_at: '2030-01-01T00:04:59.999Z' }), 'STATE_PERMIT_NOT_YET_VALID')
  await scenario((claim, permit) => ({ ...claim, occurred_at: permit.expires_at, persisted_at: permit.expires_at }), 'STATE_PERMIT_EXPIRED')
  await scenario((claim) => ({ ...claim, occurred_at: '2030-01-01T01:04:30.001Z', persisted_at: '2030-01-01T01:04:30.001Z' }), 'STATE_PERMIT_CLAIM_LIFETIME_INSUFFICIENT')
  await scenario((claim) => ({ ...claim, recorded_by_binding_code: trustedBindings.handoff_broker }), 'STATE_AUTHENTICATED_BINDING_MISMATCH')
})

test('D9.1 atomically rejects bootstrap claims whose matched seal was revoked or expired after permit issuance', (t) => {
  const claimInput = (claim) => ({
    operation: {
      operationId: claim.operation_id,
      operationNonce: claim.operation_nonce,
      operationModeCode: 'bootstrap',
      startedAt: claim.persisted_at,
      runtimeProfileRecordDigestSha256: runtimeDigest,
      identityBindingsRecordDigestSha256: bindingsDigest,
    },
    claimTransition: claim,
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  })

  const revoked = initializedStore()
  t.after(revoked.remove)
  const revokedSeal = registerBootstrapSeal(revoked.store)
  const revokedPermit = frozen('bootstrap_permit')
  revoked.store.issuePermit({ record: revokedPermit, persistedAt: revokedPermit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher })
  revoked.store.revokeFixedRecord({
    registryKindCode: 'bundle_seal',
    recordCode: revokedSeal.record_code,
    recordDigestSha256: revokedSeal.record_digest_sha256,
    revokedAt: '2030-01-01T00:05:00.500Z',
    reasonCode: 'synthetic.revoked-before-claim',
    authenticatedRuntimeRoleCode: 'trusted_launcher',
    authenticatedBindingCode: trustedBindings.trusted_launcher,
  })
  expectCode(() => revoked.store.beginOperation(claimInput(frozen('bootstrap_transition_in_progress'))), 'STATE_BOOTSTRAP_SEAL_MISMATCH')
  assert.equal(revoked.store.inspect().activeOperation, null)

  const substituted = initializedStore()
  t.after(substituted.remove)
  const originalSeal = registerBootstrapSeal(substituted.store)
  const substitutionPermit = frozen('bootstrap_permit')
  substituted.store.issuePermit({ record: substitutionPermit, persistedAt: substitutionPermit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher })
  substituted.store.revokeFixedRecord({
    registryKindCode: 'bundle_seal',
    recordCode: originalSeal.record_code,
    recordDigestSha256: originalSeal.record_digest_sha256,
    revokedAt: '2030-01-01T00:05:00.250Z',
    reasonCode: 'synthetic.replace-pinned-seal',
    authenticatedRuntimeRoleCode: 'trusted_launcher',
    authenticatedBindingCode: trustedBindings.trusted_launcher,
  })
  const semanticClone = resealRecord({ ...originalSeal, record_code: 'synthetic.bootstrap-seal-clone' })
  substituted.store.registerFixedRecord({
    record: semanticClone,
    recordedAt: '2030-01-01T00:05:00.500Z',
    authenticatedRuntimeRoleCode: 'trusted_launcher',
    authenticatedBindingCode: trustedBindings.trusted_launcher,
  })
  expectCode(() => substituted.store.beginOperation(claimInput(frozen('bootstrap_transition_in_progress'))), 'STATE_BOOTSTRAP_SEAL_MISMATCH')
  assert.equal(substituted.store.inspect().activeOperation, null)

  const expired = initializedStore()
  t.after(expired.remove)
  const expiringSeal = frozen('bootstrap_bundle_seal')
  expiringSeal.expires_at = '2030-01-01T00:05:00.500Z'
  resealRecord(expiringSeal)
  expired.store.registerFixedRecord({ record: expiringSeal, recordedAt: expiringSeal.sealed_at, authenticatedRuntimeRoleCode: 'trusted_launcher', authenticatedBindingCode: trustedBindings.trusted_launcher })
  const expiredPermit = frozen('bootstrap_permit')
  expired.store.issuePermit({ record: expiredPermit, persistedAt: expiredPermit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher })
  expectCode(() => expired.store.beginOperation(claimInput(frozen('bootstrap_transition_in_progress'))), 'STATE_BOOTSTRAP_SEAL_MISMATCH')
  assert.equal(expired.store.inspect().activeOperation, null)
})

test('D9.1 permit issuance is bounded by every participating identity binding', (t) => {
  const limitedIdentityRecord = structuredClone(trustedIdentityBindingsRecord)
  delete limitedIdentityRecord.record_digest_sha256
  limitedIdentityRecord.bindings = limitedIdentityRecord.bindings.map((binding) => binding.runtime_role_code === 'operational_witness'
    ? { ...binding, valid_until: '2030-01-01T00:30:00.000Z' }
    : binding)
  limitedIdentityRecord.record_digest_sha256 = sha256Hex(Buffer.from(canonicalizeStateRecord(limitedIdentityRecord), 'utf8'))
  const { store, remove } = initializedStore({ identityRecord: limitedIdentityRecord })
  t.after(remove)
  const seal = resealRecord({ ...frozen('bootstrap_bundle_seal'), identity_bindings_record_digest_sha256: limitedIdentityRecord.record_digest_sha256 })
  store.registerFixedRecord({ record: seal, recordedAt: seal.sealed_at, authenticatedRuntimeRoleCode: 'trusted_launcher', authenticatedBindingCode: trustedBindings.trusted_launcher })
  const permit = resealRecord({ ...frozen('bootstrap_permit'), identity_bindings_record_digest_sha256: limitedIdentityRecord.record_digest_sha256 })
  expectCode(() => store.issuePermit({
    record: permit,
    persistedAt: permit.issued_at,
    authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority',
    authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority,
    authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher,
  }), 'STATE_PERMIT_BINDING_LIFETIME_INVALID')
})

test('D9.1 fixed-record and permit resolution recheck their exact active generation', (t) => {
  const { store, remove } = initializedStore()
  t.after(remove)
  const seal = registerBootstrapSeal(store)
  const permit = frozen('bootstrap_permit')
  store.issuePermit({ record: permit, persistedAt: permit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: trustedBindings.trusted_launcher })
  const secondIdentityRecord = identityGeneration({ generationNumber: 2, generationCode: 'synthetic.resolution-bindings-002', runtimeProfileDigest: '74'.repeat(32), issuedAt: '2030-01-01T00:05:09.000Z' })
  const second = firstPair({
    pairCode: 'synthetic.resolution-pair-002',
    pairGeneration: 2,
    activatedAt: '2030-01-01T00:05:10.000Z',
    runtimeProfile: { ...firstPair().runtimeProfile, generationNumber: 2, generationCode: 'synthetic.resolution-runtime-002', recordDigestSha256: '74'.repeat(32), validFrom: '2030-01-01T00:05:09.000Z' },
    identityBindings: { ...firstPair().identityBindings, generationNumber: 2, generationCode: 'synthetic.resolution-bindings-002', recordDigestSha256: secondIdentityRecord.record_digest_sha256, boundRuntimeProfileRecordDigestSha256: '74'.repeat(32), validFrom: '2030-01-01T00:05:09.000Z' },
    identityBindingsRecord: secondIdentityRecord,
  })
  store.activateGenerationPair(second)
  expectCode(() => store.resolveFixedRecord({ registryKindCode: 'bundle_seal', recordCode: seal.record_code, recordDigestSha256: seal.record_digest_sha256, asOf: '2030-01-01T00:05:11.000Z' }), 'STATE_ACTIVE_GENERATION_SUBSTITUTED')
  expectCode(() => store.resolvePermit({ permitCode: permit.permit_code, recordDigestSha256: permit.record_digest_sha256, asOf: '2030-01-01T00:05:11.000Z' }), 'STATE_ACTIVE_GENERATION_SUBSTITUTED')
})

test('D9.1 operation nonce, lock, and exact no-effect state are fail closed', async (t) => {
  const { store, remove } = initializedStore()
  t.after(remove)
  const op = operation()
  store.beginOperation({ operation: op, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher })
  expectCode(() => store.finishNoEffect({
    operationId: op.operationId,
    operationNonce: op.operationNonce,
    recordedAt: '2030-01-01T00:02:01.000Z',
    beforeLogicalStateSha256: '11'.repeat(32),
    afterLogicalStateSha256: '12'.repeat(32),
    authenticatedVerifierBindingCode: trustedBindings.independent_verifier,
  }), 'STATE_OPERATION_EFFECT_DETECTED')
  store.finishNoEffect({
    operationId: op.operationId,
    operationNonce: op.operationNonce,
    recordedAt: '2030-01-01T00:02:02.000Z',
    beforeLogicalStateSha256: '11'.repeat(32),
    afterLogicalStateSha256: '11'.repeat(32),
    authenticatedVerifierBindingCode: trustedBindings.independent_verifier,
  })
  assert.equal(store.inspect().activeOperation, null)
  expectCode(() => store.beginOperation({ operation: { ...op, startedAt: '2030-01-01T00:02:03.000Z' }, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), 'STATE_NONCE_REPLAY')
  const substituted = operation({ operationId: 'synthetic.operation-substituted', operationNonce: 'ac'.repeat(32), startedAt: '2030-01-01T00:02:04.000Z', runtimeProfileRecordDigestSha256: '00'.repeat(32) })
  expectCode(() => store.beginOperation({ operation: substituted, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), 'STATE_ACTIVE_GENERATION_SUBSTITUTED')
})

test('D9.1 interrupted publishes require deterministic recovery before mutation', async (t) => {
  let armed = false
  let crashStage = 'after_pending_fsync'
  const { store, root, remove } = initializedStore({
    faultInjector(stage) {
      if (armed && stage === crashStage) throw new SimulatedStateCrash(stage)
    },
  })
  t.after(remove)
  armed = true
  const beforeSequence = store.inspect().sequence
  assert.throws(() => store.beginOperation({ operation: operation(), authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), SimulatedStateCrash)
  const recovered = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  assert.deepEqual(recovered.inspect().recoveryReasons, ['lock_without_operation', 'pending_publish'])
  recovered.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:02:01.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
  assert.deepEqual(recovered.inspect().recoveryReasons, ['lock_without_operation'])
  recovered.discardUnregisteredLock({ recoveredAt: '2030-01-01T00:02:02.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
  assert.equal(recovered.inspect().recoveryRequired, false)
  assert.equal(recovered.inspect().sequence, beforeSequence + 2, 'publish and lock recovery actions were both audited')

  armed = false
  crashStage = 'after_commit_link'
  const secondLocation = initializedStore({
    faultInjector(stage) {
      if (armed && stage === crashStage) throw new SimulatedStateCrash(stage)
    },
  })
  t.after(secondLocation.remove)
  armed = true
  const secondOp = operation({ operationId: 'synthetic.operation-crash-linked', operationNonce: 'ad'.repeat(32) })
  assert.throws(() => secondLocation.store.beginOperation({ operation: secondOp, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), SimulatedStateCrash)
  const linked = openProtectedStateStore({ rootPath: secondLocation.root, trustedIdentityBindingsRecord })
  assert.deepEqual(linked.inspect().recoveryReasons, ['lock_without_operation', 'pending_publish', 'unanchored_commit'])
  linked.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:02:01.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
  assert.deepEqual(linked.inspect().recoveryReasons, ['unfinished_operation'])
  linked.recoverNoEffectAfterCrash({
    operationId: secondOp.operationId,
    operationNonce: secondOp.operationNonce,
    recordedAt: '2030-01-01T00:02:02.000Z',
    beforeLogicalStateSha256: '22'.repeat(32),
    afterLogicalStateSha256: '22'.repeat(32),
    authenticatedVerifierBindingCode: trustedBindings.independent_verifier,
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(linked.inspect().recoveryRequired, false)
})

test('D9.1 can anchor and audit an interrupted genesis activation from the explicit bootstrap trust anchor', (t) => {
  let armed = false
  const location = workspace('jedi-d9-state-genesis-recovery-')
  t.after(location.remove)
  const store = createProtectedStateStore({
    rootPath: location.root,
    trustedIdentityBindingsRecord,
    faultInjector(stage) {
      if (armed && stage === 'after_commit_link') throw new SimulatedStateCrash(stage)
    },
  })
  armed = true
  assert.throws(() => store.activateGenerationPair(firstPair()), SimulatedStateCrash)
  const restarted = openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
  assert.deepEqual(restarted.inspect().recoveryReasons, ['pending_publish', 'unanchored_commit'])
  const result = restarted.recoverInterruptedPublish({
    recoveredAt: '2030-01-01T00:01:02.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(result.actionCode, 'finalized_durable_unanchored_commit')
  assert.equal(restarted.inspect().sequence, 2)
  assert.equal(restarted.inspect().recoveryRequired, false)
  assert.equal(restarted.selectActiveGenerationPair({ asOf: '2030-01-01T00:01:03.000Z' }).pair_generation, 1)
})

test('D9.1 safely discards pre-link genesis remnants after real process death and keeps genesis retryable', (t) => {
  const moduleUrl = pathToFileURL(path.join(projectDirectory, 'd9/control-plane/state-store.mjs')).href
  const childSource = `
    import fs from 'node:fs';
    const input = JSON.parse(fs.readFileSync(0, 'utf8'));
    const { openProtectedStateStore } = await import(${JSON.stringify(moduleUrl)});
    const store = openProtectedStateStore({ rootPath: input.root, trustedIdentityBindingsRecord: input.identityRecord, faultInjector(stage) { if (stage === input.crashStage) process.exit(72); } });
    store.activateGenerationPair(input.pair);
  `
  for (const crashStage of ['after_append_lock_fsync', 'after_pending_fsync']) {
    const location = workspace(`jedi-d9-state-pre-genesis-${crashStage}-`)
    t.after(location.remove)
    createProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', childSource], {
      input: JSON.stringify({ root: location.root, identityRecord: trustedIdentityBindingsRecord, pair: firstPair(), crashStage }),
      encoding: 'utf8',
    })
    assert.equal(child.status, 72, child.stderr)
    const restarted = openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
    assert.equal(restarted.inspect().sequence, 0)
    assert.equal(restarted.inspect().recoveryRequired, true)
    const recovered = restarted.recoverInterruptedPublish({
      recoveredAt: '2030-01-01T00:01:02.000Z',
      authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
    })
    assert.deepEqual(recovered, {
      actionCode: 'discarded_pre_genesis_interruption',
      bootstrapTrustAnchorUsed: true,
      durableAuditRecorded: false,
      recoveryReasons: [],
    })
    restarted.activateGenerationPair({ ...firstPair(), activatedAt: '2030-01-01T00:01:03.000Z' })
    assert.equal(restarted.selectActiveGenerationPair({ asOf: '2030-01-01T00:01:04.000Z' }).pair_generation, 1)
  }

  const unattributed = workspace('jedi-d9-state-pre-genesis-unattributed-')
  t.after(unattributed.remove)
  createProtectedStateStore({ rootPath: unattributed.root, trustedIdentityBindingsRecord })
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', childSource], {
    input: JSON.stringify({ root: unattributed.root, identityRecord: trustedIdentityBindingsRecord, pair: firstPair(), crashStage: 'after_append_lock_directory' }),
    encoding: 'utf8',
  })
  assert.equal(child.status, 72, child.stderr)
  const unsealed = openProtectedStateStore({ rootPath: unattributed.root, trustedIdentityBindingsRecord })
  const before = fileTreeDigest(unattributed.root)
  expectCode(() => unsealed.recoverInterruptedPublish({
    recoveredAt: '2030-01-02T00:02:00.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  }), 'STATE_PRE_GENESIS_INCIDENT_TIME_UNAVAILABLE')
  assert.equal(fileTreeDigest(unattributed.root), before)
})

test('D9.1 publish recovery preflights time and the complete pending inventory before mutation', (t) => {
  let armed = false
  const { store, root, remove } = initializedStore({
    faultInjector(stage) {
      if (armed && stage === 'after_commit_link') throw new SimulatedStateCrash(stage)
    },
  })
  t.after(remove)
  armed = true
  assert.throws(
    () => store.beginOperation({ operation: operation(), authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }),
    SimulatedStateCrash,
  )

  const invalidTimeStore = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  const beforeInvalidTime = fileTreeDigest(root)
  expectCode(() => invalidTimeStore.recoverInterruptedPublish({
    recoveredAt: 'invalid',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  }), 'STATE_TIMESTAMP_INVALID')
  assert.equal(fileTreeDigest(root), beforeInvalidTime)

  const unexpected = path.join(root, 'pending', 'unexpected.pending')
  fs.writeFileSync(unexpected, 'synthetic obstruction\n', { mode: 0o400 })
  const beforeUnexpected = fileTreeDigest(root)
  expectCode(() => invalidTimeStore.recoverInterruptedPublish({
    recoveredAt: '2030-01-01T00:02:01.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  }), 'STATE_RECOVERY_AMBIGUOUS')
  assert.equal(fileTreeDigest(root), beforeUnexpected)
})

test('D9.1 anchors and audits an unanchored generation revocation after the selected generation expires', (t) => {
  let armed = false
  const { store, root, remove } = initializedStore({
    faultInjector(stage, context) {
      if (armed && stage === 'after_commit_link' && context.sequence === 2) throw new SimulatedStateCrash(stage)
    },
  })
  t.after(remove)
  armed = true
  assert.throws(() => store.revokeGenerationPair({
    pairCode: firstPair().pairCode,
    pairGeneration: 1,
    runtimeProfileRecordDigestSha256: runtimeDigest,
    identityBindingsRecordDigestSha256: bindingsDigest,
    revokedAt: '2030-01-01T00:02:00.000Z',
    reasonCode: 'synthetic.crash-boundary-revocation',
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), SimulatedStateCrash)
  const restarted = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  assert.deepEqual(restarted.inspect().recoveryReasons, ['pending_publish', 'unanchored_commit'])
  const result = restarted.recoverInterruptedPublish({
    recoveredAt: '2030-01-02T00:02:00.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(result.actionCode, 'finalized_durable_unanchored_commit')
  assert.equal(restarted.inspect().recoveryRequired, false)
  assert.equal(restarted.inspect().sequence, 3)
  assert.equal(restarted.projectGenerationPairRevocation({ pairCode: firstPair().pairCode }).reason_code, 'synthetic.crash-boundary-revocation')
  expectCode(() => restarted.selectActiveGenerationPair({ asOf: '2030-01-02T00:02:01.000Z' }), 'STATE_ACTIVE_GENERATION_REVOKED')
  const reopenedAgain = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  assert.equal(reopenedAgain.inspect().sequence, 3)
  assert.equal(reopenedAgain.inspect().recoveryRequired, false)
})

test('D9.1 completes HEAD-anchored revocation cleanup after real process death without resurrecting authority', (t) => {
  const { root, remove } = initializedStore()
  t.after(remove)
  const moduleUrl = pathToFileURL(path.join(projectDirectory, 'd9/control-plane/state-store.mjs')).href
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import fs from 'node:fs';
    const input = JSON.parse(fs.readFileSync(0, 'utf8'));
    const { openProtectedStateStore } = await import(${JSON.stringify(moduleUrl)});
    const store = openProtectedStateStore({ rootPath: input.root, trustedIdentityBindingsRecord: input.identityRecord, faultInjector(stage) { if (stage === 'after_head_replace') process.exit(72); } });
    store.revokeGenerationPair(input.revocation);
  `], {
    input: JSON.stringify({
      root,
      identityRecord: trustedIdentityBindingsRecord,
      revocation: {
        pairCode: firstPair().pairCode,
        pairGeneration: 1,
        runtimeProfileRecordDigestSha256: runtimeDigest,
        identityBindingsRecordDigestSha256: bindingsDigest,
        revokedAt: '2030-01-01T00:02:00.000Z',
        reasonCode: 'synthetic.head-anchored-revocation',
        authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
      },
    }),
    encoding: 'utf8',
  })
  assert.equal(child.status, 72, child.stderr)
  const restarted = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  assert.deepEqual(restarted.inspect().recoveryReasons, ['append_lock_present', 'pending_publish'])
  const recovered = restarted.recoverInterruptedPublish({
    recoveredAt: '2030-01-02T00:02:00.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(recovered.actionCode, 'completed_durable_head_commit_cleanup')
  assert.equal(restarted.inspect().recoveryRequired, false)
  expectCode(() => restarted.selectActiveGenerationPair({ asOf: '2030-01-02T00:02:01.000Z' }), 'STATE_ACTIVE_GENERATION_REVOKED')
})

test('D9.1 publish recovery cannot precede an abandoned append lock or pending commit', (t) => {
  const moduleUrl = pathToFileURL(path.join(projectDirectory, 'd9/control-plane/state-store.mjs')).href
  const childSource = `
    import fs from 'node:fs';
    const input = JSON.parse(fs.readFileSync(0, 'utf8'));
    const { openProtectedStateStore } = await import(${JSON.stringify(moduleUrl)});
    const store = openProtectedStateStore({ rootPath: input.root, trustedIdentityBindingsRecord: input.identityRecord, faultInjector(stage) { if (stage === input.crashStage) process.exit(72); } });
    store.registerFixedRecord({ record: input.record, recordedAt: '2030-01-01T00:05:16.001Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: 'binding.handoff-broker' });
  `
  for (const crashStage of ['after_append_lock_fsync', 'after_pending_fsync']) {
    const { root, remove } = initializedStore()
    t.after(remove)
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', childSource], {
      input: JSON.stringify({ root, identityRecord: trustedIdentityBindingsRecord, record: frozen('collector_handoff'), crashStage }),
      encoding: 'utf8',
    })
    assert.equal(child.status, 72, child.stderr)
    const restarted = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
    const before = fileTreeDigest(root)
    expectCode(() => restarted.recoverInterruptedPublish({
      recoveredAt: '2030-01-01T00:03:00.000Z',
      authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
    }), 'STATE_RECOVERY_CHRONOLOGY_INVALID')
    assert.equal(fileTreeDigest(root), before)
    restarted.recoverInterruptedPublish({
      recoveredAt: '2030-01-01T00:05:17.000Z',
      authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
    })
    assert.equal(restarted.inspect().recoveryRequired, false)
  }
})

test('D9.1 rejects an expired commit-persistence binding before durable publication', (t) => {
  const limited = structuredClone(trustedIdentityBindingsRecord)
  delete limited.record_digest_sha256
  limited.bindings = limited.bindings.map((binding) => binding.runtime_role_code === 'trusted_launcher'
    ? { ...binding, valid_until: '2030-01-01T00:02:00.000Z' }
    : binding)
  limited.record_digest_sha256 = sha256Hex(Buffer.from(canonicalizeStateRecord(limited), 'utf8'))
  const { store, root, remove } = initializedStore({ identityRecord: limited })
  t.after(remove)
  const handoff = resealRecord({ ...frozen('collector_handoff'), identity_bindings_record_digest_sha256: limited.record_digest_sha256 })
  const before = fileTreeDigest(root)
  const sequence = store.inspect().sequence
  expectCode(() => store.registerFixedRecord({
    record: handoff,
    recordedAt: '2030-01-01T00:05:16.001Z',
    authenticatedRuntimeRoleCode: 'handoff_broker',
    authenticatedBindingCode: trustedBindings.handoff_broker,
  }), 'STATE_AUTHENTICATED_BINDING_EXPIRED')
  assert.equal(store.inspect().sequence, sequence)
  assert.equal(fileTreeDigest(root), before)
  assert.equal(openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord: limited }).inspect().sequence, sequence)
})

test('D9.1 operation-lock recovery remains historically anchored after generation expiry', (t) => {
  const afterExpiry = '2030-01-02T00:02:00.000Z'

  let armed = false
  const unregistered = initializedStore({ faultInjector(stage) { if (armed && stage === 'after_lock_fsync') throw new SimulatedStateCrash(stage) } })
  t.after(unregistered.remove)
  armed = true
  const unregisteredOperation = operation({ operationId: 'synthetic.expired-unregistered-lock', operationNonce: 'e3'.repeat(32) })
  assert.throws(() => unregistered.store.beginOperation({ operation: unregisteredOperation, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), SimulatedStateCrash)
  const unregisteredRestart = openProtectedStateStore({ rootPath: unregistered.root, trustedIdentityBindingsRecord })
  unregisteredRestart.discardUnregisteredLock({ recoveredAt: afterExpiry, authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
  assert.equal(unregisteredRestart.inspect().recoveryRequired, false)

  const interrupted = initializedStore()
  t.after(interrupted.remove)
  const interruptedOperation = operation({ operationId: 'synthetic.expired-in-progress', operationNonce: 'e4'.repeat(32) })
  interrupted.store.beginOperation({ operation: interruptedOperation, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher })
  const interruptedRestart = openProtectedStateStore({ rootPath: interrupted.root, trustedIdentityBindingsRecord })
  interruptedRestart.recoverNoEffectAfterCrash({
    operationId: interruptedOperation.operationId,
    operationNonce: interruptedOperation.operationNonce,
    recordedAt: afterExpiry,
    beforeLogicalStateSha256: 'e5'.repeat(32),
    afterLogicalStateSha256: 'e5'.repeat(32),
    authenticatedVerifierBindingCode: trustedBindings.independent_verifier,
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(interruptedRestart.inspect().recoveryRequired, false)

  let terminalArmed = false
  const terminal = initializedStore({ faultInjector(stage) { if (terminalArmed && stage === 'after_terminal_commit_before_unlock') throw new SimulatedStateCrash(stage) } })
  t.after(terminal.remove)
  const terminalOperation = operation({ operationId: 'synthetic.expired-terminal-lock', operationNonce: 'e6'.repeat(32) })
  terminal.store.beginOperation({ operation: terminalOperation, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher })
  terminalArmed = true
  assert.throws(() => terminal.store.finishNoEffect({
    operationId: terminalOperation.operationId,
    operationNonce: terminalOperation.operationNonce,
    recordedAt: '2030-01-01T00:02:01.000Z',
    beforeLogicalStateSha256: 'e7'.repeat(32),
    afterLogicalStateSha256: 'e7'.repeat(32),
    authenticatedVerifierBindingCode: trustedBindings.independent_verifier,
  }), SimulatedStateCrash)
  const terminalRestart = openProtectedStateStore({ rootPath: terminal.root, trustedIdentityBindingsRecord })
  terminalRestart.reconcileTerminalLock({ recoveredAt: afterExpiry, authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
  assert.equal(terminalRestart.inspect().recoveryRequired, false)
})

test('D9.1 serializes appenders with a filesystem mutex and refreshes under that mutex', (t) => {
  let armed = false
  let competingFailure = null
  const location = workspace('jedi-d9-state-append-serialization-')
  t.after(location.remove)
  let competing
  const store = createProtectedStateStore({
    rootPath: location.root,
    trustedIdentityBindingsRecord,
    faultInjector(stage) {
      if (armed && stage === 'after_append_lock_fsync') {
        try {
          competing.registerFixedRecord({ record: frozen('collector_handoff'), recordedAt: '2030-01-01T00:05:16.001Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: trustedBindings.handoff_broker })
        } catch (error) {
          competingFailure = error
        }
      }
    },
  })
  store.activateGenerationPair(firstPair())
  competing = openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
  armed = true
  store.registerFixedRecord({ record: frozen('collector_handoff'), recordedAt: '2030-01-01T00:05:16.001Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: trustedBindings.handoff_broker })
  assert.ok(competingFailure instanceof StateStoreError)
  assert.equal(competingFailure.code, 'STATE_RECOVERY_REQUIRED')
  assert.equal(openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord }).inspect().sequence, 2)
})

test('D9.1 rechecks recovery holds after acquiring the append mutex', (t) => {
  let armed = false
  let competing
  const location = workspace('jedi-d9-state-under-lock-recheck-')
  t.after(location.remove)
  const store = createProtectedStateStore({
    rootPath: location.root,
    trustedIdentityBindingsRecord,
    faultInjector(stage) {
      if (armed && stage === 'before_append_lock_acquire') {
        armed = false
        const racingOperation = operation({ operationId: 'synthetic.racing-operation', operationNonce: 'da'.repeat(32) })
        competing.beginOperation({ operation: racingOperation, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher })
        competing.markRecoveryRequired({
          operationId: racingOperation.operationId,
          operationNonce: racingOperation.operationNonce,
          recordedAt: '2030-01-01T00:02:01.000Z',
          reasonCode: 'synthetic.racing-recovery-hold',
          lastKnownLogicalStateSha256: null,
          authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
        })
      }
    },
  })
  store.activateGenerationPair(firstPair())
  competing = openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
  armed = true
  expectCode(() => store.registerFixedRecord({ record: frozen('collector_handoff'), recordedAt: '2030-01-01T00:05:16.001Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: trustedBindings.handoff_broker }), 'STATE_RECOVERY_REQUIRED')
  assert.deepEqual(store.inspect().recoveryReasons, ['operation_recovery_hold'])
})

test('D9.1 recovers a real process-death append mutex through a durable audited intent', (t) => {
  const moduleUrl = pathToFileURL(path.join(projectDirectory, 'd9/control-plane/state-store.mjs')).href
  const childSource = `
    import fs from 'node:fs';
    const input = JSON.parse(fs.readFileSync(0, 'utf8'));
    const { openProtectedStateStore } = await import(${JSON.stringify(moduleUrl)});
    const store = openProtectedStateStore({ rootPath: input.root, trustedIdentityBindingsRecord: input.identityRecord, faultInjector(stage) { if (stage === input.crashStage) process.exit(72); } });
    store.registerFixedRecord({ record: input.record, recordedAt: '2030-01-01T00:05:16.001Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: 'binding.handoff-broker' });
  `
  for (const [crashStage, expectedReason] of [
    ['after_append_lock_directory', 'incomplete_append_lock'],
    ['after_append_lock_partial_write', 'incomplete_append_lock'],
    ['after_append_lock_fsync', 'append_lock_present'],
  ]) {
    const { root, remove } = initializedStore()
    t.after(remove)
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', childSource], {
      input: JSON.stringify({ root, identityRecord: trustedIdentityBindingsRecord, record: frozen('collector_handoff'), crashStage }),
      encoding: 'utf8',
    })
    assert.equal(child.status, 72, child.stderr)
    const abandoned = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
    assert.deepEqual(abandoned.inspect().recoveryReasons, [expectedReason])
    const recovery = abandoned.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:05:17.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
    assert.equal(recovery.actionCode, 'discarded_abandoned_append_lock')
    assert.equal(abandoned.inspect().recoveryRequired, false)
    assert.equal(abandoned.inspect().sequence, 2)
  }
})

test('D9.1 refuses to merge an unanchored commit with a mismatched or incomplete append mutex', (t) => {
  const moduleUrl = pathToFileURL(path.join(projectDirectory, 'd9/control-plane/state-store.mjs')).href
  const childSource = `
    import fs from 'node:fs';
    const input = JSON.parse(fs.readFileSync(0, 'utf8'));
    const { openProtectedStateStore } = await import(${JSON.stringify(moduleUrl)});
    const store = openProtectedStateStore({ rootPath: input.root, trustedIdentityBindingsRecord: input.identityRecord, faultInjector(stage) { if (stage === 'after_commit_link') process.exit(72); } });
    store.registerFixedRecord({ record: input.record, recordedAt: '2030-01-01T00:05:16.001Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: 'binding.handoff-broker' });
  `
  const crashedLocation = () => {
    const location = initializedStore()
    t.after(location.remove)
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', childSource], {
      input: JSON.stringify({ root: location.root, identityRecord: trustedIdentityBindingsRecord, record: frozen('collector_handoff') }),
      encoding: 'utf8',
    })
    assert.equal(child.status, 72, child.stderr)
    return location
  }

  const mismatched = crashedLocation()
  const leasePath = path.join(mismatched.root, 'append.lock', 'lease.json')
  const lease = JSON.parse(fs.readFileSync(leasePath, 'utf8'))
  delete lease.lease_sha256
  lease.transaction_code = 'registry.substituted'
  lease.lease_sha256 = sha256Hex(Buffer.from(canonicalizeStateRecord(lease), 'utf8'))
  fs.chmodSync(leasePath, 0o600)
  fs.writeFileSync(leasePath, `${canonicalizeStateRecord(lease)}\n`)
  fs.chmodSync(leasePath, 0o400)
  const mismatchStore = openProtectedStateStore({ rootPath: mismatched.root, trustedIdentityBindingsRecord })
  const mismatchDigest = fileTreeDigest(mismatched.root)
  expectCode(() => mismatchStore.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:05:17.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority }), 'STATE_RECOVERY_AMBIGUOUS')
  assert.equal(fileTreeDigest(mismatched.root), mismatchDigest)

  const incomplete = crashedLocation()
  fs.unlinkSync(path.join(incomplete.root, 'append.lock', 'lease.json'))
  const incompleteStore = openProtectedStateStore({ rootPath: incomplete.root, trustedIdentityBindingsRecord })
  const incompleteDigest = fileTreeDigest(incomplete.root)
  expectCode(() => incompleteStore.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:05:17.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority }), 'STATE_RECOVERY_AMBIGUOUS')
  assert.equal(fileTreeDigest(incomplete.root), incompleteDigest)
})

test('D9.1 publish recovery resumes and audits every protected crash boundary', (t) => {
  const recoveryStages = [
    'after_recovery_intent_fsync',
    'after_recovery_append_lock_cleanup',
    'after_recovery_head_replace',
    'after_recovery_pending_cleanup',
    'after_recovery_audit_pending_fsync',
    'after_recovery_audit_commit_link',
    'after_recovery_audit_commit',
  ]
  for (const stageToCrash of recoveryStages) {
    let crashOperation = false
    const location = initializedStore({
      faultInjector(stage) {
        if (crashOperation && stage === 'after_commit_link') throw new SimulatedStateCrash(stage)
      },
    })
    t.after(location.remove)
    crashOperation = true
    assert.throws(() => location.store.beginOperation({ operation: operation(), authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), SimulatedStateCrash)
    let armed = true
    const recovering = openProtectedStateStore({
      rootPath: location.root,
      trustedIdentityBindingsRecord,
      faultInjector(stage) {
        if (armed && stage === stageToCrash) throw new SimulatedStateCrash(stage)
      },
    })
    assert.throws(() => recovering.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:02:01.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority }), SimulatedStateCrash, stageToCrash)
    const held = openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
    assert.equal(held.inspect().recoveryReasons.includes('recovery_audit_pending'), true, stageToCrash)
    armed = false
    held.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:02:01.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
    assert.equal(held.inspect().recoveryReasons.includes('recovery_audit_pending'), false, stageToCrash)
    assert.equal(held.inspect().sequence, 3, stageToCrash)
  }
})

test('D9.1 recovery intent survives repeated crashes without losing or duplicating its audit', (t) => {
  let crashOperation = false
  const location = initializedStore({ faultInjector(stage) { if (crashOperation && stage === 'after_commit_link') throw new SimulatedStateCrash(stage) } })
  t.after(location.remove)
  crashOperation = true
  assert.throws(() => location.store.beginOperation({ operation: operation(), authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), SimulatedStateCrash)
  const firstRecovery = openProtectedStateStore({
    rootPath: location.root,
    trustedIdentityBindingsRecord,
    faultInjector(stage) { if (stage === 'after_recovery_head_replace') throw new SimulatedStateCrash(stage) },
  })
  assert.throws(() => firstRecovery.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:02:01.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority }), SimulatedStateCrash)
  const secondRecovery = openProtectedStateStore({
    rootPath: location.root,
    trustedIdentityBindingsRecord,
    faultInjector(stage) { if (stage === 'after_recovery_audit_commit_link') throw new SimulatedStateCrash(stage) },
  })
  assert.throws(() => secondRecovery.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:02:01.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority }), SimulatedStateCrash)
  const finalRecovery = openProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
  assert.equal(finalRecovery.inspect().recoveryReasons.includes('recovery_audit_pending'), true)
  finalRecovery.recoverInterruptedPublish({ recoveredAt: '2030-01-01T00:02:01.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
  assert.equal(finalRecovery.inspect().sequence, 3)
  assert.equal(finalRecovery.inspect().recoveryReasons.includes('recovery_audit_pending'), false)
})

test('D9.1 protected-state canonical framing matches independent fixed vectors', (t) => {
  const location = workspace('jedi-d9-state-golden-')
  t.after(location.remove)
  const store = createProtectedStateStore({ rootPath: location.root, trustedIdentityBindingsRecord })
  assert.deepEqual(fileDigestAndLength(path.join(location.root, 'HEAD.json')), {
    sha256: '2b892a7ded01602a6735a9e12e2d9819649eaa0e63b651b40c2d8b1566663863',
    byteLength: 104,
  })
  store.activateGenerationPair(firstPair())
  let commitFiles = fs.readdirSync(path.join(location.root, 'commits')).sort()
  assert.equal(commitFiles[0], '000000000001-b6db4f9d5ad41575fbd0572001258b604dc4304330b38f2f474539b908f5e53e.json')
  assert.deepEqual(fileDigestAndLength(path.join(location.root, 'commits', commitFiles[0])), {
    sha256: '54014f7a8ff4669c2987c38346507349b055fdabafb88f1f3574214b87f20343',
    byteLength: 13451,
  })
  store.beginOperation({ operation: operation(), authenticatedLauncherBindingCode: trustedBindings.trusted_launcher })
  commitFiles = fs.readdirSync(path.join(location.root, 'commits')).sort()
  assert.equal(commitFiles[1], '000000000002-b795f17b734f7d7bf218f4d65887be09d7aaab39507fa33562b4eb5e203d16ad.json')
  assert.deepEqual(fileDigestAndLength(path.join(location.root, 'commits', commitFiles[1])), {
    sha256: '1db4c189559dcb141f916a4ee954304cfce7505cbb2dd2065b1a8f04ad636d9b',
    byteLength: 1251,
  })
})

test('D9.1 classifies and recovers a crash before lock-lease publication', (t) => {
  let armed = false
  const { store, root, remove } = initializedStore({
    faultInjector(stage) {
      if (armed && stage === 'after_lock_directory') throw new SimulatedStateCrash(stage)
    },
  })
  t.after(remove)
  armed = true
  assert.throws(
    () => store.beginOperation({ operation: operation(), authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }),
    SimulatedStateCrash,
  )
  const leasePath = path.join(root, 'operation.lock', 'lease.json')
  fs.writeFileSync(leasePath, '{"partial":', { mode: 0o400 })
  const recovered = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  assert.deepEqual(recovered.inspect().recoveryReasons, ['incomplete_operation_lock'])
  const before = recovered.inspect().sequence
  recovered.discardUnregisteredLock({
    recoveredAt: '2030-01-01T00:02:01.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(recovered.inspect().recoveryRequired, false)
  assert.equal(recovered.inspect().sequence, before + 1)
})

test('D9.1 audits distinct incomplete-lock incidents and retries one durable incident exactly once', (t) => {
  let armed = false
  let crashRecoveryAfterAudit = false
  const { store, root, remove } = initializedStore({
    faultInjector(stage) {
      if (armed && stage === 'after_lock_directory') throw new SimulatedStateCrash(stage)
      if (crashRecoveryAfterAudit && stage === 'after_lock_recovery_commit_before_unlock') throw new SimulatedStateCrash(stage)
    },
  })
  t.after(remove)

  armed = true
  assert.throws(() => store.beginOperation({
    operation: operation({ operationId: 'synthetic.incomplete-lock-one', operationNonce: 'f1'.repeat(32) }),
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), SimulatedStateCrash)
  armed = false
  crashRecoveryAfterAudit = true
  const firstRecovery = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord, faultInjector: store.faultInjector })
  assert.throws(() => firstRecovery.discardUnregisteredLock({
    recoveredAt: '2030-01-01T00:02:01.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  }), SimulatedStateCrash)
  const afterAuditSequence = firstRecovery.inspect().sequence
  crashRecoveryAfterAudit = false
  const exactRetry = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  exactRetry.discardUnregisteredLock({
    recoveredAt: '2030-01-01T00:02:01.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(exactRetry.inspect().sequence, afterAuditSequence, 'exact incident retry does not duplicate its recovery audit')

  armed = true
  const secondCrashStore = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord, faultInjector: store.faultInjector })
  const secondOperation = operation({ operationId: 'synthetic.incomplete-lock-two', operationNonce: 'f2'.repeat(32), startedAt: '2030-01-01T00:02:02.000Z' })
  assert.throws(() => secondCrashStore.beginOperation({ operation: secondOperation, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), SimulatedStateCrash)
  armed = false
  const secondRecovery = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  secondRecovery.discardUnregisteredLock({
    recoveredAt: '2030-01-01T00:02:03.000Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(secondRecovery.inspect().sequence, afterAuditSequence + 1, 'a distinct incomplete directory receives a distinct recovery audit')
})

test('D9.1 terminal-commit crashes retain the result and require lock reconciliation', async (t) => {
  let armed = false
  const { store, root, remove } = initializedStore({
    faultInjector(stage) {
      if (armed && stage === 'after_terminal_commit_before_unlock') throw new SimulatedStateCrash(stage)
    },
  })
  t.after(remove)
  const op = operation({ operationId: 'synthetic.operation-terminal-crash', operationNonce: 'ae'.repeat(32) })
  store.beginOperation({ operation: op, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher })
  armed = true
  assert.throws(() => store.finishNoEffect({ operationId: op.operationId, operationNonce: op.operationNonce, recordedAt: '2030-01-01T00:02:01.000Z', beforeLogicalStateSha256: '33'.repeat(32), afterLogicalStateSha256: '33'.repeat(32), authenticatedVerifierBindingCode: trustedBindings.independent_verifier }), SimulatedStateCrash)
  const restarted = openProtectedStateStore({
    rootPath: root,
    trustedIdentityBindingsRecord,
    faultInjector(stage) { if (stage === 'after_terminal_lock_recovery_commit_before_unlock') throw new SimulatedStateCrash(stage) },
  })
  assert.deepEqual(restarted.inspect().recoveryReasons, ['terminal_operation_lock'])
  assert.throws(() => restarted.reconcileTerminalLock({ recoveredAt: '2030-01-01T00:02:02.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority }), SimulatedStateCrash)
  const exactRetry = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  const beforeInvalidRetry = fileTreeDigest(root)
  expectCode(() => exactRetry.reconcileTerminalLock({ recoveredAt: 'invalid', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority }), 'STATE_TIMESTAMP_INVALID')
  expectCode(() => exactRetry.reconcileTerminalLock({ recoveredAt: '2030-01-01T00:02:03.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority }), 'STATE_RECOVERY_RETRY_MISMATCH')
  assert.equal(fileTreeDigest(root), beforeInvalidRetry)
  exactRetry.reconcileTerminalLock({ recoveredAt: '2030-01-01T00:02:02.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
  assert.equal(restarted.inspect().recoveryRequired, false)
  expectCode(() => restarted.beginOperation({ operation: { ...op, startedAt: '2030-01-01T00:02:03.000Z' }, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), 'STATE_NONCE_REPLAY')
})

test('D9.1 recovery-required terminal crash permits lock cleanup while retaining the durable recovery hold', (t) => {
  let armed = false
  const { store, root, remove } = initializedStore({
    faultInjector(stage) {
      if (armed && stage === 'after_recovery_required_commit_before_unlock') throw new SimulatedStateCrash(stage)
    },
  })
  t.after(remove)
  const op = operation({ operationId: 'synthetic.operation-recovery-terminal-crash', operationNonce: 'e1'.repeat(32) })
  store.beginOperation({ operation: op, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher })
  armed = true
  assert.throws(() => store.markRecoveryRequired({
    operationId: op.operationId,
    operationNonce: op.operationNonce,
    recordedAt: '2030-01-01T00:02:01.000Z',
    reasonCode: 'synthetic.recovery-boundary',
    lastKnownLogicalStateSha256: '44'.repeat(32),
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }), SimulatedStateCrash)
  const restarted = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  assert.deepEqual(restarted.inspect().recoveryReasons, ['operation_recovery_hold', 'terminal_operation_lock'])
  restarted.reconcileTerminalLock({ recoveredAt: '2030-01-01T00:02:02.000Z', authenticatedRecoveryBindingCode: trustedBindings.recovery_authority })
  assert.deepEqual(restarted.inspect().recoveryReasons, ['operation_recovery_hold'])
  assert.equal(restarted.inspect().activeOperation, null)
  assert.equal(restarted.projectOperation({ operationId: op.operationId, operationNonce: op.operationNonce }).state_code, 'recovery_required')
})

test('D9.1 unregistered-lock recovery cannot be backdated before acquisition', (t) => {
  let armed = false
  const { store, root, remove } = initializedStore({
    faultInjector(stage) {
      if (armed && stage === 'after_lock_fsync') throw new SimulatedStateCrash(stage)
    },
  })
  t.after(remove)
  armed = true
  const op = operation({ operationId: 'synthetic.operation-backdated-lock-recovery', operationNonce: 'e2'.repeat(32), startedAt: '2030-01-01T00:05:00.000Z' })
  assert.throws(() => store.beginOperation({ operation: op, authenticatedLauncherBindingCode: trustedBindings.trusted_launcher }), SimulatedStateCrash)
  const restarted = openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord })
  const before = fileTreeDigest(root)
  expectCode(() => restarted.discardUnregisteredLock({
    recoveredAt: '2030-01-01T00:04:59.999Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  }), 'STATE_RECOVERY_CHRONOLOGY_INVALID')
  assert.equal(fileTreeDigest(root), before)
  restarted.discardUnregisteredLock({
    recoveredAt: '2030-01-01T00:05:00.001Z',
    authenticatedRecoveryBindingCode: trustedBindings.recovery_authority,
  })
  assert.equal(restarted.inspect().recoveryRequired, false)
})

test('D9.1 protected commit chain detects mutation, gaps, forks, and unsafe roots', async (t) => {
  const { store, root, remove } = initializedStore()
  t.after(remove)
  const before = fileTreeDigest(root)
  const commitDirectory = path.join(root, 'commits')
  const commitName = fs.readdirSync(commitDirectory)[0]
  const commitPath = path.join(commitDirectory, commitName)
  fs.chmodSync(commitPath, 0o600)
  const bytes = fs.readFileSync(commitPath)
  fs.writeFileSync(commitPath, Buffer.concat([bytes.subarray(0, -2), Buffer.from('x\n')]))
  expectCode(() => openProtectedStateStore({ rootPath: root, trustedIdentityBindingsRecord }), 'STATE_FILE_INVALID_JSON')
  assert.notEqual(fileTreeDigest(root), before)

  const gapLocation = initializedStore()
  t.after(gapLocation.remove)
  const original = fs.readdirSync(path.join(gapLocation.root, 'commits'))[0]
  fs.renameSync(path.join(gapLocation.root, 'commits', original), path.join(gapLocation.root, 'commits', `000000000002${original.slice(12)}`))
  expectCode(() => openProtectedStateStore({ rootPath: gapLocation.root, trustedIdentityBindingsRecord }), 'STATE_COMMIT_GAP_OR_FORK')

  const unsafeParent = workspace()
  t.after(unsafeParent.remove)
  fs.mkdirSync(unsafeParent.root, { mode: 0o755 })
  expectCode(() => openProtectedStateStore({ rootPath: unsafeParent.root, trustedIdentityBindingsRecord }), 'STATE_ROOT_PERMISSIONS_INVALID')
})
