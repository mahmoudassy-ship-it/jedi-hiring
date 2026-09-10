import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { verifyControlPlaneBuild } from '../d9/control-plane/build-integrity.mjs'
import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import { loadApprovedContractSet } from '../d9/control-plane/contracts.mjs'
import {
  D9StateAppendBrokerError,
  assertProtectedStateAppendBroker,
  createProtectedStateAppendBroker,
  createSyntheticCrashStateAppendBroker,
} from '../d9/control-plane/state-append-broker.mjs'
import { createProtectedStateStore, openProtectedStateStore } from '../d9/control-plane/state-store.mjs'
import { createGenerationFixture, fixture, projectDirectory, reseal, verifyFixture } from './d9-1-support/runtime-fixture.mjs'

const contractRoot = path.join(projectDirectory, 'docs/schema/d9-0')
const sourceDirectory = path.join(projectDirectory, 'd9/control-plane')
const sourceLeaves = Object.freeze({ canonical: 'canonical.mjs', state_append_broker: 'state-append-broker.mjs', state_store: 'state-store.mjs' })

function chownTree(target, uid, gid) {
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    const child = path.join(target, entry.name)
    if (entry.isDirectory()) chownTree(child, uid, gid)
    fs.chownSync(child, uid, gid)
  }
  fs.chownSync(target, uid, gid)
}

function bindings(generation) {
  return Object.fromEntries(generation.identityBindings.bindings.map((binding) => [binding.runtime_role_code, binding.binding_code]))
}

function rotatedGenerationFixture(t, contractSet) {
  const generationFixture = createGenerationFixture(t)
  generationFixture.runtime.record_code = 'synthetic.runtime-profile-002'
  generationFixture.runtime.profile_generation = 8
  generationFixture.runtime.issued_at = '2030-01-01T00:02:00.000Z'
  reseal(generationFixture.runtime)
  generationFixture.identity.record_code = 'synthetic.identity-bindings-002'
  generationFixture.identity.binding_generation = 12
  generationFixture.identity.issued_at = '2030-01-01T00:02:00.000Z'
  generationFixture.identity.runtime_profile_record_digest_sha256 = generationFixture.runtime.record_digest_sha256
  generationFixture.identity.bindings = generationFixture.identity.bindings.map((binding) => ({
    ...binding,
    binding_code: `${binding.binding_code}.v2`,
    valid_from: '2030-01-01T00:02:00.000Z',
  }))
  reseal(generationFixture.identity)
  generationFixture.selection = {
    profile_code: generationFixture.runtime.profile_code,
    profile_generation: generationFixture.runtime.profile_generation,
    runtime_profile_record_digest_sha256: generationFixture.runtime.record_digest_sha256,
    binding_set_code: generationFixture.identity.binding_set_code,
    binding_generation: generationFixture.identity.binding_generation,
    identity_bindings_record_digest_sha256: generationFixture.identity.record_digest_sha256,
  }
  return { generationFixture, generation: verifyFixture(contractSet, generationFixture) }
}

async function environment(t, { crashOperationCode = null, crashPhase = 'after_commit_before_response', timeoutMs = 5_000 } = {}) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-state-broker-'))
  fs.chmodSync(workspace, 0o755)
  t.after(() => fs.rmSync(workspace, { force: true, recursive: true }))
  const contractSet = loadApprovedContractSet({ contractRoot })
  const generationFixture = createGenerationFixture(t)
  const generation = verifyFixture(contractSet, generationFixture)
  const verifiedControlPlaneBuild = verifyControlPlaneBuild({
    manifestPath: generationFixture.options.controlPlaneBuildManifestPath,
    projectRoot: projectDirectory,
    verifiedGeneration: generation,
  })
  const trustedBindings = bindings(generation)
  const launcherBinding = generation.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'trusted_launcher')
  const rootPath = path.join(workspace, 'protected-state')
  const provisioningStore = createProtectedStateStore({ rootPath, trustedIdentityBindingsRecord: generation.identityBindings })
  provisioningStore.activateGenerationPair({
    pairCode: 'synthetic.broker-generation-pair',
    pairGeneration: 1,
    runtimeProfile: { generationNumber: generation.selection.profile_generation, generationCode: generation.runtimeProfile.profile_code, recordDigestSha256: generation.runtimeProfile.record_digest_sha256, validFrom: generation.runtimeProfile.issued_at, expiresAt: generation.identityBindings.expires_at },
    identityBindings: { generationNumber: generation.selection.binding_generation, generationCode: generation.identityBindings.binding_set_code, recordDigestSha256: generation.identityBindings.record_digest_sha256, boundRuntimeProfileRecordDigestSha256: generation.runtimeProfile.record_digest_sha256, validFrom: generation.identityBindings.issued_at, expiresAt: generation.identityBindings.expires_at },
    identityBindingsRecord: generation.identityBindings,
    activatedAt: '2030-01-01T00:01:01.000Z',
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  })
  chownTree(rootPath, launcherBinding.unix_uid, launcherBinding.unix_uid)
  const store = openProtectedStateStore({ rootPath, expectedUid: launcherBinding.unix_uid, trustedIdentityBindingsRecord: generation.identityBindings })

  const runtimeDirectory = path.join(workspace, 'broker-runtime')
  fs.mkdirSync(runtimeDirectory, { mode: 0o755 })
  for (const leaf of Object.values(sourceLeaves)) {
    const source = path.join(sourceDirectory, leaf)
    const target = path.join(runtimeDirectory, leaf)
    fs.copyFileSync(source, target)
    fs.chmodSync(target, 0o444)
  }
  fs.chmodSync(runtimeDirectory, 0o555)
  const brokerOptions = {
    nonceSource: (() => { let value = 1; return () => (value++).toString(16).padStart(64, '0') })(),
    rootPath,
    timeoutMs,
    trustedGenesisIdentityBindingsRecord: generation.identityBindings,
    verifiedControlPlaneBuild,
    verifiedGeneration: generation,
    workerModulePath: path.join(runtimeDirectory, sourceLeaves.state_append_broker),
  }
  const broker = crashOperationCode === null
    ? await createProtectedStateAppendBroker(brokerOptions)
    : await createSyntheticCrashStateAppendBroker(brokerOptions, crashOperationCode, crashPhase)
  t.after(() => broker.close())
  return { broker, generation, rootPath, runtimeDirectory, store, trustedBindings, verifiedControlPlaneBuild, workspace }
}

function handoff(generation) {
  const record = fixture('collector_handoff')
  const collector = generation.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'collector')
  record.runtime_profile_record_digest_sha256 = generation.runtimeProfile.record_digest_sha256
  record.identity_bindings_record_digest_sha256 = generation.identityBindings.record_digest_sha256
  record.collector_binding_code = collector.binding_code
  record.collector_principal_code = collector.atlas_principal_code
  record.collector_build_sha256 = generation.runtimeProfile.component_releases.find((release) => release.runtime_role_code === 'collector').executable_sha256
  return reseal(record)
}

function stateReference(generation) {
  const state = fixture('logical_state_empty')
  state.state_payload.runtime_profile_record_digest_sha256 = generation.runtimeProfile.record_digest_sha256
  state.logical_state_sha256 = canonicalSha256(state.state_payload)
  reseal(state)
  return { state_seal_code: state.record_code, state_seal_record_digest_sha256: state.record_digest_sha256, logical_state_sha256: state.logical_state_sha256 }
}

function sealAndPermit(generation) {
  const reference = stateReference(generation)
  const seal = fixture('bootstrap_bundle_seal')
  seal.runtime_profile_record_digest_sha256 = generation.runtimeProfile.record_digest_sha256
  seal.identity_bindings_record_digest_sha256 = generation.identityBindings.record_digest_sha256
  seal.target_logical_state = reference
  reseal(seal)
  const permit = fixture('bootstrap_permit')
  permit.runtime_profile_record_digest_sha256 = generation.runtimeProfile.record_digest_sha256
  permit.identity_bindings_record_digest_sha256 = generation.identityBindings.record_digest_sha256
  permit.importer_release_sha256 = generation.runtimeProfile.component_releases.find((release) => release.runtime_role_code === 'bundle_importer').executable_sha256
  permit.target_empty_logical_state = reference
  reseal(permit)
  return { permit, reference, seal }
}

function bootstrapClaim({ permit, reference, seal, trustedBindings }) {
  const claim = fixture('bootstrap_transition_in_progress')
  Object.assign(claim, {
    permit_code: permit.permit_code,
    permit_issuance_record_digest_sha256: permit.record_digest_sha256,
    operation_id: seal.operation_id,
    operation_nonce: permit.operation_nonce,
    observed_logical_state: reference,
    recorded_by_binding_code: trustedBindings.trusted_launcher,
    persisted_by_binding_code: trustedBindings.trusted_launcher,
  })
  return reseal(claim)
}

function bootstrapRecoveryTransition({ claim, reference, trustedBindings }) {
  const terminal = structuredClone(claim)
  Object.assign(terminal, {
    record_code: 'synthetic.permit-transition-scope-recovery',
    transition_sequence: 2,
    previous_transition_record_digest_sha256: claim.record_digest_sha256,
    from_state_code: 'in_progress',
    to_state_code: 'recovery_required',
    transition_code: 'state_ambiguous',
    observed_logical_state: reference,
    occurred_at: '2030-01-01T00:05:02.000Z',
    persisted_at: '2030-01-01T00:05:02.000Z',
    reason_code: 'state_ambiguous',
    recorded_by_binding_code: trustedBindings.trusted_launcher,
    persisted_by_binding_code: trustedBindings.trusted_launcher,
  })
  return reseal(terminal)
}

test('persistent trusted-launcher UID child owns fixed-record persistence', async (t) => {
  const context = await environment(t)
  assert.equal(assertProtectedStateAppendBroker(context.broker), context.broker)
  const record = handoff(context.generation)
  const result = await context.broker.registerFixedRecord({ record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker })
  assert.notEqual(result.brokerPid, process.pid)
  assert.equal(result.brokerUid, 61018)
  assert.equal(result.brokerGid, 61018)
  assert.equal(context.store.resolveFixedRecord({ registryKindCode: 'collector_handoff', recordCode: record.record_code, recordDigestSha256: record.record_digest_sha256, asOf: '2030-01-01T00:05:17.000Z' }).record_digest_sha256, record.record_digest_sha256)
})

test('one broker process owns permit issue and transition append', async (t) => {
  const context = await environment(t)
  const { permit, reference, seal } = sealAndPermit(context.generation)
  const sealResult = await context.broker.registerFixedRecord({ record: seal, recordedAt: seal.sealed_at, authenticatedRuntimeRoleCode: 'trusted_launcher', authenticatedBindingCode: context.trustedBindings.trusted_launcher })
  const permitResult = await context.broker.issuePermit({ record: permit, persistedAt: permit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: context.trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: context.trustedBindings.trusted_launcher })
  const transition = fixture('bootstrap_transition_in_progress')
  Object.assign(transition, {
    record_code: 'synthetic.permit-transition-withdrawal', permit_code: permit.permit_code, permit_issuance_record_digest_sha256: permit.record_digest_sha256,
    transition_sequence: 1, previous_transition_record_digest_sha256: null, from_state_code: 'ready', to_state_code: 'revoked', transition_code: 'authority_withdrawal',
    operation_id: seal.operation_id, operation_nonce: permit.operation_nonce, observed_logical_state: reference, recovery_permit_record_digest_sha256: null, completion_journal_head_record_digest_sha256: null,
    recorded_by_runtime_role_code: 'bootstrap_authority', recorded_by_binding_code: context.trustedBindings.bootstrap_authority, persisted_by_binding_code: context.trustedBindings.trusted_launcher,
    occurred_at: '2030-01-01T00:05:01.000Z', persisted_at: '2030-01-01T00:05:01.000Z', reason_code: 'authority_withdrawal',
  })
  reseal(transition)
  const transitionResult = await context.broker.appendPermitTransition({ record: transition, authenticatedSemanticRuntimeRoleCode: 'bootstrap_authority', authenticatedSemanticBindingCode: context.trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: context.trustedBindings.trusted_launcher })
  assert.equal(sealResult.brokerPid, permitResult.brokerPid)
  assert.equal(permitResult.brokerPid, transitionResult.brokerPid)
  assert.equal(context.store.projectPermit({ permitCode: permit.permit_code, asOf: '2030-01-01T00:05:02.000Z' }).stateCode, 'revoked')
})

test('authenticated broker owns fixed-record and active-generation revocations', async (t) => {
  const context = await environment(t)
  const record = handoff(context.generation)
  await context.broker.registerFixedRecord({ record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker })
  await assert.rejects(
    () => context.broker.revokeFixedRecord({ registryKindCode: 'collector_handoff', recordCode: record.record_code, recordDigestSha256: record.record_digest_sha256, revokedAt: '2030-01-01T00:05:18.000Z', reasonCode: 'synthetic.wrong-actor', authenticatedRuntimeRoleCode: 'trusted_launcher', authenticatedBindingCode: context.trustedBindings.trusted_launcher }),
    (error) => error.code === 'STATE_BROKER_APPEND_REJECTED' && error.details.workerCode === 'STATE_REGISTRY_WRITER_INVALID',
  )
  const revoked = await context.broker.revokeFixedRecord({ registryKindCode: 'collector_handoff', recordCode: record.record_code, recordDigestSha256: record.record_digest_sha256, revokedAt: '2030-01-01T00:05:19.000Z', reasonCode: 'synthetic.integrity-hold', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker })
  assert.equal(revoked.brokerPid, context.broker.attestation().brokerPid)
  assert.equal(context.store.projectFixedRecordRevocation({ registryKindCode: 'collector_handoff', recordCode: record.record_code }).reason_code, 'synthetic.integrity-hold')

  const generationRevoked = await context.broker.revokeGenerationPair({
    pairCode: 'synthetic.broker-generation-pair',
    pairGeneration: 1,
    runtimeProfileRecordDigestSha256: context.generation.runtimeProfile.record_digest_sha256,
    identityBindingsRecordDigestSha256: context.generation.identityBindings.record_digest_sha256,
    revokedAt: '2030-01-01T00:05:20.000Z',
    reasonCode: 'synthetic.generation-integrity-hold',
    authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher,
  })
  assert.equal(generationRevoked.brokerPid, revoked.brokerPid)
  assert.equal(context.store.projectGenerationPairRevocation({ pairCode: 'synthetic.broker-generation-pair' }).reason_code, 'synthetic.generation-integrity-hold')
  await assert.rejects(() => context.broker.registerFixedRecord({ record, recordedAt: '2030-01-01T00:05:21.000Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }), (error) => error.code === 'STATE_BROKER_TERMINATED')
})

test('persistent broker retains the process-held lease across begin and finish', async (t) => {
  const context = await environment(t)
  const operation = { operationId: 'synthetic.broker-dry-run', operationNonce: 'ab'.repeat(32), operationModeCode: 'dry_run', startedAt: '2030-01-01T00:02:00.000Z', runtimeProfileRecordDigestSha256: context.generation.runtimeProfile.record_digest_sha256, identityBindingsRecordDigestSha256: context.generation.identityBindings.record_digest_sha256 }
  const begun = await context.broker.beginSyntheticDryRun({ operation, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher })
  assert.deepEqual(context.store.inspect().activeOperation, { operationId: operation.operationId, operationNonce: operation.operationNonce })
  const finished = await context.broker.finishSyntheticNoEffect({ operationId: operation.operationId, operationNonce: operation.operationNonce, recordedAt: '2030-01-01T00:02:01.000Z', beforeLogicalStateSha256: '11'.repeat(32), afterLogicalStateSha256: '11'.repeat(32), reasonCode: 'synthetic_control_plane_no_effect', authenticatedVerifierBindingCode: context.trustedBindings.independent_verifier })
  assert.equal(begun.brokerPid, finished.brokerPid)
  assert.equal(context.store.inspect().activeOperation, null)
  await assert.rejects(() => context.broker.beginSyntheticDryRun({ operation: { ...operation, operationId: 'synthetic.document-import', operationNonce: 'ac'.repeat(32), operationModeCode: 'document_import', startedAt: '2030-01-01T00:02:02.000Z' }, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher }), (error) => error.code === 'STATE_BROKER_INPUT_INVALID')
  await assert.rejects(() => context.broker.beginSyntheticDryRun({ operation: { ...operation, operationId: 'synthetic.claim', operationNonce: 'ad'.repeat(32), startedAt: '2030-01-01T00:02:02.000Z' }, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher, claimTransition: {} }), (error) => error.code === 'STATE_BROKER_INPUT_INVALID')
})

test('broker rejects replay/collision and closed-input violations without another commit', async (t) => {
  const context = await environment(t)
  const record = handoff(context.generation)
  const input = { record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }
  await context.broker.registerFixedRecord(input)
  const sequence = context.store.inspect().sequence
  await assert.rejects(() => context.broker.registerFixedRecord(input), (error) => error instanceof D9StateAppendBrokerError && error.code === 'STATE_BROKER_APPEND_REJECTED' && error.details.workerCode === 'STATE_REGISTRY_REPLAY')
  assert.equal(context.store.inspect().sequence, sequence)
  await assert.rejects(() => context.broker.registerFixedRecord({ ...input, extra: true }), (error) => error.code === 'STATE_BROKER_INPUT_INVALID')
  const tampered = { ...record, collector_version: 'tampered-without-resealing' }
  await assert.rejects(
    () => context.broker.registerFixedRecord({ ...input, record: tampered, recordedAt: '2030-01-01T00:05:18.000Z' }),
    (error) => error.code === 'STATE_BROKER_APPEND_REJECTED' && error.details.workerCode === 'STATE_RECORD_DIGEST_MISMATCH',
  )
})

test('local nonce rejection does not desynchronize the broker request sequence', async (t) => {
  const context = await environment(t)
  await context.broker.close()
  const nonces = ['not-a-hash', 'a1'.repeat(32), 'a1'.repeat(32), 'a2'.repeat(32)]
  const broker = await createProtectedStateAppendBroker({
    nonceSource: () => nonces.shift(),
    rootPath: context.rootPath,
    trustedGenesisIdentityBindingsRecord: context.generation.identityBindings,
    verifiedControlPlaneBuild: context.verifiedControlPlaneBuild,
    verifiedGeneration: context.generation,
    workerModulePath: path.join(context.runtimeDirectory, sourceLeaves.state_append_broker),
  })
  t.after(() => broker.close())
  const first = handoff(context.generation)
  const firstInput = { record: first, recordedAt: first.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }
  const before = context.store.inspect().sequence
  await assert.rejects(() => broker.registerFixedRecord(firstInput), (error) => error.code === 'STATE_BROKER_CONFIGURATION_INVALID')
  await broker.registerFixedRecord(firstInput)

  const second = reseal({
    ...handoff(context.generation),
    record_code: 'synthetic.collector-handoff-nonce-two',
    handoff_recorded_at: '2030-01-01T00:05:17.000Z',
  })
  const secondInput = { record: second, recordedAt: second.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }
  await assert.rejects(() => broker.registerFixedRecord(secondInput), (error) => error.code === 'STATE_BROKER_REPLAY')
  await broker.registerFixedRecord(secondInput)
  assert.equal(context.store.inspect().sequence, before + 2)
})

test('broker startup rejects symlinked state and substituted runtime source', async (t) => {
  const context = await environment(t)
  const symlink = path.join(context.workspace, 'state-link')
  fs.symlinkSync(context.rootPath, symlink)
  await assert.rejects(() => createProtectedStateAppendBroker({ rootPath: symlink, verifiedControlPlaneBuild: context.verifiedControlPlaneBuild, verifiedGeneration: context.generation, workerModulePath: path.join(context.workspace, 'missing.mjs') }), (error) => error.code === 'STATE_BROKER_CONFIGURATION_INVALID')
})

test('commit-before-response loss reconciles an exact fixed-record effect and permanently closes the broker', async (t) => {
  const context = await environment(t, { crashOperationCode: 'register_fixed_record' })
  const record = handoff(context.generation)
  const result = await context.broker.registerFixedRecord({ record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker })
  assert.equal(result.persistenceStatus, 'persisted_after_response_loss')
  assert.equal(context.store.resolveFixedRecord({ registryKindCode: 'collector_handoff', recordCode: record.record_code, recordDigestSha256: record.record_digest_sha256, asOf: record.handoff_recorded_at }).record_digest_sha256, record.record_digest_sha256)
  await assert.rejects(() => context.broker.registerFixedRecord({ record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }), (error) => error.code === 'STATE_BROKER_TERMINATED')
})

test('commit-before-response loss reconciles an exact registry revocation', async (t) => {
  const context = await environment(t, { crashOperationCode: 'revoke_fixed_record' })
  const record = handoff(context.generation)
  await context.broker.registerFixedRecord({ record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker })
  const result = await context.broker.revokeFixedRecord({ registryKindCode: 'collector_handoff', recordCode: record.record_code, recordDigestSha256: record.record_digest_sha256, revokedAt: '2030-01-01T00:05:18.000Z', reasonCode: 'synthetic.response-loss-hold', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker })
  assert.equal(result.persistenceStatus, 'persisted_after_response_loss')
  assert.equal(context.store.projectFixedRecordRevocation({ registryKindCode: 'collector_handoff', recordCode: record.record_code }).reason_code, 'synthetic.response-loss-hold')
})

test('commit-before-response loss reconciles an exact active-generation revocation', async (t) => {
  const context = await environment(t, { crashOperationCode: 'revoke_generation_pair' })
  const result = await context.broker.revokeGenerationPair({
    pairCode: 'synthetic.broker-generation-pair',
    pairGeneration: 1,
    runtimeProfileRecordDigestSha256: context.generation.runtimeProfile.record_digest_sha256,
    identityBindingsRecordDigestSha256: context.generation.identityBindings.record_digest_sha256,
    revokedAt: '2030-01-01T00:05:18.000Z',
    reasonCode: 'synthetic.response-loss-generation-hold',
    authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher,
  })
  assert.equal(result.persistenceStatus, 'persisted_after_response_loss')
  assert.equal(context.store.projectGenerationPairRevocation({ pairCode: 'synthetic.broker-generation-pair' }).reason_code, 'synthetic.response-loss-generation-hold')
})

test('commit-before-response loss during begin poisons the broker and requires recovery', async (t) => {
  const context = await environment(t, { crashOperationCode: 'begin_synthetic_dry_run' })
  const operation = { operationId: 'synthetic.crashed-dry-run', operationNonce: 'bb'.repeat(32), operationModeCode: 'dry_run', startedAt: '2030-01-01T00:02:00.000Z', runtimeProfileRecordDigestSha256: context.generation.runtimeProfile.record_digest_sha256, identityBindingsRecordDigestSha256: context.generation.identityBindings.record_digest_sha256 }
  await assert.rejects(() => context.broker.beginSyntheticDryRun({ operation, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher }), (error) => error.code === 'STATE_BROKER_RECOVERY_REQUIRED')
  assert.equal(context.store.inspect().recoveryRequired, true)
  await assert.rejects(() => context.broker.beginSyntheticDryRun({ operation: { ...operation, operationId: 'synthetic.second', operationNonce: 'bc'.repeat(32) }, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher }), (error) => error.code === 'STATE_BROKER_RECOVERY_REQUIRED')
})

test('commit-before-response loss during synthetic permit claim is ambiguous and cannot authorize handle delivery', async (t) => {
  const context = await environment(t, { crashOperationCode: 'begin_synthetic_bootstrap_scope_audit' })
  const { permit, reference, seal } = sealAndPermit(context.generation)
  await context.broker.registerFixedRecord({ record: seal, recordedAt: seal.sealed_at, authenticatedRuntimeRoleCode: 'trusted_launcher', authenticatedBindingCode: context.trustedBindings.trusted_launcher })
  await context.broker.issuePermit({ record: permit, persistedAt: permit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: context.trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: context.trustedBindings.trusted_launcher })
  const claimTransition = bootstrapClaim({ permit, reference, seal, trustedBindings: context.trustedBindings })
  const operation = { operationId: seal.operation_id, operationNonce: permit.operation_nonce, operationModeCode: 'bootstrap', startedAt: claimTransition.persisted_at, runtimeProfileRecordDigestSha256: context.generation.runtimeProfile.record_digest_sha256, identityBindingsRecordDigestSha256: context.generation.identityBindings.record_digest_sha256 }
  await assert.rejects(
    () => context.broker.beginSyntheticBootstrapScopeAudit({ operation, claimTransition, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher }),
    (error) => error.code === 'STATE_BROKER_RECOVERY_REQUIRED' && error.details.reconciliation.status === 'ambiguous',
  )
  assert.deepEqual(context.store.inspect().activeOperation, { operationId: operation.operationId, operationNonce: operation.operationNonce })
  assert.equal(context.store.projectPermit({ permitCode: permit.permit_code, asOf: claimTransition.persisted_at }).stateCode, 'in_progress')
  await assert.rejects(
    () => context.broker.beginSyntheticBootstrapScopeAudit({ operation, claimTransition, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher }),
    (error) => error.code === 'STATE_BROKER_RECOVERY_REQUIRED',
  )
})

test('pre-append response loss is an explicit permanent failure, never a success-shaped no-op', async (t) => {
  const context = await environment(t, { crashOperationCode: 'register_fixed_record', crashPhase: 'before_append' })
  const record = handoff(context.generation)
  const before = context.store.inspect()
  const input = { record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }
  await assert.rejects(() => context.broker.registerFixedRecord(input), (error) => error.code === 'STATE_BROKER_APPEND_NOT_PERSISTED' && error.details.reconciliation.status === 'absent')
  assert.deepEqual(context.store.inspect(), before)
  await assert.rejects(() => context.broker.registerFixedRecord(input), (error) => error.code === 'STATE_BROKER_APPEND_NOT_PERSISTED')
})

test('generation expiry terminates the pinned broker before another commit', async (t) => {
  const context = await environment(t)
  const before = context.store.inspect()
  const record = handoff(context.generation)
  const input = { record, recordedAt: context.generation.identityBindings.expires_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }
  await assert.rejects(() => context.broker.registerFixedRecord(input), (error) => error.code === 'STATE_BROKER_APPEND_REJECTED' && error.details.workerCode === 'STATE_ACTIVE_GENERATION_EXPIRED')
  assert.deepEqual(context.store.inspect(), before)
  await assert.rejects(() => context.broker.registerFixedRecord(input), (error) => error.code === 'STATE_BROKER_APPEND_REJECTED')
})

test('runtime source substitution after startup terminates the broker before another commit', async (t) => {
  const context = await environment(t)
  const source = path.join(context.runtimeDirectory, sourceLeaves.canonical)
  fs.chmodSync(source, 0o644)
  fs.appendFileSync(source, '\n')
  fs.chmodSync(source, 0o444)
  const before = context.store.inspect()
  const record = handoff(context.generation)
  await assert.rejects(() => context.broker.registerFixedRecord({ record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }), (error) => error.code === 'STATE_BROKER_APPEND_REJECTED' && error.details.workerCode === 'STATE_BROKER_BUILD_MISMATCH')
  assert.deepEqual(context.store.inspect(), before)
})

test('a timed-out worker is killed, permanently poisoned, and cannot lend its delayed response to another request', async (t) => {
  const context = await environment(t, { timeoutMs: 1_000 })
  const record = handoff(context.generation)
  const input = { record, recordedAt: record.handoff_recorded_at, authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }
  const before = context.store.inspect()
  process.kill(context.broker.attestation().brokerPid, 'SIGSTOP')
  await assert.rejects(
    () => context.broker.registerFixedRecord(input),
    (error) => error.code === 'STATE_BROKER_APPEND_NOT_PERSISTED' && error.details.reconciliation.status === 'absent',
  )
  assert.deepEqual(context.store.inspect(), before)
  await assert.rejects(() => context.broker.registerFixedRecord(input), (error) => error.code === 'STATE_BROKER_APPEND_NOT_PERSISTED')
})

test('terminal response loss is reconciled field-for-field and a fresh broker can resume', async (t) => {
  const context = await environment(t, { crashOperationCode: 'finish_synthetic_no_effect' })
  const operation = { operationId: 'synthetic.terminal-response-loss', operationNonce: 'be'.repeat(32), operationModeCode: 'dry_run', startedAt: '2030-01-01T00:02:00.000Z', runtimeProfileRecordDigestSha256: context.generation.runtimeProfile.record_digest_sha256, identityBindingsRecordDigestSha256: context.generation.identityBindings.record_digest_sha256 }
  await context.broker.beginSyntheticDryRun({ operation, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher })
  const result = await context.broker.finishSyntheticNoEffect({ operationId: operation.operationId, operationNonce: operation.operationNonce, recordedAt: '2030-01-01T00:02:01.000Z', beforeLogicalStateSha256: '11'.repeat(32), afterLogicalStateSha256: '11'.repeat(32), reasonCode: 'synthetic_control_plane_no_effect', authenticatedVerifierBindingCode: context.trustedBindings.independent_verifier })
  assert.equal(result.persistenceStatus, 'persisted_after_response_loss')
  assert.equal(context.store.inspect().activeOperation, null)
  assert.equal(context.store.inspect().recoveryRequired, false)
  await assert.rejects(() => context.broker.beginSyntheticDryRun({ operation: { ...operation, operationId: 'synthetic.closed-broker', operationNonce: 'bf'.repeat(32) }, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher }), (error) => error.code === 'STATE_BROKER_TERMINATED')

  const restarted = await createProtectedStateAppendBroker({
    nonceSource: (() => { let value = 0xc1; return () => (value++).toString(16).padStart(64, '0') })(),
    rootPath: context.rootPath,
    trustedGenesisIdentityBindingsRecord: context.generation.identityBindings,
    verifiedControlPlaneBuild: context.verifiedControlPlaneBuild,
    verifiedGeneration: context.generation,
    workerModulePath: path.join(context.runtimeDirectory, sourceLeaves.state_append_broker),
  })
  t.after(() => restarted.close())
  const next = { ...operation, operationId: 'synthetic.after-exact-reconciliation', operationNonce: 'c2'.repeat(32), startedAt: '2030-01-01T00:02:02.000Z' }
  await restarted.beginSyntheticDryRun({ operation: next, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher })
  await restarted.finishSyntheticNoEffect({ operationId: next.operationId, operationNonce: next.operationNonce, recordedAt: '2030-01-01T00:02:03.000Z', beforeLogicalStateSha256: '12'.repeat(32), afterLogicalStateSha256: '12'.repeat(32), reasonCode: 'synthetic_control_plane_no_effect', authenticatedVerifierBindingCode: context.trustedBindings.independent_verifier })
  assert.equal(context.store.inspect().recoveryRequired, false)
})

test('recovery-terminal response loss resolves exactly while retaining a durable restart hold', async (t) => {
  const context = await environment(t, { crashOperationCode: 'mark_synthetic_recovery_required' })
  const operation = { operationId: 'synthetic.recovery-terminal-response-loss', operationNonce: 'c3'.repeat(32), operationModeCode: 'dry_run', startedAt: '2030-01-01T00:02:00.000Z', runtimeProfileRecordDigestSha256: context.generation.runtimeProfile.record_digest_sha256, identityBindingsRecordDigestSha256: context.generation.identityBindings.record_digest_sha256 }
  await context.broker.beginSyntheticDryRun({ operation, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher })
  const result = await context.broker.markSyntheticRecoveryRequired({ operationId: operation.operationId, operationNonce: operation.operationNonce, recordedAt: '2030-01-01T00:02:01.000Z', reasonCode: 'synthetic.unverified-effect', lastKnownLogicalStateSha256: '13'.repeat(32), authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher })
  assert.equal(result.persistenceStatus, 'persisted_after_response_loss')
  assert.deepEqual(context.store.inspect().recoveryReasons, ['operation_recovery_hold'])

  const restarted = await createProtectedStateAppendBroker({
    nonceSource: () => 'c4'.repeat(32),
    rootPath: context.rootPath,
    trustedGenesisIdentityBindingsRecord: context.generation.identityBindings,
    verifiedControlPlaneBuild: context.verifiedControlPlaneBuild,
    verifiedGeneration: context.generation,
    workerModulePath: path.join(context.runtimeDirectory, sourceLeaves.state_append_broker),
  })
  t.after(() => restarted.close())
  await assert.rejects(
    () => restarted.registerFixedRecord({ record: handoff(context.generation), recordedAt: '2030-01-01T00:05:18.000Z', authenticatedRuntimeRoleCode: 'handoff_broker', authenticatedBindingCode: context.trustedBindings.handoff_broker }),
    (error) => error.code === 'STATE_BROKER_APPEND_REJECTED' && error.details.workerCode === 'STATE_RECOVERY_REQUIRED',
  )
})

test('synthetic permitted recovery response loss verifies the exact operation and permit terminal projections', async (t) => {
  const context = await environment(t, { crashOperationCode: 'mark_synthetic_bootstrap_scope_recovery' })
  const { permit, reference, seal } = sealAndPermit(context.generation)
  await context.broker.registerFixedRecord({ record: seal, recordedAt: seal.sealed_at, authenticatedRuntimeRoleCode: 'trusted_launcher', authenticatedBindingCode: context.trustedBindings.trusted_launcher })
  await context.broker.issuePermit({ record: permit, persistedAt: permit.issued_at, authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority', authenticatedIssuerBindingCode: context.trustedBindings.bootstrap_authority, authenticatedPersistenceBindingCode: context.trustedBindings.trusted_launcher })
  const claimTransition = bootstrapClaim({ permit, reference, seal, trustedBindings: context.trustedBindings })
  const operation = { operationId: seal.operation_id, operationNonce: permit.operation_nonce, operationModeCode: 'bootstrap', startedAt: claimTransition.persisted_at, runtimeProfileRecordDigestSha256: context.generation.runtimeProfile.record_digest_sha256, identityBindingsRecordDigestSha256: context.generation.identityBindings.record_digest_sha256 }
  await context.broker.beginSyntheticBootstrapScopeAudit({ operation, claimTransition, authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher })
  const terminalPermitTransition = bootstrapRecoveryTransition({ claim: claimTransition, reference, trustedBindings: context.trustedBindings })
  const result = await context.broker.markSyntheticBootstrapScopeRecovery({
    operationId: operation.operationId,
    operationNonce: operation.operationNonce,
    recordedAt: terminalPermitTransition.persisted_at,
    reasonCode: 'synthetic.d9-2-verification-unimplemented',
    lastKnownLogicalStateSha256: reference.logical_state_sha256,
    authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher,
    terminalPermitTransition,
  })
  assert.equal(result.persistenceStatus, 'persisted_after_response_loss')
  const projectedOperation = context.store.projectOperation({ operationId: operation.operationId, operationNonce: operation.operationNonce })
  assert.equal(projectedOperation.state_code, 'recovery_required')
  assert.deepEqual(context.store.projectPermit({ permitCode: permit.permit_code, asOf: terminalPermitTransition.persisted_at }).currentTransition, terminalPermitTransition)
  assert.deepEqual(context.store.inspect().recoveryReasons, ['operation_recovery_hold'])
})

test('broker restart after binding rotation replays genesis against the separate original trust anchor', async (t) => {
  const context = await environment(t)
  await context.broker.close()
  const rotated = rotatedGenerationFixture(t, loadApprovedContractSet({ contractRoot }))
  chownTree(context.rootPath, 0, 0)
  const rotationStore = openProtectedStateStore({
    rootPath: context.rootPath,
    expectedUid: 0,
    trustedIdentityBindingsRecord: context.generation.identityBindings,
  })
  rotationStore.activateGenerationPair({
    pairCode: 'synthetic.broker-generation-pair-002',
    pairGeneration: 2,
    runtimeProfile: {
      generationNumber: rotated.generation.selection.profile_generation,
      generationCode: rotated.generation.runtimeProfile.profile_code,
      recordDigestSha256: rotated.generation.runtimeProfile.record_digest_sha256,
      validFrom: rotated.generation.runtimeProfile.issued_at,
      expiresAt: rotated.generation.identityBindings.expires_at,
    },
    identityBindings: {
      generationNumber: rotated.generation.selection.binding_generation,
      generationCode: rotated.generation.identityBindings.binding_set_code,
      recordDigestSha256: rotated.generation.identityBindings.record_digest_sha256,
      boundRuntimeProfileRecordDigestSha256: rotated.generation.runtimeProfile.record_digest_sha256,
      validFrom: rotated.generation.identityBindings.issued_at,
      expiresAt: rotated.generation.identityBindings.expires_at,
    },
    identityBindingsRecord: rotated.generation.identityBindings,
    activatedAt: '2030-01-01T00:03:00.000Z',
    authenticatedLauncherBindingCode: context.trustedBindings.trusted_launcher,
  })
  const launcherUid = rotated.generation.identityBindings.bindings.find((binding) => binding.runtime_role_code === 'trusted_launcher').unix_uid
  chownTree(context.rootPath, launcherUid, launcherUid)
  const rotatedBuild = verifyControlPlaneBuild({
    manifestPath: rotated.generationFixture.options.controlPlaneBuildManifestPath,
    projectRoot: projectDirectory,
    verifiedGeneration: rotated.generation,
  })
  const options = {
    nonceSource: (() => { let value = 0xd1; return () => (value++).toString(16).padStart(64, '0') })(),
    rootPath: context.rootPath,
    trustedGenesisIdentityBindingsRecord: context.generation.identityBindings,
    verifiedControlPlaneBuild: rotatedBuild,
    verifiedGeneration: rotated.generation,
    workerModulePath: path.join(context.runtimeDirectory, sourceLeaves.state_append_broker),
  }
  const currentBindings = bindings(rotated.generation)
  const first = await createProtectedStateAppendBroker(options)
  const operation = {
    operationId: 'synthetic.rotated-broker-operation',
    operationNonce: 'd2'.repeat(32),
    operationModeCode: 'dry_run',
    startedAt: '2030-01-01T00:04:00.000Z',
    runtimeProfileRecordDigestSha256: rotated.generation.runtimeProfile.record_digest_sha256,
    identityBindingsRecordDigestSha256: rotated.generation.identityBindings.record_digest_sha256,
  }
  await first.beginSyntheticDryRun({ operation, authenticatedLauncherBindingCode: currentBindings.trusted_launcher })
  await first.finishSyntheticNoEffect({
    operationId: operation.operationId,
    operationNonce: operation.operationNonce,
    recordedAt: '2030-01-01T00:04:01.000Z',
    beforeLogicalStateSha256: 'd3'.repeat(32),
    afterLogicalStateSha256: 'd3'.repeat(32),
    reasonCode: 'synthetic_control_plane_no_effect',
    authenticatedVerifierBindingCode: currentBindings.independent_verifier,
  })
  await first.close()
  const restarted = await createProtectedStateAppendBroker({ ...options, nonceSource: () => 'd4'.repeat(32) })
  t.after(() => restarted.close())
  assert.equal(restarted.attestation().identityBindingsRecordDigestSha256, rotated.generation.identityBindings.record_digest_sha256)
})
