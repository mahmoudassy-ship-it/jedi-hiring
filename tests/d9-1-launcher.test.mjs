import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { canonicalSha256, canonicalize, sha256Bytes, sha256File } from '../d9/control-plane/canonical.mjs'
import { verifyControlPlaneBuild } from '../d9/control-plane/build-integrity.mjs'
import {
  loadApprovedContractSet,
  validateApprovedRecord,
} from '../d9/control-plane/contracts.mjs'
import {
  D9LauncherError,
  createSyntheticBootstrapRosterVerifier,
  createSyntheticNoEffectProbe,
  createSyntheticPeerAttestor,
  createTrustedLauncher,
} from '../d9/control-plane/launcher.mjs'
import { SYNTHETIC_DESCRIPTOR_BYTES, compileLinuxEnforcement } from '../d9/control-plane/platform.mjs'
import {
  createProtectedStateAppendBroker,
  createSyntheticCrashStateAppendBroker,
} from '../d9/control-plane/state-append-broker.mjs'
import {
  createProtectedStateStore,
  openProtectedStateStore,
} from '../d9/control-plane/state-store.mjs'
import { createTestDatabase } from './helpers.mjs'
import {
  createGenerationFixture,
  fixture,
  projectDirectory,
  reseal,
  verifyFixture,
} from './d9-1-support/runtime-fixture.mjs'

const approvedContractRoot = path.join(projectDirectory, 'docs/schema/d9-0')
let platform

test.before(async () => {
  platform = await compileLinuxEnforcement()
})

test.after(async () => {
  await platform.dispose()
})

function clock(start = '2030-01-01T00:10:00.000Z') {
  let value = Date.parse(start)
  const source = () => new Date(value++).toISOString()
  source.peek = () => new Date(value).toISOString()
  return source
}

function exactTrustedBindings(verifiedGeneration) {
  return Object.freeze(Object.fromEntries(
    verifiedGeneration.identityBindings.bindings.map((binding) => [binding.runtime_role_code, binding.binding_code]),
  ))
}

function emptyStateSeal(contractSet, verifiedGeneration) {
  const seal = fixture('logical_state_empty')
  seal.state_payload.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  seal.logical_state_sha256 = canonicalSha256(seal.state_payload)
  reseal(seal)
  return validateApprovedRecord({
    contractSet,
    schemaFile: 'logical-state-seal-v1.schema.json',
    record: seal,
  })
}

function bootstrapSeal(verifiedGeneration, stateSeal) {
  const record = fixture('bootstrap_bundle_seal')
  record.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  record.identity_bindings_record_digest_sha256 = verifiedGeneration.identityBindings.record_digest_sha256
  record.target_logical_state = {
    state_seal_code: stateSeal.record_code,
    state_seal_record_digest_sha256: stateSeal.record_digest_sha256,
    logical_state_sha256: stateSeal.logical_state_sha256,
  }
  return reseal(record)
}

function collectorHandoff(verifiedGeneration) {
  const record = fixture('collector_handoff')
  const collector = verifiedGeneration.identityBindings.bindings.find(
    (binding) => binding.runtime_role_code === 'collector',
  )
  const broker = verifiedGeneration.identityBindings.bindings.find(
    (binding) => binding.runtime_role_code === 'handoff_broker',
  )
  record.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  record.identity_bindings_record_digest_sha256 = verifiedGeneration.identityBindings.record_digest_sha256
  record.collector_binding_code = collector.binding_code
  record.collector_principal_code = collector.atlas_principal_code
  record.collector_build_sha256 = verifiedGeneration.runtimeProfile.component_releases.find(
    (release) => release.runtime_role_code === 'collector',
  ).executable_sha256
  record.handoff_broker_binding_code = broker.binding_code
  return reseal(record)
}

function bootstrapPermit(verifiedGeneration, stateSeal) {
  const record = fixture('bootstrap_permit')
  record.runtime_profile_record_digest_sha256 = verifiedGeneration.runtimeProfile.record_digest_sha256
  record.identity_bindings_record_digest_sha256 = verifiedGeneration.identityBindings.record_digest_sha256
  record.importer_release_sha256 = verifiedGeneration.runtimeProfile.component_releases.find(
    (release) => release.runtime_role_code === 'bundle_importer',
  ).executable_sha256
  record.target_empty_logical_state = {
    state_seal_code: stateSeal.record_code,
    state_seal_record_digest_sha256: stateSeal.record_digest_sha256,
    logical_state_sha256: stateSeal.logical_state_sha256,
  }
  return reseal(record)
}

function bootstrapWithdrawal(permit, seal, stateSeal, persistedAt, verifiedGeneration) {
  const record = fixture('bootstrap_transition_in_progress')
  record.record_code = 'synthetic.permit-transition-withdrawn'
  record.permit_code = permit.permit_code
  record.permit_issuance_record_digest_sha256 = permit.record_digest_sha256
  record.transition_sequence = 1
  record.previous_transition_record_digest_sha256 = null
  record.from_state_code = 'ready'
  record.to_state_code = 'revoked'
  record.transition_code = 'authority_withdrawal'
  record.operation_id = seal.operation_id
  record.operation_nonce = permit.operation_nonce
  record.observed_logical_state = {
    state_seal_code: stateSeal.record_code,
    state_seal_record_digest_sha256: stateSeal.record_digest_sha256,
    logical_state_sha256: stateSeal.logical_state_sha256,
  }
  record.recovery_permit_record_digest_sha256 = null
  record.completion_journal_head_record_digest_sha256 = null
  record.recorded_by_runtime_role_code = 'bootstrap_authority'
  record.recorded_by_binding_code = verifiedGeneration.identityBindings.bindings.find(
    (binding) => binding.runtime_role_code === 'bootstrap_authority',
  ).binding_code
  record.persisted_by_binding_code = verifiedGeneration.identityBindings.bindings.find(
    (binding) => binding.runtime_role_code === 'trusted_launcher',
  ).binding_code
  record.occurred_at = persistedAt
  record.persisted_at = persistedAt
  record.reason_code = 'authority_withdrawal'
  return reseal(record)
}

function chownTree(target, uid, gid) {
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    const child = path.join(target, entry.name)
    if (entry.isDirectory()) chownTree(child, uid, gid)
    fs.chownSync(child, uid, gid)
  }
  fs.chownSync(target, uid, gid)
}

async function createEnvironment(t, {
  brokerCrashOperationCode = null,
  mutatePeer,
  nonceSource = () => 'a1'.repeat(32),
  operationIdSource = () => 'synthetic.launcher-dry-run',
  pairMutator = (pair) => pair,
  probeRun = async () => ({ canonicalEffectCode: 'none', issuedHandleCount: 0, rollbackVerified: true }),
  rosterVerify = async (input) => ({
    bundleDigestSha256: input.bundleDigestSha256,
    manifestPath: input.manifestPath,
    observedPrincipalRosterSha256: input.expectedPrincipalRosterSha256,
    permitCode: input.permitCode,
    reviewedGitCommit: input.reviewedGitCommit,
    syntheticTestDouble: true,
  }),
  revokeGenerationAt = null,
  timeSource = clock(),
} = {}) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-1-launcher-'))
  fs.chmodSync(workspace, 0o755)
  t.after(() => fs.rmSync(workspace, { force: true, recursive: true }))
  const isolatedContractRoot = path.join(workspace, 'contracts')
  fs.cpSync(approvedContractRoot, isolatedContractRoot, { recursive: true })
  const contractSet = loadApprovedContractSet({ contractRoot: isolatedContractRoot })
  const generationFixture = createGenerationFixture(t, { serviceExecutablePath: platform.syntheticExecutablePath })
  const verifiedGeneration = verifyFixture(contractSet, generationFixture)
  const runtimeProfilePath = path.join(generationFixture.root, 'protected/runtime-profile.json')
  const identityBindingsPath = path.join(generationFixture.root, 'protected/identity-bindings.json')
  fs.mkdirSync(path.dirname(runtimeProfilePath), { recursive: true })
  fs.writeFileSync(runtimeProfilePath, canonicalize(generationFixture.runtime))
  fs.writeFileSync(identityBindingsPath, canonicalize(generationFixture.identity))
  const database = createTestDatabase()
  t.after(database.remove)
  const stateRoot = path.join(workspace, 'protected-state')
  const lockRoot = path.join(workspace, 'kernel-lock')
  fs.mkdirSync(lockRoot, { mode: 0o700 })
  fs.writeFileSync(path.join(lockRoot, 'peer-attestation.handle'), SYNTHETIC_DESCRIPTOR_BYTES, { mode: 0o600 })
  const trustedBindings = exactTrustedBindings(verifiedGeneration)
  const provisioningStateStore = createProtectedStateStore({
    rootPath: stateRoot,
    trustedIdentityBindingsRecord: verifiedGeneration.identityBindings,
  })
  provisioningStateStore.activateGenerationPair(pairMutator({
    pairCode: 'synthetic.launcher-generation-pair',
    pairGeneration: 1,
    runtimeProfile: {
      generationNumber: verifiedGeneration.selection.profile_generation,
      generationCode: verifiedGeneration.runtimeProfile.profile_code,
      recordDigestSha256: verifiedGeneration.runtimeProfile.record_digest_sha256,
      validFrom: verifiedGeneration.runtimeProfile.issued_at,
      expiresAt: verifiedGeneration.identityBindings.expires_at,
    },
    identityBindings: {
      generationNumber: verifiedGeneration.selection.binding_generation,
      generationCode: verifiedGeneration.identityBindings.binding_set_code,
      recordDigestSha256: verifiedGeneration.identityBindings.record_digest_sha256,
      boundRuntimeProfileRecordDigestSha256: verifiedGeneration.runtimeProfile.record_digest_sha256,
      validFrom: verifiedGeneration.identityBindings.issued_at,
      expiresAt: verifiedGeneration.identityBindings.expires_at,
    },
    identityBindingsRecord: verifiedGeneration.identityBindings,
    activatedAt: '2030-01-01T00:01:01.000Z',
    authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
  }))
  if (revokeGenerationAt !== null) {
    provisioningStateStore.revokeGenerationPair({
      pairCode: 'synthetic.launcher-generation-pair',
      pairGeneration: 1,
      runtimeProfileRecordDigestSha256: verifiedGeneration.runtimeProfile.record_digest_sha256,
      identityBindingsRecordDigestSha256: verifiedGeneration.identityBindings.record_digest_sha256,
      revokedAt: revokeGenerationAt,
      reasonCode: 'synthetic.revocation',
      authenticatedLauncherBindingCode: trustedBindings.trusted_launcher,
    })
  }
  const launcherBinding = verifiedGeneration.identityBindings.bindings.find(
    (binding) => binding.runtime_role_code === 'trusted_launcher',
  )
  chownTree(stateRoot, launcherBinding.unix_uid, launcherBinding.unix_uid)
  const protectedStateStore = openProtectedStateStore({
    rootPath: stateRoot,
    expectedUid: launcherBinding.unix_uid,
    trustedIdentityBindingsRecord: verifiedGeneration.identityBindings,
  })

  const brokerRuntimeRoot = path.join(workspace, 'state-broker-runtime')
  fs.mkdirSync(brokerRuntimeRoot, { mode: 0o755 })
  for (const leaf of ['canonical.mjs', 'state-append-broker.mjs', 'state-store.mjs']) {
    fs.copyFileSync(path.join(projectDirectory, 'd9/control-plane', leaf), path.join(brokerRuntimeRoot, leaf))
    fs.chmodSync(path.join(brokerRuntimeRoot, leaf), 0o444)
  }
  fs.chmodSync(brokerRuntimeRoot, 0o555)
  const verifiedControlPlaneBuild = verifyControlPlaneBuild({
    manifestPath: generationFixture.options.controlPlaneBuildManifestPath,
    projectRoot: projectDirectory,
    verifiedGeneration,
  })
  const stateAppendBrokerOptions = {
    nonceSource: (() => { let value = 1; return () => (value++).toString(16).padStart(64, '0') })(),
    rootPath: stateRoot,
    trustedGenesisIdentityBindingsRecord: verifiedGeneration.identityBindings,
    verifiedControlPlaneBuild,
    verifiedGeneration,
    workerModulePath: path.join(brokerRuntimeRoot, 'state-append-broker.mjs'),
  }
  const stateAppendBroker = brokerCrashOperationCode === null
    ? await createProtectedStateAppendBroker(stateAppendBrokerOptions)
    : await createSyntheticCrashStateAppendBroker(stateAppendBrokerOptions, brokerCrashOperationCode)
  t.after(() => stateAppendBroker.close())
  const stateSeal = emptyStateSeal(contractSet, verifiedGeneration)
  const observedProbeInputs = []
  const observedPeerRoles = []
  const launcher = createTrustedLauncher({
    configuration: {
      databasePath: database.databasePath,
      expectedEmptyStateSeal: stateSeal,
      operationLockLeaf: 'd9-1-operation.lock',
      operationLockRootPath: lockRoot,
      projectRoot: projectDirectory,
      syntheticControlPlaneOnly: true,
    },
    contractSet,
    nonceSource,
    operationIdSource,
    peerAttestor: createSyntheticPeerAttestor({
      descriptorLeaf: 'peer-attestation.handle',
      descriptorRootPath: lockRoot,
      platform,
      verifiedGeneration,
      mutatePeer(peer, roleCode, requestDigestSha256) {
        observedPeerRoles.push(roleCode)
        return mutatePeer ? mutatePeer(peer, roleCode, requestDigestSha256) : peer
      },
    }),
    platform,
    protectedStateStore,
    runtimeVerification: {
      componentFiles: generationFixture.options.componentFiles,
      controlPlaneBuildManifestPath: generationFixture.options.controlPlaneBuildManifestPath,
      evidenceBundleSchemaPath: generationFixture.options.evidenceBundleSchemaPath,
      identityBindingsPath,
      migrationsDirectory: generationFixture.options.migrationsDirectory,
      operationalProfileFiles: generationFixture.options.operationalProfileFiles,
      runtimeDomainFile: generationFixture.options.runtimeDomainFile,
      runtimeProfilePath,
      scannerFiles: generationFixture.options.scannerFiles,
    },
    stateAppendBroker,
    syntheticBootstrapRosterVerifier: createSyntheticBootstrapRosterVerifier({ verify: rosterVerify }),
    syntheticNoEffectProbe: createSyntheticNoEffectProbe({
      async run(input) {
        observedProbeInputs.push(structuredClone(input))
        return probeRun(input)
      },
    }),
    timeSource,
    verifiedGeneration,
  })
  return {
    database,
    contractSet,
    generationFixture,
    launcher,
    lockRoot,
    isolatedContractRoot,
    observedProbeInputs,
    observedPeerRoles,
    protectedStateStore,
    stateRoot,
    stateAppendBroker,
    stateSeal,
    trustedBindings,
    verifiedGeneration,
    identityBindingsPath,
    runtimeProfilePath,
  }
}

test('trusted launcher fails closed through startup and audits all seven approved scope partitions', async (t) => {
  const environment = await createEnvironment(t)
  const result = await environment.launcher.start()
  assert.deepEqual(result, {
    syntheticControlPlaneOnly: true,
    activeProfileGeneration: 7,
    activeBindingGeneration: 11,
    scopePartitionCount: 7,
    atlasTableCount: 13,
    logicalStateSha256: environment.stateSeal.logical_state_sha256,
  })
  const audit = environment.launcher.scopeAudit()
  assert.equal(audit.length, 7)
  assert.deepEqual(audit.map((entry) => entry.operationScopeCode).toSorted(), [
    'accepted_bootstrap_no_op',
    'accepted_document_no_op',
    'bootstrap_first_acceptance',
    'exact_bootstrap_reconstruction',
    'ordinary_document_import',
    'post_promotion_completion_bootstrap',
    'post_promotion_completion_document',
  ])
  assert.equal(audit.every((entry) => entry.requiredGrantCount + entry.forbiddenGrantCount === 33), true)
  await assert.rejects(() => environment.launcher.start({ scopeCode: 'ordinary_document_import' }), (error) => (
    error instanceof D9LauncherError && error.code === 'LAUNCHER_INPUT_INVALID'
  ))
  assert.throws(() => environment.launcher.scopeAudit({ operationModeCode: 'bootstrap' }), /accepts no caller fields/)
})

test('all seven exact partitions deliver only their required grants to authenticated processes and confirm termination', async (t) => {
  const environment = await createEnvironment(t)
  await environment.launcher.start()
  const result = await environment.launcher.runSyntheticHandleDeliveryAudit()
  assert.equal(result.syntheticTestDouble, true)
  assert.equal(result.scopeCount, 7)
  assert.equal(result.verifiedGrantCount, 83)
  assert.equal(result.deliveredGrantCount, 78)
  assert.equal(result.receiverTerminationCount, 29)
  assert.equal(result.stateAppendBrokerGrantCount, 5)
  assert.equal(result.stateAppendBrokerScopeCount, 5)
  assert.deepEqual(result.summaries.map((entry) => entry.verifiedGrantCount), [5, 12, 15, 11, 24, 7, 9])
  assert.deepEqual(result.summaries.map((entry) => entry.descriptorDeliveredGrantCount), [5, 12, 14, 10, 23, 6, 8])
  assert.deepEqual(result.summaries.map((entry) => entry.receiverTerminationCount), [3, 4, 5, 4, 7, 3, 3])
  assert.deepEqual(result.summaries.map((entry) => entry.stateAppendBrokerGrantCount), [0, 0, 1, 1, 1, 1, 1])
  await assert.rejects(
    () => environment.launcher.runSyntheticHandleDeliveryAudit({ operationScopeCode: 'ordinary_document_import' }),
    (error) => error instanceof D9LauncherError && error.code === 'LAUNCHER_INPUT_INVALID',
  )
})

test('launcher maps protected fixed-record and permit writes to authenticated bindings', async (t) => {
  const timeSource = clock()
  const environment = await createEnvironment(t, { timeSource })
  await environment.launcher.start()
  const handoff = collectorHandoff(environment.verifiedGeneration)
  const handoffResult = await environment.launcher.registerCollectorHandoff(Buffer.from(canonicalize(handoff)))
  assert.equal(handoffResult.recordCode, handoff.record_code)
  const resolvedHandoff = environment.launcher.resolveControlReference({
    recordCode: handoff.record_code,
    recordDigestSha256: handoff.record_digest_sha256,
    recordKindCode: 'collector_handoff',
  })
  assert.equal(resolvedHandoff.record_digest_sha256, handoff.record_digest_sha256)

  const seal = bootstrapSeal(environment.verifiedGeneration, environment.stateSeal)
  const sealResult = await environment.launcher.registerBundleSeal(Buffer.from(canonicalize(seal)))
  assert.equal(sealResult.recordCode, seal.record_code)

  const permit = bootstrapPermit(environment.verifiedGeneration, environment.stateSeal)
  const permitResult = await environment.launcher.issueBootstrapPermit(Buffer.from(canonicalize(permit)))
  assert.equal(permitResult.permitCode, permit.permit_code)
  assert.equal(permitResult.operationScopeCode, null)
  assert.equal(permitResult.requiredHandleCount, null)
  assert.equal(permitResult.claimEligible, false)
  assert.equal(permitResult.handlesIssued, false)
  const resolved = environment.launcher.resolveControlReference({
    recordCode: permit.permit_code,
    recordDigestSha256: permit.record_digest_sha256,
    recordKindCode: 'bootstrap_permit',
  })
  assert.equal(resolved.stateCode, 'ready')
  assert.equal(resolved.record.record_digest_sha256, permit.record_digest_sha256)
  assert.equal(typeof environment.launcher.claimBootstrapPermit, 'undefined')
  assert.equal(typeof environment.launcher.beginPermittedOperation, 'undefined')

  const withdrawal = bootstrapWithdrawal(
    permit,
    seal,
    environment.stateSeal,
    timeSource.peek(),
    environment.verifiedGeneration,
  )
  const withdrawn = await environment.launcher.appendBootstrapPermitWithdrawal(Buffer.from(canonicalize(withdrawal)))
  assert.equal(withdrawn.transitionCode, withdrawal.record_code)
  assert.equal(environment.protectedStateStore.projectPermit({
    permitCode: permit.permit_code,
    asOf: timeSource.peek(),
  }).stateCode, 'revoked')

  const substituted = structuredClone(seal)
  substituted.runtime_profile_record_digest_sha256 = '00'.repeat(32)
  reseal(substituted)
  await assert.rejects(
    () => environment.launcher.registerBundleSeal(Buffer.from(canonicalize(substituted))),
    (error) => error instanceof D9LauncherError && error.code === 'LAUNCHER_GENERATION_SUBSTITUTION',
  )
})

test('disposable permit audit binds a verified synthetic roster to the exact scope, delivers and revokes grants, and ends recovery-required without effect', async (t) => {
  const environment = await createEnvironment(t)
  await environment.launcher.start()
  const seal = bootstrapSeal(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.registerBundleSeal(Buffer.from(canonicalize(seal)))
  const permit = bootstrapPermit(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.issueBootstrapPermit(Buffer.from(canonicalize(permit)))
  const databaseDigest = sha256File(environment.database.databasePath)

  const result = await environment.launcher.runSyntheticPermitScopedBootstrapAudit()
  assert.deepEqual({
    acceptedBundleProjectionVerified: result.acceptedBundleProjectionVerified,
    canonicalEffectCode: result.canonicalEffectCode,
    descriptorDeliveredGrantCount: result.descriptorDeliveredGrantCount,
    issuedHandleCount: result.issuedHandleCount,
    operationScopeCode: result.operationScopeCode,
    outcomeCode: result.outcomeCode,
    permitStateCode: result.permitStateCode,
    realBootstrapExecuted: result.realBootstrapExecuted,
    receiverTerminationCount: result.receiverTerminationCount,
    stateAppendBrokerGrantCount: result.stateAppendBrokerGrantCount,
    syntheticTestDouble: result.syntheticTestDouble,
  }, {
    acceptedBundleProjectionVerified: false,
    canonicalEffectCode: 'none_observed_not_accepted',
    descriptorDeliveredGrantCount: 14,
    issuedHandleCount: 15,
    operationScopeCode: 'bootstrap_first_acceptance',
    outcomeCode: 'synthetic_scope_exercised_recovery_required',
    permitStateCode: 'recovery_required',
    realBootstrapExecuted: false,
    receiverTerminationCount: 5,
    stateAppendBrokerGrantCount: 1,
    syntheticTestDouble: true,
  })
  assert.equal(sha256File(environment.database.databasePath), databaseDigest)
  assert.equal(environment.protectedStateStore.projectPermit({ permitCode: permit.permit_code, asOf: '2030-01-01T00:59:00.000Z' }).stateCode, 'recovery_required')
  const operation = environment.protectedStateStore.projectOperation({ operationId: seal.operation_id, operationNonce: permit.operation_nonce })
  assert.equal(operation.state_code, 'recovery_required')
  assert.equal(operation.permit_code, permit.permit_code)
  assert.equal(environment.protectedStateStore.inspect().recoveryRequired, true)
  assert.equal(environment.protectedStateStore.inspect().activeOperation, null)
  await assert.rejects(
    () => environment.launcher.runSyntheticPermitScopedBootstrapAudit(),
    (error) => error.code === 'LAUNCHER_RECOVERY_REQUIRED',
  )
  assert.equal(typeof environment.launcher.claimBootstrapPermit, 'undefined')
  assert.equal(typeof environment.launcher.beginPermittedOperation, 'undefined')
})

test('synthetic permit audit rejects a mismatched roster before claim or handle delivery', async (t) => {
  const environment = await createEnvironment(t, {
    rosterVerify: async (input) => ({
      bundleDigestSha256: input.bundleDigestSha256,
      manifestPath: input.manifestPath,
      observedPrincipalRosterSha256: 'ff'.repeat(32),
      permitCode: input.permitCode,
      reviewedGitCommit: input.reviewedGitCommit,
      syntheticTestDouble: true,
    }),
  })
  await environment.launcher.start()
  const seal = bootstrapSeal(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.registerBundleSeal(Buffer.from(canonicalize(seal)))
  const permit = bootstrapPermit(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.issueBootstrapPermit(Buffer.from(canonicalize(permit)))
  const before = environment.protectedStateStore.inspect()
  await assert.rejects(
    () => environment.launcher.runSyntheticPermitScopedBootstrapAudit(),
    (error) => error.code === 'LAUNCHER_SYNTHETIC_ROSTER_MISMATCH',
  )
  assert.deepEqual(environment.protectedStateStore.inspect(), before)
  assert.equal(environment.protectedStateStore.projectPermit({ permitCode: permit.permit_code, asOf: '2030-01-01T00:59:00.000Z' }).stateCode, 'ready')
})

test('lost permit-claim response fails closed before any scope handle is delivered', async (t) => {
  const environment = await createEnvironment(t, { brokerCrashOperationCode: 'begin_synthetic_bootstrap_scope_audit' })
  await environment.launcher.start()
  const seal = bootstrapSeal(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.registerBundleSeal(Buffer.from(canonicalize(seal)))
  const permit = bootstrapPermit(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.issueBootstrapPermit(Buffer.from(canonicalize(permit)))
  const peerCountBeforeClaim = environment.observedPeerRoles.length
  await assert.rejects(
    () => environment.launcher.runSyntheticPermitScopedBootstrapAudit(),
    (error) => error.code === 'STATE_BROKER_RECOVERY_REQUIRED',
  )
  assert.equal(environment.observedPeerRoles.length, peerCountBeforeClaim)
  assert.equal(environment.protectedStateStore.projectPermit({ permitCode: permit.permit_code, asOf: '2030-01-01T00:59:00.000Z' }).stateCode, 'in_progress')
  assert.deepEqual(environment.protectedStateStore.inspect().recoveryReasons, ['unfinished_operation'])
})

test('permit-scoped delivery revalidates the issuance-pinned seal before every role and stops at exclusive expiry', async (t) => {
  let expireSeal = false
  let currentTime = Date.parse('2030-01-01T00:10:00.000Z')
  const environment = await createEnvironment(t, {
    mutatePeer(peer, roleCode) {
      if (roleCode === 'database_writer') expireSeal = true
      return peer
    },
    timeSource() {
      return expireSeal ? '2030-01-01T01:04:30.000Z' : new Date(currentTime++).toISOString()
    },
  })
  await environment.launcher.start()
  const seal = bootstrapSeal(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.registerBundleSeal(Buffer.from(canonicalize(seal)))
  const permit = bootstrapPermit(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.issueBootstrapPermit(Buffer.from(canonicalize(permit)))
  await assert.rejects(
    () => environment.launcher.runSyntheticPermitScopedBootstrapAudit(),
    (error) => error.code === 'LAUNCHER_RECOVERY_REQUIRED' && error.cause?.code === 'STATE_BOOTSTRAP_SEAL_MISMATCH',
  )
  assert.deepEqual(environment.observedPeerRoles.slice(-3), ['bundle_importer', 'cloner_promoter', 'database_writer'])
  assert.equal(environment.observedPeerRoles.includes('independent_verifier'), false)
  assert.equal(environment.protectedStateStore.projectPermit({ permitCode: permit.permit_code, asOf: '2030-01-01T01:04:30.001Z' }).stateCode, 'recovery_required')
})

test('synthetic permit audit is unreachable without exactly one launcher-issued permit', async (t) => {
  const environment = await createEnvironment(t)
  await environment.launcher.start()
  await assert.rejects(
    () => environment.launcher.runSyntheticPermitScopedBootstrapAudit(),
    (error) => error.code === 'LAUNCHER_SYNTHETIC_PERMIT_UNAVAILABLE',
  )
})

for (const [label, selectedPath] of [
  ['runtime profile', (environment) => environment.runtimeProfilePath],
  ['identity bindings', (environment) => environment.identityBindingsPath],
]) {
  test(`launcher rejects a post-construction ${label} symlink swap even when target bytes are approved`, async (t) => {
    const environment = await createEnvironment(t)
    await environment.launcher.start()
    const selected = selectedPath(environment)
    const approvedTarget = `${selected}.approved`
    fs.renameSync(selected, approvedTarget)
    fs.symlinkSync(approvedTarget, selected)
    const before = environment.protectedStateStore.inspect()
    await assert.rejects(
      () => environment.launcher.revokeActiveGeneration({ reasonCode: 'synthetic.must-not-apply' }),
      (error) => error.code === 'LAUNCHER_CONFIGURATION_INVALID',
    )
    assert.deepEqual(environment.protectedStateStore.inspect(), before)
  })
}

test('launcher routes registry and active-generation revocations through the protected broker', async (t) => {
  const environment = await createEnvironment(t)
  await environment.launcher.start()
  const handoff = collectorHandoff(environment.verifiedGeneration)
  await environment.launcher.registerCollectorHandoff(Buffer.from(canonicalize(handoff)))
  const handoffRevocation = await environment.launcher.revokeRegisteredControlRecord({
    recordKindCode: 'collector_handoff',
    recordCode: handoff.record_code,
    recordDigestSha256: handoff.record_digest_sha256,
    reasonCode: 'synthetic.handoff-integrity-hold',
  })
  assert.equal(handoffRevocation.recordCode, handoff.record_code)
  assert.throws(() => environment.launcher.resolveControlReference({ recordKindCode: 'collector_handoff', recordCode: handoff.record_code, recordDigestSha256: handoff.record_digest_sha256 }), (error) => error.code === 'STATE_REGISTRY_RECORD_REVOKED')

  const seal = bootstrapSeal(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.registerBundleSeal(Buffer.from(canonicalize(seal)))
  await environment.launcher.revokeRegisteredControlRecord({
    recordKindCode: 'bundle_seal',
    recordCode: seal.record_code,
    recordDigestSha256: seal.record_digest_sha256,
    reasonCode: 'synthetic.seal-integrity-hold',
  })
  assert.throws(() => environment.launcher.resolveControlReference({ recordKindCode: 'bundle_seal', recordCode: seal.record_code, recordDigestSha256: seal.record_digest_sha256 }), (error) => error.code === 'STATE_REGISTRY_RECORD_REVOKED')
  await assert.rejects(() => environment.launcher.revokeRegisteredControlRecord({ recordKindCode: 'bootstrap_permit', recordCode: seal.record_code, recordDigestSha256: seal.record_digest_sha256, reasonCode: 'synthetic.invalid-kind' }), (error) => error.code === 'LAUNCHER_RECORD_KIND_INVALID')

  const generationRevocation = await environment.launcher.revokeActiveGeneration({ reasonCode: 'synthetic.active-generation-hold' })
  assert.equal(generationRevocation.pairCode, 'synthetic.launcher-generation-pair')
  assert.equal(environment.protectedStateStore.projectGenerationPairRevocation({ pairCode: generationRevocation.pairCode }).reason_code, 'synthetic.active-generation-hold')
  await assert.rejects(() => environment.launcher.runSyntheticBootstrapDryRun(), (error) => error.code === 'LAUNCHER_NOT_STARTED')
})

test('synthetic bootstrap dry-run is zero-handle, rollback-verified, replay-safe, and has no canonical effect', async (t) => {
  let verifierRequestDigest
  const environment = await createEnvironment(t, {
    mutatePeer(peer, role, requestDigestSha256) {
      if (role === 'independent_verifier') verifierRequestDigest = requestDigestSha256
      return peer
    },
  })
  await environment.launcher.start()
  const beforeDatabase = sha256File(environment.database.databasePath)
  const beforeSequence = environment.protectedStateStore.inspect().sequence
  const result = await environment.launcher.runSyntheticBootstrapDryRun()
  assert.deepEqual(result, {
    outcomeCode: 'synthetic_no_effect_verified',
    operationId: 'synthetic.launcher-dry-run',
    operationNonce: 'a1'.repeat(32),
    issuedHandleCount: 0,
    logicalStateSha256: environment.stateSeal.logical_state_sha256,
    acceptedBundleProjectionVerified: false,
  })
  assert.equal(sha256File(environment.database.databasePath), beforeDatabase)
  assert.equal(environment.protectedStateStore.inspect().sequence, beforeSequence + 2)
  assert.equal(environment.protectedStateStore.inspect().activeOperation, null)
  assert.equal(verifierRequestDigest, sha256Bytes(Buffer.from(canonicalize({
    format: 'jedi-atlas-d91-synthetic-no-effect-attestation',
    format_version: '1.0.0',
    outcome_code: 'synthetic_no_effect_verified',
    operation_id: 'synthetic.launcher-dry-run',
    operation_nonce: 'a1'.repeat(32),
    before_database_file_sha256: beforeDatabase,
    before_logical_state_sha256: environment.stateSeal.logical_state_sha256,
    after_database_file_sha256: beforeDatabase,
    after_logical_state_sha256: environment.stateSeal.logical_state_sha256,
    issued_handle_count: 0,
  }), 'utf8')))
  assert.deepEqual(environment.observedProbeInputs, [{
    operationId: 'synthetic.launcher-dry-run',
    operationNonce: 'a1'.repeat(32),
    operationModeCode: 'dry_run',
    bundleKindCode: 'principal_bootstrap',
    issuedHandleGrants: [],
    syntheticTestDouble: true,
  }])
  assert.equal(Object.keys(environment.observedProbeInputs[0]).some((key) => /path|principal|scope|fingerprint/iu.test(key)), false)

  await assert.rejects(
    () => environment.launcher.runSyntheticBootstrapDryRun(),
    (error) => error.code === 'STATE_BROKER_APPEND_REJECTED' && error.details?.workerCode === 'STATE_NONCE_REPLAY',
  )
  assert.equal(sha256File(environment.database.databasePath), beforeDatabase)
})

test('frozen operation deadline places a hung synthetic probe on recovery hold', async (t) => {
  const environment = await createEnvironment(t, { probeRun: async () => await new Promise(() => {}) })
  await environment.launcher.start()
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const pending = environment.launcher.runSyntheticBootstrapDryRun()
  while (environment.observedProbeInputs.length === 0) await new Promise((resolve) => setImmediate(resolve))
  t.mock.timers.tick(environment.verifiedGeneration.runtimeProfile.limits.operation_timeout_ms)
  await assert.rejects(
    pending,
    (error) => error instanceof D9LauncherError && error.code === 'LAUNCHER_RECOVERY_REQUIRED' && error.cause?.code === 'LAUNCHER_OPERATION_TIMEOUT',
  )
  assert.deepEqual(environment.protectedStateStore.inspect().recoveryReasons, ['operation_recovery_hold'])
})

test('startup rejects kernel-peer identity spoofing and revoked active generations', async (t) => {
  const spoofed = await createEnvironment(t, {
    mutatePeer(peer, role) {
      return role === 'human_submitter' ? { ...peer, uid: peer.uid + 10_000 } : peer
    },
  })
  await spoofed.launcher.start()
  await assert.rejects(() => spoofed.launcher.runSyntheticBootstrapDryRun(), (error) => error.code === 'PEER_IDENTITY_UNMAPPED')

  const revoked = await createEnvironment(t, { revokeGenerationAt: '2030-01-01T00:09:00.000Z' })
  await assert.rejects(() => revoked.launcher.start(), (error) => error.code === 'STATE_ACTIVE_GENERATION_REVOKED')

  const substitutedPair = await createEnvironment(t, {
    pairMutator(pair) {
      return {
        ...pair,
        runtimeProfile: { ...pair.runtimeProfile, generationCode: 'synthetic.substituted-profile-code' },
      }
    },
  })
  await assert.rejects(
    () => substitutedPair.launcher.start(),
    (error) => error instanceof D9LauncherError && error.code === 'LAUNCHER_GENERATION_SUBSTITUTION',
  )
})

test('launcher rehashes protected runtime inputs before every privileged boundary', async (t) => {
  const environment = await createEnvironment(t)
  await environment.launcher.start()
  fs.appendFileSync(environment.generationFixture.options.controlPlaneBuildManifestPath, 'substitution\n')
  const before = environment.protectedStateStore.inspect()
  await assert.rejects(
    () => environment.launcher.runSyntheticBootstrapDryRun(),
    (error) => error.code === 'RUNTIME_PROFILE_MISMATCH',
  )
  assert.deepEqual(environment.protectedStateStore.inspect(), before)
})

test('mid-operation runtime or frozen-contract substitution prevents a terminal no-effect record', async (t) => {
  for (const targetKind of ['runtime', 'contract']) {
    await t.test(targetKind, async (subtest) => {
      let targetPath
      const environment = await createEnvironment(subtest, {
        probeRun: async () => {
          fs.appendFileSync(targetPath, '\nsubstituted-during-probe\n')
          return { canonicalEffectCode: 'none', issuedHandleCount: 0, rollbackVerified: true }
        },
      })
      targetPath = targetKind === 'runtime'
        ? environment.generationFixture.options.componentFiles.bundle_importer.executable
        : path.join(environment.isolatedContractRoot, 'common-v1.schema.json')
      await environment.launcher.start()
      await assert.rejects(
        () => environment.launcher.runSyntheticBootstrapDryRun(),
        (error) => error instanceof D9LauncherError && error.code === 'LAUNCHER_RECOVERY_REQUIRED',
      )
      assert.deepEqual(environment.protectedStateStore.inspect().recoveryReasons, ['operation_recovery_hold'])
    })
  }
})

test('authentication that crosses binding-generation expiry fails before persistence', async (t) => {
  let crossExpiry = false
  const environment = await createEnvironment(t, {
    mutatePeer(peer, role) {
      if (role === 'handoff_broker') crossExpiry = true
      return peer
    },
    timeSource() {
      return crossExpiry ? '2030-01-02T00:01:00.000Z' : '2030-01-01T00:10:00.000Z'
    },
  })
  await environment.launcher.start()
  const before = environment.protectedStateStore.inspect()
  const handoff = collectorHandoff(environment.verifiedGeneration)
  await assert.rejects(
    () => environment.launcher.registerCollectorHandoff(Buffer.from(canonicalize(handoff))),
    (error) => ['IDENTITY_BINDING_MISMATCH', 'RUNTIME_PROFILE_MISMATCH', 'STATE_ACTIVE_GENERATION_MISSING'].includes(error.code),
  )
  assert.deepEqual(environment.protectedStateStore.inspect(), before)
})

test('launcher rejects semantically invalid handoff chronology before protected-state mutation', async (t) => {
  const environment = await createEnvironment(t)
  await environment.launcher.start()
  const handoff = collectorHandoff(environment.verifiedGeneration)
  ;[handoff.collection_started_at, handoff.collection_completed_at] = [
    handoff.collection_completed_at,
    handoff.collection_started_at,
  ]
  reseal(handoff)
  const before = environment.protectedStateStore.inspect()
  await assert.rejects(
    () => environment.launcher.registerCollectorHandoff(Buffer.from(canonicalize(handoff))),
    (error) => error.code === 'CEREMONY_CHRONOLOGY_INVALID',
  )
  assert.deepEqual(environment.protectedStateStore.inspect(), before)
})

test('unreopened bootstrap roster commitment may be stored but cannot become claimable or issue handles in D9.1', async (t) => {
  const environment = await createEnvironment(t)
  await environment.launcher.start()
  const seal = bootstrapSeal(environment.verifiedGeneration, environment.stateSeal)
  await environment.launcher.registerBundleSeal(Buffer.from(canonicalize(seal)))
  const permit = bootstrapPermit(environment.verifiedGeneration, environment.stateSeal)
  permit.expected_principal_roster_sha256 = 'ff'.repeat(32)
  reseal(permit)
  const result = await environment.launcher.issueBootstrapPermit(Buffer.from(canonicalize(permit)))
  assert.equal(result.claimEligible, false)
  assert.equal(result.handlesIssued, false)
  assert.equal(result.operationScopeCode, null)
  assert.equal(typeof environment.launcher.claimBootstrapPermit, 'undefined')
  assert.equal(typeof environment.launcher.beginPermittedOperation, 'undefined')
})

test('native kernel lock excludes launcher before protected operation mutation', async (t) => {
  const environment = await createEnvironment(t)
  await environment.launcher.start()
  const held = await platform.holdOperationLock({
    rootPath: environment.lockRoot,
    relativePath: 'd9-1-operation.lock',
  })
  try {
    const before = environment.protectedStateStore.inspect()
    await assert.rejects(() => environment.launcher.runSyntheticBootstrapDryRun(), (error) => (
      error.code === 'OPERATION_LOCK_UNAVAILABLE'
    ))
    assert.deepEqual(environment.protectedStateStore.inspect(), before)
  } finally {
    await held.release()
  }
})

test('unproven synthetic rollback records recovery-required terminal state without database effects', async (t) => {
  const environment = await createEnvironment(t, {
    probeRun: async () => ({ canonicalEffectCode: 'unknown', issuedHandleCount: 0, rollbackVerified: false }),
  })
  await environment.launcher.start()
  const databaseDigest = sha256File(environment.database.databasePath)
  const beforeSequence = environment.protectedStateStore.inspect().sequence
  await assert.rejects(
    () => environment.launcher.runSyntheticBootstrapDryRun(),
    (error) => error instanceof D9LauncherError && error.code === 'LAUNCHER_RECOVERY_REQUIRED',
  )
  assert.equal(sha256File(environment.database.databasePath), databaseDigest)
  assert.equal(environment.protectedStateStore.inspect().sequence, beforeSequence + 2)
  assert.equal(environment.protectedStateStore.inspect().activeOperation, null)
  assert.equal(environment.protectedStateStore.inspect().recoveryRequired, true)
  assert.deepEqual(environment.protectedStateStore.inspect().recoveryReasons, ['operation_recovery_hold'])
  await assert.rejects(
    () => environment.launcher.runSyntheticBootstrapDryRun(),
    (error) => error instanceof D9LauncherError && error.code === 'LAUNCHER_RECOVERY_REQUIRED',
  )
})

test('a protected-state crash remains detectable and cannot be hidden as a synthetic no-effect result', async (t) => {
  const environment = await createEnvironment(t, {
    brokerCrashOperationCode: 'begin_synthetic_dry_run',
  })
  await environment.launcher.start()
  await assert.rejects(
    () => environment.launcher.runSyntheticBootstrapDryRun(),
    (error) => error.code === 'STATE_BROKER_RECOVERY_REQUIRED',
  )
  const reopened = openProtectedStateStore({
    rootPath: environment.stateRoot,
    expectedUid: 61018,
    trustedIdentityBindingsRecord: environment.verifiedGeneration.identityBindings,
  })
  assert.equal(reopened.inspect().recoveryRequired, true)
  assert.deepEqual(reopened.inspect().recoveryReasons, ['unfinished_operation'])
})
