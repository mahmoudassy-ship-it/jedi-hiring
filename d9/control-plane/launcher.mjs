import fs from 'node:fs'
import path from 'node:path'
import { verifyControlPlaneBuild } from './build-integrity.mjs'
import { canonicalize, sha256Bytes } from './canonical.mjs'
import {
  validateBootstrapPermitSemantics,
  validateBundleSealSemantics,
  validateCollectorHandoffSemantics,
} from './ceremony-semantics.mjs'
import {
  assertApprovedContractSet,
  assertVerifiedApprovedRecord,
  assertVerifiedRuntimeGeneration,
  loadApprovedContractSet,
  validateApprovedRecord,
  verifyRuntimeGeneration,
} from './contracts.mjs'
import { verifyEmptyCanonicalState } from './empty-state.mjs'
import { resolvePeerBinding } from './identity.mjs'
import { assertLinuxEnforcement } from './platform.mjs'
import {
  deriveHandleScope,
  syntheticBootstrapFirstAcceptanceFacts,
  syntheticVerifiedOperationFactSets,
  verifyIssuedHandleGrants,
} from './scopes.mjs'
import { assertProtectedStateAppendBroker } from './state-append-broker.mjs'
import { assertProtectedStateStore } from './state-store.mjs'

const HASH_PATTERN = /^[0-9a-f]{64}$/u
const CODE_PATTERN = /^[a-z0-9][a-z0-9._-]{1,94}[a-z0-9]$/u
const TIMESTAMP_PATTERN = /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u
const TEST_ATTESTOR_KIND = 'synthetic_d9_1_peer_attestor'
const TEST_PROBE_KIND = 'synthetic_d9_2_no_effect_probe'
const TEST_ROSTER_VERIFIER_KIND = 'synthetic_d9_2_bootstrap_roster_verifier'
const DRY_RUN_REQUEST_DIGEST = sha256Bytes(Buffer.from('jedi-atlas:d9.1:synthetic-no-effect', 'utf8'))

const syntheticPeerAttestors = new WeakSet()
const syntheticNoEffectProbes = new WeakSet()
const syntheticBootstrapRosterVerifiers = new WeakSet()

export class D9LauncherError extends Error {
  constructor(code, message, options) {
    super(`${code}: ${message}`, options)
    this.name = 'D9LauncherError'
    this.code = code
  }
}

function fail(code, message, options) {
  throw new D9LauncherError(code, message, options)
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('LAUNCHER_INPUT_INVALID', `${label} must be an object`)
  }
  const actual = Object.keys(value).toSorted()
  const wanted = [...expected].toSorted()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail('LAUNCHER_INPUT_INVALID', `${label} has unknown or missing fields`)
  }
}

function noArguments(args, label) {
  if (args.length !== 0) fail('LAUNCHER_INPUT_INVALID', `${label} accepts no caller fields`)
}

function timestamp(value, label) {
  if (
    typeof value !== 'string'
    || !TIMESTAMP_PATTERN.test(value)
    || Number.isNaN(Date.parse(value))
    || new Date(value).toISOString() !== value
  ) fail('LAUNCHER_CLOCK_INVALID', `${label} is not a canonical UTC timestamp`)
  return value
}

function stableCode(value, label) {
  if (typeof value !== 'string' || !CODE_PATTERN.test(value)) fail('LAUNCHER_GENERATOR_INVALID', `${label} is not a stable code`)
  return value
}

function sha256(value, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) fail('LAUNCHER_GENERATOR_INVALID', `${label} is not lowercase SHA-256 hex`)
  return value
}

function absolutePath(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    fail('LAUNCHER_CONFIGURATION_INVALID', `${label} must be an absolute NUL-free path`)
  }
  return path.resolve(value)
}

function protectedRegularFile(value, label) {
  const filePath = absolutePath(value, label)
  const stat = fs.lstatSync(filePath)
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail('LAUNCHER_CONFIGURATION_INVALID', `${label} must be a regular non-symlink file`)
  }
  return filePath
}

function readProtectedRegularBytes(filePath, label) {
  let descriptor
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_CLOEXEC | (fs.constants.O_NOFOLLOW ?? 0),
    )
  } catch (error) {
    fail('LAUNCHER_CONFIGURATION_INVALID', `${label} could not be opened without following symlinks`, { cause: error })
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true })
    if (!before.isFile()) fail('LAUNCHER_CONFIGURATION_INVALID', `${label} is not a regular file`)
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor, { bigint: true })
    const current = fs.lstatSync(filePath, { bigint: true })
    if (
      current.isSymbolicLink()
      || !current.isFile()
      || before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || after.dev !== current.dev
      || after.ino !== current.ino
    ) fail('LAUNCHER_CONFIGURATION_INVALID', `${label} changed identity or content while it was read`)
    return bytes
  } finally {
    fs.closeSync(descriptor)
  }
}

function relativeLeaf(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(value) || value === '.' || value === '..') {
    fail('LAUNCHER_CONFIGURATION_INVALID', `${label} must be one safe relative leaf`)
  }
  return value
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

async function withDeadline(promise, timeoutMs, label) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new D9LauncherError('LAUNCHER_OPERATION_TIMEOUT', `${label} exceeded the frozen operation timeout`)), timeoutMs)
        timer.unref?.()
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

function bindingByRole(verifiedGeneration, role) {
  const matches = verifiedGeneration.identityBindings.bindings.filter((binding) => binding.runtime_role_code === role)
  if (matches.length !== 1) fail('LAUNCHER_BINDING_MISSING', `verified generation has ${matches.length} bindings for ${role}`)
  return matches[0]
}

function releaseByRole(verifiedGeneration, role) {
  const matches = verifiedGeneration.runtimeProfile.component_releases.filter((release) => release.runtime_role_code === role)
  if (matches.length !== 1) fail('LAUNCHER_RELEASE_MISSING', `verified generation has ${matches.length} releases for ${role}`)
  return matches[0]
}

function assertLinkedGeneration(record, verifiedGeneration) {
  if (
    record.runtime_profile_record_digest_sha256 !== verifiedGeneration.runtimeProfile.record_digest_sha256
    || record.identity_bindings_record_digest_sha256 !== verifiedGeneration.identityBindings.record_digest_sha256
  ) fail('LAUNCHER_GENERATION_SUBSTITUTION', 'record does not bind the exact active runtime and identity generation')
}

function sameStateReference(left, right) {
  return left.state_seal_code === right.record_code
    && left.state_seal_record_digest_sha256 === right.record_digest_sha256
    && left.logical_state_sha256 === right.logical_state_sha256
}

function sealApprovedRecord(unsignedRecord) {
  const record = structuredClone(unsignedRecord)
  record.record_digest_sha256 = sha256Bytes(Buffer.from(canonicalize(record), 'utf8'))
  return record
}

function bootstrapClaimTransition({ permit, operationId, persistedAt, launcherBindingCode }) {
  return sealApprovedRecord({
    format: 'jedi-atlas-bootstrap-control',
    format_version: '1.0.0',
    record_kind_code: 'permit_transition',
    record_code: `synthetic.claim-${permit.record_digest_sha256.slice(0, 24)}`,
    permit_kind_code: 'bootstrap',
    permit_code: permit.permit_code,
    permit_issuance_record_digest_sha256: permit.record_digest_sha256,
    transition_sequence: 1,
    previous_transition_record_digest_sha256: null,
    from_state_code: 'ready',
    to_state_code: 'in_progress',
    transition_code: 'operation_claimed',
    operation_id: operationId,
    operation_nonce: permit.operation_nonce,
    observed_logical_state: permit.target_empty_logical_state,
    recovery_permit_record_digest_sha256: null,
    completion_journal_head_record_digest_sha256: null,
    recorded_by_runtime_role_code: 'trusted_launcher',
    recorded_by_binding_code: launcherBindingCode,
    persisted_by_binding_code: launcherBindingCode,
    occurred_at: persistedAt,
    persisted_at: persistedAt,
    reason_code: 'operation_claimed',
  })
}

function bootstrapSyntheticRecoveryTransition({ claim, persistedAt, launcherBindingCode, observedLogicalState }) {
  return sealApprovedRecord({
    format: 'jedi-atlas-bootstrap-control',
    format_version: '1.0.0',
    record_kind_code: 'permit_transition',
    record_code: `synthetic.recovery-${claim.record_digest_sha256.slice(0, 24)}`,
    permit_kind_code: 'bootstrap',
    permit_code: claim.permit_code,
    permit_issuance_record_digest_sha256: claim.permit_issuance_record_digest_sha256,
    transition_sequence: 2,
    previous_transition_record_digest_sha256: claim.record_digest_sha256,
    from_state_code: 'in_progress',
    to_state_code: 'recovery_required',
    transition_code: 'state_ambiguous',
    operation_id: claim.operation_id,
    operation_nonce: claim.operation_nonce,
    observed_logical_state: observedLogicalState,
    recovery_permit_record_digest_sha256: null,
    completion_journal_head_record_digest_sha256: null,
    recorded_by_runtime_role_code: 'trusted_launcher',
    recorded_by_binding_code: launcherBindingCode,
    persisted_by_binding_code: launcherBindingCode,
    occurred_at: persistedAt,
    persisted_at: persistedAt,
    reason_code: 'state_ambiguous',
  })
}

/**
 * D9.1 deliberately exposes only its synthetic no-effect integration profile.
 * This test adapter still exercises the real Linux SOCK_SEQPACKET/SO_PEERCRED,
 * executable-inode, pidfd, SCM_RIGHTS, and receiver-termination boundary. It
 * does not stand in for the later long-running operational IPC listener.
 */
export function createSyntheticPeerAttestor({
  descriptorLeaf,
  descriptorRootPath,
  mutatePeer = undefined,
  platform,
  verifiedGeneration,
} = {}) {
  assertVerifiedRuntimeGeneration(verifiedGeneration)
  try { assertLinuxEnforcement(platform) } catch (error) {
    fail('PLATFORM_CONTROL_UNAVAILABLE', 'synthetic peer attestation requires verified Linux enforcement', { cause: error })
  }
  if (mutatePeer !== undefined && typeof mutatePeer !== 'function') {
    fail('LAUNCHER_CONFIGURATION_INVALID', 'mutatePeer must be a test function when supplied')
  }
  const attestor = Object.freeze({
    kindCode: TEST_ATTESTOR_KIND,
    syntheticTestDouble: true,
    async attest({ descriptorGrants = undefined, expectedRuntimeRoleCode, requestDigestSha256 }) {
      const binding = bindingByRole(verifiedGeneration, expectedRuntimeRoleCode)
      const syntheticEndpointCode = binding.ipc_endpoint_code
        ?? `ipc.synthetic-${expectedRuntimeRoleCode.replaceAll('_', '-')}`
      const result = await platform.runSyntheticPeerExchange({
        descriptorGrants: descriptorGrants ?? [{
          access_code: 'attestation_only',
          runtime_role_code: expectedRuntimeRoleCode,
          slot_code: 'synthetic_attestation',
        }],
        expectedEndpointCode: syntheticEndpointCode,
        expectedPeerGid: binding.unix_uid,
        expectedPeerUid: binding.unix_uid,
        relativePath: descriptorLeaf,
        requestDigestSha256,
        rootPath: descriptorRootPath,
        syntheticPeerGid: binding.unix_uid,
        syntheticPeerUid: binding.unix_uid,
      })
      if (result.status !== 'ok' || result.descriptor_metadata_verified !== true || result.termination_confirmed !== true) {
        fail('PEER_ATTESTATION_FAILED', 'native synthetic peer was not authenticated and terminated', { cause: result })
      }
      const peer = {
        pid: result.peer_pid,
        uid: result.peer_uid,
        gid: result.peer_gid,
        executableSha256: binding.principal_kind_code === 'service' ? platform.executableSha256 : null,
        ipcEndpointCode: binding.principal_kind_code === 'service' ? result.authenticatedEndpointCode : null,
      }
      return mutatePeer ? mutatePeer(structuredClone(peer), expectedRuntimeRoleCode, requestDigestSha256) : peer
    },
  })
  syntheticPeerAttestors.add(attestor)
  return attestor
}

export function createSyntheticNoEffectProbe({ run } = {}) {
  if (typeof run !== 'function') fail('LAUNCHER_CONFIGURATION_INVALID', 'synthetic no-effect probe requires run')
  const probe = Object.freeze({ kindCode: TEST_PROBE_KIND, syntheticTestDouble: true, run })
  syntheticNoEffectProbes.add(probe)
  return probe
}

/**
 * Explicit D9.2 test double. It proves that D9.1 gates its disposable permit
 * exercise on a roster-verification result without implementing manifest I/O,
 * roster derivation, accepted-bundle projection, or a database writer.
 */
export function createSyntheticBootstrapRosterVerifier({ verify } = {}) {
  if (typeof verify !== 'function') fail('LAUNCHER_CONFIGURATION_INVALID', 'synthetic bootstrap roster verifier requires verify')
  const verifier = Object.freeze({
    kindCode: TEST_ROSTER_VERIFIER_KIND,
    syntheticTestDouble: true,
    verify,
  })
  syntheticBootstrapRosterVerifiers.add(verifier)
  return verifier
}

class TrustedLauncher {
  #configuration
  #contractSet
  #controlPlaneBuild
  #expectedStateSeal
  #launcherBinding
  #nonceSource
  #operationIdSource
  #peerAttestor
  #platform
  #protectedStateStore
  #scopeAudit = null
  #stateAppendBroker
  #started = false
  #syntheticBootstrapPermits = new Map()
  #syntheticBootstrapRosterVerifier
  #syntheticNoEffectProbe
  #timeSource
  #verifiedGeneration
  #runtimeVerification
  #recoveryHold = false

  constructor(dependencies) {
    exactKeys(dependencies, [
      'configuration',
      'contractSet',
      'nonceSource',
      'operationIdSource',
      'peerAttestor',
      'platform',
      'protectedStateStore',
      'runtimeVerification',
      'stateAppendBroker',
      'syntheticBootstrapRosterVerifier',
      'syntheticNoEffectProbe',
      'timeSource',
      'verifiedGeneration',
    ], 'trusted launcher dependencies')
    assertApprovedContractSet(dependencies.contractSet)
    assertVerifiedRuntimeGeneration(dependencies.verifiedGeneration)
    try { assertLinuxEnforcement(dependencies.platform) } catch (error) {
      fail('PLATFORM_CONTROL_UNAVAILABLE', 'launcher requires the verified Linux enforcement implementation', { cause: error })
    }
    try { assertProtectedStateStore(dependencies.protectedStateStore) } catch (error) {
      fail('LAUNCHER_CONFIGURATION_INVALID', 'launcher requires a protected-state read projector', { cause: error })
    }
    try { assertProtectedStateAppendBroker(dependencies.stateAppendBroker) } catch (error) {
      fail('LAUNCHER_CONFIGURATION_INVALID', 'launcher requires the dedicated-UID fixed-function append worker', { cause: error })
    }
    if (!syntheticPeerAttestors.has(dependencies.peerAttestor) || dependencies.peerAttestor.kindCode !== TEST_ATTESTOR_KIND || dependencies.peerAttestor.syntheticTestDouble !== true || typeof dependencies.peerAttestor.attest !== 'function') {
      fail('LAUNCHER_CONFIGURATION_INVALID', 'D9.1 accepts only its explicit synthetic peer attestor test double')
    }
    if (!syntheticNoEffectProbes.has(dependencies.syntheticNoEffectProbe) || dependencies.syntheticNoEffectProbe.kindCode !== TEST_PROBE_KIND || dependencies.syntheticNoEffectProbe.syntheticTestDouble !== true || typeof dependencies.syntheticNoEffectProbe.run !== 'function') {
      fail('LAUNCHER_CONFIGURATION_INVALID', 'D9.1 accepts only its explicit synthetic D9.2 no-effect probe')
    }
    if (!syntheticBootstrapRosterVerifiers.has(dependencies.syntheticBootstrapRosterVerifier) || dependencies.syntheticBootstrapRosterVerifier.kindCode !== TEST_ROSTER_VERIFIER_KIND || dependencies.syntheticBootstrapRosterVerifier.syntheticTestDouble !== true || typeof dependencies.syntheticBootstrapRosterVerifier.verify !== 'function') {
      fail('LAUNCHER_CONFIGURATION_INVALID', 'D9.1 accepts only its explicit synthetic D9.2 bootstrap-roster verifier')
    }
    if (typeof dependencies.timeSource !== 'function' || typeof dependencies.nonceSource !== 'function' || typeof dependencies.operationIdSource !== 'function') {
      fail('LAUNCHER_CONFIGURATION_INVALID', 'launcher time, nonce, and operation ID sources are required')
    }

    exactKeys(dependencies.runtimeVerification, [
      'componentFiles',
      'controlPlaneBuildManifestPath',
      'evidenceBundleSchemaPath',
      'identityBindingsPath',
      'migrationsDirectory',
      'operationalProfileFiles',
      'runtimeDomainFile',
      'runtimeProfilePath',
      'scannerFiles',
    ], 'runtime verification inputs')
    for (const method of ['inspect', 'selectActiveGenerationPair', 'selectGenerationPairForActiveOperation', 'resolveFixedRecord', 'resolveBootstrapBundleSealForPermit', 'resolvePermit', 'resolvePermitForActiveOperation']) {
      if (typeof dependencies.protectedStateStore?.[method] !== 'function') {
        fail('LAUNCHER_CONFIGURATION_INVALID', `protected state projector lacks ${method}`)
      }
    }

    exactKeys(dependencies.configuration, [
      'databasePath',
      'expectedEmptyStateSeal',
      'operationLockLeaf',
      'operationLockRootPath',
      'projectRoot',
      'syntheticControlPlaneOnly',
    ], 'trusted launcher configuration')
    if (dependencies.configuration.syntheticControlPlaneOnly !== true) {
      fail('LAUNCHER_OPERATION_UNAVAILABLE', 'D9.1 is limited to the synthetic control-plane no-effect profile')
    }
    assertVerifiedApprovedRecord(dependencies.configuration.expectedEmptyStateSeal, {
      contractSet: dependencies.contractSet,
      schemaFile: 'logical-state-seal-v1.schema.json',
    })

    this.#contractSet = dependencies.contractSet
    this.#verifiedGeneration = dependencies.verifiedGeneration
    this.#platform = dependencies.platform
    this.#protectedStateStore = dependencies.protectedStateStore
    this.#stateAppendBroker = dependencies.stateAppendBroker
    this.#peerAttestor = dependencies.peerAttestor
    this.#syntheticBootstrapRosterVerifier = dependencies.syntheticBootstrapRosterVerifier
    this.#syntheticNoEffectProbe = dependencies.syntheticNoEffectProbe
    this.#timeSource = dependencies.timeSource
    this.#nonceSource = dependencies.nonceSource
    this.#operationIdSource = dependencies.operationIdSource
    this.#expectedStateSeal = dependencies.configuration.expectedEmptyStateSeal
    this.#runtimeVerification = deepFreeze({
      componentFiles: structuredClone(dependencies.runtimeVerification.componentFiles),
      controlPlaneBuildManifestPath: protectedRegularFile(dependencies.runtimeVerification.controlPlaneBuildManifestPath, 'controlPlaneBuildManifestPath'),
      evidenceBundleSchemaPath: protectedRegularFile(dependencies.runtimeVerification.evidenceBundleSchemaPath, 'evidenceBundleSchemaPath'),
      identityBindingsPath: protectedRegularFile(dependencies.runtimeVerification.identityBindingsPath, 'identityBindingsPath'),
      migrationsDirectory: absolutePath(dependencies.runtimeVerification.migrationsDirectory, 'migrationsDirectory'),
      operationalProfileFiles: structuredClone(dependencies.runtimeVerification.operationalProfileFiles),
      runtimeDomainFile: protectedRegularFile(dependencies.runtimeVerification.runtimeDomainFile, 'runtimeDomainFile'),
      runtimeProfilePath: protectedRegularFile(dependencies.runtimeVerification.runtimeProfilePath, 'runtimeProfilePath'),
      scannerFiles: structuredClone(dependencies.runtimeVerification.scannerFiles),
    })
    this.#configuration = Object.freeze({
      databasePath: absolutePath(dependencies.configuration.databasePath, 'databasePath'),
      operationLockLeaf: relativeLeaf(dependencies.configuration.operationLockLeaf, 'operationLockLeaf'),
      operationLockRootPath: absolutePath(dependencies.configuration.operationLockRootPath, 'operationLockRootPath'),
      projectRoot: absolutePath(dependencies.configuration.projectRoot, 'projectRoot'),
      syntheticControlPlaneOnly: true,
    })
    this.#controlPlaneBuild = verifyControlPlaneBuild({
      manifestPath: this.#runtimeVerification.controlPlaneBuildManifestPath,
      projectRoot: this.#configuration.projectRoot,
      verifiedGeneration: this.#verifiedGeneration,
    })
  }

  #now(label) {
    return timestamp(this.#timeSource(), label)
  }

  #assertStarted() {
    if (!this.#started) fail('LAUNCHER_NOT_STARTED', 'launcher startup has not completed')
    if (this.#recoveryHold) fail('LAUNCHER_RECOVERY_REQUIRED', 'launcher is in a fail-closed recovery hold')
  }

  #revalidateGeneration(asOf) {
    const observedContractSet = loadApprovedContractSet({ contractRoot: this.#contractSet.contractRoot })
    const observed = verifyRuntimeGeneration({
      contractSet: observedContractSet,
      runtimeProfileBytes: readProtectedRegularBytes(this.#runtimeVerification.runtimeProfilePath, 'runtimeProfilePath'),
      identityBindingsBytes: readProtectedRegularBytes(this.#runtimeVerification.identityBindingsPath, 'identityBindingsPath'),
      selection: this.#verifiedGeneration.selection,
      asOf,
      migrationsDirectory: this.#runtimeVerification.migrationsDirectory,
      evidenceBundleSchemaPath: this.#runtimeVerification.evidenceBundleSchemaPath,
      componentFiles: this.#runtimeVerification.componentFiles,
      runtimeDomainFile: this.#runtimeVerification.runtimeDomainFile,
      operationalProfileFiles: this.#runtimeVerification.operationalProfileFiles,
      scannerFiles: this.#runtimeVerification.scannerFiles,
    })
    if (canonicalize(observed.selection) !== canonicalize(this.#verifiedGeneration.selection)) {
      fail('LAUNCHER_GENERATION_SUBSTITUTION', 'reverified runtime generation differs from the protected selection')
    }
    const observedBuild = verifyControlPlaneBuild({
      manifestPath: this.#runtimeVerification.controlPlaneBuildManifestPath,
      projectRoot: this.#configuration.projectRoot,
      verifiedGeneration: observed,
    })
    if (observedBuild.manifestFileSha256 !== this.#controlPlaneBuild.manifestFileSha256 ||
        observedBuild.manifestDigestSha256 !== this.#controlPlaneBuild.manifestDigestSha256) {
      fail('LAUNCHER_GENERATION_SUBSTITUTION', 'control-plane build differs from the selected generation')
    }
    return observed
  }

  #assertActive(asOf, activeOperation = null) {
    this.#revalidateGeneration(asOf)
    const selection = this.#verifiedGeneration.selection
    const pair = activeOperation === null
      ? this.#protectedStateStore.selectActiveGenerationPair({
        asOf,
        runtimeProfileRecordDigestSha256: selection.runtime_profile_record_digest_sha256,
        identityBindingsRecordDigestSha256: selection.identity_bindings_record_digest_sha256,
      })
      : this.#protectedStateStore.selectGenerationPairForActiveOperation({
        asOf,
        operationId: activeOperation.operationId,
        operationNonce: activeOperation.operationNonce,
        runtimeProfileRecordDigestSha256: selection.runtime_profile_record_digest_sha256,
        identityBindingsRecordDigestSha256: selection.identity_bindings_record_digest_sha256,
      })
    if (
      pair.runtime_profile.generation_number !== selection.profile_generation
      || pair.runtime_profile.generation_code !== selection.profile_code
      || pair.runtime_profile.record_digest_sha256 !== selection.runtime_profile_record_digest_sha256
      || pair.identity_bindings.generation_number !== selection.binding_generation
      || pair.identity_bindings.generation_code !== selection.binding_set_code
      || pair.identity_bindings.record_digest_sha256 !== selection.identity_bindings_record_digest_sha256
      || pair.identity_bindings.bound_runtime_profile_record_digest_sha256 !== selection.runtime_profile_record_digest_sha256
      || canonicalize(pair.identity_bindings_record) !== canonicalize(this.#verifiedGeneration.identityBindings)
    ) fail('LAUNCHER_GENERATION_SUBSTITUTION', 'protected active pair identity differs from the verified generation')
    return pair
  }

  #assertPermitAuthority(asOf, operationContext) {
    this.#assertActive(asOf, {
      operationId: operationContext.operation_id,
      operationNonce: operationContext.operation_nonce,
    })
    const selection = this.#verifiedGeneration.selection
    return this.#protectedStateStore.resolvePermitForActiveOperation({
      asOf,
      operationId: operationContext.operation_id,
      operationNonce: operationContext.operation_nonce,
      permitCode: operationContext.permit_code,
      permitRecordDigestSha256: operationContext.permit_record_digest_sha256,
      permitClaimRecordDigestSha256: operationContext.permit_claim_record_digest_sha256,
      runtimeProfileRecordDigestSha256: selection.runtime_profile_record_digest_sha256,
      identityBindingsRecordDigestSha256: selection.identity_bindings_record_digest_sha256,
    })
  }

  async #authenticatePeer(expectedRuntimeRoleCode, operationModeCode, asOf, requestDigestSha256, descriptorGrants = undefined) {
    sha256(requestDigestSha256, 'authenticated request digest')
    const peer = await this.#peerAttestor.attest(Object.freeze({
      expectedRuntimeRoleCode,
      operationModeCode,
      requestDigestSha256,
      descriptorGrants,
    }))
    return resolvePeerBinding({
      verifiedGeneration: this.#verifiedGeneration,
      operationModeCode,
      expectedRuntimeRoleCode,
      peer,
      asOf,
    })
  }

  async #authenticate(expectedRuntimeRoleCode, operationModeCode, asOf, requestDigestSha256) {
    return this.#authenticatePeer(expectedRuntimeRoleCode, operationModeCode, asOf, requestDigestSha256)
  }

  #verifyStateAppendBroker() {
    const attestation = this.#stateAppendBroker.attestation()
    exactKeys(attestation, [
      'brokerBindingCode',
      'brokerGid',
      'brokerPid',
      'brokerUid',
      'identityBindingsRecordDigestSha256',
      'nodeExecutableSha256',
      'runtimeProfileRecordDigestSha256',
      'syntheticPrivatePipeHarness',
    ], 'state append worker attestation')
    const binding = bindingByRole(this.#verifiedGeneration, 'trusted_launcher')
    const release = releaseByRole(this.#verifiedGeneration, 'trusted_launcher')
    if (
      attestation.syntheticPrivatePipeHarness !== true
      || !Number.isSafeInteger(attestation.brokerPid)
      || attestation.brokerPid < 1
      || attestation.brokerUid !== binding.unix_uid
      || attestation.brokerGid !== binding.unix_uid
      || attestation.brokerBindingCode !== binding.binding_code
      || attestation.nodeExecutableSha256 !== binding.executable_sha256
      || attestation.nodeExecutableSha256 !== release.executable_sha256
      || attestation.runtimeProfileRecordDigestSha256 !== this.#verifiedGeneration.runtimeProfile.record_digest_sha256
      || attestation.identityBindingsRecordDigestSha256 !== this.#verifiedGeneration.identityBindings.record_digest_sha256
    ) fail('LAUNCHER_APPEND_BROKER_SUBSTITUTION', 'state append worker differs from the selected trusted-launcher build, identity, or generation')
    return Object.freeze({
      atlasPrincipalCode: binding.atlas_principal_code,
      bindingCode: binding.binding_code,
      gid: attestation.brokerGid,
      pid: attestation.brokerPid,
      principalKindCode: binding.principal_kind_code,
      runtimeRoleCode: binding.runtime_role_code,
      uid: attestation.brokerUid,
    })
  }

  #verifyEmpty() {
    return verifyEmptyCanonicalState({
      databasePath: this.#configuration.databasePath,
      projectRoot: this.#configuration.projectRoot,
      runtimeProfile: this.#verifiedGeneration.runtimeProfile,
      digestProfiles: this.#contractSet.digestProfiles,
      expectedStateSeal: this.#expectedStateSeal,
    })
  }

  #auditAllScopes() {
    const factSets = syntheticVerifiedOperationFactSets({ contractSet: this.#contractSet })
    const summaries = factSets.map((verifiedFacts) => {
      const scope = deriveHandleScope({ contractSet: this.#contractSet, verifiedFacts })
      verifyIssuedHandleGrants({ contractSet: this.#contractSet, scope, issuedGrants: scope.required_handle_grants })
      return {
        operationScopeCode: scope.operation_scope_code,
        requiredGrantCount: scope.required_handle_grants.length,
        forbiddenGrantCount: scope.forbidden_handle_grants.length,
      }
    })
    if (summaries.length !== 7) fail('LAUNCHER_SCOPE_AUDIT_FAILED', 'D9.0.1 must define exactly seven execution partitions')
    return deepFreeze(summaries)
  }

  async #deliverSyntheticScope({ operationContext, scope, verifiedFacts }) {
    const grants = verifyIssuedHandleGrants({
      contractSet: this.#contractSet,
      scope,
      issuedGrants: structuredClone(scope.required_handle_grants),
    })
    const grantsByRole = new Map()
    for (const grant of grants) {
      const group = grantsByRole.get(grant.runtime_role_code) ?? []
      group.push(grant)
      grantsByRole.set(grant.runtime_role_code, group)
    }
    let deliveredGrantCount = 0
    let receiverCount = 0
    let stateAppendBrokerGrantCount = 0
    for (const [runtimeRoleCode, roleGrants] of grantsByRole) {
      const deliveryAt = this.#now('synthetic handle delivery time')
      if (operationContext === null) this.#assertActive(deliveryAt)
      else this.#assertPermitAuthority(deliveryAt, operationContext)
      if (runtimeRoleCode === 'trusted_launcher') {
        this.#verifyStateAppendBroker()
        stateAppendBrokerGrantCount += roleGrants.length
        continue
      }
      const requestDigestSha256 = sha256Bytes(Buffer.from(canonicalize({
        format: 'jedi-atlas-d91-synthetic-handle-delivery',
        format_version: '1.0.0',
        operation_context: operationContext,
        operation_scope_code: scope.operation_scope_code,
        recipient_runtime_role_code: runtimeRoleCode,
        grants: roleGrants,
        verified_facts: verifiedFacts,
      }), 'utf8'))
      const receiver = await this.#authenticatePeer(
        runtimeRoleCode,
        verifiedFacts.operation_mode_code,
        deliveryAt,
        requestDigestSha256,
        roleGrants,
      )
      if (receiver.runtimeRoleCode !== runtimeRoleCode) {
        fail('LAUNCHER_HANDLE_RECIPIENT_MISMATCH', 'synthetic descriptor reached an unexpected runtime role')
      }
      deliveredGrantCount += roleGrants.length
      receiverCount += 1
    }
    return deepFreeze({
      operationScopeCode: scope.operation_scope_code,
      verifiedGrantCount: grants.length,
      descriptorDeliveredGrantCount: deliveredGrantCount,
      receiverTerminationCount: receiverCount,
      stateAppendBrokerGrantCount,
    })
  }

  async runSyntheticHandleDeliveryAudit(...args) {
    noArguments(args, 'runSyntheticHandleDeliveryAudit')
    this.#assertStarted()
    const scopes = syntheticVerifiedOperationFactSets({ contractSet: this.#contractSet }).map((verifiedFacts) => ({
      verifiedFacts,
      scope: deriveHandleScope({ contractSet: this.#contractSet, verifiedFacts }),
    }))
    const summaries = []
    for (const { verifiedFacts, scope } of scopes) {
      summaries.push(await this.#deliverSyntheticScope({ operationContext: null, scope, verifiedFacts }))
    }
    return deepFreeze({
      syntheticTestDouble: true,
      scopeCount: summaries.length,
      verifiedGrantCount: summaries.reduce((total, summary) => total + summary.verifiedGrantCount, 0),
      deliveredGrantCount: summaries.reduce((total, summary) => total + summary.descriptorDeliveredGrantCount, 0),
      receiverTerminationCount: summaries.reduce((total, summary) => total + summary.receiverTerminationCount, 0),
      stateAppendBrokerGrantCount: summaries.reduce((total, summary) => total + summary.stateAppendBrokerGrantCount, 0),
      stateAppendBrokerScopeCount: summaries.filter((summary) => summary.stateAppendBrokerGrantCount > 0).length,
      summaries,
    })
  }

  async start(...args) {
    noArguments(args, 'start')
    if (this.#started) fail('LAUNCHER_ALREADY_STARTED', 'launcher startup cannot be repeated')
    this.#platform.probe()
    const asOf = this.#now('launcher startup time')
    const inspection = this.#protectedStateStore.inspect()
    if (inspection.recoveryRequired || inspection.activeOperation !== null) {
      fail('LAUNCHER_RECOVERY_REQUIRED', 'protected state requires recovery before startup')
    }
    this.#assertActive(asOf)
    this.#launcherBinding = this.#verifyStateAppendBroker()
    const boundaryAt = this.#now('launcher startup boundary time')
    this.#assertActive(boundaryAt)
    const emptyState = this.#verifyEmpty()
    this.#scopeAudit = this.#auditAllScopes()
    this.#started = true
    return deepFreeze({
      syntheticControlPlaneOnly: true,
      activeProfileGeneration: this.#verifiedGeneration.selection.profile_generation,
      activeBindingGeneration: this.#verifiedGeneration.selection.binding_generation,
      scopePartitionCount: this.#scopeAudit.length,
      atlasTableCount: emptyState.atlasTableCount,
      logicalStateSha256: emptyState.logicalStateSha256,
    })
  }

  scopeAudit(...args) {
    noArguments(args, 'scopeAudit')
    this.#assertStarted()
    return this.#scopeAudit
  }

  #approvedRecord(recordBytes, schemaFile) {
    if (!Buffer.isBuffer(recordBytes) && !(recordBytes instanceof Uint8Array)) {
      fail('LAUNCHER_INPUT_INVALID', 'protected record input must be exact bytes')
    }
    return validateApprovedRecord({ contractSet: this.#contractSet, schemaFile, recordBytes })
  }

  async registerCollectorHandoff(recordBytes, ...extra) {
    if (extra.length) fail('LAUNCHER_INPUT_INVALID', 'registerCollectorHandoff accepts only exact record bytes')
    this.#assertStarted()
    const record = this.#approvedRecord(recordBytes, 'collector-handoff-v1.schema.json')
    const requestDigestSha256 = sha256Bytes(Buffer.from(recordBytes))
    if (record.record_kind_code !== 'collector_handoff') fail('LAUNCHER_RECORD_KIND_INVALID', 'record is not a collector handoff')
    assertLinkedGeneration(record, this.#verifiedGeneration)
    validateCollectorHandoffSemantics({
      contractSet: this.#contractSet,
      verifiedGeneration: this.#verifiedGeneration,
      collectorHandoff: record,
    })
    const authenticationAt = this.#now('handoff authentication time')
    this.#assertActive(authenticationAt)
    const broker = await this.#authenticate('handoff_broker', 'document_import', authenticationAt, requestDigestSha256)
    const collector = bindingByRole(this.#verifiedGeneration, 'collector')
    const collectorRelease = releaseByRole(this.#verifiedGeneration, 'collector')
    if (
      record.handoff_broker_binding_code !== broker.bindingCode
      || record.collector_binding_code !== collector.binding_code
      || record.collector_principal_code !== collector.atlas_principal_code
      || record.collector_build_sha256 !== collectorRelease.executable_sha256
    ) fail('LAUNCHER_HANDOFF_SUBSTITUTION', 'collector handoff differs from the verified broker, collector, principal, or release')
    const recordedAt = this.#now('handoff persistence time')
    this.#assertActive(recordedAt)
    const result = await this.#stateAppendBroker.registerFixedRecord({
      record,
      recordedAt,
      authenticatedRuntimeRoleCode: 'handoff_broker',
      authenticatedBindingCode: broker.bindingCode,
    })
    return deepFreeze({ ...result, recordCode: record.record_code, recordDigestSha256: record.record_digest_sha256 })
  }

  async registerBundleSeal(recordBytes, ...extra) {
    if (extra.length) fail('LAUNCHER_INPUT_INVALID', 'registerBundleSeal accepts only exact record bytes')
    this.#assertStarted()
    const record = this.#approvedRecord(recordBytes, 'collector-handoff-v1.schema.json')
    const requestDigestSha256 = sha256Bytes(Buffer.from(recordBytes))
    if (record.record_kind_code !== 'bundle_seal') fail('LAUNCHER_RECORD_KIND_INVALID', 'record is not a bundle seal')
    assertLinkedGeneration(record, this.#verifiedGeneration)
    const operationMode = record.bundle_kind_code === 'principal_bootstrap' ? 'bootstrap' : 'document_import'
    const authenticationAt = this.#now('bundle-seal authentication time')
    this.#assertActive(authenticationAt)
    const submitter = await this.#authenticate('human_submitter', operationMode, authenticationAt, requestDigestSha256)
    if (
      record.launcher_binding_code !== this.#launcherBinding.bindingCode
      || record.submitter_binding_code !== submitter.bindingCode
      || record.importer_binding_code !== bindingByRole(this.#verifiedGeneration, 'bundle_importer').binding_code
    ) fail('LAUNCHER_BUNDLE_SEAL_SUBSTITUTION', 'bundle seal differs from verified launcher, submitter, or importer bindings')
    const recordedAt = this.#now('bundle-seal persistence time')
    this.#assertActive(recordedAt)
    const resolvedHandoffs = []
    for (const handoff of record.collector_handoffs) {
      const resolved = this.#protectedStateStore.resolveFixedRecord({
        registryKindCode: 'collector_handoff',
        recordCode: handoff.record_code,
        recordDigestSha256: handoff.record_digest_sha256,
        asOf: recordedAt,
      })
      resolvedHandoffs.push(validateCollectorHandoffSemantics({
        contractSet: this.#contractSet,
        verifiedGeneration: this.#verifiedGeneration,
        collectorHandoff: validateApprovedRecord({
          contractSet: this.#contractSet,
          schemaFile: 'collector-handoff-v1.schema.json',
          record: resolved,
        }),
      }))
    }
    validateBundleSealSemantics({
      contractSet: this.#contractSet,
      verifiedGeneration: this.#verifiedGeneration,
      bundleSeal: record,
      collectorHandoffs: resolvedHandoffs,
    })
    if (record.bundle_kind_code === 'principal_bootstrap' &&
        (!sameStateReference(record.target_logical_state, this.#expectedStateSeal) || this.#expectedStateSeal.produced_at > record.sealed_at)) {
      fail('LAUNCHER_BUNDLE_SEAL_SUBSTITUTION', 'bootstrap bundle seal does not target the verified pre-existing empty state')
    }
    const result = await this.#stateAppendBroker.registerFixedRecord({
      record,
      recordedAt,
      authenticatedRuntimeRoleCode: 'trusted_launcher',
      authenticatedBindingCode: this.#launcherBinding.bindingCode,
    })
    return deepFreeze({ ...result, recordCode: record.record_code, recordDigestSha256: record.record_digest_sha256 })
  }

  async issueBootstrapPermit(recordBytes, ...extra) {
    if (extra.length) fail('LAUNCHER_INPUT_INVALID', 'issueBootstrapPermit accepts only exact record bytes')
    this.#assertStarted()
    const record = this.#approvedRecord(recordBytes, 'bootstrap-control-v1.schema.json')
    const requestDigestSha256 = sha256Bytes(Buffer.from(recordBytes))
    if (record.record_kind_code !== 'permit_issuance' || record.permit_kind_code !== 'bootstrap') {
      fail('LAUNCHER_RECORD_KIND_INVALID', 'record is not a bootstrap permit issuance')
    }
    assertLinkedGeneration(record, this.#verifiedGeneration)
    const authenticationAt = this.#now('bootstrap-permit authentication time')
    this.#assertActive(authenticationAt)
    const authority = await this.#authenticate('bootstrap_authority', 'bootstrap', authenticationAt, requestDigestSha256)
    const submitter = await this.#authenticate('human_submitter', 'bootstrap', authenticationAt, requestDigestSha256)
    const witness = await this.#authenticate('operational_witness', 'bootstrap', authenticationAt, requestDigestSha256)
    if (
      record.issuer_binding_code !== authority.bindingCode
      || record.submitter_binding_code !== submitter.bindingCode
      || record.witness_binding_code !== witness.bindingCode
      || record.importer_binding_code !== bindingByRole(this.#verifiedGeneration, 'bundle_importer').binding_code
      || record.importer_release_sha256 !== releaseByRole(this.#verifiedGeneration, 'bundle_importer').executable_sha256
      || !sameStateReference(record.target_empty_logical_state, this.#expectedStateSeal)
    ) fail('LAUNCHER_PERMIT_SUBSTITUTION', 'bootstrap permit differs from the verified identities, release, or empty-state seal')
    const persistedAt = this.#now('bootstrap-permit persistence time')
    this.#assertActive(persistedAt)
    const bundleSeal = validateApprovedRecord({
      contractSet: this.#contractSet,
      schemaFile: 'collector-handoff-v1.schema.json',
      record: this.#protectedStateStore.resolveBootstrapBundleSealForPermit({ permit: record, asOf: persistedAt }),
    })
    validateBundleSealSemantics({
      contractSet: this.#contractSet,
      verifiedGeneration: this.#verifiedGeneration,
      bundleSeal,
      collectorHandoffs: [],
    })
    validateBootstrapPermitSemantics({
      contractSet: this.#contractSet,
      verifiedGeneration: this.#verifiedGeneration,
      bootstrapPermit: record,
      bootstrapBundleSeals: [bundleSeal],
      emptyLogicalStateSeal: this.#expectedStateSeal,
    })
    const result = await this.#stateAppendBroker.issuePermit({
      record,
      persistedAt,
      authenticatedIssuerRuntimeRoleCode: 'bootstrap_authority',
      authenticatedIssuerBindingCode: authority.bindingCode,
      authenticatedPersistenceBindingCode: this.#launcherBinding.bindingCode,
    })
    this.#syntheticBootstrapPermits.set(record.permit_code, deepFreeze(structuredClone(record)))
    return deepFreeze({
      ...result,
      permitCode: record.permit_code,
      recordDigestSha256: record.record_digest_sha256,
      operationScopeCode: null,
      requiredHandleCount: null,
      claimEligible: false,
      handlesIssued: false,
    })
  }

  /**
   * Disposable D9.1 proof of the frozen permit -> roster gate -> exact scope ->
   * descriptor-delivery boundary. It intentionally cannot produce a spent
   * permit or an accepted result: without D9.2 projection verification it
   * closes the claimed permit and operation as recovery-required.
   */
  async runSyntheticPermitScopedBootstrapAudit(...args) {
    noArguments(args, 'runSyntheticPermitScopedBootstrapAudit')
    this.#assertStarted()
    if (this.#syntheticBootstrapPermits.size !== 1) {
      fail('LAUNCHER_SYNTHETIC_PERMIT_UNAVAILABLE', 'synthetic permit-scope audit requires exactly one permit issued by this launcher instance')
    }
    const issuedPermit = [...this.#syntheticBootstrapPermits.values()][0]
    const verificationAt = this.#now('synthetic bootstrap roster verification time')
    this.#assertActive(verificationAt)
    const resolvedPermit = this.#protectedStateStore.resolvePermit({
      permitCode: issuedPermit.permit_code,
      recordDigestSha256: issuedPermit.record_digest_sha256,
      asOf: verificationAt,
      requiredStateCode: 'ready',
    }).record
    const bundleSeal = validateApprovedRecord({
      contractSet: this.#contractSet,
      schemaFile: 'collector-handoff-v1.schema.json',
      record: this.#protectedStateStore.resolveBootstrapBundleSealForPermit({ permit: resolvedPermit, asOf: verificationAt }),
    })
    validateBundleSealSemantics({
      contractSet: this.#contractSet,
      verifiedGeneration: this.#verifiedGeneration,
      bundleSeal,
      collectorHandoffs: [],
    })
    validateBootstrapPermitSemantics({
      contractSet: this.#contractSet,
      verifiedGeneration: this.#verifiedGeneration,
      bootstrapPermit: validateApprovedRecord({
        contractSet: this.#contractSet,
        schemaFile: 'bootstrap-control-v1.schema.json',
        record: resolvedPermit,
      }),
      bootstrapBundleSeals: [bundleSeal],
      emptyLogicalStateSeal: this.#expectedStateSeal,
    })
    const rosterResult = await withDeadline(this.#syntheticBootstrapRosterVerifier.verify(deepFreeze({
      bundleDigestSha256: resolvedPermit.bootstrap_bundle.bundle_digest_sha256,
      expectedPrincipalRosterSha256: resolvedPermit.expected_principal_roster_sha256,
      manifestPath: resolvedPermit.manifest_path,
      permitCode: resolvedPermit.permit_code,
      reviewedGitCommit: resolvedPermit.reviewed_git_commit,
      syntheticTestDouble: true,
    })), this.#verifiedGeneration.runtimeProfile.limits.operation_timeout_ms, 'synthetic D9.2 roster verifier')
    exactKeys(rosterResult, [
      'bundleDigestSha256',
      'manifestPath',
      'observedPrincipalRosterSha256',
      'permitCode',
      'reviewedGitCommit',
      'syntheticTestDouble',
    ], 'synthetic D9.2 roster result')
    if (
      rosterResult.syntheticTestDouble !== true
      || rosterResult.permitCode !== resolvedPermit.permit_code
      || rosterResult.bundleDigestSha256 !== resolvedPermit.bootstrap_bundle.bundle_digest_sha256
      || rosterResult.manifestPath !== resolvedPermit.manifest_path
      || rosterResult.reviewedGitCommit !== resolvedPermit.reviewed_git_commit
      || rosterResult.observedPrincipalRosterSha256 !== resolvedPermit.expected_principal_roster_sha256
    ) fail('LAUNCHER_SYNTHETIC_ROSTER_MISMATCH', 'synthetic roster result does not bind the exact sealed permit commitment')

    const verifiedFacts = syntheticBootstrapFirstAcceptanceFacts({
      bundleSeal,
      contractSet: this.#contractSet,
      observedPrincipalRosterSha256: rosterResult.observedPrincipalRosterSha256,
      permit: resolvedPermit,
    })
    const scope = deriveHandleScope({ contractSet: this.#contractSet, verifiedFacts })
    const executionRules = this.#contractSet.classification.permit_scope_execution_rules.filter((rule) => (
      rule.permit_kind_code === resolvedPermit.permit_kind_code && rule.scope_code === resolvedPermit.scope_code
    ))
    const requiredSlotCodes = [...new Set(scope.required_handle_grants.map((grant) => grant.slot_code))].toSorted()
    if (
      executionRules.length !== 1
      || canonicalize(executionRules[0].allowed_handle_slot_codes.toSorted()) !== canonicalize(requiredSlotCodes)
    ) fail('LAUNCHER_SCOPE_AUDIT_FAILED', 'permit scope does not authorize the exact derived handle-slot set')

    const nativeLock = await this.#platform.holdOperationLock({
      rootPath: this.#configuration.operationLockRootPath,
      relativePath: this.#configuration.operationLockLeaf,
    })
    const operationId = bundleSeal.operation_id
    const operationNonce = resolvedPermit.operation_nonce
    let nativeReleaseAttempted = false
    let operationBegun = false
    let claimTransition
    try {
      const operationStartedAt = this.#now('synthetic permitted operation start time')
      this.#assertActive(operationStartedAt)
      const before = this.#verifyEmpty()
      claimTransition = validateApprovedRecord({
        contractSet: this.#contractSet,
        schemaFile: 'bootstrap-control-v1.schema.json',
        record: bootstrapClaimTransition({
          permit: resolvedPermit,
          operationId,
          persistedAt: operationStartedAt,
          launcherBindingCode: this.#launcherBinding.bindingCode,
        }),
      })
      await this.#stateAppendBroker.beginSyntheticBootstrapScopeAudit({
        operation: {
          operationId,
          operationNonce,
          operationModeCode: 'bootstrap',
          startedAt: operationStartedAt,
          runtimeProfileRecordDigestSha256: this.#verifiedGeneration.runtimeProfile.record_digest_sha256,
          identityBindingsRecordDigestSha256: this.#verifiedGeneration.identityBindings.record_digest_sha256,
        },
        claimTransition,
        authenticatedLauncherBindingCode: this.#launcherBinding.bindingCode,
      })
      operationBegun = true
      const delivery = await this.#deliverSyntheticScope({
        operationContext: {
          operation_id: operationId,
          operation_nonce: operationNonce,
          permit_code: resolvedPermit.permit_code,
          permit_record_digest_sha256: resolvedPermit.record_digest_sha256,
          permit_claim_record_digest_sha256: claimTransition.record_digest_sha256,
        },
        scope,
        verifiedFacts,
      })
      const after = this.#verifyEmpty()
      if (before.logicalStateSha256 !== after.logicalStateSha256 || before.databaseFileSha256 !== after.databaseFileSha256) {
        fail('LAUNCHER_UNEXPECTED_EFFECT', 'synthetic permit-scope audit changed canonical state')
      }
      nativeReleaseAttempted = true
      await nativeLock.release()
      const completedAt = this.#now('synthetic permitted recovery boundary time')
      this.#revalidateGeneration(completedAt)
      const terminalPermitTransition = validateApprovedRecord({
        contractSet: this.#contractSet,
        schemaFile: 'bootstrap-control-v1.schema.json',
        record: bootstrapSyntheticRecoveryTransition({
          claim: claimTransition,
          persistedAt: completedAt,
          launcherBindingCode: this.#launcherBinding.bindingCode,
          observedLogicalState: resolvedPermit.target_empty_logical_state,
        }),
      })
      await this.#stateAppendBroker.markSyntheticBootstrapScopeRecovery({
        operationId,
        operationNonce,
        recordedAt: completedAt,
        reasonCode: 'synthetic.d9-2-verification-unimplemented',
        lastKnownLogicalStateSha256: after.logicalStateSha256,
        authenticatedLauncherBindingCode: this.#launcherBinding.bindingCode,
        terminalPermitTransition,
      })
      operationBegun = false
      this.#recoveryHold = true
      return deepFreeze({
        acceptedBundleProjectionVerified: false,
        canonicalEffectCode: 'none_observed_not_accepted',
        databaseFileSha256: after.databaseFileSha256,
        descriptorDeliveredGrantCount: delivery.descriptorDeliveredGrantCount,
        issuedHandleCount: delivery.verifiedGrantCount,
        logicalStateSha256: after.logicalStateSha256,
        operationId,
        operationNonce,
        operationScopeCode: scope.operation_scope_code,
        outcomeCode: 'synthetic_scope_exercised_recovery_required',
        permitCode: resolvedPermit.permit_code,
        permitStateCode: 'recovery_required',
        receiverTerminationCount: delivery.receiverTerminationCount,
        realBootstrapExecuted: false,
        stateAppendBrokerGrantCount: delivery.stateAppendBrokerGrantCount,
        syntheticTestDouble: true,
      })
    } catch (error) {
      if (operationBegun) {
        this.#recoveryHold = true
        let causalError = error
        if (!nativeReleaseAttempted) {
          nativeReleaseAttempted = true
          try { await nativeLock.release() } catch (releaseError) { causalError = new AggregateError([error, releaseError]) }
        }
        const failedAt = this.#now('synthetic permitted failure time')
        try {
          const terminalPermitTransition = validateApprovedRecord({
            contractSet: this.#contractSet,
            schemaFile: 'bootstrap-control-v1.schema.json',
            record: bootstrapSyntheticRecoveryTransition({
              claim: claimTransition,
              persistedAt: failedAt,
              launcherBindingCode: this.#launcherBinding.bindingCode,
              observedLogicalState: resolvedPermit.target_empty_logical_state,
            }),
          })
          await this.#stateAppendBroker.markSyntheticBootstrapScopeRecovery({
            operationId,
            operationNonce,
            recordedAt: failedAt,
            reasonCode: 'synthetic.d9-1-scope-audit-failed',
            lastKnownLogicalStateSha256: this.#expectedStateSeal.logical_state_sha256,
            authenticatedLauncherBindingCode: this.#launcherBinding.bindingCode,
            terminalPermitTransition,
          })
          operationBegun = false
        } catch (recoveryError) {
          fail('LAUNCHER_RECOVERY_AMBIGUOUS', 'synthetic permitted audit failed and recovery state could not be recorded', {
            cause: new AggregateError([causalError, recoveryError]),
          })
        }
        fail('LAUNCHER_RECOVERY_REQUIRED', `synthetic permitted audit failed closed (${error?.code ?? 'unknown failure'})`, { cause: causalError })
      }
      throw error
    } finally {
      if (!nativeReleaseAttempted) await nativeLock.release()
    }
  }

  async appendBootstrapPermitWithdrawal(recordBytes, ...extra) {
    if (extra.length) fail('LAUNCHER_INPUT_INVALID', 'appendBootstrapPermitWithdrawal accepts only exact record bytes')
    this.#assertStarted()
    const record = this.#approvedRecord(recordBytes, 'bootstrap-control-v1.schema.json')
    if (record.record_kind_code !== 'permit_transition' || record.permit_kind_code !== 'bootstrap' || record.transition_code !== 'authority_withdrawal') {
      fail('LAUNCHER_RECORD_KIND_INVALID', 'D9.1 independently appends only bootstrap authority-withdrawal transitions')
    }
    const requestDigestSha256 = sha256Bytes(Buffer.from(recordBytes))
    const persistedAt = this.#now('permit-withdrawal persistence time')
    if (record.persisted_at !== persistedAt) {
      fail('LAUNCHER_CLOCK_INVALID', 'transition persisted_at must equal the protected broker time')
    }
    this.#assertActive(persistedAt)
    const authority = await this.#authenticate('bootstrap_authority', 'bootstrap', persistedAt, requestDigestSha256)
    const persistenceBroker = this.#verifyStateAppendBroker()
    if (record.recorded_by_runtime_role_code !== 'bootstrap_authority' ||
        record.recorded_by_binding_code !== authority.bindingCode ||
        record.persisted_by_binding_code !== persistenceBroker.bindingCode ||
        authority.uid === persistenceBroker.uid) {
      fail('LAUNCHER_TRANSITION_ACTOR_MISMATCH', 'transition semantic and persistence actors are not the required distinct bindings')
    }
    const afterAuthenticationAt = this.#now('permit-withdrawal post-authentication time')
    this.#assertActive(afterAuthenticationAt)
    if (afterAuthenticationAt >= record.expires_at) fail('LAUNCHER_PERMIT_EXPIRED', 'permit expired during transition authentication')
    const result = await this.#stateAppendBroker.appendPermitTransition({
      record,
      authenticatedSemanticRuntimeRoleCode: 'bootstrap_authority',
      authenticatedSemanticBindingCode: authority.bindingCode,
      authenticatedPersistenceBindingCode: persistenceBroker.bindingCode,
    })
    return deepFreeze({ ...result, transitionCode: record.record_code, recordDigestSha256: record.record_digest_sha256 })
  }

  resolveControlReference(reference, ...extra) {
    if (extra.length) fail('LAUNCHER_INPUT_INVALID', 'resolveControlReference accepts one closed reference')
    this.#assertStarted()
    exactKeys(reference, ['recordCode', 'recordDigestSha256', 'recordKindCode'], 'control reference')
    stableCode(reference.recordCode, 'recordCode')
    sha256(reference.recordDigestSha256, 'recordDigestSha256')
    const asOf = this.#now('control-reference resolution time')
    this.#assertActive(asOf)
    if (reference.recordKindCode === 'collector_handoff' || reference.recordKindCode === 'bundle_seal') {
      return this.#protectedStateStore.resolveFixedRecord({
        registryKindCode: reference.recordKindCode,
        recordCode: reference.recordCode,
        recordDigestSha256: reference.recordDigestSha256,
        asOf,
      })
    }
    if (reference.recordKindCode === 'bootstrap_permit') {
      return this.#protectedStateStore.resolvePermit({
        permitCode: reference.recordCode,
        recordDigestSha256: reference.recordDigestSha256,
        asOf,
        requiredStateCode: 'ready',
      })
    }
    fail('LAUNCHER_RECORD_KIND_INVALID', 'control reference kind is not supported by D9.1')
  }

  async revokeRegisteredControlRecord(request, ...extra) {
    if (extra.length) fail('LAUNCHER_INPUT_INVALID', 'revokeRegisteredControlRecord accepts one closed request')
    this.#assertStarted()
    exactKeys(request, ['reasonCode', 'recordCode', 'recordDigestSha256', 'recordKindCode'], 'control-record revocation')
    stableCode(request.reasonCode, 'reasonCode')
    stableCode(request.recordCode, 'recordCode')
    sha256(request.recordDigestSha256, 'recordDigestSha256')
    if (!['collector_handoff', 'bundle_seal'].includes(request.recordKindCode)) {
      fail('LAUNCHER_RECORD_KIND_INVALID', 'only a handoff or bundle seal may be revoked through this interface')
    }
    const authenticationAt = this.#now('control-record revocation authentication time')
    this.#assertActive(authenticationAt)
    const requestDigestSha256 = sha256Bytes(Buffer.from(canonicalize(request), 'utf8'))
    const actor = request.recordKindCode === 'collector_handoff'
      ? await this.#authenticate('handoff_broker', 'document_import', authenticationAt, requestDigestSha256)
      : this.#launcherBinding
    const revokedAt = this.#now('control-record revocation persistence time')
    this.#assertActive(revokedAt)
    const result = await this.#stateAppendBroker.revokeFixedRecord({
      registryKindCode: request.recordKindCode,
      recordCode: request.recordCode,
      recordDigestSha256: request.recordDigestSha256,
      revokedAt,
      reasonCode: request.reasonCode,
      authenticatedRuntimeRoleCode: actor.runtimeRoleCode,
      authenticatedBindingCode: actor.bindingCode,
    })
    return deepFreeze({ ...result, recordCode: request.recordCode, recordDigestSha256: request.recordDigestSha256, revokedAt })
  }

  async revokeActiveGeneration(request, ...extra) {
    if (extra.length) fail('LAUNCHER_INPUT_INVALID', 'revokeActiveGeneration accepts one closed request')
    this.#assertStarted()
    exactKeys(request, ['reasonCode'], 'active-generation revocation')
    stableCode(request.reasonCode, 'reasonCode')
    const revokedAt = this.#now('active-generation revocation time')
    const pair = this.#assertActive(revokedAt)
    const result = await this.#stateAppendBroker.revokeGenerationPair({
      pairCode: pair.pair_code,
      pairGeneration: pair.pair_generation,
      runtimeProfileRecordDigestSha256: pair.runtime_profile.record_digest_sha256,
      identityBindingsRecordDigestSha256: pair.identity_bindings.record_digest_sha256,
      revokedAt,
      reasonCode: request.reasonCode,
      authenticatedLauncherBindingCode: this.#launcherBinding.bindingCode,
    })
    this.#started = false
    return deepFreeze({ ...result, pairCode: pair.pair_code, pairGeneration: pair.pair_generation, revokedAt })
  }

  async runSyntheticBootstrapDryRun(...args) {
    noArguments(args, 'runSyntheticBootstrapDryRun')
    this.#assertStarted()
    const startedAt = this.#now('synthetic dry-run start time')
    this.#assertActive(startedAt)
    await this.#authenticate('human_submitter', 'dry_run', startedAt, DRY_RUN_REQUEST_DIGEST)
    const operationId = stableCode(this.#operationIdSource(), 'operation ID')
    const operationNonce = sha256(this.#nonceSource(), 'operation nonce')
    const nativeLock = await this.#platform.holdOperationLock({
      rootPath: this.#configuration.operationLockRootPath,
      relativePath: this.#configuration.operationLockLeaf,
    })
    let operationBegun = false
    let nativeReleaseAttempted = false
    try {
      const operationStartedAt = this.#now('synthetic dry-run protected start time')
      this.#assertActive(operationStartedAt)
      const before = this.#verifyEmpty()
      await this.#stateAppendBroker.beginSyntheticDryRun({
        operation: {
          operationId,
          operationNonce,
          operationModeCode: 'dry_run',
          startedAt: operationStartedAt,
          runtimeProfileRecordDigestSha256: this.#verifiedGeneration.runtimeProfile.record_digest_sha256,
          identityBindingsRecordDigestSha256: this.#verifiedGeneration.identityBindings.record_digest_sha256,
        },
        authenticatedLauncherBindingCode: this.#launcherBinding.bindingCode,
      })
      operationBegun = true
      const probeResult = await withDeadline(this.#syntheticNoEffectProbe.run(deepFreeze({
        operationId,
        operationNonce,
        operationModeCode: 'dry_run',
        bundleKindCode: 'principal_bootstrap',
        issuedHandleGrants: [],
        syntheticTestDouble: true,
      })), this.#verifiedGeneration.runtimeProfile.limits.operation_timeout_ms, 'synthetic D9.2 no-effect probe')
      exactKeys(probeResult, ['canonicalEffectCode', 'issuedHandleCount', 'rollbackVerified'], 'synthetic D9.2 probe result')
      if (probeResult.canonicalEffectCode !== 'none' || probeResult.issuedHandleCount !== 0 || probeResult.rollbackVerified !== true) {
        fail('LAUNCHER_SYNTHETIC_PROBE_FAILED', 'synthetic D9.2 probe did not prove a zero-handle rollback')
      }
      const verificationAt = this.#now('synthetic dry-run verification time')
      this.#revalidateGeneration(verificationAt)
      const after = this.#verifyEmpty()
      if (before.logicalStateSha256 !== after.logicalStateSha256 || before.databaseFileSha256 !== after.databaseFileSha256) {
        fail('LAUNCHER_UNEXPECTED_EFFECT', 'synthetic no-effect path changed canonical state')
      }
      // Keep the protected-state operation lease until the kernel lock holder
      // has confirmed release. A release failure is therefore persisted as an
      // operation recovery hold rather than being discovered after terminality.
      nativeReleaseAttempted = true
      await nativeLock.release()
      const verifierAuthenticationAt = this.#now('synthetic dry-run verifier authentication time')
      this.#revalidateGeneration(verifierAuthenticationAt)
      const terminalAttestation = {
        format: 'jedi-atlas-d91-synthetic-no-effect-attestation',
        format_version: '1.0.0',
        outcome_code: 'synthetic_no_effect_verified',
        operation_id: operationId,
        operation_nonce: operationNonce,
        before_database_file_sha256: before.databaseFileSha256,
        before_logical_state_sha256: before.logicalStateSha256,
        after_database_file_sha256: after.databaseFileSha256,
        after_logical_state_sha256: after.logicalStateSha256,
        issued_handle_count: 0,
      }
      const terminalRequestDigest = sha256Bytes(Buffer.from(canonicalize(terminalAttestation), 'utf8'))
      const verifier = await this.#authenticate('independent_verifier', 'dry_run', verifierAuthenticationAt, terminalRequestDigest)
      const completedAt = this.#now('synthetic dry-run completion time')
      this.#revalidateGeneration(completedAt)
      await this.#stateAppendBroker.finishSyntheticNoEffect({
        operationId,
        operationNonce,
        recordedAt: completedAt,
        beforeLogicalStateSha256: before.logicalStateSha256,
        afterLogicalStateSha256: after.logicalStateSha256,
        reasonCode: 'synthetic_control_plane_no_effect',
        authenticatedVerifierBindingCode: verifier.bindingCode,
      })
      operationBegun = false
      return deepFreeze({
        outcomeCode: 'synthetic_no_effect_verified',
        operationId,
        operationNonce,
        issuedHandleCount: 0,
        logicalStateSha256: after.logicalStateSha256,
        acceptedBundleProjectionVerified: false,
      })
    } catch (error) {
      if (operationBegun) {
        this.#recoveryHold = true
        const failedAt = this.#now('synthetic dry-run failure time')
        try {
          await this.#stateAppendBroker.markSyntheticRecoveryRequired({
            operationId,
            operationNonce,
            recordedAt: failedAt,
            reasonCode: 'synthetic.no-effect-unproven',
            lastKnownLogicalStateSha256: this.#expectedStateSeal.logical_state_sha256,
            authenticatedLauncherBindingCode: this.#launcherBinding.bindingCode,
          })
        } catch (recoveryError) {
          fail('LAUNCHER_RECOVERY_AMBIGUOUS', 'synthetic operation failed and recovery state could not be recorded', {
            cause: new AggregateError([error, recoveryError]),
          })
        }
        fail('LAUNCHER_RECOVERY_REQUIRED', `synthetic operation did not prove no effect and was placed in recovery-required state (${error?.code ?? 'unknown failure'})`, { cause: error })
      }
      throw error
    } finally {
      if (!nativeReleaseAttempted) await nativeLock.release()
    }
  }
}

export function createTrustedLauncher(dependencies) {
  return new TrustedLauncher(dependencies)
}
