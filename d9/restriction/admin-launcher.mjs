import { randomBytes } from 'node:crypto'

import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { assertLinuxEnforcement } from '../control-plane/platform.mjs'
import { assertD941AuthorityRegistry } from './authority.mjs'
import { failD941 } from './errors.mjs'

const launchers = new WeakSet()
const authenticatedSessions = new WeakSet()

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child)
    if (!Object.isFrozen(value)) Object.freeze(value)
  }
  return value
}

function registerD941AuthenticatedSession(session) {
  deepFreeze(session)
  authenticatedSessions.add(session)
  return session
}

export const D941_ADMIN_SCOPES = Object.freeze({
  control_submission: Object.freeze({
    roleCode: 'journal_broker',
    runtimeRoleCode: 'journal_broker',
    grants: Object.freeze([
      Object.freeze({ slot_code: 'd941_control_store', runtime_role_code: 'journal_broker', access_code: 'append_only' }),
      Object.freeze({ slot_code: 'd941_global_ledger', runtime_role_code: 'journal_broker', access_code: 'append_only' }),
    ]),
  }),
  access_shutdown: Object.freeze({
    roleCode: 'trusted_launcher',
    runtimeRoleCode: 'trusted_launcher',
    grants: Object.freeze([
      Object.freeze({ slot_code: 'd941_access_store', runtime_role_code: 'trusted_launcher', access_code: 'append_only' }),
      Object.freeze({ slot_code: 'd941_receiver_control', runtime_role_code: 'trusted_launcher', access_code: 'terminate_only' }),
    ]),
  }),
  capability_revocation: Object.freeze({
    roleCode: 'custody_operator',
    runtimeRoleCode: 'trusted_launcher',
    grants: Object.freeze([
      Object.freeze({ slot_code: 'd941_access_store', runtime_role_code: 'trusted_launcher', access_code: 'append_only' }),
      Object.freeze({ slot_code: 'd941_capability_control', runtime_role_code: 'trusted_launcher', access_code: 'revoke_only' }),
    ]),
  }),
  deletion_execution: Object.freeze({
    roleCode: 'deletion_executor',
    runtimeRoleCode: 'custody_adapter',
    grants: Object.freeze([
      Object.freeze({ slot_code: 'd941_primary_root', runtime_role_code: 'custody_adapter', access_code: 'unlink_primary_name_only' }),
      Object.freeze({ slot_code: 'd941_operation_lock', runtime_role_code: 'custody_adapter', access_code: 'exclusive_lock' }),
      Object.freeze({ slot_code: 'd941_execution_store', runtime_role_code: 'custody_adapter', access_code: 'append_only' }),
    ]),
  }),
  independent_verification: Object.freeze({
    roleCode: 'independent_verifier',
    runtimeRoleCode: 'independent_verifier',
    grants: Object.freeze([
      Object.freeze({ slot_code: 'd941_primary_root', runtime_role_code: 'independent_verifier', access_code: 'integrity_only' }),
      Object.freeze({ slot_code: 'd941_receipt_store', runtime_role_code: 'independent_verifier', access_code: 'append_only' }),
    ]),
  }),
  recovery_classification: Object.freeze({
    roleCode: 'journal_broker',
    runtimeRoleCode: 'journal_broker',
    grants: Object.freeze([
      Object.freeze({ slot_code: 'd941_global_ledger', runtime_role_code: 'journal_broker', access_code: 'read_only' }),
      Object.freeze({ slot_code: 'd941_recovery_store', runtime_role_code: 'journal_broker', access_code: 'append_only' }),
    ]),
  }),
})

const frozenImporterSlots = new Set([
  'runtime_profile', 'identity_bindings', 'reviewed_root', 'handoff_registry', 'staging_root', 'custody_root',
  'candidate_database', 'canonical_database', 'operation_journal', 'permit_control_store', 'backup_root',
  'logical_state_verifier', 'clearance_registry',
])

for (const [scopeCode, scope] of Object.entries(D941_ADMIN_SCOPES)) {
  if (scope.grants.length < 1 || scope.grants.length > 8 || scope.grants.some((grant) => frozenImporterSlots.has(grant.slot_code))) {
    throw new Error(`D9.4.1 administrative scope is not isolated: ${scopeCode}`)
  }
  const keys = scope.grants.map((grant) => `${grant.slot_code}/${grant.runtime_role_code}/${grant.access_code}`)
  if (new Set(keys).size !== keys.length) throw new Error(`D9.4.1 administrative scope contains duplicate grants: ${scopeCode}`)
}

export function createD941AdministrativeLauncher({ authorityRegistry, linuxEnforcement, handleRootPath, handleRelativePath = 'synthetic.handle', trustedClock = () => new Date().toISOString(), maxFutureSkewMs = 0 }) {
  assertD941AuthorityRegistry(authorityRegistry)
  assertLinuxEnforcement(linuxEnforcement).probe()

  function scopeFor(scopeCode, suppliedGrants = null) {
    const scope = D941_ADMIN_SCOPES[scopeCode]
    if (!scope) failD941('D941_SCOPE_UNKNOWN', 'unknown administrative operation scope')
    if (suppliedGrants !== null && canonicalize(suppliedGrants) !== canonicalize(scope.grants)) {
      failD941('D941_SCOPE_SUBSTITUTION', 'caller-supplied grants differ from the exact administrative partition')
    }
    return scope
  }

  function consumeNonce(nonce, at) {
    const trustedNow = Date.parse(trustedClock())
    const suppliedAt = Date.parse(at)
    if (!Number.isFinite(trustedNow) || !Number.isFinite(suppliedAt) || suppliedAt < trustedNow) failD941('D941_TRUSTED_TIME_BACKDATE', 'caller-supplied authentication time predates the trusted launcher clock')
    if (!Number.isSafeInteger(maxFutureSkewMs) || maxFutureSkewMs < 0 || suppliedAt - trustedNow > maxFutureSkewMs) failD941('D941_TRUSTED_TIME_FUTURE', 'caller-supplied authentication time exceeds the fixed trusted-clock skew window')
    if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/u.test(nonce)) failD941('D941_NONCE_INVALID', 'operation nonce is invalid')
    authorityRegistry.claimAuthenticationNonce({ nonce, claimedAt: at })
  }

  const launcher = Object.freeze({
    scope(scopeCode) {
      return scopeFor(scopeCode)
    },
    async authenticateService({ scopeCode, bindingCode, at, nonce = randomBytes(32).toString('hex'), suppliedGrants = null, scenario = 'normal' }) {
      const scope = scopeFor(scopeCode, suppliedGrants)
      consumeNonce(nonce, at)
      const generation = authorityRegistry.authorityContext.verifiedGeneration
      const binding = generation.identityBindings.bindings.find((item) => item.binding_code === bindingCode)
      if (!binding || binding.principal_kind_code !== 'service' || binding.runtime_role_code !== scope.runtimeRoleCode) {
        failD941('D941_LAUNCH_BINDING_MISMATCH', 'scope recipient does not resolve to its exact verified service binding')
      }
      if (binding.executable_sha256 !== linuxEnforcement.executableSha256) {
        failD941('D941_LAUNCH_BUILD_MISMATCH', 'synthetic peer build differs from the verified D9.0.1 service release')
      }
      const requestDigestSha256 = canonicalSha256({ scope_code: scopeCode, binding_code: bindingCode, at, nonce, grants: scope.grants })
      const exchange = await linuxEnforcement.runSyntheticPeerExchange({
        descriptorGrants: scope.grants,
        expectedEndpointCode: binding.ipc_endpoint_code,
        expectedPeerUid: binding.unix_uid,
        syntheticPeerUid: binding.unix_uid,
        expectedPeerGid: process.getgid(),
        syntheticPeerGid: process.getgid(),
        nonce,
        relativePath: handleRelativePath,
        requestDigestSha256,
        rootPath: handleRootPath,
        scenario,
      })
      if (exchange.status !== 'ok' || exchange.ack_same_channel !== true || exchange.descriptor_metadata_verified !== true ||
          exchange.termination_confirmed !== true || exchange.receiverExitConfirmed !== true) {
        failD941('D941_IPC_AUTHENTICATION_FAILED', 'native peer exchange did not complete its authenticated, process-bound lifecycle', { details: exchange })
      }
      const actor = authorityRegistry.resolveActor({
        roleCode: scope.roleCode,
        bindingCode,
        at,
        peer: {
          pid: exchange.peer_pid,
          uid: exchange.peer_uid,
          gid: exchange.peer_gid,
          executableSha256: linuxEnforcement.executableSha256,
          ipcEndpointCode: exchange.authenticatedEndpointCode,
        },
      })
      return registerD941AuthenticatedSession(Object.freeze({ actor, scopeCode, grants: scope.grants, nonce, requestDigestSha256, exchange, authenticatedAt: at }))
    },
    async authenticateHumanSubmission({ roleCode, bindingCode, at, nonce = randomBytes(32).toString('hex'), scenario = 'normal' }) {
      consumeNonce(nonce, at)
      const generation = authorityRegistry.authorityContext.verifiedGeneration
      const binding = generation.identityBindings.bindings.find((item) => item.binding_code === bindingCode)
      if (!binding || binding.principal_kind_code !== 'human') failD941('D941_LAUNCH_BINDING_MISMATCH', 'human submission does not resolve to a verified human binding')
      const requestDigestSha256 = canonicalSha256({ operation_code: 'd941_control_submission', role_code: roleCode, binding_code: bindingCode, at, nonce })
      const exchange = await linuxEnforcement.runSyntheticPeerExchange({
        descriptorGrants: [{ slot_code: 'd941_submission_channel', runtime_role_code: 'human_submitter', access_code: 'submit_only' }],
        expectedEndpointCode: 'ipc.d941-human-submission',
        expectedPeerUid: binding.unix_uid,
        syntheticPeerUid: binding.unix_uid,
        expectedPeerGid: process.getgid(), syntheticPeerGid: process.getgid(),
        nonce, relativePath: handleRelativePath, requestDigestSha256, rootPath: handleRootPath, scenario,
      })
      if (exchange.status !== 'ok' || exchange.termination_confirmed !== true) failD941('D941_IPC_AUTHENTICATION_FAILED', 'human submission peer exchange failed')
      const actor = authorityRegistry.resolveActor({
        roleCode,
        bindingCode,
        at,
        peer: { pid: exchange.peer_pid, uid: exchange.peer_uid, gid: exchange.peer_gid, executableSha256: null, ipcEndpointCode: null },
      })
      return registerD941AuthenticatedSession(Object.freeze({ actor, scopeCode: 'human_control_submission', grants: Object.freeze([]), nonce, requestDigestSha256, exchange, authenticatedAt: at }))
    },
    async authenticateAuthorityTransition({ roleCode, bindingCode, at, nonce = randomBytes(32).toString('hex'), scenario = 'normal' }) {
      if (!['operational_witness', 'recovery_authority'].includes(roleCode)) failD941('D941_AUTHORITY_TRANSITION_ROLE_FORBIDDEN', 'authority transitions use only the closed human role set')
      consumeNonce(nonce, at)
      const generation = authorityRegistry.authorityContext.verifiedGeneration
      const binding = generation.identityBindings.bindings.find((item) => item.binding_code === bindingCode)
      if (!binding || binding.principal_kind_code !== 'human') failD941('D941_LAUNCH_BINDING_MISMATCH', 'authority transition does not resolve to a verified human binding')
      const requestDigestSha256 = canonicalSha256({ operation_code: 'd941_authority_transition', role_code: roleCode, binding_code: bindingCode, at, nonce })
      const exchange = await linuxEnforcement.runSyntheticPeerExchange({
        descriptorGrants: [{ slot_code: 'd941_authority_transition', runtime_role_code: 'human_submitter', access_code: 'submit_only' }],
        expectedEndpointCode: 'ipc.d941-authority-transition', expectedPeerUid: binding.unix_uid, syntheticPeerUid: binding.unix_uid,
        expectedPeerGid: process.getgid(), syntheticPeerGid: process.getgid(), nonce, relativePath: handleRelativePath,
        requestDigestSha256, rootPath: handleRootPath, scenario,
      })
      if (exchange.status !== 'ok' || exchange.termination_confirmed !== true || exchange.receiverExitConfirmed !== true) failD941('D941_IPC_AUTHENTICATION_FAILED', 'authority transition peer exchange failed')
      const actor = authorityRegistry.resolveTransitionActor({
        roleCode, bindingCode, at,
        peer: { pid: exchange.peer_pid, uid: exchange.peer_uid, gid: exchange.peer_gid, executableSha256: null, ipcEndpointCode: null },
      })
      return registerD941AuthenticatedSession(Object.freeze({ actor, scopeCode: 'authority_transition', grants: Object.freeze([]), nonce, requestDigestSha256, exchange, authenticatedAt: at }))
    },
  })
  launchers.add(launcher)
  return launcher
}

export function assertD941AdministrativeLauncher(value) {
  if (!launchers.has(value)) failD941('D941_LAUNCHER_UNTRUSTED', 'launcher was not created by the fixed D9.4.1 factory')
  return value
}

export function assertD941AuthenticatedSession(value, expectedScopeCode = null) {
  if (!authenticatedSessions.has(value)) failD941('D941_SESSION_UNTRUSTED', 'session was not authenticated by the fixed administrative launcher')
  if (expectedScopeCode !== null && value.scopeCode !== expectedScopeCode) failD941('D941_SESSION_SCOPE_MISMATCH', 'authenticated session belongs to a different administrative partition')
  return value
}
