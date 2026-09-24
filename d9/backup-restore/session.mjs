import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { randomBytes } from 'node:crypto'
import { assertLinuxEnforcement } from '../control-plane/platform.mjs'
import { failD951 } from './errors.mjs'
import { deepFreeze } from './contracts.mjs'

const authorities = new WeakSet()
const sessions = new WeakSet()

export function createD951SyntheticAuthority({ contractSet, authorityContext, authorityRegistry, linuxEnforcement, handleRootPath, trustedClock }) {
  if (!contractSet?.classifications || !authorityContext?.verifiedGeneration || typeof authorityRegistry?.stateAt !== 'function' || typeof handleRootPath !== 'string' || typeof trustedClock !== 'function') {
    failD951('D951_AUTHORITY_INVALID', 'verified D9.0.1/D9.4 authority inputs and trusted clock are required')
  }
  assertLinuxEnforcement(linuxEnforcement).probe()
  const rules = new Map(contractSet.classifications.role_assignment_rules.map((rule) => [rule.semantic_role_code, rule]))
  if (authorityRegistry.authorityContext !== authorityContext) failD951('D951_AUTHORITY_INVALID', 'authority context is not the registry verified context')
  const generation = authorityContext.verifiedGeneration.identityBindings
  const roster = authorityContext.authorityRoster
  const authority = Object.freeze({
    async authenticate({ semanticRoleCode, bindingCode, processInstanceCode, authenticatedAt = trustedClock(), scenario = 'normal' }) {
      const rule = rules.get(semanticRoleCode)
      if (!rule || typeof processInstanceCode !== 'string' || processInstanceCode.length < 3) failD951('D951_ROLE_FORBIDDEN', 'semantic role or process identity is outside D9.5.0')
      authorityRegistry.stateAt(authenticatedAt)
      const binding = generation.bindings.find((item) => item.binding_code === bindingCode)
      if (!binding || binding.runtime_role_code !== rule.runtime_role_code || binding.principal_kind_code !== rule.actor_kind_code) failD951('D951_IDENTITY_MISMATCH', 'binding does not satisfy the frozen D9.5 role mapping')
      if (!(generation.issued_at <= authenticatedAt && authenticatedAt < generation.expires_at && binding.valid_from <= authenticatedAt && authenticatedAt < binding.valid_until)) failD951('D951_IDENTITY_EXPIRED', 'identity generation or binding is not current')
      const nonce = randomBytes(32).toString('hex')
      const endpoint = binding.principal_kind_code === 'service' ? binding.ipc_endpoint_code : 'ipc.d951-human-submission'
      const requestDigestSha256 = canonicalSha256({ semantic_role_code: semanticRoleCode, binding_code: bindingCode, process_instance_code: processInstanceCode, authenticated_at: authenticatedAt, nonce })
      const exchange = await linuxEnforcement.runSyntheticPeerExchange({ descriptorGrants: [{ slot_code: 'd951_ephemeral_authenticated_channel', runtime_role_code: binding.runtime_role_code, access_code: 'message_only' }], expectedEndpointCode: endpoint, expectedPeerUid: binding.unix_uid, syntheticPeerUid: binding.unix_uid, expectedPeerGid: process.getgid(), syntheticPeerGid: process.getgid(), nonce, relativePath: 'synthetic.handle', requestDigestSha256, rootPath: handleRootPath, scenario })
      if (exchange.status !== 'ok' || exchange.ack_same_channel !== true || exchange.descriptor_metadata_verified !== true || exchange.termination_confirmed !== true || exchange.receiverExitConfirmed !== true) failD951('D951_PEER_MISMATCH', 'kernel-authenticated process-bound exchange failed')
      const expectedPeer = { uid: binding.unix_uid, executable_sha256: binding.principal_kind_code === 'service' ? binding.executable_sha256 : null, ipc_endpoint_code: binding.principal_kind_code === 'service' ? binding.ipc_endpoint_code : null }
      const observedPeer = { uid: exchange.peer_uid, executable_sha256: binding.principal_kind_code === 'service' ? linuxEnforcement.executableSha256 : null, ipc_endpoint_code: binding.principal_kind_code === 'service' ? exchange.authenticatedEndpointCode : null }
      if (canonicalize(observedPeer) !== canonicalize(expectedPeer)) failD951('D951_PEER_MISMATCH', 'kernel/build/endpoint facts do not match the verified binding')
      const peer = { pid: exchange.peer_pid, uid: exchange.peer_uid, gid: exchange.peer_gid, executableSha256: binding.principal_kind_code === 'service' ? linuxEnforcement.executableSha256 : null, ipcEndpointCode: binding.principal_kind_code === 'service' ? exchange.authenticatedEndpointCode : null }
      let resolved = null
      if (rule.d940_role_code !== null) {
        resolved = authorityRegistry.resolveActor({ roleCode: rule.d940_role_code, bindingCode, peer, at: authenticatedAt })
      }
      const actor = { actor_kind_code: binding.principal_kind_code, semantic_role_code: semanticRoleCode, runtime_role_code: binding.runtime_role_code, binding_code: binding.binding_code, principal_code: resolved?.principal_code ?? binding.atlas_principal_code, ipc_endpoint_code: binding.ipc_endpoint_code, executable_build_sha256: binding.executable_sha256, binding_generation: generation.binding_generation, runtime_profile_record_digest_sha256: generation.runtime_profile_record_digest_sha256, identity_bindings_record_digest_sha256: generation.record_digest_sha256, authority_roster_record_digest_sha256: roster.record_digest_sha256, process_instance_code: processInstanceCode }
      const session = deepFreeze({ semanticRoleCode, bindingCode, processInstanceCode, actorKindCode: binding.principal_kind_code, authenticatedAt, generationDigest: generation.record_digest_sha256, peer, receiverTerminated: exchange.receiverExitConfirmed, actor })
      sessions.add(session)
      return session
    },
    revalidate(session, expectedRole, at = trustedClock()) {
      if (!sessions.has(session) || session.semanticRoleCode !== expectedRole) failD951('D951_SESSION_UNTRUSTED', 'session was not issued for the required D9.5 role')
      authorityRegistry.stateAt(at)
      const binding = generation.bindings.find((item) => item.binding_code === session.bindingCode)
      if (!binding || !(session.authenticatedAt <= at && at < generation.expires_at && binding.valid_from <= at && at < binding.valid_until) || session.generationDigest !== generation.record_digest_sha256 || session.actor.authority_roster_record_digest_sha256 !== roster.record_digest_sha256) failD951('D951_SESSION_EXPIRED', 'session is no longer current')
      const rule = rules.get(expectedRole)
      if (rule?.d940_role_code !== null) {
        const resolved = authorityRegistry.resolveActor({ roleCode: rule.d940_role_code, bindingCode: session.bindingCode, peer: session.peer, at })
        if (resolved.principal_code !== session.actor.principal_code || resolved.authority_roster_record_digest_sha256 !== session.actor.authority_roster_record_digest_sha256) failD951('D951_SESSION_EXPIRED', 'session no longer resolves through the adopted authority roster')
      }
      return session
    },
  })
  authorities.add(authority)
  return authority
}

export function assertD951Authority(value) {
  if (!authorities.has(value)) failD951('D951_AUTHORITY_UNTRUSTED', 'authority was not created by the D9.5 launcher boundary')
  return value
}

export function assertD951Session(value, expectedRole = null) {
  if (!sessions.has(value) || (expectedRole !== null && value.semanticRoleCode !== expectedRole)) failD951('D951_SESSION_UNTRUSTED', 'session is not a branded D9.5 session for the required role')
  return value
}
