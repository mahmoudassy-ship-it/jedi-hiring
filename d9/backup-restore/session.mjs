import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { randomBytes } from 'node:crypto'
import { assertLinuxEnforcement } from '../control-plane/platform.mjs'
import { failD951 } from './errors.mjs'

const authorities = new WeakSet()
const sessions = new WeakSet()

export function createD951SyntheticAuthority({ contractSet, authorityContext, authorityRegistry, linuxEnforcement, handleRootPath, trustedClock }) {
  if (!contractSet?.classifications || !authorityContext?.verifiedGeneration || typeof authorityRegistry?.stateAt !== 'function' || typeof handleRootPath !== 'string' || typeof trustedClock !== 'function') {
    failD951('D951_AUTHORITY_INVALID', 'verified D9.0.1/D9.4 authority inputs and trusted clock are required')
  }
  assertLinuxEnforcement(linuxEnforcement).probe()
  const rules = new Map(contractSet.classifications.role_assignment_rules.map((rule) => [rule.semantic_role_code, rule]))
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
      if (rule.d940_role_code !== null) {
        const assignment = roster.assignments.find((item) => item.role_code === rule.d940_role_code && item.binding_code === bindingCode) ??
          roster.human_identity_mappings.find((item) => item.d901_runtime_role_code === binding.runtime_role_code && item.binding_code === bindingCode)
        if (!assignment) failD951('D951_AUTHORITY_MISMATCH', 'binding is absent from the adopted D9.4 authority roster')
      }
      const session = Object.freeze({ semanticRoleCode, bindingCode, processInstanceCode, actorKindCode: binding.principal_kind_code, authenticatedAt, generationDigest: generation.record_digest_sha256, peerPid: exchange.peer_pid, receiverTerminated: exchange.receiverExitConfirmed })
      sessions.add(session)
      return session
    },
    revalidate(session, expectedRole, at = trustedClock()) {
      if (!sessions.has(session) || session.semanticRoleCode !== expectedRole) failD951('D951_SESSION_UNTRUSTED', 'session was not issued for the required D9.5 role')
      authorityRegistry.stateAt(at)
      if (!(session.authenticatedAt <= at && at < generation.expires_at)) failD951('D951_SESSION_EXPIRED', 'session is no longer current')
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
