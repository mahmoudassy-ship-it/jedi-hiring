import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { assertDurableNamespaceStore, durableJsonBytes } from '../custody/durable-store.mjs'
import { assertLinuxEnforcement } from '../control-plane/platform.mjs'
import { assertVerifiedD940AuthorityContext } from './contracts.mjs'
import { failD941 } from './errors.mjs'
import { assertD941AuthenticatedSession } from './admin-launcher.mjs'

const registries = new WeakSet()
const lockConfigurations = new WeakMap()
const lockStates = new WeakMap()
const TARGETS = Object.freeze(['d901_identity_generation', 'd940_authority_extension', 'd940_authority_roster', 'd940_roster_adoption'])

function timestamp(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u.test(value) ||
      Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    failD941('D941_AUTHORITY_TIME_INVALID', `${label} must be a canonical UTC timestamp`)
  }
  return value
}

function seal(record) {
  const result = structuredClone(record)
  result.record_digest_sha256 = canonicalSha256(result, { excludedTopLevelField: 'record_digest_sha256' })
  return Object.freeze(result)
}

function eventCode(sequence) {
  return `authority-state-${String(sequence).padStart(8, '0')}`
}

function loadEvents(store) {
  return store.inventory().projection['authority-events'].map(({ record_code: recordCode }) => {
    const value = JSON.parse(store.read({ namespaceCode: 'authority-events', recordCode }).toString('utf8'))
    if (value.record_digest_sha256 !== canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' })) {
      failD941('D941_AUTHORITY_STATE_CORRUPT', `${recordCode} has a mismatched digest`)
    }
    return value
  }).sort((left, right) => left.sequence - right.sequence)
}

function validateEventChain(events) {
  let previous = null
  for (const [index, event] of events.entries()) {
    if (event.sequence !== index + 1 || event.previous_record_digest_sha256 !== previous || event.record_code !== eventCode(index + 1)) {
      failD941('D941_AUTHORITY_STATE_CHAIN_INVALID', 'authority state is gapped, forked, reordered, or backdated')
    }
    if (index > 0 && events[index - 1].persisted_at >= event.persisted_at) {
      failD941('D941_AUTHORITY_STATE_CHAIN_INVALID', 'authority persistence time is not strictly increasing')
    }
    previous = event.record_digest_sha256
  }
  return events
}

export function createD941AuthorityRegistry({ store, authorityContext, clock, linuxEnforcement, operationLockRootPath, operationLockLeaf = 'd941-operation.lock' }) {
  assertDurableNamespaceStore(store)
  assertVerifiedD940AuthorityContext(authorityContext)
  if (!store.namespaceCodes.includes('authority') || !store.namespaceCodes.includes('authority-events')) {
    failD941('D941_AUTHORITY_STORE_INVALID', 'authority store lacks its fixed namespaces')
  }
  if (typeof clock !== 'function') failD941('D941_AUTHORITY_INPUT_INVALID', 'clock is required')
  assertLinuxEnforcement(linuxEnforcement)
  if (typeof operationLockRootPath !== 'string' || operationLockRootPath.length === 0 || typeof operationLockLeaf !== 'string' || operationLockLeaf.length === 0) failD941('D941_AUTHORITY_INPUT_INVALID', 'authority registry requires a fixed native operation-lock identity')

  const records = [
    authorityContext.operationalProfile,
    authorityContext.authorityIdentityExtension,
    authorityContext.authorityRoster,
    authorityContext.authorityRosterAdoption,
  ]
  let destructiveLockHeld = false
  for (const record of records) {
    store.append({ namespaceCode: 'authority', recordCode: record.record_code, bytes: durableJsonBytes(record), replayKey: record.record_code })
  }

  function events() {
    return validateEventChain(loadEvents(store))
  }

  function currentState(at) {
    timestamp(at, 'authority evaluation time')
    const bounded = events().filter((event) => event.persisted_at <= at)
    const selected = bounded.find((event) => event.event_kind_code === 'synthetic_selection_recorded')
    if (!selected) failD941('D941_AUTHORITY_NOT_SELECTED', 'synthetic authority context has no protected selection')
    const revoked = new Set(bounded.filter((event) => event.event_kind_code === 'authority_target_revoked').map((event) => event.target_code))
    return Object.freeze({ selected, revoked })
  }

  function appendEvent({ eventKindCode, targetCode, actorSession, reasonCode, persistedAt }) {
    if (!['synthetic_selection_recorded', 'authority_target_revoked'].includes(eventKindCode) || !TARGETS.includes(targetCode)) {
      failD941('D941_AUTHORITY_EVENT_INVALID', 'unknown authority transition')
    }
    timestamp(persistedAt, 'authority persistence time')
    const trustedNow = timestamp(clock(), 'trusted authority clock')
    if (Date.parse(persistedAt) > Date.parse(trustedNow)) failD941('D941_AUTHORITY_TIME_FUTURE', 'authority persistence time cannot be later than the trusted authority clock')
    assertD941AuthenticatedSession(actorSession, 'authority_transition')
    if (Date.parse(persistedAt) < Date.parse(actorSession.authenticatedAt)) failD941('D941_AUTHORITY_TIME_BACKDATE', 'authority transitions cannot predate the authenticated transition session')
    const requiredRole = eventKindCode === 'synthetic_selection_recorded' ? 'operational_witness' : 'recovery_authority'
    if (actorSession.actor.role_code !== requiredRole || actorSession.actor.actor_kind_code !== 'human') {
      failD941('D941_AUTHORITY_TRANSITION_ROLE_FORBIDDEN', `authority transition requires ${requiredRole}`)
    }
    const service = actorSession.actor.actor_kind_code === 'service'
    const revalidatedActor = resolveAgainstVerifiedContext({
      roleCode: actorSession.actor.role_code,
      bindingCode: actorSession.actor.identity_binding.binding_code,
      at: persistedAt,
      requireSelection: eventKindCode !== 'synthetic_selection_recorded',
      peer: {
        pid: actorSession.exchange.peer_pid,
        uid: actorSession.exchange.peer_uid,
        gid: actorSession.exchange.peer_gid,
        executableSha256: service ? actorSession.exchange.executableSha256 : null,
        ipcEndpointCode: service ? actorSession.exchange.authenticatedEndpointCode : null,
      },
    })
    if (canonicalize(revalidatedActor) !== canonicalize(actorSession.actor)) failD941('D941_AUTHORITY_TRANSITION_ACTOR_STALE', 'transition actor no longer resolves to the exact selected authority generation')
    const prior = events()
    if (prior.some((event) => event.event_kind_code === eventKindCode && event.target_code === targetCode)) {
      failD941('D941_AUTHORITY_EVENT_REPLAY', 'authority transition already exists')
    }
    if (eventKindCode === 'authority_target_revoked' && !prior.some((event) => event.event_kind_code === 'synthetic_selection_recorded')) {
      failD941('D941_AUTHORITY_EVENT_INVALID', 'authority cannot be revoked before synthetic selection')
    }
    const record = seal({
      format: 'jedi-atlas-d941-synthetic-authority-state-event',
      format_version: '1.0.0',
      record_code: eventCode(prior.length + 1),
      sequence: prior.length + 1,
      previous_record_digest_sha256: prior.at(-1)?.record_digest_sha256 ?? null,
      event_kind_code: eventKindCode,
      target_code: targetCode,
      authority_context_sha256: canonicalSha256({
        identity_bindings: authorityContext.verifiedGeneration.identityBindings.record_digest_sha256,
        extension: authorityContext.authorityIdentityExtension.record_digest_sha256,
        roster: authorityContext.authorityRoster.record_digest_sha256,
        adoption: authorityContext.authorityRosterAdoption.record_digest_sha256,
      }),
      actor_binding_code: actorSession.actor.identity_binding.binding_code,
      reason_code: reasonCode,
      persisted_at: persistedAt,
      activation_boundary_code: 'synthetic_unactivated_test_runtime_only',
      record_digest_sha256: null,
    })
    store.append({ namespaceCode: 'authority-events', recordCode: record.record_code, bytes: durableJsonBytes(record), replayKey: record.record_code })
    return record
  }

  function resolveAgainstVerifiedContext({ roleCode, bindingCode, peer, at, requireSelection }) {
      const state = requireSelection ? currentState(at) : { revoked: new Set() }
      if (TARGETS.some((target) => state.revoked.has(target))) {
        failD941('D941_AUTHORITY_REVOKED', 'one or more required authority targets are revoked')
      }
      const { verifiedGeneration, authorityRoster, authorityRosterAdoption } = authorityContext
      const identity = verifiedGeneration.identityBindings
      if (!(identity.issued_at <= at && at < identity.expires_at && authorityRoster.valid_from <= at && at < authorityRoster.valid_until && authorityRosterAdoption.adopted_at <= at)) {
        failD941('D941_AUTHORITY_EXPIRED', 'identity generation, roster, or adoption is not current')
      }
      // `operational_witness` is deliberately an authority-transition role, not
      // a control/deletion assignment. It is therefore present in the frozen
      // D9.0.1 mapping and roster-adoption contract, but not in the ordinary
      // D9.4 semantic assignment list. Resolve that exact mapping here without
      // widening it into a control role.
      const assignment = authorityRoster.assignments.find((item) => item.role_code === roleCode && item.binding_code === bindingCode) ??
        (roleCode === 'operational_witness'
          ? authorityRoster.human_identity_mappings.find((item) => item.d901_runtime_role_code === roleCode && item.binding_code === bindingCode)
          : null)
      const binding = identity.bindings.find((item) => item.binding_code === bindingCode)
      if (!assignment || !binding || assignment.d901_runtime_role_code !== binding.runtime_role_code ||
          (assignment.actor_kind_code ?? 'human') !== binding.principal_kind_code) {
        failD941('D941_ACTOR_UNQUALIFIED', 'binding is not qualified for the requested D9.4 role')
      }
      if (!(binding.valid_from <= at && at < binding.valid_until)) failD941('D941_ACTOR_EXPIRED', 'binding is not active')
      const exactPeerKeys = ['executableSha256', 'gid', 'ipcEndpointCode', 'pid', 'uid']
      if (!peer || canonicalize(Object.keys(peer).toSorted()) !== canonicalize(exactPeerKeys)) failD941('D941_PEER_FACTS_INVALID', 'peer facts have unknown or missing fields')
      if (!Number.isSafeInteger(peer.pid) || peer.pid < 1 || !Number.isSafeInteger(peer.uid) || peer.uid < 0 || !Number.isSafeInteger(peer.gid) || peer.gid < 0 || peer.uid !== binding.unix_uid) failD941('D941_PEER_IDENTITY_MISMATCH', 'kernel UID/GID/PID facts do not resolve to the exact binding')
      if (binding.principal_kind_code === 'service') {
        if (peer.executableSha256 !== binding.executable_sha256 || peer.ipcEndpointCode !== binding.ipc_endpoint_code) failD941('D941_PEER_BUILD_ENDPOINT_MISMATCH', 'service build or endpoint differs from the verified binding')
      } else if (peer.executableSha256 !== null || peer.ipcEndpointCode !== null) failD941('D941_PEER_FACTS_INVALID', 'human identity must not invent service endpoint or executable facts')
      return Object.freeze({ identity_binding: { identity_bindings_record_digest_sha256: identity.record_digest_sha256, binding_set_code: identity.binding_set_code, binding_generation: identity.binding_generation, binding_code: binding.binding_code }, authority_roster_record_digest_sha256: authorityRoster.record_digest_sha256, actor_kind_code: assignment.actor_kind_code ?? 'human', role_code: assignment.role_code ?? roleCode, principal_code: assignment.principal_code })
  }

  const registry = Object.freeze({
    authorityContext,
    selectSynthetic({ actorSession, persistedAt = clock() } = {}) {
      const prior = events()
      if (prior.length !== 0) failD941('D941_AUTHORITY_ALREADY_SELECTED', 'authority selection is append-only and one-time')
      const event = appendEvent({
        eventKindCode: 'synthetic_selection_recorded',
        targetCode: 'd940_roster_adoption',
        actorSession,
        reasonCode: 'synthetic_test_selection_only',
        persistedAt,
      })
      return Object.freeze({ event, operational: false, activationStateCode: 'synthetic_unactivated' })
    },
    async revoke({ targetCode, actorSession, reasonCode = 'synthetic_revocation', persistedAt = clock() }) {
      if (destructiveLockHeld) failD941('D941_AUTHORITY_LOCKED', 'authority transitions are serialized behind the destructive operation lock')
      const lease = linuxEnforcement === null ? null : await linuxEnforcement.holdOperationLock({ rootPath: operationLockRootPath, relativePath: operationLockLeaf })
      try {
        assertD941AuthenticatedSession(actorSession, 'authority_transition')
        resolveAgainstVerifiedContext({ roleCode: actorSession?.actor?.role_code, bindingCode: actorSession?.actor?.identity_binding?.binding_code, peer: actorSession?.exchange ? { pid: actorSession.exchange.peer_pid, uid: actorSession.exchange.peer_uid, gid: actorSession.exchange.peer_gid, executableSha256: null, ipcEndpointCode: null } : null, at: persistedAt, requireSelection: true })
        return appendEvent({ eventKindCode: 'authority_target_revoked', targetCode, actorSession, reasonCode, persistedAt })
      } finally { if (lease) await lease.release() }
    },
    stateAt(at) {
      return currentState(at)
    },
    resolveActor({ roleCode, bindingCode, peer, at }) {
      return resolveAgainstVerifiedContext({ roleCode, bindingCode, peer, at, requireSelection: true })
    },
    resolveTransitionActor({ roleCode, bindingCode, peer, at }) {
      if (!['operational_witness', 'recovery_authority'].includes(roleCode)) failD941('D941_AUTHORITY_TRANSITION_ROLE_FORBIDDEN', 'role cannot perform authority transitions')
      if (roleCode === 'operational_witness') {
        const { verifiedGeneration, authorityRoster, authorityRosterAdoption } = authorityContext
        const identity = verifiedGeneration.identityBindings
        const binding = identity.bindings.find((item) => item.binding_code === bindingCode)
        const mapping = authorityRoster.human_identity_mappings.find((item) => item.binding_code === bindingCode && item.d901_runtime_role_code === 'operational_witness')
        if (!binding || !mapping || binding.runtime_role_code !== 'operational_witness' || binding.principal_kind_code !== 'human' ||
            !(identity.issued_at <= at && at < identity.expires_at && binding.valid_from <= at && at < binding.valid_until && authorityRoster.valid_from <= at && at < authorityRoster.valid_until && authorityRosterAdoption.adopted_at <= at) ||
            authorityRosterAdoption.identity_bindings_record_digest_sha256 !== identity.record_digest_sha256 || authorityRosterAdoption.authority_roster_record_digest_sha256 !== authorityRoster.record_digest_sha256 ||
            !peer || peer.uid !== binding.unix_uid || !Number.isSafeInteger(peer.pid) || peer.pid < 1 || peer.executableSha256 !== null || peer.ipcEndpointCode !== null) {
          failD941('D941_ACTOR_UNQUALIFIED', 'selection requires the exact current D9.0.1 operational witness and adopted D9.4 authority generation')
        }
        return Object.freeze({ identity_binding: { identity_bindings_record_digest_sha256: identity.record_digest_sha256, binding_set_code: identity.binding_set_code, binding_generation: identity.binding_generation, binding_code: binding.binding_code }, authority_roster_record_digest_sha256: authorityRoster.record_digest_sha256, actor_kind_code: 'human', role_code: 'operational_witness', principal_code: mapping.principal_code })
      }
      return resolveAgainstVerifiedContext({ roleCode, bindingCode, peer, at, requireSelection: roleCode !== 'operational_witness' })
    },
    revalidateSession(session, at) {
      assertD941AuthenticatedSession(session)
      const service = session.actor.actor_kind_code === 'service'
      const resolved = resolveAgainstVerifiedContext({ roleCode: session.actor.role_code, bindingCode: session.actor.identity_binding.binding_code, at, requireSelection: true, peer: { pid: session.exchange.peer_pid, uid: session.exchange.peer_uid, gid: session.exchange.peer_gid, executableSha256: service ? session.exchange.executableSha256 ?? authorityContext.verifiedGeneration.identityBindings.bindings.find((item) => item.binding_code === session.actor.identity_binding.binding_code).executable_sha256 : null, ipcEndpointCode: service ? session.exchange.authenticatedEndpointCode : null } })
      if (canonicalize(resolved) !== canonicalize(session.actor)) failD941('D941_SESSION_ACTOR_DRIFT', 'authenticated session actor no longer matches the exact verified binding')
      return resolved
    },
    claimAuthenticationNonce({ nonce, claimedAt }) {
      if (!/^[0-9a-f]{64}$/u.test(nonce)) failD941('D941_NONCE_INVALID', 'authentication nonce is invalid')
      timestamp(claimedAt, 'nonce claim time')
      const recordCode = `auth-nonce-${nonce}`
      if (store.inventory().projection.authority.some((item) => item.record_code === recordCode)) failD941('D941_NONCE_REPLAY', 'authentication nonce was already consumed, including before restart')
      const record = seal({ format: 'jedi-atlas-d941-authentication-nonce-claim', format_version: '1.0.0', record_code: recordCode, nonce, claimed_at: claimedAt, activation_boundary_code: 'synthetic_unactivated_test_runtime_only', record_digest_sha256: null })
      store.append({ namespaceCode: 'authority', recordCode, bytes: durableJsonBytes(record), replayKey: recordCode })
      return record
    },
    events,
    head() {
      const current = events().at(-1) ?? null
      return Object.freeze({ sequence: current?.sequence ?? 0, digest: current?.record_digest_sha256 ?? null, persistedAt: current?.persisted_at ?? null })
    },
    close() {},
  })
  registries.add(registry)
  lockConfigurations.set(registry, Object.freeze({ linuxEnforcement, operationLockRootPath, operationLockLeaf }))
  lockStates.set(registry, Object.freeze({ get: () => destructiveLockHeld, set: (held) => { destructiveLockHeld = held } }))
  return registry
}

export function assertD941AuthorityLockBinding(registry, expected) {
  assertD941AuthorityRegistry(registry)
  const actual = lockConfigurations.get(registry)
  if (!actual || actual.linuxEnforcement !== expected.linuxEnforcement || actual.operationLockRootPath !== expected.operationLockRootPath || actual.operationLockLeaf !== expected.operationLockLeaf) {
    failD941('D941_AUTHORITY_LOCK_IDENTITY_MISMATCH', 'authority registry and journal broker do not share one verified native operation-lock identity')
  }
  return true
}

export function setD941DestructiveLockHeld(registry, held) {
  assertD941AuthorityRegistry(registry)
  if (typeof held !== 'boolean') failD941('D941_AUTHORITY_INPUT_INVALID', 'lock state must be boolean')
  const state = lockStates.get(registry)
  if (!state) failD941('D941_AUTHORITY_LOCK_IDENTITY_MISMATCH', 'authority registry has no protected lock state')
  // The broker is the only caller in this module boundary; the registry's
  // own revoke path also uses the same kernel lock and checks this state.
  state.set(held)
}

export function assertD941AuthorityRegistry(value) {
  if (!registries.has(value)) failD941('D941_AUTHORITY_REGISTRY_UNTRUSTED', 'authority registry was not created by the fixed factory')
  return value
}
