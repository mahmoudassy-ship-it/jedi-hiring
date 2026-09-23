import assert from 'node:assert/strict'
import { test } from 'node:test'

import { createD941AdministrativeLauncher, D941_ADMIN_SCOPES } from '../d9/restriction/admin-launcher.mjs'
import { createD941LedgerBroker } from '../d9/restriction/ledger.mjs'
import { createD941Fixture, humanSession, makeControlRecord, serviceSession, subjectFor } from './d9-4-1-support/fixture.mjs'

test('D9.4.1 verifies frozen authority and selects only synthetic unactivated state', async (t) => {
  const fixture = await createD941Fixture(t)
  const state = fixture.registry.stateAt('2030-01-01T00:10:01.000Z')
  assert.equal(state.selected.activation_boundary_code, 'synthetic_unactivated_test_runtime_only')
  assert.equal(fixture.authorityContext.operationalProfile.settings.operational_execution_code, 'unimplemented')
})

test('administrative scopes remain closed and disjoint from frozen importer slots', () => {
  const frozen = new Set(['runtime_profile', 'identity_bindings', 'reviewed_root', 'handoff_registry', 'staging_root', 'custody_root', 'candidate_database', 'canonical_database', 'operation_journal'])
  for (const scope of Object.values(D941_ADMIN_SCOPES)) for (const grant of scope.grants) assert.equal(frozen.has(grant.slot_code), false)
})

test('journal broker rejects an authority registry bound to a different native lock identity', async (t) => {
  const fixture = await createD941Fixture(t)
  assert.throws(() => createD941LedgerBroker({ store: fixture.store, authorityContext: fixture.authorityContext, authorityRegistry: fixture.registry, clock: fixture.time.clock, linuxEnforcement: fixture.linux, operationLockRootPath: fixture.roots.handle }), /D941_AUTHORITY_LOCK_IDENTITY_MISMATCH/)
})

test('kernel-authenticated service launch checks peer, build, endpoint, grants and replay', async (t) => {
  const fixture = await createD941Fixture(t)
  const session = await serviceSession(fixture, 'deletion_execution', 'custody_adapter')
  assert.equal(session.actor.role_code, 'deletion_executor')
  assert.equal(session.exchange.termination_confirmed, true)
  await assert.rejects(serviceSession(fixture, 'deletion_execution', 'independent_verifier'), /D941_LAUNCH_BINDING_MISMATCH/)
  await assert.rejects(serviceSession(fixture, 'deletion_execution', 'custody_adapter', undefined, { suppliedGrants: [] }), /D941_SCOPE_SUBSTITUTION/)
  const nonce = 'a'.repeat(64)
  await serviceSession(fixture, 'independent_verification', 'independent_verifier', undefined, { nonce })
  await assert.rejects(serviceSession(fixture, 'independent_verification', 'independent_verifier', undefined, { nonce }), /D941_NONCE_REPLAY/)
})

test('identity and roster revocation is fail closed', async (t) => {
  const fixture = await createD941Fixture(t)
  const staleJournal = await serviceSession(fixture, 'control_submission', 'journal_broker')
  const staleActor = await humanSession(fixture, 'security_authority', 'recovery_operator')
  const revoker = await fixture.launcher.authenticateAuthorityTransition({ roleCode: 'recovery_authority', bindingCode: fixture.byRole.get('recovery_operator').binding_code, at: '2030-01-01T00:10:02.000Z' })
  await fixture.registry.revoke({ targetCode: 'd940_authority_roster', actorSession: revoker, persistedAt: '2030-01-01T00:10:02.000Z' })
  await assert.rejects(serviceSession(fixture, 'control_submission', 'journal_broker', '2030-01-01T00:10:03.000Z'), /D941_AUTHORITY_REVOKED/)
  const persistedAt = fixture.time.reserve(3_000)
  const record = makeControlRecord({ fixture, kind: 'restriction_imposed', code: 'control.after-revoke.001', operationId: 'operation.after-revoke.001', nonce: 'f'.repeat(64), subject: subjectFor().subject, semanticActor: staleActor.actor, persistenceActor: staleJournal.actor, sequence: 1, effectiveAt: persistedAt, recordedAt: persistedAt, persistedAt })
  await assert.rejects(fixture.broker.append({ record, semanticSession: staleActor, persistenceSession: staleJournal }), /D941_AUTHORITY_REVOKED/)
})

test('authority transitions reject raw actors and wrong authenticated roles', async (t) => {
  const fixture = await createD941Fixture(t)
  const service = await serviceSession(fixture, 'control_submission', 'journal_broker')
  await assert.rejects(fixture.registry.revoke({ targetCode: 'd940_authority_roster', actorSession: service, persistedAt: '2030-01-01T00:10:02.000Z' }), /D941_SESSION_SCOPE_MISMATCH/)
  await assert.rejects(fixture.registry.revoke({ targetCode: 'd940_authority_roster', actorSession: { actor: { role_code: 'recovery_authority' } }, persistedAt: '2030-01-01T00:10:02.000Z' }), /D941_SESSION_UNTRUSTED/)
  const revoker = await fixture.launcher.authenticateAuthorityTransition({ roleCode: 'recovery_authority', bindingCode: fixture.byRole.get('recovery_operator').binding_code, at: '2030-01-01T00:10:00.000Z' })
  await assert.rejects(fixture.registry.revoke({ targetCode: 'd940_authority_roster', actorSession: revoker, persistedAt: '2030-01-01T00:10:04.000Z' }), /D941_AUTHORITY_TIME_FUTURE/)
})

test('authentication nonce claims survive launcher reconstruction', async (t) => {
  const fixture = await createD941Fixture(t); const nonce = 'b'.repeat(64)
  await serviceSession(fixture, 'control_submission', 'journal_broker', undefined, { nonce })
  const restarted = createD941AdministrativeLauncher({ authorityRegistry: fixture.registry, linuxEnforcement: fixture.linux, handleRootPath: fixture.roots.handle, trustedClock: () => '2030-01-01T00:10:00.000Z', maxFutureSkewMs: 5_000 })
  await assert.rejects(restarted.authenticateService({ scopeCode: 'control_submission', bindingCode: fixture.byRole.get('journal_broker').binding_code, at: '2030-01-01T00:10:01.000Z', nonce }), /D941_NONCE_REPLAY/)
})

test('expired actors and peer/build substitution fail closed', async (t) => {
  const fixture = await createD941Fixture(t)
  await assert.rejects(serviceSession(fixture, 'control_submission', 'journal_broker', '2020-01-01T00:00:00.000Z'), /D941_TRUSTED_TIME_BACKDATE/)
  await assert.rejects(serviceSession(fixture, 'control_submission', 'journal_broker', '2030-01-03T00:00:00.000Z'), /D941_(AUTHORITY_EXPIRED|TRUSTED_TIME_FUTURE)/)
  await assert.rejects(serviceSession(fixture, 'control_submission', 'journal_broker', undefined, { scenario: 'build_substitution' }), /D941_IPC_AUTHENTICATION_FAILED/)
  await assert.rejects(serviceSession(fixture, 'control_submission', 'journal_broker', undefined, { scenario: 'spoof_uid' }), /D941_IPC_AUTHENTICATION_FAILED/)
})

test('authenticated actor bindings are deeply immutable and cannot be substituted after issuance', async (t) => {
  const fixture = await createD941Fixture(t)
  const session = await serviceSession(fixture, 'control_submission', 'journal_broker')
  assert.equal(Object.isFrozen(session.actor.identity_binding), true)
  assert.throws(() => { session.actor.identity_binding.binding_code = 'binding.attacker' }, TypeError)
  assert.throws(() => { session.exchange.authenticatedEndpointCode = 'ipc.attacker' }, TypeError)
})
