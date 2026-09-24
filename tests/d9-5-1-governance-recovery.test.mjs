import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'
import { createD951Fixture, backupArgs, authorizationArgs, restoreArgs } from './d9-5-1-support/fixture.mjs'

const COPY_STATES = ['primary', 'backup', 'derived', 'temporary', 'replica', 'open_descriptor', 'unknown'].map((copy_class_code) => ({ copy_class_code, state_code: copy_class_code === 'backup' ? 'present' : 'absent_verified' }))

test('D9.5.1 persists retention heads, bounded deletion-aware evidence, and deterministic drill outcomes', async (t) => {
  const fixture = await createD951Fixture(t)
  const { manifest } = fixture.runtime.createBackup(backupArgs(fixture, '201'))
  const retention = fixture.runtime.recordRetention({ manifest, decisionCode: 'retain', retainUntil: '2031-01-01T00:00:00.000Z', holdStateCode: 'none', reasonCode: 'synthetic_policy', authoritySession: fixture.sessions.get('legal_records_authority'), persistenceSession: fixture.sessions.get('persistence_broker') })
  const head = fixture.runtime.attestRetentionHead({ manifest, operationId: 'retention.attest.201', operationNonce: '2'.repeat(64), verifierSession: fixture.sessions.get('control_state_verifier'), persistenceSession: fixture.sessions.get('persistence_broker') })
  assert.equal(head.head_record_digest_sha256, retention.record_digest_sha256)
  const assessment = fixture.runtime.assessDeletionAware({ operationId: 'deletion.aware.201', operationNonce: '3'.repeat(64), manifest, copyClassStates: COPY_STATES, verifierSession: fixture.sessions.get('control_state_verifier'), persistenceSession: fixture.sessions.get('persistence_broker') })
  assert.equal(assessment.complete_erasure_claimed, false); assert.equal(assessment.bytes_accessible, false)
  const passed = fixture.runtime.recordDrill({ drillCode: 'synthetic.201', manifest, expectedInventoryDigestSha256: manifest.source_inventory_digest_sha256, observedInventoryDigestSha256: manifest.source_inventory_digest_sha256, schedulerSession: fixture.sessions.get('drill_scheduler'), verifierSession: fixture.sessions.get('restored_state_verifier'), persistenceSession: fixture.sessions.get('persistence_broker') })
  const failed = fixture.runtime.recordDrill({ drillCode: 'synthetic.202', manifest, expectedInventoryDigestSha256: manifest.source_inventory_digest_sha256, observedInventoryDigestSha256: 'f'.repeat(64), schedulerSession: fixture.sessions.get('drill_scheduler'), verifierSession: fixture.sessions.get('restored_state_verifier'), persistenceSession: fixture.sessions.get('persistence_broker') })
  assert.equal(passed.outcome_code, 'passed'); assert.equal(failed.outcome_code, 'failed'); assert.equal(failed.escalation_code, 'reconciliation_required')
})

test('D9.5.1 fails closed when control state moves between reconstruction and promotion', async (t) => {
  let fixture
  fixture = await createD951Fixture(t, { runtimeFault(code) {
    if (code === 'after_controls_applied') fixture.controlResolver.replaceForSyntheticTest({ head_sequence: 2, head_digest_sha256: 'd'.repeat(64), directives: [{ directive_code: 'apply_tombstone_before_restore', basis_record_digest_sha256: 'e'.repeat(64) }] })
  } })
  const { manifest } = fixture.runtime.createBackup(backupArgs(fixture, '203'))
  const authorization = fixture.runtime.authorizeRestore(authorizationArgs(fixture, manifest, '203'))
  assert.throws(() => fixture.runtime.restore(restoreArgs(fixture, manifest, authorization)), { code: 'D951_CONTROL_MOVED' })
  assert.equal(fs.readdirSync(fixture.roots.promotion).length, 0)
  assert.equal(fs.readdirSync(fixture.roots.staging).length, 1)
})

test('D9.5.1 detects backup corruption, wrong references, missing bytes, and does not expose staged bytes', async (t) => {
  const fixture = await createD951Fixture(t)
  const { manifest } = fixture.runtime.createBackup(backupArgs(fixture, '204'))
  const copy = manifest.backup_copies[0]
  assert.throws(() => fixture.backupStore.read({ identity: copy.artifact, backendReference: 'objects/' + '0'.repeat(64) }), { code: 'D951_REFERENCE_MISMATCH' })
  const objectPath = `${fixture.roots.backup}/${copy.backend_reference}`
  fs.writeFileSync(objectPath, Buffer.alloc(copy.artifact.byte_length), { mode: 0o600 })
  assert.throws(() => fixture.backupStore.read({ identity: copy.artifact, backendReference: copy.backend_reference }), { code: 'D951_COPY_MISMATCH' })
})

test('D9.5.1 leaves target-without-receipt state classification-only after response-loss boundary', async (t) => {
  let fail = true
  const fixture = await createD951Fixture(t, { storeFault(stage, context) { if (fail && stage === 'after_directory_sync' && context.namespaceCode === 'backup-manifests') { fail = false; throw Object.assign(new Error('response lost'), { code: 'SYNTHETIC_RESPONSE_LOSS' }) } } })
  const args = backupArgs(fixture, '205')
  assert.throws(() => fixture.runtime.createBackup(args), /response lost/u)
  assert.throws(() => fixture.store.inventory(), { code: 'D931_STORE_RECOVERY_REQUIRED' })
  assert.throws(() => fixture.runtime.createBackup(args), { code: 'D931_STORE_RECOVERY_REQUIRED' })
})

test('D9.5.1 rejects peer, build, endpoint, role, and process substitutions', async (t) => {
  const fixture = await createD951Fixture(t)
  const binding = fixture.byRole.get('backup_adapter')
  const base = { semanticRoleCode: 'backup_producer', bindingCode: binding.binding_code, processInstanceCode: 'process.spoof.001', authenticatedAt: fixture.clock() }
  await assert.rejects(() => fixture.authority.authenticate({ ...base, scenario: 'spoof_uid' }), { code: 'D951_PEER_MISMATCH' })
  await assert.rejects(() => fixture.authority.authenticate({ ...base, scenario: 'build_substitution' }), { code: 'D951_PEER_MISMATCH' })
  await assert.rejects(() => fixture.authority.authenticate({ ...base, semanticRoleCode: 'restore_executor' }), { code: 'D951_IDENTITY_MISMATCH' })
})
