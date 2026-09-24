import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'
import { createD951Fixture, backupArgs, authorizationArgs, restoreArgs } from './d9-5-1-support/fixture.mjs'

test('D9.5.1 reconstructs inaccessible bytes, applies controls, verifies, and atomically promotes synthetic state', async (t) => {
  const fixture = await createD951Fixture(t)
  const backup = fixture.runtime.createBackup(backupArgs(fixture, '101'))
  const authorization = fixture.runtime.authorizeRestore(authorizationArgs(fixture, backup.manifest, '101'))
  const restored = fixture.runtime.restore(restoreArgs(fixture, backup.manifest, authorization))
  assert.equal(restored.outcomeCode, 'succeeded'); assert.equal(restored.lifecycle.length, 10)
  assert.deepEqual(restored.lifecycle.map((item) => item.stage_code), ['authorized', 'staging_started', 'bytes_reconstructed_inaccessible', 'controls_revalidated', 'controls_applied', 'staged_state_verified', 'promotion_started', 'promoted', 'post_promotion_verified', 'completed'])
  assert.ok(fs.existsSync(restored.promotedPath)); assert.equal(restored.lifecycle.at(-1).technical_claims.complete_erasure_claimed, false)
  assert.ok(Object.isFrozen(backup.manifest.technical_claims)); assert.throws(() => { backup.manifest.technical_claims.legal_authority_claimed = true }, TypeError)
  const replay = fixture.runtime.restore(restoreArgs(fixture, backup.manifest, authorization))
  assert.equal(replay.replay, true); assert.equal(replay.recoveryCode, 'exact_replay_no_op_after_full_revalidation')
  assert.equal(fixture.runtime.inspectRestoreRecovery(authorization.operation_id).classificationCode, 'exact_replay_no_op_after_full_revalidation')
})

test('D9.5.1 blocks restore on hold/tombstone, changing controls, expiry, and identity substitutions', async (t) => {
  const fixture = await createD951Fixture(t)
  const backup = fixture.runtime.createBackup(backupArgs(fixture, '102'))
  const authorization = fixture.runtime.authorizeRestore(authorizationArgs(fixture, backup.manifest, '102'))
  fixture.controlResolver.replaceForSyntheticTest(fixture.controlState('do_not_restore'))
  assert.equal(fixture.runtime.restore(restoreArgs(fixture, backup.manifest, authorization)).outcomeCode, 'withheld')
  fixture.controlResolver.replaceForSyntheticTest(fixture.controlState('apply_tombstone_before_restore', 3))
  assert.equal(fixture.runtime.restore(restoreArgs(fixture, backup.manifest, authorization)).outcomeCode, 'withheld')
  fixture.controlResolver.replaceForSyntheticTest(fixture.controlState('apply_restriction_before_restore', 4))
  const restricted = fixture.runtime.restore(restoreArgs(fixture, backup.manifest, authorization))
  assert.equal(restricted.outcomeCode, 'withheld'); assert.equal(restricted.recoveryCode, 'restriction_enforcement_unimplemented_fail_closed')
  const substituted = structuredClone(authorization); substituted.target_environment_identity_sha256 = '8'.repeat(64)
  const substitutedArgs = restoreArgs(fixture, backup.manifest, substituted)
  assert.throws(() => fixture.runtime.restore(substitutedArgs), { code: 'D951_RECORD_DIGEST_INVALID' })
  const forged = { ...structuredClone(authorization), record_code: 'restore-authorization-forged', record_digest_sha256: authorization.record_digest_sha256 }
  assert.throws(() => fixture.runtime.restore(restoreArgs(fixture, backup.manifest, forged)), { code: 'D951_RECORD_DIGEST_INVALID' })
  const loaded = fixture.history.records('backup-manifests')[0]
  assert.throws(() => { loaded.backup_copies[0].artifact.sha256 = '0'.repeat(64) }, TypeError)
})

test('D9.5.1 enforces distinct humans, service separation, seven-class inventory, and never claims complete erasure', async (t) => {
  const fixture = await createD951Fixture(t)
  const backup = fixture.runtime.createBackup(backupArgs(fixture, '103'))
  const bad = authorizationArgs(fixture, backup.manifest, '103'); bad.approvalRecords[1] = bad.approvalRecords[0]
  assert.throws(() => fixture.runtime.authorizeRestore(bad), { code: 'D951_APPROVALS_INVALID' })
  const states = ['primary', 'backup', 'derived', 'temporary', 'replica', 'open_descriptor', 'unknown'].map((copy_class_code) => ({ copy_class_code, state_code: copy_class_code === 'backup' ? 'present' : 'absent_verified' }))
  const inventory = fixture.runtime.inventoryCopyClasses(states)
  assert.equal(inventory.completeErasureClaimed, false)
  assert.throws(() => fixture.runtime.inventoryCopyClasses(states.slice(1)), { code: 'D951_COPY_INVENTORY_INCOMPLETE' })
})

test('D9.5.1 fault injection fails closed at every restore persistence and promotion boundary', async (t) => {
  let selected = null
  const fixture = await createD951Fixture(t, { runtimeFault(code) { if (code === selected) throw Object.assign(new Error(`crash at ${code}`), { code: 'SYNTHETIC_CRASH' }) } })
  const { manifest } = fixture.runtime.createBackup(backupArgs(fixture, '104'))
  const stages = ['authorized', 'staging_started', 'bytes_reconstructed_inaccessible', 'controls_revalidated', 'controls_applied', 'staged_state_verified', 'promotion_started', 'promoted', 'post_promotion_verified', 'completed']
  for (const [index, stage] of stages.entries()) {
    selected = `after_${stage}`
    const suffix = `104${index}`
    const authorization = fixture.runtime.authorizeRestore(authorizationArgs(fixture, manifest, suffix))
    const args = restoreArgs(fixture, manifest, authorization)
    assert.throws(() => fixture.runtime.restore(args), { code: 'SYNTHETIC_CRASH' })
    const promoted = fs.readdirSync(fixture.roots.promotion).some((name) => name.startsWith('generation-'))
    assert.equal(promoted, index >= 7, `promotion visibility at ${stage}`)
    if (stage === 'completed') {
      selected = null
      assert.equal(fixture.runtime.inspectRestoreRecovery(authorization.operation_id).classificationCode, 'recovery_required_no_automatic_rollback')
      assert.throws(() => fixture.runtime.restore(args), { code: 'D951_RECOVERY_REQUIRED' })
    }
  }
})
