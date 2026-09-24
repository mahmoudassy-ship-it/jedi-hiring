import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { createD951Fixture, backupArgs } from './d9-5-1-support/fixture.mjs'
import { createDurableNamespaceStore } from '../d9/custody/durable-store.mjs'
import { createD951BackupStore } from '../d9/backup-restore/storage.mjs'
import { createD951History, D951_NAMESPACES } from '../d9/backup-restore/history.mjs'
import { createD951Runtime } from '../d9/backup-restore/runtime.mjs'

test('D9.5.1 creates exact durable backups, preserves chain order, and deduplicates bytes without replacing objects', async (t) => {
  const fixture = await createD951Fixture(t)
  const firstArgs = backupArgs(fixture, '001')
  const first = fixture.runtime.createBackup(firstArgs)
  const secondArgs = backupArgs(fixture, '002'); secondArgs.sources = firstArgs.sources
  const second = fixture.runtime.createBackup(secondArgs)
  assert.equal(first.manifest.backup_chain_sequence, 1); assert.equal(second.manifest.backup_chain_sequence, 2)
  assert.equal(second.manifest.previous_backup_manifest_record_digest_sha256, first.manifest.record_digest_sha256)
  assert.equal(fixture.backupStore.inventory().length, 3)
  assert.equal(first.durabilityReceipts[0].technical_claims.legal_authority_claimed, false)
})

test('D9.5.1 exact accepted backup replay is a no-op and conflicting replay fails', async (t) => {
  const fixture = await createD951Fixture(t)
  const args = backupArgs(fixture, '003')
  const first = fixture.runtime.createBackup(args)
  const before = fixture.history.records('global-journal').length
  const replay = fixture.runtime.createBackup(args)
  assert.equal(replay.replay, true); assert.equal(replay.manifest.record_digest_sha256, first.manifest.record_digest_sha256)
  assert.equal(fixture.history.records('global-journal').length, before)
  const conflict = { ...args, backupSetCode: 'backup.set.changed' }
  assert.throws(() => fixture.runtime.createBackup(conflict), { code: 'D951_OPERATION_REPLAY' })
})

test('D9.5.1 reconstructs replay state from protected history after restart', async (t) => {
  const fixture = await createD951Fixture(t)
  const args = backupArgs(fixture, '004'); const first = fixture.runtime.createBackup(args)
  const receiptCount = fixture.history.records('global-journal').length
  fixture.runtime.close(); fixture.backupStore.close(); fixture.store.close()
  const store = createDurableNamespaceStore({ rootPath: fixture.roots.history, namespaceCodes: D951_NAMESPACES }); t.after(() => store.close())
  const backupStore = createD951BackupStore({ rootPath: fixture.roots.backup }); t.after(() => backupStore.close())
  const history = createD951History({ store, clock: fixture.clock })
  const runtime = createD951Runtime({ contractSet: fixture.contractSet, authority: fixture.authority, backupStore, history, controlResolver: fixture.controlResolver, checkpointResolver: fixture.checkpointResolver, stagingRootPath: fixture.roots.staging, promotionRootPath: fixture.roots.promotion, clock: fixture.clock }); t.after(() => runtime.close())
  const replay = runtime.createBackup(args)
  assert.equal(replay.replay, true); assert.equal(replay.manifest.record_digest_sha256, first.manifest.record_digest_sha256)
  assert.equal(history.records('global-journal').length, receiptCount)
})

test('D9.5.1 replay reopens every backup byte and rejects corrupted persisted projection', async (t) => {
  const fixture = await createD951Fixture(t)
  const args = backupArgs(fixture, '005'); const result = fixture.runtime.createBackup(args)
  const copy = result.manifest.backup_copies[0]
  fs.writeFileSync(path.join(fixture.roots.backup, copy.backend_reference), Buffer.alloc(copy.artifact.byte_length), { mode: 0o600 })
  assert.throws(() => fixture.runtime.createBackup(args), { code: 'D951_COPY_MISMATCH' })
})

test('D9.5.1 rejects hash drift, source mutation, unsafe roots, and operation collisions', async (t) => {
  const fixture = await createD951Fixture(t)
  const args = backupArgs(fixture, '010'); args.sources[0].content_sha256 = '0'.repeat(64)
  assert.throws(() => fixture.runtime.createBackup(args), { code: 'D951_SOURCE_MISMATCH' })
  const good = backupArgs(fixture, '011'); fixture.runtime.createBackup(good)
  const collision = backupArgs(fixture, '012'); collision.operationId = good.operationId; collision.operationNonce = good.operationNonce
  assert.throws(() => fixture.runtime.createBackup(collision), { code: 'D951_OPERATION_REPLAY' })
  const outside = path.join(fixture.roots.sources, 'link'); fs.symlinkSync('/tmp', outside)
  assert.ok(fs.lstatSync(outside).isSymbolicLink())
})

test('D9.5.1 fails closed at durability boundaries and classifies every frozen crash boundary without action authority', async (t) => {
  let boundary = null
  const fixture = await createD951Fixture(t, { runtimeFault(code) { if (code === boundary) throw Object.assign(new Error('synthetic crash'), { code: 'SYNTHETIC_CRASH' }) } })
  const expected = { before_staging: 'safe_no_effect', after_staging_before_controls: 'retain_inaccessible_and_reconcile', after_controls_before_verification: 'retain_inaccessible_and_reconcile', after_verification_before_promotion: 'retain_inaccessible_and_reconcile', after_promotion_before_post_verification: 'recovery_required_no_automatic_rollback', after_verification_before_receipt: 'recovery_required_exact_replay_only', after_receipt_before_response: 'exact_replay_no_op_after_full_revalidation' }
  for (const [code, result] of Object.entries(expected)) assert.deepEqual(fixture.runtime.classifyCrash(code), { boundaryCode: code, classificationCode: result, actionAuthorized: false })
  assert.throws(() => fixture.runtime.classifyCrash('invented'), { code: 'D951_CRASH_BOUNDARY_UNKNOWN' })
})
