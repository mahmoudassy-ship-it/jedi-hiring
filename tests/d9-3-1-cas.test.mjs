import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { createRestrictedLocalCas, custodyReferenceFor } from '../d9/custody/cas.mjs'
import { sha256Bytes } from '../d9/control-plane/canonical.mjs'
import { createD931Fixture } from './d9-3-1-support/fixture.mjs'

const nonce = '34'.repeat(32)

test('restricted CAS prepares, verifies, publishes without replacement, and reopens exact bytes', async (t) => {
  const fixture = await createD931Fixture(t)
  const cas = createRestrictedLocalCas({ protectedRootPath: fixture.casRoot })
  t.after(() => cas.close())
  const source = fs.openSync(path.join(fixture.stagingRoot, fixture.handoff.staged_path), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  t.after(() => fs.closeSync(source))
  const prepared = cas.prepare({ operationId: 'operation.synthetic.cas1', operationNonce: nonce, artifact: fixture.artifact, sourceDescriptor: source })
  const verified = cas.verifyPrepared(prepared)
  const published = cas.publishNoReplace(verified)
  assert.deepEqual(published, {
    backendCode: 'pilot_local_cas_v1', backendReference: custodyReferenceFor(fixture.artifact), dispositionCode: 'created_new', outcomeCode: 'published',
    fileDataSynced: true, parentDirectorySynced: true, fanoutAncestorsPreprovisionedAndSynced: true, noReplaceEnforced: true, reopenedAndRehashed: true,
  })
  const descriptor = cas.openIntegrity({ artifact: fixture.artifact, backendReference: published.backendReference })
  assert.deepEqual(fs.readFileSync(descriptor), fs.readFileSync(path.join(fixture.stagingRoot, fixture.handoff.staged_path)))
  fs.closeSync(descriptor)
  assert.equal(cas.inventory().length, 1)
})

test('restricted CAS returns existing_exact and rejects key collisions, links, and substituted fanout', async (t) => {
  const fixture = await createD931Fixture(t)
  const cas = createRestrictedLocalCas({ protectedRootPath: fixture.casRoot })
  t.after(() => cas.close())
  const sourcePath = path.join(fixture.stagingRoot, fixture.handoff.staged_path)
  const publish = (operationId) => {
    const fd = fs.openSync(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    try { return cas.publishNoReplace(cas.verifyPrepared(cas.prepare({ operationId, operationNonce: nonce, artifact: fixture.artifact, sourceDescriptor: fd }))) } finally { fs.closeSync(fd) }
  }
  publish('operation.synthetic.cas2')
  assert.equal(publish('operation.synthetic.cas3').outcomeCode, 'reused_verified')

  const final = path.join(fixture.casRoot, custodyReferenceFor(fixture.artifact))
  const extra = path.join(path.dirname(final), 'extra-link')
  fs.linkSync(final, extra)
  assert.throws(() => cas.verifyExisting({ artifact: fixture.artifact, backendReference: custodyReferenceFor(fixture.artifact) }), /D931_CAS_OBJECT_REJECTED/)
  fs.unlinkSync(extra)

  const original = fs.readFileSync(final)
  const corrupted = Buffer.from(original)
  corrupted[0] ^= 1
  fs.writeFileSync(final, corrupted)
  assert.throws(() => cas.inventory(), /D931_CAS_INVENTORY_CORRUPT/)
  fs.writeFileSync(final, original)

  const fanout = path.dirname(final)
  const externalFanout = `${fixture.casRoot}.fanout-real`
  fs.renameSync(fanout, externalFanout)
  fs.symlinkSync(externalFanout, fanout)
  t.after(() => fs.rmSync(externalFanout, { recursive: true, force: true }))
  assert.throws(() => cas.verifyExisting({ artifact: fixture.artifact, backendReference: custodyReferenceFor(fixture.artifact) }), /D931_CAS_PATH_REJECTED/)
  const fd = fs.openSync(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  const prepared = cas.verifyPrepared(cas.prepare({ operationId: 'operation.synthetic.cas.path-drift', operationNonce: nonce, artifact: fixture.artifact, sourceDescriptor: fd }))
  fs.closeSync(fd)
  assert.throws(() => cas.publishNoReplace(prepared), /D931_CAS_PATH_REJECTED/)
  assert.throws(() => cas.inventory(), /D931_CAS_RECOVERY_REQUIRED/)
})

test('restricted CAS fault boundaries never replace an existing exact object', async (t) => {
  const fixture = await createD931Fixture(t)
  const sourcePath = path.join(fixture.stagingRoot, fixture.handoff.staged_path)
  for (const point of ['after_temporary_write', 'after_temporary_sync', 'before_publish', 'after_no_replace_publish', 'after_file_sync', 'after_parent_sync']) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-fault-'))
    fs.chmodSync(root, 0o700)
    const cas = createRestrictedLocalCas({ protectedRootPath: root, faultInjector(actual) { if (actual === point) throw new Error(`synthetic crash ${point}`) } })
    const fd = fs.openSync(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    assert.throws(() => {
      const p = cas.prepare({ operationId: `operation.synthetic.${point}`, operationNonce: nonce, artifact: fixture.artifact, sourceDescriptor: fd })
      const v = cas.verifyPrepared(p)
      cas.publishNoReplace(v)
    }, /synthetic crash/)
    fs.closeSync(fd)
    const retryFd = fs.openSync(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    assert.throws(() => cas.prepare({ operationId: `operation.synthetic.${point}.retry`, operationNonce: nonce, artifact: fixture.artifact, sourceDescriptor: retryFd }), /D931_CAS_RECOVERY_REQUIRED/)
    assert.throws(() => cas.inventory(), /D931_CAS_RECOVERY_REQUIRED/)
    fs.closeSync(retryFd)
    cas.close()
    const reopened = createRestrictedLocalCas({ protectedRootPath: root })
    const crashState = reopened.inspectCrashState()
    if (['after_no_replace_publish', 'after_file_sync', 'after_parent_sync'].includes(point)) {
      assert.equal(crashState.stateCode, 'ambiguous_published_with_linked_temporary')
      assert.equal(crashState.actionExecutionCode, 'none_classification_only')
      assert.equal(crashState.temporaries.length, 1)
      assert.equal(crashState.published.length, 1)
      assert.equal(crashState.temporaries[0].inode, crashState.published[0].inode)
    } else if (['after_temporary_write', 'after_temporary_sync', 'before_publish'].includes(point)) {
      assert.equal(crashState.stateCode, 'temporary_present')
    }
    if (crashState.stateCode !== 'stable') assert.throws(() => reopened.openIntegrity({ artifact: fixture.artifact, backendReference: custodyReferenceFor(fixture.artifact) }), /D931_CAS_RECOVERY_REQUIRED/)
    reopened.close()
    fs.rmSync(root, { force: true, recursive: true })
  }
})

test('restricted CAS rejects every operation after its root descriptor is closed and reused', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-close-'))
  fs.chmodSync(root, 0o700)
  const cas = createRestrictedLocalCas({ protectedRootPath: root })
  const rootReal = fs.realpathSync(root)
  const rootFd = fs.readdirSync('/proc/self/fd').map(Number).find((fd) => (() => { try { return fs.realpathSync(`/proc/self/fd/${fd}`) === rootReal } catch { return false } })())
  assert.ok(Number.isInteger(rootFd))
  cas.close()
  const substitute = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-substitute-'))
  fs.chmodSync(substitute, 0o700)
  const substituteFd = fs.openSync(substitute, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
  assert.equal(substituteFd, rootFd, 'the closed CAS descriptor must be reused for the adversarial substitute')
  for (const operation of [
    () => cas.inventory(),
    () => cas.inspectCrashState(),
    () => cas.verifyExisting({ artifact: { byte_layer_code: 'retrieved_body', hash_algorithm_code: 'sha256', sha256: '00'.repeat(32), byte_length: 1 }, backendReference: `objects/sha256/00/${'00'.repeat(32)}` }),
    () => cas.openIntegrity({ artifact: { byte_layer_code: 'retrieved_body', hash_algorithm_code: 'sha256', sha256: '00'.repeat(32), byte_length: 1 }, backendReference: `objects/sha256/00/${'00'.repeat(32)}` }),
  ]) assert.throws(operation, /D931_CAS_CLOSED/)
  fs.closeSync(substituteFd)
  fs.rmSync(root, { recursive: true, force: true })
  fs.rmSync(substitute, { recursive: true, force: true })
})

test('restricted CAS closes its protected root descriptor when construction fails', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-constructor-'))
  fs.chmodSync(root, 0o700)
  const prepared = createRestrictedLocalCas({ protectedRootPath: root })
  prepared.close()
  fs.chmodSync(path.join(root, 'private-temp'), 0o755)
  const rootReal = fs.realpathSync(root)
  const countRootDescriptors = () => fs.readdirSync('/proc/self/fd').filter((entry) => {
    try { return fs.realpathSync(`/proc/self/fd/${entry}`) === rootReal } catch { return false }
  }).length
  const before = countRootDescriptors()
  assert.throws(() => createRestrictedLocalCas({ protectedRootPath: root }), /D931_CAS_PATH_REJECTED/)
  assert.equal(countRootDescriptors(), before, 'failed construction must not leak the CAS root descriptor')
  fs.rmSync(root, { recursive: true, force: true })

  const readFailureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-constructor-read-'))
  fs.chmodSync(readFailureRoot, 0o700)
  const initialized = createRestrictedLocalCas({ protectedRootPath: readFailureRoot })
  initialized.close()
  const readFailureReal = fs.realpathSync(readFailureRoot)
  const countReadFailureDescriptors = () => fs.readdirSync('/proc/self/fd').filter((entry) => {
    try { return fs.realpathSync(`/proc/self/fd/${entry}`) === readFailureReal } catch { return false }
  }).length
  const beforeReadFailure = countReadFailureDescriptors()
  const originalReaddir = fs.readdirSync
  fs.readdirSync = (target, ...args) => {
    if (String(target).endsWith('/private-temp')) throw Object.assign(new Error('synthetic temp enumeration failure'), { code: 'EIO' })
    return originalReaddir(target, ...args)
  }
  try { assert.throws(() => createRestrictedLocalCas({ protectedRootPath: readFailureRoot }), /synthetic temp enumeration failure/) } finally { fs.readdirSync = originalReaddir }
  assert.equal(countReadFailureDescriptors(), beforeReadFailure, 'late constructor failure must close the CAS root descriptor')
  fs.rmSync(readFailureRoot, { recursive: true, force: true })
})

test('restricted CAS rejects extra and missing fixed-layout namespaces', () => {
  for (const mutation of ['rogue-root', 'rogue-objects', 'rogue-sha', 'missing-fanout']) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `jedi-d931-cas-layout-${mutation}-`))
    fs.chmodSync(root, 0o700)
    const initialized = createRestrictedLocalCas({ protectedRootPath: root })
    initialized.close()
    if (mutation === 'rogue-root') fs.mkdirSync(path.join(root, 'rogue'), { mode: 0o700 })
    if (mutation === 'rogue-objects') fs.mkdirSync(path.join(root, 'objects', 'rogue'), { mode: 0o700 })
    if (mutation === 'rogue-sha') fs.mkdirSync(path.join(root, 'objects', 'sha256', 'rogue'), { mode: 0o700 })
    if (mutation === 'missing-fanout') fs.rmdirSync(path.join(root, 'objects', 'sha256', 'ff'))
    assert.throws(() => createRestrictedLocalCas({ protectedRootPath: root }), /D931_CAS_INVENTORY_CORRUPT/)
    fs.rmSync(root, { recursive: true, force: true })
  }

  const liveRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-live-layout-'))
  fs.chmodSync(liveRoot, 0o700)
  const live = createRestrictedLocalCas({ protectedRootPath: liveRoot })
  fs.mkdirSync(path.join(liveRoot, 'objects', 'rogue-live'), { mode: 0o700 })
  assert.throws(() => live.inventory(), /D931_CAS_INVENTORY_CORRUPT/)
  live.close()
  fs.rmSync(liveRoot, { recursive: true, force: true })
})

test('crash-state inspection rejects wrong-fanout and content-mismatched published objects', () => {
  for (const corruption of ['wrong-fanout', 'hash-mismatch']) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `jedi-d931-cas-inspect-${corruption}-`))
    fs.chmodSync(root, 0o700)
    const initialized = createRestrictedLocalCas({ protectedRootPath: root })
    initialized.close()
    const bytes = Buffer.from('synthetic corruption probe')
    const correctDigest = sha256Bytes(bytes)
    const fanout = corruption === 'wrong-fanout' ? (correctDigest.startsWith('ff') ? '00' : 'ff') : correctDigest.slice(0, 2)
    const leaf = corruption === 'wrong-fanout' ? correctDigest : '00'.repeat(32)
    fs.writeFileSync(path.join(root, 'objects', 'sha256', fanout, leaf), bytes, { mode: 0o600 })
    const reopened = createRestrictedLocalCas({ protectedRootPath: root })
    assert.throws(() => reopened.inspectCrashState(), /D931_CAS_INVENTORY_CORRUPT/)
    reopened.close()
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('crash-state inspection rejects an unexplained hard link to a published object', async (t) => {
  const fixture = await createD931Fixture(t)
  const cas = createRestrictedLocalCas({ protectedRootPath: fixture.casRoot })
  const sourcePath = path.join(fixture.stagingRoot, fixture.handoff.staged_path)
  const descriptor = fs.openSync(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  try {
    const prepared = cas.prepare({ operationId: 'operation.synthetic.cas-unmatched-link', operationNonce: nonce, artifact: fixture.artifact, sourceDescriptor: descriptor })
    cas.publishNoReplace(cas.verifyPrepared(prepared))
  } finally {
    fs.closeSync(descriptor)
  }
  cas.close()
  const externalDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-external-link-'))
  const externalLink = path.join(externalDirectory, 'unexpected-link')
  fs.linkSync(path.join(fixture.casRoot, custodyReferenceFor(fixture.artifact)), externalLink)
  const reopened = createRestrictedLocalCas({ protectedRootPath: fixture.casRoot })
  assert.throws(() => reopened.inspectCrashState(), /D931_CAS_INVENTORY_CORRUPT/)
  assert.throws(() => reopened.inventory(), /D931_CAS_RECOVERY_REQUIRED/)
  reopened.close()
  fs.unlinkSync(externalLink)
  fs.rmdirSync(externalDirectory)
})

test('restricted CAS rejects a configured-root swap before provisioning', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-root-swap-'))
  const substitute = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-cas-root-substitute-'))
  fs.chmodSync(root, 0o700)
  fs.chmodSync(substitute, 0o755)
  const originalOpen = fs.openSync
  fs.openSync = (target, ...args) => originalOpen(target === root ? substitute : target, ...args)
  try { assert.throws(() => createRestrictedLocalCas({ protectedRootPath: root }), /D931_CAS_PATH_REJECTED/) } finally { fs.openSync = originalOpen }
  assert.deepEqual(fs.readdirSync(root), [])
  assert.deepEqual(fs.readdirSync(substitute), [])
  fs.rmSync(root, { recursive: true, force: true })
  fs.rmSync(substitute, { recursive: true, force: true })
})
