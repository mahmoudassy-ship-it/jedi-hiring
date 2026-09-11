import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { createOneShotIntegrityGrantSink, createOneShotIntegrityRelay } from '../d9/custody/integrity.mjs'
import { persistSupportingRecord } from '../d9/custody/coordinator.mjs'
import { canonicalRecord } from '../d9/custody/contracts.mjs'
import { createDurableNamespaceStore } from '../d9/custody/durable-store.mjs'
import { createProtectedJournalBroker, D931_JOURNAL_NAMESPACES } from '../d9/custody/journal.mjs'
import { createD931Fixture, createSyntheticAvailableCustody, makeClock } from './d9-3-1-support/fixture.mjs'

test('one-shot integrity relay persists result before confirmed receiver termination and grants no processing access', async (t) => {
  const fixture = await createD931Fixture(t, { integrity: true })
  const custody = await createSyntheticAvailableCustody(t, fixture)
  const { admission, store, journal, clock } = custody
  const verifier = fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.verifier')
  const foreignSink = createOneShotIntegrityGrantSink()
  const foreignRelay = createOneShotIntegrityRelay({ admissionResolver: admission, journalBroker: journal, journalPeerProvider: custody.journalPeerProvider, contractSet: fixture.contracts, bindingRoleResolver: admission.bindingRole, journalBindingCode: 'binding.journal-broker', journalProfileDigest: fixture.journalProfile.record_digest_sha256, launcherBindingCode: 'binding.launcher', clock, runtimeBuild: fixture.integrityBuild, grantSink: foreignSink })
  t.after(() => foreignRelay.dispose())
  await assert.rejects(() => foreignRelay.verify({ purposeCode: 'integrity', processingAccessRequested: false, adapterOpenResult: custody.available, verifierBindingCode: verifier.binding_code }), /D931_CUSTODY_DESCRIPTOR_UNAVAILABLE/, 'a separately branded sink cannot consume another sink\'s registered descriptor')
  const relay = createOneShotIntegrityRelay({ admissionResolver: admission, journalBroker: journal, journalPeerProvider: custody.journalPeerProvider, contractSet: fixture.contracts, bindingRoleResolver: admission.bindingRole, journalBindingCode: 'binding.journal-broker', journalProfileDigest: fixture.journalProfile.record_digest_sha256, launcherBindingCode: 'binding.launcher', clock, runtimeBuild: fixture.integrityBuild, grantSink: custody.integrityGrantSink })
  t.after(() => relay.dispose())
  assert.equal(verifier.executable_sha256, fixture.integrityBuild.sha256)
  const context = { purposeCode: 'integrity', processingAccessRequested: false, adapterOpenResult: custody.available, verifierBindingCode: verifier.binding_code, operationId: 'caller.substitution', artifact: { sha256: '00'.repeat(32), byte_length: 0 } }
  const result = await relay.verify(context)
  assert.equal(result.verifier.verification_outcome_code, 'passed')
  assert.equal(result.verifier.recomputed_artifact.sha256, fixture.artifact.sha256, 'the native relay accepted exactly one SCM_RIGHTS-delivered alias of the custody object')
  assert.equal(result.terminal.lifecycle_outcome_code, 'completed_verified')
  assert.equal(result.processingAccessGranted, false)
  assert.equal(result.delivery.operation_id, custody.openCustody.operation_id)
  assert.equal(result.delivery.artifact.sha256, fixture.artifact.sha256)
  assert.equal(result.descriptorFreeCoordinatorRequired, true)
  assert.equal(store.inventory().projection['supporting-records'].length, 47, 'operation start, six adapter exchanges, and three lifecycle records retain request, subject, and acknowledgement bytes')
  assert.equal(store.inventory().projection['journal-events'].length, 1, 'integrity lifecycle adds no semantic event beyond the required operation-start record')
  const forgedLifecycle = structuredClone(result.delivery)
  forgedLifecycle.operation_id = 'synthetic.forgerole'
  forgedLifecycle.record_code = 'integrity.delivery.synthetic.forgerole'
  forgedLifecycle.producer_binding_code = 'binding.importer'
  const forgedRecord = canonicalRecord(forgedLifecycle)
  await assert.rejects(() => persistSupportingRecord({ journalPeerProvider: custody.journalPeerProvider, journalBroker: journal, record: forgedRecord, kindCode: 'integrity_access_lifecycle_record', journalCode: `journal.${forgedRecord.operation_id}`, journalBindingCode: 'binding.journal-broker', journalProfileDigest: fixture.journalProfile.record_digest_sha256, createdAt: '2030-01-01T00:20:20.000Z' }), /D931_SUPPORTING_ROLE_REJECTED/)
  store.close()
  const reopenedStore = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => reopenedStore.close())
  const reopenedJournal = createProtectedJournalBroker({ store: reopenedStore, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:21:00.000Z') })
  assert.equal(reopenedJournal.head(`journal.${custody.common.operationId}`).record_digest_sha256, custody.operationStart.acknowledgement.payload.persisted_record_digest_sha256)
  const disconnectedLifecycle = structuredClone(result.delivery)
  disconnectedLifecycle.operation_id = 'synthetic.disconnected'
  disconnectedLifecycle.record_code = 'integrity.delivery.synthetic.disconnected'
  const disconnectedRecord = canonicalRecord(disconnectedLifecycle)
  await persistSupportingRecord({ journalPeerProvider: custody.journalPeerProvider, journalBroker: reopenedJournal, record: disconnectedRecord, kindCode: 'integrity_access_lifecycle_record', journalCode: 'journal.synthetic.disconnected', journalBindingCode: 'binding.journal-broker', journalProfileDigest: fixture.journalProfile.record_digest_sha256, createdAt: '2030-01-01T00:20:55.000Z' })
  reopenedStore.close()
  const corruptedRestartStore = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => corruptedRestartStore.close())
  assert.throws(() => createProtectedJournalBroker({ store: corruptedRestartStore, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock: makeClock('2030-01-01T00:21:30.000Z') }), /D931_SUPPORTING_CHAIN_CORRUPT/, 'restart rejects an individually valid lifecycle record disconnected from an exact integrity adapter stream')

  const faultFixture = await createD931Fixture(t, { integrity: true })
  const faultCustody = await createSyntheticAvailableCustody(t, faultFixture)
  const faultRelay = createOneShotIntegrityRelay({ admissionResolver: faultCustody.admission, journalBroker: faultCustody.journal, journalPeerProvider: faultCustody.journalPeerProvider, contractSet: faultFixture.contracts, bindingRoleResolver: faultCustody.admission.bindingRole, journalBindingCode: 'binding.journal-broker', journalProfileDigest: faultFixture.journalProfile.record_digest_sha256, launcherBindingCode: 'binding.launcher', clock: faultCustody.clock, runtimeBuild: faultFixture.integrityBuild, grantSink: faultCustody.integrityGrantSink, faultInjector(point) { if (point === 'after_verifier_result_persist_before_receiver_termination') throw new Error('synthetic crash') } })
  t.after(() => faultRelay.dispose())
  const faultVerifier = faultFixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.verifier')
  const children = () => fs.readFileSync(`/proc/self/task/${process.pid}/children`, 'utf8').trim().split(/\s+/u).filter(Boolean).toSorted()
  const custodyObject = path.join(faultFixture.casRoot, faultCustody.openCustody.payload.backend_reference)
  const custodyDescriptorCount = () => fs.readdirSync('/proc/self/fd').filter((leaf) => {
    try { return fs.realpathSync(`/proc/self/fd/${leaf}`) === fs.realpathSync(custodyObject) } catch { return false }
  }).length
  const childrenBefore = children()
  const descriptorsBefore = custodyDescriptorCount()
  assert.equal(descriptorsBefore, 1, 'the one-shot adapter result owns exactly one input custody descriptor')
  await assert.rejects(() => faultRelay.verify({ purposeCode: 'integrity', processingAccessRequested: false, verifierBindingCode: faultVerifier.binding_code, adapterOpenResult: faultCustody.available }), /D931_INTEGRITY_RECOVERY_REQUIRED/)
  await assert.rejects(() => faultRelay.verify({ purposeCode: 'integrity', processingAccessRequested: false, verifierBindingCode: faultVerifier.binding_code, adapterOpenResult: faultCustody.available }), /D931_INTEGRITY_RECOVERY_REQUIRED/, 'a post-grant lifecycle fault permanently latches this relay instance for recovery')
  assert.deepEqual(children(), childrenBefore)
  assert.equal(custodyDescriptorCount(), 0, 'the failed relay consumes and closes its input without leaking a replacement')
  assert.equal(faultCustody.store.inventory().projection['journal-events'].length, 1)
})

test('integrity relay fails closed on build and processing substitution', async (t) => {
  const fixture = await createD931Fixture(t, { integrity: true })
  const custody = await createSyntheticAvailableCustody(t, fixture)
  const relay = createOneShotIntegrityRelay({ admissionResolver: custody.admission, journalBroker: custody.journal, journalPeerProvider: custody.journalPeerProvider, contractSet: fixture.contracts, bindingRoleResolver: custody.admission.bindingRole, journalBindingCode: 'binding.journal-broker', journalProfileDigest: fixture.journalProfile.record_digest_sha256, launcherBindingCode: 'binding.launcher', clock: custody.clock, runtimeBuild: fixture.integrityBuild, grantSink: custody.integrityGrantSink })
  t.after(() => relay.dispose())
  await assert.rejects(() => relay.verify({ purposeCode: 'integrity', processingAccessRequested: true }), /D931_PROCESSING_ACCESS_FORBIDDEN/)
  fs.chmodSync(fixture.integrityBuild.executable, 0o700)
  fs.appendFileSync(fixture.integrityBuild.executable, Buffer.from([0]))
  fs.chmodSync(fixture.integrityBuild.executable, 0o500)
  const verifier = fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.verifier')
  const context = { purposeCode: 'integrity', processingAccessRequested: false, adapterOpenResult: custody.available, verifierBindingCode: verifier.binding_code }
  await assert.rejects(() => relay.verify(context), /D931_INTEGRITY_BUILD_MISMATCH/)
})
