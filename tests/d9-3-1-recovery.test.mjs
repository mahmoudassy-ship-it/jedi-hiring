import assert from 'node:assert/strict'
import test from 'node:test'
import { createD931AdmissionResolver, createProtectedInventorySnapshotReader } from '../d9/custody/admission.mjs'
import { canonicalRecord } from '../d9/custody/contracts.mjs'
import { createDurableNamespaceStore } from '../d9/custody/durable-store.mjs'
import { createProtectedJournalBroker, D931_JOURNAL_NAMESPACES } from '../d9/custody/journal.mjs'
import { appendOperationStarted } from '../d9/custody/coordinator.mjs'
import { createClassificationOnlyRecoveryAssessment, evaluateRecoveryClassification } from '../d9/custody/recovery.mjs'
import { admitFixtureAuthority, authenticatedPeerFor, createD931Fixture, d930Fixture, makeClock } from './d9-3-1-support/fixture.mjs'

function baselineKnowledge() {
  const complete = { state_code: 'complete_nonempty', head_digest_sha256: '11'.repeat(32) }
  return {
    snapshot_completeness_code: 'complete',
    operation_control_inventory: complete, capability_inventory: complete,
    primary_receipt_inventory: complete, custody_inventory: complete,
    candidate_inventory: complete, canonical_state_inventory: complete,
    reference_inventory: { state_code: 'complete_empty', head_digest_sha256: null },
    hold_inventory: { state_code: 'complete_empty', head_digest_sha256: null },
    backup_inventory: { state_code: 'unavailable_d9_5', head_digest_sha256: null },
  }
}

function baselineObservation() {
  return {
    operation_state_code: 'terminal', lock_state_code: 'held_by_recovery_operation', temporary_state_code: 'absent',
    final_object_state_code: 'absent', primary_receipt_state_code: 'absent', adapter_response_state_code: 'absent',
    journal_link_state_code: 'absent', artifact_backup_state_code: 'unavailable_d9_5', candidate_state_code: 'absent',
    prior_backup_state_code: 'unavailable_d9_5', promotion_state_code: 'not_started', canonical_state_code: 'prior_exact',
    final_backup_state_code: 'unavailable_d9_5', completion_state_code: 'absent', reference_scan_code: 'complete_none',
    hold_scan_code: 'complete_none', bytes_state_code: 'not_applicable',
  }
}

function setPath(knowledge, observation, dotted, value) {
  const target = dotted.startsWith('knowledge.') ? knowledge : observation
  const parts = dotted.replace(/^(knowledge|observation)\./u, '').split('.')
  let cursor = target
  for (const part of parts.slice(0, -1)) cursor = cursor[part]
  cursor[parts.at(-1)] = value
}

function closeImplications(observation) {
  if (observation.completion_state_code === 'exact') {
    Object.assign(observation, { promotion_state_code: 'target_verified', canonical_state_code: 'target_exact', final_backup_state_code: 'reference_exact', candidate_state_code: 'sealed', prior_backup_state_code: 'reference_exact' })
  }
  if (observation.promotion_state_code === 'target_verified') Object.assign(observation, { candidate_state_code: 'sealed', prior_backup_state_code: 'reference_exact' })
  if (!['absent', 'unknown'].includes(observation.candidate_state_code)) observation.artifact_backup_state_code = 'reference_exact'
  if (observation.artifact_backup_state_code === 'reference_exact') observation.journal_link_state_code = 'exact'
  if (observation.journal_link_state_code === 'exact') observation.adapter_response_state_code = 'exact_resolvable'
  if (observation.adapter_response_state_code === 'exact_resolvable') observation.primary_receipt_state_code = 'exact'
  if (observation.primary_receipt_state_code === 'exact') observation.final_object_state_code = 'exact'
}

test('all 19 frozen recovery decisions and all 14 crash boundaries remain classification-only', async (t) => {
  const fixture = await createD931Fixture(t)
  const classifications = fixture.contracts.classifications
  assert.equal(Object.hasOwn(fixture.contracts, 'validators'), false)
  assert.equal(Object.isFrozen(classifications), true)
  assert.equal(Object.isFrozen(classifications.recovery_decision_rules), true)
  assert.equal(Object.isFrozen(classifications.recovery_decision_rules[0]), true)
  assert.throws(() => {
    classifications.recovery_decision_rules[0].decision_rule_code = 'mutated'
  }, TypeError)
  assert.equal(classifications.recovery_decision_rules.length, 19)
  assert.equal(classifications.crash_boundary_rules.length, 14)
  for (const rule of classifications.recovery_decision_rules) {
    for (const predicate of rule.match_any) {
      const knowledge = baselineKnowledge()
      const observation = baselineObservation()
      for (const [path, value] of Object.entries(predicate)) setPath(knowledge, observation, path, value)
      closeImplications(observation)
      const selected = evaluateRecoveryClassification({ classifications, knowledge, observation })
      assert.equal(selected.decision_rule_code, rule.decision_rule_code)
      assert.equal(selected.action_execution_code, 'none_classification_only')
    }
  }
  for (const boundary of classifications.crash_boundary_rules) {
    const rule = classifications.recovery_decision_rules.find((entry) => entry.decision_rule_code === boundary.decision_rule_code)
    assert.ok(rule, boundary.boundary_code)
    assert.equal(rule.action_execution_code, 'none_classification_only')
  }
})

test('protected snapshot is deeply immutable and classification fails closed without a terminal source and recovery authority', async (t) => {
  const fixture = await createD931Fixture(t)
  const admission = createD931AdmissionResolver({ contractSet: fixture.contracts, verifiedGeneration: fixture.generation, custodyProfile: fixture.custodyProfile, journalProfile: fixture.journalProfile })
  admitFixtureAuthority(admission, fixture)
  const store = createDurableNamespaceStore({ rootPath: fixture.journalRoot, namespaceCodes: D931_JOURNAL_NAMESPACES })
  t.after(() => store.close())
  const clock = makeClock('2030-01-01T00:12:30.000Z')
  const journal = createProtectedJournalBroker({ store, contractSet: fixture.contracts, admissionResolver: admission, journalBindingCode: 'binding.journal-broker', clock })
  let source = d930Fixture('journal_broker_request')
  source.sender_binding_code = 'binding.custody-adapter'
  source.recipient_binding_code = 'binding.journal-broker'
  source.runtime_profile_record_digest_sha256 = fixture.generation.runtimeProfile.record_digest_sha256
  source.identity_bindings_record_digest_sha256 = fixture.generation.identityBindings.record_digest_sha256
  source.d930_journal_profile_record_digest_sha256 = fixture.journalProfile.record_digest_sha256
  source.payload.semantic_assertion.component_binding_code = 'binding.custody-adapter'
  source.payload.semantic_assertion.component_executable_sha256 = fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.custody-adapter').executable_sha256
  source.payload.semantic_assertion.runtime_profile_record_digest_sha256 = fixture.generation.runtimeProfile.record_digest_sha256
  source.payload.semantic_assertion.identity_bindings_record_digest_sha256 = fixture.generation.identityBindings.record_digest_sha256
  source.payload.semantic_assertion.d930_journal_profile_record_digest_sha256 = fixture.journalProfile.record_digest_sha256
  source.payload.semantic_assertion = canonicalRecord(source.payload.semantic_assertion)
  source.payload.semantic_assertion_record_digest_sha256 = source.payload.semantic_assertion.record_digest_sha256
  const journalPeerProvider = (request) => authenticatedPeerFor(fixture, request)
  const root = await appendOperationStarted({ journalPeerProvider, journalBroker: journal, journalCode: `journal.${fixture.seal.operation_id}`,
    journalBindingCode: 'binding.journal-broker', componentBindingCode: 'binding.importer',
    componentExecutableSha256: fixture.generation.identityBindings.bindings.find((entry) => entry.binding_code === 'binding.importer').executable_sha256,
    journalProfileDigest: fixture.journalProfile.record_digest_sha256, operationModeCode: 'document_import',
    operationId: fixture.seal.operation_id, operationNonce: fixture.seal.operation_nonce,
    authorizationBundleSealDigest: fixture.seal.record_digest_sha256,
    bundle: fixture.seal.bundle, targetLogicalState: fixture.seal.target_logical_state,
    runtimeProfileDigest: fixture.generation.runtimeProfile.record_digest_sha256,
    identityBindingsDigest: fixture.generation.identityBindings.record_digest_sha256,
    eventAt: '2030-01-01T00:12:28.000Z', requestCreatedAt: '2030-01-01T00:12:29.000Z' })
  source = root.request
  const inventoryReaders = Object.fromEntries(Object.keys(baselineKnowledge()).filter((key) => key.endsWith('_inventory')).map((code) => [code, () => structuredClone(baselineKnowledge()[code])]))
  const reader = createProtectedInventorySnapshotReader({ journalBroker: journal, inventoryReaders, clock })
  const snapshot = reader.capture({ operationId: source.operation_id, operationNonce: source.operation_nonce, journalCode: source.payload.journal_code })
  assert.throws(() => { snapshot.journalHead.event_sequence = 99 }, TypeError)
  assert.throws(() => { snapshot.inventoryHeads[0].state_code = 'unavailable' }, TypeError)
  assert.match(snapshot.capturedAt, /Z$/)
  const semanticBase = d930Fixture('journal_semantic')
  semanticBase.runtime_profile_record_digest_sha256 = fixture.generation.runtimeProfile.record_digest_sha256
  semanticBase.identity_bindings_record_digest_sha256 = fixture.generation.identityBindings.record_digest_sha256
  semanticBase.d930_journal_profile_record_digest_sha256 = fixture.journalProfile.record_digest_sha256
  assert.throws(() => createClassificationOnlyRecoveryAssessment({
    admissionResolver: admission, journalBroker: journal, snapshot, observation: baselineObservation(),
    context: {
      subjectOperationId: source.operation_id, subjectOperationNonce: source.operation_nonce,
      recoveryOperationId: 'operation.synthetic.recovery1', recoveryOperationNonce: '77'.repeat(32),
      recoveryLockOwnerBindingCode: 'binding.launcher', recoveryLockProjectionSha256: '78'.repeat(32),
      recoveryLockAcquiredAt: '2030-01-01T00:30:00.100Z', recoveryLockExpiresAt: '2030-01-01T00:40:00.000Z',
      scanStartedAt: '2030-01-01T00:30:00.200Z', scanCompletedAt: '2030-01-01T00:30:01.000Z', snapshotCompletenessCode: 'complete',
      sourceTerminalJournalCode: source.payload.journal_code, recoveryChainCode: 'recovery.synthetic.001', recoveryAttemptSequence: 1,
      priorAttemptTerminalRecordDigestSha256: null, subjectBundle: semanticBase.bundle, subjectArtifact: semanticBase.bundle.bundle_kind_code === 'single_document' ? fixture.artifact : null,
      subjectCopyCode: semanticBase.bundle.bundle_kind_code === 'single_document' ? 'copy.primary.synthetic.001' : null,
      subjectBackendCode: semanticBase.bundle.bundle_kind_code === 'single_document' ? 'pilot_local_cas_v1' : null,
      subjectBackendReference: semanticBase.bundle.bundle_kind_code === 'single_document' ? `objects/sha256/${fixture.artifact.sha256.slice(0, 2)}/${fixture.artifact.sha256}` : null,
      sourceTerminalErrorCode: 'PROMOTION_STATE_AMBIGUOUS', semanticBase, componentBindingCode: 'binding.custody-adapter', eventAt: '2030-01-01T00:30:01.500Z',
    },
  }), /D931_INVENTORY_SNAPSHOT_REJECTED/)
  assert.equal(store.inventory().projection['recovery-assessments'].length, 0)
  assert.equal(store.inventory().projection['journal-events'].length, 1)
})

test('recovery fails closed on incomplete snapshots and contradictory observations', async (t) => {
  const fixture = await createD931Fixture(t)
  const knowledge = baselineKnowledge()
  knowledge.snapshot_completeness_code = 'incomplete'
  assert.equal(evaluateRecoveryClassification({ classifications: fixture.contracts.classifications, knowledge, observation: baselineObservation() }).decision_rule_code, 'incomplete_or_unknown')
  const contradiction = baselineObservation()
  contradiction.primary_receipt_state_code = 'exact'
  assert.throws(() => evaluateRecoveryClassification({ classifications: fixture.contracts.classifications, knowledge: baselineKnowledge(), observation: contradiction }), /D931_RECOVERY_OBSERVATION_CONTRADICTION/)
})
