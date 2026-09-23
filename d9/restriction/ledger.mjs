import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { assertDurableNamespaceStore, durableJsonBytes } from '../custody/durable-store.mjs'
import { assertLinuxEnforcement } from '../control-plane/platform.mjs'
import { assertD941AuthenticatedSession } from './admin-launcher.mjs'
import { assertD941AuthorityLockBinding, assertD941AuthorityRegistry, setD941DestructiveLockHeld } from './authority.mjs'
import { assertVerifiedD940AuthorityContext, sealD940Record, validateD940Record } from './contracts.mjs'
import { failD941 } from './errors.mjs'
import { assertD941RuntimeSemantics } from './semantics.mjs'
import { getD941RecoveryClassificationProof, persistD941RecoveryAssessmentLink } from './recovery.mjs'

export const D941_STORE_NAMESPACES = Object.freeze([
  'authority', 'authority-events', 'control', 'access', 'execution', 'receipt', 'backup', 'recovery', 'ledger',
])

const targetNamespaces = Object.freeze({
  'jedi-atlas-custody-control-record': 'control',
  'jedi-atlas-access-revocation-record': 'access',
  'jedi-atlas-deletion-execution-record': 'execution',
  'jedi-atlas-deletion-receipt': 'receipt',
  'jedi-atlas-backup-coordination-record': 'backup',
  'jedi-atlas-d940-recovery-assessment': 'recovery',
})

const brokers = new WeakSet()

function readJson(store, namespaceCode, recordCode) {
  try { return JSON.parse(store.read({ namespaceCode, recordCode }).toString('utf8')) } catch (error) {
    failD941('D941_LEDGER_RECORD_INVALID', `${namespaceCode}/${recordCode} is unreadable`, { cause: error.message })
  }
}

function entries(store, namespaceCode) {
  return store.inventory().projection[namespaceCode].map(({ record_code: code }) => readJson(store, namespaceCode, code))
}

function same(left, right) { return canonicalize(left) === canonicalize(right) }

function assertActor(recordActor, session, label) {
  assertD941AuthenticatedSession(session)
  if (!same(recordActor, session.actor)) failD941('D941_ACTOR_SESSION_MISMATCH', `${label} does not match its authenticated session`)
}

function validateReceiptChain(store, contractSet) {
  const receipts = entries(store, 'ledger').sort((left, right) => left.receipt_sequence - right.receipt_sequence)
  let predecessor = null
  let persistedAt = null
  for (const [index, receipt] of receipts.entries()) {
    validateD940Record({ contractSet, record: receipt })
    if (receipt.receipt_sequence !== index + 1 || receipt.previous_receipt_record_digest_sha256 !== predecessor ||
        (persistedAt !== null && receipt.persisted_at <= persistedAt)) {
      failD941('D941_LEDGER_CHAIN_INVALID', 'D9.4 ledger is gapped, forked, reordered, colliding, or backdated')
    }
    const namespace = targetNamespaces[receipt.target_format]
    const target = readJson(store, namespace, receipt.target_record_code)
    if (target.record_digest_sha256 !== receipt.target_record_digest_sha256 || target.subject.subject_identity_sha256 !== receipt.target_subject_identity_sha256) {
      failD941('D941_LEDGER_TARGET_MISMATCH', 'receipt does not resolve to its exact target')
    }
    predecessor = receipt.record_digest_sha256
    persistedAt = receipt.persisted_at
  }
  const referenced = new Set(receipts.map((receipt) => `${namespaceByReceipt(receipt)}/${receipt.target_record_code}`))
  for (const namespace of Object.values(targetNamespaces)) {
    for (const { record_code: recordCode } of store.inventory().projection[namespace]) {
      if (!referenced.has(`${namespace}/${recordCode}`)) failD941('D941_LEDGER_RECOVERY_REQUIRED', 'a persisted D9.4 target lacks its global ledger receipt')
    }
  }
  return receipts
}

function namespaceByReceipt(receipt) { return targetNamespaces[receipt.target_format] }

export function createD941LedgerBroker({ store, authorityContext, authorityRegistry, clock, linuxEnforcement, operationLockRootPath, operationLockLeaf = 'd941-operation.lock', faultInjector = null }) {
  assertDurableNamespaceStore(store)
  assertVerifiedD940AuthorityContext(authorityContext)
  if (!same(store.namespaceCodes, D941_STORE_NAMESPACES)) failD941('D941_LEDGER_STORE_INVALID', 'store namespace inventory is not exact')
  const { contractSet } = authorityContext
  assertD941AuthorityRegistry(authorityRegistry)
  assertD941AuthorityLockBinding(authorityRegistry, { linuxEnforcement, operationLockRootPath, operationLockLeaf })
  assertLinuxEnforcement(linuxEnforcement).probe()
  let operationLockContext = null

  function persistedNonceClaims() {
    const claims = new Map()
    for (const namespace of Object.values(targetNamespaces)) for (const record of entries(store, namespace)) {
      const key = `${record.operation_id}/${record.operation_nonce}`
      const prior = claims.get(key)
      if (prior && prior !== record.subject.subject_identity_sha256) failD941('D941_OPERATION_NONCE_COLLISION', 'persisted operation/nonce collides across subjects')
      claims.set(key, record.subject.subject_identity_sha256)
    }
    return claims
  }

  function head() {
    const receipts = validateReceiptChain(store, contractSet)
    const receipt = receipts.at(-1) ?? null
    return Object.freeze({ sequence: receipt?.receipt_sequence ?? 0, digest: receipt?.record_digest_sha256 ?? null, persistedAt: receipt?.persisted_at ?? null })
  }

  function prepareAppend({ record, semanticSession, persistenceSession, approvalSessions = [], runtimeProof = null, allowPendingEffect = false, expectedPersistedAt: suppliedPersistedAt = null }) {
    validateD940Record({ contractSet, record })
    const namespaceCode = targetNamespaces[record.format]
    if (!namespaceCode) failD941('D941_LEDGER_TARGET_UNSUPPORTED', 'record format is not a D9.4 ledger target')
    assertD941AuthenticatedSession(persistenceSession, record.format === 'jedi-atlas-d940-recovery-assessment' ? 'recovery_classification' : 'control_submission')
    assertD941AuthenticatedSession(semanticSession)
    if (Date.parse(record.knowledge_boundary.recorded_at) < Date.parse(semanticSession.authenticatedAt) ||
        Date.parse(record.knowledge_boundary.persisted_at) < Date.parse(persistenceSession.authenticatedAt) ||
        approvalSessions.some((session, index) => Date.parse(record.human_approvals[index].decided_at) < Date.parse(session.authenticatedAt))) {
      failD941('D941_SESSION_TIME_BACKDATE', 'record and approval times cannot precede the authenticated session issue times')
    }
    authorityRegistry.revalidateSession(semanticSession, record.knowledge_boundary.recorded_at)
    authorityRegistry.revalidateSession(persistenceSession, record.knowledge_boundary.persisted_at)
    for (const [index, session] of approvalSessions.entries()) authorityRegistry.revalidateSession(session, record.human_approvals[index].decided_at)
    const replayReceipt = entries(store, 'ledger').find((receipt) => receipt.target_record_code === record.record_code)
    if (replayReceipt) {
      if (replayReceipt.target_record_digest_sha256 !== record.record_digest_sha256) failD941('D941_LEDGER_REPLAY_COLLISION', 'record code was replayed with different content')
      return Object.freeze({ replay: Object.freeze({ record, receipt: replayReceipt, created: false }) })
    }
    const prior = head()
    const expectedSequence = prior.sequence + 1
    // Chronology is checked after semantic validation so rejected actor/role
    // submissions do not consume a persistence clock slot.
    const claim = `${record.operation_id}/${record.operation_nonce}`
    const nonceClaims = persistedNonceClaims()
    const priorClaim = nonceClaims.get(claim)
    if (priorClaim && priorClaim !== record.subject.subject_identity_sha256) failD941('D941_OPERATION_NONCE_COLLISION', 'operation/nonce was replayed for another subject')

    const existingRecords = Object.values(targetNamespaces).flatMap((namespace) => entries(store, namespace))
    assertD941RuntimeSemantics({ contractSet, operationalProfile: authorityContext.operationalProfile, record, semanticSession, persistenceSession, approvalSessions, existingRecords, broker, runtimeProof, allowPendingEffect })
    if (record.chain) {
      const stream = entries(store, namespaceCode).filter((item) => item.chain?.stream_code === record.chain.stream_code).sort((a, b) => a.chain.sequence - b.chain.sequence)
      const previous = stream.at(-1)
      if (previous && (previous.operation_id !== record.operation_id || previous.operation_nonce !== record.operation_nonce || previous.subject.subject_identity_sha256 !== record.subject.subject_identity_sha256)) {
        failD941('D941_TARGET_CHAIN_INVALID', 'target successor changes operation, nonce, or subject context')
      }
      if (record.chain.sequence !== stream.length + 1 || record.chain.predecessor_record_digest_sha256 !== (stream.at(-1)?.record_digest_sha256 ?? null)) {
        failD941('D941_TARGET_CHAIN_INVALID', 'target stream is gapped, forked, reordered, or has the wrong predecessor')
      }
    }
    const expectedPersistedAt = suppliedPersistedAt ?? clock()
    if (record.knowledge_boundary.receipt_sequence !== expectedSequence || record.knowledge_boundary.persisted_at !== expectedPersistedAt ||
        (prior.persistedAt !== null && record.knowledge_boundary.persisted_at <= prior.persistedAt) ||
        record.knowledge_boundary.recorded_at > record.knowledge_boundary.persisted_at || record.knowledge_boundary.effective_at > record.knowledge_boundary.recorded_at) {
      failD941('D941_LEDGER_CHRONOLOGY_INVALID', 'target knowledge boundary does not match the next gapless persistence point')
    }
    return Object.freeze({ namespaceCode, prior, expectedSequence, expectedPersistedAt })
  }

  function persistPrepared(record, prepared) {
    const { namespaceCode, prior, expectedSequence } = prepared
    const bytes = durableJsonBytes(record)
    store.append({ namespaceCode, recordCode: record.record_code, bytes, replayKey: record.record_code })
    faultInjector?.('after_target_persisted_before_receipt', { record })
    const receipt = sealD940Record({
      format: 'jedi-atlas-d940-journal-append-receipt', format_version: '1.0.0',
      record_code: `d940-receipt-${String(expectedSequence).padStart(8, '0')}`,
      journal_namespace_code: 'd940.global.control-journal.v1', receipt_sequence: expectedSequence,
      previous_receipt_record_digest_sha256: prior.digest, target_format: record.format,
      target_record_code: record.record_code, target_record_digest_sha256: record.record_digest_sha256,
      target_subject_identity_sha256: record.subject.subject_identity_sha256,
      operation_id: record.operation_id, operation_nonce: record.operation_nonce,
      semantic_actor: record.semantic_actor ?? record.independent_verifier, persistence_actor: record.persistence_actor,
      semantic_recorded_at: record.knowledge_boundary.recorded_at, persisted_at: record.knowledge_boundary.persisted_at,
      durability_state_code: 'record_and_receipt_flushed_in_protected_d940_ledger', record_digest_sha256: null,
    })
    validateD940Record({ contractSet, record: receipt })
    store.append({ namespaceCode: 'ledger', recordCode: receipt.record_code, bytes: durableJsonBytes(receipt), replayKey: receipt.record_code })
    faultInjector?.('after_receipt_persisted_before_response', { record, receipt })
    return Object.freeze({ record, receipt, created: true })
  }

  function appendLocked(input) {
    const previousContext = operationLockContext
    operationLockContext = Object.freeze({
      kind: 'ledger_append',
      format: input.record?.format,
      recordCode: input.record?.record_code,
      recordDigestSha256: input.record?.record_digest_sha256,
      operationId: input.record?.operation_id,
      operationNonce: input.record?.operation_nonce,
      subjectIdentitySha256: input.record?.subject?.subject_identity_sha256,
    })
    try {
      const prepared = prepareAppend(input)
      const result = prepared.replay ?? persistPrepared(input.record, prepared)
      if (input.record.format === 'jedi-atlas-d940-recovery-assessment') {
        persistD941RecoveryAssessmentLink(input.runtimeProof ?? getD941RecoveryClassificationProof(input.record), input.record, result.receipt, broker)
      }
      return result
    } finally { operationLockContext = previousContext }
  }

  async function append(input) {
    const lease = await linuxEnforcement.holdOperationLock({ rootPath: operationLockRootPath, relativePath: operationLockLeaf })
    try {
      return appendLocked(input)
    } finally { await lease.release() }
  }

  async function withDestructiveLock(callback) {
    const lease = await linuxEnforcement.holdOperationLock({ rootPath: operationLockRootPath, relativePath: operationLockLeaf })
    const leaseToken = Object.freeze({})
    const pending = new Set()
    let active = true
    let accepting = true
    operationLockContext = Object.freeze({ kind: 'destructive_operation', leaseToken })
    setD941DestructiveLockHeld(authorityRegistry, true)
    const assertLeaseActive = () => {
      if (!active || operationLockContext?.kind !== 'destructive_operation' || operationLockContext.leaseToken !== leaseToken) failD941('D941_OPERATION_LOCK_REQUIRED', 'retained destructive-lock capability is inactive or no longer owns the kernel lease')
    }
    const assertAccepting = () => {
      assertLeaseActive()
      if (!accepting) failD941('D941_OPERATION_LOCK_REQUIRED', 'destructive-lock callback has settled and accepts no new capability work')
    }
    const track = (promise) => {
      pending.add(promise)
      void promise.then(() => pending.delete(promise), () => pending.delete(promise))
      return promise
    }
    const context = Object.freeze({
      lock_identity_sha256: canonicalSha256({ operationLockRootPath, operationLockLeaf }),
      authority_head_digest_sha256: authorityRegistry.head().digest,
      assertAuthorityHead() {
        assertAccepting()
        const current = authorityRegistry.head().digest
        if (current !== context.authority_head_digest_sha256) failD941('D941_AUTHORITY_HEAD_CHANGED', 'authority state changed while the destructive lock was held')
        return true
      },
      appendLocked(input) {
        assertAccepting()
        return appendLocked(input)
      },
      effectThenAppend(input, effect) {
        assertAccepting()
        const work = (async () => {
          const prepared = prepareAppend({ ...input, runtimeProof: null, allowPendingEffect: true })
          if (prepared.replay) return prepared.replay
          assertLeaseActive()
          const effectResult = await effect()
          assertLeaseActive()
          if (authorityRegistry.head().digest !== context.authority_head_digest_sha256) failD941('D941_AUTHORITY_HEAD_CHANGED', 'authority state changed during the protected effect')
          const finalized = prepareAppend({ ...input, runtimeProof: effectResult?.runtimeProof ?? input.runtimeProof ?? null, expectedPersistedAt: prepared.expectedPersistedAt })
          if (finalized.replay) return finalized
          assertLeaseActive()
          return Object.freeze({ append: persistPrepared(input.record, finalized), effectResult })
        })()
        return track(work)
      },
    })
    try { return await callback(context) } finally {
      accepting = false
      while (pending.size !== 0) await Promise.allSettled([...pending])
      active = false
      operationLockContext = null
      setD941DestructiveLockHeld(authorityRegistry, false)
      await lease.release()
    }
  }
  function assertRecoveryAppendLock(record) {
    const context = operationLockContext
    if (!context || context.kind !== 'ledger_append' || record?.format !== 'jedi-atlas-d940-recovery-assessment' ||
        context.format !== record.format || context.recordCode !== record.record_code || context.recordDigestSha256 !== record.record_digest_sha256 ||
        context.operationId !== record.operation_id || context.operationNonce !== record.operation_nonce ||
        context.subjectIdentitySha256 !== record.subject?.subject_identity_sha256) {
      failD941('D941_OPERATION_LOCK_REQUIRED', 'D9.4 recovery source-CAS persistence requires the exact operation-bound assessment append lock')
    }
    return true
  }
  const broker = Object.freeze({ append, head, authorityHead: () => authorityRegistry.head(), revalidateSession: (session, at) => authorityRegistry.revalidateSession(session, at), validate: () => validateReceiptChain(store, contractSet), store, withDestructiveLock, assertRecoveryAppendLock })
  brokers.add(broker)
  return broker
}

export function assertD941LedgerBroker(value) {
  if (!brokers.has(value)) failD941('D941_LEDGER_UNTRUSTED', 'ledger broker was not created by the fixed factory')
  return value
}
