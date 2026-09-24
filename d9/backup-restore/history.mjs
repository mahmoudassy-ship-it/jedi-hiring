import { canonicalSha256 } from '../control-plane/canonical.mjs'
import { assertDurableNamespaceStore, durableJsonBytes } from '../custody/durable-store.mjs'
import { assertTimestamp, deepFreeze, sealD951, validateD950Record } from './contracts.mjs'
import { failD951 } from './errors.mjs'
import { assertD951Session } from './session.mjs'

export const D951_NAMESPACES = Object.freeze([
  'backup-manifests', 'backup-receipts', 'restore-authorizations', 'restore-plans', 'restore-lifecycle',
  'deletion-aware', 'retention-controls', 'retention-heads', 'retention-journal', 'restore-drills', 'global-journal',
])

const NAMESPACE_RULES = Object.freeze({
  'backup-manifests': Object.freeze({ format: 'jedi-atlas-backup-set-manifest', roles: Object.freeze(['backup_producer']) }),
  'backup-receipts': Object.freeze({ format: 'jedi-atlas-backup-durability-receipt', roles: Object.freeze(['backup_verifier']) }),
  'restore-authorizations': Object.freeze({ format: 'jedi-atlas-restore-authorization', roles: Object.freeze(['restore_requester']) }),
  'restore-plans': Object.freeze({ format: 'jedi-atlas-restore-plan', roles: Object.freeze(['restore_executor']) }),
  'restore-lifecycle': Object.freeze({ format: 'jedi-atlas-restore-lifecycle-record', roles: Object.freeze(['restore_requester', 'restore_executor', 'control_state_verifier', 'restored_state_verifier']) }),
  'deletion-aware': Object.freeze({ format: 'jedi-atlas-deletion-aware-reconstruction', roles: Object.freeze(['control_state_verifier']) }),
  'retention-controls': Object.freeze({ format: 'jedi-atlas-backup-retention-control', roles: Object.freeze(['legal_records_authority']) }),
  'retention-heads': Object.freeze({ format: 'jedi-atlas-retention-head-attestation', roles: Object.freeze(['control_state_verifier']) }),
  'retention-journal': Object.freeze({ format: 'jedi-atlas-retention-journal-record', roles: Object.freeze(['legal_records_authority', 'control_state_verifier']) }),
  'restore-drills': Object.freeze({ format: 'jedi-atlas-restore-drill-record', roles: Object.freeze(['restored_state_verifier']) }),
})

export function createD951History({ store, clock, faultInjector = null }) {
  assertDurableNamespaceStore(store)
  if (D951_NAMESPACES.some((code) => !store.namespaceCodes.includes(code)) || typeof clock !== 'function') failD951('D951_HISTORY_INVALID', 'history requires the exact namespace inventory and trusted clock')
  function records(namespace) { return store.inventory().projection[namespace].map(({ record_code: code }) => {
    const value = JSON.parse(store.read({ namespaceCode: namespace, recordCode: code }).toString('utf8'))
    if (value.record_digest_sha256 !== canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' })) failD951('D951_HISTORY_CORRUPT', `${namespace}/${code} has an invalid self digest`)
    return deepFreeze(value)
  }) }
  function validateGlobalChain(receipts) {
    let previous = null
    for (const [index, receipt] of receipts.toSorted((a, b) => a.receipt_sequence - b.receipt_sequence).entries()) {
      validateD950Record('journal-append-receipt-v1.schema.json', receipt)
      if (receipt.receipt_sequence !== index + 1 || receipt.previous_receipt_record_digest_sha256 !== previous) failD951('D951_HISTORY_CHAIN_INVALID', 'global journal is gapped, forked, or rolled back')
      previous = receipt.record_digest_sha256
    }
  }
  function head() { const receipts = records('global-journal'); validateGlobalChain(receipts); return receipts.toSorted((a, b) => a.receipt_sequence - b.receipt_sequence).at(-1) ?? null }
  function verifyCompleteState() {
    const receipts = records('global-journal'); validateGlobalChain(receipts)
    const targetRecords = []
    for (const namespace of D951_NAMESPACES.filter((item) => item !== 'global-journal')) for (const record of records(namespace)) targetRecords.push({ namespace, record })
    const used = new Set()
    for (const { namespace, record } of targetRecords) {
      const matches = receipts.filter((item) => item.target_record_code === record.record_code && item.target_record_digest_sha256 === record.record_digest_sha256 && item.target_format === record.format)
      if (matches.length !== 1) failD951('D951_RECOVERY_REQUIRED', `target ${namespace}/${record.record_code} does not have exactly one receipt`)
      used.add(matches[0].record_digest_sha256)
    }
    if (used.size !== receipts.length) failD951('D951_RECOVERY_REQUIRED', 'global journal contains an orphan or duplicate target receipt')
    return Object.freeze({ receiptCount: receipts.length, targetCount: targetRecords.length })
  }
  return Object.freeze({
    append({ namespaceCode, record, semanticSession, persistenceSession }) {
      if (!D951_NAMESPACES.includes(namespaceCode) || namespaceCode === 'global-journal') failD951('D951_NAMESPACE_INVALID', 'target namespace is not appendable')
      assertD951Session(semanticSession); assertD951Session(persistenceSession, 'persistence_broker')
      if (semanticSession.bindingCode === persistenceSession.bindingCode) failD951('D951_SEPARATION_VIOLATION', 'semantic and persistence actors must differ')
      const rule = NAMESPACE_RULES[namespaceCode]
      if (!rule || record?.format !== rule.format || !rule.roles.includes(semanticSession.semanticRoleCode)) failD951('D951_NAMESPACE_ROLE_FORBIDDEN', 'record format or semantic role cannot write this namespace')
      verifyCompleteState()
      const sealed = record.record_digest_sha256 ? deepFreeze(structuredClone(record)) : sealD951(record)
      const replay = store.inventory().projection[namespaceCode].find(({ record_code: code }) => code === sealed.record_code)
      if (replay) {
        const prior = store.read({ namespaceCode, recordCode: sealed.record_code })
        if (canonicalSha256(JSON.parse(prior.toString('utf8'))) !== canonicalSha256(sealed)) failD951('D951_REPLAY_COLLISION', 'record code already names different content')
        const receipt = records('global-journal').find((item) => item.target_record_digest_sha256 === sealed.record_digest_sha256)
        if (!receipt) failD951('D951_RECOVERY_REQUIRED', 'target exists without its journal receipt')
        return Object.freeze({ record: sealed, receipt, created: false })
      }
      const prior = head(); const persistedAt = assertTimestamp(clock(), 'persistence time')
      const receipt = sealD951({ format: 'jedi-atlas-d950-journal-append-receipt', format_version: '1.0.0', record_code: `receipt-${String((prior?.receipt_sequence ?? 0) + 1).padStart(8, '0')}`, journal_namespace_code: 'd950.global.journal.v1', receipt_sequence: (prior?.receipt_sequence ?? 0) + 1, previous_receipt_record_digest_sha256: prior?.record_digest_sha256 ?? null, target_format: sealed.format, target_record_code: sealed.record_code, target_record_digest_sha256: sealed.record_digest_sha256, operation_id: sealed.operation_id ?? sealed.record_code, operation_nonce: sealed.operation_nonce ?? '0'.repeat(64), semantic_actor: semanticSession.actor, persistence_actor: persistenceSession.actor, semantic_recorded_at: sealed.persisted_at ?? sealed.created_at ?? persistedAt, persisted_at: persistedAt, durability_state_code: 'record_and_receipt_flushed_in_protected_d950_ledger', record_digest_sha256: null })
      validateD950Record('journal-append-receipt-v1.schema.json', receipt)
      store.append({ namespaceCode, recordCode: sealed.record_code, bytes: durableJsonBytes(sealed) })
      faultInjector?.('after_target_before_receipt', { namespaceCode, sealed })
      store.append({ namespaceCode: 'global-journal', recordCode: receipt.record_code, bytes: durableJsonBytes(receipt) })
      return Object.freeze({ record: sealed, receipt, created: true })
    },
    records, head,
    verifyComplete: verifyCompleteState,
  })
}
