import { canonicalSha256 } from '../control-plane/canonical.mjs'
import { assertDurableNamespaceStore, durableJsonBytes } from '../custody/durable-store.mjs'
import { assertTimestamp, sealD951 } from './contracts.mjs'
import { failD951 } from './errors.mjs'

export const D951_NAMESPACES = Object.freeze([
  'backup-manifests', 'backup-receipts', 'restore-authorizations', 'restore-plans', 'restore-lifecycle',
  'deletion-aware', 'retention-controls', 'retention-heads', 'retention-journal', 'restore-drills', 'global-journal',
])

export function createD951History({ store, clock, faultInjector = null }) {
  assertDurableNamespaceStore(store)
  if (D951_NAMESPACES.some((code) => !store.namespaceCodes.includes(code)) || typeof clock !== 'function') failD951('D951_HISTORY_INVALID', 'history requires the exact namespace inventory and trusted clock')
  function records(namespace) { return store.inventory().projection[namespace].map(({ record_code: code }) => JSON.parse(store.read({ namespaceCode: namespace, recordCode: code }).toString('utf8'))) }
  function head() { return records('global-journal').toSorted((a, b) => a.receipt_sequence - b.receipt_sequence).at(-1) ?? null }
  return Object.freeze({
    append({ namespaceCode, record, semanticSession, persistenceSession }) {
      if (!D951_NAMESPACES.includes(namespaceCode) || namespaceCode === 'global-journal') failD951('D951_NAMESPACE_INVALID', 'target namespace is not appendable')
      if (semanticSession.bindingCode === persistenceSession.bindingCode) failD951('D951_SEPARATION_VIOLATION', 'semantic and persistence actors must differ')
      const sealed = record.record_digest_sha256 ? Object.freeze(structuredClone(record)) : sealD951(record)
      const replay = store.inventory().projection[namespaceCode].find(({ record_code: code }) => code === sealed.record_code)
      if (replay) {
        const prior = store.read({ namespaceCode, recordCode: sealed.record_code })
        if (canonicalSha256(JSON.parse(prior.toString('utf8'))) !== canonicalSha256(sealed)) failD951('D951_REPLAY_COLLISION', 'record code already names different content')
        const receipt = records('global-journal').find((item) => item.target_record_digest_sha256 === sealed.record_digest_sha256)
        if (!receipt) failD951('D951_RECOVERY_REQUIRED', 'target exists without its journal receipt')
        return Object.freeze({ record: sealed, receipt, created: false })
      }
      const prior = head(); const persistedAt = assertTimestamp(clock(), 'persistence time')
      const receipt = sealD951({ format: 'jedi-atlas-d951-journal-receipt', format_version: '1.0.0', record_code: `receipt-${String((prior?.receipt_sequence ?? 0) + 1).padStart(8, '0')}`, journal_namespace_code: namespaceCode, receipt_sequence: (prior?.receipt_sequence ?? 0) + 1, previous_receipt_record_digest_sha256: prior?.record_digest_sha256 ?? null, target_format: sealed.format, target_record_code: sealed.record_code, target_record_digest_sha256: sealed.record_digest_sha256, operation_id: sealed.operation_id ?? sealed.record_code, operation_nonce: sealed.operation_nonce ?? '0'.repeat(64), semantic_actor_binding_code: semanticSession.bindingCode, persistence_actor_binding_code: persistenceSession.bindingCode, semantic_recorded_at: sealed.persisted_at ?? sealed.created_at ?? persistedAt, persisted_at: persistedAt, durability_state_code: 'durable', record_digest_sha256: null })
      store.append({ namespaceCode, recordCode: sealed.record_code, bytes: durableJsonBytes(sealed) })
      faultInjector?.('after_target_before_receipt', { namespaceCode, sealed })
      store.append({ namespaceCode: 'global-journal', recordCode: receipt.record_code, bytes: durableJsonBytes(receipt) })
      return Object.freeze({ record: sealed, receipt, created: true })
    },
    records, head,
  })
}
