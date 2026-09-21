import { canonicalSha256 } from '../control-plane/canonical.mjs'
import { assertD941LedgerBroker } from './ledger.mjs'
import { failD941 } from './errors.mjs'

const namespaceByFormat = Object.freeze({
  'jedi-atlas-custody-control-record': 'control',
  'jedi-atlas-access-revocation-record': 'access',
  'jedi-atlas-deletion-execution-record': 'execution',
  'jedi-atlas-deletion-receipt': 'receipt',
  'jedi-atlas-backup-coordination-record': 'backup',
  'jedi-atlas-d940-recovery-assessment': 'recovery',
})

function boundedRecords(broker, subjectIdentitySha256, { knownThroughSequence, knownAt }) {
  const receipts = broker.validate().filter((receipt) => receipt.receipt_sequence <= knownThroughSequence && receipt.persisted_at <= knownAt)
  if (receipts.length !== knownThroughSequence || receipts.some((receipt, index) => receipt.receipt_sequence !== index + 1)) {
    failD941('D941_PROJECTION_LEDGER_GAP', 'knowledge-bounded ledger has a gap, fork, or unavailable receipt')
  }
  return receipts.filter((receipt) => receipt.target_subject_identity_sha256 === subjectIdentitySha256).map((receipt) => {
    const record = JSON.parse(broker.store.read({ namespaceCode: namespaceByFormat[receipt.target_format], recordCode: receipt.target_record_code }).toString('utf8'))
    return { receipt, record }
  })
}

export function projectD941Subject({ broker, subjectIdentitySha256, effectiveAsOf, knownAt, knownThroughSequence, operationId = null, operationNonce = null }) {
  assertD941LedgerBroker(broker)
  const bounded = boundedRecords(broker, subjectIdentitySha256, { knownThroughSequence, knownAt })
  const allControls = bounded.filter(({ record }) => record.format === 'jedi-atlas-custody-control-record' && record.knowledge_boundary.effective_at <= effectiveAsOf).map(({ record }) => record)
  const controls = operationId === null ? allControls : allControls.filter((record) => record.operation_id === operationId && record.operation_nonce === operationNonce)
  const access = bounded.filter(({ record }) => record.format === 'jedi-atlas-access-revocation-record').map(({ record }) => record)
  const backups = bounded.filter(({ record }) => record.format === 'jedi-atlas-backup-coordination-record').map(({ record }) => record)

  // Corrections are resolved over the complete subject stream.  Applying the
  // correction set only to an operation-scoped slice would make a global hold
  // disappear merely because it was authored by another operation.
  const superseded = new Set()
  for (const record of allControls) {
    if (['control_corrected', 'control_withdrawn'].includes(record.record_kind_code) && record.corrects_record_digest_sha256) superseded.add(record.corrects_record_digest_sha256)
  }
  const activeControls = controls.filter((record) => !superseded.has(record.record_digest_sha256) && record.record_kind_code !== 'control_withdrawn')
  const activeBlockingControls = allControls.filter((record) => !superseded.has(record.record_digest_sha256) && record.record_kind_code !== 'control_withdrawn')
  const semanticKind = (record) => record.record_kind_code === 'control_corrected' ? record.corrected_record_kind_code : record.record_kind_code
  // Resolve one semantic leaf per control stream.  A release in stream B may
  // never clear an independently active restriction/hold in stream A.
  const leaves = (source) => [...source.reduce((streams, record) => {
    const key = record.chain?.stream_code ?? record.record_code
    streams.set(key, record)
    return streams
  }, new Map()).values()]
  const latest = (kinds, source = activeControls) => leaves(source.filter((record) => kinds.includes(semanticKind(record)))).at(-1) ?? null
  const anyActive = (imposedKind, releasedKind, source) => leaves(source.filter((record) => [imposedKind, releasedKind].includes(semanticKind(record)))).some((record) => semanticKind(record) === imposedKind)
  const restriction = latest(['restriction_imposed', 'restriction_released'], activeBlockingControls)
  const quarantine = latest(['quarantine_imposed', 'quarantine_released'], activeBlockingControls)
  const hold = latest(['hold_imposed', 'hold_released'], activeBlockingControls)
  const clearance = leaves(activeBlockingControls.filter((record) => semanticKind(record) === 'clearance_revoked')).at(-1) ?? null
  const tombstone = latest(['tombstone_applied'])
  const authorization = latest(['deletion_authorized', 'deletion_authorization_revoked', 'deletion_denied'])
  const activeRestriction = anyActive('restriction_imposed', 'restriction_released', activeBlockingControls)
  const activeQuarantine = anyActive('quarantine_imposed', 'quarantine_released', activeBlockingControls)
  const activeHold = anyActive('hold_imposed', 'hold_released', activeBlockingControls)
  const authorizationActive = authorization && semanticKind(authorization) === 'deletion_authorized' && authorization.authorization_expires_at > effectiveAsOf
  const capabilityRevoked = access.some((record) => record.record_kind_code === 'capability_revoked')
  const descriptorTargets = new Map()
  for (const record of access.filter((item) => item.access_target_kind_code === 'issued_descriptor')) descriptorTargets.set(record.access_target_identity_sha256, record)
  const descriptorsClosed = descriptorTargets.size > 0 && [...descriptorTargets.values()].every((record) => record.record_kind_code === 'descriptor_termination_confirmed' && record.receiver_termination_state_code === 'confirmed' && record.descriptor_close_state_code === 'confirmed')
  const accessShutdown = capabilityRevoked && descriptorsClosed
  const blocked = Boolean(activeRestriction || activeQuarantine || activeHold || clearance || tombstone)
  const result = {
    subject_identity_sha256: subjectIdentitySha256,
    effective_as_of: effectiveAsOf,
    known_at: knownAt,
    known_through_receipt_sequence: knownThroughSequence,
    control_count: controls.length,
    active_restriction: Boolean(activeRestriction), active_quarantine: Boolean(activeQuarantine), active_hold: Boolean(activeHold),
    clearance_revoked: Boolean(clearance), tombstoned: Boolean(tombstone), authorization_active: Boolean(authorizationActive),
    deletion_authorization_record_digest_sha256: authorizationActive ? authorization.record_digest_sha256 : null,
    deletion_request_record_digest_sha256: authorizationActive ? authorization.authorization_scope?.deletion_request_record_digest_sha256 ?? null : null,
    authorization_scope_sha256: authorizationActive ? authorization.authorization_scope_sha256 : null,
    tombstone_record_digest_sha256: tombstone?.record_digest_sha256 ?? null,
    access_shutdown_confirmed: accessShutdown,
    backup_or_unknown_copy_state: backups.length === 0 || backups.some((record) => record.execution_code === 'unreachable_until_d9_5'),
    access_eligibility_code: blocked ? 'withheld' : 'eligible_under_d940_only',
  }
  return Object.freeze({ ...result, projection_sha256: canonicalSha256(result) })
}

export function assertD941DeletionEligible(projection) {
  if (!projection.tombstoned || !projection.authorization_active || !projection.access_shutdown_confirmed || projection.active_hold ||
      projection.backup_or_unknown_copy_state !== true) {
    failD941('D941_DELETION_INELIGIBLE', 'restriction projection does not satisfy the exact bounded primary-name deletion gate')
  }
  return projection
}
