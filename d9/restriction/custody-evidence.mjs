import { canonicalSha256, canonicalize, sha256Bytes } from '../control-plane/canonical.mjs'
import { assertApprovedD930ContractSet, validateD930Record } from '../custody/contracts.mjs'
import { failD941 } from './errors.mjs'

const evidenceSets = new WeakSet()

export function createD941SyntheticCustodyEvidence({ contractSet, operationalProfile, primaryReceipt, subject }) {
  assertApprovedD930ContractSet(contractSet)
  validateD930Record({ contractSet, record: operationalProfile })
  validateD930Record({ contractSet, record: primaryReceipt })
  if (primaryReceipt.d930_operational_profile_record_digest_sha256 !== operationalProfile.record_digest_sha256 ||
      primaryReceipt.semantic_payload_sha256 !== canonicalSha256(primaryReceipt.semantic) ||
      primaryReceipt.semantic.finalization_outcome_code !== 'published' ||
      primaryReceipt.semantic.no_replace_disposition_code !== 'created_new' ||
      primaryReceipt.semantic.file_data_synced !== true || primaryReceipt.semantic.parent_directory_synced !== true ||
      primaryReceipt.semantic.no_replace_enforced !== true || primaryReceipt.semantic.reopened_and_rehashed !== true ||
      typeof primaryReceipt.persistence_request_record_digest_sha256 !== 'string' ||
      typeof primaryReceipt.persisted_by_binding_code !== 'string') {
    failD941('D941_CUSTODY_EVIDENCE_UNVERIFIED', 'D9.3 receipt is not an exact, durably linked primary finalization result')
  }
  const semantic = primaryReceipt.semantic
  if (canonicalize(semantic.artifact) !== canonicalize(subject.subject_payload.artifact) || semantic.copy_code !== subject.subject_payload.copy_code ||
    semantic.backend_code !== subject.subject_payload.backend_code || semantic.backend_reference !== subject.subject_payload.backend_reference) {
    failD941('D941_CUSTODY_EVIDENCE_SUBJECT_MISMATCH', 'D9.3 primary receipt does not resolve the exact custody subject')
  }
  const receiptSha256 = sha256Bytes(Buffer.from(canonicalize(primaryReceipt), 'utf8'))
  const lineageProjectionSha256 = canonicalSha256({ operation_id: semantic.operation_id, operation_nonce: semantic.operation_nonce, bundle: semantic.bundle, artifact: semantic.artifact, copy_code: semantic.copy_code })
  const custodyLeafProjectionSha256 = canonicalSha256({ artifact: semantic.artifact, copy_code: semantic.copy_code, backend_code: semantic.backend_code, backend_reference: semantic.backend_reference, primary_receipt_sha256: receiptSha256 })
  const evidence = Object.freeze({
    d930OperationalProfileSha256: operationalProfile.record_digest_sha256,
    d930PrimaryDurabilityReceiptSha256: receiptSha256,
    subjectLineageProjectionSha256: lineageProjectionSha256,
    custodyLeafProjectionSha256,
    resolve() { return Object.freeze({ d930OperationalProfileSha256: operationalProfile.record_digest_sha256, d930PrimaryDurabilityReceiptSha256: receiptSha256, subjectLineageProjectionSha256: lineageProjectionSha256, custodyLeafProjectionSha256 }) },
  })
  evidenceSets.add(evidence)
  return evidence
}

export function assertD941SyntheticCustodyEvidence(value) {
  if (!evidenceSets.has(value)) failD941('D941_CUSTODY_EVIDENCE_UNTRUSTED', 'custody evidence was not resolved through the fixed D9.3 verifier')
  return value
}
