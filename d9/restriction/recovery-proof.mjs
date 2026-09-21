import { failD941 } from './errors.mjs'

const proofs = new WeakSet()
const recordProofs = new WeakMap()

export function issueD941RecoveryClassificationProof(record, reconstruction, broker) {
  const proof = Object.freeze({
    record_digest_sha256: record.record_digest_sha256,
    reconstruction_digest_sha256: reconstruction.protected_inventory_digest_sha256,
    subject_identity_sha256: record.subject.subject_identity_sha256,
    ledger_head_digest_sha256: broker.head().digest,
    inventory_digest_sha256: broker.store.inventory().digest,
  })
  proofs.add(proof); recordProofs.set(record, proof)
  return proof
}

export function getD941RecoveryClassificationProof(record) { return recordProofs.get(record) ?? null }

export function assertD941RecoveryClassificationProof(proof, record) {
  if (!proof || !proofs.has(proof) || proof.record_digest_sha256 !== record.record_digest_sha256 ||
      proof.subject_identity_sha256 !== record.subject.subject_identity_sha256 || proof.reconstruction_digest_sha256 !== proof.inventory_digest_sha256) {
    failD941('D941_RECOVERY_CLASSIFICATION_UNPROVEN', 'recovery assessment lacks a fixed protected-state classification proof')
  }
  return true
}
