import { spawn } from 'node:child_process'
import { once } from 'node:events'

import { canonicalSha256 } from '../control-plane/canonical.mjs'
import { failD941 } from './errors.mjs'

const inventories = new WeakSet()
const effectProofs = new WeakSet()

export function createD941SyntheticAccessInventory() {
  const capability = Object.freeze({
    kind: 'unconsumed_capability', capability_record_digest_sha256: '1'.repeat(64), capability_leaf_record_digest_sha256: '2'.repeat(64),
  })
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })
  const descriptor = Object.freeze({
    kind: 'issued_descriptor', descriptor_lifecycle_record_digest_sha256: '3'.repeat(64), receiver_process_instance_code: 'receiver.synthetic.001', pid: child.pid,
  })
  const identity = (item) => canonicalSha256(item.kind === 'unconsumed_capability'
    ? { access_target_kind_code: item.kind, capability_record_digest_sha256: item.capability_record_digest_sha256, capability_leaf_record_digest_sha256: item.capability_leaf_record_digest_sha256 }
    : { access_target_kind_code: item.kind, descriptor_lifecycle_record_digest_sha256: item.descriptor_lifecycle_record_digest_sha256, receiver_process_instance_code: item.receiver_process_instance_code })
  let capabilityRevoked = false
  let receiverTerminated = false
  const inventory = Object.freeze({
    entries() { return Object.freeze([Object.freeze({ ...capability, identity: identity(capability) }), Object.freeze({ ...descriptor, identity: identity(descriptor) })]) },
    revokeCapability(targetIdentity) {
      if (targetIdentity !== identity(capability) || capabilityRevoked) failD941('D941_CAPABILITY_REVOCATION_INVALID', 'capability is unknown or already revoked')
      capabilityRevoked = true
    },
    async terminateAndReap(targetIdentity) {
      if (targetIdentity !== identity(descriptor) || receiverTerminated) failD941('D941_DESCRIPTOR_TERMINATION_INVALID', 'descriptor receiver is unknown or already terminal')
      child.kill('SIGTERM'); await once(child, 'exit'); receiverTerminated = true
    },
    effectProof(record) {
      const expected = record.access_target_kind_code === 'unconsumed_capability' ? capabilityRevoked : receiverTerminated
      if (!expected || !['capability_revoked', 'descriptor_termination_confirmed'].includes(record.record_kind_code)) failD941('D941_ACCESS_EFFECT_UNPROVEN', 'terminal access record lacks the fixed-function effect attestation')
      const proof = Object.freeze({ record_digest_sha256: record.record_digest_sha256, target_identity: record.access_target_identity_sha256, operation_id: record.operation_id, operation_nonce: record.operation_nonce, inventory_identity_sha256: canonicalSha256(inventory.entries()) })
      effectProofs.add(proof)
      return proof
    },
    assertShutdown() {
      if (!capabilityRevoked || !receiverTerminated) failD941('D941_ACCESS_SHUTDOWN_INCOMPLETE', 'live capability or receiver remains active')
      return true
    },
    dispose() { if (child.exitCode === null) child.kill('SIGKILL'); inventories.delete(inventory) },
  })
  inventories.add(inventory)
  return inventory
}

export function assertD941AccessEffectProof(proof, record) {
  if (!proof || !effectProofs.has(proof) || proof.record_digest_sha256 !== record.record_digest_sha256 || proof.target_identity !== record.access_target_identity_sha256 || proof.operation_id !== record.operation_id || proof.operation_nonce !== record.operation_nonce) {
    failD941('D941_ACCESS_EFFECT_UNPROVEN', 'terminal access record was not produced by the fixed-function revocation/termination effect')
  }
  return true
}

export function assertD941SyntheticAccessInventory(value) {
  if (!inventories.has(value)) failD941('D941_ACCESS_INVENTORY_UNTRUSTED', 'access inventory is not the fixed synthetic runtime')
  return value
}
