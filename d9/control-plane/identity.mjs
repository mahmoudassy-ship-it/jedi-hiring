import { assertVerifiedRuntimeGeneration } from './contracts.mjs'

const PEER_FIELDS = [
  'pid',
  'uid',
  'gid',
  'executableSha256',
  'ipcEndpointCode',
]
const TIMESTAMP_PATTERN = /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u

export class D9IdentityError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`)
    this.name = 'D9IdentityError'
    this.code = code
  }
}

function reject(code, message) {
  throw new D9IdentityError(code, message)
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    reject('PEER_ATTESTATION_INVALID', `${label} must be a plain object`)
  }
  const actual = Object.keys(value).toSorted()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected.toSorted()[index])) {
    reject('PEER_ATTESTATION_INVALID', `${label} has unknown or missing fields`)
  }
}

function canonicalTimestamp(value, label) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value) || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    reject('PEER_ATTESTATION_INVALID', `${label} is not a canonical UTC timestamp`)
  }
  return value
}

/**
 * Maps kernel facts to one protected binding. The launcher obtains `peer` from
 * its platform adapter; this function never treats manifest/CLI values as peer
 * facts and never accepts an Atlas principal code as authentication.
 */
export function resolvePeerBinding({
  verifiedGeneration,
  operationModeCode,
  expectedRuntimeRoleCode,
  peer,
  asOf,
}) {
  assertVerifiedRuntimeGeneration(verifiedGeneration)
  exactKeys(peer, PEER_FIELDS, 'kernel peer facts')
  canonicalTimestamp(asOf, 'asOf')
  if (!Number.isSafeInteger(peer.pid) || peer.pid < 1 ||
      !Number.isSafeInteger(peer.uid) || peer.uid < 0 ||
      !Number.isSafeInteger(peer.gid) || peer.gid < 0) {
    reject('PEER_ATTESTATION_INVALID', 'kernel peer PID/UID/GID is invalid')
  }
  if (peer.executableSha256 !== null && !/^[0-9a-f]{64}$/u.test(peer.executableSha256)) {
    reject('PEER_ATTESTATION_INVALID', 'kernel peer executable digest is invalid')
  }
  if (peer.ipcEndpointCode !== null && !/^[a-z0-9][a-z0-9._-]{1,94}[a-z0-9]$/u.test(peer.ipcEndpointCode)) {
    reject('PEER_ATTESTATION_INVALID', 'kernel peer endpoint is invalid')
  }

  const candidates = verifiedGeneration.identityBindings.bindings.filter((binding) => binding.unix_uid === peer.uid)
  if (candidates.length !== 1) reject('PEER_IDENTITY_UNMAPPED', 'kernel UID does not resolve to exactly one active binding')
  const binding = candidates[0]
  if (binding.runtime_role_code !== expectedRuntimeRoleCode) {
    reject('PEER_ROLE_MISMATCH', 'kernel UID is bound to a different runtime role')
  }
  if (!binding.allowed_operation_modes.includes(operationModeCode)) {
    reject('PEER_OPERATION_FORBIDDEN', 'binding is not eligible for this operation mode')
  }
  if (!(binding.valid_from <= asOf && asOf < binding.valid_until)) {
    reject('PEER_BINDING_INACTIVE', 'binding is not active at the protected evaluation time')
  }
  if (binding.principal_kind_code === 'service') {
    if (peer.executableSha256 !== binding.executable_sha256 || peer.ipcEndpointCode !== binding.ipc_endpoint_code) {
      reject('PEER_BUILD_OR_ENDPOINT_MISMATCH', 'service peer build or endpoint differs from its protected binding')
    }
  } else if (peer.executableSha256 !== null || peer.ipcEndpointCode !== null) {
    reject('PEER_ATTESTATION_INVALID', 'human peer facts must not invent a service build or endpoint')
  }

  return Object.freeze({
    bindingCode: binding.binding_code,
    runtimeRoleCode: binding.runtime_role_code,
    atlasPrincipalCode: binding.atlas_principal_code,
    principalKindCode: binding.principal_kind_code,
    pid: peer.pid,
    uid: peer.uid,
    gid: peer.gid,
  })
}
