import assert from 'node:assert/strict'
import test from 'node:test'
import { loadApprovedContractSet } from '../d9/control-plane/contracts.mjs'
import { resolvePeerBinding } from '../d9/control-plane/identity.mjs'
import {
  contractRoot,
  createGenerationFixture,
  verifyFixture,
} from './d9-1-support/runtime-fixture.mjs'

function kernelFacts(binding, overrides = {}) {
  return {
    pid: 45123,
    uid: binding.unix_uid,
    gid: 65123,
    executableSha256: binding.executable_sha256,
    ipcEndpointCode: binding.ipc_endpoint_code,
    ...overrides,
  }
}

function setup(t) {
  const contractSet = loadApprovedContractSet({ contractRoot })
  const fixture = createGenerationFixture(t)
  const generation = verifyFixture(contractSet, fixture)
  const binding = (role) => generation.identityBindings.bindings.find((candidate) => candidate.runtime_role_code === role)
  return { generation, binding }
}

test('kernel UID, service build, endpoint, mode, and protected binding resolve together', (t) => {
  const { generation, binding } = setup(t)
  const importer = binding('bundle_importer')
  const resolved = resolvePeerBinding({
    verifiedGeneration: generation,
    operationModeCode: 'bootstrap',
    expectedRuntimeRoleCode: 'bundle_importer',
    peer: kernelFacts(importer),
    asOf: '2030-01-01T00:10:00.000Z',
  })
  assert.equal(resolved.bindingCode, importer.binding_code)
  assert.equal(resolved.atlasPrincipalCode, 'synthetic.importer')
  assert.equal(resolved.uid, importer.unix_uid)
})

test('caller identity spoofing, peer mismatch, build substitution, endpoint substitution, and mode misuse fail closed', async (t) => {
  const { generation, binding } = setup(t)
  const importer = binding('bundle_importer')
  const base = {
    verifiedGeneration: generation,
    operationModeCode: 'bootstrap',
    expectedRuntimeRoleCode: 'bundle_importer',
    peer: kernelFacts(importer),
    asOf: '2030-01-01T00:10:00.000Z',
  }
  const cases = [
    ['unmapped UID', { peer: kernelFacts(importer, { uid: 999_999 }) }, 'PEER_IDENTITY_UNMAPPED'],
    ['wrong role', { expectedRuntimeRoleCode: 'trusted_launcher' }, 'PEER_ROLE_MISMATCH'],
    ['build substitution', { peer: kernelFacts(importer, { executableSha256: '0'.repeat(64) }) }, 'PEER_BUILD_OR_ENDPOINT_MISMATCH'],
    ['endpoint substitution', { peer: kernelFacts(importer, { ipcEndpointCode: 'ipc.writer' }) }, 'PEER_BUILD_OR_ENDPOINT_MISMATCH'],
    ['forbidden mode', { operationModeCode: 'unknown_mode' }, 'PEER_OPERATION_FORBIDDEN'],
    ['caller principal field', { peer: { ...kernelFacts(importer), atlasPrincipalCode: 'system.bootstrap' } }, 'PEER_ATTESTATION_INVALID'],
  ]
  for (const [label, override, code] of cases) {
    await t.test(label, () => {
      assert.throws(() => resolvePeerBinding({ ...base, ...override }), (error) => error.code === code)
    })
  }
})

test('human mapping carries no service-build or endpoint claim', (t) => {
  const { generation, binding } = setup(t)
  const submitter = binding('human_submitter')
  const base = {
    verifiedGeneration: generation,
    operationModeCode: 'bootstrap',
    expectedRuntimeRoleCode: 'human_submitter',
    asOf: '2030-01-01T00:10:00.000Z',
  }
  assert.equal(resolvePeerBinding({ ...base, peer: kernelFacts(submitter) }).bindingCode, submitter.binding_code)
  assert.throws(
    () => resolvePeerBinding({ ...base, peer: kernelFacts(submitter, { executableSha256: '1'.repeat(64) }) }),
    (error) => error.code === 'PEER_ATTESTATION_INVALID',
  )
})
