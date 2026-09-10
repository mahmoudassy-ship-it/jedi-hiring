import assert from 'node:assert/strict'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { loadApprovedContractSet } from '../d9/control-plane/contracts.mjs'
import {
  deriveHandleScope,
  handleGrantKey,
  syntheticVerifiedOperationFactSets,
  verifyIssuedHandleGrants,
} from '../d9/control-plane/scopes.mjs'

const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const contractSet = loadApprovedContractSet({ contractRoot: path.join(projectDirectory, 'docs/schema/d9-0') })
const rules = contractSet.classification.operation_handle_scope_rules
const selectorFields = contractSet.classification.operation_handle_scope_policy.selector_fields
const syntheticFactSets = syntheticVerifiedOperationFactSets({ contractSet })

function factsFor(rule) {
  const matches = syntheticFactSets.filter((facts) => selectorFields.every((field) => facts[field] === rule[field]))
  assert.equal(matches.length, 1)
  return matches[0]
}

function assertScopeFailure(action) {
  assert.throws(action, (error) => {
    assert.match(error.code, /^HANDLE_SCOPE_/u)
    return true
  })
}

test('all seven D9.0.1 selectors derive one exact 33-grant partition', () => {
  assert.equal(rules.length, 7)
  assert.deepEqual(rules.map((rule) => rule.required_handle_grants.length), [5, 12, 15, 11, 24, 7, 9])

  for (const rule of rules) {
    const scope = deriveHandleScope({ contractSet, verifiedFacts: factsFor(rule) })
    assert.equal(scope.operation_scope_code, rule.operation_scope_code)
    assert.equal(scope.required_handle_grants.length + scope.forbidden_handle_grants.length, 33)
    assert.equal(new Set([...scope.required_handle_grants, ...scope.forbidden_handle_grants].map(handleGrantKey)).size, 33)
    assert.deepEqual(verifyIssuedHandleGrants({ contractSet, scope, issuedGrants: structuredClone(scope.required_handle_grants) }), scope.required_handle_grants)
  }
})

test('every missing required grant and every additional forbidden grant is rejected', () => {
  for (const rule of rules) {
    const scope = deriveHandleScope({ contractSet, verifiedFacts: factsFor(rule) })
    for (let index = 0; index < scope.required_handle_grants.length; index += 1) {
      const missing = structuredClone(scope.required_handle_grants)
      missing.splice(index, 1)
      assertScopeFailure(() => verifyIssuedHandleGrants({ contractSet, scope, issuedGrants: missing }))
    }
    for (const forbidden of scope.forbidden_handle_grants) {
      const additional = [...structuredClone(scope.required_handle_grants), structuredClone(forbidden)]
      assertScopeFailure(() => verifyIssuedHandleGrants({ contractSet, scope, issuedGrants: additional }))
    }
  }
})

test('complete-scope substitution, wrong recipient, wrong access, and duplicates are rejected', () => {
  for (const [index, rule] of rules.entries()) {
    const scope = deriveHandleScope({ contractSet, verifiedFacts: factsFor(rule) })
    const other = rules[(index + 1) % rules.length]
    assertScopeFailure(() => verifyIssuedHandleGrants({
      contractSet,
      scope,
      issuedGrants: structuredClone(other.required_handle_grants),
    }))

    const wrongRecipient = structuredClone(scope.required_handle_grants)
    wrongRecipient[0].runtime_role_code = wrongRecipient[0].runtime_role_code === 'trusted_launcher' ? 'bundle_importer' : 'trusted_launcher'
    assertScopeFailure(() => verifyIssuedHandleGrants({ contractSet, scope, issuedGrants: wrongRecipient }))

    const wrongAccess = structuredClone(scope.required_handle_grants)
    wrongAccess[0].access_code = wrongAccess[0].access_code === 'read_only' ? 'write_fixed_function' : 'read_only'
    assertScopeFailure(() => verifyIssuedHandleGrants({ contractSet, scope, issuedGrants: wrongAccess }))

    const duplicate = [...structuredClone(scope.required_handle_grants), structuredClone(scope.required_handle_grants[0])]
    assertScopeFailure(() => verifyIssuedHandleGrants({ contractSet, scope, issuedGrants: duplicate }))
  }
})

test('caller-selected scope, unmatched facts, malformed grants, and fabricated scopes fail closed', () => {
  const facts = factsFor(rules[0])
  assertScopeFailure(() => deriveHandleScope({
    contractSet,
    verifiedFacts: { ...facts, operation_scope_code: rules[0].operation_scope_code },
  }))
  assertScopeFailure(() => deriveHandleScope({
    contractSet,
    verifiedFacts: { ...facts, source_authorization_code: 'caller_selected' },
  }))

  const scope = deriveHandleScope({ contractSet, verifiedFacts: facts })
  const malformed = structuredClone(scope.required_handle_grants)
  malformed[0].descriptor = 7
  assertScopeFailure(() => verifyIssuedHandleGrants({ contractSet, scope, issuedGrants: malformed }))
  assertScopeFailure(() => verifyIssuedHandleGrants({
    contractSet,
    scope: structuredClone(scope),
    issuedGrants: structuredClone(scope.required_handle_grants),
  }))
})
