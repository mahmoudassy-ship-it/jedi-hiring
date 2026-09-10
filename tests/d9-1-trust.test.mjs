import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {
  canonicalSha256,
  canonicalize,
  parseStrictJson,
} from '../d9/control-plane/canonical.mjs'
import {
  APPROVED_D9_FINGERPRINTS,
  assertVerifiedApprovedRecord,
  assertVerifiedRuntimeGeneration,
  loadApprovedContractSet,
  validateApprovedRecord,
  verifyRuntimeGeneration,
} from '../d9/control-plane/contracts.mjs'
import {
  contractRoot,
  createGenerationFixture,
  fixture,
  migrationsDirectory,
  reseal,
  verifyFixture,
} from './d9-1-support/runtime-fixture.mjs'

function temporaryDirectory(prefix = 'jedi-d9-1-trust-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix))
}

function assertCode(code) {
  return (error) => {
    assert.equal(error.code, code)
    return true
  }
}

test('D9 canonical JSON matches every approved micro-vector and rejects ambiguous input', () => {
  const golden = JSON.parse(fs.readFileSync(path.join(contractRoot, 'fixtures/golden-vectors-v1.json'), 'utf8'))
  for (const vector of golden.micro_vectors) {
    const payload = vector.excluded_top_level_field === null
      ? vector.value
      : Object.fromEntries(Object.entries(vector.value).filter(([key]) => key !== vector.excluded_top_level_field))
    assert.equal(canonicalize(payload), vector.canonical_utf8, vector.vector_code)
    assert.equal(canonicalSha256(vector.value, { excludedTopLevelField: vector.excluded_top_level_field }), vector.sha256, vector.vector_code)
  }

  assert.throws(() => parseStrictJson('{"outer":{"same":1,"same":2}}'), assertCode('DUPLICATE_KEY'))
  assert.throws(() => parseStrictJson(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), assertCode('INVALID_ENCODING'))
  assert.throws(() => parseStrictJson(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d])), assertCode('INVALID_ENCODING'))
  for (const number of ['-1', '1.0', '1e0', '-0']) {
    assert.throws(() => parseStrictJson(`{"number":${number}}`), assertCode('INVALID_NUMBER'))
  }
  assert.throws(() => parseStrictJson('{"a":{"b":{"c":1}}}', { maximumDepth: 2 }), assertCode('RESOURCE_LIMIT_EXCEEDED'))
  assert.throws(() => parseStrictJson('{"a":1,"b":2}', { maximumMembers: 1 }), assertCode('RESOURCE_LIMIT_EXCEEDED'))
  assert.throws(() => parseStrictJson('{}', { maximumBytes: 1 }), assertCode('INVALID_SIZE'))
})

test('approved D9.0.1 catalog, schema inventory, and four fingerprints verify', () => {
  const contractSet = loadApprovedContractSet({ contractRoot })
  assert.deepEqual(contractSet.fingerprints, APPROVED_D9_FINGERPRINTS)
  assert.equal(contractSet.catalog.format_version, '1.0.1')
  assert.equal(contractSet.catalog.schemas.find((entry) => entry.schema_file === 'runtime-profile-v1.schema.json').contract_version, '1.0.1')
  assert.equal(contractSet.classification.format_version, '1.0.1')
  assert.equal(contractSet.catalog.schemas.length, 11)
  assert.equal(contractSet.classification.logical_handle_slot_rules.length, 13)
  assert.equal(contractSet.classification.logical_handle_slot_rules.flatMap((slot) => slot.recipients).length, 33)
  assert.equal(contractSet.classification.operation_handle_scope_rules.length, 7)
})

test('catalog or schema byte substitution fails before runtime selection', (t) => {
  const root = temporaryDirectory('jedi-d9-1-contract-copy-')
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  fs.cpSync(contractRoot, root, { recursive: true })

  const catalogPath = path.join(root, 'contract-catalog-v1.json')
  fs.appendFileSync(catalogPath, ' ')
  assert.throws(() => loadApprovedContractSet({ contractRoot: root }), assertCode('RUNTIME_PROFILE_MISMATCH'))

  fs.copyFileSync(path.join(contractRoot, 'contract-catalog-v1.json'), catalogPath)
  fs.appendFileSync(path.join(root, 'runtime-profile-v1.schema.json'), '\n')
  assert.throws(() => loadApprovedContractSet({ contractRoot: root }), assertCode('INCOMPATIBLE_CONTRACT_VERSION'))
})

test('handoff, bundle-seal, and bootstrap-control records receive schema-and-digest brands', () => {
  const contractSet = loadApprovedContractSet({ contractRoot })
  for (const [fixtureCode, schemaFile] of [
    ['collector_handoff', 'collector-handoff-v1.schema.json'],
    ['bootstrap_bundle_seal', 'collector-handoff-v1.schema.json'],
    ['bootstrap_permit', 'bootstrap-control-v1.schema.json'],
    ['bootstrap_transition_in_progress', 'bootstrap-control-v1.schema.json'],
  ]) {
    const verified = validateApprovedRecord({
      contractSet,
      schemaFile,
      recordBytes: Buffer.from(canonicalize(fixture(fixtureCode))),
    })
    assert.equal(assertVerifiedApprovedRecord(verified, { contractSet, schemaFile }), verified)
    assert.ok(Object.isFrozen(verified))
  }

  const canonicalRecord = fixture('collector_handoff')
  for (const noncanonicalBytes of [
    Buffer.from(`${JSON.stringify(canonicalRecord, null, 2)}\n`, 'utf8'),
    Buffer.from(` ${canonicalize(canonicalRecord)}`, 'utf8'),
    Buffer.from(`${canonicalize(canonicalRecord)}\r\n`, 'utf8'),
    Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(canonicalRecord).reverse())), 'utf8'),
  ]) {
    assert.throws(
      () => validateApprovedRecord({ contractSet, schemaFile: 'collector-handoff-v1.schema.json', recordBytes: noncanonicalBytes }),
      assertCode('INCOMPATIBLE_CONTRACT_VERSION'),
    )
  }

  const unverified = fixture('bootstrap_bundle_seal')
  assert.throws(() => assertVerifiedApprovedRecord(unverified), assertCode('INCOMPATIBLE_CONTRACT_VERSION'))
  const unknown = { ...unverified, caller_override: true }
  reseal(unknown)
  assert.throws(() => validateApprovedRecord({ contractSet, schemaFile: 'collector-handoff-v1.schema.json', record: unknown }), assertCode('INCOMPATIBLE_CONTRACT_VERSION'))
  const wrongDigest = { ...unverified, record_digest_sha256: '0'.repeat(64) }
  assert.throws(() => validateApprovedRecord({ contractSet, schemaFile: 'collector-handoff-v1.schema.json', record: wrongDigest }), assertCode('INCOMPATIBLE_CONTRACT_VERSION'))
  const duplicateBytes = Buffer.from(JSON.stringify(unverified).replace('{', `{"format":"${unverified.format}",`))
  assert.throws(() => validateApprovedRecord({ contractSet, schemaFile: 'collector-handoff-v1.schema.json', recordBytes: duplicateBytes }), assertCode('INCOMPATIBLE_CONTRACT_VERSION'))
})

test('runtime and identity generation verifies closed shapes and every actual pinned file', (t) => {
  const contractSet = loadApprovedContractSet({ contractRoot })
  const generation = createGenerationFixture(t)
  const verified = verifyFixture(contractSet, generation)
  assert.equal(assertVerifiedRuntimeGeneration(verified), verified)
  assert.equal(verified.runtimeProfile.profile_generation, 7)
  assert.equal(verified.identityBindings.binding_generation, 11)
  assert.ok(Object.isFrozen(verified.runtimeProfile))
  assert.ok(Object.isFrozen(verified.identityBindings.bindings))
})

test('runtime and identity loaders reject every noncanonical transport form', (t) => {
  const contractSet = loadApprovedContractSet({ contractRoot })
  for (const target of ['runtime', 'identity']) {
    for (const form of ['pretty', 'leading-space', 'trailing-lf', 'reversed-keys']) {
      const generation = createGenerationFixture(t)
      const value = generation[target]
      const canonical = canonicalize(value)
      const bytes = (() => {
        if (form === 'pretty') return Buffer.from(JSON.stringify(value, null, 2), 'utf8')
        if (form === 'leading-space') return Buffer.from(` ${canonical}`, 'utf8')
        if (form === 'trailing-lf') return Buffer.from(`${canonical}\n`, 'utf8')
        return Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(value).reverse())), 'utf8')
      })()
      assert.notEqual(bytes.toString('utf8'), canonical)
      assert.throws(() => verifyRuntimeGeneration({
        contractSet,
        runtimeProfileBytes: target === 'runtime' ? bytes : Buffer.from(canonicalize(generation.runtime), 'utf8'),
        identityBindingsBytes: target === 'identity' ? bytes : Buffer.from(canonicalize(generation.identity), 'utf8'),
        selection: generation.selection,
        ...generation.options,
      }), assertCode(target === 'runtime' ? 'RUNTIME_PROFILE_MISMATCH' : 'IDENTITY_BINDING_MISMATCH'), `${target}:${form}`)
    }
  }
})

test('profile, build, dependency, migration, generation, and identity substitutions fail closed', async (t) => {
  const contractSet = loadApprovedContractSet({ contractRoot })

  await t.test('unknown runtime field', (t) => {
    const generation = createGenerationFixture(t)
    generation.runtime.caller_override = true
    reseal(generation.runtime)
    generation.selection.runtime_profile_record_digest_sha256 = generation.runtime.record_digest_sha256
    assert.throws(() => verifyFixture(contractSet, generation), assertCode('RUNTIME_PROFILE_MISMATCH'))
  })

  await t.test('stale selected generation', (t) => {
    const generation = createGenerationFixture(t)
    generation.selection.profile_generation += 1
    assert.throws(() => verifyFixture(contractSet, generation), assertCode('RUNTIME_PROFILE_MISMATCH'))
  })

  await t.test('executable substitution', (t) => {
    const generation = createGenerationFixture(t)
    fs.appendFileSync(generation.options.componentFiles.trusted_launcher.executable, 'substituted')
    assert.throws(() => verifyFixture(contractSet, generation), assertCode('RUNTIME_PROFILE_MISMATCH'))
  })

  await t.test('dependency-lock substitution', (t) => {
    const generation = createGenerationFixture(t)
    fs.appendFileSync(generation.options.componentFiles.bundle_importer.dependencyLock, 'substituted')
    assert.throws(() => verifyFixture(contractSet, generation), assertCode('RUNTIME_PROFILE_MISMATCH'))
  })

  await t.test('migration substitution', (t) => {
    const generation = createGenerationFixture(t)
    const copiedMigrations = path.join(generation.root, 'migrations')
    fs.cpSync(migrationsDirectory, copiedMigrations, { recursive: true })
    fs.appendFileSync(path.join(copiedMigrations, '005_tranche_2a_source_quarantine.sql'), '\n-- substituted')
    generation.options.migrationsDirectory = copiedMigrations
    assert.throws(() => verifyFixture(contractSet, generation), assertCode('RUNTIME_PROFILE_MISMATCH'))
  })

  await t.test('identity build substitution', (t) => {
    const generation = createGenerationFixture(t)
    generation.identity.bindings.find((binding) => binding.runtime_role_code === 'trusted_launcher').executable_sha256 = '0'.repeat(64)
    reseal(generation.identity)
    generation.selection.identity_bindings_record_digest_sha256 = generation.identity.record_digest_sha256
    assert.throws(() => verifyFixture(contractSet, generation), assertCode('IDENTITY_BINDING_MISMATCH'))
  })

  await t.test('expired binding generation', (t) => {
    const generation = createGenerationFixture(t)
    generation.options.asOf = generation.identity.expires_at
    assert.throws(() => verifyFixture(contractSet, generation), assertCode('IDENTITY_BINDING_MISMATCH'))
  })

  await t.test('duplicate protected record key', (t) => {
    const generation = createGenerationFixture(t)
    const bytes = Buffer.from(JSON.stringify(generation.runtime).replace('{', '{"format":"jedi-atlas-runtime-profile",'))
    assert.throws(() => verifyRuntimeGeneration({
      contractSet,
      runtimeProfileBytes: bytes,
      identityBindingsBytes: Buffer.from(canonicalize(generation.identity), 'utf8'),
      selection: generation.selection,
      ...generation.options,
    }), assertCode('RUNTIME_PROFILE_MISMATCH'))
  })
})
