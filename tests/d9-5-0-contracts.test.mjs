import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

test('D9.5.0 design-only contracts pass the offline validator', { timeout: 180_000 }, () => {
  const output = execFileSync(
    process.execPath,
    ['--disable-warning=ExperimentalWarning', 'docs/schema/validate-d9-5-0.mjs'],
    { cwd: project, encoding: 'utf8' },
  )

  const result = JSON.parse(output)
  assert.equal(result.schemas, 13)
  assert.equal(result.registries, 4)
  assert.equal(result.invalid_adversarial_cases, 62)
  assert.equal(result.valid_synthetic_contract_records, 66)
  assert.equal(result.drill_matrix_positive_cases, 4)
  assert.ok(result.digest_leaf_mutations >= 2500)
  assert.equal(result.frozen_validators_executed, 7)
  assert.equal(result.frozen_migrations, 5)
  assert.equal(result.atlas_tables_empty, 13)
  assert.equal(result.integrity_check, 'ok')
  assert.equal(result.foreign_key_check, 'clean')
})
