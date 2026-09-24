import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalSha256, sha256Bytes } from '../control-plane/canonical.mjs'
import { failD951 } from './errors.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(here, '../../docs/schema/d9-5-0')
const SHA = /^[0-9a-f]{64}$/u

export const D950_FINGERPRINTS = Object.freeze({
  catalog: '7bd5805b2aa6646f40f09636060636ce7fdc32ef57bac6fc7e826b4de41d17fe',
  classifications: 'fa58f6701f33934eba9b59e58787a9075d3b2cdc619e0c9fbc4996bd0101247b',
  digestProfiles: 'e66777e1dcf6f03d1a6abaeaa68d75ad93735254b39b76159213db8b7c45c137',
  fieldRegistry: 'd2a5ea5476a1699cecf704dfd92b3071577ceee1e0cc46ed16c07f3854390c85',
  storageProfiles: 'a7ec47414e1553d37f2662b7991d8a5e45aaa5db1fe25e7e3d642eb11a768f32',
  validator: '27cce83bd58c7c3f7fcce467c2c286ba3b1490ba84405f986f03e3da4cb2553b',
  rootInventory: '8f25289beae9c844d587d8aacbdd88caf213ac29beb95effbc1d775705abd9f7',
})

function readJson(file) { return JSON.parse(fs.readFileSync(path.join(ROOT, file), 'utf8')) }
function raw(file) { return sha256Bytes(fs.readFileSync(path.join(ROOT, file))) }
function semantic(value) { return canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' }) }

export function loadD950ContractSet() {
  const catalog = readJson('contract-catalog-v1.json')
  const classifications = readJson('classifications-v1.json')
  const digestProfiles = readJson('digest-profiles-v1.json')
  const fieldRegistry = readJson('field-source-registry-v1.json')
  const storageProfiles = readJson('storage-profiles-v1.json')
  const rootInventory = readJson('root-inventory-v1.json')
  const actual = {
    catalog: raw('contract-catalog-v1.json'), classifications: semantic(classifications),
    digestProfiles: semantic(digestProfiles), fieldRegistry: semantic(fieldRegistry),
    storageProfiles: semantic(storageProfiles), validator: raw('../validate-d9-5-0.mjs'),
    rootInventory: raw('root-inventory-v1.json'),
  }
  for (const [key, expected] of Object.entries(D950_FINGERPRINTS)) {
    if (actual[key] !== expected) failD951('D951_FROZEN_CONTRACT_MISMATCH', `${key} differs from the approved D9.5.0 fingerprint`)
  }
  if (catalog.status_code !== 'design_only_contract_freeze' || classifications.status_code !== 'design_only_contract_freeze') {
    failD951('D951_FROZEN_CONTRACT_MISMATCH', 'D9.5.0 lifecycle boundary changed')
  }
  return Object.freeze({ catalog, classifications, digestProfiles, fieldRegistry, storageProfiles, rootInventory })
}

export function assertSha(value, label) {
  if (typeof value !== 'string' || !SHA.test(value)) failD951('D951_HASH_INVALID', `${label} must be lowercase SHA-256`)
  return value
}

export function assertTimestamp(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/u.test(value) || new Date(value).toISOString() !== value) {
    failD951('D951_TIME_INVALID', `${label} must be a canonical UTC timestamp`)
  }
  return value
}

export function sealD951(record) {
  const value = structuredClone(record)
  value.record_digest_sha256 = canonicalSha256(value, { excludedTopLevelField: 'record_digest_sha256' })
  return Object.freeze(value)
}
