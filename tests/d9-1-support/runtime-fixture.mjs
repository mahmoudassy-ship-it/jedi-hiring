import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { CONTROL_PLANE_SOURCE_FILES, runningExecutableSha256 } from '../../d9/control-plane/build-integrity.mjs'
import { canonicalSha256, canonicalize, sha256Bytes } from '../../d9/control-plane/canonical.mjs'
import { verifyRuntimeGeneration } from '../../d9/control-plane/contracts.mjs'

export const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
export const contractRoot = path.join(projectDirectory, 'docs/schema/d9-0')
export const migrationsDirectory = path.join(projectDirectory, 'data/migrations')
export const evidenceBundleSchemaPath = path.join(projectDirectory, 'docs/schema/tranche-2a-evidence-bundle-v1.schema.json')

const fixtures = JSON.parse(fs.readFileSync(path.join(contractRoot, 'fixtures/valid-contracts-v1.json'), 'utf8')).fixtures

export function fixture(code) {
  const match = fixtures.find((item) => item.fixture_code === code)
  if (!match) throw new Error(`Unknown synthetic D9 fixture: ${code}`)
  return structuredClone(match.value)
}

export function reseal(record) {
  record.record_digest_sha256 = canonicalSha256(record, { excludedTopLevelField: 'record_digest_sha256' })
  return record
}

function writeArtifact(root, relativePath, bytes) {
  const target = path.join(root, relativePath)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, bytes)
  return target
}

export function createGenerationFixture(t, { serviceExecutablePath = undefined } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-1-runtime-fixture-'))
  let removed = false
  const remove = () => {
    if (!removed) fs.rmSync(root, { recursive: true, force: true })
    removed = true
  }
  if (t?.after) t.after(remove)

  const runtime = fixture('runtime_profile')
  const identity = fixture('identity_bindings')
  runtime.profile_generation = 7

  const componentFiles = {}
  for (const release of runtime.component_releases) {
    let executable
    if (release.runtime_role_code === 'trusted_launcher') {
      executable = path.join(root, 'components/trusted_launcher.bin')
      fs.mkdirSync(path.dirname(executable), { recursive: true })
      fs.copyFileSync('/proc/self/exe', executable)
      fs.chmodSync(executable, 0o755)
    } else if (serviceExecutablePath) {
      executable = path.join(root, `components/${release.runtime_role_code}.bin`)
      fs.mkdirSync(path.dirname(executable), { recursive: true })
      fs.copyFileSync(serviceExecutablePath, executable)
      fs.chmodSync(executable, 0o755)
    } else {
      executable = writeArtifact(root, `components/${release.runtime_role_code}.bin`, `synthetic executable for ${release.runtime_role_code}\n`)
    }
    const dependencyLock = release.runtime_role_code === 'trusted_launcher'
      ? path.join(root, 'locks/trusted_launcher.lock')
      : writeArtifact(root, `locks/${release.runtime_role_code}.lock`, `synthetic dependency lock for ${release.runtime_role_code}\n`)
    release.executable_sha256 = sha256Bytes(fs.readFileSync(executable))
    componentFiles[release.runtime_role_code] = { executable, dependencyLock }
  }

  const controlPlaneBuildManifest = {
    format: 'jedi-atlas-d91-control-plane-build',
    format_version: '1.0.0',
    node_executable_sha256: runningExecutableSha256(),
    source_files: CONTROL_PLANE_SOURCE_FILES.map((relativePath) => ({
      relative_path: relativePath,
      sha256: sha256Bytes(fs.readFileSync(path.join(projectDirectory, relativePath))),
    })),
    manifest_digest_sha256: null,
  }
  controlPlaneBuildManifest.manifest_digest_sha256 = canonicalSha256(controlPlaneBuildManifest, {
    excludedTopLevelField: 'manifest_digest_sha256',
  })
  const controlPlaneBuildManifestPath = componentFiles.trusted_launcher.dependencyLock
  writeArtifact(root, 'locks/trusted_launcher.lock', canonicalize(controlPlaneBuildManifest))
  for (const release of runtime.component_releases) {
    release.dependency_lock_sha256 = sha256Bytes(fs.readFileSync(componentFiles[release.runtime_role_code].dependencyLock))
  }

  const runtimeDomainFile = writeArtifact(root, 'runtime/domain.marker', 'synthetic D9.1 runtime domain\n')
  runtime.runtime_domain_sha256 = sha256Bytes(fs.readFileSync(runtimeDomainFile))

  const operationalProfileFiles = {}
  for (const profile of runtime.operational_profiles) {
    const file = writeArtifact(root, `profiles/${profile.profile_kind_code}.json`, `{"synthetic_profile":"${profile.profile_kind_code}"}\n`)
    profile.generation = 3
    profile.profile_sha256 = sha256Bytes(fs.readFileSync(file))
    operationalProfileFiles[profile.profile_kind_code] = file
  }

  const scannerFiles = {}
  for (const scanner of runtime.scanner_policy.required_scanners) {
    const build = writeArtifact(root, `scanners/${scanner.scanner_code}.bin`, `synthetic scanner ${scanner.scanner_code}\n`)
    const rules = writeArtifact(root, `scanners/${scanner.scanner_code}.rules`, `synthetic rules ${scanner.scanner_code}\n`)
    scanner.build_sha256 = sha256Bytes(fs.readFileSync(build))
    scanner.rules_sha256 = sha256Bytes(fs.readFileSync(rules))
    scannerFiles[scanner.scanner_code] = { build, rules }
  }

  reseal(runtime)
  identity.binding_generation = 11
  identity.runtime_profile_record_digest_sha256 = runtime.record_digest_sha256
  identity.runtime_domain_sha256 = runtime.runtime_domain_sha256
  const releases = new Map(runtime.component_releases.map((release) => [release.runtime_role_code, release]))
  for (const binding of identity.bindings) {
    if (binding.principal_kind_code === 'service') binding.executable_sha256 = releases.get(binding.runtime_role_code).executable_sha256
  }
  reseal(identity)

  const selection = {
    profile_code: runtime.profile_code,
    profile_generation: runtime.profile_generation,
    runtime_profile_record_digest_sha256: runtime.record_digest_sha256,
    binding_set_code: identity.binding_set_code,
    binding_generation: identity.binding_generation,
    identity_bindings_record_digest_sha256: identity.record_digest_sha256,
  }

  return {
    root,
    remove,
    runtime,
    identity,
    selection,
    options: {
      asOf: '2030-01-01T00:10:00.000Z',
      migrationsDirectory,
      evidenceBundleSchemaPath,
      componentFiles,
      controlPlaneBuildManifestPath,
      runtimeDomainFile,
      operationalProfileFiles,
      scannerFiles,
    },
  }
}

export function verifyFixture(contractSet, generation) {
  return verifyRuntimeGeneration({
    contractSet,
    runtimeProfileBytes: Buffer.from(canonicalize(generation.runtime), 'utf8'),
    identityBindingsBytes: Buffer.from(canonicalize(generation.identity), 'utf8'),
    selection: generation.selection,
    ...generation.options,
  })
}
