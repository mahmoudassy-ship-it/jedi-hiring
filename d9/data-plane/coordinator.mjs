import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { applyMigrations } from '../../data/lib/migrations.mjs'
import { canonicalize, sha256Bytes } from '../control-plane/canonical.mjs'
import { openApprovedEvidenceManifest } from './manifest.mjs'
import { preflightEvidenceBundle } from './preflight.mjs'
import { buildImportPlan } from './plan.mjs'
import { applyImportPlanToCandidate } from './writer.mjs'
import {
  cloneDisposableCandidate,
  copySyntheticTestGeneration,
  assertSyntheticReadOnlySource,
  openSyntheticReadOnlyDatabaseDescriptor,
} from './candidate.mjs'
import { verifyStagedManifestArtifacts } from './bytes.mjs'
import { logicalStateDigest } from './projection.mjs'
import {
  assertAcceptedDatabaseVerification,
  verifyAcceptedCandidate,
  verifyAcceptedDatabaseConnection,
  verifyCandidateAndSyntheticCopy,
} from './verifier.mjs'
import { createD92PreflightRuntime, assertD92PilotManifestShape, assertSyntheticD92RuntimeContext } from './runtime.mjs'
import { verifyFrozenDatabaseBoundary } from './state-boundary.mjs'
import { failD92 } from './errors.mjs'

export async function verifyOrPlanAcceptedBundle({
  source,
  reviewedRootDescriptor,
  manifestRelativePath,
  reader,
  byteAdapter,
  runtimeContext,
}) {
  assertSyntheticReadOnlySource(source)
  assertSyntheticD92RuntimeContext(runtimeContext)
  const opened = openApprovedEvidenceManifest({ manifestRelativePath, reader, reviewedRootDescriptor })
  const manifest = opened.manifest
  assertD92PilotManifestShape(runtimeContext, manifest)
  const runtime = createD92PreflightRuntime(runtimeContext, { manifestByteLength: opened.manifestBytes.length })
  verifyFrozenDatabaseBoundary({ database: source.database, runtimeContext })
  const before = logicalStateDigest(source.database)
  const existing = source.database.prepare('SELECT bundle_sequence,bundle_digest_sha256 FROM atlas_evidence_bundle_receipts WHERE bundle_code=?').get(manifest.bundle_id)
  if (existing) {
    if (existing.bundle_digest_sha256 !== manifest.bundle_digest_sha256) failD92('ACCEPTED_REPLAY_DRIFT', 'accepted bundle code was replayed with different content')
    const verification = verifyAcceptedDatabaseConnection({
      database: source.database,
      reviewedRootDescriptor,
      reader,
      byteAdapter,
      runtimeContext,
      throughBundleSequence: existing.bundle_sequence,
    })
    if (logicalStateDigest(source.database) !== before) failD92('NO_OP_MUTATED_STATE', 'accepted-bundle verification changed source state')
    return Object.freeze({
      outcome: 'no_op_verified',
      bundleCode: manifest.bundle_id,
      bundleDigestSha256: manifest.bundle_digest_sha256,
      verification,
    })
  }

  const preflight = preflightEvidenceBundle({ database: source.database, manifest, runtime })
  verifyStagedManifestArtifacts({ manifest, byteAdapter, database: source.database })
  const plan = buildImportPlan(preflight)
  const candidate = await cloneDisposableCandidate({ source })
  try {
    const writeResult = applyImportPlanToCandidate({ candidate, plan })
    const verification = verifyCandidateAndSyntheticCopy({
      candidate,
      copyGeneration: copySyntheticTestGeneration,
      reviewedRootDescriptor,
      reader,
      byteAdapter,
      runtimeContext,
    })
    if (logicalStateDigest(source.database) !== before) failD92('SOURCE_DATABASE_MUTATED', 'candidate operation changed its read-only source')
    return Object.freeze({
      outcome: 'candidate_verified',
      bundleCode: manifest.bundle_id,
      bundleDigestSha256: manifest.bundle_digest_sha256,
      candidate,
      planDigestSha256: plan.plan_digest_sha256,
      verification,
      writeResult,
    })
  } catch (error) {
    candidate.dispose()
    throw error
  }
}

function openDatabaseDescriptor(databasePath) {
  return fs.openSync(databasePath, fs.constants.O_RDONLY | fs.constants.O_CLOEXEC | (fs.constants.O_NOFOLLOW ?? 0))
}

function copyVerifiedMigrations({ reconstructionRoot, runtimeContext }) {
  const sourceDirectory = path.join(runtimeContext.projectRoot, 'data/migrations')
  const expected = runtimeContext.verifiedGeneration.runtimeProfile.migration_hashes
  let entries
  try { entries = fs.readdirSync(sourceDirectory, { withFileTypes: true }) } catch (error) {
    failD92('RECONSTRUCTION_MIGRATIONS_INVALID', 'approved migration directory is unavailable', { cause: error })
  }
  const actualNames = entries.map((entry) => entry.name).toSorted()
  const expectedNames = expected.map((entry) => entry.migration_name).toSorted()
  if (entries.some((entry) => !entry.isFile()) || canonicalize(actualNames) !== canonicalize(expectedNames)) {
    failD92('RECONSTRUCTION_MIGRATIONS_INVALID', 'migration inventory differs from the verified runtime generation')
  }
  const targetDirectory = path.join(reconstructionRoot, 'verified-migrations')
  fs.mkdirSync(targetDirectory, { mode: 0o700 })
  for (const migration of expected) {
    const sourcePath = path.join(sourceDirectory, migration.migration_name)
    let descriptor
    try {
      descriptor = fs.openSync(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
      const before = fs.fstatSync(descriptor)
      if (!before.isFile() || before.nlink !== 1 || before.size <= 0 || before.size > 1024 * 1024) {
        failD92('RECONSTRUCTION_MIGRATIONS_INVALID', `migration is not a bounded single-link regular file: ${migration.migration_name}`)
      }
      const bytes = fs.readFileSync(descriptor)
      const after = fs.fstatSync(descriptor)
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mtimeMs !== after.mtimeMs || bytes.length !== before.size || sha256Bytes(bytes) !== migration.sha256) {
        failD92('RECONSTRUCTION_MIGRATIONS_INVALID', `migration bytes differ from the verified runtime generation: ${migration.migration_name}`)
      }
      const targetPath = path.join(targetDirectory, migration.migration_name)
      fs.writeFileSync(targetPath, bytes, { flag: 'wx', mode: 0o600 })
      if (sha256Bytes(fs.readFileSync(targetPath)) !== migration.sha256) {
        failD92('RECONSTRUCTION_MIGRATIONS_INVALID', `private migration copy failed verification: ${migration.migration_name}`)
      }
    } catch (error) {
      if (error?.code?.startsWith?.('RECONSTRUCTION_')) throw error
      failD92('RECONSTRUCTION_MIGRATIONS_INVALID', `migration could not be securely copied: ${migration.migration_name}`, { cause: error })
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor)
    }
  }
  return targetDirectory
}

export async function reconstructSyntheticAcceptedSet(options) {
  const expectedKeys = ['byteAdapter', 'expectedVerification', 'manifestRelativePaths', 'reader', 'reviewedRootDescriptor', 'runtimeContext']
  if (!options || typeof options !== 'object' || Array.isArray(options)
    || canonicalize(Object.keys(options).toSorted()) !== canonicalize(expectedKeys)) {
    failD92('RECONSTRUCTION_INPUT_INVALID', 'reconstruction input has unknown or missing fields')
  }
  const { expectedVerification, manifestRelativePaths, reader, reviewedRootDescriptor, byteAdapter, runtimeContext } = options
  if (!Array.isArray(manifestRelativePaths) || manifestRelativePaths.length === 0) failD92('RECONSTRUCTION_INPUT_INVALID', 'ordered accepted manifest paths are required')
  assertSyntheticD92RuntimeContext(runtimeContext)
  const trustedExpected = assertAcceptedDatabaseVerification(expectedVerification)
  const reconstructionRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-reconstruction-'))
  const basePath = path.join(reconstructionRoot, 'from-zero.sqlite')
  const candidates = []
  try {
    const verifiedMigrationsDirectory = copyVerifiedMigrations({ reconstructionRoot, runtimeContext })
    applyMigrations({ databasePath: basePath, migrationsDirectory: verifiedMigrationsDirectory })
    let currentPath = basePath
    for (const manifestRelativePath of manifestRelativePaths) {
      const descriptor = openDatabaseDescriptor(currentPath)
      const source = openSyntheticReadOnlyDatabaseDescriptor(descriptor)
      try {
        const result = await verifyOrPlanAcceptedBundle({
          source,
          reviewedRootDescriptor,
          manifestRelativePath,
          reader,
          byteAdapter,
          runtimeContext,
        })
        if (result.outcome !== 'candidate_verified') failD92('RECONSTRUCTION_REPLAY_INVALID', 'from-zero reconstruction encountered an unexpected no-op')
        candidates.push(result.candidate)
        currentPath = result.candidate.candidateDatabasePath
      } finally {
        source.close()
        fs.closeSync(descriptor)
      }
    }
    const finalCandidate = candidates.at(-1)
    const finalVerification = verifyAcceptedCandidate({
      candidate: finalCandidate,
      reviewedRootDescriptor,
      reader,
      byteAdapter,
      runtimeContext,
    })
    if (finalVerification.reconstructableStateSha256 !== trustedExpected.reconstructableStateSha256
      || finalVerification.logicalStateSha256 !== trustedExpected.logicalStateSha256
      || finalVerification.frozenBoundary.boundarySha256 !== trustedExpected.frozenBoundary.boundarySha256) {
      failD92('RECONSTRUCTION_MISMATCH', 'from-zero reconstructed data differs from the accepted synthetic state')
    }
    return Object.freeze({
      outcome: 'reconstruction_verified',
      acceptedBundleCount: finalVerification.acceptedBundleCount,
      reconstructableStateSha256: finalVerification.reconstructableStateSha256,
    })
  } finally {
    for (const candidate of candidates.reverse()) candidate.dispose()
    fs.rmSync(reconstructionRoot, { recursive: true, force: true })
  }
}
