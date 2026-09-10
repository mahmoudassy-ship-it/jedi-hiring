import { openApprovedEvidenceManifest } from './manifest.mjs'
import { verifyCurrentCustodyBytes } from './bytes.mjs'
import { logicalStateDigest, reconstructableStateDigest, verifyDatabaseHealth, verifyPersistedBundleProjection } from './projection.mjs'
import { copySyntheticTestGeneration, withCandidateReadOnly, withSyntheticGenerationReadOnly } from './candidate.mjs'
import { assertD92PilotManifestShape, assertSyntheticD92RuntimeContext, createD92PreflightRuntime } from './runtime.mjs'
import { verifyFrozenDatabaseBoundary } from './state-boundary.mjs'
import { projectAcceptedLogicalState } from './state-projection.mjs'
import { failD92 } from './errors.mjs'
import { preflightEvidenceBundle } from './preflight.mjs'

const acceptedDatabaseVerifications = new WeakMap()

export function assertAcceptedDatabaseVerification(value) {
  const metadata = acceptedDatabaseVerifications.get(value)
  if (!metadata?.reconstructionEligible) {
    failD92('RECONSTRUCTION_INPUT_INVALID', 'reconstruction requires a branded full-head accepted-database verification')
  }
  return value
}

export function verifyAcceptedDatabaseConnection({ database, reviewedRootDescriptor, reader, byteAdapter, runtimeContext, throughBundleSequence = null }) {
  assertSyntheticD92RuntimeContext(runtimeContext)
  if (throughBundleSequence !== null && (!Number.isSafeInteger(throughBundleSequence) || throughBundleSequence <= 0)) {
    failD92('ACCEPTED_SEQUENCE_INVALID', 'accepted verification sequence bound is invalid')
  }
  verifyDatabaseHealth(database)
  const frozenBoundary = verifyFrozenDatabaseBoundary({ database, runtimeContext })
  const completeReceiptState = database.prepare('SELECT count(*) AS count,max(bundle_sequence) AS maximum FROM atlas_evidence_bundle_receipts').get()
  const receipts = database.prepare(`SELECT bundle_code,bundle_sequence,bundle_digest_sha256,manifest_path
    FROM atlas_evidence_bundle_receipts
    ${throughBundleSequence === null ? '' : 'WHERE bundle_sequence <= ?'}
    ORDER BY bundle_sequence`).all(...(throughBundleSequence === null ? [] : [throughBundleSequence]))
  if (throughBundleSequence !== null && (receipts.length !== throughBundleSequence || receipts.at(-1)?.bundle_sequence !== throughBundleSequence)) {
    failD92('ACCEPTED_SEQUENCE_GAP', 'accepted verification bound is not present as a contiguous receipt prefix')
  }
  if (receipts.length === 0 && database.prepare('SELECT count(*) AS count FROM atlas_principals').get().count !== 0) {
    failD92('PRINCIPAL_ROSTER_MISMATCH', 'principal rows exist without an accepted bootstrap receipt')
  }
  const seen = new Map()
  const manifests = []
  for (let index = 0; index < receipts.length; index += 1) {
    const receipt = receipts[index]
    if (receipt.bundle_sequence !== index + 1) failD92('ACCEPTED_SEQUENCE_GAP', 'accepted receipt sequence is not contiguous')
    const opened = openApprovedEvidenceManifest({ manifestRelativePath: receipt.manifest_path, reader, reviewedRootDescriptor })
    const manifest = opened.manifest
    assertD92PilotManifestShape(runtimeContext, manifest)
    if (manifest.bundle_id !== receipt.bundle_code || manifest.bundle_sequence !== receipt.bundle_sequence || manifest.bundle_digest_sha256 !== receipt.bundle_digest_sha256) {
      failD92('ACCEPTED_MANIFEST_DRIFT', `accepted manifest identity differs for sequence ${receipt.bundle_sequence}`)
    }
    for (const dependency of manifest.required_bundles) {
      const required = seen.get(dependency.bundle_id)
      if (!required || required.bundle_digest_sha256 !== dependency.bundle_digest_sha256) {
        failD92('ACCEPTED_DEPENDENCY_DRIFT', `accepted dependency differs for ${manifest.bundle_id}`)
      }
    }
    const preflight = preflightEvidenceBundle({
      database,
      manifest,
      runtime: createD92PreflightRuntime(runtimeContext, { manifestByteLength: opened.manifestBytes.length }),
      verifyAcceptedReplay: true,
    })
    if (preflight.mode !== 'no_op') failD92('ACCEPTED_PREFLIGHT_MISMATCH', `accepted manifest did not produce a complete no-op preflight: ${manifest.bundle_id}`)
    verifyPersistedBundleProjection({ database, manifest })
    manifests.push(manifest)
    seen.set(receipt.bundle_code, receipt)
  }
  const artifactCount = database.prepare(`SELECT count(*) AS count FROM atlas_artifacts
    ${throughBundleSequence === null ? '' : 'WHERE evidence_bundle_receipt_id IN (SELECT id FROM atlas_evidence_bundle_receipts WHERE bundle_sequence <= ?)'}
  `).get(...(throughBundleSequence === null ? [] : [throughBundleSequence])).count
  const custodyObjectsChecked = artifactCount === 0 ? 0 : verifyCurrentCustodyBytes({ database, byteAdapter, throughBundleSequence })
  const logicalStateProjection = projectAcceptedLogicalState({ database, manifests, runtimeContext, throughBundleSequence })
  const result = Object.freeze({
    acceptedBundleCount: receipts.length,
    custodyObjectsChecked,
    frozenBoundary,
    databaseSnapshotSha256: logicalStateDigest(database),
    logicalStateProjection,
    logicalStateSha256: logicalStateProjection.logicalStateSha256,
    reconstructableStateSha256: reconstructableStateDigest(database),
    verifiedBundles: Object.freeze(receipts.map((row) => Object.freeze({
      bundleCode: row.bundle_code,
      bundleDigestSha256: row.bundle_digest_sha256,
      bundleSequence: row.bundle_sequence,
    }))),
  })
  const reconstructionEligible = throughBundleSequence === null
    || (completeReceiptState.count === throughBundleSequence && completeReceiptState.maximum === throughBundleSequence)
  acceptedDatabaseVerifications.set(result, Object.freeze({ reconstructionEligible }))
  return result
}

export function verifyAcceptedCandidate({ candidate, reviewedRootDescriptor, reader, byteAdapter, runtimeContext }) {
  return withCandidateReadOnly(candidate, (database) => verifyAcceptedDatabaseConnection({
    database,
    reviewedRootDescriptor,
    reader,
    byteAdapter,
    runtimeContext,
  }))
}

export function verifyCandidateAndSyntheticCopy({ candidate, reviewedRootDescriptor, reader, byteAdapter, runtimeContext }) {
  const candidateResult = verifyAcceptedCandidate({ candidate, reviewedRootDescriptor, reader, byteAdapter, runtimeContext })
  const generation = copySyntheticTestGeneration(candidate)
  const copiedResult = withSyntheticGenerationReadOnly(generation, (database) => verifyAcceptedDatabaseConnection({
    database,
    reviewedRootDescriptor,
    reader,
    byteAdapter,
    runtimeContext,
  }))
  if (candidateResult.logicalStateSha256 !== copiedResult.logicalStateSha256
    || candidateResult.frozenBoundary.boundarySha256 !== copiedResult.frozenBoundary.boundarySha256) {
    failD92('SYNTHETIC_COPY_MISMATCH', 'post-copy synthetic generation differs from verified candidate')
  }
  return Object.freeze({ candidate: candidateResult, syntheticPostCopyGeneration: copiedResult })
}
