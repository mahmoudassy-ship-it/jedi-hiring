import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { assertSyntheticD92RuntimeContext } from './runtime.mjs'
import { projectFrozenTableRows } from './state-boundary.mjs'
import { failD92 } from './errors.mjs'

function projectionDigest(value, label) {
  try { return canonicalSha256(value) } catch (error) {
    failD92('STATE_PROJECTION_INVALID', `${label} contains a noncanonical value`, { cause: error })
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function receiptProjection(database, receipt) {
  const row = database.prepare(`SELECT r.bundle_sequence,r.bundle_code,r.format_version_code,r.bundle_digest_sha256,
      r.manifest_path,r.bundle_created_at,s.principal_code AS submitted_by_principal_code,
      i.principal_code AS imported_by_principal_code,r.importer_software_code,r.importer_version,
      p.principal_code AS recorded_by_principal_code,r.recorded_at
    FROM atlas_evidence_bundle_receipts r
    JOIN atlas_principals s ON s.id=r.submitted_by_principal_id
    JOIN atlas_principals i ON i.id=r.imported_by_principal_id
    JOIN atlas_principals p ON p.id=r.recorded_by_principal_id
    WHERE r.id=?`).get(receipt.id)
  if (!row) failD92('STATE_PROJECTION_INVALID', 'receipt-head row is unavailable')
  return { ...row }
}

function principalRoster(database) {
  return database.prepare(`SELECT p.id,p.principal_code,p.principal_kind_code,
      c.principal_code AS created_by_principal_code,p.created_at
    FROM atlas_principals p JOIN atlas_principals c ON c.id=p.created_by_principal_id
    ORDER BY p.id ASC`).all().map((row) => ({ ...row }))
}

function exactManifestMap(receipts, manifests) {
  if (!Array.isArray(manifests) || manifests.length !== receipts.length) failD92('STATE_PROJECTION_INVALID', 'logical-state projection requires every retained manifest')
  const result = new Map()
  for (const manifest of manifests) {
    if (result.has(manifest.bundle_id)) failD92('STATE_PROJECTION_INVALID', 'logical-state manifests contain a duplicate bundle identity')
    result.set(manifest.bundle_id, manifest)
  }
  for (const receipt of receipts) {
    const manifest = result.get(receipt.bundle_code)
    if (!manifest || manifest.bundle_sequence !== receipt.bundle_sequence || manifest.bundle_digest_sha256 !== receipt.bundle_digest_sha256) {
      failD92('STATE_PROJECTION_INVALID', 'logical-state manifest differs from its accepted receipt')
    }
  }
  return result
}

function tableDigest(database, profiles, tableCode, throughBundleSequence) {
  const rows = projectFrozenTableRows(database, profiles, tableCode, { throughBundleSequence })
  return { table_code: tableCode, row_count: rows.length, rows_sha256: projectionDigest(rows, `${tableCode} row projection`) }
}

/**
 * Deterministically projects the exact frozen logical-state payload at every
 * accepted receipt boundary. This is not an issued logical-state-seal record:
 * protected verifier identity and production time belong to operational
 * activation, which D9.2 deliberately does not perform.
 */
export function projectAcceptedLogicalState({ database, manifests, runtimeContext, throughBundleSequence = null }) {
  const context = assertSyntheticD92RuntimeContext(runtimeContext)
  if (throughBundleSequence !== null && (!Number.isSafeInteger(throughBundleSequence) || throughBundleSequence <= 0)) {
    failD92('STATE_PROJECTION_INVALID', 'logical-state bundle-sequence bound is invalid')
  }
  const runtime = context.verifiedGeneration.runtimeProfile
  const profiles = context.contractSet.digestProfiles
  const receipts = database.prepare(`SELECT id,bundle_code,bundle_sequence,bundle_digest_sha256
    FROM atlas_evidence_bundle_receipts
    ${throughBundleSequence === null ? '' : 'WHERE bundle_sequence <= ?'}
    ORDER BY bundle_sequence ASC,bundle_code COLLATE BINARY ASC`).all(...(throughBundleSequence === null ? [] : [throughBundleSequence])).map((row) => ({ ...row }))
  const manifestMap = exactManifestMap(receipts, manifests)
  if (receipts.length === 0) {
    return Object.freeze({
      throughBundleSequence: 0,
      statePayload: deepFreeze(structuredClone(context.baselineStateSeal.state_payload)),
      logicalStateSha256: context.baselineStateSeal.logical_state_sha256,
      priorLogicalStateSha256: null,
    })
  }

  const projectedTables = profiles.sqlite_projections.table_rows.projections.map((row) => row.table_code)
  const legacyCodes = projectedTables.filter((code) => !code.startsWith('atlas_'))
  const atlasCodes = projectedTables.filter((code) => code.startsWith('atlas_'))
  const legacyRows = legacyCodes.map((code) => tableDigest(database, profiles, code, null))
  const roster = principalRoster(database)
  const rosterSha256 = projectionDigest(roster, 'principal roster')
  let priorLogicalStateSha256 = context.baselineStateSeal.logical_state_sha256
  let latest

  for (const receipt of receipts) {
    const prefix = receipts.filter((row) => row.bundle_sequence <= receipt.bundle_sequence)
    const dependencyGraph = prefix.map((row) => {
      const manifest = manifestMap.get(row.bundle_code)
      return {
        bundle_code: row.bundle_code,
        bundle_sequence: row.bundle_sequence,
        bundle_digest_sha256: row.bundle_digest_sha256,
        required_bundles: manifest.required_bundles.map(({ bundle_id, bundle_digest_sha256 }) => {
          const dependency = prefix.find((candidate) => candidate.bundle_code === bundle_id && candidate.bundle_digest_sha256 === bundle_digest_sha256)
          if (!dependency) failD92('STATE_PROJECTION_INVALID', `logical-state dependency is unresolved: ${bundle_id}`)
          return { bundle_id, bundle_sequence: dependency.bundle_sequence, bundle_digest_sha256 }
        }),
      }
    })
    const statePayload = {
      canonical_lineage_code: context.baselineStateSeal.state_payload.canonical_lineage_code,
      runtime_profile_record_digest_sha256: runtime.record_digest_sha256,
      contract_catalog_sha256: runtime.contract_catalog_sha256,
      receipt_head: {
        bundle_id: receipt.bundle_code,
        bundle_sequence: receipt.bundle_sequence,
        bundle_digest_sha256: receipt.bundle_digest_sha256,
        receipt_row_sha256: projectionDigest(receiptProjection(database, receipt), 'receipt head'),
      },
      migration_hashes: runtime.migration_hashes,
      complete_schema_sha256: runtime.database_contract.complete_schema_sha256,
      legacy_schema_sha256: runtime.database_contract.legacy_schema_sha256,
      legacy_rows: legacyRows,
      principal_roster: roster,
      principal_roster_sha256: rosterSha256,
      atlas_tables: atlasCodes.map((code) => tableDigest(database, profiles, code, receipt.bundle_sequence)),
      receipt_dependency_graph_sha256: projectionDigest(dependencyGraph, 'receipt dependency graph'),
      prohibited_surfaces_sha256: runtime.database_contract.prohibited_surfaces_sha256,
      prior_logical_state_sha256: priorLogicalStateSha256,
    }
    const logicalStateSha256 = projectionDigest(statePayload, 'logical-state payload')
    latest = Object.freeze({
      throughBundleSequence: receipt.bundle_sequence,
      statePayload: deepFreeze(statePayload),
      logicalStateSha256,
      priorLogicalStateSha256,
    })
    priorLogicalStateSha256 = logicalStateSha256
  }
  if (!latest || canonicalize(latest.statePayload.migration_hashes) !== canonicalize(runtime.migration_hashes)) {
    failD92('STATE_PROJECTION_INVALID', 'logical-state projection did not bind the frozen migration inventory')
  }
  return latest
}
