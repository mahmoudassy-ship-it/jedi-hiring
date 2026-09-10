import { isDeepStrictEqual } from 'node:util'
import { canonicalize, sha256Bytes } from '../control-plane/canonical.mjs'
import { projectManifestRows, PLAN_TABLES } from './plan.mjs'
import { failD92 } from './errors.mjs'

export const PERSISTED_PROJECTION_COLUMNS = Object.freeze({
  atlas_evidence_bundle_receipts: ['id', 'bundle_sequence', 'bundle_code', 'format_version_code', 'bundle_digest_sha256', 'manifest_path', 'bundle_created_at', 'submitted_by_principal_id', 'imported_by_principal_id', 'importer_software_code', 'importer_version', 'recorded_by_principal_id', 'recorded_at'],
  atlas_retrieval_locations: ['id', 'location_code', 'location_url', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_artifacts: ['id', 'artifact_code', 'byte_layer_code', 'hash_algorithm_code', 'sha256', 'byte_length', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_retrieval_events: ['id', 'retrieval_event_code', 'requested_location_id', 'last_attempted_location_id', 'resolved_location_id', 'conditional_basis_retrieval_event_id', 'conditional_validator_kind_code', 'conditional_validator_value', 'artifact_id', 'outcome_code', 'request_method_code', 'request_profile_code', 'request_accept', 'request_accept_language', 'request_accept_encoding', 'started_at', 'completed_at', 'captured_at', 'http_status_code', 'response_etag', 'response_last_modified', 'response_content_type', 'response_content_length', 'response_content_encoding', 'response_vary', 'detected_media_type', 'observed_sha256', 'observed_byte_length', 'collector_principal_id', 'collector_software_code', 'collector_version', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_retrieval_redirects: ['id', 'redirect_code', 'retrieval_event_id', 'hop_ordinal', 'from_location_id', 'to_location_id', 'http_status_code', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_artifact_custody_events: ['id', 'custody_event_code', 'artifact_id', 'copy_code', 'event_kind_code', 'predecessor_custody_event_id', 'custody_class_code', 'backend_code', 'backend_reference', 'eligibility_declared_by_principal_id', 'eligibility_declared_at', 'redistribution_eligible_declared', 'no_sensitive_data_declared', 'size_eligible_declared', 'permanent_history_acknowledged', 'reason', 'occurred_at', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_processing_runs: ['id', 'processing_run_code', 'run_ordinal', 'input_artifact_id', 'method_code', 'processor_principal_id', 'processor_software_code', 'processor_version', 'configuration_sha256', 'started_at', 'completed_at', 'outcome_code', 'failure_code', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_processing_outputs: ['id', 'processing_output_code', 'processing_run_id', 'artifact_id', 'output_ordinal', 'output_kind_code', 'detected_media_type', 'produced_at', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
  atlas_unverified_candidate_occurrences: ['id', 'candidate_record_code', 'candidate_chain_code', 'record_kind_code', 'corrects_candidate_occurrence_id', 'processing_run_id', 'processing_output_id', 'claim_type_code', 'observed_value', 'normalized_value', 'confidence_basis_points', 'locator_kind_code', 'locator_value', 'span_start', 'span_end', 'reason', 'evidence_bundle_receipt_id', 'recorded_by_principal_id', 'recorded_at'],
})

const CODE_COLUMNS = Object.freeze({
  atlas_evidence_bundle_receipts: 'bundle_code',
  atlas_retrieval_locations: 'location_code',
  atlas_artifacts: 'artifact_code',
  atlas_retrieval_events: 'retrieval_event_code',
  atlas_retrieval_redirects: 'redirect_code',
  atlas_artifact_custody_events: 'custody_event_code',
  atlas_processing_runs: 'processing_run_code',
  atlas_processing_outputs: 'processing_output_code',
  atlas_unverified_candidate_occurrences: 'candidate_record_code',
})

const FK_KIND = Object.freeze({
  evidence_bundle_receipt_id: 'receipt', submitted_by_principal_id: 'principal', imported_by_principal_id: 'principal', recorded_by_principal_id: 'principal', collector_principal_id: 'principal', processor_principal_id: 'principal', eligibility_declared_by_principal_id: 'principal',
  requested_location_id: 'location', last_attempted_location_id: 'location', resolved_location_id: 'location', from_location_id: 'location', to_location_id: 'location',
  artifact_id: 'artifact', input_artifact_id: 'artifact', conditional_basis_retrieval_event_id: 'retrieval', retrieval_event_id: 'retrieval', predecessor_custody_event_id: 'custody', processing_run_id: 'run', processing_output_id: 'output', corrects_candidate_occurrence_id: 'candidate',
})

const PLAN_TO_PERSISTED = Object.freeze({
  evidence_bundle_code: 'evidence_bundle_receipt_id', submitted_by_principal_code: 'submitted_by_principal_id', imported_by_principal_code: 'imported_by_principal_id', recorded_by_principal_code: 'recorded_by_principal_id', collector_principal_code: 'collector_principal_id', processor_principal_code: 'processor_principal_id', eligibility_declared_by_principal_code: 'eligibility_declared_by_principal_id',
  requested_location_code: 'requested_location_id', last_attempted_location_code: 'last_attempted_location_id', resolved_location_code: 'resolved_location_id', from_location_code: 'from_location_id', to_location_code: 'to_location_id',
  artifact_code: 'artifact_id', input_artifact_code: 'input_artifact_id', conditional_basis_retrieval_event_code: 'conditional_basis_retrieval_event_id', retrieval_event_code: 'retrieval_event_id', predecessor_custody_event_code: 'predecessor_custody_event_id', processing_run_code: 'processing_run_id', processing_output_code: 'processing_output_id', corrects_candidate_record_code: 'corrects_candidate_occurrence_id',
})

function codeMap(database, sql) {
  return new Map(database.prepare(sql).all().map((row) => [row.id, row.code]))
}

function maps(database) {
  return {
    principal: codeMap(database, 'SELECT id,principal_code AS code FROM atlas_principals'),
    receipt: codeMap(database, 'SELECT id,bundle_code AS code FROM atlas_evidence_bundle_receipts'),
    location: codeMap(database, 'SELECT id,location_code AS code FROM atlas_retrieval_locations'),
    artifact: codeMap(database, 'SELECT id,artifact_code AS code FROM atlas_artifacts'),
    retrieval: codeMap(database, 'SELECT id,retrieval_event_code AS code FROM atlas_retrieval_events'),
    custody: codeMap(database, 'SELECT id,custody_event_code AS code FROM atlas_artifact_custody_events'),
    run: codeMap(database, 'SELECT id,processing_run_code AS code FROM atlas_processing_runs'),
    output: codeMap(database, 'SELECT id,processing_output_code AS code FROM atlas_processing_outputs'),
    candidate: codeMap(database, 'SELECT id,candidate_record_code AS code FROM atlas_unverified_candidate_occurrences'),
  }
}

function expectedRowsFromPlanRows(planRows) {
  const result = {}
  for (const table of PLAN_TABLES) {
    const codeColumn = CODE_COLUMNS[table]
    result[table] = planRows[table].map((row) => {
      const converted = { id: row[codeColumn] }
      for (const [column, value] of Object.entries(row)) {
        converted[column === codeColumn ? column : (PLAN_TO_PERSISTED[column] ?? column)] = value
      }
      return converted
    })
  }
  return result
}

function verifyProjectedRows({ database, receipt, expected, bootstrapPrincipals, label }) {
  const codeMaps = maps(database)
  for (const table of PLAN_TABLES) {
    const actual = normalizedRows(database, table, receipt.id, codeMaps)
    const wanted = expected[table].toSorted((left, right) => left.id.localeCompare(right.id))
    if (!isDeepStrictEqual(actual, wanted)) failD92('PROJECTION_MISMATCH', `${table} differs from ${label}`)
  }
  if (bootstrapPrincipals) {
    const wanted = bootstrapPrincipals.toSorted((left, right) => left.id - right.id)
    const actual = database.prepare(`SELECT p.id,p.principal_code,p.principal_kind_code,c.principal_code AS created_by_principal_code,p.created_at
      FROM atlas_principals p JOIN atlas_principals c ON c.id=p.created_by_principal_id ORDER BY p.id`).all()
    if (!isDeepStrictEqual(actual.map((row) => ({ ...row })), wanted)) failD92('PROJECTION_PRINCIPAL_MISMATCH', 'bootstrap principal roster differs from the accepted input')
  }
}

function normalizedRows(database, table, receiptId, codeMaps) {
  const columns = database.prepare(`PRAGMA table_xinfo(${table})`).all().map((row) => row.name)
  if (!isDeepStrictEqual(columns, PERSISTED_PROJECTION_COLUMNS[table])) failD92('PROJECTION_SCHEMA_DRIFT', `${table} columns differ from the approved projection`)
  const predicate = table === 'atlas_evidence_bundle_receipts' ? 'id=?' : 'evidence_bundle_receipt_id=?'
  return database.prepare(`SELECT * FROM ${table} WHERE ${predicate}`).all(receiptId).map((row) => {
    if (!Number.isSafeInteger(row.id) || row.id <= 0) failD92('PROJECTION_INVALID', `${table} contains a nonpositive identity`)
    const result = { id: row[CODE_COLUMNS[table]] }
    for (const column of columns.slice(1)) {
      const kind = FK_KIND[column]
      if (!kind) result[column] = row[column]
      else if (row[column] === null) result[column] = null
      else {
        const stableCode = codeMaps[kind].get(row[column])
        if (stableCode === undefined) failD92('PROJECTION_REFERENCE_INVALID', `${table}.${column} does not resolve to a stable code`)
        result[column] = stableCode
      }
    }
    return result
  }).toSorted((left, right) => left.id.localeCompare(right.id))
}

export function verifyPersistedBundleProjection({ database, manifest }) {
  const receipt = database.prepare('SELECT id,bundle_digest_sha256 FROM atlas_evidence_bundle_receipts WHERE bundle_code=?').get(manifest.bundle_id)
  if (!receipt) failD92('PROJECTION_RECEIPT_MISSING', `receipt is absent for ${manifest.bundle_id}`)
  if (receipt.bundle_digest_sha256 !== manifest.bundle_digest_sha256) failD92('PROJECTION_RECEIPT_DRIFT', `receipt digest differs for ${manifest.bundle_id}`)
  const bootstrapPrincipals = manifest.principal_bootstrap
    ? [manifest.principal_bootstrap.trust_root, ...manifest.principal_bootstrap.principals]
      .map(({ runtime_role_code: ignored, ...row }) => row)
    : null
  verifyProjectedRows({
    database,
    receipt,
    expected: expectedRowsFromPlanRows(projectManifestRows(manifest)),
    bootstrapPrincipals,
    label: `canonical manifest ${manifest.bundle_id}`,
  })
  return Object.freeze({ bundleCode: manifest.bundle_id, bundleDigestSha256: manifest.bundle_digest_sha256, tableCount: PLAN_TABLES.length })
}

export function verifyPersistedPlanProjection({ database, plan }) {
  const receiptRow = plan.rows.atlas_evidence_bundle_receipts[0]
  const receipt = database.prepare('SELECT id,bundle_digest_sha256 FROM atlas_evidence_bundle_receipts WHERE bundle_code=?').get(plan.source_bundle_code)
  if (!receipt || receipt.bundle_digest_sha256 !== plan.source_bundle_digest_sha256
    || receiptRow.bundle_code !== plan.source_bundle_code || receiptRow.bundle_digest_sha256 !== plan.source_bundle_digest_sha256) {
    failD92('PROJECTION_RECEIPT_DRIFT', `receipt differs from fixed import plan ${plan.source_bundle_code}`)
  }
  verifyProjectedRows({
    database,
    receipt,
    expected: expectedRowsFromPlanRows(plan.rows),
    bootstrapPrincipals: plan.bootstrap_principals.length > 0 ? plan.bootstrap_principals : null,
    label: `fixed import plan ${plan.source_bundle_code}`,
  })
  return true
}

export function snapshotDatabase(database) {
  const tables = database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map((row) => row.name)
  const snapshot = {}
  for (const table of tables) {
    const columns = database.prepare(`PRAGMA table_xinfo(${table})`).all().map((row) => row.name)
    const order = columns.includes('id') ? 'id' : columns.map((column) => `"${column}"`).join(',')
    snapshot[table] = database.prepare(`SELECT * FROM "${table}" ORDER BY ${order}`).all().map((row) => Object.fromEntries(
      Object.entries(row).map(([key, value]) => [key,
        ArrayBuffer.isView(value) ? { blob_hex: Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('hex') }
          : typeof value === 'bigint' ? { integer_text: value.toString() }
            : value]),
    ))
  }
  return snapshot
}

export function logicalStateDigest(database) {
  return sha256Bytes(Buffer.from(canonicalize(snapshotDatabase(database)), 'utf8'))
}

export function reconstructableStateDigest(database) {
  const snapshot = snapshotDatabase(database)
  if (snapshot.schema_migrations) snapshot.schema_migrations = snapshot.schema_migrations.map(({ applied_at: ignored, ...row }) => row)
  if (snapshot.migration_checksums) snapshot.migration_checksums = snapshot.migration_checksums.map(({ recorded_at: ignored, ...row }) => row)
  return sha256Bytes(Buffer.from(canonicalize(snapshot), 'utf8'))
}

export function verifyDatabaseHealth(database) {
  const integrity = database.prepare('PRAGMA integrity_check').all()
  if (integrity.length !== 1 || integrity[0].integrity_check !== 'ok') failD92('DATABASE_INTEGRITY_FAILED', 'SQLite integrity_check failed')
  const foreignKeys = database.prepare('PRAGMA foreign_key_check').all()
  if (foreignKeys.length !== 0) failD92('DATABASE_FOREIGN_KEY_FAILED', 'SQLite foreign_key_check failed')
  return true
}
