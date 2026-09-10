import fs from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { parseStrictJson } from '../control-plane/canonical.mjs'
import { parseImportPlanBytes, PLAN_TABLES } from './plan.mjs'
import { verifyPersistedPlanProjection } from './projection.mjs'

const EXPECTED_FD = 3
const WRITER_REQUEST_BYTES_MAX = 65_536

function readBoundedRequest() {
  const chunks = []
  let total = 0
  while (true) {
    const chunk = Buffer.allocUnsafe(Math.min(16_384, WRITER_REQUEST_BYTES_MAX + 1 - total))
    const read = fs.readSync(0, chunk, 0, chunk.length, null)
    if (read === 0) break
    total += read
    if (total > WRITER_REQUEST_BYTES_MAX) fail('WRITER_REQUEST_TOO_LARGE', 'writer request exceeds the frozen IPC packet ceiling')
    chunks.push(chunk.subarray(0, read))
  }
  if (total === 0) fail('WRITER_REQUEST_INVALID', 'writer request is empty')
  return Buffer.concat(chunks, total)
}

function fail(code, message) {
  const error = new Error(`${code}: ${message}`)
  error.code = code
  throw error
}

function exactRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('WRITER_REQUEST_INVALID', 'writer request must be an object')
  const keys = Object.keys(value).toSorted()
  if (JSON.stringify(keys) !== JSON.stringify(['plan_base64', 'synthetic_fault_code'])) fail('WRITER_REQUEST_INVALID', 'writer request has unknown or missing fields')
  if (typeof value.plan_base64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value.plan_base64)) fail('WRITER_REQUEST_INVALID', 'plan_base64 is invalid')
  if (![null, 'after_all_rows', 'integrity_corruption', 'projection_extra_row'].includes(value.synthetic_fault_code)) fail('WRITER_REQUEST_INVALID', 'unknown synthetic fault')
  if (value.synthetic_fault_code !== null && process.env.D9_SYNTHETIC_TEST_ONLY !== '1') fail('WRITER_REQUEST_INVALID', 'synthetic fault injection is disabled')
}

function mapByCode(database, table, codeColumn) {
  return new Map(database.prepare(`SELECT id,${codeColumn} AS code FROM ${table}`).all().map((row) => [row.code, row.id]))
}

function required(map, code, label) {
  const id = code === null ? null : map.get(code)
  if (code !== null && id === undefined) fail('WRITER_REFERENCE_MISSING', `${label} does not resolve: ${code}`)
  return id
}

function applyPlan(database, plan, syntheticFaultCode) {
  database.exec('PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON; PRAGMA journal_mode=MEMORY')
  if (database.prepare('PRAGMA foreign_keys').get().foreign_keys !== 1) fail('WRITER_PRAGMA_FAILED', 'foreign keys unavailable')
  if (database.prepare('PRAGMA recursive_triggers').get().recursive_triggers !== 1) fail('WRITER_PRAGMA_FAILED', 'recursive triggers unavailable')
  for (const table of PLAN_TABLES) {
    if (!database.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) fail('WRITER_SCHEMA_MISMATCH', `required table is absent: ${table}`)
  }

  database.exec('BEGIN IMMEDIATE')
  try {
    if (plan.bootstrap_principals.length > 0) {
      if (database.prepare('SELECT count(*) AS count FROM atlas_principals').get().count !== 0) fail('WRITER_BOOTSTRAP_FORBIDDEN', 'principal bootstrap requires an empty principal table')
      const insertPrincipal = database.prepare('INSERT INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(?,?,?,?,?)')
      const ids = new Map()
      for (const principal of plan.bootstrap_principals) {
        const creatorId = principal.id === 1 ? 1 : required(ids, principal.created_by_principal_code, 'principal creator')
        insertPrincipal.run(principal.id, principal.principal_code, principal.principal_kind_code, creatorId, principal.created_at)
        ids.set(principal.principal_code, principal.id)
      }
    }

    const principals = mapByCode(database, 'atlas_principals', 'principal_code')
    const receiptRow = plan.rows.atlas_evidence_bundle_receipts[0]
    const receiptId = database.prepare(`INSERT INTO atlas_evidence_bundle_receipts(
      bundle_sequence,bundle_code,format_version_code,bundle_digest_sha256,manifest_path,bundle_created_at,
      submitted_by_principal_id,imported_by_principal_id,importer_software_code,importer_version,recorded_by_principal_id,recorded_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`).get(
      receiptRow.bundle_sequence, receiptRow.bundle_code, receiptRow.format_version_code, receiptRow.bundle_digest_sha256,
      receiptRow.manifest_path, receiptRow.bundle_created_at,
      required(principals, receiptRow.submitted_by_principal_code, 'submitter'),
      required(principals, receiptRow.imported_by_principal_code, 'importer'),
      receiptRow.importer_software_code, receiptRow.importer_version,
      required(principals, receiptRow.recorded_by_principal_code, 'receipt recorder'), receiptRow.recorded_at,
    ).id

    const locations = mapByCode(database, 'atlas_retrieval_locations', 'location_code')
    const insertLocation = database.prepare('INSERT INTO atlas_retrieval_locations(location_code,location_url,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?) RETURNING id')
    for (const row of plan.rows.atlas_retrieval_locations) {
      const id = insertLocation.get(row.location_code, row.location_url, receiptId, required(principals, row.recorded_by_principal_code, 'location recorder'), row.recorded_at).id
      locations.set(row.location_code, id)
    }

    const artifacts = mapByCode(database, 'atlas_artifacts', 'artifact_code')
    const insertArtifact = database.prepare('INSERT INTO atlas_artifacts(artifact_code,byte_layer_code,hash_algorithm_code,sha256,byte_length,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?,?,?,?) RETURNING id')
    for (const row of plan.rows.atlas_artifacts) {
      const id = insertArtifact.get(row.artifact_code, row.byte_layer_code, row.hash_algorithm_code, row.sha256, row.byte_length, receiptId, required(principals, row.recorded_by_principal_code, 'artifact recorder'), row.recorded_at).id
      artifacts.set(row.artifact_code, id)
    }

    const retrievalEvents = mapByCode(database, 'atlas_retrieval_events', 'retrieval_event_code')
    const insertRetrieval = database.prepare(`INSERT INTO atlas_retrieval_events(
      retrieval_event_code,requested_location_id,last_attempted_location_id,resolved_location_id,conditional_basis_retrieval_event_id,
      conditional_validator_kind_code,conditional_validator_value,artifact_id,outcome_code,request_method_code,request_profile_code,
      request_accept,request_accept_language,request_accept_encoding,started_at,completed_at,captured_at,http_status_code,
      response_etag,response_last_modified,response_content_type,response_content_length,response_content_encoding,response_vary,
      detected_media_type,observed_sha256,observed_byte_length,collector_principal_id,collector_software_code,collector_version,
      evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
    )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`)
    for (const row of plan.rows.atlas_retrieval_events) {
      const id = insertRetrieval.get(
        row.retrieval_event_code, required(locations, row.requested_location_code, 'requested location'),
        required(locations, row.last_attempted_location_code, 'last attempted location'), required(locations, row.resolved_location_code, 'resolved location'),
        required(retrievalEvents, row.conditional_basis_retrieval_event_code, 'conditional basis'),
        row.conditional_validator_kind_code, row.conditional_validator_value, required(artifacts, row.artifact_code, 'retrieval artifact'),
        row.outcome_code, row.request_method_code, row.request_profile_code, row.request_accept, row.request_accept_language,
        row.request_accept_encoding, row.started_at, row.completed_at, row.captured_at, row.http_status_code, row.response_etag,
        row.response_last_modified, row.response_content_type, row.response_content_length, row.response_content_encoding,
        row.response_vary, row.detected_media_type, row.observed_sha256, row.observed_byte_length,
        required(principals, row.collector_principal_code, 'collector'), row.collector_software_code, row.collector_version,
        receiptId, required(principals, row.recorded_by_principal_code, 'retrieval recorder'), row.recorded_at,
      ).id
      retrievalEvents.set(row.retrieval_event_code, id)
    }

    const insertRedirect = database.prepare('INSERT INTO atlas_retrieval_redirects(redirect_code,retrieval_event_id,hop_ordinal,from_location_id,to_location_id,http_status_code,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?,?,?,?,?)')
    for (const row of plan.rows.atlas_retrieval_redirects) {
      insertRedirect.run(row.redirect_code, required(retrievalEvents, row.retrieval_event_code, 'redirect event'), row.hop_ordinal,
        required(locations, row.from_location_code, 'redirect source'), required(locations, row.to_location_code, 'redirect target'),
        row.http_status_code, receiptId, required(principals, row.recorded_by_principal_code, 'redirect recorder'), row.recorded_at)
    }

    const custodyEvents = mapByCode(database, 'atlas_artifact_custody_events', 'custody_event_code')
    const insertCustody = database.prepare(`INSERT INTO atlas_artifact_custody_events(
      custody_event_code,artifact_id,copy_code,event_kind_code,predecessor_custody_event_id,custody_class_code,backend_code,
      backend_reference,eligibility_declared_by_principal_id,eligibility_declared_at,redistribution_eligible_declared,
      no_sensitive_data_declared,size_eligible_declared,permanent_history_acknowledged,reason,occurred_at,
      evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
    )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`)
    for (const row of plan.rows.atlas_artifact_custody_events) {
      const id = insertCustody.get(row.custody_event_code, required(artifacts, row.artifact_code, 'custody artifact'), row.copy_code,
        row.event_kind_code, required(custodyEvents, row.predecessor_custody_event_code, 'custody predecessor'), row.custody_class_code,
        row.backend_code, row.backend_reference, required(principals, row.eligibility_declared_by_principal_code, 'eligibility declarant'),
        row.eligibility_declared_at, row.redistribution_eligible_declared, row.no_sensitive_data_declared,
        row.size_eligible_declared, row.permanent_history_acknowledged, row.reason, row.occurred_at, receiptId,
        required(principals, row.recorded_by_principal_code, 'custody recorder'), row.recorded_at).id
      custodyEvents.set(row.custody_event_code, id)
    }

    const processingRuns = mapByCode(database, 'atlas_processing_runs', 'processing_run_code')
    const insertRun = database.prepare(`INSERT INTO atlas_processing_runs(
      processing_run_code,run_ordinal,input_artifact_id,method_code,processor_principal_id,processor_software_code,processor_version,
      configuration_sha256,started_at,completed_at,outcome_code,failure_code,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
    )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`)
    for (const row of plan.rows.atlas_processing_runs) {
      const id = insertRun.get(row.processing_run_code, row.run_ordinal, required(artifacts, row.input_artifact_code, 'processing input'),
        row.method_code, required(principals, row.processor_principal_code, 'processor'), row.processor_software_code,
        row.processor_version, row.configuration_sha256, row.started_at, row.completed_at, row.outcome_code, row.failure_code,
        receiptId, required(principals, row.recorded_by_principal_code, 'processing recorder'), row.recorded_at).id
      processingRuns.set(row.processing_run_code, id)
    }

    const processingOutputs = mapByCode(database, 'atlas_processing_outputs', 'processing_output_code')
    const insertOutput = database.prepare('INSERT INTO atlas_processing_outputs(processing_output_code,processing_run_id,artifact_id,output_ordinal,output_kind_code,detected_media_type,produced_at,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id')
    for (const row of plan.rows.atlas_processing_outputs) {
      const id = insertOutput.get(row.processing_output_code, required(processingRuns, row.processing_run_code, 'processing run'),
        required(artifacts, row.artifact_code, 'processing output artifact'), row.output_ordinal, row.output_kind_code,
        row.detected_media_type, row.produced_at, receiptId, required(principals, row.recorded_by_principal_code, 'output recorder'), row.recorded_at).id
      processingOutputs.set(row.processing_output_code, id)
    }

    const candidates = mapByCode(database, 'atlas_unverified_candidate_occurrences', 'candidate_record_code')
    const insertCandidate = database.prepare(`INSERT INTO atlas_unverified_candidate_occurrences(
      candidate_record_code,candidate_chain_code,record_kind_code,corrects_candidate_occurrence_id,processing_run_id,
      processing_output_id,claim_type_code,observed_value,normalized_value,confidence_basis_points,locator_kind_code,
      locator_value,span_start,span_end,reason,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
    )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`)
    for (const row of plan.rows.atlas_unverified_candidate_occurrences) {
      const id = insertCandidate.get(row.candidate_record_code, row.candidate_chain_code, row.record_kind_code,
        required(candidates, row.corrects_candidate_record_code, 'candidate predecessor'), required(processingRuns, row.processing_run_code, 'candidate run'),
        required(processingOutputs, row.processing_output_code, 'candidate output'), row.claim_type_code, row.observed_value,
        row.normalized_value, row.confidence_basis_points, row.locator_kind_code, row.locator_value, row.span_start, row.span_end,
        row.reason, receiptId, required(principals, row.recorded_by_principal_code, 'candidate recorder'), row.recorded_at).id
      candidates.set(row.candidate_record_code, id)
    }

    if (syntheticFaultCode === 'after_all_rows') fail('WRITER_SYNTHETIC_FAULT', 'injected after every plan table was populated')
    if (syntheticFaultCode === 'integrity_corruption') {
      database.exec('PRAGMA writable_schema=ON')
      database.prepare("UPDATE sqlite_schema SET rootpage=2147483647 WHERE type='table' AND name='atlas_artifacts'").run()
      database.exec('PRAGMA writable_schema=RESET')
    }
    if (syntheticFaultCode === 'projection_extra_row') {
      database.prepare(`INSERT INTO atlas_retrieval_locations(
        location_code,location_url,evidence_bundle_receipt_id,recorded_by_principal_id,recorded_at
      )VALUES(?,?,?,?,?)`).run(
        'synthetic.writer-projection-fault', 'https://example.invalid/writer-projection-fault', receiptId,
        required(principals, receiptRow.recorded_by_principal_code, 'projection-fault recorder'), receiptRow.recorded_at,
      )
    }
    let integrity
    try { integrity = database.prepare('PRAGMA integrity_check').all() } catch (error) {
      fail('WRITER_INTEGRITY_FAILED', `candidate integrity check could not complete: ${error.message}`)
    }
    if (integrity.length !== 1 || integrity[0].integrity_check !== 'ok') fail('WRITER_INTEGRITY_FAILED', 'candidate integrity check failed')
    const fk = database.prepare('PRAGMA foreign_key_check').all()
    if (fk.length !== 0) fail('WRITER_FOREIGN_KEY_FAILED', 'candidate contains foreign-key violations')
    verifyPersistedPlanProjection({ database, plan })
    database.exec('COMMIT')
    return { outcome: 'written', inserted_counts: Object.fromEntries(PLAN_TABLES.map((table) => [table, plan.rows[table].length])) }
  } catch (error) {
    database.exec('ROLLBACK')
    throw error
  }
}

let result
try {
  const request = parseStrictJson(readBoundedRequest(), {
    maximumBytes: WRITER_REQUEST_BYTES_MAX,
    maximumDepth: 4,
    maximumMembers: 8,
    contractNumbers: true,
  })
  exactRequest(request)
  const plan = parseImportPlanBytes(Buffer.from(request.plan_base64, 'base64'))
  const stat = fs.fstatSync(EXPECTED_FD)
  if (!stat.isFile()) fail('WRITER_DESCRIPTOR_INVALID', 'candidate descriptor is not a regular file')
  const database = new DatabaseSync(`/proc/self/fd/${EXPECTED_FD}`)
  try {
    result = applyPlan(database, plan, request.synthetic_fault_code)
  } finally {
    database.close()
  }
} catch (error) {
  result = { outcome: 'rejected', error_code: error.code ?? 'WRITER_FAILED', message: String(error.message ?? error) }
}

process.stdout.write(JSON.stringify(result))
process.exitCode = result.outcome === 'written' ? 0 : 1
