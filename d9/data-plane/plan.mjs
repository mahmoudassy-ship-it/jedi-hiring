import { canonicalSha256, canonicalize, parseStrictJson } from '../control-plane/canonical.mjs'
import { assertPreflightResult } from './preflight.mjs'
import { failD92 } from './errors.mjs'

export const IMPORT_PLAN_FORMAT = 'jedi-atlas-d9-2-import-plan'
export const IMPORT_PLAN_VERSION = '1.0.0'
export const IMPORT_PLAN_BYTES_MAX = 48 * 1024

export const PLAN_TABLES = Object.freeze([
  'atlas_evidence_bundle_receipts',
  'atlas_retrieval_locations',
  'atlas_artifacts',
  'atlas_retrieval_events',
  'atlas_retrieval_redirects',
  'atlas_artifact_custody_events',
  'atlas_processing_runs',
  'atlas_processing_outputs',
  'atlas_unverified_candidate_occurrences',
])

const ROW_FIELDS = Object.freeze({
  atlas_evidence_bundle_receipts: ['bundle_sequence', 'bundle_code', 'format_version_code', 'bundle_digest_sha256', 'manifest_path', 'bundle_created_at', 'submitted_by_principal_code', 'imported_by_principal_code', 'importer_software_code', 'importer_version', 'recorded_by_principal_code', 'recorded_at'],
  atlas_retrieval_locations: ['location_code', 'location_url', 'evidence_bundle_code', 'recorded_by_principal_code', 'recorded_at'],
  atlas_artifacts: ['artifact_code', 'byte_layer_code', 'hash_algorithm_code', 'sha256', 'byte_length', 'evidence_bundle_code', 'recorded_by_principal_code', 'recorded_at'],
  atlas_retrieval_events: ['retrieval_event_code', 'requested_location_code', 'last_attempted_location_code', 'resolved_location_code', 'conditional_basis_retrieval_event_code', 'conditional_validator_kind_code', 'conditional_validator_value', 'artifact_code', 'outcome_code', 'request_method_code', 'request_profile_code', 'request_accept', 'request_accept_language', 'request_accept_encoding', 'started_at', 'completed_at', 'captured_at', 'http_status_code', 'response_etag', 'response_last_modified', 'response_content_type', 'response_content_length', 'response_content_encoding', 'response_vary', 'detected_media_type', 'observed_sha256', 'observed_byte_length', 'collector_principal_code', 'collector_software_code', 'collector_version', 'evidence_bundle_code', 'recorded_by_principal_code', 'recorded_at'],
  atlas_retrieval_redirects: ['redirect_code', 'retrieval_event_code', 'hop_ordinal', 'from_location_code', 'to_location_code', 'http_status_code', 'evidence_bundle_code', 'recorded_by_principal_code', 'recorded_at'],
  atlas_artifact_custody_events: ['custody_event_code', 'artifact_code', 'copy_code', 'event_kind_code', 'predecessor_custody_event_code', 'custody_class_code', 'backend_code', 'backend_reference', 'eligibility_declared_by_principal_code', 'eligibility_declared_at', 'redistribution_eligible_declared', 'no_sensitive_data_declared', 'size_eligible_declared', 'permanent_history_acknowledged', 'reason', 'occurred_at', 'evidence_bundle_code', 'recorded_by_principal_code', 'recorded_at'],
  atlas_processing_runs: ['processing_run_code', 'run_ordinal', 'input_artifact_code', 'method_code', 'processor_principal_code', 'processor_software_code', 'processor_version', 'configuration_sha256', 'started_at', 'completed_at', 'outcome_code', 'failure_code', 'evidence_bundle_code', 'recorded_by_principal_code', 'recorded_at'],
  atlas_processing_outputs: ['processing_output_code', 'processing_run_code', 'artifact_code', 'output_ordinal', 'output_kind_code', 'detected_media_type', 'produced_at', 'evidence_bundle_code', 'recorded_by_principal_code', 'recorded_at'],
  atlas_unverified_candidate_occurrences: ['candidate_record_code', 'candidate_chain_code', 'record_kind_code', 'corrects_candidate_record_code', 'processing_run_code', 'processing_output_code', 'claim_type_code', 'observed_value', 'normalized_value', 'confidence_basis_points', 'locator_kind_code', 'locator_value', 'span_start', 'span_end', 'reason', 'evidence_bundle_code', 'recorded_by_principal_code', 'recorded_at'],
})

const PLAN_KEYS = ['format', 'format_version', 'source_bundle_code', 'source_bundle_digest_sha256', 'bootstrap_principals', 'rows', 'plan_digest_sha256']
const PRINCIPAL_FIELDS = ['id', 'principal_code', 'principal_kind_code', 'created_by_principal_code', 'created_at']
const HASH = /^[0-9a-f]{64}$/u
const plans = new WeakSet()

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) failD92('IMPORT_PLAN_INVALID', `${label} must be an object`)
  if (canonicalize(Object.keys(value).toSorted()) !== canonicalize([...keys].toSorted())) {
    failD92('IMPORT_PLAN_INVALID', `${label} has unknown or missing fields`)
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

export function projectManifestRows(manifest) {
  const receipt = {
    bundle_sequence: manifest.bundle_sequence,
    bundle_code: manifest.bundle_id,
    format_version_code: manifest.format_version,
    bundle_digest_sha256: manifest.bundle_digest_sha256,
    manifest_path: manifest.manifest_path,
    bundle_created_at: manifest.bundle_created_at,
    submitted_by_principal_code: manifest.submitter_principal_code,
    imported_by_principal_code: manifest.expected_importer_principal_code,
    importer_software_code: manifest.expected_importer_software_code,
    importer_version: manifest.expected_importer_version,
    recorded_by_principal_code: manifest.submitter_principal_code,
    recorded_at: manifest.bundle_created_at,
  }
  return {
    atlas_evidence_bundle_receipts: [receipt],
    atlas_retrieval_locations: manifest.retrieval_locations.map((row) => ({
      location_code: row.record_code,
      location_url: row.url,
      evidence_bundle_code: manifest.bundle_id,
      recorded_by_principal_code: row.recorded_by_principal_code,
      recorded_at: row.recorded_at,
    })),
    atlas_artifacts: manifest.artifacts.map((row) => ({
      artifact_code: row.record_code,
      byte_layer_code: row.byte_layer_code,
      hash_algorithm_code: row.hash_algorithm_code,
      sha256: row.sha256,
      byte_length: row.byte_length,
      evidence_bundle_code: manifest.bundle_id,
      recorded_by_principal_code: row.recorded_by_principal_code,
      recorded_at: row.recorded_at,
    })),
    atlas_retrieval_events: manifest.retrieval_events.map((row) => ({
      retrieval_event_code: row.record_code,
      requested_location_code: row.requested_location_code,
      last_attempted_location_code: row.last_attempted_location_code,
      resolved_location_code: row.resolved_location_code,
      conditional_basis_retrieval_event_code: row.conditional_basis_retrieval_event_code,
      conditional_validator_kind_code: row.conditional_validator_kind_code,
      conditional_validator_value: row.conditional_validator_value,
      artifact_code: row.artifact_code,
      outcome_code: row.outcome_code,
      request_method_code: row.request_method_code,
      request_profile_code: row.request_profile_code,
      request_accept: row.request_headers.accept,
      request_accept_language: row.request_headers.accept_language,
      request_accept_encoding: row.request_headers.accept_encoding,
      started_at: row.started_at,
      completed_at: row.completed_at,
      captured_at: row.captured_at,
      http_status_code: row.http_status_code,
      response_etag: row.response_metadata.etag ?? null,
      response_last_modified: row.response_metadata.last_modified ?? null,
      response_content_type: row.response_metadata.content_type ?? null,
      response_content_length: row.response_metadata.content_length ?? null,
      response_content_encoding: row.response_metadata.content_encoding ?? null,
      response_vary: row.response_metadata.vary ?? null,
      detected_media_type: row.detected_media_type,
      observed_sha256: row.observed_sha256,
      observed_byte_length: row.observed_byte_length,
      collector_principal_code: row.collector_principal_code,
      collector_software_code: row.collector_software_code,
      collector_version: row.collector_version,
      evidence_bundle_code: manifest.bundle_id,
      recorded_by_principal_code: row.recorded_by_principal_code,
      recorded_at: row.recorded_at,
    })),
    atlas_retrieval_redirects: manifest.retrieval_events.flatMap((event) => event.redirects.map((row) => ({
      redirect_code: row.record_code,
      retrieval_event_code: event.record_code,
      hop_ordinal: row.ordinal,
      from_location_code: row.from_location_code,
      to_location_code: row.to_location_code,
      http_status_code: row.http_status_code,
      evidence_bundle_code: manifest.bundle_id,
      recorded_by_principal_code: event.recorded_by_principal_code,
      recorded_at: event.recorded_at,
    }))),
    atlas_artifact_custody_events: manifest.custody_events.map((row) => ({
      custody_event_code: row.record_code,
      artifact_code: row.artifact_code,
      copy_code: row.copy_code,
      event_kind_code: row.event_kind_code,
      predecessor_custody_event_code: row.predecessor_custody_event_code,
      custody_class_code: row.custody_class_code,
      backend_code: row.backend_code,
      backend_reference: row.backend_reference,
      eligibility_declared_by_principal_code: row.repository_eligibility_declaration?.declared_by_principal_code ?? null,
      eligibility_declared_at: row.repository_eligibility_declaration?.declared_at ?? null,
      redistribution_eligible_declared: row.repository_eligibility_declaration?.redistribution_eligible_declared === true ? 1 : null,
      no_sensitive_data_declared: row.repository_eligibility_declaration?.no_sensitive_data_declared === true ? 1 : null,
      size_eligible_declared: row.repository_eligibility_declaration?.size_eligible_declared === true ? 1 : null,
      permanent_history_acknowledged: row.repository_eligibility_declaration?.permanent_history_acknowledged === true ? 1 : null,
      reason: row.reason,
      occurred_at: row.occurred_at,
      evidence_bundle_code: manifest.bundle_id,
      recorded_by_principal_code: row.recorded_by_principal_code,
      recorded_at: row.recorded_at,
    })),
    atlas_processing_runs: manifest.processing_runs.map((row) => ({
      processing_run_code: row.record_code,
      run_ordinal: row.ordinal,
      input_artifact_code: row.input_artifact_code,
      method_code: row.method_code,
      processor_principal_code: row.processor_principal_code,
      processor_software_code: row.processor_software_code,
      processor_version: row.processor_version,
      configuration_sha256: row.configuration_sha256,
      started_at: row.started_at,
      completed_at: row.completed_at,
      outcome_code: row.outcome_code,
      failure_code: row.failure_code,
      evidence_bundle_code: manifest.bundle_id,
      recorded_by_principal_code: row.recorded_by_principal_code,
      recorded_at: row.recorded_at,
    })),
    atlas_processing_outputs: manifest.processing_runs.flatMap((run) => run.outputs.map((row) => ({
      processing_output_code: row.record_code,
      processing_run_code: run.record_code,
      artifact_code: row.artifact_code,
      output_ordinal: row.ordinal,
      output_kind_code: row.output_kind_code,
      detected_media_type: row.detected_media_type,
      produced_at: row.produced_at,
      evidence_bundle_code: manifest.bundle_id,
      recorded_by_principal_code: run.recorded_by_principal_code,
      recorded_at: run.recorded_at,
    }))),
    atlas_unverified_candidate_occurrences: manifest.candidate_occurrences.map((row) => ({
      candidate_record_code: row.record_code,
      candidate_chain_code: row.chain_code,
      record_kind_code: row.record_kind_code,
      corrects_candidate_record_code: row.corrects_candidate_record_code,
      processing_run_code: row.processing_run_code,
      processing_output_code: row.processing_output_code,
      claim_type_code: row.claim_type_code,
      observed_value: row.observed_value,
      normalized_value: row.normalized_value,
      confidence_basis_points: row.confidence_basis_points,
      locator_kind_code: row.locator_kind_code,
      locator_value: row.locator_value,
      span_start: row.span_start,
      span_end: row.span_end,
      reason: row.reason,
      evidence_bundle_code: manifest.bundle_id,
      recorded_by_principal_code: row.recorded_by_principal_code,
      recorded_at: row.recorded_at,
    })),
  }
}

function assertPlanShape(plan) {
  exactKeys(plan, PLAN_KEYS, 'import plan')
  if (plan.format !== IMPORT_PLAN_FORMAT || plan.format_version !== IMPORT_PLAN_VERSION) failD92('IMPORT_PLAN_INVALID', 'unsupported import plan contract')
  if (!HASH.test(plan.source_bundle_digest_sha256) || !HASH.test(plan.plan_digest_sha256)) failD92('IMPORT_PLAN_INVALID', 'plan hashes must be lowercase SHA-256')
  if (!Array.isArray(plan.bootstrap_principals)) failD92('IMPORT_PLAN_INVALID', 'bootstrap_principals must be an array')
  for (const principal of plan.bootstrap_principals) {
    exactKeys(principal, PRINCIPAL_FIELDS, 'bootstrap principal')
    if (!Number.isSafeInteger(principal.id) || principal.id <= 0) failD92('IMPORT_PLAN_INVALID', 'bootstrap principal identity must be positive')
    for (const field of PRINCIPAL_FIELDS.slice(1)) {
      if (typeof principal[field] !== 'string') failD92('IMPORT_PLAN_INVALID', `bootstrap principal ${field} must be text`)
    }
  }
  exactKeys(plan.rows, PLAN_TABLES, 'plan rows')
  for (const table of PLAN_TABLES) {
    if (!Array.isArray(plan.rows[table])) failD92('IMPORT_PLAN_INVALID', `${table} plan rows must be an array`)
    for (const row of plan.rows[table]) {
      exactKeys(row, ROW_FIELDS[table], `${table} row`)
      for (const value of Object.values(row)) {
        if (value !== null && typeof value !== 'string' && !(typeof value === 'number' && Number.isSafeInteger(value))) {
          failD92('IMPORT_PLAN_INVALID', `${table} contains a noncanonical SQLite value`)
        }
      }
    }
  }
  if (plan.rows.atlas_evidence_bundle_receipts.length !== 1) failD92('IMPORT_PLAN_INVALID', 'plan must contain exactly one receipt')
  const receipt = plan.rows.atlas_evidence_bundle_receipts[0]
  if (receipt.bundle_code !== plan.source_bundle_code || receipt.bundle_digest_sha256 !== plan.source_bundle_digest_sha256) {
    failD92('IMPORT_PLAN_INVALID', 'plan envelope differs from its receipt')
  }
  if (plan.bootstrap_principals.length > 0) {
    if (plan.bootstrap_principals.length !== 4 || receipt.bundle_sequence !== 1) failD92('IMPORT_PLAN_INVALID', 'bootstrap plan requires the exact sequence-1 four-principal boundary')
    const [root, submitter, collector, importer] = plan.bootstrap_principals
    if (root.id !== 1 || root.principal_code !== 'system.bootstrap' || root.principal_kind_code !== 'service' || root.created_by_principal_code !== 'system.bootstrap') {
      failD92('IMPORT_PLAN_INVALID', 'bootstrap plan trust root differs from the fixed boundary')
    }
    if (submitter.id !== 2 || submitter.principal_kind_code !== 'human' || submitter.principal_code !== receipt.submitted_by_principal_code
      || collector.id !== 3 || collector.principal_kind_code !== 'service'
      || importer.id !== 4 || importer.principal_kind_code !== 'service' || importer.principal_code !== receipt.imported_by_principal_code
      || new Set(plan.bootstrap_principals.map((principal) => principal.principal_code)).size !== 4) {
      failD92('IMPORT_PLAN_INVALID', 'bootstrap plan roles or stable identities differ from the approved four-principal boundary')
    }
    if (PLAN_TABLES.slice(1).some((table) => plan.rows[table].length !== 0)) failD92('IMPORT_PLAN_INVALID', 'bootstrap plan must not contain evidence rows')
  } else if (receipt.bundle_sequence === 1) {
    failD92('IMPORT_PLAN_INVALID', 'sequence-1 plan requires the explicit bootstrap roster')
  }
  const expectedDigest = canonicalSha256(plan, { excludedTopLevelField: 'plan_digest_sha256' })
  if (expectedDigest !== plan.plan_digest_sha256) failD92('IMPORT_PLAN_INVALID', 'plan digest mismatch')
}

export function buildImportPlan(preflightResult) {
  const { manifest, mode } = assertPreflightResult(preflightResult)
  if (mode !== 'insert') failD92('IMPORT_PLAN_MODE_INVALID', 'only a complete insert preflight can produce a write plan')
  const bootstrapPrincipals = manifest.principal_bootstrap
    ? [manifest.principal_bootstrap.trust_root, ...manifest.principal_bootstrap.principals].map(({ runtime_role_code: ignored, ...principal }) => principal)
    : []
  const plan = {
    format: IMPORT_PLAN_FORMAT,
    format_version: IMPORT_PLAN_VERSION,
    source_bundle_code: manifest.bundle_id,
    source_bundle_digest_sha256: manifest.bundle_digest_sha256,
    bootstrap_principals: bootstrapPrincipals,
    rows: projectManifestRows(manifest),
    plan_digest_sha256: '0'.repeat(64),
  }
  plan.plan_digest_sha256 = canonicalSha256(plan, { excludedTopLevelField: 'plan_digest_sha256' })
  assertPlanShape(plan)
  const frozen = deepFreeze(plan)
  plans.add(frozen)
  return frozen
}

export function assertImportPlan(plan) {
  if (!plans.has(plan)) failD92('IMPORT_PLAN_UNTRUSTED', 'import plan was not produced from a branded complete preflight')
  assertPlanShape(plan)
  return plan
}

export function serializeImportPlan(plan) {
  assertImportPlan(plan)
  const bytes = Buffer.from(canonicalize(plan), 'utf8')
  if (bytes.length > IMPORT_PLAN_BYTES_MAX) failD92('IMPORT_PLAN_TOO_LARGE', 'import plan exceeds the frozen synthetic IPC allowance')
  return bytes
}

export function parseImportPlanBytes(bytes) {
  let plan
  try {
    plan = parseStrictJson(bytes, { maximumBytes: IMPORT_PLAN_BYTES_MAX, maximumDepth: 32, maximumMembers: 50000, contractNumbers: true })
    assertPlanShape(plan)
  } catch (error) {
    if (error?.code?.startsWith?.('IMPORT_PLAN_')) throw error
    failD92('IMPORT_PLAN_INVALID', 'writer rejected malformed import plan', { cause: error })
  }
  return deepFreeze(plan)
}

export { ROW_FIELDS }
