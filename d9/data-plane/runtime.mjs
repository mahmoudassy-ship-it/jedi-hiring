import path from 'node:path'
import {
  assertApprovedContractSet,
  assertVerifiedRuntimeGeneration,
  validateApprovedRecord,
} from '../control-plane/contracts.mjs'
import { canonicalSha256, canonicalize } from '../control-plane/canonical.mjs'
import { failD92 } from './errors.mjs'

const contexts = new WeakSet()
const preflightRuntimes = new WeakSet()
const EMPTY_COLLECTION_SHA256 = canonicalSha256([])
const APPROVED_SYNTHETIC_EMPTY_LEGACY_ROWS = Object.freeze([
  Object.freeze({ table_code: 'actors', row_count: 9, rows_sha256: '62126d3327e9499a83d4cc3627f72c2e2f8a580c8c5f3aebae75b839106986fe' }),
  Object.freeze({ table_code: 'country_overlays', row_count: 0, rows_sha256: EMPTY_COLLECTION_SHA256 }),
  Object.freeze({ table_code: 'hiring_stages', row_count: 8, rows_sha256: '96273aefc65daf6c55c79ac07d52d9dfa057b556dc9f769feb63a0cec85e0938' }),
  Object.freeze({ table_code: 'jurisdictions', row_count: 1, rows_sha256: '816b629f871227483e41eab2ad47bca9ac22e13a01c80c4ed791c5f4282b19d4' }),
  Object.freeze({ table_code: 'legal_instruments', row_count: 12, rows_sha256: '07fed7588bbc0042bad160a3df5787e4cf53d215345726aff829aa2351791422' }),
  Object.freeze({ table_code: 'legal_lenses', row_count: 9, rows_sha256: '312af367ed943ead3176ce35d2e58067f2490914c846f3f00fd2f896f2b7ba74' }),
  Object.freeze({ table_code: 'requirement_actors', row_count: 56, rows_sha256: '352f218598e97e880b58862df6f8da64fb4dc9bc8b69178ea4c3f44cc710f534' }),
  Object.freeze({ table_code: 'requirement_hiring_stages', row_count: 93, rows_sha256: '8fd8bb6c4ba82900930b343a5bfa293e8c9ddcafaa9adeb4cbd4946824dc125c' }),
  Object.freeze({ table_code: 'requirement_legal_lenses', row_count: 48, rows_sha256: '6333129de3911ba5a0a041ff3d50a415d1a474eaea76f30d8e1ec16b326d6e09' }),
  Object.freeze({ table_code: 'requirement_relations', row_count: 12, rows_sha256: '4a7602afedc1488308b775c66305f9521297edcd3b9f6a1e7b8358f777e78507' }),
  Object.freeze({ table_code: 'requirement_search', row_count: 20, rows_sha256: '15206acb10feba3ca8c6eef630cd13d007cff80052eae52d1476bcaa28d8fffc' }),
  Object.freeze({ table_code: 'requirements', row_count: 20, rows_sha256: 'a72d163b7d630a517cbc6d58fe1264daf813239e49713dbc82ddf192955b2ff8' }),
  Object.freeze({ table_code: 'source_checks', row_count: 12, rows_sha256: 'b9baa160f0fd0ca3286fb4df6de35604c8014f79c56cc509c2ab61af0512710d' }),
])

function roleBinding(generation, role) {
  const matches = generation.identityBindings.bindings.filter((binding) => binding.runtime_role_code === role)
  if (matches.length !== 1) failD92('RUNTIME_BINDING_MISMATCH', `verified synthetic generation must contain exactly one ${role} binding`)
  return matches[0]
}

function same(value, expected, label) {
  if (canonicalize(value) !== canonicalize(expected)) failD92('RUNTIME_BASELINE_MISMATCH', `${label} differs from the verified runtime generation`)
}

function exactTableInventory(actual, expected, label) {
  const codes = actual.map((row) => row.table_code)
  if (new Set(codes).size !== codes.length || canonicalize(codes) !== canonicalize(expected)) {
    failD92('RUNTIME_BASELINE_MISMATCH', `${label} is not the exact frozen table inventory`)
  }
}

function validateSyntheticBaseline({ baselineStateSeal, contractSet, generation }) {
  const seal = validateApprovedRecord({
    contractSet,
    schemaFile: 'logical-state-seal-v1.schema.json',
    record: structuredClone(baselineStateSeal),
  })
  const payload = seal.state_payload
  if (canonicalSha256(payload) !== seal.logical_state_sha256) failD92('RUNTIME_BASELINE_MISMATCH', 'baseline logical-state digest is invalid')
  const projections = contractSet.digestProfiles.sqlite_projections.table_rows.projections
  const legacyTables = projections.map((row) => row.table_code).filter((code) => !code.startsWith('atlas_'))
  const atlasTables = projections.map((row) => row.table_code).filter((code) => code.startsWith('atlas_'))
  exactTableInventory(payload.legacy_rows, legacyTables, 'baseline legacy rows')
  exactTableInventory(payload.atlas_tables, atlasTables, 'baseline Atlas rows')
  if (seal.record_code !== 'synthetic.state-empty'
    || seal.produced_by_binding_code !== 'binding.verifier'
    || seal.produced_at !== '2030-01-01T00:02:00.000Z'
    || payload.canonical_lineage_code !== 'synthetic.pilot-lineage'
    || payload.receipt_head !== null
    || payload.prior_logical_state_sha256 !== null
    || payload.principal_roster.length !== 0
    || payload.principal_roster_sha256 !== EMPTY_COLLECTION_SHA256
    || payload.receipt_dependency_graph_sha256 !== EMPTY_COLLECTION_SHA256
    || payload.atlas_tables.some((row) => row.row_count !== 0 || row.rows_sha256 !== EMPTY_COLLECTION_SHA256)) {
    failD92('RUNTIME_BASELINE_MISMATCH', 'D9.2 synthetic baseline must be the exact empty Atlas state')
  }
  if (canonicalize(payload.legacy_rows) !== canonicalize(APPROVED_SYNTHETIC_EMPTY_LEGACY_ROWS)) {
    failD92('RUNTIME_BASELINE_MISMATCH', 'baseline legacy rows differ from the approved D9.0.1 synthetic empty-state fixture')
  }
  const verifier = roleBinding(generation, 'independent_verifier')
  const bindings = generation.identityBindings
  if (seal.produced_by_binding_code !== verifier.binding_code
    || verifier.principal_kind_code !== 'service'
    || !(bindings.issued_at <= seal.produced_at && seal.produced_at < bindings.expires_at)
    || !(verifier.valid_from <= seal.produced_at && seal.produced_at < verifier.valid_until)) {
    failD92('RUNTIME_BASELINE_MISMATCH', 'baseline seal is not attributable to the selected independent verifier at its production time')
  }
  const runtime = generation.runtimeProfile
  if (payload.runtime_profile_record_digest_sha256 !== runtime.record_digest_sha256
    || payload.contract_catalog_sha256 !== runtime.contract_catalog_sha256
    || payload.complete_schema_sha256 !== runtime.database_contract.complete_schema_sha256
    || payload.legacy_schema_sha256 !== runtime.database_contract.legacy_schema_sha256
    || payload.prohibited_surfaces_sha256 !== runtime.database_contract.prohibited_surfaces_sha256) {
    failD92('RUNTIME_BASELINE_MISMATCH', 'baseline seal does not pin the verified runtime and database contract')
  }
  same(payload.migration_hashes, runtime.migration_hashes, 'baseline migration inventory')
  return seal
}

export function createSyntheticD92RuntimeContext({
  baselineStateSeal,
  contractSet,
  importerSoftwareCode = 'synthetic-importer',
  importerVersion = '1.0.0',
  projectRoot,
  verifiedGeneration,
}) {
  assertApprovedContractSet(contractSet)
  const generation = assertVerifiedRuntimeGeneration(verifiedGeneration)
  if (!path.isAbsolute(projectRoot)) failD92('RUNTIME_BINDING_MISMATCH', 'synthetic project root must be absolute')
  if (importerSoftwareCode !== 'synthetic-importer' || importerVersion !== '1.0.0') {
    failD92('RUNTIME_BINDING_MISMATCH', 'unactivated D9.2 accepts only the fixed synthetic importer identity')
  }
  if (generation.runtimeProfile.format_version !== '1.0.1'
    || generation.runtimeProfile.profile_code !== 'pilot_local_restricted_v1'
    || generation.runtimeProfile.processor_policy_code !== 'disabled'
    || canonicalize(generation.runtimeProfile.custody_policy) !== canonicalize({
      custody_class_code: 'restricted_store',
      backend_code: 'pilot_local_cas_v1',
      reference_profile_code: 'sha256_fanout_v1',
      publish_code: 'no_replace',
      backup_required: true,
    })) {
    failD92('RUNTIME_PROFILE_MISMATCH', 'D9.2 requires the approved D9.0.1 pilot runtime profile')
  }
  const submitter = roleBinding(generation, 'human_submitter')
  const importer = roleBinding(generation, 'bundle_importer')
  const collector = roleBinding(generation, 'collector')
  if (submitter.principal_kind_code !== 'human' || typeof submitter.atlas_principal_code !== 'string'
    || importer.principal_kind_code !== 'service' || typeof importer.atlas_principal_code !== 'string'
    || collector.principal_kind_code !== 'service' || typeof collector.atlas_principal_code !== 'string') {
    failD92('RUNTIME_BINDING_MISMATCH', 'verified generation lacks the required attributed human/service bindings')
  }
  const context = Object.freeze({
    syntheticTestDouble: true,
    contractSet,
    verifiedGeneration: generation,
    baselineStateSeal: validateSyntheticBaseline({ baselineStateSeal, contractSet, generation }),
    projectRoot,
    authenticatedSubmitterPrincipalCode: submitter.atlas_principal_code,
    authenticatedImporterPrincipalCode: importer.atlas_principal_code,
    authenticatedCollectorPrincipalCode: collector.atlas_principal_code,
    importerSoftwareCode,
    importerVersion,
  })
  contexts.add(context)
  return context
}

export function assertSyntheticD92RuntimeContext(context) {
  if (!contexts.has(context) || context.syntheticTestDouble !== true) failD92('RUNTIME_BINDING_MISSING', 'a verified synthetic D9.2 runtime context is required')
  assertVerifiedRuntimeGeneration(context.verifiedGeneration)
  assertApprovedContractSet(context.contractSet)
  return context
}

export function createD92PreflightRuntime(context, { componentTestOnly = false, manifestByteLength }) {
  assertSyntheticD92RuntimeContext(context)
  if (typeof componentTestOnly !== 'boolean' || !Number.isSafeInteger(manifestByteLength) || manifestByteLength <= 0) {
    failD92('RUNTIME_BINDING_MISMATCH', 'preflight runtime inputs are invalid')
  }
  const runtime = Object.freeze({
    authenticatedSubmitterPrincipalCode: context.authenticatedSubmitterPrincipalCode,
    authenticatedImporterPrincipalCode: context.authenticatedImporterPrincipalCode,
    authenticatedCollectorPrincipalCode: context.authenticatedCollectorPrincipalCode,
    importerSoftwareCode: context.importerSoftwareCode,
    importerVersion: context.importerVersion,
    manifestByteLength,
    policy: componentTestOnly ? null : context.verifiedGeneration.runtimeProfile,
    syntheticComponentTestOnly: componentTestOnly,
  })
  preflightRuntimes.add(runtime)
  return runtime
}

export function assertD92PreflightRuntime(runtime) {
  if (!preflightRuntimes.has(runtime)) failD92('RUNTIME_BINDING_MISSING', 'semantic preflight requires a branded D9.2 runtime view')
  return runtime
}

export function assertD92PilotManifestShape(context, manifest) {
  const runtime = assertSyntheticD92RuntimeContext(context)
  if (manifest.submitter_principal_code !== runtime.authenticatedSubmitterPrincipalCode
    || manifest.expected_importer_principal_code !== runtime.authenticatedImporterPrincipalCode
    || manifest.expected_importer_software_code !== runtime.importerSoftwareCode
    || manifest.expected_importer_version !== runtime.importerVersion) {
    failD92('RUNTIME_BINDING_MISMATCH', 'manifest attribution differs from the verified synthetic runtime context')
  }
  const bootstrap = manifest.bundle_sequence === 1
  if (bootstrap) {
    const trustRoot = manifest.principal_bootstrap?.trust_root
    const principals = manifest.principal_bootstrap?.principals ?? []
    const expectedPrincipals = [
      { id: 2, principal_code: runtime.authenticatedSubmitterPrincipalCode, principal_kind_code: 'human', created_by_principal_code: 'system.bootstrap', runtime_role_code: 'manifest_submitter' },
      { id: 3, principal_code: runtime.authenticatedCollectorPrincipalCode, principal_kind_code: 'service', created_by_principal_code: runtime.authenticatedSubmitterPrincipalCode, runtime_role_code: 'collector' },
      { id: 4, principal_code: runtime.authenticatedImporterPrincipalCode, principal_kind_code: 'service', created_by_principal_code: runtime.authenticatedSubmitterPrincipalCode, runtime_role_code: 'bundle_importer' },
    ]
    const actualPrincipals = principals.map(({ id, principal_code, principal_kind_code, created_by_principal_code, runtime_role_code }) => (
      { id, principal_code, principal_kind_code, created_by_principal_code, runtime_role_code }
    ))
    if (!manifest.principal_bootstrap || manifest.principal_bootstrap.principals.length !== 3
      || trustRoot.id !== 1
      || trustRoot.principal_code !== 'system.bootstrap'
      || trustRoot.principal_kind_code !== 'service'
      || trustRoot.created_by_principal_code !== 'system.bootstrap'
      || canonicalize(actualPrincipals) !== canonicalize(expectedPrincipals)
      || manifest.artifacts.length !== 0 || manifest.retrieval_locations.length !== 0
      || manifest.retrieval_events.length !== 0 || manifest.custody_events.length !== 0
      || manifest.processing_runs.length !== 0 || manifest.candidate_occurrences.length !== 0
      || manifest.required_bundles.length !== 0) {
      failD92('RUNTIME_PROFILE_MISMATCH', 'accepted bootstrap differs from the frozen empty-evidence pilot shape')
    }
  } else {
    const artifact = manifest.artifacts[0]
    const retrieval = manifest.retrieval_events[0]
    const custody = manifest.custody_events[0]
    const custodyPolicy = runtime.verifiedGeneration.runtimeProfile.custody_policy
    const usedLocationCodes = new Set([
      retrieval.requested_location_code,
      retrieval.last_attempted_location_code,
      retrieval.resolved_location_code,
      ...retrieval.redirects.flatMap((redirect) => [redirect.from_location_code, redirect.to_location_code]),
    ])
    usedLocationCodes.delete(null)
    const declaredLocationCodes = new Set(manifest.retrieval_locations.map((location) => location.record_code))
    if (manifest.bundle_sequence !== 2 || manifest.principal_bootstrap !== undefined || manifest.artifacts.length !== 1
      || manifest.retrieval_events.length !== 1 || manifest.custody_events.length !== 1
      || manifest.processing_runs.length !== 0 || manifest.candidate_occurrences.length !== 0
      || manifest.required_bundles.length !== 1
      || artifact.byte_layer_code !== 'retrieved_body'
      || retrieval.outcome_code !== 'retrieved_retained'
      || retrieval.http_status_code !== 200
      || retrieval.artifact_code !== artifact.record_code
      || retrieval.artifact_staged_path !== artifact.staged_path
      || retrieval.request_method_code !== 'GET'
      || retrieval.request_profile_code !== 'http_get_representation_v1'
      || retrieval.request_headers.accept_encoding !== 'identity'
      || retrieval.response_metadata.content_encoding !== undefined
      || retrieval.collector_principal_code !== runtime.authenticatedCollectorPrincipalCode
      || retrieval.redirects.length > 5
      || custody.event_kind_code !== 'placed'
      || custody.artifact_code !== artifact.record_code
      || custody.custody_class_code !== custodyPolicy.custody_class_code
      || custody.backend_code !== custodyPolicy.backend_code
      || custody.backend_reference !== artifact.staged_path
      || custody.repository_eligibility_declaration !== null
      || canonicalize([...declaredLocationCodes].toSorted()) !== canonicalize([...usedLocationCodes].toSorted())) {
      failD92('RUNTIME_PROFILE_MISMATCH', 'accepted document differs from the frozen one-document pilot shape')
    }
  }
  return manifest
}
