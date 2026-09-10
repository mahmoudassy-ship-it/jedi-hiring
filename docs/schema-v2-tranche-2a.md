# Tranche 2A source-evidence quarantine — approved physical specification

Status: approved physical schema and manifest contract. Migration `005_tranche_2a_source_quarantine.sql` implements the DDL byte-for-byte; the retained [approved DDL](schema/tranche-2a-source-quarantine.proposed.sql) remains an audit artifact guarded by automated equality checks. The [bundle JSON Schema](schema/tranche-2a-evidence-bundle-v1.schema.json) and [offline validator](schema/validate-tranche-2a.mjs) remain the approved contract and adversarial design harness. The canonical schema remains empty: all nine tables contain zero rows, and no collector, operational artifact adapter, evidence, legal data, API, export, search, or frontend integration was added. [Decision 9](tranche-2a-importer-custody.md) is the approved operational design for the fixed-function importer and controlled-pilot custody profile as proposed at commit `ee3ccd777849c7ffcad1efe5d5d9170c15171a65`. Its historical design-only [D9.0 contract freeze](d9-0-contract-freeze.md) was approved at commit `320b2d6969ede88796c44e652f6422f73e7fe4fe`; D9.0.1 was approved at commit `58a10d43ee5fcc3121a368301b4f5a925f26a9e3` and is the applicable contract revision for subsequent D9 implementation, superseding only the corrected runtime-profile and handle-scope contracts while preserving the original approval in Git history. D9.1 is approved at implementation commit `79046c27dfa6923383be33a1d0aaa5a7641f5d1f` only as a synthetic, unactivated launcher/bootstrap control plane. D9.2 now has a [synthetic, unactivated accepted-bundle verifier implementation candidate](d9-2-accepted-bundle-verifier.md) awaiting separate approval. It writes only disposable candidates and does not authorize or perform real bootstrap, evidence import, custody operations, canonical database writing, or legal verification.

## Boundary and minimality

Migration 005 creates nine empty tables: six core tables, two normalized child tables, and one technical receipt. The receipt is infrastructure for idempotency and provenance; it is not evidence and does not change the approved six-concept ontology.

| Logical boundary | Physical table | Why it has independent identity |
|---|---|---|
| Retrieval location | `atlas_retrieval_locations` | The exact requestable HTTPS location is reused across attempts and asserts no authority fact. |
| Retrieval event | `atlas_retrieval_events` | Every attempt is a distinct immutable fact, including retries and failures. |
| Artifact identity | `atlas_artifacts` | Exact bytes deduplicate by byte layer, SHA-256, and byte length, independently of location and custody. |
| Artifact custody | `atlas_artifact_custody_events` | Copy-specific availability, relocation, restriction, and tombstoning change over time without changing byte identity. |
| Processing run | `atlas_processing_runs` | Each content-decoding/parser/OCR/normalization/manual-transcription attempt has its own input, configuration, time, and outcome. |
| Candidate occurrence | `atlas_unverified_candidate_occurrences` | Repeated and conflicting extracted claims retain distinct provenance and correction history. |
| Ordered redirects | `atlas_retrieval_redirects` | A repeating ordered child cannot be safely flattened without losing hop identity and constraints. |
| Derived outputs | `atlas_processing_outputs` | A run may emit several exact artifacts with separate roles and order. |
| Technical receipt | `atlas_evidence_bundle_receipts` | One deterministic acceptance identity supports all-or-nothing import, replay no-op, and record-to-bundle provenance. |

The manifest is a transport/provenance envelope, not a table or seventh evidence concept. No authority instrument, provision, issuer, officiality, jurisdictional attribution, currency, consolidation, binding force, legal effect, verification, review, publication, or applicability object exists here.

## Conventions shared with Tranche 1A

Every table is `STRICT`. IDs are positive `INTEGER PRIMARY KEY` rowid aliases; SQLite reports those PK columns with `notnull=0`, but their primary-key semantics still prohibit a persisted null identity and the schema rejects nonpositive explicit IDs. All IDs, ordinals, lengths, status codes and booleans are SQLite `INTEGER`, while every identifier code, hash, path, URL, time, reason, value and media field is `TEXT`. All FKs use `ON UPDATE RESTRICT ON DELETE RESTRICT`. Times are canonical UTC millisecond timestamps (`YYYY-MM-DDTHH:MM:SS.sssZ`). Text is byte-bounded where appropriate, rejects embedded NUL, and uses closed CHECK values only for structural states. Every listed column has no SQL default; nullability is stated explicitly, and all unmarked non-PK columns are `NOT NULL`. Each row records a non-bootstrap principal and deterministic record time. UPDATE and DELETE triggers make history immutable. A BEFORE INSERT collision/validation trigger prevents `INSERT OR REPLACE` from deleting and recreating a row even when recursive triggers are disabled. Bundle sequence, not filesystem enumeration or local import time, fixes replay order and therefore stable generated integer IDs.

`recorded_at` is the deterministic attribution time supplied by the manifest. For custody, `occurred_at` is the reported time of the custody event, while the linked receipt's `bundle_sequence` is the authoritative knowledge-order boundary. Event time and knowledge order are never conflated: a later bundle may report an earlier occurrence without rewriting what an earlier accepted bundle knew. Bundle creation timestamps must be monotonic nondecreasing in bundle-sequence order.

Writers must still assert `foreign_keys=ON` and `recursive_triggers=ON`; schema guards do not depend solely on those connection settings. Attribution is not authentication, authorization, qualification, or verification.

## Exact table and column catalog

### `atlas_evidence_bundle_receipts` — technical helper

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `bundle_sequence` | positive, globally unique and contiguous deterministic replay ordinal |
| `bundle_code` | unique canonical code, 3–80 bytes |
| `format_version_code` | exactly `1.0.0` |
| `bundle_digest_sha256` | unique lowercase SHA-256 of the canonical bundle payload; not a hash of source-file whitespace |
| `manifest_path` | unique safe relative path, 1–240 bytes; bound to the actual reviewed-root-relative input file |
| `bundle_created_at` | canonical deterministic manifest time |
| `submitted_by_principal_id` | FK; must be non-bootstrap human |
| `imported_by_principal_id` | FK; must be non-bootstrap service |
| `importer_software_code`, `importer_version` | bounded reported implementation identity, checked against trusted runtime configuration |
| `recorded_by_principal_id` | FK; equals submitter |
| `recorded_at` | equals `bundle_created_at`; no local wall-clock value |

An identical accepted `bundle_code` plus digest is eligible for an importer no-op only after the importer rechecks the complete expected projection and required bytes. The same code with another digest fails closed. Accepted manifests replay strictly by contiguous sequence, and `bundle_created_at` cannot be earlier than the immediately preceding receipt; each cross-bundle dependency pins both bundle code and digest. The importer accepts a reviewed root and a relative manifest path, opens that path without following a symlink or escaping the root, and requires the normalized opened path to equal the manifest's `manifest_path`. The stored value is therefore bound provenance, not submitter-declared commentary. An optional operational audit service may record local acceptance time outside the canonical reconstruction; that time never derives canonical rows and the service does not exist in this tranche.

### `atlas_retrieval_locations` — core

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `location_code` | unique deterministic code `location.<sha256(exact URL UTF-8)>` |
| `location_url` | exact unique credential-free HTTPS string, 9–2048 bytes |
| `evidence_bundle_receipt_id` | FK to first importing receipt |
| `recorded_by_principal_id` | FK to manifest submitter; never principal 1 |
| `recorded_at` | canonical time no later than bundle creation; no later than `started_at` when used as the original requested location, and no later than `completed_at` when used as a last-attempted, resolved, or redirect endpoint location |

SQLite performs only defensive URL-shape checks. URL parsing, canonical code recomputation, signed-token rejection, SSRF/DNS policy, redirect policy, and semantic safety belong to validation/import or future collection operations. A location asserts only that this exact string was requested or observed.

### `atlas_artifacts` — core

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `artifact_code` | deterministic `artifact.<byte-layer>.sha256.<digest>.<length>` |
| `byte_layer_code` | `retrieved_body` or `derived_output` |
| `hash_algorithm_code` | exactly `sha256` |
| `sha256` | lowercase 64-hex digest of the exact stored bytes |
| `byte_length` | nonnegative integer |
| `evidence_bundle_receipt_id` | FK to first importing receipt |
| `recorded_by_principal_id` | FK to manifest submitter |
| `recorded_at` | canonical time no later than bundle creation |

Identity is exactly `(byte_layer_code, hash_algorithm_code, sha256, byte_length)`. It excludes URL, media type, filename, custody, access, officiality, and availability. Raw-byte hashing applies no Unicode, line-ending, markup, or filename normalization. A hash with no retrievable bytes does not create an artifact row. The importer requires every newly introduced identity to have an initial custody placement and at least one typed origin no later than identity recording in the same bundle: retained retrieval for `retrieved_body`, or processing output for `derived_output`. Later occurrences of the same bytes reuse the identity only after their own staged bytes are verified. Within one bundle, a repeated derived output is valid only for a higher-ordinal run after an earlier grounded run has already supplied the production edge; artifact declaration order alone cannot ground it.

### `atlas_retrieval_events` — core

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `retrieval_event_code` | unique bundle-prefixed code |
| `requested_location_id` | required FK for the original location supplied to the acquisition attempt |
| `last_attempted_location_id` | required FK for the terminal request target, including a redirected target at which a network failure occurred |
| `resolved_location_id` | nullable FK for the terminal location from which an HTTP response was actually received; equals `last_attempted_location_id` for HTTP outcomes and is null for network failures |
| `conditional_basis_retrieval_event_id` | nullable self-FK; paired with an exact conditional validator for a conditional request and required for `not_modified` |
| `conditional_validator_kind_code`, `conditional_validator_value` | nullable paired fields; `etag` uses the version-1 ASCII entity-tag profile (quoted visible `etagc`, excluding a quote, with optional uppercase `W/`), while `last_modified` uses an exact canonical 29-byte IMF-fixdate |
| `artifact_id` | nullable artifact FK; required only for `retrieved_retained` |
| `outcome_code` | `retrieved_retained`, `observed_not_retained`, `not_modified`, `network_failed`, or `http_failed` |
| `request_method_code`, `request_profile_code` | exactly `GET` and `http_get_representation_v1` |
| `request_accept`, `request_accept_language`, `request_accept_encoding` | nullable, allowlisted representation-negotiation request values; trimmed, byte-bounded, and free of C0 controls and DEL |
| `started_at`, `completed_at` | canonical interval; completion is not before start |
| `captured_at` | nullable canonical timestamp within the attempt |
| `http_status_code` | nullable integer 100–599 with outcome-specific rules |
| `response_etag` | nullable observed entity-tag, at most 512 bytes; version-1 ASCII entity-tag profile with one quoted opaque tag and optional uppercase `W/` |
| `response_last_modified` | nullable observed canonical 29-byte IMF-fixdate |
| `response_content_type` | nullable observed value, at most 255 bytes; trimmed and free of C0 controls and DEL |
| `response_content_length` | nullable nonnegative observed value |
| `response_content_encoding` | nullable canonical lowercase ordered `Content-Encoding` list, at most 255 bytes; HTTP tokens joined by `, ` |
| `response_vary` | nullable canonical lowercase sorted unique observed `Vary` field-name set, at most 512 bytes, or `*` |
| `detected_media_type` | required collector-reported detection for body outcomes; separate from response `Content-Type` and artifact identity |
| `observed_sha256`, `observed_byte_length` | optional pair only for `observed_not_retained`; creates no artifact |
| `collector_principal_id` | non-bootstrap service principal FK, distinct from the technical bundle importer |
| `collector_software_code`, `collector_version` | bounded collector identity/version |
| `evidence_bundle_receipt_id` | receipt FK for the bundle that adds this occurrence |
| `recorded_by_principal_id` | submitter FK; never principal 1 |
| `recorded_at` | canonical time at or after completion and no later than bundle creation |

Attempts never deduplicate. Manifest version 1 is GET-only. A `retrieved_retained` or `observed_not_retained` event is exactly HTTP 200; partial content (`206`) and every other 2xx status are rejected in version 1. `not_modified` is exactly HTTP 304, creates no artifact, and must point to an earlier retained HTTP-200 retrieval with the same original requested location, the current last-attempted location equal to the basis resolved location, the same request method/profile, and the same supported content-negotiation values. Its exact validator kind/value is the value sent on the terminal GET that produced the 304—not merely on an initial request before redirects—and must equal the corresponding ETag or Last-Modified value on the basis event. A conditional network failure may retain that conditional basis and validator while still having no resolved location, response status, or response metadata.

A basis with `Vary: *` or any field outside `Accept`, `Accept-Encoding`, and `Accept-Language` is recorded but cannot support a version-1 304. If a 304 carries `Vary`, it must equal its basis value. To canonicalize observed `Vary`, combine field lines, split the comma list, trim optional whitespace, lowercase and validate every HTTP field-name token, reject duplicates, sort lexically, and join with `, `; `*` is represented alone. Unsupported tokens are preserved in that canonical observation and never silently dropped. `Content-Encoding` preserves coding order, lowercases each valid HTTP token, and joins tokens with `, `. Request negotiation and response field values reject the entire C0 control range (`U+0000`–`U+001F`) and DEL (`U+007F`). ETags use the deliberately narrower ASCII version-1 profile described above; a future format must define the RFC `obs-text` byte/Unicode mapping before admitting it. Last-Modified and conditional last-modified validators use canonical IMF-fixdate; SQLite provides defensive shape and numeric-range checks, while the manifest validator/importer validates the actual calendar date and weekday. The request profile records exact `Accept`, `Accept-Language`, and `Accept-Encoding` values; the response separately records canonical observed `Vary`, `Content-Encoding`, content type/length, ETag, and Last-Modified.

The redirect chain begins at `requested_location_id` and ends at `last_attempted_location_id`; with no redirects those two locations are equal. `resolved_location_id` is populated only after an HTTP response and then equals the last attempted location. `network_failed` therefore preserves even a redirected or conditional terminal attempt without claiming a resolved response location. `http_failed` records only status 300–599 other than 304 and has a resolved location. Network and HTTP failures create no artifact and have no captured body. An HTTP 200 whose exact bytes were observed but not retained is `observed_not_retained` and cannot feed processing. Every other outcome requires both `observed_sha256` and `observed_byte_length` to be null; importer preflight mirrors that SQL rule before opening a transaction.

For each `retrieved_retained` occurrence, the manifest also carries a transport-only content-addressed `artifact_staged_path`. The importer hashes that attempt's staged response bytes before linking or deduplicating the artifact identity; the path is not stored on the event row. `retrieved_body` is exactly the HTTP/1.1 response-body octets after transfer framing is removed, or the HTTP/2/3 DATA payload octets concatenated in protocol order, before any `Content-Encoding` decoding. Gzip, Brotli, or other content decoding is a separate `content_decoding` processing run whose result is a `derived_output`; client-library automatic decoding cannot define the captured layer. Every other outcome requires a null staged path. Graph validation also requires an available custody interval that overlaps or follows the capture within the accepted knowledge boundary, so `retained` cannot be asserted from staged bytes alone.

### `atlas_retrieval_redirects` — helper

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `redirect_code` | unique bundle-prefixed code |
| `retrieval_event_id` | event FK |
| `hop_ordinal` | positive and unique within event |
| `from_location_id`, `to_location_id` | distinct location FKs |
| `http_status_code` | exactly `301`, `302`, `303`, `307`, or `308` |
| `evidence_bundle_receipt_id` | same receipt FK as parent event |
| `recorded_by_principal_id` | same submitter FK as parent event |
| `recorded_at` | exactly the parent event's canonical record time |

The manifest validator/importer enforces a contiguous chain from the original requested location through ordered hops to the last attempted location, whether the terminal result is an HTTP response or network failure. SQLite enforces identity, order uniqueness, allowed redirect statuses, endpoint chronology, provenance, and immutability but cannot validate a complete child set at parent insertion time.

### `atlas_artifact_custody_events` — core

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `custody_event_code` | unique bundle-prefixed code |
| `artifact_id` | artifact FK |
| `copy_code` | stable logical-copy code |
| `event_kind_code` | `placed`, `relocated`, `restricted`, `quarantined`, `restored`, or `tombstoned` |
| `predecessor_custody_event_id` | nullable self-FK; null only for `placed`; one successor maximum |
| `custody_class_code` | `repository` or `restricted_store` |
| `backend_code`, `backend_reference` | backend-neutral, secret-free safe relative reference; null for tombstone |
| `eligibility_declared_by_principal_id`, `eligibility_declared_at` | nullable human submitter declaration attribution; required for a live repository copy |
| four eligibility declarations | nullable booleans `redistribution_eligible_declared`, `no_sensitive_data_declared`, `size_eligible_declared`, `permanent_history_acknowledged`; all true for live repository copies and all null otherwise |
| `reason` | nonblank, no-NUL, at most 1000 bytes |
| `occurred_at` | reported custody-event occurrence time; may be historically earlier than bundle discovery but not later than `recorded_at` |
| `evidence_bundle_receipt_id` | receipt FK for the bundle that appends this custody state |
| `recorded_by_principal_id` | submitter FK; never principal 1 |
| `recorded_at` | canonical knowledge-recording time after predecessor recording and no later than bundle creation |

Each `(artifact_id, copy_code)` has one root and a linear current-leaf history. Successors retain the same artifact and copy, target the current knowledge leaf, have a later `recorded_at`, and cannot report an occurrence earlier than their predecessor. `restored` may follow `restricted`, `quarantined`, or a mistaken/reversed `tombstoned` leaf, preserving the entire chain. `relocated` may follow only an available `placed`, `relocated`, or `restored` leaf and must change `backend_code` or `custody_class_code`; it cannot silently clear a restriction, quarantine, or tombstone. Relocation while restricted is represented by another `restricted` event at the new restricted-store reference. Restricted and quarantined leaves require `restricted_store` custody. Every non-tombstone reference is the backend-neutral content address `objects/sha256/<first-two-hex>/<sha256>`. Repository eligibility fields are authenticated-submitter declarations, not reviews, legal rights determinations, or publication approval. The adapter must enforce access per custody copy; deduplicated byte storage must never grant one custody context access through another.

### `atlas_processing_runs` — core

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `processing_run_code` | unique bundle-prefixed code |
| `run_ordinal` | zero-based, contiguous and unique within the receipt; fixes same-bundle dependency order |
| `input_artifact_id` | exact artifact FK |
| `method_code` | `content_decoding`, `parser`, `ocr`, `normalization`, or `manual_transcription` |
| `processor_principal_id` | non-bootstrap principal FK, distinct from the technical importer; human for manual transcription and service for automated methods |
| `processor_software_code`, `processor_version` | bounded processor identity/version |
| `configuration_sha256` | exact lowercase SHA-256 of the bundle's canonical, bounded, secret-free flat configuration object |
| `started_at`, `completed_at` | canonical interval |
| `outcome_code` | `succeeded` or `failed` |
| `failure_code` | null on success and required on failure |
| `evidence_bundle_receipt_id` | receipt FK for this run occurrence |
| `recorded_by_principal_id` | submitter FK; never principal 1 |
| `recorded_at` | canonical time at or after run completion and no later than bundle creation |

The manifest retains the configuration object; SQLite retains its recomputed identity. Processor software/version remains a reported identity until an operational build-attestation system exists. The input requires declared retained/available custody at run start using only custody knowledge accepted at this run's receipt sequence; the future adapter must also confirm actual access and integrity. Every processing chain must be grounded in a retained-retrieval artifact, or in a derived artifact produced by an earlier already-grounded run. “Earlier” means a lower receipt sequence, or a lower `run_ordinal` in the same receipt; timestamps do not override this order. A same-bundle run can therefore consume a derived artifact only after a lower-ordinal, already-grounded run has produced that identity. A run cannot consume an artifact it produces, and the complete artifact/run graph must be acyclic, including when timestamps are equal. A failure has no outputs. Retrying is a new run. Successful retrieval remains unchanged when processing fails. Manual transcription uses this same path and may not directly alter candidates or authority records.

Non-decoding processors must not perform a hidden `Content-Encoding` transformation: when interpretation requires decoding a coded HTTP representation, an explicit `content_decoding` run must first produce the derived input consumed by the parser, OCR, normalization, or transcription run. The manifest and output-kind matrix make that lineage auditable, but SQLite cannot prove what an executable did internally. Processor build attestation, sandboxing, and conformance tests therefore remain operational prerequisites; the approved schema does not add an ambiguous artifact-to-retrieval-occurrence inference merely because identical bytes may have been observed in more than one response context.

The version-1 method/output contract is closed:

| Processing method | Permitted output kinds | Additional rule |
|---|---|---|
| `content_decoding` | `decoded_body` | Input must be `retrieved_body`. Success produces exactly one output; failure produces none. Configuration is exactly `{ "content_coding": "<canonical coding list>" }`, and that value must equal an observed `Content-Encoding` on a retained retrieval occurrence for the input artifact. |
| `parser` | `extracted_text`, `structured_data`, `diagnostic` | A successful run may emit any ordered combination permitted by the manifest bounds. |
| `ocr` | `ocr_text`, `diagnostic` | A successful run may emit any ordered combination permitted by the manifest bounds. |
| `normalization` | `normalized_text`, `diagnostic` | A successful run may emit any ordered combination permitted by the manifest bounds. |
| `manual_transcription` | `manual_transcript`, `diagnostic` | Processor must be a human principal; direct candidate or authority editing is forbidden. |

SQLite defensively enforces the input byte layer, method/output pairs, success/failure shape, and lineage edges. The manifest validator/importer additionally proves the exact configuration shape, the observed-coding match, complete output counts, contiguous ordinals, and whole-graph grounding before `BEGIN`.

### `atlas_processing_outputs` — helper

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `processing_output_code` | unique bundle-prefixed code |
| `processing_run_id` | successful run FK |
| `artifact_id` | `derived_output` artifact FK |
| `output_ordinal` | nonnegative and unique within run |
| `output_kind_code` | `decoded_body`, `normalized_text`, `extracted_text`, `ocr_text`, `structured_data`, `manual_transcript`, or `diagnostic` |
| `detected_media_type` | observed bounded media type, not artifact identity |
| `produced_at` | within the parent run interval; the artifact identity must already exist by row recording, while each newly introduced artifact has at least one origin no later than its identity record |
| `evidence_bundle_receipt_id` | same receipt FK as parent run |
| `recorded_by_principal_id` | same submitter FK as parent run |
| `recorded_at` | exactly the parent run's canonical record time |

The run input plus each output row is the exact derivation edge. Multiple output artifacts are supported. A newly declared derived artifact gets its first origin from the producing run. After an already-grounded producer with a lower receipt sequence—or, within the same receipt, a lower `run_ordinal`—a later run may link the same byte-identical artifact only after independently rehashing that occurrence's staged output. It cannot be reused by an earlier or mutually dependent run. Every manifest output carries a transport-only content-addressed `staged_path`; the importer hashes those emitted bytes before linking or deduplicating the artifact identity, but the path is not stored on the output row or made part of artifact identity. Diagnostic outputs cannot support candidate occurrences.

### `atlas_unverified_candidate_occurrences` — core

| Column | Type and rule |
|---|---|
| `id` | positive `INTEGER PK` |
| `candidate_record_code` | unique bundle-prefixed immutable-record code |
| `candidate_chain_code` | stable correction-chain code |
| `record_kind_code` | `assertion`, `correction`, or `withdrawal` |
| `corrects_candidate_occurrence_id` | nullable self-FK; one successor maximum |
| `processing_run_id`, `processing_output_id` | composite-enforced exact successful-run/output lineage |
| `claim_type_code` | structural unverified metadata-claim code, 3–80 bytes |
| `observed_value`, `normalized_value` | bounded occurrence values; withdrawal values are null |
| `confidence_basis_points` | nullable 0–10000 processing score, never legal confidence |
| `locator_kind_code` | `byte_span` or `text_span` only in manifest version 1 |
| `locator_value` | required precise locator description |
| `span_start`, `span_end` | required nonnegative half-open span; interpretation is fixed by `locator_kind_code` (`byte_span` or `text_span`) |
| `reason` | nonblank correction/import explanation |
| `evidence_bundle_receipt_id` | receipt FK for the bundle that appends this occurrence; may differ from the original run/output receipt |
| `recorded_by_principal_id` | current bundle's submitter FK; never principal 1 |
| `recorded_at` | canonical time after source output and predecessor and no later than current bundle creation |

Each chain has one assertion root. A correction or withdrawal targets the current leaf of the same chain and claim type at a later record time and in the same or a later evidence-bundle sequence, including across a pinned later bundle. Reinstatement is a correction of the withdrawal. Correcting evidence does not modify source bytes. Separate chain codes preserve repeated or conflicting candidates rather than merging them. Byte spans are zero-based half-open offsets into exact output bytes and are adapter-bounds-checked. Text spans count Unicode scalar values after strict UTF-8 decoding. Page regions, JSON Pointer, and XPath are excluded from version 1 because no deterministic, versioned page-coordinate, JSON-parser, namespace, or XPath evaluation profile has been approved.

## Cardinality, keys, deletion and future consumers

| Object | Cardinality and enforced keys | Future reference direction |
|---|---|---|
| receipt | one receipt introduces zero or many rows of every evidence type; sequence, code, digest and path are each unique | operational audit may refer to receipt; evidence rows already carry concrete receipt FKs |
| location | one location may be an original request, last attempted target, resolved response location, or redirect endpoint for many events; exact URL and deterministic code are each unique | exact-source monitor policies may refer to locations, never infer authority from them |
| artifact | one identity may support many retrievals, custody copies, run inputs and outputs; byte-layer/hash/length and artifact code are unique | 2B representation drafts may cite precise artifacts through future type-safe evidence links |
| retrieval event | one original requested location, one terminal last-attempted location, at most one resolved response location, at most one retained artifact, and zero or many ordered redirects; a 304 has exactly one earlier basis | freshness request outcomes may refer to exact retrieval events |
| redirect | exactly one parent event and one from/to location; `(event, ordinal)` is unique | no independent authority consumer |
| custody event | exactly one artifact/copy; one root per copy and at most one successor per event | importer/adapters derive availability; later holds may refer to concrete custody events |
| processing run | exactly one input artifact; zero or many ordered outputs; failed runs have none | candidate and later change-detection lineage refer to exact runs |
| processing output | exactly one run and one derived artifact; `(run, ordinal)` and `(id, run)` are unique | candidates use the composite FK to prevent wrong-run output references |
| candidate occurrence | exactly one run/output; one root per chain and at most one successor per occurrence | 2B drafts may later cite supporting and conflicting occurrences without elevating them |

Every row is immutable after insertion, all deletion/update actions are `RESTRICT`, and every table has explicit UPDATE/DELETE rejection plus an INSERT collision guard. There is no cascade. The partial root/successor unique indexes and validation triggers enforce linear custody/candidate histories; the fixed importer additionally validates the complete graph before opening its transaction.

## Constraints and generated-object inventory

The exact DDL contains **9 tables, 27 named indexes, and 27 named triggers**. It contains no transaction-control statement or seed.

Tables: `atlas_evidence_bundle_receipts`, `atlas_retrieval_locations`, `atlas_artifacts`, `atlas_retrieval_events`, `atlas_retrieval_redirects`, `atlas_artifact_custody_events`, `atlas_processing_runs`, `atlas_processing_outputs`, and `atlas_unverified_candidate_occurrences`.

Named indexes:

- `atlas_evidence_bundle_receipts_code_uidx`, `atlas_evidence_bundle_receipts_sequence_uidx`, `atlas_evidence_bundle_receipts_digest_uidx`, `atlas_evidence_bundle_receipts_path_uidx`
- `atlas_retrieval_locations_code_uidx`, `atlas_retrieval_locations_url_uidx`
- `atlas_artifacts_code_uidx`, `atlas_artifacts_identity_uidx`
- `atlas_retrieval_events_code_uidx`, `atlas_retrieval_events_location_time_idx`
- `atlas_retrieval_redirects_code_uidx`, `atlas_retrieval_redirects_event_ordinal_uidx`
- `atlas_artifact_custody_events_code_uidx`, `atlas_artifact_custody_events_one_root_uidx`, `atlas_artifact_custody_events_predecessor_uidx`, `atlas_artifact_custody_events_leaf_idx`
- `atlas_processing_runs_code_uidx`, `atlas_processing_runs_receipt_ordinal_uidx`, `atlas_processing_runs_input_time_idx`
- `atlas_processing_outputs_code_uidx`, `atlas_processing_outputs_run_ordinal_uidx`, `atlas_processing_outputs_id_run_uidx`
- `atlas_candidate_occurrences_record_code_uidx`, `atlas_candidate_occurrences_one_root_uidx`, `atlas_candidate_occurrences_predecessor_uidx`, `atlas_candidate_occurrences_leaf_idx`, `atlas_candidate_occurrences_run_output_idx`

Named triggers, three per table:

- `atlas_evidence_bundle_receipts_validate_insert`, `atlas_evidence_bundle_receipts_immutable_update`, `atlas_evidence_bundle_receipts_immutable_delete`
- `atlas_retrieval_locations_validate_insert`, `atlas_retrieval_locations_immutable_update`, `atlas_retrieval_locations_immutable_delete`
- `atlas_artifacts_validate_insert`, `atlas_artifacts_immutable_update`, `atlas_artifacts_immutable_delete`
- `atlas_retrieval_events_validate_insert`, `atlas_retrieval_events_immutable_update`, `atlas_retrieval_events_immutable_delete`
- `atlas_retrieval_redirects_validate_insert`, `atlas_retrieval_redirects_immutable_update`, `atlas_retrieval_redirects_immutable_delete`
- `atlas_artifact_custody_events_validate_insert`, `atlas_artifact_custody_events_immutable_update`, `atlas_artifact_custody_events_immutable_delete`
- `atlas_processing_runs_validate_insert`, `atlas_processing_runs_immutable_update`, `atlas_processing_runs_immutable_delete`
- `atlas_processing_outputs_validate_insert`, `atlas_processing_outputs_immutable_update`, `atlas_processing_outputs_immutable_delete`
- `atlas_candidate_occurrences_validate_insert`, `atlas_candidate_occurrences_immutable_update`, `atlas_candidate_occurrences_immutable_delete`

Insert triggers combine collision protection, provenance, chronology, state, and chain checks. Exact trigger definitions are authoritative in migration 005 and its byte-identical retained approved DDL.

The validator's physical-schema expectation is fixed independently of SQLite's emitted object names. It uses `PRAGMA table_list` for every table's `STRICT` flag; `PRAGMA table_xinfo` for exact column order, declared type, nullability, default absence and primary-key position; `PRAGMA foreign_key_list` for every target column and `RESTRICT` action; and complete `PRAGMA index_list`/`index_xinfo` rows plus independently pinned normalized `sqlite_schema.sql` hashes for all tables, indexes, and triggers. Index verification covers uniqueness, partial status and predicate, every indexed and auxiliary key entry, column order, `BINARY` collation, and ascending direction. It also rejects wrong storage types and nonpositive explicit IDs. Object-name counts alone are not schema validation.

The offline adversarial validator first asserts raw-byte equality between migration 005 and the retained approved DDL. It applies the real frozen migrations 001–004 before that exact body in a disposable fresh-install path and separately upgrades a disposable database already at 004. It verifies the frozen migration hashes, preserves deterministic row-level digests for all 13 legacy v1 tables and junctions, compares every pre-005 `sqlite_schema` object and SQL definition byte-for-byte, tests a no-op rerun, checks the exact nine-table/27-index/27-trigger physical inventory, and requires clean `PRAGMA integrity_check` and `PRAGMA foreign_key_check`. A disposable mutation that drops `requirements_status_idx` proves that missing legacy schema is detected even when all legacy row digests still match. Permanent migration tests additionally exercise production fresh install through 005, exact checksum-ledger recording, at-004 upgrade, empty tables, late-failure rollback, and legacy repository/search parity.

Fixed expected hashes cover every normalized migration-005 table, index, and trigger definition. Twelve separately applied schema mutants prove detection of a weakened receipt hash CHECK, candidate-successor chronology, candidate-successor knowledge sequence, retrieval outcome rule, alternate-key collision guard, processing-cycle guard, custody-transition guard, immutable-update guard, location chronology guard, composite candidate-lineage FK, index collation, and index direction. The receipt-hash and candidate-chronology mutants also have behavioral raw-SQL probes demonstrating that the canonical schema rejects the bad row while the intentionally weakened schema accepts it. These are schema-contract checks only: the harness is not a production importer or operational guarantee.

Closed controlled values in the approved migration-005 schema are: receipt format `1.0.0`; request method/profile `GET|http_get_representation_v1`; conditional validators `etag|last_modified`; artifact byte layers `retrieved_body|derived_output`; hash algorithm `sha256`; retrieval outcomes `retrieved_retained|observed_not_retained|not_modified|network_failed|http_failed`; custody events `placed|relocated|restricted|quarantined|restored|tombstoned`; custody classes `repository|restricted_store`; processing methods `content_decoding|parser|ocr|normalization|manual_transcription`; processing outcomes `succeeded|failed`; output kinds `decoded_body|normalized_text|extracted_text|ocr_text|structured_data|manual_transcript|diagnostic`; candidate record kinds `assertion|correction|withdrawal`; and locator kinds `byte_span|text_span`. Repository declarations are four nullable SQLite booleans constrained to `0|1`; a live repository custody row requires every declaration to be exactly `1`, never `0` or `NULL`, while restricted or tombstoned custody requires the declaration fields to be null. Retrieval outcome and hash/length state constraints use total `CASE` expressions and explicit null tests so no closed branch can pass through SQLite's three-valued `CHECK` behavior. HTTP status and run/output ordinals are structural integers, not taxonomies. Claim, software, version, backend, bundle, copy and record codes are bounded identifiers, not claims that an evolving legal taxonomy has been approved.

## Field-level epistemic classification

| Classification | Exact fields or field groups |
|---|---|
| Transport-declared audit claim | `bundle_id`, `bundle_sequence`, bound bundle path/times, original requested, terminal last-attempted and response-resolved URLs, GET request profile and allowlisted negotiation values, conditional validator, event/run times and outcomes, redirects, response metadata including canonical Content-Encoding/Vary, detected media types, collector/processor software and versions, methods/configuration, custody class/backend/reference/reason, custody occurrence time, output kind and production time |
| Importer-verified technical fact | format/schema conformance, recomputed bundle/configuration digests, trusted submitter/importer runtime match, exact staged/custody bytes, recomputed artifact hash/length, content-addressed paths, resolvable references, structural chronology/state combinations, and all-or-nothing transaction result |
| Unverified processing claim | that a reported run produced a particular output, plus candidate `claim_type_code`, observed/normalized values, locator/span, reason, and `confidence_basis_points` |
| Human declaration | submitter and recorder attribution, four repository-eligibility acknowledgements, and manifest credential/personal-data/hostile-input declarations |
| Technical identity/derivation | integer IDs; stable record/copy/chain codes; artifact byte layer/hash/length identity; receipt provenance; custody leaf under explicit event-time/knowledge-sequence bounds; raw and active candidate projections under explicit record-time/knowledge-sequence bounds |
| Explicitly unreachable | authoritative issuer identity, authoritative jurisdiction, officiality, legal-document identity, currency, consolidation, binding force, legal status/effect, applicability, verification, review, approval, publication |

The importer can prove that supplied bytes match declared identities and that rows obey the contract; it cannot prove that collector-reported times, server metadata, software identity, execution outcome or causation are true. Detected media type is a report at retrieval/output time and is intentionally excluded from artifact identity. Candidate values are hostile unverified claims even when produced by a human-transcription run. A candidate may merely suggest an issuer, jurisdiction, officiality, document type, identifier, date, or purported legal status; neither that value nor its claim code creates the corresponding authoritative concept in Tranche 2A.

## Version-1 evidence-bundle contract

The JSON Schema fixes the exact envelope. It includes a positive contiguous `bundle_sequence`, exact pinned `required_bundles`, importer implementation identity, and arrays carrying new locations, new artifacts, retrieval events with embedded redirect hops, custody events, processing runs with embedded outputs, and candidate occurrences. Embedded repeating children map to normalized helper rows. References use stable record codes. Location codes derive from exact URL UTF-8; artifact codes derive from exact byte identity; event/run/output/candidate/custody codes are bundle-prefixed. A code may resolve locally or to a row introduced by a directly listed dependency whose receipt code and digest both match. New artifacts carry staged paths. A later bundle may refer to an existing artifact without redeclaring it for a 304 basis, custody transition, processing input, or candidate correction; each new processing output nevertheless supplies transport-only staged bytes so the importer verifies that occurrence before deduplicating the identity. Retrieval events explicitly distinguish the original requested location, terminal last-attempted location, and response-resolved location. Version 1 permits only GET, HTTP 200 body observations, the closed 301/302/303/307/308 redirect set, strict HTTP 304 conditional reuse, and 300–599 HTTP failures other than 304; it rejects 206 and all other 2xx statuses. It pins the processing method/output matrix and the exact `content_coding` configuration described above. Version 1 requires one bundle-wide `contains_personal_data: false` declaration covering every artifact in the bundle: all personal-data-bearing artifacts are rejected, and restricted custody is not an exception. A later approved format and governance policy would be required before such material could be accepted.

`required_bundles` is sorted lexically by bundle code, has no duplicates, cannot include the current bundle, and pins each direct external dependency by stable identity and canonical digest. Each bundle after sequence 1 must at least pin its immediate sequence predecessor, so the ledger forms one reproducible chain; any other cross-bundle target's introducing bundle must also be listed directly. The durable bundle set must contain one unique manifest for every sequence from 1 through the maximum. Rebuilds use ascending `bundle_sequence`; the importer refuses gaps, duplicates, dependency cycles, dependencies on a later/equal sequence, or a filesystem enumeration order that disagrees with the manifest ledger.

### Canonical serialization and bundle digest

Version 1 uses this closed profile:

1. Limit the pilot manifest to 2 MiB, then decode as UTF-8 without BOM; reject empty input and invalid UTF-8.
2. Reject duplicate object keys before ordinary JSON parsing.
3. Reject lone UTF-16 surrogates. Preserve all valid Unicode scalar values exactly; perform no NFC/NFD or other Unicode normalization.
4. Permit JSON null and booleans. Permit only nonnegative safe integers `0..9007199254740991`; prohibit fractions, exponents, negative values, and negative zero in source JSON. The raw parser validates number tokens before `JSON.parse`, because parsed JavaScript numbers cannot preserve those lexical distinctions. Quantities needing other forms must be strings in a future format.
5. Sort object keys lexicographically by UTF-16 code units; schema keys are ASCII, making this byte-stable. Preserve array order exactly because redirects, outputs, and occurrence history are ordered evidence.
6. Serialize strings with ECMAScript `JSON.stringify` escaping, objects/arrays compactly with no insignificant whitespace, and no trailing line ending. Source-file CRLF/LF and whitespace therefore do not affect the digest; string content does.
7. Omit the top-level `bundle_digest_sha256` member entirely, canonicalize the remaining object, encode that serialization as UTF-8, and compute lowercase SHA-256. No other field is omitted. Explicit null differs from absence.
8. Store the resulting digest in `bundle_digest_sha256`. The importer recomputes before resolving or mutating anything.

### Independent canonicalization golden vectors

The validator commits expected canonical strings and SHA-256 values as constants, rather than calculating the expected values with the canonicalizer under test. These vectors are the version-1 compatibility anchors:

| Case | Canonical UTF-8 text | SHA-256 |
|---|---|---|
| UTF-16 key ordering, astral/BMP ordering, array and null | `{"a":[null,true,0],"😀":"astral","":"bmp"}` | `399ef25b59ef34e7bc8794bc8a1e4ed91b61bb6052a3c2af3d7a34f8e08b5ad7` |
| Unicode non-normalization (`e` + combining acute remains distinct from `é`) | `{"é":"NFD","é":"NFC"}` | `897b10cef0f117a16e395bf3b5d553fc6fdddbffb887ed8dc71bfb07b653959d` |
| Whitespace/CRLF-independent parse of `{ "b": [null,2], "a": 1 }` | `{"a":1,"b":[null,2]}` | `6345bd8358a8b8436e6943f731e2c7a17f456854bdc5de3ffa2eefd927e9652a` |
| Exclude only top-level digest; retain nested member | `{"a":null,"nested":{"bundle_digest_sha256":"keep"}}` | `b50e49d2fe981fe2966682436f68fa5c2b0b2d0ac52dee732e110b2b2a43d6a9` |
| Processing configuration | `{"mode":"synthetic","page_limit":2,"scripts_enabled":false}` | `1fd20eb02ac208b429577e7087b6fea4e81cc0627f891b0da964ceb76d8c2d73` |
| Complete minimal sequence-1 manifest, including bootstrap and every required empty collection | fixed literal committed in the validator | `63a19074159f0ad98347f2ad148db1b048d8f41af3857f407396f4e7932dacb4` |

The canonical ordering vector `{"a":1,"b":2}` hashes to `43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777`; the reversed noncanonical text `{"b":2,"a":1}` hashes to `3fb75453225c732a76b7899ea2096dda1455189c89817239732182f73fe5a09f` and is rejected as a purported canonical payload. Raw source objects may arrive with either key order; canonicalization must always emit the first string.

The complete-manifest canonical string and expected digest are hard-coded independently of the canonicalizer under test. In addition, the validator mutates every scalar manifest leaf in complete positive bundles and proves that each mutation changes the digest, except for the intentionally excluded top-level `bundle_digest_sha256` field. Array reversal is separately tested because array order is evidence-bearing.

The raw artifact digest is different: it covers the exact staged and custody byte sequence with no JSON or text normalization. `retrieved_body` means the exact HTTP/1.1 response-body octets after transfer framing is removed, or HTTP/2/3 DATA payload octets concatenated in protocol order, before any `Content-Encoding` decompression, character decoding, line-ending changes, markup cleanup, or other transformation. Content-coding decoding is a separately attributed/versioned `content_decoding` processing run with a `derived_output`. Collector and client configurations must disable transparent decoding for this captured layer and record observed `Content-Encoding`. `derived_output` is the exact persisted output byte sequence; output kind/media and the processing configuration describe its format without becoming part of byte identity.

JSON Schema rejects unknown fields and structural violations. Its character-count bounds are only a first line of defense: the fixed importer applies the documented UTF-8 byte bounds before mutation. The fixed importer additionally enforces graph, chronology, digest, file, identity, URL, and state rules. Schema plus declarations cannot reliably detect every secret, personal datum, malicious document, signed URL, or unsafe network destination; independent scanning and operational controls remain mandatory.

## Principal bootstrap and write isolation

Tranche 1A intentionally contains no principals. The approved contract unambiguously chooses a **first-bundle bootstrap ceremony**: the sequence-1 pilot bundle must contain one explicit `principal_bootstrap` envelope. It declares the fixed service trust root `(1, system.bootstrap)`, at least one human submitter, one service collector, and one distinct service importer with explicit IDs, creation attribution, causal timestamps, and runtime roles. No declared operational principal may reuse the reserved `system.bootstrap` code or ID. The future importer will accept the envelope only when `atlas_principals` and the receipt ledger are empty, only during an explicit one-time ceremony, and only when a trusted runtime identity map binds the authenticated human invoker and importer executable identity to the declared principals. It will refuse bootstrap content in every later bundle. This is visible, versioned input—not hidden seed data. A separate principal-registration-envelope design is not an open alternative in the approved contract.

The trust-root service creates principal identities only and never records evidence. The manifest submitter is the human accountable for submitting the bundle. The collector is the service that performed acquisition and may only produce an untrusted staged bundle. A processor is the attributed human/service that produced a run. The importer is a different fixed-function service that validates and writes; migration-005 insert guards structurally reject using the receipt's importer principal as collector or processor. Caller-supplied IDs or principal codes are insufficient: the future importer must resolve stable codes against the database and verify the authenticated invoker and executable identity against trusted runtime configuration outside the manifest. Distinct stored attribution still does not prove distinct authenticated processes; runtime/process isolation supplies that guarantee.

Pilot isolation is a reviewed Git-bundle workflow:

1. Automation writes artifacts and manifests only to an untrusted workspace or pull request. It has no canonical database path or credential.
2. Human review accepts the bundle as structurally ready, not legally true.
3. A network-free fixed-function importer, run with a trusted invoker mapping and narrowly configured artifact adapter, opens the generated canonical SQLite database read-only through the approved cloner boundary. Only the isolated fixed-statement writer may open the disposable candidate database writable.
4. No generic SQL console or unrestricted database handle is exposed to the collector.

SQLite has no table-level permissions. These controls belong to process isolation, filesystem permissions, CI identity, and the fixed importer—not `principal_kind_code`.

## Storage-independent artifact adapter

The future importer accepts a configured reviewed bundle root and a caller-selected relative manifest path. It normalizes and confines the path, rejects absolute paths, traversal, symlinks and root escape, opens the file from that root, and requires the opened relative path to equal the manifest's own `manifest_path`. The manifest bytes used for digest verification are read from that already-confined handle; the implementation must avoid a check/open race. The future artifact adapter separately consumes a minimal interface: prepare or resolve a content-addressed object under an approved custody class; open a read-only byte stream; report exact byte length; recompute SHA-256 while reading; confirm that the import context may access that custody copy; and finalize or safely abandon a prepared placement. Fetching, legal-rights determination, and authority drafting are outside the import adapter.

The synthetic repository-file adapter resolves only a configured repository root plus a normalized relative path, rejects empty/dot/traversal segments, uses `lstat`/`realpath` containment and refuses symbolic links, opens without following unsafe links where supported, and never performs network access. Every live custody reference is `objects/sha256/<first-two-hex>/<sha256>` and must reopen to the declared length/hash before SQLite mutation. It does not make an artifact repository-eligible. A repository custody declaration is accepted only when the authenticated human submitter makes the four explicit acknowledgements; those declarations remain operational assertions, not a review or legal-rights approval.

SQLite cannot transact atomically with Git or an external object store. The safe ordering is: verify staged bytes; prepare an immutable content-addressed object; reopen and verify it; then execute the SQLite transaction. A database rollback may leave an unreachable content-addressed orphan, which a later reconciliation job may remove only after proving no accepted manifest/receipt references it. The reverse failure mode—committed SQLite custody pointing to bytes that were never durable—is forbidden. Tombstoning is committed as history before separately authorized physical removal; until removal completes the bytes may be orphaned but are no longer declared available. Operational authorization, retention, and deletion auditing remain prerequisites.

## Deterministic importer contract

The approved production-importer contract requires every step through preflight to complete before a database transaction starts. The D9.2 candidate implements the following rules only for synthetic inputs and disposable candidates; protected operational orchestration, custody, promotion, journal, backup, and recovery remain later boundaries. Its fixed writer also performs SQLite integrity and foreign-key checks plus the complete plan-to-persisted projection inside the transaction before commit; the independent verifier repeats manifest-based verification afterward:

1. Accept the configured reviewed root and relative manifest path, confine/open it without following symlinks or escaping the root, require the opened path to equal the manifest declaration, then read the bounded bytes as UTF-8 with fatal decoding; reject BOM, invalid encoding, duplicate keys and forbidden number tokens, and validate the v1 JSON Schema plus UTF-8 byte limits.
2. Recompute canonical serialization and bundle digest.
3. Require the next contiguous sequence and monotonic bundle-creation chronology; verify every direct dependency's code/digest and construct a read-only, type-aware resolver limited to current declarations plus pinned accepted bundles.
4. Resolve every stable reference and reject missing, ambiguous, wrong-type, unpinned, or cyclic references. Build the complete processing graph and prove every input is grounded in a retained retrieval or an earlier already-grounded run; reject self-origin and multi-run cycles independently of timestamps.
5. Validate the one-time first-bundle bootstrap or existing principal identities, trusted runtime mappings, every attribution and chronology rule, role-specific retrieval-location availability (requested by attempt start; last-attempted, resolved and redirect endpoints by completion), outcome/conditional/representation combinations, the exact HTTP-200/304/failure and redirect-status profiles, C0/DEL-free fields, canonical ETag/IMF-fixdate/Content-Encoding/Vary values, redirect completeness through the last attempted location, custody roots/transitions and event-time/knowledge-order rules, processing ordinals and grounding, the closed method/output/configuration matrix, candidate correction chains, and all closed state combinations.
6. Resolve only newly declared staged artifacts through the staging adapter without network access; existing artifact references require no restaging.
7. Stream and recompute exact staged byte length/SHA-256 for each new artifact, every retained-retrieval occurrence and every processing-output occurrence; require a qualifying placement for every new artifact used as retained input/output; and prepare/reopen every live custody destination to verify the same bytes.
8. Validate custody class and authenticated repository-eligibility declarations without inventing copyright, privacy, or rights approval.
9. Preflight every SQL-enforced rule without writing: primary/stable-code, URL, artifact natural-identity, manifest-path, sequence/digest, run/output/redirect ordinal, partial-root and predecessor uniqueness collisions; positive IDs/types; receipt and principal attribution; all parent/child/FK matches; every SQL chronology rule; custody-root and current-leaf rules; and the complete processing graph. Existing natural identities must match exactly. SQL remains the defensive final boundary, but a semantic-preflight rejection must occur before `BEGIN`.
10. Open one `BEGIN IMMEDIATE` transaction only after preflight succeeds. For the sequence-1 ceremony only, insert the validated bootstrap principals first because the receipt FKs require them; then insert the deterministic technical receipt as the first Tranche 2A row and apply the remaining evidence rows in dependency order with every row connected to that receipt. Any failure rolls back principal bootstrap, receipt, and every evidence row.
11. Immediately after insertion and before commit, compare the complete canonical expected projection with the database.
12. The complete projection check covers every persisted column and every relationship in all nine tables. It resolves database FKs back to manifest stable codes, checks nulls, child order, composite run/output lineage, receipt provenance, predecessor/correction edges, custody declarations and occurrence time, retrieval request/response/conditional fields, processor configuration digest, and all other scalar values. It runs immediately after a new import and again before returning `no_op`; an altered ETag, outcome, timestamp, custody field, run configuration, candidate value, missing child, or changed relationship fails closed. Matching only row presence, counts, IDs, or selected columns is insufficient.
13. Return `no_op` only when code/digest match, the full projection check succeeds, dependencies remain pinned, and every currently live referenced custody copy accessible to the importer re-verifies. A historical copy whose current leaf is a tombstone is deliberately not required. Fail closed when an existing stable ID/code is paired with different content or when a natural identity resolves inconsistently.

Canonical rows contain only manifest-declared deterministic times. The importer's local wall clock may appear in noncanonical operational logs, never in reconstructed row content or digests. Given migrations, ordered accepted bundles, trusted identity mapping, and artifact bytes, a rebuild yields the same logical rows and row-level content digests.

An identical-bundle no-op and a disaster rebuild have different byte prerequisites. A no-op trusts the already accepted receipt/projection and rechecks current live custody; it must not demand bytes whose custody chain now ends in an authorized tombstone. A fresh sequential rebuild still requires every artifact's originally staged bytes at the bundle where the identity first enters the ledger. A deletion-aware restore protocol that can reconstruct tombstoned history after those bytes have been lawfully destroyed requires separately approved durable acceptance evidence and is an unresolved operational prerequisite; this design does not pretend the hash alone is a reproducible artifact.

## Enforcement-responsibility matrix

| Invariant | Primary enforcement |
|---|---|
| STRICT types, positive IDs, FKs, closed state values, canonical timestamp shape | SQLite |
| Complete timestamp validity, monotonic bundle creation, and cross-record chronology | SQLite plus manifest validator/importer |
| Custody occurrence time is separate from receipt-sequence knowledge order | Physical fields/FKs and deterministic projection; importer freezes run validation to its receipt sequence |
| Bootstrap cannot record evidence | SQLite insert triggers; importer also rejects |
| Attribution is not authorization | Architecture statement; trusted runtime/importer policy |
| Collector lacks canonical DB access | Filesystem/process/CI isolation; not SQLite |
| Collector/processor attribution differs from technical importer | SQLite insert triggers and importer validation; actual runtime identity/process separation remains external |
| Retrieval attempts never deduplicate | SQLite unique event code only; importer always creates a new attempt |
| Artifact identity is only byte layer + SHA-256 + length | SQLite composite uniqueness and code check; adapter recomputation |
| Artifact identity excludes custody/media/URL/access | Physical normalization in SQLite |
| Storage deduplication cannot broaden access | Artifact adapter and custody-specific operational authorization |
| Requested, last-attempted and response-resolved locations and redirects remain distinct | SQLite columns/FKs/ordinals and role-specific defensive chronology; importer validates the complete chain, including redirected network failure |
| GET-only HTTP-200 body capture, rejected 206/other 2xx, closed redirect statuses, and exact retrieved-body octets | SQLite closed status combinations and redirect CHECK; collector captures pre-content-decoding octets; importer validates transport profile and bytes |
| Canonical request/response values reject C0/DEL; ETag, IMF-fixdate, Content-Encoding and Vary have pinned syntax/semantics | SQLite defensive shape/range checks; manifest validator/importer enforce full token canonicalization, actual IMF calendar/weekday validity, Vary ordering/uniqueness and supported-304 semantics |
| `not_modified` has no artifact and names an exact retained basis, validator, terminal location and representation profile | SQLite CHECK/trigger; importer validates the complete redirect/conditional graph and supported Vary subset |
| Failed retrieval has no artifact | SQLite outcome CHECK |
| `observed_not_retained` cannot feed processing | No artifact identity plus SQLite retained-custody requirement |
| Retrieval success survives processing failure | Separate SQLite tables and immutable rows |
| Runs use exact retained inputs and record processor/configuration/outcome | SQLite FK/trigger; importer and adapter verify bytes/access |
| Content-coding transformation is an explicit run, never a hidden parser behavior | Manifest method/configuration/output lineage; future processor conformance and build attestation; SQLite cannot inspect executable behavior |
| Derived outputs have exact, acyclic, retrieval-grounded lineage, including same-bundle reuse only after a lower-ordinal grounded producer | SQLite run/output/artifact FKs, run ordinals, method/output checks and cycle guard; importer proves the complete graph and exact configuration/output matrix |
| Manual transcription is processing, not direct edit | SQLite closed method and candidate lineage; importer API surface |
| Repeated/conflicting candidates remain separate | SQLite occurrence identities; importer never value-deduplicates |
| Every candidate has successful run/output and a version-1 byte/text span | SQLite composite FK/CHECK/trigger; manifest and adapter bounds/UTF-8 validation |
| Candidate corrections cannot move backward in knowledge sequence; historical views bind record time and receipt sequence | SQLite successor trigger; importer preflight; raw-leaf and active-candidate projection queries |
| Confidence is processing metadata, not legal confidence | Schema naming and inaccessible authority/review model |
| Authority/legal/review/publication concepts are unreachable | Absence from DDL, importer, repository/API/frontend |
| Corrections/withdrawals/restrictions/relocation/tombstones preserve history | SQLite immutable current-leaf chains |
| Retries are new events/runs | Importer behavior and distinct stable codes |
| UPDATE/DELETE/REPLACE cannot rewrite history | SQLite immutable and collision triggers, including recursive triggers off |
| Manifest is deterministic, versioned, ordered, dependency-pinned, and idempotent | JSON Schema/raw manifest validator, importer preflight, technical receipt/sequence |
| Manifest path identifies the actual reviewed input | Importer reviewed-root confinement, symlink/escape checks, opened-path equality and race-safe read; SQLite stores the bound value |
| Every SQL collision, chronology, attribution, root and graph rule is checked before transaction | Fixed-function importer semantic preflight; SQLite remains defensive final boundary |
| New import and no-op projections match every persisted field and relationship | Fixed-function importer full stable-code projection, before commit and before returning `no_op` |
| Exact staged and declared custody bytes exist and match declarations | Artifact adapters plus importer before transaction |
| Each retained retrieval and processing output re-observes its own bytes before identity deduplication | Transport-only staged path plus importer/adapter hash-and-length recomputation |
| Every newly retained/derived artifact and retained/output occurrence has qualifying custody | Manifest graph/interval validation and fixed importer completeness check; mandatory-child existence is not enforceable at parent insert in SQLite |
| Every new artifact has a typed retrieval or processing origin | Manifest graph validation and fixed importer completeness check; mandatory-child existence is not enforceable at parent insert in SQLite |
| Credentials/signed URLs/unsafe paths are rejected | JSON Schema shape, importer URL/path rules and scanning, adapter realpath checks, operational secret scanner |
| Every personal-data-bearing artifact is rejected in manifest v1 | Required false declaration plus importer/scanning/policy; restricted custody does not override; JSON Schema alone cannot prove absence |
| HTTPS/SSRF/redirect safety | Future collector network policy; importer is deliberately network-free |
| Size/decompression/resource limits and disabled active content/entities | Future isolated collector/parser; not SQLite |
| Secret/header redaction | Collector allowlist, importer schema/scanner, operational logging policy |
| Access restriction or legally required removal leaves tombstone | Custody events plus adapter/policy-controlled byte removal |
| Local import time/filesystem order cannot change canonical reconstruction | Contiguous bundle sequence, pinned dependencies, manifest times and deterministic receipt; local time only in noncanonical logs |

## Transactions, correction, and deterministic projections

State meanings are deliberately technical and closed for this pilot:

| Record | State behavior |
|---|---|
| retrieval | `retrieved_retained` is exactly HTTP 200 whose occurrence bytes were rehashed and linked to a retained artifact; `observed_not_retained` is exactly HTTP 200 with no artifact; `not_modified` is exactly 304 plus an exact earlier retained basis; `network_failed` retains its last attempted (and, if used, conditional) request context but has no response-resolved location/status/body; `http_failed` has a resolved location and status 300–599 other than 304, with no body artifact. Status 206 and every other 2xx are rejected in manifest v1. |
| custody | `placed` begins one copy chain as available; `relocated` keeps an available copy but must change backend or custody class; `restricted` and `quarantined` retain a restricted-store reference but make that copy ineligible as processing input; `restored` makes it available again; `tombstoned` declares no current backend reference. Event occurrence time and receipt-sequence knowledge order are separate. |
| processing | `succeeded` emits only kinds permitted by its method and has no failure code; `content_decoding` success emits exactly one `decoded_body`, while other successful methods may emit zero or more ordered permitted outputs. `failed` requires a failure code and emits no output. Every retry is a new run. |
| candidate | `assertion` is the one root of a chain; `correction` supersedes its current leaf with a nonblank value; `withdrawal` supersedes its current leaf with null values; a later correction may reinstate a withdrawn chain. |
| receipt | insertion means the complete bundle transaction was structurally accepted; there is no mutable receipt state, and acceptance is not legal verification. |

Imports are all-or-nothing. Natural-identity reuse is resolved during preflight. For sequence 1 only, the validated bootstrap principals are inserted first; the receipt then precedes location/artifact/event/redirect/custody/run/output/candidate rows inside the same transaction. Later bundles begin with the receipt. A collision discovered after transaction start still aborts everything.

Custody projection takes two independent inputs: `:event_as_of` and `:known_through_bundle_sequence`. Join every custody event to its receipt, retain only rows with `occurred_at <= :event_as_of` and `bundle_sequence <= :known_through_bundle_sequence`, and within each `(artifact_id, copy_code)` select the row with no qualifying successor under those same bounds. Interpret that leaf to derive the copy's declared state. A declared retained artifact has at least one qualifying available leaf with a backend reference; actual retrievability additionally requires an adapter integrity check. Restrictions are evaluated per copy, never from artifact identity alone.

A processing run fixes `known_through_bundle_sequence` to its own receipt sequence and `event_as_of` to `started_at`. Therefore a bundle accepted later may report a historical restriction, but it cannot retroactively change whether the earlier run had a qualifying input according to the evidence known when that run was accepted. For example, placement at T1 in sequence 1, an accepted run at T3 in sequence 2, and a restriction occurring at T2 but first recorded in sequence 3 leaves the sequence-2 run valid-as-accepted; a later projection through sequence 3 shows the restriction for event times at or after T2. This is an audit statement, not a claim that the physical use was legally authorized.

Candidate history has two distinct projections, and both take `recorded_as_of` plus `known_through_bundle_sequence`. The **raw correction-chain leaf** joins every candidate and successor to its evidence-bundle receipt, applies both bounds to both sides, and returns the bounded leaf even when it is a withdrawal. The **active candidate projection** first resolves that raw leaf and then returns no candidate when the leaf is a withdrawal; it must not filter withdrawals before leaf resolution because that would incorrectly reveal a superseded predecessor. A later-bundle correction whose declared `recorded_at` is backdated cannot change a view bounded to an earlier bundle sequence. Raising the sequence bound may expose that correction; when it follows a withdrawal, it reinstates the active candidate without deleting audit history. Different chain codes remain separate even when claim type and value match, so conflicts and repeated observations survive.

Retrieval and processing records have no mutable current-status projection. Retry attempts append rows. `not_modified` refers to its exact conditional basis rather than inheriting a new artifact. Relocation/restriction/tombstone events change custody declarations only; they never alter artifact, retrieval, processing, or candidate history.

The version-1 manifest has no generic polymorphic “supersedes” pointer. Its type-safe supersession references are `corrects_candidate_record_code` for candidate correction/withdrawal and `predecessor_custody_event_code` for custody relocation/restriction/quarantine/restoration/tombstoning. Location and artifact rows are exact identities: a different URL or byte sequence is a new identity, while erroneous unused declarations remain immutable and non-authoritative. Retrieval events and processing runs are occurrence logs, not current-truth assertions; a retry is a new occurrence and an apparent conflict is preserved. Qualifying an already accepted erroneous event/run would require a separately approved type-safe incident/review record in a later governance or freshness tranche. Tranche 2A therefore does not silently void or rewrite those facts and derives no legal conclusion from them.

## Threat model

- **Hostile documents and prompt injection:** artifacts and extracted text are inert untrusted bytes. No content can issue instructions, select tools, or create authority records. Parsing must be isolated and resource-bounded.
- **Network abuse:** collectors require HTTPS scheme, DNS/IP re-evaluation, private/link-local/loopback denial, redirect caps and revalidation, and response/decompression limits. The importer never fetches.
- **Secret leakage:** manifests allow only named response fields, prohibit auth/cookie fields and transient signed locations, reject obvious configuration-key forms including token-boundary variants of `api_key`, `private_key`, `signing_key`, credentials, passwords, secrets and tokens, and require scanning before Git. Logs redact headers and paths. Detection is defense-in-depth, not proof.
- **Path and symlink escape:** adapters confine relative references to a configured root and reject traversal and unsafe links.
- **Hash confusion:** algorithm and byte layer are explicit; bytes and lengths are streamed and recomputed. Media type and filename never influence identity.
- **Privilege spoofing:** manifest principal codes are claims until matched against authenticated runtime configuration. Collectors cannot open the canonical database.
- **History rewriting:** immutable triggers and collision guards reject UPDATE, DELETE and REPLACE. Corrections and custody changes append.
- **Rights/privacy removal:** manifest v1 rejects all personal-data-bearing artifacts before custody is considered. For otherwise eligible non-personal artifacts, immutable logical identity/history remains while an authorized custody action removes or restricts bytes and records a tombstone without prohibited content.
- **Availability and disaster loss:** Git-held eligible pilot bytes require clone/rebuild testing; restricted backends require approved backup/restore before real use.

## Synthetic scenario coverage

The standalone validator creates no real source material or live URL. Two deterministic synthetic bundles cover first-boot and later-history behavior:

- a successful HTTP-200 HTTPS-shaped retrieval with one redirect and retained pre-content-decoding raw bytes;
- a second retrieval of identical bytes, yielding two events and one artifact identity;
- a strict 304 linked to its exact earlier retained basis, terminal location, validator, supported negotiation profile and Vary semantics;
- redirected and conditional network failures that preserve requested/last-attempted context without inventing a resolved location, plus HTTP failures with no artifact;
- an HTTP-200 `observed_not_retained` event that cannot become a processing input, plus rejection of 206 and all other 2xx statuses;
- accepted canonical ETag, IMF-fixdate, Content-Encoding and Vary examples; rejected C0/DEL, invalid weekday/calendar dates, malformed tags/coding lists and unsorted or duplicate Vary fields;
- the complete processing method/output matrix, including pinned `content_coding`; a successful parser run with two derived outputs and exact lineage; and a higher-ordinal same-bundle run whose staged output deduplicates to an artifact already produced by an earlier grounded run;
- a separate failed processing run that leaves retrieval success unchanged;
- repeated and conflicting candidate occurrences plus correction and withdrawal;
- repository placement, relocation, restriction, restoration, restricted custody, and tombstones;
- a second-bundle 304 against a pinned first-bundle basis, restoration after a tombstone, and candidate reinstatement after withdrawal without restaging the earlier artifact;
- exact GET representation provenance across original requested, terminal last-attempted and response-resolved locations; pre-content-decoding retrieved bytes; observed Content-Encoding/Vary; and a 304 whose exact ETag/Last-Modified validator and request profile match its basis;
- a grounded processing chain plus rejected same-run self-origin and A→B→A cycles, including equal-time cases;
- placement at T1, an accepted run at T3, and a later-bundle restriction occurring at T2, proving event-time/receipt-sequence projection does not retroactively invalidate the accepted run;
- independently fixed canonical strings/digests for UTF-16 ordering, arrays/nulls, CRLF/whitespace independence, non-normalized Unicode, astral/BMP ordering, top-level digest exclusion, configuration hashing and one complete manifest; reversed-key mutation rejection; and every-manifest-leaf digest sensitivity except the top-level digest field;
- complete post-import/no-op projection comparison and mutations of ETag, outcome, timestamp, custody fields, configuration, candidate values and relationships that all fail closed;
- schema execution plus fixed physical introspection of STRICT flags, exact columns/types/nullability/defaults/PKs, FKs/actions, and complete index SQL/key definitions including collation and direction, with wrong-type and nonpositive-ID rejection;
- direct-SQL retrieval outcome, observed hash/length, repository declaration, other nullable state, and candidate sequence matrices that bypass manifest preflight;
- raw and active candidate projections bounded independently by record time and evidence-bundle sequence, including withdrawal and backdated reinstatement;
- fresh-ID/fresh-primary-code `INSERT OR REPLACE` collisions against every independently collidable alternate, composite and partial unique key with recursive triggers disabled, preserving original counts and digests. The `(id, processing_run_id)` output index exists to support a composite foreign key and is necessarily primary-key-subsumed, so its collision is covered by the isolated primary-key probe. A deliberately corrupted disposable receipt ledger exercises the otherwise nonconstructible SHA-256 digest-collision preflight branch;
- semantic-preflight failures—including manifest-path collision and role-specific location chronology violations—observed before `BEGIN`; and an injected post-insert/pre-commit failure after every evidence table has rows, restoring principal, receipt and all evidence-table counts/digests.

The standalone Tranche 2A validator validates the approved schema/contract and its design-era import simulation. The separate D9.2 tests exercise a synthetic, unactivated implementation against disposable databases. Neither suite claims that an operational importer, collector, parser, artifact provider, authentication system, custody adapter, backup, promotion coordinator, or access-control deployment exists.

## Independent review reconciliation

Independent read-only HTTP/manifest and SQLite/validator reviews were repeated after the final hardening pass; a separate documentation-consistency review checked the same tree. No blocker remained after reconciliation.

Accepted findings were incorporated: cross-bundle references now require digest-pinned dependencies, monotonic creation time and contiguous replay sequence; later bundles can append 304s, custody successors and candidate corrections; the first-bundle bootstrap is one-time and runtime-bound and rejects any operational principal that reuses its reserved code before `BEGIN`; new artifacts require adapter-verified custody; repository paths and the manifest input are root-confined and symlink-safe; raw JSON Schema validation, lexical parsing, independent micro-vectors, a complete-manifest golden vector and every-leaf digest sensitivity are exercised; repository eligibility is an attributed declaration rather than a review; configuration hashes are recomputed from retained canonical manifest objects; complete projection comparison and full physical-schema introspection were tightened. Retrieval evidence now distinguishes original requested, terminal last-attempted and response-resolved locations, represents redirected/conditional network failure without inventing an HTTP response, accepts only HTTP 200 full-body observations and strict 304 reuse, requires null observed-body hash/length outside `observed_not_retained` before `BEGIN`, and pins C0/DEL, the ASCII ETag profile, IMF-fixdate, Content-Encoding and Vary handling. Total SQLite state checks and direct-SQL mutation matrices close nullable retrieval, observed-hash/length, repository-declaration, tombstone, processing-outcome and candidate-predecessor branches. Exact pre-content-decoding byte identity and the closed processing method/output/configuration matrix are explicit. Processing lineage is ordered, acyclic and retrieval-grounded; same-bundle byte reuse requires a higher-ordinal run after an earlier grounded production edge. Custody projections separate occurrence time from receipt-sequence knowledge. Candidate history now distinguishes a dual-bounded raw chain leaf from its active, withdrawal-excluding projection, and successor knowledge sequence is enforced in both SQL and preflight. Every index definition is pinned through normalized SQL and complete collation/direction/key introspection, with explicit `NOCASE` and descending-index mutants. A no-op does not demand an intentionally tombstoned historical copy. The field epistemic table separates reported observations from importer-verified facts. Documentation corrections also distinguish general unretained observations from the HTTP-200 `observed_not_retained` outcome, locate bootstrap provenance in the first manifest, and state the sequence-1 insertion order accurately.

The recommendation to add a generic correction/supersession table was rejected because it would introduce a seventh evidence concept or an unenforceable polymorphic target. Instead, candidate and custody supersession remain explicit type-safe chains; exact location/byte identities never change; retrieval/run occurrence logs have no “current truth” projection; and later qualification of a disputed accepted occurrence is carried as a concrete future governance/freshness prerequisite. The recommendation to store a canonical local acceptance clock in SQLite was also rejected because it would make rebuilds nondeterministic; a separate durable operational audit is required before operation. A suggested blanket SQL prohibition on all non-decoding methods consuming a retrieved-body identity was not adopted: the same exact bytes may have several retrieval occurrences with different reported representation metadata, while a run currently names the artifact rather than one occurrence. The contract instead forbids hidden decoding, requires an explicit decoding edge when decoding is needed, and carries processor conformance/build attestation as an operational prerequisite rather than claiming SQLite can inspect program behavior.

Still unimplemented at the current boundary are production authentication/authorization configuration, operational `AF_UNIX` service endpoints, D9.1/D9.2 protected-runtime integration, operational storage commit coordination and orphan reconciliation, canonical promotion, external backup/restore and deletion-aware reconstruction, artifact rights/privacy decisions, robust secret/personal-data/malware scanning, collector network controls, parser sandboxing, and the later type-safe event/run qualification workflow. Approved Decision 9 specifies the pilot design for those later runtime, custody, recovery, scanning and clearance portions. Historical D9.0 closes the version-1 message shapes; approved D9.0.1 supplies the applicable corrected runtime-profile and classification revisions for exact logical-handle scope. Approved D9.1 tests its isolated synthetic control-plane portion only. The D9.2 candidate adds synthetic descriptor-confined manifest intake, semantic preflight, disposable fixed-statement writing with pre-commit projection, independent full persisted projection, receipt-prefix-bounded accepted no-op, and hash-pinned from-zero reconstruction verification, but it neither activates a protected runtime generation nor writes canonical state. It projects the frozen logical-state payload but does not issue an operational seal record. Any D9.3 durability-receipt linkage requires a separately versioned and reviewed contract extension. Production hosted custody, processing and event/run qualification remain later work. More complex locator profiles are future-format work, not a version-1 prerequisite. The standalone Tranche 2A harness tests its historical synthetic adapter and simulated importer; D9.2 has its own implementation tests. D9.0 validates contracts, while D9.1's synthetic native tests and dedicated-UID private-pipe append worker do not prove an operational deployment or custody guarantees.

## Unresolved prerequisites before real pilot data

- Implement and security-review the approved one-time first-bundle principal bootstrap ceremony and trusted runtime bindings; the contract no longer leaves the transport choice internally unresolved.
- Approve or revise D9.2, then integrate its fixed manifest/preflight/plan/writer/verifier seams with the protected D9.1 runtime and trusted authenticated-invoker mapping without widening either boundary.
- Implement and security-review D9.0's approved repository-eligibility and human rights/privacy contract in its later authorized tranche; every prospective artifact still requires an independent decision, and a schema-valid synthetic clearance is not that decision.
- Implement the synthetic repository-file adapter and approve a durable restricted-store adapter before restricted artifacts are accepted.
- Define custody retention, restriction, legal-removal authorization, backup/restore, and disaster-recovery procedures.
- Define a deletion-aware restore mode before an artifact whose bytes were lawfully destroyed can be reconstructed as historical tombstoned metadata; the ordinary fresh rebuild intentionally requires original staged bytes.
- Add secret, personal-data, malware and archive-bomb scanning; parser sandboxing; and collector SSRF/redirect controls before automation.
- Decide the carried freshness change-candidate vocabulary, staleness model, and byte-change escalation policy in their later tranche.
- Decide the later type-safe incident/review record for qualifying a structurally accepted but subsequently disputed retrieval or processing occurrence; the approved pilot contract deliberately does not pretend such logs have a mutable truth status.
- Review licensing and redistribution for every prospective artifact. No real document is approved by this design.
