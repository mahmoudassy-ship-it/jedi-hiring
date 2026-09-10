# Review governance and freshness

Status: approved sixth architectural requirement. Separately numbered implementation Decision 6 approves the boundary between Tranche 2A source-evidence quarantine and Tranche 2B source-backed authority drafting, Decision 7 approves the hybrid pilot evidence-custody/import contract, and Decision 8 approves six logical Tranche 2A evidence boundaries; the architectural-requirement and implementation-decision numbering series are distinct. The exact 2A schema and manifest contract were later approved, and migration `005_tranche_2a_source_quarantine.sql` implements the empty nine-table physical schema. [Decision 9](tranche-2a-importer-custody.md) approves the operational architecture for the fixed-function importer, identity boundary, custody, backup and one-document pilot as proposed at commit `ee3ccd777849c7ffcad1efe5d5d9170c15171a65`. Its historical design-only [D9.0 contract freeze](d9-0-contract-freeze.md) was approved at commit `320b2d6969ede88796c44e652f6422f73e7fe4fe`; D9.0.1 was approved at commit `58a10d43ee5fcc3121a368301b4f5a925f26a9e3` and is the applicable revision for subsequent D9 implementation, superseding only the corrected runtime-profile and handle-scope contracts. D9.1 is the approved synthetic, unactivated control plane. D9.2 now has a [synthetic, unactivated accepted-bundle verifier implementation candidate](d9-2-accepted-bundle-verifier.md) awaiting separate approval. It adds no production activation: no collector, operational custody adapter, authentication/authorization binding, monitoring, review-domain table, real evidence, or public surface exists. Migration implementation, design approval, and synthetic component implementation are not authorization for real evidence, public exposure, or production use.

The earlier foundation-level review-policy proposal is superseded. Principal lifecycle/status, review roles, grants, qualifications, policies, actual reviews, publication decisions, and their evaluator will be implemented together as a review-governance vertical slice so their invariants can be tested end to end. Migration 005 imported no substantive evidence or legal data, and its nine tables remain empty. If later accepted through an approved importer, Tranche 2A observations, artifacts, processing runs and candidates remain quarantined evidence, while Tranche 2B authority records may only be human-attributed, evidence-linked unpublished drafts. Neither class is reviewed, verified, approved or public before governance gates exist and are satisfied. Any policy/content hash in that slice must define and test canonical UTF-8 serialization, field order, null representation, normalization, and recomputation.

Tranche 1A principal 1 (`system.bootstrap`, service) is only the technical creation trust root. It cannot record languages, jurisdictions, or jurisdiction versions and can never satisfy a human, reviewer, qualification, adoption, or publication requirement. The approved Tranche 2A contract chooses a one-time first-bundle ceremony to create this root and the separately attributable operational principals under trusted runtime binding. D9.2 can exercise the exact roster only in a disposable synthetic candidate; no implementation executes the real ceremony. Creation attribution is evidence of who or what recorded a row; it is not authentication, authorization, qualification, or review eligibility.

## Trust boundary and record states

Automated extraction may write only through a segregated Tranche 2A ingestion surface. It cannot create or modify authority drafts, proposition versions, reviews or publication decisions. A human drafter may create a new evidence-linked unpublished authority draft from quarantined evidence; this never moves, mutates, relabels or elevates the evidence and is not verification. `draft`, `reviewed`, `published`, `stale`, and `withdrawn` require distinct, auditable semantics; editing published or reviewed content always creates a new unpublished immutable version. The exact relationship between content state and derived freshness or eligibility remains an explicit later decision.

The pipeline is:

```text
retrieval location -> retrieval event -> artifact identity -> artifact custody -> processing run -> unverified candidate -> evidence-linked authority draft -> gated reviews -> publication decision
```

These are at least five separate processes. The pipeline labels are conceptual rather than stored state machines; where migration 005 does store a closed technical outcome, its exact approved enum is documented in the Tranche 2A physical specification:

1. **Retrieval outcome:** `attempted -> retrieved | not_modified | network_failed | http_failed`. It records acquisition facts only.
2. **Processing-run outcome:** a separate content-decoding, parser, OCR, normalization or attributed human-transcription attempt against one retained artifact results in method-permitted output or a processing failure. Retrieval remains successful when processing fails, and a later run may retry the same artifact.
3. **Change candidate:** `detected -> deduplicated -> awaiting_triage -> no_material_impact | parser_only | false_positive | confirmed_material | uncertain_escalated -> closed`. Only a human triage decision moves beyond `awaiting_triage`; the final vocabulary is unresolved below.
4. **Legal content:** begins with an evidence-linked `unpublished_draft`, not a quarantined retrieval candidate, and may later move through review and publication decisions. A confirmed impact creates a new unpublished version; history is never overwritten. Whether `stale` is a content state, a derived freshness/eligibility condition, or both remains unresolved below.
5. **Publication/freshness eligibility:** computed for one immutable version and one `as_of` time from publication decision, mandatory gates, review freshness, holds, and withdrawals. It is not stored as a universal status.

Within manifest v1, `observed_not_retained` means specifically an HTTP-200 body observation whose exact bytes were observed but not placed in durable custody. A URL, response validator, archive reference, or failed request may still be retrieval evidence, but it is not this outcome. Evidence without durably retrievable, integrity-verified exact bytes cannot be the sole evidentiary basis of a Tranche 2B authority draft.

## Approved Tranche 2A trust boundary

- Distinct retrieval events are never collapsed, even if content-addressed storage deduplicates identical bytes.
- A retained retrieval artifact requires durably retrievable exact bytes plus the hash algorithm and byte-layer definition, byte length, capture time, original requested location, terminal last-attempted location, response-resolved location, relevant response metadata and collector version. A retained derived artifact instead requires exact processing-run/output lineage. For manifest v1, `retrieved_body` is the exact GET response-body octets after HTTP transfer framing and before content-coding decompression; observed Content-Encoding is recorded and decoding is a separate processing run. A hash alone is not a reproducible artifact.
- Processing runs and derived outputs link to the exact artifact and separately identify method, processor/configuration versions, permitted output role and derived hashes.
- Substantive research enters through deterministic, schema-versioned, idempotent manifests or import bundles rather than schema migrations. The generated SQLite database is not durable under this repository's current workflow; this does not imply that SQLite is inherently incapable of being an authoritative store.
- Creating a 2B draft references precise supporting or conflicting evidence. The link provides traceability, not proof, sufficiency or verification.
- SQLite principal fields provide attribution, not authorization. Before automation operates, it requires a separate staging store or fixed-function trusted importer with no write access to 2B, review or publication surfaces.
- Retrieved documents and extracted text are hostile inputs, including possible prompt-injection content. Fetching and parsing require HTTPS/SSRF and redirect protection, size/time/decompression limits, isolated resource-bounded parsing, disabled active content and external entities, and secret/header redaction.
- Logical evidence history is append-only or correction-safe. Controlled quarantine, access restriction or legally required artifact removal records an auditable tombstone rather than silently erasing custody history.
- Tranche 2A cannot establish authoritative issuer or jurisdiction, officiality, document identity, currency, consolidation, binding force, legal status/effect, verification, review or publication, and cannot feed public APIs, exports, search or the frontend.

## Approved Decision 7 custody and import contract

The pilot preserves two distinct durable things: a version-controlled manifest describing what was captured and the exact bytes to which it refers. Immutable, schema-versioned Git manifests form the canonical pilot intake ledger. Each retained artifact is identified by SHA-256 over a precisely named stored byte layer, and its identity is independent of the backend that holds it.

For the initial three-to-five-document pilot, Git may hold exact artifact bytes only after an explicit determination that they are small, non-sensitive, permitted for repository redistribution and suitable for effectively permanent retention in clones and Git history. Restricted, revocable, uncertain-rights or larger non-personal artifacts require an approved durable content-addressed store. Manifest v1 rejects every personal-data-bearing artifact before custody is considered; restricted custody cannot override that rule. A URL, ETag, archive link or hash without durably retrievable, integrity-verified bytes creates no artifact identity. Only an HTTP-200 body whose bytes were actually observed but not retained uses the `observed_not_retained` outcome, and it cannot be the sole evidentiary basis of a Tranche 2B authority draft. Git supplies reviewable version history but is not a tamper-proof audit log.

Each evidence bundle must be able to declare its format version and stable identity; attributed submitter; original requested, terminal last-attempted and response-resolved locations plus redirect history; retrieval time and outcome; GET representation profile, exact conditional validator/basis, supported negotiation values, Content-Encoding and Vary; an allowlist of non-secret response metadata; collector identity/version and capture method; artifact byte layer, SHA-256, byte length, detected media type, custody class and backend-independent reference; separate processing/configuration runs and derived-output hashes; unverified candidates; and correction, supersession or tombstone links. Manifest v1 accepts full response representations only at HTTP 200, rejects 206 and every other 2xx, restricts redirects to 301/302/303/307/308, and treats 304 as strict conditional reuse. A redirected or conditional network failure retains its attempted-request context without inventing a resolved response. Manifests must contain no credentials, cookies, authorization headers, signed download URLs or personal data. Commit authorship does not substitute for Atlas attribution.

The v1 HTTP profile rejects C0 controls and DEL in stored request/response field values. ETags use a deliberately narrow ASCII quoted-entity-tag profile with an optional uppercase `W/`; HTTP dates are canonical IMF-fixdate with calendar and weekday validation; Content-Encoding is a lowercase ordered token list; and Vary is a lowercase, sorted, unique token set or `*`. A 304 basis is valid only for the same original requested location, terminal location, method/profile and supported `Accept`/`Accept-Encoding`/`Accept-Language` representation dimensions, with the exact validator value. SQLite supplies defensive row-local shape checks; complete canonicalization, redirect-chain, conditional-basis and cross-row semantics belong to manifest validation and importer preflight.

Manifest serialization and hashing must be canonical and versioned, with independent micro-vectors, one complete-manifest canonical string/hash and every-leaf digest-sensitivity coverage rather than expected values generated by the implementation under test. Raw artifact hashing covers the exact stored byte sequence without text or filename normalization; normalized text, content-decoded bodies and extraction outputs are separate derived artifacts with acyclic lineage grounded in a retained retrieval. A same-bundle run may consume or reuse a derived artifact only after a lower-ordinal grounded run has supplied its production edge; timestamps and artifact-declaration order do not establish grounding. Processing methods, permitted outputs and configuration requirements are closed in the approved v1 contract: in particular, `content_decoding` takes `retrieved_body`, pins the observed ordered Content-Encoding value as its sole configuration property, and emits exactly one `decoded_body` on success. Structural import must be network-free, deterministic, transactional, idempotent, fail closed on conflicting identities, unavailable required artifacts or hash/length mismatch, and reproduce the same canonical row-level digests from the same migrations, bundles and available artifacts. Complete semantic preflight precedes `BEGIN`. The declared manifest path is bound to the actual reviewed-root-relative input, and every persisted field and relationship is compared inside the write transaction before commit and again before returning no-op. Receipt sequence, not local import time, is the knowledge-order boundary. Technical bundle acceptance is never legal verification or publication.

Logical observations remain append-only, but approved custody actions may restrict or remove bytes. The Tranche 2A custody tombstone records artifact/copy identity, reason, attribution and time; it is not itself an authorization. Before real byte removal, a later operational/governance record must preserve the removal authority, affected dependencies and execution result without retaining prohibited content. Dependent authority drafts then become unsupported or held until replacement evidence exists. Backend selection must provide the backup, restore, access-control and integrity properties appropriate to its custody class. A pilot using repository-held artifacts requires a fresh-clone, network-free rebuild test. Production monitoring additionally requires the durable operational controls reserved for its later tranche.

## Approved Decision 8 logical evidence boundaries

Tranche 2A separates six logical records without requiring exactly six physical tables. The chain describes a successful evidence path; failed or not-retained attempts stop earlier. The approved exact nine-table design, manifest contract, and enforcement allocation are documented in [Tranche 2A source-evidence quarantine](schema-v2-tranche-2a.md). Migration 005 implements the empty physical tables. The D9.2 candidate implements manifest intake and disposable candidate verification for synthetic tests only; operational importing, adapters, activation, and enforcement remain unimplemented:

1. **Retrieval location:** a public, credential-free HTTPS address that may be requested. It asserts no officiality, issuer, jurisdiction or legal-document identity.
2. **Retrieval event:** one immutable GET acquisition attempt with an original requested location, terminal last-attempted location, optional response-resolved location, ordered redirect evidence, time, collector version, closed representation/negotiation profile, allowlisted response metadata, exact conditional validator/basis and terminal outcome. Distinct attempts are never deduplicated. Redirected and conditional network failures retain attempted-request context without a resolved response. A `not_modified` result is exactly HTTP 304, creates no new artifact, and identifies a representation-compatible retained HTTP-200 basis.
3. **Artifact identity:** one exact stored byte sequence identified by its defined byte layer, SHA-256 and byte length. Retrieval metadata such as ETag, Last-Modified and declared media type is not part of byte identity. Both raw and derived bytes use this identity mechanism, while derivation lineage distinguishes them.
4. **Artifact custody:** append-only or correction-safe history of available, restricted, relocated, quarantined or tombstoned copies at secret-free backend references. Occurrence time and receipt-sequence knowledge order remain separate, so later-discovered historical events do not rewrite an earlier acceptance boundary. Current retrievability is derived. Relocation changes backend or custody class; tombstoning never rewrites artifact identity or retrieval history, and deduplication never broadens access.
5. **Processing run:** one immutable content-decoding, parser, OCR, normalization or expressly identified human-transcription attempt against one retained artifact, with processor/configuration identity and a separate outcome. It produces only the output kinds permitted by its method; successful content decoding produces exactly one decoded body and pins the observed content-coding configuration. Every run chain is acyclic and ultimately grounded in a retained retrieval; a run cannot consume an artifact it produces, and same-bundle dependency/reuse is permitted only after a lower-ordinal grounded producer. Failure never changes the retrieval outcome.
6. **Unverified candidate occurrence:** one immutable occurrence of typed extracted metadata claims linked to its processing run, relevant output and precise locator or span. Manifest v1 permits only byte and text spans. Preserve observed and normalized suggestions separately. Confidence is processing metadata, not legal confidence. Conflicting or repeated candidates remain distinct; correction or withdrawal creates linked later history rather than mutation. Historical reads bind both `recorded_as_of` and `known_through_bundle_sequence`: a raw correction-chain leaf may be a withdrawal for audit, while the active projection excludes that leaf rather than revealing its superseded predecessor.

The versioned manifest is the transport and provenance envelope, not a seventh legal-evidence concept. Every future evidence row directly retains deterministic receipt/bundle provenance. Bootstrap principal provenance instead remains in the accepted sequence-1 manifest because Tranche 1A principal rows have no receipt FK. Migration 005 provides one technical receipt table for sequence, idempotency and provenance; it is not legal evidence and does not change the approved logical boundaries. The approved contract chooses a one-time sequence-1 `principal_bootstrap` envelope bound to trusted runtime identities. D9.2 proves its synthetic disposable projection but does not activate or execute the real ceremony. Direct unaudited manual edits are prohibited: manual transcription must be an attributed processing method, while human legal drafting remains in Tranche 2B.

The Decision 8 `unverified candidate` is a hostile extracted metadata-claim occurrence—for example, a suggested title, issuer, language, jurisdiction, date, identifier, document type, officiality or purported legal-status claim. Every such value remains unverified. Authoritative issuer/jurisdiction, officiality, legal identity/status/effect and publication are unreachable in Tranche 2A; allowing a candidate to suggest those strings does not model them as legal facts. The occurrence is distinct from the later freshness-monitoring `change candidate`, which concerns a possible change affecting previously modeled legal content.

## Version-specific review gates

Every approval targets the exact immutable content version and its hash. A content change creates a new version and invalidates only approvals affected by that version.

Reviews normally target exactly one immutable version. If a grouped review is later supported for workflow convenience, the junction must record a separate result, limitations, and next-review date for every target; no group-level result may imply approval of all targets.

Default gates are researcher/author preparation; independent official-source verification; independent substantive legal review; qualified local-jurisdiction review for national material; translation review when a non-authoritative translation is used; editorial/data-quality/accessibility review; and an independent publication decision.

At minimum, author, substantive legal reviewer, and publisher are different human principals. Automated agents cannot approve, satisfy a human gate, or publish. Review records include principal, role, qualifications, qualification expiry, conflicts of interest, recusals, exact version/hash, result, limitations, decision time, and next review due.

The later governance slice must enforce all of the following:

- no self-grant, self-verification, or self-publication;
- authority-draft author differs from official-source verifier;
- author differs from substantive legal reviewer and publisher;
- substantive legal reviewer differs from publisher;
- qualification scope is immutable and sealed with its assertion;
- language, jurisdiction, subject-area, and coverage matching are explicit and fail closed;
- policy seals validate the complete required-gate set and canonical payload hash;
- policy adoption is attributable to a qualified human—never anonymous or a service principal;
- mandatory gates are non-waivable and approvals count distinct eligible humans;
- active policy versions cannot overlap, reopen, or resurrect unexpectedly.

## Fail-closed public eligibility

A proposition version is public only when an effective decision explicitly says `publish_validated` or `publish_with_warning`; a current qualifying review covers that exact version; authoritative provisions have a future reviewed official-source determination covering the exact evidence-linked authority representation; atomicity, source mapping, required translation review, and required local validation are resolved; and no later blocking review, withdrawal, or confirmed material-change event applies.

Missing, rejected, stale, expired, superseded, or recused mandatory reviews block publication. `publish_with_warning` requires machine-readable warning codes and human-readable text and cannot bypass authoritative-source, atomicity, substantive-review, local-validation, translation-review, or freshness gates. Editing or confirmed material source change restarts affected gates. Emergency withdrawal removes eligibility immediately without deleting history. Ineligible list records are omitted and public detail routes return 404.

## Freshness monitor

Two monitor classes are required:

- Exact-source monitors check known documents, metadata, consolidated versions, representations, and languages.
- Discovery monitors look for amendments, omnibus instruments, corrigenda, repeals, implementing measures, cases, and guidance, including changes that leave the original document URL unchanged.

Append-only monitoring records capture monitor policy and source coverage; every run and retrieval outcome; original requested, terminal last-attempted and response-resolved URL, HTTP status, ETag, Last-Modified, media type and retrieval time; exact retained-artifact identity; separate linked parser/normalizer runs and derived hashes; detected-change candidate; concrete affected-instrument, provision, proposition-version, national-comparison and training-projection junctions; triage decision; escalation; notification attempt; and closure. Concrete target junctions are required instead of unenforceable polymorphic IDs.

## Change handling without automated legal conclusions

A detected change creates or reuses a deduplicated review candidate, preserves before/after observations and a diff, identifies potentially affected records, marks them `change_pending_review` or applies a risk-based publication hold, and notifies reviewers. Monitoring never rewrites legal text, interpretation, normative effect, applicability, dates, relationships, legal events, publication decisions, or public content.

A human reviewer classifies the candidate as `no_material_impact`, `formatting_or_parser_change`, `correction_or_corrigendum`, `amendment_or_repeal`, `new_implementing_or_interpretive_authority`, `false_positive`, or `uncertain_requires_escalation`. Confirmed impact creates new unpublished source/legal/proposition versions and restarts affected gates.

Retrieval failures are retrieval outcomes; parser failures are separate parser-run outcomes against retained artifacts. Neither is a legal change. They update monitoring health and may create staleness or escalation but do not alter recorded law.

Raw-byte and layout-only differences are always preserved as evidence differences. Whether every such difference creates a legal-review candidate is deferred to a later candidate-creation policy. Normalized-text equality, parser version, risk policy and human triage will determine escalation and whether a hold is warranted.

## Deterministic hold matrix

| Condition | Existing version | Required signal | Who may clear it |
|---|---|---|---|
| Retrieval failure or linked parser-run failure before due date | Remains public | Monitoring-health degradation; no legal change | Successful later run; operator may close infrastructure incident |
| Monitor run overdue | Remains public with freshness warning until risk-policy grace expires; then withheld | `monitor_overdue` with last attempt/success | Successful run plus automated health recomputation; human required if hold was escalated |
| Human legal review overdue/expired | Withheld; warning cannot bypass | `human_review_stale` | New qualified independent reviewer approval |
| Detected change awaiting triage | Risk policy decides warning or temporary hold; high-risk/source-loss cases withheld | `change_pending_review` | Qualified human triager records a supported classification |
| Confirmed material change | Existing affected version withheld; new version starts unpublished | `material_change_confirmed` | Full affected review gates plus independent publisher on new version |
| Emergency withdrawal | Immediately withheld | `emergency_withdrawal` | Authorized independent publisher/legal governance principal through a new decision; history retained |

No automated principal clears a legal/publication hold. Automated recovery may clear only an infrastructure-health warning that policy explicitly defines as non-legal and that never invalidated human review.

## Transparent freshness display

Expose separately:

- law applicable as of;
- source last attempted;
- source last successfully retrieved;
- last human legal verification;
- next review due;
- monitoring coverage and health;
- pending-change or stale-warning state.

The defensible product claim is: “Monitored against identified official sources and verified as of the displayed date.” Never claim the atlas is guaranteed always current.

## Scheduling and operational boundary

Intervals are configurable by volatility, authority type, jurisdiction and risk. Pilot defaults are daily discovery-feed checks, weekly exact-source metadata checks, monthly forced full retrieval, and human recertification every 90–365 days.

The pilot may use a candidate-only GitHub Action with scheduled and manual triggers. It may store workflow diagnostics and open a deduplicated issue or draft PR, but cannot change canonical legal data. Schema migrations remain schema-only; substantive research must come from structurally validated deterministic import bundles under Decision 7. Because this repository's generated SQLite database is ignored, it is not durable production history. A hosted durable store plus an independent missed-run heartbeat is required before monitoring may be described as operational. Decision 7 approves the storage-independent pilot contract but does not select or operate a production provider. Approved Decision 9 narrows the pre-monitoring pilot to reviewed Git manifests plus a restricted local content-addressed store and independently verified backup; it explicitly does not make that single-host profile operational monitoring or select a hosted provider.

## Carried unresolved questions

- Reconcile `parser_only` with `formatting_or_parser_change` when the change-candidate vocabulary is approved.
- Decide whether `stale` is a legal-content state, a derived freshness/eligibility condition, or both without conflating publication history and current public eligibility.
- Define the policy that turns a recorded byte or layout difference into a legal-review candidate or publication hold.
- Using D9.0.1 as the applicable approved contract revision, approve or revise the synthetic D9.2 accepted-bundle verifier candidate, then implement and security-review the remaining operational Decision 9 sequence: real ceremony authorization, authenticated-principal activation, D9.1/D9.2 process integration, local custody adapter, clearance procedure, retention/tombstone controls, backup/restore tests and durable operational audit before accepting any evidence. Any D9.3 durability-receipt contract extension must be separately versioned, reviewed, and approved; it must not silently alter an approved D9.0 revision.
- Define a deletion-aware restore protocol before legally destroyed bytes can be absent from a fresh rebuild; a hash and tombstone alone do not recreate an artifact.

## Future acceptance tests

- Extraction alone cannot publish.
- Authors cannot approve or publish their own work; agents cannot satisfy human gates.
- National content cannot publish without current qualified local validation.
- Edits invalidate approvals for the affected version only.
- Discovery finds an amendment even when the original URL is unchanged.
- Network failures do not alter recorded law.
- Overdue monitoring creates visible staleness.
- Automated checks cannot create legal events or publication decisions.
- Historical versions remain retrievable.
- Every public version exposes sources, applicable-as-of date, human verification date, and freshness state.
- A pristine clone verifies and rebuilds repository-held pilot evidence without network access.
- Reimport is a no-op only after every persisted column and relationship in all nine migration-005 tables is resolved back to stable manifest codes and compared immediately before the return; mutations to HTTP metadata/outcome/time, custody, configuration, candidate content or any edge fail closed, as do missing bytes, digest/length mismatch, stable-identity conflict or partial import.
- Identical bytes may deduplicate storage without collapsing retrieval events, and backend relocation does not change artifact identity.
- Forbidden secrets, obvious credential configuration keys, transient signed locations and all personal-data-bearing artifacts cannot enter v1 manifests; repository-ineligible artifacts are rejected.
- Any external artifact backend passes integrity, access-control, backup/restore and tombstone tests before use.
- Retrieval locations cannot contain credentials or transient signed access material and do not imply authority identity.
- Successful retrieval followed by processing failure preserves the successful retrieval and exact artifact; a retry is a new processing run. The closed method/output matrix and `content_decoding` configuration are enforced.
- Current artifact availability is derived from custody history, and copy removal never rewrites byte identity or acquisition history.
- Every candidate occurrence resolves to exact processing and evidence lineage; repeated or conflicting occurrences retain separate provenance.
- Correction/withdrawal chains are append-only, cycle-free and deterministic, and never alter captured bytes.
- Processing lineage is acyclic and retrieval-grounded; same-run self-origin and multi-run cycles fail even when their timestamps are equal. Within one bundle, a run can consume or reuse derived bytes only after a lower-ordinal grounded producer.
- Custody projection accepts an event-time bound and a receipt-sequence knowledge bound; later-discovered historical restrictions do not retroactively rewrite earlier run acceptance.
- GET representation evidence preserves original requested, terminal last-attempted and response-resolved locations; exact pre-content-decoding HTTP-200 body bytes; canonical negotiation/ETag/IMF-fixdate/Content-Encoding/Vary metadata; and the exact validator/basis for every strict 304. Redirected and conditional network failures remain distinguishable, and 206/other 2xx are rejected.
- Independent micro- and complete-manifest golden vectors plus every-leaf mutation checks pin canonical bundle hashing; only the top-level digest field is excluded.
- All semantic checks—including every collision, chronology, attribution, root, custody and graph rule—complete before the importer begins a transaction, while the database independently rejects the row-local and cross-row subset expressed in its constraints/triggers.
- The standalone adversarial validator verifies that migration 005 is byte-identical to the approved DDL, applies a 001–004 baseline plus that exact body in fresh and at-004 upgrade paths, preserves all 13 legacy row-level digests and complete pre-005 schema definitions, inspects exact physical schema details, and runs integrity/foreign-key checks without claiming that its simulated importer is production code. Permanent migration tests separately exercise fresh installation through production 005, exact checksum recording, at-004 upgrade, no-op replay, empty-table inventory, rollback, and legacy application/search parity.

## Future implementation tranches

7. Freshness evidence and candidate-review workflow.
8. Crosswalk and auditable backfill.
9. API v2 and parity.
10. Operational scheduler, durable storage, alerts, and missed-run heartbeat — separately approved.
11. Legacy retirement — separately approved.
