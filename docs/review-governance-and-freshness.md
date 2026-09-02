# Review governance and freshness

Status: approved sixth architectural requirement. This document specifies future domain behavior; Tranche 0 does not implement monitoring or review-domain tables.

## Trust boundary and record states

Automated extraction may write only to quarantined ingestion candidates and immutable source observations. It cannot create or modify authoritative proposition versions or publication decisions. A researcher may promote verified material into a new unpublished draft. `draft`, `reviewed`, `published`, `stale`, and `withdrawn` are distinct, auditable states; editing published or reviewed content always creates a new unpublished immutable version.

The pipeline is:

```text
source observation -> quarantined candidate -> researcher draft -> gated reviews -> publication decision
```

These are four separate state machines:

1. **Observation outcome:** `attempted -> retrieved | not_modified | network_failed | http_failed | parse_failed`. It records retrieval facts only.
2. **Change candidate:** `detected -> deduplicated -> awaiting_triage -> no_material_impact | parser_only | false_positive | confirmed_material | uncertain_escalated -> closed`. Only a human triage decision moves beyond `awaiting_triage`.
3. **Legal content:** `quarantined -> unpublished_draft -> reviewed -> published -> stale | withdrawn`. A confirmed impact creates a new unpublished version; history is never overwritten.
4. **Publication/freshness eligibility:** computed for one immutable version and one `as_of` time from publication decision, mandatory gates, review freshness, holds, and withdrawals. It is not stored as a universal status.

## Version-specific review gates

Every approval targets the exact immutable content version and its hash. A content change creates a new version and invalidates only approvals affected by that version.

Reviews normally target exactly one immutable version. If a grouped review is later supported for workflow convenience, the junction must record a separate result, limitations, and next-review date for every target; no group-level result may imply approval of all targets.

Default gates are researcher/author preparation; independent official-source verification; independent substantive legal review; qualified local-jurisdiction review for national material; translation review when a non-authoritative translation is used; editorial/data-quality/accessibility review; and an independent publication decision.

At minimum, author, substantive legal reviewer, and publisher are different human principals. Automated agents cannot approve, satisfy a human gate, or publish. Review records include principal, role, qualifications, qualification expiry, conflicts of interest, recusals, exact version/hash, result, limitations, decision time, and next review due.

## Fail-closed public eligibility

A proposition version is public only when an effective decision explicitly says `publish_validated` or `publish_with_warning`; a current qualifying review covers that exact version; authoritative provisions have official immutable source-version support; atomicity, source mapping, required translation review, and required local validation are resolved; and no later blocking review, withdrawal, or confirmed material-change event applies.

Missing, rejected, stale, expired, superseded, or recused mandatory reviews block publication. `publish_with_warning` requires machine-readable warning codes and human-readable text and cannot bypass authoritative-source, atomicity, substantive-review, local-validation, translation-review, or freshness gates. Editing or confirmed material source change restarts affected gates. Emergency withdrawal removes eligibility immediately without deleting history. Ineligible list records are omitted and public detail routes return 404.

## Freshness monitor

Two monitor classes are required:

- Exact-source monitors check known documents, metadata, consolidated versions, representations, and languages.
- Discovery monitors look for amendments, omnibus instruments, corrigenda, repeals, implementing measures, cases, and guidance, including changes that leave the original document URL unchanged.

Append-only monitoring records capture monitor policy and source coverage; every run and request outcome; requested/final URL, HTTP status, ETag, Last-Modified, media type and retrieval time; raw-content and normalized-text hashes; parser/normalizer version; immutable observation or archived-artifact reference; detected-change candidate; concrete affected-instrument, provision, proposition-version, national-comparison and training-projection junctions; triage decision; escalation; notification attempt; and closure. Concrete target junctions are required instead of unenforceable polymorphic IDs.

## Change handling without automated legal conclusions

A detected change creates or reuses a deduplicated review candidate, preserves before/after observations and a diff, identifies potentially affected records, marks them `change_pending_review` or applies a risk-based publication hold, and notifies reviewers. Monitoring never rewrites legal text, interpretation, normative effect, applicability, dates, relationships, legal events, publication decisions, or public content.

A human reviewer classifies the candidate as `no_material_impact`, `formatting_or_parser_change`, `correction_or_corrigendum`, `amendment_or_repeal`, `new_implementing_or_interpretive_authority`, `false_positive`, or `uncertain_requires_escalation`. Confirmed impact creates new unpublished source/legal/proposition versions and restarts affected gates.

Network failures and parser failures are observations, not legal changes. They update monitoring health and may create staleness/escalation but do not alter recorded law.

Raw-byte or layout-only differences create a candidate but do not automatically block publication. Normalized-text equality, parser version, and human triage determine whether a hold is warranted.

## Deterministic hold matrix

| Condition | Existing version | Required signal | Who may clear it |
|---|---|---|---|
| Monitor request/parser failure before due date | Remains public | Monitoring-health degradation; no legal change | Successful later run; operator may close infrastructure incident |
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

The pilot may use a candidate-only GitHub Action with scheduled and manual triggers. It may store workflow diagnostics and open a deduplicated issue or draft PR, but cannot change canonical legal data. Because the generated SQLite database is ignored, workflow artifacts are not durable production history. A hosted durable store plus an independent missed-run heartbeat is required before monitoring may be described as operational.

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

## Future implementation tranches

7. Freshness evidence and candidate-review workflow.
8. Crosswalk and auditable backfill.
9. API v2 and parity.
10. Operational scheduler, durable storage, alerts, and missed-run heartbeat — separately approved.
11. Legacy retirement — separately approved.
