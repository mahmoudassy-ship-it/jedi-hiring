# First evidence pilot — verification report template

Status: template only. Store the completed, signed report in the protected audit store; commit only an approved content-free summary if separately authorized.

## Report identity

- Report ID/version/digest:
- Operation type: `bootstrap` / `one_document`
- Operation, bundle and receipt stable IDs:
- Started/completed at (trusted UTC):
- Approved authorization and decision-register references (bootstrap, or separate pre-fetch and post-capture/import records):
- Repository commit, release/build and dependency-lock digests:
- Environment inventory and go/no-go checklist digests:
- Authors/verifiers/approvers: protected binding references and roles only:

## Frozen boundary verification

| Boundary | Expected fingerprint/hash | Observed | Validator/evidence | Result |
|---|---|---|---|---|
| D9.0.1 catalog/classification/handles/scopes |  |  |  |  |
| D9.3.0 |  |  |  |  |
| D9 recovery v1.3 selected route |  |  |  |  |
| D9.4.0 |  |  |  |  |
| D9.5.0 |  |  |  |  |
| Migrations 001–005 |  |  |  |  |

Record v1.2 only as immutable historical/read-only compatibility. Do not conflate source-state identity with journal-tip receipt identity.

## Environment and trust evidence

- Host/boot/kernel and required primitive result:
- Exact active profile, binding, extension/roster and revocation heads:
- Executable/dependency/endpoint/peer verification:
- Trusted clock sources, offset, health and discontinuity result:
- Protected root/mount/device/inode/owner/mode inventory:
- Credential delivery/rotation test (references only, never values):
- Operation lock, nonce/replay and handle-scope result:
- Monitoring and missed-run heartbeat result:

## Bundle and source evidence

- Reviewed manifest relative path and opened-file digest:
- Canonical manifest and seal digests:
- Submitter/handoff/collector/processor protected bindings:
- Requested, redirect, last-attempted and resolved location stable IDs:
- Frozen request method/profile; exact Accept, Accept-Language and Accept-Encoding; cookie/credential absence:
- Observed Vary, Content-Encoding, content type/length, ETag and Last-Modified:
- Retrieval time/outcome/status and allowlisted metadata digest:
- Artifact byte layer, SHA-256, byte length and media observation:
- Collector and operational safety scanner/parser versions/configuration and outcomes (not Atlas processing runs):
- Rights/custody, repository eligibility, privacy and security decision references:
- Limitations, conflicts and negative findings:

For bootstrap, mark document fields `not applicable` and prove zero artifacts. Do not label an observed issuer, identifier, URL or artifact as legally authoritative.

## State and projection verification

| Evidence | Before | Candidate | Promoted | No-op replay | Result |
|---|---|---|---|---|---|
| Canonical DB generation/hash |  |  |  |  |  |
| Migration ledger/integrity/FK checks |  |  |  |  |  |
| Complete legacy schema/digests |  |  |  |  |  |
| All 13 Atlas table counts/digests |  |  |  |  |  |
| Bundle receipt projection |  |  |  |  |  |
| Every persisted manifest column/relation |  |  |  |  |  |
| Journal/source/checkpoint/receipt heads |  |  |  |  |  |
| Primary custody inventory/receipts |  |  |  |  |  |
| Restriction/hold/tombstone projection |  |  |  |  |  |

Attach machine-readable, content-free result digests. The identical replay must produce zero changes across every row, relationship, receipt, journal head and custody object.

## Backup and reconstruction

- Prior-backup authorization, exact pre-promotion generation, copy/backend/manifest and durability receipt ID:
- Final-backup authorization, exact promoted generation, copy/backend/manifest and durability receipt ID:
- Independent failure-domain/admin/key evidence:
- Exact prior/final copy hashes, lengths and coverage verification:
- Restore authorization and restriction evaluation:
- Inaccessible staging generation and inventory digest:
- Reconstructed DB/artifact/journal/receipt projection comparison:
- Atomic promotion: `not performed` for the disposable drill:
- Drill cleanup authorization/result:
- RPO/RTO measured boundaries and outcome:

## Incidents and limitations

- Response loss, retries, failures, orphans, alerts or recovery classifications:
- Containment and current holds:
- Unresolved ambiguity or unavailable evidence:
- Known scope limitations:
- Required follow-up and deadline:

Any unresolved material item makes the report `failed` or `reconciliation_required`, never pass-with-silence.

## Final assertions

Select one: `technical_success` / `technical_failure` / `reconciliation_required`.

The signatories assert only that the bounded technical facts above were checked against the approved contracts and evidence. They do **not** assert officiality, legal identity, currency, binding force, legal effect, evidence acceptance, substantive legal verification, compliance, publication eligibility, complete erasure or fitness for Tranche 2B.

- Independent technical verifier:
- Operational witness:
- Security authority:
- Recovery authority (backup/drill only):
- Rights/privacy roles (document bundle only):
- Governance acceptance decision and date:
