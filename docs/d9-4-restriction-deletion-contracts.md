# D9.4.0 restriction, security, and deletion-control contracts

Status: **design-only proposal awaiting approval**. The fingerprinted catalog uses the permanent lifecycle-neutral value `design_only_contract_freeze`; approval, if granted, will be recorded externally and will not change the contract root. This proposal creates no executable restriction service, clearance process, deletion capability, custody effect, credential, Atlas row, evidence import, legal conclusion, API, export, search result, or frontend behavior.

## Plain-language decision

D9.4 should be split into two separately reviewed milestones:

1. **D9.4.0 — contract/design freeze:** this document, ten top-level machine contracts, closed registries, synthetic fixtures, fixed hashes, and an offline validator.
2. **D9.4.1 — synthetic, unactivated implementation:** a later implementation may enforce these controls against synthetic bytes and disposable protected stores only after D9.4.0 approval and a fresh audit of launcher privileges.

Restriction is an immediate fail-closed access decision. Deletion is a different, slower process requiring scoped human authorization, confirmed access shutdown, a logical tombstone, exact inventory, a separate executor, and independent verification. D9.4 can describe and later verify deletion of the approved primary CAS name only. It cannot claim that backups, replicas, temporary files, open descriptors, storage media, or unknown copies have been erased. D9.5 alone may define and implement backup deletion, restore, and deletion-aware reconstruction.

## Audit result and frozen-boundary compatibility

The audit covered approved D9.0.1, D9.3.0, the approved synthetic D9.3.1 implementation, Decision 9, migrations 001–005, and their tests. No frozen-contract edit is required for D9.4.0:

- D9.3.0 explicitly defers restriction, tombstoning, destructive-policy execution, and primary-copy orphan cleanup to D9.4.
- D9.3.0 already separates semantic `event_at` from broker-controlled knowledge order and requires classification-only recovery.
- D9.3.1 deliberately implements no restriction, deletion, relocation, backup, or recovery action.
- D9.0.1 clearances and custody capabilities can be referenced exactly without being reinterpreted or mutated.
- D9.5 backup receipt references remain typed but operationally unavailable.

One compatibility gap is explicit rather than hidden: the frozen D9.3.0 journal broker cannot carry D9.4 record formats. D9.4.0 therefore defines a separate, versioned, global append-receipt contract and namespace. It does not reinterpret or mutate the D9.3.0 journal. D9.4.1 would need a new protected broker implementing this exact ledger contract before any control could have effect.

The current D9.0.1 seven operation-handle partitions do not grant a destructive administrative surface. That is correct for the approved importer. A future D9.4.1 implementation will require a separately reviewed administrative launcher/profile and exact restricted handles or an equivalently isolated control service. It must not widen the frozen importer partitions in place. This is an activation prerequisite, not a blocker to a separate design-only contract root.

## Trust boundary

```mermaid
flowchart LR
  H[Authenticated human requester] --> CR[Protected control-record broker]
  A[Independent human authorities] --> CR
  S[Scanner/security signal] -->|may impose restriction only| CR
  CR -->|deny new seals and opens| CA[Custody adapter]
  CR -->|revoke unconsumed grants| GR[Capability store]
  CR -->|terminate and confirm receivers| L[Trusted launcher]
  CR -->|exact authorized scope only| E[Deletion executor]
  E -->|primary-copy observation| V[Independent verifier]
  V --> R[Bounded deletion receipt]
  CR --> J[Protected journal broker]
  R --> J
  CR --> B[D9.5 coordination directives]
  B -. no execution before D9.5 .-> BK[(Backup domain)]
  CA --> C[(Restricted primary CAS)]
  C -. physical custody only .-> Q[Accepted evidence]
  Q -. later human legal gates .-> LA[Verified legal authority]
```

The control broker, custody adapter, launcher, deletion executor, independent verifier, journal broker, and future backup operator are distinct runtime roles. A caller-supplied role, principal code, record digest, or reason category is never authentication or authorization.

## Contract inventory and versioning

The new root is `docs/schema/d9-4-0/`. It contains 18 files: eleven schemas (one shared and ten top-level), three registries, one catalog, and three synthetic fixture files. The validator is outside the fingerprinted root.

| File | Contract or role |
|---|---|
| `common-v1.schema.json` | Closed actor, subject, reason, human-approval, hash-chain, and knowledge-boundary definitions. |
| `operational-profile-v1.schema.json` | Unactivated profile that pins D9.0.1, D9.3.0, the approved D9.3.1 tree, limits, precedence, deletion scope, and D9.5 unreachability. |
| `authority-roster-v1.schema.json` | Unactivated, effective-dated mapping from one exact D9.0.1 identity-binding generation to closed D9.4 semantic roles; it is not authentication or a legal qualification. |
| `authority-roster-adoption-v1.schema.json` | Two independently authenticated external-human decisions adopting the exact roster generation; roster members cannot adopt their own authority. |
| `custody-control-record-v1.schema.json` | Append-only restrictions, holds, clearance revocations, deletion requests/decisions, tombstones, corrections, withdrawals, releases, and explicit propagation edges. |
| `access-revocation-record-v1.schema.json` | Capability revocation and already-issued descriptor termination lifecycle. |
| `deletion-execution-record-v1.schema.json` | Primary-copy inventory, unlink attempt, verification, failure, and reconciliation observations. |
| `deletion-receipt-v1.schema.json` | Bounded receipt that can assert only an observed primary-namespace result. |
| `backup-coordination-record-v1.schema.json` | Restriction/tombstone/restore directives whose execution is unreachable until D9.5. |
| `recovery-assessment-v1.schema.json` | Classification-only crash assessment with no recovery authority or action. |
| `journal-append-receipt-v1.schema.json` | Separate D9.4 protected-ledger acknowledgement binding the exact target record, global sequence, semantic actor, persistence actor, operation, nonce, and times. |
| `classifications-v1.json` | Total subject, reason, actor, separation, precedence, propagation, access, deletion, backup, crash, and fail-closed matrices. |
| `digest-profiles-v1.json` | Canonical JSON, subject identity, self-digest, exact-byte, and protected-store resolver profiles. |
| `field-registry-v1.json` | Producer, consumer, storage, confidentiality, and canonical/operational classification for every top-level field; nested fields inherit deterministically. |
| `contract-catalog-v1.json` | Exact raw hashes, frozen predecessors, migrations, and design-only boundary. |
| `fixtures/*.json` | Synthetic valid/invalid cases and independently fixed canonicalization vectors. |

Any semantic change requires a new versioned contract root or explicit correction lineage, new hashes, review, and approval. Approved D9.0.1 and D9.3.0 files are never edited or aliased.

### Proposal fingerprints

| Surface | SHA-256 |
|---|---|
| Exact catalog file | `7f36ca6922cc92ef32b01b0a5b5e896d78f7a359affd06a2bd943a9b28b6c2bc` |
| Classification semantic record | `f929f22495ebbbc9849b76890ecc5d0eb4ee23cc0b1e2a6d528993c8063f8585` |
| Digest-profile semantic record | `48e7bcb3941630df7e728995f3e48936e591eac3cb874ccb78a1ec77f710da8b` |
| Field-registry semantic record | `bc707e9946b885c48bc6eaab59ddacaed5c8fbeec6739c3c15d097a6e7002991` |
| Subject matrix | `86557dc7eaeb3449ab5db26c93b2dbc125ae4f89c07deaef11e84a549cbbb745` |
| Actor/separation matrix | `882a3523645dc95775ff312d15950102708777842f9f7054a70eba4290c528f0` |
| Restriction/access projection matrix | `ca4b30c5d3463e393193b20f219e81da5b046b4b1ba403b1bfdc72a122e6b752` |
| Deletion lifecycle matrix | `daff0b0e4cc3b1ba4f094a8eb49ea8608d876df6769dab86611bfeebba3081fc` |
| Recovery/backup matrix | `eb5214b374cca1dddb8a7fb76d17b3c645615d6bcc3c4067e98e57b870efbe16` |
| Sorted 18-file contract-root inventory | `9ca5e3099e362c73f0a61616d02b81acc0df3cbd14fd3891b460e82875b4f64e` |

These are proposal anchors, not operational attestations.

## Stable subject identity and propagation

A subject is the canonical SHA-256 of exactly `{subject_kind_code, subject_payload}`. Six closed kinds exist:

| Kind | Identity payload | Meaning boundary |
|---|---|---|
| `artifact` | byte layer, algorithm, SHA-256, byte length | Exact logical bytes only. |
| `custody_copy` | artifact identity, copy code, backend code, backend reference | One physical-copy identity. |
| `evidence_bundle` | exact bundle code, sequence, and digest | One accepted or candidate bundle identity. |
| `processing_output` | bundle, run code, output code, output artifact | One derived-output occurrence. |
| `candidate_occurrence` | bundle, candidate record code, candidate chain code | One unverified occurrence, not a legal fact. |
| `authority_draft` | future draft code and immutable draft-version digest | An opaque future target only; it establishes no authority or legal status. |

Propagation is explicit. A bundle restriction may point to artifacts, copies, outputs, candidates, and future drafts; an artifact restriction may point to its copies and descendants; an output restriction may point to its derived artifact, candidate occurrences, and drafts. A copy restriction affects only that copy. Missing or incomplete required graph resolution fails closed. No generic tag, title match, or inferred source relationship creates a propagation edge.

For access shutdown, an active `propagation_asserted` leaf is the target subject's trigger only when its exact basis is itself an active blocking leaf, the source identity matches that basis, the basis has a strictly earlier protected receipt sequence and persistence time, and the complete protected lineage contains an allowed explicit source-to-target edge. The shutdown deadline starts at the propagation assertion's protected knowledge time. Withdrawal of the assertion or release/staleness of its basis removes it from later active projections without rewriting earlier bounded views.

Historical references remain digest-resolvable in protected audit views. Active projections never resolve tombstoned bytes or silently fall back to another copy. Public projection remains absent.

## Effective time and knowledge order

Every control, access, execution, and backup record carries:

- `effective_at`: asserted occurrence/effect time;
- `recorded_at`: semantic recorder time;
- `persisted_at`: journal/control broker persistence time;
- `receipt_sequence`: broker-controlled knowledge sequence.

The enforced chronology is `effective_at <= recorded_at <= persisted_at`. Each stream—including every D9.5 coordination-directive stream—begins at sequence 1 and is strictly gapless, unforked, no-replace, and hash chained. Persistence time and knowledge sequence strictly increase. A later record may describe an earlier effective event, but it cannot rewrite a query bounded by an earlier `persisted_at` or `receipt_sequence`.

Corrections and withdrawals are new append-only leaves for the same subject, operation, nonce, and stream. A correction identifies the exact current leaf and declares the corrected record kind. In this version it changes only the bounded explanatory `reason_summary` used by the derived projection; it cannot change subject identity, operation, nonce, effective point, authority, or lifecycle kind. A withdrawal marks an eligible nonterminal operational assertion void only for derived projections while preserving every byte. Tombstones and deletion authorizations are deliberately excluded from generic correction/withdrawal targets: a deletion authorization instead has an explicit, append-only revocation transition, including after tombstoning but before unlink, while a tombstone remains active and cannot be undone by a generic correction. Neither operation deletes, overwrites, reuses a code with different bytes, nor authorizes restoration of deleted content. Retrying creates a new operation and nonce.

## Restriction precedence and access eligibility

Access projection evaluates the first matching row:

| Priority | Condition | New or active projection | Deletion |
|---:|---|---|---|
| 10 | Active tombstone | withheld | requires exact still-current authorization and inventory |
| 20 | Active legal/records-retention hold | withheld | blocked |
| 25 | Deletion authorization revoked | withheld | blocked |
| 30 | Active quarantine | withheld | requires separate authorization and inventory |
| 40 | Active restriction or revoked clearance | withheld | requires separate authorization and inventory |
| 50 | Active or unknown descriptor | withheld | blocked |
| 60 | Unknown, gap, fork, collision, or incomplete inventory | withheld | blocked |
| 70 | No active D9.4 control | only eligible for the independent D9.3 clearance check | not requested |

An automated detector may request the bounded `quarantine_imposed` service action through the restricted broker. The `restriction_imposed` action itself remains human-attributed in the closed actor matrix. Automation cannot release a restriction or quarantine, lift a hold, approve deletion, verify deletion, or claim legal significance. A reason category records why review was triggered; it is not a legal conclusion.

New capabilities and opens are denied as soon as the earliest applicable, still-active blocking leaf for that shutdown episode becomes known to the protected control store. Operational cutoff and the 30-second shutdown deadline use protected receipt sequence and `persisted_at`, not a potentially backdated `effective_at`; callers cannot cite a later record to reset the deadline. A released historical restriction does not poison a later episode: access after the release and before a new blocking leaf is evaluated against the new episode trigger. Unconsumed capabilities are explicitly revoked. A restriction cannot revoke an already transferred Unix descriptor by declaration: the launcher must close the sender, terminate and reap the receiver, and record whether descriptor closure is confirmed. Deletion remains blocked while any descriptor is active, unknown, or unsuccessfully terminated.

## Roles, human gates, and separation of duties

| Action | Required human decision | Service attestation/effect | Separation |
|---|---|---|---|
| Immediate restriction | none for a bounded emergency restriction; a human may also impose | detector/custody service may request or persist only | service cannot release or approve deletion |
| Formal hold | one appropriate legal/records, privacy, or security human | broker persists | requester cannot approve own hold where it creates authority |
| Release restriction | one appropriate human | broker persists | automated agent cannot release |
| Release hold | two independent humans in the applicable authority set | broker persists | no self-release |
| Delete request | one human requester | none | request is not authorization |
| Ordinary primary deletion authorization | legal/records authority plus deletion authority | none | both distinct from requester and each other |
| Personal-data-category deletion authorization | privacy authority, legal/records authority, and deletion authority | none | three distinct humans; category is not a privacy-law conclusion |
| Execute primary deletion | prior exact human authorization | deletion-executor service | executor is not requester, approver, verifier, or journal broker |
| Verify primary absence and receipt | none additional | independent verifier service | verifier differs from executor and journal broker |
| Recover or reconcile | separate human recovery authority remains required | classification service may classify only | original executor cannot mint recovery authority |

Human approval records pin the exact subject, scope digest, decision, time, expiry, binding, and principal. Each decision must exist by the control record's semantic recording time, and every mandatory approval must remain valid through the authorization's full exclusive validity interval; an authorization may not outlive an approval. Distinct humans are counted by authenticated binding plus principal mapping, never by caller-supplied text. Approval records themselves are immutable. Expired, mismatched, self-issued, or role-substituted approvals fail closed; any later invalidation must be a separately authorized, append-only authorization-revocation or control event. Active identity-generation, qualification-revocation, and authority-roster evaluation remain D9.4.1 prerequisites rather than an invented approval-revocation resolver in this design.

## Reason categories and holds

The closed pilot categories are `legal_hold`, `records_retention`, `licensing`, `confidentiality`, `personal_data`, `malware`, `disputed_source`, `security_incident`, `deletion_request`, and `other_operational`. They are triage and control categories only. They do not prove legal duty, rights ownership, personal-data status, malware presence, source authenticity, or compliance.

`legal_hold`, `records_retention`, `disputed_source`, and unclassified `other_operational` block physical deletion until an authorized append-only release resolves the exact hold. Licensing, confidentiality, personal-data, malware, and security signals immediately restrict access and may proceed to deletion only through the applicable scoped human gates. Contradictory categories resolve to the more restrictive outcome.

## Deletion lifecycle

The only valid forward path is:

```text
requested -> authorized or denied
authorized -> authorization_revoked or logically_tombstoned
logically_tombstoned -> execution_started
execution_started -> inventory_observed or recovery_required
inventory_observed -> primary_name_removed, unlink_failed, or recovery_required
primary_name_removed -> primary_absence_verified or recovery_required
primary_absence_verified -> bounded primary-copy receipt
```

A tombstone blocks active resolution immediately and persists even when unlink or verification fails. It does not prove deletion. Execution requires an unexpired, unrevoked exact authorization; no blocking hold; a linear control history; an exact protected-ledger head snapshot known at or before—and no more than 1,000 milliseconds before—the unlink event's `effective_at`; confirmed revocation of the exact D9.0.1 capability leaf; confirmed closure/termination of every exact D9.3.0 descriptor-delivery record in the complete source-access inventory; a complete primary namespace inventory; no unexpected hard links, symlinks, path substitution, replicas, or temporary names; and exact subject identity. A later known hold or authorization revocation, an authorization or approval expiring between execution start and unlink, an omitted descriptor, an unresolved digest, or any other unknown or contradiction stops the operation.

The executor may unlink only the exact no-follow primary CAS name selected by the approved backend profile. It cannot list or delete arbitrary paths. The independent verifier separately observes the approved primary namespace, path identity, directory synchronization, open descriptors, link/replica/temp inventory, and resulting absence. Whole-directory rollback, compromised root/kernel, hidden storage layers, media remanence, and unregistered copies remain outside the receipt's proof.

## What a deletion receipt proves

A receipt binds the exact request, scoped authorization, tombstone, exact resolved D9.3.0 operational profile and complete protected primary-durability-receipt store snapshot, pre-unlink safety snapshot, execution, verification, operation/nonce, copy, artifact, executor, verifier, completion, and separate D9.4 ledger head. The pilot CAS reference must exactly equal `objects/sha256/<first-two-hash-characters>/<full-sha256>` for the declared retrieved-body artifact; arbitrary or substituted paths fail closed. Version 1 admits only the successful outcome `primary_copy_absence_verified`; a failed unlink or verification creates an execution/recovery fact and no deletion receipt. A successful receipt means only that the approved verifier observed the exact primary name absent within the approved primary namespace after the declared unlink/sync sequence at that time.

Every receipt hard-codes `complete_erasure_claimed=false`, `backup_erasure_claimed=false`, and `legal_compliance_claimed=false`, plus explicit limitation codes. Its `remaining_copy_classes` is the canonical fail-closed set `backup`, `derived`, `open_descriptor`, `replica`, `temporary`, and `unknown`: these classes were not excluded by the bounded primary-name observation. It cannot prove complete erasure, backup/derived/replica/temp/open-descriptor erasure, storage-media overwrite, legal compliance, or absence from unknown systems.

Artifact hashes, subject identities, backend references, reasons, and receipts may remain sensitive after deletion. They remain in restricted, access-controlled audit storage and are omitted from public projections. D9.4.0 does not authorize destruction of append-only audit metadata. A later legally required metadata-removal protocol would need its own versioned design, authority, tombstone, and audit treatment.

## D9.5 coordination

D9.4.0 emits only append-only directives: apply restriction before restore, apply tombstone before restore, do not restore, or delete a backup copy after a future D9.5 authorization. Each record hard-codes `unreachable_until_separately_approved_d9_5`. It is not a backup command or receipt.

A future restore must pin and reconstruct the exact D9.4 global control-ledger head before making bytes accessible, apply the latest knowledge-bounded restriction/tombstone state, preserve historical sequences and receipts, and refuse resurrection when controls are missing, ambiguous, stale, or contradictory. Primary deletion retains the complete canonical fail-closed remaining-copy class set until separately approved protocols can prove a narrower result. D9.4 records a typed but null D9.5 backup-receipt reference; no D9.5 receipt may be invented before that separately approved implementation exists.

## Crash and reconciliation semantics

Eight closed crash boundaries cover restriction persistence through journal linkage. The recovery contract records an immutable snapshot digest, inventory/access/control states, one closed classification, semantic and persistence actors/times, and `action_execution_code=none_classification_only`. It always records `recovery_authority_present=false` in D9.4.0 fixtures and cannot perform cleanup, retry, unlink, restoration, or control correction.

Orphan classification is conservative. An object or temporary name is deletable only after the future implementation proves it is outside an active operation, has no control/evidence/candidate/output/draft/backup reference, has no hold, is older than the approved grace period, and has a complete consistent inventory. Otherwise it is retained and held. Crash recovery cannot invent authorization from an expired request or infer safety from missing records.

## Threat and failure matrix

| Threat/failure | Required disposition |
|---|---|
| Unauthorized restriction/deletion | authenticated role resolution; append rejection; alert; no effect |
| Self-approval or role substitution | reject before persistence and at broker boundary |
| Stale/revoked authorization | reject; retain/tombstone remains; new human decision required |
| Concurrent access and deletion | operation lock plus live descriptor inventory; deletion blocked |
| Descriptor issued immediately before restriction | deny further use, revoke capability, terminate/reap receiver, confirm closure |
| Open descriptor during deletion | block deletion; restriction remains active |
| Hard link, symlink, path substitution, extra replica | fail closed; no arbitrary cleanup |
| Partial unlink or crash | tombstone remains; classify `reconciliation_required`; no invented retry authority |
| Primary absent but backup present | receipt says primary scope only; D9.5 action pending |
| Restore would resurrect restricted bytes | apply control ledger before exposure or reject restore |
| Replay, collision, fork, gap, rollback, or backdating | no-replace, digest/nonce/sequence checks; knowledge-bounded projection; fail closed |
| Whole-directory rollback | outside local journal proof; requires rollback-resistant external control in an operational profile |
| Compromised kernel/root | explicitly outside the component guarantee; incident response required |
| Deletion verification unavailable/fails | no success receipt; tombstone persists; human reconciliation required |
| Missing/contradictory inventory | retain and hold; no deletion |
| Receipt cited as legal or complete-erasure proof | structurally false claims plus mandatory limitations; reject reinterpretation |

## Field provenance, storage, and confidentiality

The machine field registry is normative. Each nested leaf inherits its top-level field classification unless an exact sensitive-family rule is more restrictive.

| Field family | Trusted producer | Consumer | Storage | Confidentiality | State class |
|---|---|---|---|---|---|
| format/version/type | reviewed contract; instance producer selects closed value | every parser | instance store | internal | canonical contract identity |
| subject identity | manifest/SQLite projection plus independent resolver | control broker, adapter, verifier, D9.5 | protected control/receipt store | restricted integrity | operational reference, not legal truth |
| actor/binding/principal | authenticated runtime mapping | launcher/broker | protected control/journal | restricted personnel/security | operational attribution, not authorization by itself |
| reason and human approval | authenticated human through fixed broker | control evaluator | protected control store | restricted legal/security | operational decision, not legal conclusion |
| effective/recorded time | semantic actor | evaluator/auditor | append-only store | internal | claimed event chronology |
| persisted time/sequence/predecessor | journal/control broker | all projections | append-only store | restricted integrity | knowledge order |
| protected-ledger append receipt | D9.4 journal broker | projector, verifier, D9.5 | separate protected D9.4 ledger | highly restricted integrity | persistence acknowledgement, not legal or erasure proof |
| capability/descriptor lifecycle | launcher/custody service | deletion evaluator/verifier | highly restricted control store | highly restricted security | operational access history |
| inventory/execution observation | executor or verifier according to variant | independent verifier/recovery | execution store | highly restricted security | bounded observation |
| deletion receipt/limitations | independent verifier; broker persists | authorities, D9.5, auditor | receipt store/journal | highly restricted legal/security | bounded technical receipt |
| backup directive | authorized control actor | future D9.5 broker | control store | restricted operational | directive only, no execution authority |
| recovery assessment | independent classifier; broker persists | human recovery authority | D9.3 recovery namespace | highly restricted security | classification only |

No record is stored in Atlas SQLite by this design. No contract field may be exposed publicly or interpreted as officiality, legal identity, legal status, legal effect, review, publication, or compliance.

## Validation design

The offline validator:

- pins migrations 001–005, D9.0.1 and D9.3.0 catalog/semantic fingerprints, and the approved D9.3.1 Git tree;
- rejects missing, substituted, or extra contract-root artifacts through exact catalog and root-inventory fingerprints;
- compiles all eleven schemas (one shared and ten top-level) and rejects unknown fields/versions/states;
- validates canonical timestamps, safe strings, self-digests, exact subject identities, and independent golden canonical strings/hashes;
- verifies complete field coverage, all matrix fingerprints, exact identity-binding/externally adopted authority-roster resolution, distinct human gates, knowledge chronology, global receipt order, chain gap/fork/backdating/replay/collision behavior, restriction precedence, exact D9.0.1 clearance and open-custody exchanges, complete capability/descriptor/message and D9.3.0 receipt-store snapshots, access shutdown, explicit authorization revocation, stale global safety heads, exact CAS references, deletion transitions, bounded receipt proof links, D9.5 unreachability, and classification-only recovery;
- weakens representative schemas in memory to prove fixed raw hashes and semantic checks detect the weakened boundary;
- applies migrations 001–005 to a disposable database, runs integrity/foreign-key checks, and confirms all 13 Atlas tables remain empty.

Passing validation proves only internal consistency of this design proposal and the exercised synthetic cases. It does not prove OS identity, authorization, descriptor revocation, secure unlink, storage erasure, durable sync, legal compliance, human review, or operational readiness.

## Independent review disposition

The security/least-privilege review and the determinism/versioning review identified concrete blockers in the first draft. The proposal accepts and resolves them as follows:

- human gate counts, distinct principals, self-approval, role substitution, approval expiry, and exact scope hashes are now evaluated rather than merely declared;
- every actor resolves through one exact active D9.0.1 binding generation and an immutable, unactivated D9.4 authority roster; caller text is never trusted as identity or authority;
- deletion authorization now pins the requester, exact D9.3.0 custody profile and primary-durability receipt, subject, operation/nonce, projections, reason, interval, and request; explicit revocation blocks execution;
- corrections and withdrawals require the same subject/operation/nonce/stream and current leaf; deletion authorization uses its own revocation transition and tombstones cannot be generically withdrawn;
- the primary-deletion proof graph resolves exact request, authorization, tombstone, D9.3 custody facts, access shutdown, safety snapshot, execution, verification, receipt, global ledger head, and D9.5 directive;
- path/file-type/no-follow observations, directory synchronization, copy inventory, and bounded receipt limitations are explicit; no receipt claims storage overwrite or complete erasure;
- a separate D9.4 global append-receipt contract resolves the frozen D9.3.0 broker-format incompatibility without modifying the frozen contract;
- global knowledge order uses one named namespace and gapless receipt chain, and D9.5 records pin the exact control-ledger head needed by a future restore;
- access shutdown resolves the earliest active applicable control for the episode, supports only explicitly grounded propagation, rejects released historical triggers and later deadline-reset substitutions, and compares the complete frozen D9.0.1 open exchange and D9.3 descriptor context;
- every backup-coordination stream is independently root/gap/fork/backdating checked, while the primary receipt conservatively retains every unexcluded backup, derived, descriptor, replica, temporary, and unknown copy class;
- destructive safety snapshots have a fixed 1,000-millisecond maximum age and are still required to pin the latest protected journal head;
- the validator exhaustively iterates closed action, reason, transition, access, execution, backup, and recovery matrices and checks independently fixed canonical payloads.

The reviews rejected widening any frozen D9.0.1 importer partition, treating a claimed actor/role as authorization, treating a tombstone as erasure, or allowing D9.4 to simulate D9.5. The operational implementation questions listed below remain deliberately unresolved and fail closed.

## Implementation boundary and prerequisites

Before D9.4.1 may begin, approval must pin this exact root and a separate implementation task must resolve:

1. a least-privilege administrative launcher/handle scope that does not widen importer authority;
2. protected identity generations and role qualifications for human authorities;
3. append-only control/execution/receipt stores plus the separate D9.4 global ledger and rollback-resistant audit strategy;
4. authenticated IPC for control, launcher termination, executor, verifier, and the new D9.4 journal broker;
5. live descriptor/capability inventory, an operation lock, and an atomic cross-store knowledge snapshot whose exact ledger head cannot go stale before unlink;
6. safe no-follow primary-name unlink and independent namespace verification primitives;
7. operational alerting, incident handling, and credential management outside Git;
8. separate D9.5 backup/restore contracts before any complete reconstruction or erasure claim;
9. full synthetic fault, race, rollback, and privilege testing before any real byte is admitted.

D9.4.1, if later approved, remains synthetic and unactivated. D9.5 remains separately reviewed. Real restriction/deletion effects, evidence, operational credentials, bootstrap, import, legal review, publication, API/frontend exposure, and production use each require later explicit authorization.

## Approval boundary

This proposal finishes in an **awaiting approval** state. Approval would freeze the machine contract and authorize only later consideration of D9.4.1. It would not activate a runtime, authorize deletion, populate Atlas, establish accepted evidence, verify legal authority, or make any public claim.
