# First evidence pilot — evidence-empty bootstrap ceremony

Status: runbook proposal, not authorization. Execute only after the readiness proposal, all `B` gates, the operational release and an exact one-use bootstrap authorization are separately approved. The ceremony imports no document, evidence, legal claim or review.

## Required roles and separation

- `human_submitter` prepares the exact reviewed sequence-1 bundle.
- `bootstrap_authority` issues the one-use permit.
- `operational_witness` independently observes identity, clock, heads, counts and terminal result.
- `trusted_launcher`, `bundle_importer`, `database_writer`, `cloner_promoter`, `independent_verifier`, `journal_broker` and `backup_adapter` act only through their approved fixed-function interfaces.

The submitter, bootstrap authority and witness are distinct eligible humans. Attribution never proves authentication, authorization, qualification or review eligibility.

## Preconditions

1. Freeze the reviewed repository commit, operational builds, D9 contract fingerprints, active identity/profile generations, migration hashes and protected environment inventory.
2. Prove healthy trusted time, exact endpoints/builds/peers, one-operation lock, empty replay/nonce state and no unresolved hold, incident or recovery-required classification.
3. Verify the canonical database is a clean 001–005 installation, all 13 Atlas tables are empty, the complete legacy schema/digests match the approved baseline and the application remains v1-only.
4. Verify primary CAS, custody, processing and candidate inventories are empty; bootstrap requires no artifact, custody placement, processing output or candidate occurrence.
5. Verify an independent backup destination, rollback anchor and disposable restore staging are healthy and empty for this operation.
6. Open the reviewed manifest descriptor relative to its approved immutable root. Prove no symlink/root escape and bind the declared relative path to the opened file.
7. Validate the strict manifest, canonical digest, bundle seal, handoff, exact four synthetic-free operational principal records, zero artifact shape, exact dependency graph and all D9.0.1 handle scopes.
8. Record a signed go decision tied to the exact pre-state heads, manifest digest, build generation, operation nonce, permit and expiry.

Any missing, stale, contradictory or unverifiable fact is NO-GO. Do not repair the canonical state during the ceremony.

## Ceremony sequence

1. Acquire the protected operation lock; capture stable before-head observations from every required store.
2. Issue exactly one bootstrap permit for the accepted manifest and exact handles. Confirm sufficient lifetime; never extend or fork it.
3. Run complete semantic preflight before opening a database transaction or finalizing custody. Recompute all referenced bytes and canonical hashes. The bootstrap bundle contains no artifact bytes.
4. Clone the canonical database into a disposable candidate using the approved descriptor-bound path.
5. Apply the deterministic typed bootstrap plan through the fixed-statement writer. Only the four approved principal rows and one evidence-bundle receipt may be created.
6. Verify the full candidate projection twice: the importer verifier and an independent verifier compare every persisted column/relationship to the exact bundle and approved state.
7. Create and independently verify the `prior_backup` of the exact pre-promotion canonical generation. Append its receipt and required journal/checkpoint transition; re-observe every source head at append time. Missing or moving state cancels promotion.
8. Atomically promote the verified candidate. A response loss after durable promotion is classified from protected source-state and journal-tip receipt identities; never rerun speculatively.
9. Independently verify the promoted generation, then create and verify the distinct `final_backup` and bounded durability receipt for that exact post-promotion state. Retain both prior- and final-backup receipt identities.
10. Restore the final backup into inaccessible disposable staging. Verify exact generation, database hash, migration ledger, table projection, journal/receipt prefixes, restriction state and no publication surface. Destroy only the disposable drill generation under its approved procedure.
11. Replay the identical accepted bundle. The complete persisted projection must verify and return exact `no_op`; no row, receipt, head, file or timestamp may change.
12. Release/revoke every capability, terminate and reap descriptor receivers, close the operation, externally anchor heads and generate the verification report.

## Expected terminal projection

| Object | Expected count/state |
|---|---|
| `atlas_principals` | 4 exact rows from the accepted bootstrap bundle |
| `atlas_evidence_bundle_receipts` | 1 accepted sequence-1 receipt |
| Other three Tranche 1A tables | 0 rows |
| Other eight Tranche 2A tables | 0 rows |
| Legacy tables/rows/relationships | byte/schema/digest-equivalent to pre-state |
| Primary artifact custody | empty |
| Independent backups | exact verified prior backup of the pre-promotion generation and final backup of the promoted bootstrap generation; no source artifact |
| API/search/export/frontend | no Atlas route; legacy v1 only |

## Stop, response-loss and rollback rules

- Before durable promotion: abort, revoke handles, preserve protected logs and isolate the identified disposable candidate. Dispose of it only after no-effect classification, forensic/evidence-preservation review and explicit scoped cleanup authorization; classify staging/orphans conservatively.
- After a possible durable effect: do not retry, delete, restore or roll back. Freeze writes and resolve from checkpoint, journal, receipt and source-state identities.
- A failed/no-effect run consumes its nonce/permit according to the frozen contract; a replacement requires a new authorization.
- A missing/invalid prior backup blocks promotion. A promoted generation whose final backup is missing or unverified is a recovery-required incident and blocks document import. Do not represent success.
- Never use a database copy, filesystem snapshot or Git reset to overwrite canonical history.

## Completion evidence

The witness records the exact operation/result identifiers, manifest and build digests, before/after heads, four-principal projection digest, migration/legacy digests, distinct prior/final backup and restore receipts, no-op replay result, clock evidence, capability revocation, limitations and any incident. Completion proves only technical evidence-empty bootstrap; it does not approve evidence, authority, law, review or publication.
