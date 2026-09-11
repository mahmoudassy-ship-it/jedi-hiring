# D9.1 — launcher and bootstrap control plane

Status: **approved at implementation commit `79046c27dfa6923383be33a1d0aaa5a7641f5d1f` for its synthetic, unactivated control-plane boundary only**. This approval is not production readiness and does not authorize real bootstrap, evidence import, custody operations, database writing, or legal verification. The separate [synthetic, unactivated D9.2 accepted-bundle verifier](d9-2-accepted-bundle-verifier.md) is approved at implementation commit `460547b7fe75a94f689dabc97fd91ee6f803934a`; neither approval activates or joins the two boundaries. The [D9.3.0 custody-durability contract extension](d9-3-0-custody-durability-contracts.md) is proposed and awaiting approval; it creates no runtime. D9.3.1 primary-custody implementation remains a later separately reviewed step.

The applicable frozen inputs remain:

- D9.0.1 catalog: `e0a5663b378453a00626f02961465a60a474e145dd5160bf85a1797cd9316d2a`;
- classification record: `8d7b64822663edf09dac0d613ed9da30de0569acb8a1258a84e1850af656deef`;
- global handle matrix: `68c54bc683be3b3ff8ffba615fc850045c75a42539606858bffd42a881470f7e`;
- seven operation scopes: `9c2c9fd552bfdaac26448feace4de8f729c5b0587fa904ba65647b21c4de897e`.

No file under `docs/schema/d9-0/` and no migration is changed by D9.1.

## Delivered boundary

The implementation is deliberately isolated in `d9/control-plane/`. It supplies:

| Component | Responsibility | Explicit limit |
|---|---|---|
| Canonical JSON reader | Bounded, strict UTF-8 parsing, duplicate-key rejection, D9 canonical serialization and SHA-256 | It is not a general JSON or signature framework |
| Contract verifier | Pins the catalog, schemas, registries, runtime profile, bindings, component/dependency bytes, operational profiles, scanner files, migrations and database contract | Checked-in synthetic records cannot be selected as a real active generation |
| Scope evaluator | Derives exactly one of the seven D9.0.1 partitions from five verified facts and checks the exact required grant set | A caller cannot supply an operation scope or expand it |
| Protected control store | Append-only active-generation, revocation, handoff/seal, permit, transition, nonce and operation-control records with hash chains and crash holds | It is a synthetic D9.1 control ledger, not the D9 operation journal, Atlas data, or a substitute for D9.3 durability |
| Dedicated-UID append worker | Is the only process used by the integrated harness to mutate that ledger; pins the selected generation, Node executable and complete D9.1 source inventory and owns the operation lease across begin/terminal appends | Its root-owned spawn plus private inherited pipes are a synthetic harness boundary, not the frozen operational `AF_UNIX`/`SOCK_SEQPACKET` service IPC profile |
| Linux enforcement helper | Probes and exercises `SOCK_SEQPACKET`, kernel peer identity, descriptor passing, close-on-exec, safe relative opening, kernel-held locking and confirmed receiver termination | It contains synthetic integration-peer modes only; later services must be independently built and pinned |
| Empty-state verifier | Opens only a disposable/caller-designated database read-only, validates migrations/schema/legacy digests and proves all 13 Atlas tables are empty | It cannot verify a completed accepted bundle; that projection belongs to D9.2 |
| Synthetic launcher facade | Applies the closed test-harness startup order, identity mapping, seal/permit checks, exact scope selection, zero-handle dry-run, teardown and recovery-hold behavior | It has no operational permit-claim or permitted-operation API. One disposable, explicitly synthetic claim exercise uses a branded roster-verifier test double and must end `recovery_required`; importer, writer, custody, backup and accepted-projection verification remain outside D9.1. The separately approved D9.2 boundary implements only synthetic disposable data-plane verification. |

Attribution remains distinct from authentication and authorization. An Atlas principal code in a manifest or contract never authenticates its caller. The launcher derives identity from a protected binding generation plus kernel peer facts. No authentication material is stored in Git, D9 contracts, SQLite, command arguments, or the operation response.

## Closed startup and operation order

Startup and each exercised synthetic boundary fail closed in this order:

1. Probe every required Linux primitive. A missing or deliberately disabled guarantee is an error, not a fallback.
2. Inspect the append-only control store. A broken chain, unpublished partial record, unterminated prior operation, or recovery hold blocks ordinary work.
3. Verify the dedicated-UID append worker against the exact selected `trusted_launcher` binding, Node build and D9.1 source inventory. The harness-created pipe is not accepted as an operational service endpoint.
4. Select exactly one current, non-revoked active runtime/binding generation from protected state. The caller cannot select a generation.
5. Read and hash held contract, runtime, binding, build, dependency, operational-profile, scanner, migration and schema bytes. Runtime-profile and identity-binding records are reopened with `O_NOFOLLOW`, checked by descriptor identity before and after reading, required to remain canonical exact bytes, and rechecked before every privileged boundary.
6. Map the authenticated Unix peer to exactly one active binding for the requested operation mode. Caller-supplied UIDs, binding codes and principal codes are ignored as identity evidence.
7. Validate fixed handoff, seal and permit records before the dedicated worker recomputes their canonical record digests and appends them. Handoff/seal and active-generation revocations use the same authenticated worker and exact-target projection. D9.1 stores a permit as operationally unclaimable; it does not implement the manifest roster resolver required for a real claim.
8. Derive and validate all seven operation scopes from the five frozen selector facts. Required and forbidden grants must be a complete, disjoint partition of the 33-grant universe.
9. For the synthetic dry run only, acquire the fixed kernel-held operation lock, append the nonce-bound begin record through the dedicated worker, run a zero-handle test double, independently authenticate the synthetic verifier, append the terminal result and release the locks.
10. Separately exercise grouped descriptor delivery to synthetic non-launcher peer processes over authenticated `SOCK_SEQPACKET`, with exact grant metadata, close acknowledgement, pidfd termination and confirmed exit. The five scope grants addressed to `trusted_launcher` are checked against the pinned append-worker identity but are not represented as operationally issued descriptors.
11. For one disposable permit-bound test only, require a branded synthetic D9.2 roster-verifier result to match the exact seal and permit commitment, atomically claim that permit with operation start, derive `bootstrap_first_acceptance` from those verified facts, deliver exactly its 15 grants, prove the database remained empty, then append the permit and operation `recovery_required` terminals. The test can never create `spent`, `verified_effect`, `canonical_receipt_verified`, or an accepted-bundle result.

No API accepts SQL, a database table, an arbitrary filesystem root, a principal ID, an operation-scope code, or an alternate contract fingerprint. Protected deployment wiring is intentionally outside the operation request.

## Active generations and revocation

D9.0.1 intentionally did not define a lifecycle format for active runtime/binding generations. D9.1 therefore uses a narrowly scoped internal control record, outside the frozen contract catalog:

- activation records have a strictly increasing positive sequence and bind one runtime-profile identity/digest to one identity-binding identity/digest;
- every activation pins its predecessor, activation time and canonical record digest;
- a new activation does not delete or rewrite its predecessor;
- revocations are append-only, bind the exact selected pair, take effect at their protected persistence time, and are routed through the selected trusted-launcher append worker;
- an activation or revocation fork, gap, unknown predecessor, backdated persistence time, stale selection, expired binding set, or multiple current heads fails closed;
- the active pair is rechecked immediately before a claim, append or handle issue.

Reopening the ledger always validates sequence one against the separately supplied original genesis identity-binding record. That immutable replay anchor is not replaced by the currently selected generation, so a broker can restart after an authorized binding rotation without treating the new generation as historical genesis.

These records carry no authentication material and do not alter the frozen runtime-profile or identity-binding formats. Filesystem ownership and mode checks protect the pilot store from ordinary roles; the hash chain detects corruption and accidental or unauthorized mutation. This is not protection from a compromised administrator or kernel.

## Handoffs, seals and permits

The fixed-function registry stores exact immutable D9.0.1 record bytes and their canonical digests. The protected worker independently recomputes each canonical record digest before accepting a handoff, seal, permit issuance or permit transition. It accepts only recognized handoff/seal or bootstrap-control variants and rejects stale hashes, a stable code or digest collision with different bytes, and reuse of a nonce already reserved by either a permit or an operation. Handoff revocation requires the current `handoff_broker` binding; bundle-seal and active-generation revocation require the current trusted-launcher binding. Each revocation is a new exact-target append and never edits its target. Registry membership establishes traceability, not source authenticity, legal correctness, rights clearance, review, or publication.

Permit issuance and transitions remain separate records. D9.1 validates and stores an issuance and supports the closed bootstrap-authority withdrawal edge. Every issuance result says `claimEligible: false` and `handlesIssued: false` because no operational claim API exists. The approved, unactivated D9.2 boundary can securely reopen the exact synthetic manifest and verify its bootstrap roster in disposable tests; integrating that result with a real protected claim remains separately unauthorized.

To prove the D9.0.1 ownership split without fabricating that missing D9.2 result, the launcher exposes one no-argument `runSyntheticPermitScopedBootstrapAudit` test boundary. It accepts only the single permit issued by that launcher instance and only a factory-branded synthetic roster-verifier dependency. The verifier output must repeat the exact permit, bundle digest, reviewed commit and manifest path and match the committed roster hash. That result is then tied to the atomic claim, `bootstrap_first_acceptance` selector facts and operation nonce before any synthetic descriptor delivery. The worker rechecks that the exact source bundle seal is still nonrevoked and unexpired inside claim application. A lost claim response is always ambiguous and no handles follow it. Even on a clean run, D9.1 cannot verify an accepted projection, so the frozen `state_ambiguous` transition closes the permit as `recovery_required`; the operation receives the same terminal state and the launcher enters a recovery hold. The exercise is not a bootstrap, importer, writer, manifest resolver or accepted-bundle no-op.

The synthetic append worker checks monotonically increasing persistence chronology, structurally separate semantic/persistence attribution, and distinct bindings on edges whose frozen rule requires it. Permit and operation nonces share one namespace. A permit pins the exact bundle-seal registry record selected at issuance; claim application and every later handle-recipient group recheck that same record, its revocation state, exclusive expiry, exact claim, operation lock, generation and permit leaf. A semantically identical replacement seal cannot revive a revoked or expired pinned seal. Operation completion also enforces the semantic pair at the protected-state replay boundary: `no_effect_verified` may accompany only its matching permit transition, `recovery_required` only `state_ambiguous`, and D9.1 exposes no accepted-effect path. A response loss permanently closes the worker. An exactly projected fixed-record or terminal-operation append may be reported as persisted-after-response-loss; an absent append is an explicit failure; every begin response loss is ambiguous because the dead worker lost its process-held lease. Permitted-terminal reconciliation compares both the complete immutable permit leaf and operation terminal, expected states, lock absence and recovery hold. Locally malformed or repeated request nonces are rejected before consuming a broker request number; no delayed response may satisfy a later request.

## Exact handle scopes

The evaluator uses only:

1. `operation_mode_code`;
2. `bundle_kind_code`;
3. `source_authorization_code`;
4. `permit_kind_code`;
5. `permit_scope_code`.

The seven approved results are `accepted_bootstrap_no_op`, `accepted_document_no_op`, `bootstrap_first_acceptance`, `exact_bootstrap_reconstruction`, `ordinary_document_import`, `post_promotion_completion_bootstrap`, and `post_promotion_completion_document`. Tests remove every required grant in turn, add every forbidden grant, substitute slot/access combinations, change recipients, and alter each selector. All must be rejected. The harness validates all 83 scope occurrences; it performs grouped native descriptor sessions for the 78 occurrences addressed to later non-launcher services and confirms 29 synthetic receivers have terminated. The five `trusted_launcher` occurrences are bound to the dedicated worker identity in the audit result, not misreported as descriptor delivery.

D9.0.1 defines no handle partition for `dry_run`. The D9.1 bootstrap dry run is therefore a synthetic internal validation path with **zero operational handles**. It cannot be upgraded into a real scoped operation by application convention; doing so requires a separately versioned contract decision.

The permit-bound scope exercise is different from that dry run: it derives one existing frozen partition from a synthetically verified roster result and physically exercises 14 non-launcher grant occurrences across five short-lived peers plus one launcher/append-worker grant. Its descriptor request digest binds the permit, operation ID, operation nonce, exact selector facts, recipient and grants. All receivers are terminated before the method returns. Its mandatory recovery terminal is proof that D9.1 did not and cannot complete the D9.2 acceptance path.

## Linux identity and descriptor boundary

Node.js does not expose the required `SO_PEERCRED`, `SO_PEERPIDFD`, `SCM_RIGHTS`, `openat2`, or `flock` surface. D9.1 includes a small C helper and compiles it only into a disposable directory for integration tests; no generated executable is committed. This helper proves the kernel primitives used by the synthetic peer, handle and operation-lock tests; it is not an operational IPC listener. The helper:

- uses Unix `SOCK_SEQPACKET` and one bounded packet;
- checks connection and per-packet kernel credentials;
- rejects claimed UID/PID mismatches, truncation, unexpected ancillary data and more than eight descriptors;
- opens a fixed relative leaf beneath a held root with `openat2` resolution restrictions;
- receives descriptors with `MSG_CMSG_CLOEXEC`;
- binds delivery and acknowledgement to a 256-bit operation nonce and a one-use descriptor token;
- detects a repeated acknowledgement as replay;
- holds a kernel `flock` for the operation; and
- retains a pidfd, terminates the synthetic receiver after acknowledgement, and confirms exit before reporting revocation.

Closing a sender descriptor is not described as revocation: `SCM_RIGHTS` creates an independent receiver reference. Later importer/writer/custody services must run as distinct pinned releases with the same tested broker boundary and must meet the frozen process/thread/network restrictions. Until those releases and an administrator-owned active generation exist, production startup has no valid configuration and fails closed.

The integrated state append worker is intentionally different: the root-owned test harness spawns the exact pinned Node executable under the synthetic `trusted_launcher` UID/GID with no supplementary groups, passes a protected root descriptor and closed canonical messages through private inherited pipes, and then verifies the child-reported PID/UID/build/generation. That demonstrates write ownership in the disposable harness, but it does **not** satisfy or replace the approved operational `AF_UNIX`/`SOCK_SEQPACKET`, filesystem-ACL and peer-credential channel. Operational endpoint creation and activation remain separately reviewed deployment work; D9.1 makes no contrary claim.

## Empty-state and no-effect semantics

The empty-state verifier checks the migration ledger, all migration hashes, complete/legacy schema digests, all 13 legacy row digests, prohibited application-surface hashes, and the exact empty set of 13 Atlas tables. It uses `query_only` and a read-only SQLite connection and compares the database-file hash before and after inspection.

The synthetic D9.1 flows may validate a bootstrap seal and operationally unclaimable permit, append and finish a zero-handle control-plane dry run, and exercise the permit-bound scope path described above. Both prove that the disposable database did not change. The injected dry-run and roster-verifier probes are synthetic test doubles; their timeout cannot cancel same-process work, so later operational work must run such logic in supervised, terminable peers. Neither independently reconstructs an accepted bundle. The flows do not insert the four bootstrap principals or a receipt, emit an accepted-bundle result, or assert complete accepted-bundle projection equality. Those are D9.2 responsibilities.

## Failure and recovery behavior

The control store publishes a record only after writing a new temporary file, synchronizing it, installing it without replacement, and synchronizing its directory. Its append mutex commits to the exact base HEAD, intended sequence and intended commit digest before publication. Recovery will not combine an unanchored commit with a mismatched or incomplete mutex. Test fault points cover pre-write, partial-write, pre-publish, post-publish and terminal-record boundaries. On restart:

- unpublished temporary material is not accepted as history;
- malformed, missing, reordered or forked committed records block startup;
- a claimed nonce cannot be reused;
- a live operation without a terminal record becomes `recovery_required`;
- no code path deletes history, resets a permit, guesses an effect, or continues ordinary work through ambiguity.

Recovery itself is causal and crash-tested. Each operation-lock incident has a digest distinct from its operation ID and nonce, so a crash after the recovery audit can retry exactly without duplicating that audit while a later lock incident receives a new audit. Lock cleanup must occur after the recorded lock acquisition and current commit head; even a cleanup-only retry must match the exact durable recovery record. A terminal lock left after `operation_recovery_required` can be removed by the authenticated recovery authority while the operation recovery hold remains. Recovery authority is evaluated at the original operation or protected incident boundary, so an otherwise valid cleanup does not become impossible merely because the responsible generation later expires. A linked but unanchored generation revocation can be anchored and audited from the exact generation facts that authorized the recovered commit, even if that pair is now revoked or expired; an older generation never becomes active again. A linked interrupted genesis activation is likewise recovered from the explicit bootstrap trust anchor.

Before genesis, a complete append mutex or fully validated pending activation that never became a linked commit is unaccepted material: after proving its sealed incident time and exact bootstrap-anchor authority, it is discarded, reports `durableAuditRecorded: false` because no ledger generation yet exists, and leaves genesis retryable. An empty or partial pre-genesis append-mutex directory with no validated pending activation has no trustworthy incident time. D9.1 deliberately refuses in-band deletion with `STATE_PRE_GENESIS_INCIDENT_TIME_UNAVAILABLE`; a separately controlled, protected-log-backed out-of-band incident procedure is required. This exception is a fail-closed recovery hold, not a claim that every pre-genesis remnant is automatically retryable.

Full operation-journal recovery, candidate promotion, custody durability, backup durability and operational accepted-state reconstruction remain outside D9.1. The approved D9.2 boundary covers only synthetic disposable reconstruction while every original byte remains available; D9.3.0 defines primary-custody durability and conservative crash-state classification contracts only; D9.4 retains restriction/tombstone policy and D9.5 retains backup/restore and deletion-aware reconstruction. The D9.1 control ledger must not be presented as those later guarantees.

Low-level recovery entry points are exercised only by disposable state-store tests and are not exposed by the launcher or append worker. A later operational recovery tool must take the same kernel lock, prove the former owner process is dead, authenticate the separately qualified recovery role and persist an audited recovery intent before changing any protected head or lock state.

## Security boundary and residual prerequisites

Tests cover peer/identity spoofing, wrong kernel credentials, build/profile substitution, post-construction runtime/binding symlink swaps, stale and revoked generations, authenticated registry/generation revocation, stale record digests, path/symlink attacks, malformed IPC, local nonce/request-sequence desynchronization, cross-order permit/operation nonce replay, descriptor replay, permit fork/reuse/backdating/expiry, exact source-seal pinning and use-time revocation/expiry, terminal permit/result mismatches, short claim life, roster-to-scope binding, handle omission/addition/misdirection, partial protected-state writes, exact permitted and unpermitted response-loss reconciliation, distinct recovery-incident deduplication, lock chronology, terminal-lock cleanup and exact retry, pre-link and linked genesis recovery, unanchored-commit/mutex mismatch, unanchored revocation after expiry, crash restart, empty-state mutation and database no-effect.

Before any real bootstrap can be proposed, all of the following still require separate operational review and authorization:

- administrator-owned protected roots and deployment-specific active generation records;
- real dedicated OS identities and pinned service builds;
- a reviewed runtime-domain build and dependency inventory;
- process sandboxing, service supervision and host hardening for every later peer;
- protected-runtime integration of the approved synthetic D9.2 verifier without activating it prematurely;
- the D9.3.1 primary-custody, journal, and crash-state classification implementation, D9.4 restriction/tombstone controls, and D9.5 backup/restore implementation;
- protected authentication material provisioned outside Git;
- a separately approved bootstrap permit, people, window and ceremony.

No real credential, operational identity, protected-state generation, permit, principal, database write, custody object, evidence record, API change, frontend change, or public surface is included here.
