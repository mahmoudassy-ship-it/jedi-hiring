# D9.5.1 synthetic backup and restore runtime

Status: implementation candidate on `implementation/d9-5-1-backup-restore-runtime`; unapproved, unactivated, synthetic-only.

This vertical slice implements the approved D9.5.0 technical contract boundary for disposable tests. It creates no operational backup, recovery authority, credential, Atlas row, evidence record, legal conclusion, API, or frontend path. Exact-byte custody and restore auditability do not establish evidence acceptance, officiality, legal identity or status, legal effect, human legal verification, publication eligibility, compliance, or complete erasure.

## Implemented boundary

| Module | Responsibility |
| --- | --- |
| `contracts.mjs` | Loads the approved D9.5.0 root and fails closed on all seven frozen fingerprints. |
| `session.mjs` | Resolves the twelve frozen semantic roles through the verified D9.0.1 generation and adopted D9.4 roster. Synthetic peers complete a kernel-authenticated Unix exchange; sessions are process-bound, receiver-terminated, branded in memory, and revalidated at use. |
| `storage.mjs` | Stores exact synthetic bytes in an independent, private, descriptor-bound, content-addressed no-replace backend. It verifies hash, length, inode continuity, ownership, link count, file sync, directory sync, and final reopen. |
| `history.mjs` | Writes the eleven frozen append-only namespaces and one gapless global receipt chain through the protected no-replace namespace store. A target without a receipt is recovery-required and is never guessed complete. |
| `runtime.mjs` | Creates chained manifests and durability evidence; enforces three-human restore approval; records retention heads, bounded deletion-aware state and drills; reconstructs only into inaccessible staging; revalidates and applies current controls; independently verifies staging; and atomically renames a fully verified generation. |

The implementation uses the frozen v1.3 recovery identity route: independently derived source-state identity remains separate from journal-tip receipt identity. V1.2 is historical/read-only compatibility and is not used to create new runtime evidence.

## Security and durability properties

- All roots are configured absolute paths, opened without following the root symlink, owned by the running synthetic UID, and mode `0700`. Inputs are already-open single-link regular-file descriptors; URL, network and arbitrary-path fetching is absent.
- Backup object identity is exactly SHA-256 plus byte length. The destination is independent from primary custody. Existing content is reused only after exact reopening and hashing; no replace operation exists.
- The final backup object and object directory are synchronized before the staging link is removed. A fault at a durable append boundary leaves a fail-closed recovery-required state.
- Operation ID and nonce are bound to a canonical request. An identical accepted request is a no-op; changed content under the same identity is rejected.
- The requester and the recovery, legal-records and privacy approvers are four distinct humans. Backup producer/verifier, executor/restored-state verifier, control/restored verifier processes, and semantic/persistence actors remain separated.
- Restore bytes remain in a private staging generation through control revalidation, control application and independent inventory verification. A fresh control-head comparison is required immediately before atomic promotion.
- `do_not_restore` and tombstone directives withhold reconstruction. A changing control head cancels promotion and retains inaccessible staging for reconciliation.
- All seven copy classes are explicit. Every receipt and result fixes `complete_erasure_claimed=false`; this runtime cannot prove host-wide or media-wide erasure.
- Recovery is classification-only. It authorizes no cleanup, retry, rollback, restoration, repair or deletion action.

## Tests and fault model

Focused tests use only synthetic bytes, identities and disposable mode-`0700` directories. They cover sequential backups, identical-byte deduplication, exact replay/no-op, replay collision, source/hash/reference corruption, D9.0.1 role and peer substitution, three-human separation, all seven copy classes, retention and head evidence, deletion-aware withholding, passing/failing drills, control movement, missing bytes, inaccessible staging, all ten lifecycle fault boundaries, response loss after durable effects, and all seven closed crash classifications. Existing frozen validators remain the authoritative exhaustive contract checks.

## Unimplemented prerequisites

D9.5.1 is not operational. It lacks real credentials, isolated service accounts, a protected operational clock, independently administered backup media, external rollback resistance, operational RPO/RTO decisions, incident runbooks, recovery-authority activation, scheduled drills, alerts, and a production promotion target. No real bootstrap, evidence import, restriction, deletion, backup, restore or recovery may use this code before separate approval and activation work.
