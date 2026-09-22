# D9 recovery source-head/receipt identity correction 1.3.0

Status: **approved design-only contract freeze** at reviewed commit `d9eddd21494f59e27b2b6365456b53ee2719db2c`. Revision `1.3.0` is an additive, separately versioned correction. It preserves the approved resolver `1.0.0`, durability `1.1.0`, and checkpoint-progression `1.2.0` roots byte-for-byte and supersedes only the conflicting D9.4 source-head/receipt-identity route. Approval is external to the fingerprinted contract root and does not modify its permanent `design_only_contract_freeze` lifecycle value or activate runtime use.

This proposal proves technical journal continuity only. It grants no runtime activation, recovery action, evidence acceptance, officiality, legal identity, legal status, legal effect, legal verification, restriction, deletion, restoration, publication eligibility, compliance conclusion, operational permission, or D9.5 authority.

## Confirmed identity conflict

The frozen contracts contain two independently derived values that were routed as though they were one:

1. The frozen v1 D9.4 source head is SHA-256 over namespace, sequence, persistence time, and a complete raw-payload inventory digest.
2. A D9.4 append receipt is SHA-256 over one exact receipt record, including its target, predecessor receipt, actors, operation, nonce, and persistence facts.
3. The v1 D9.1 projection names the derived source-head value `control_ledger_head_receipt_digest_sha256`.
4. Revision 1.2 correctly binds an exact D9.4 receipt separately, but its synthetic progression path still supplies the derived source-head digest as the predecessor receipt identity.

For the same valid state these values are independently unequal. Treating either as the other requires an accidental SHA-256 collision or an invalid derivation. Revision 1.3 therefore gives each identity its own closed structure and binds them through an authenticated correspondence record. It does not reinterpret a frozen field in place.

## Three distinct identities

### D9.4 state head

The state head contains:

- namespace and frozen D9.4 source-contract fingerprint;
- source sequence;
- source persistence time;
- complete raw-payload inventory digest;
- independently derived state-head digest; and
- the frozen `raw_payload_commitments` derivation profile.

The state-head digest is the identity used for source-state comparison and source-head CAS. It is never a receipt digest.

### D9.4 journal tip

The journal tip contains:

- journal namespace;
- exact receipt sequence;
- exact receipt-record digest;
- exact target format, record code, and digest (the journal is global and may contain any of the six frozen D9.4 target formats);
- exact predecessor receipt digest; and
- receipt persistence time.

The tip receipt digest is the value used by `control_ledger_head_receipt_digest_sha256`, append predecessor/target validation, the broker receipt, and the assessment link. It is never a state-head digest.

### Source-head/receipt correspondence

The correspondence binds:

- one exact state head;
- one exact journal tip;
- the complete authenticated and gapless D9.4 receipt prefix;
- canonical raw source payload and its commitment;
- proof that the tip is the final receipt in that prefix;
- proof that each raw control-record entry is grounded in the matching receipt target;
- production-verified runtime generation, independent semantic verifier, persistence broker, executable builds and trusted observation time; and
- a canonical self-digest.

The semantic verifier recomputes the raw-payload hash, inventory digest, state-head digest, every receipt digest, the gapless predecessor chain, final tip, and prefix digest. A caller cannot supply an opaque state or receipt hash as truth. The journal broker persists the exact correspondence; it does not perform independent semantic verification.

## Corrected route

| Consumer | Required identity |
|---|---|
| Checkpoint equality | Exact correspondence reference plus independently derived state head |
| Source-head CAS | `state_head.state_head_digest_sha256` |
| D9.1 control/access projection | Actual tip receipt, distinct state head, and exact correspondence |
| `control_ledger_head_receipt_digest_sha256` | `journal_tip.receipt_record_digest_sha256` |
| Append request predecessor | Tip sequence and exact tip receipt digest |
| Append request target | Predecessor sequence + 1 and exact assessment digest |
| Broker receipt | Exact D9.4 receipt plus exact pre/post correspondences |
| Checkpoint transition | Post-state CAS plus exact post-tip receipt |
| Assessment link | Exact assessment receipt plus post correspondence |
| Restart/replay | Reconstruct both identities and their correspondence from authenticated retained bytes |

The corrected route uses complete, newly versioned v1.3 messages. They do not purport to accompany or repair a valid frozen v1.2 message, because the conflicting frozen route cannot carry both identities consistently. Frozen records and synthetic fixtures remain byte-for-byte auditable under their own validators. A future runtime must select the complete v1.3 route and reject the conflicting v1/v1.2-only route.

## Contract inventory

The isolated root is [`docs/schema/d9-recovery-resolvers-v1-3`](schema/d9-recovery-resolvers-v1-3/).

| Artifact | Purpose |
|---|---|
| `common-v1-3.schema.json` | Closed state-head, journal-tip, raw-prefix, payload-commitment and correspondence-reference definitions. |
| `source-head-receipt-correspondence-v1-3.schema.json` | Exact authenticated correspondence record. |
| `control-access-projection-v1-3.schema.json` | Complete corrected projection with actual receipt identity. |
| `checkpoint-identity-v1-3.schema.json` | Effective checkpoint identity and CAS commitment. |
| `assessment-append-request-v1-3.schema.json` | Complete receipt-predecessor/target request. |
| `assessment-append-broker-receipt-v1-3.schema.json` | Complete broker receipt with exact pre/post correspondence and D9.4 receipt. |
| `checkpoint-transition-v1-3.schema.json` | Complete post-state CAS and post-tip transition. |
| `recovery-assessment-link-v1-3.schema.json` | Exact assessment receipt and post-correspondence link. |
| `protected-append-receipt-v1-3.schema.json` | Append-only receipt for either v1.3 protected namespace. |
| `append-result-v1-3.schema.json` | Closed, noncanonical operational outcome for append, replay, or reconciliation. |
| `classifications-v1-3.json` | Identity use, compatibility, closed failures and non-authority boundary. |
| `digest-profiles-v1-3.json` | Canonical state, tip, prefix, correspondence and checkpoint-CAS profiles. |
| `field-source-registry-v1-3.json` | Trusted producers, consumers and caller-claim prohibitions. |
| `storage-profiles-v1-3.json` | Logical append-only namespaces, replay and reconstruction rules. |
| `fixtures/*` | Two-assessment synthetic path, mutation inventory and fixed golden vectors. |
| `validate-d9-recovery-resolvers-v1-3.mjs` | Offline dependency, schema, semantic, mutation, restart, replay and fingerprint validator. |

Unknown fields and versions fail closed. The schemas do not authorize storage handles, actors, services, credentials, writes, or recovery actions.

## Bootstrap and progression compatibility

No operational v1.2 progression record exists and the runtime is empty and unactivated. The empty **state head** has one deterministic identity: sequence `0`, no tip receipt, no prefix entries, and the persistence-time sentinel `1970-01-01T00:00:00.000Z`; observation time is recorded separately and cannot change that state identity. The surrounding correspondence and checkpoint remain operation- and observation-specific. Conditional on an externally verified empty/unactivated state, a new runtime can choose the corrected v1.3 route from its first source observation without migrating production state:

1. authenticate the frozen active generation and exact adapter/verifier/broker peers;
2. obtain the complete D9.4 raw source payload and exact retained receipt prefix;
3. create and persist the initial correspondence;
4. create the effective checkpoint identity from that correspondence; and
5. require v1.3 wrappers for every projection, assessment append, checkpoint transition, and assessment link.

Frozen synthetic v1/v1.1/v1.2 fixtures remain historically auditable under their own validators. They are not operational records and are never silently rewritten. If operational records are later discovered, automatic adoption is forbidden; human reconciliation and a separately reviewed migration decision are required.

## Persistence, replay, and crash semantics

The proposal defines two logical protected namespaces without choosing or implementing a storage engine:

- `d9.resolver.source-head-correspondence.v1.3` stores exact correspondence records and protected append receipts;
- `d9.resolver.identity-corrections.v1.3` stores exact corrected wrappers and protected append receipts.

Every append is no-replace, append-only, and broker-owned. Semantic verification and persistence remain separate. The synthetic actors are derived from a complete identity generation accepted by the production D9.0.1 verifier; the validator pins that verifier, canonicalizer, and fixture and checks actor validity at each trusted record time. A protected append must run schema, digest, cross-record semantic preflight, complete protected-chain reconstruction, and comparison with an independently supplied observed state-head CAS inside the same broker-held operation boundary before mutation. Format-specific collision keys cover primary code, operation/nonce, request target, checkpoint sequence, and transition sequence. Exact retained bytes may replay as a no-op only after full reconstruction. Changed bytes at any protected collision identity are rejected. A lost response after durable persistence first yields reconciliation-required and returns the byte-identical retained record only after restart revalidation.

The checkpoint CAS preimage commits to checkpoint sequence, predecessor checkpoint, exact correspondence, and independently derived state head. The immutable checkpoint record separately references the already-persisted transition receipt. Excluding that future receipt from the CAS preimage avoids a circular digest dependency without removing its audit link.

Missing bytes, moving heads, a wrong or unavailable tip, a fork, gap, rollback, extra append, mixed generation, actor/build substitution, or contradictory correspondence produces `reconciliation_required`. It never produces catch-up, inferred state, cleanup, retry, restore, restriction, deletion, or legal authority.

Restart classification treats request, D9.4 receipt, correspondence, broker receipt, transition, checkpoint, link, and projection as one ordered workflow. Every durable prefix stops at its exact next missing stage with `reconciliation_required` and no automatic action; any non-prefix state is corrupt. This contract models classification and the permissible next review point only—it does not implement completion or recovery.

## Validation coverage

The standalone validator:

- pins and executes the frozen v1, v1.1 and v1.2 validators;
- pins every predecessor catalog, root inventory, implementation anchor and migration 001–005;
- validates all v1.3 schemas and exact artifact inventories;
- derives genuinely unequal state-head and receipt-record digests;
- validates a complete authenticated receipt prefix and raw-payload inventory;
- executes two consecutive assessment transitions and a genuine deterministic empty-runtime genesis;
- verifies projection, append request, broker receipt, checkpoint, transition and assessment-link identity routing;
- rejects wrong tip, target, predecessor, sequence, time, inventory, raw prefix, producer and build;
- rejects swapped identities, accidental-equality assumptions, fork, gap, rollback and extra append;
- proves deterministic restart, response-loss reconstruction, exact replay, conflicting replay, pre-append failure, source-CAS mismatch, and fork/gap/rollback/corrupt/incomplete protected-state handling;
- mutates every correspondence leaf and proves it is digest-covered; and
- checks independently fixed canonical strings, byte lengths and SHA-256 vectors.

These are offline contract tests, not claims of runtime authentication, storage durability, atomicity, or production readiness.

## Bounded independent review and correction

The identity/cryptographic review found the frozen v1.2 route could not be wrapped without retaining its identity contradiction, that the state-head preimage key needed an explicit stored-field mapping, and that actor claims needed the production D9.0.1 verifier. The liveness/crash review found the empty-state timestamp was nondeterministic, the checkpoint preimage was circular, generic D9.4 journal targets were mislabeled as assessments, and protected append/crash outcomes were underspecified. This bounded correction accepts those findings: it uses complete v1.3 messages, exact production-verified bindings, the deterministic empty-state sentinel, generic journal target identities, a noncircular checkpoint preimage, protected receipts, and a closed result/crash matrix. It does not change any frozen artifact.

## Remaining prerequisites

Before D9.4.1 can resume under a separate authorization, implementation must provide:

1. authenticated fixed-function D9.1/D9.2/D9.3/D9.4 source adapters;
2. protected append-only correspondence and correction stores;
3. broker-held atomic source-head CAS and append without an exported race window;
4. exact ordered and unique six-head validation;
5. full pending request and broker-receipt validation before later writes;
6. trusted clock and rollback-resistant state anchoring;
7. independent implementation review; and
8. D9.5 backup, restore, deletion-aware reconstruction, and operational recovery authority.

## Proposal fingerprints

- Catalog: `0aa40744517d595cafca368852771345f52db4c0b2bda36751912607183bcc9a`
- Classifications: `972615f6a1386e29e6d4a10b0018f9c0f50ac8c71a846821a92ad5b75d029d72`
- Digest profiles: `ea210c3606fa180f31fe7fd400515774ccf1a1f04e52490635e79146ab00b0c4`
- Field/source registry: `e6f3501812e7b79e1369a2e70ddff768d577c9439b274eb0543c400f0e4b8de9`
- Storage profiles: `47fb4f4dbbb965823c63b8f0dcceee7afcb55eea2deb9abd27751450e3850553`
- Standalone validator: `49a89a606a133f9778d2329972e94c1bc40cdee9c2a3225c4746cd29ed0f3e0f`
- Root inventory: `51d076dd244aa74c4fc7a433af6ab8121031f4b6194381477460c81ccd807fda`

These identify the proposal bytes. They do not constitute approval, authentication, activation, recovery authority, legal verification, publication eligibility, or operational permission.

The external approval record pins these exact fingerprints without changing them. Approval confirms the separation between independently derived source-state identity, exact journal-tip receipt identity, and their authenticated correspondence. It grants no runtime activation, recovery action, evidence acceptance, legal verification, deletion, restoration, publication, or D9.5 authority.
