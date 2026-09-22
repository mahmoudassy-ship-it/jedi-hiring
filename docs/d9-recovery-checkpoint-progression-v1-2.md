# D9 recovery checkpoint progression correction 1.2.0

Status: **design-only proposal awaiting approval**. Revision `1.2.0` is an additive, separately versioned correction. It does not modify or reapprove the frozen resolver `1.0.0` or durability `1.1.0` roots. It supersedes only the post-assessment checkpoint-progression rule that otherwise deadlocks after the first persisted D9.4 assessment.

This proposal proves technical journal continuity only. It grants no recovery action, evidence acceptance, officiality, legal identity, legal status, legal effect, legal verification, deletion, restoration, publication eligibility, compliance conclusion, runtime activation, credential authority, or D9.5 authority.

## Confirmed liveness conflict

The frozen contracts correctly fail closed but cannot progress after a successful assessment:

1. resolver `1.0.0` requires every current source head to equal its protected checkpoint;
2. durability `1.1.0` allows a checkpoint advance only from a successful append-time attestation;
3. the attestation observes the pre-append source heads;
4. persisting the exact D9.4 assessment then advances `d940.global.control-journal.v1`;
5. the prior checkpoint no longer equals the current source set; and
6. another resolver operation cannot create the attestation that `1.1.0` requires for another advance.

Relaxing head equality or accepting an unexplained higher sequence would hide concurrent writes and is rejected. Revision `1.2.0` instead proves one exact state transition from the attested baseline through one authorized assessment append to its durable resulting head.

## Narrow correction

The evidence chain is:

```text
v1.1 checkpoint
  -> exact component resolution attestations
  -> exact composite response and append attestation
  -> protected v1.2 assessment-append request
  -> exact D9.4 assessment append
  -> durable D9.4 append receipt
  -> protected v1.2 broker receipt
  -> fixed-function finalizer
  -> protected v1.2 checkpoint transition
  -> next effective checkpoint
```

“Component resolution attestation” means the exact frozen v1 resolved response plus its v1.1 durable wrapper for each of `d901_control_access`, `d920_accepted_evidence`, and `d930_custody`. It does not create a new legal, review, or authority claim. The composite append attestation remains the frozen v1 append-revalidation record.

The prior `1.1.0` checkpoint remains immutable and auditable. The first `1.2.0` transition references both its exact record and protected append receipt. Every later transition references the immediately preceding `1.2.0` transition and its append receipt. A resolver operating under this correction uses the latest valid receipt-bound transition as its effective checkpoint; it never rewrites the `1.1.0` chain.

## Contract inventory

The isolated root is [`docs/schema/d9-recovery-resolvers-v1-2`](schema/d9-recovery-resolvers-v1-2/).

| Artifact | Purpose |
|---|---|
| `common-v1-2.schema.json` | Closed checkpoint, component-attestation, append-position, progression-head and single-D9.4-delta definitions. |
| `assessment-append-request-v1-2.schema.json` | Exact authorization envelope binding the attested baseline, exact assessment bytes, expected D9.4 predecessor/sequence and freshness deadline. |
| `assessment-append-broker-receipt-v1-2.schema.json` | Broker-persisted evidence binding the request and D9.4 receipt to an independently observed post-append head derived under frozen v1 semantics. |
| `checkpoint-transition-v1-2.schema.json` | The only record allowed to advance the effective checkpoint from the attested baseline to the exact receipt-proved resulting head. |
| `protected-append-receipt-v1-2.schema.json` | Gapless compare-and-append receipt for the two new protected namespaces. |
| `finalization-result-v1-2.schema.json` | Noncanonical operational result for persistence, exact replay, not-yet-appendable, reconciliation or rejection. |
| `classifications-v1-2.json` | Closed actors, outcomes, errors, progression rules, restart matrix and non-authority boundary. |
| `digest-profiles-v1-2.json` | Exact canonicalization, frozen-v1 raw-payload head derivation, source-set, delta and journal-chain profiles. |
| `field-source-registry-v1-2.json` | Trusted producer, consumer, storage and caller-claim policy for every field family. |
| `storage-profiles-v1-2.json` | Append-only namespace ownership, reconstruction order and crash rules. |
| `contract-catalog-v1-2.json` | Version boundary, frozen dependencies, artifact hashes, migration hashes and disabled capabilities. |
| `root-inventory-v1-2.json` | Complete content-addressed inventory excluding only itself. |
| `fixtures/*` | Synthetic valid inputs, closed mutation inventory and independently fixed canonical SHA-256 vectors. |
| `validate-d9-recovery-resolvers-v1-2.mjs` | Offline schema, semantics, state-machine, mutation, frozen-dependency and inventory validator. |

## Protected storage and atomic units

Revision `1.2.0` adds two logical namespaces; it does not select or implement a storage engine:

- `d9.resolver.progression-intents.v1.2` retains each exact assessment-append request and its exact broker receipt. Each payload and its protected append receipt are one atomic compare-and-append unit.
- `d9.resolver.checkpoint-transitions.v1.2` retains the gapless transition chain. Each transition and its protected append receipt are one atomic compare-and-append unit that also compares the exact current D9.4 source head at persistence time.

Both namespaces are append-only, no-replace and journal-broker-owned. Exact retained bytes may replay as a no-op only after complete projection verification. A reused digest, code, operation, sequence, predecessor or idempotency identity with different bytes is a conflict. Partial or ambiguous persistence is reconciliation-required.

## Exact append request

The independent verifier constructs the request only after it has verified:

- the prior checkpoint sequence, digest, ordered six-head set and source-set digest;
- the three exact component response and durable-wrapper digests in fixed D9.1/D9.2/D9.3 order;
- the exact composite response and durable-wrapper digests;
- the exact composite append-attestation and durable-wrapper digests;
- the exact canonical D9.4 assessment bytes, code, digest, operation, nonce and subject;
- classification-only fields (`action_execution_code=none_classification_only`, no recovery authority);
- the D9.4 namespace, exact current receipt sequence/digest, target sequence `predecessor + 1`, and exact assessment target;
- the active runtime generation, profile, binding, role, endpoint and executable build; and
- trusted authorization and append-revalidation deadline times.

The request does not authorize an arbitrary journal write. The journal broker may append only the embedded assessment at the exact requested predecessor and sequence before the frozen append deadline.

## Durable broker receipt

The broker receipt retains the canonical D9.4 append receipt and binds it to the request. The underlying D9.4 receipt must prove:

- the same operation, nonce, subject and assessment digest;
- the requested prior receipt digest and next sequence;
- the authenticated semantic and persistence actors;
- the exact assessment persistence time; and
- the frozen D9.4 durability state.

The D9.4 receipt proves the exact assessment append, but it is not itself the resolver source head. The post-append head is independently observed and derived using the frozen v1 `raw_payload_commitments` algorithm: exact source payload bytes determine the inventory digest, and namespace, sequence, persistence time and inventory determine the head digest. The independent verifier authenticates that observation; the journal broker persists it. A client-provided hash or a locally invented rolling digest is never sufficient.

## Checkpoint transition

A valid transition binds every item named above plus:

- the append-request and broker-receipt digests plus both protected append-receipt digests;
- all six exact pre-append and post-append heads;
- the five non-D9.4 namespace codes in fixed binary order, each byte-identical before and after;
- the single permitted D9.4 `+1` sequence delta;
- the exact D9.4 receipt digest and persistence time plus the independently recomputed frozen-v1 post-head digest and inventory digest;
- finalizer, semantic-verifier and persistence-broker identities;
- attestation, authorization deadline, assessment persistence, finalizer observation and transition persistence times;
- prior checkpoint sequence/digest and new sequence `prior + 1`; and
- the new ordered post-head set and its digest.

The assessment must have been persisted within the append-attestation deadline. Finalization may occur later after a restart because it creates no new assessment or journal fact, but it must re-read every durable input and prove that the exact post-append head is still current. The protected transition append performs that source-head comparison again in the same persistence boundary as the transition-journal compare-and-append. Any later append, even otherwise valid, makes automatic finalization unavailable rather than creating a time-of-check/time-of-use window.

There is no arbitrary checkpoint catch-up. Extra, missing, reordered, substituted, concurrent or unexplained head movement fails closed. In particular, the finalizer cannot skip multiple D9.4 receipts, synthesize a missing receipt, infer a post head, or bless a changed D9.1/D9.2/D9.3 head.

## Restart and crash behavior

| Durable state | Deterministic result | Fixed-function behavior |
|---|---|---|
| Attestation/request durable; assessment absent | `not_yet_appendable` | No transition. A separately authenticated broker path may still execute the exact unexpired request. |
| Assessment and D9.4 receipt durable; broker response lost | reconstruct exact broker receipt | Read the protected D9.4 assessment/receipt, verify the request and current head, then persist the exact broker receipt. |
| Assessment, D9.4 receipt and broker receipt durable; transition missing | finalize exact transition | Persist only the transition deterministically derived from those records. |
| Transition durable; response lost | `exact_replay_no_op` | Return the retained protected receipt; do not append again. |
| Same identity with changed bytes | `replay_collision` | Reject. |
| Another append before transition | `reconciliation_required` | Reject automatic finalization; do not catch up. |
| Missing, corrupt, forked, gapped, rolled-back, stale, incomplete or contradictory records | `reconciliation_required` | No automatic append, repair or recovery action. |

The finalizer can complete only the broker receipt or transition missing from an otherwise exact durable chain. It cannot create assessment content, change an assessment, authorize a new append, infer an unexplained head, retry a failed recovery action, delete, restore or perform D9.5 work.

## Two consecutive assessments

The offline validator proves the intended liveness path:

1. operation A resolves against an exact schema-valid, protected-receipt-bound `1.1.0` checkpoint whose source heads reproduce the frozen v1 raw-payload derivation, appends one exact D9.4 assessment and creates transition A;
2. transition A becomes the effective checkpoint, including the receipt-proved D9.4 post head;
3. operation B resolves against transition A, appends one further exact assessment and creates transition B; and
4. both transitions remain predecessor-bound, gapless and replay-stable.

The validator constructs genuine frozen-v1 request/response/attestation records and v1.1 durable wrappers, binds each assessment snapshot to the exact composite projection, applies the frozen D9.4 classification and receipt rules, and derives both post heads from the pinned raw source state. It rejects component/order substitution, changed assessment bytes, wrong producers/builds/generations, wrong predecessor/sequence/receipt, changed non-D9.4 heads, multiple deltas, D9.4 gaps/rollback/forks, source-head CAS races, wrong receipt context, partial persistence, exact-identity byte conflicts, unknown fields and authority escalation. Declared invalid fixtures are executed, and golden vectors compare canonicalized inputs to independently fixed strings and SHA-256 values.

## Trust boundary

Message fields are not authentication. Future implementation must authenticate the exact active D9.0.1 generation and kernel/IPC peer before accepting any record:

- `trusted_launcher` owns active-generation selection, trusted time and fixed-function finalizer orchestration;
- `independent_verifier` owns exact correspondence and transition semantics;
- `journal_broker` alone owns both new protected namespaces and the D9.4 append;
- frozen D9.1/D9.2/D9.3 adapters own their source facts; and
- the authenticated D9.4 source adapter exposes raw source state, while `independent_verifier` owns the frozen-profile post-head observation and `journal_broker` owns its durable receipt.

Semantic verifier and persistence broker remain distinct. The broker receipt is technical durability evidence, not independent verification. No actor gains a general checkpoint, D9.4 journal, recovery or legal-authority handle from this design.

## Canonicalization and fingerprints

All canonical records use UTF-8, no Unicode normalization, UTF-16 code-unit ascending object keys, preserved array order, duplicate-key rejection and nonnegative safe integers. Every record self-digest excludes only its own top-level `record_digest_sha256`. Canonical embedded assessment and D9.4 receipt strings must reparse to byte-identical canonical content.

The catalog pins frozen v1/v1.1 roots, their semantic validators, the D9.4 semantic validator, D9.0.1/D9.3.0/D9.4.0 catalogs, implementation commits, migrations `001–005`, and this revision's effective validator. The root inventory pins every new contract artifact except itself. Exact proposal fingerprints are generated from the completed reviewed files and recorded below before approval.

## Proposal fingerprints

- Catalog: `b6fd085a5718fdccc51ae4cfbf10645aaa3a1f79929d9ebe896247350d3ddb3c`
- Classification: `ba84bef36d9026978cbfdb83da1e327fed4ff77194a0a85a87000c8b7e36a080`
- Digest profiles: `d2f0abe41f0a6b56d870744d4929b7544a311df84ca05b416420886b29a259d6`
- Field-source registry: `ef058880ae16ed47bc8ade75839d1118a5beb718482025af49d141e173ebac6c`
- Storage profiles: `8425ca7279b297375e0e52db392cf692516b5bf2ace7e6145daf96d3a34d3bf0`
- Valid synthetic fixture: `23c484694d611f5d9afe494863e033eab719d2b6e5ceb5c282f23c558959fdca`
- Effective validator: `4708ae4c43fe8bfd83e13e216b1d5fc8fc15077e6ec38e24eda78f0b859f5ad7`
- Root inventory: `3bc242bbd7147597e9b34aad16293d8e397cb23d4b7b7a6ca3578b371403c1ad`

Approval, if later granted, must be recorded externally and must not rewrite the fingerprinted `design_only_contract_freeze` root.

## Independent review and bounded correction

The security/liveness review and the independent determinism/crash review both rejected the baseline draft despite green checks. Their concrete findings were accepted: invented rolling head semantics, partial D9.4 validation, an arbitrary checkpoint digest, missing authenticated post-head production, transition TOCTOU exposure, digest-only replay handling, descriptive-only invalid fixtures, incomplete golden-vector testing, an unpinned effective validator and an open result matrix. One bounded correction pass replaced those mechanisms with the receipt-bound and frozen-semantics design described above. No review finding was rejected. Real filesystem durability, authenticated IPC and multiprocess atomicity remain implementation prerequisites rather than design-validator claims.

## Implementation and approval boundary

This branch contains contracts, synthetic fixtures, documentation and an offline validator only. It does not resume D9.4.1, implement a finalizer or broker, allocate handles, activate services, create credentials, write Atlas rows, import evidence, process legal data, perform recovery/deletion/restoration, add migrations, or alter the API/frontend.

After approval, D9.4.1 would require a separately reviewed implementation correction that consumes this exact version. D9.5 backup, restore and operational recovery authority remain separate future work.
