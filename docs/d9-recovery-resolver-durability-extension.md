# D9 recovery-resolver durability extension 1.1.0

Status: **approved design-only contract freeze**. Revision `1.1.0` was approved externally at reviewed commit `29157dd584c81ed421dfa52313f0763ce2e0b568`. This compatible extension preserves the approved recovery-resolver `1.0.0` root byte-for-byte. It supersedes only its incomplete checkpoint, durable-record, replay, and assessment-linkage semantics. Approval freezes the exact contract, catalog, registries, inventory, fixtures, validator, and fingerprints at that commit; it neither changes the projection messages nor grants operational authority.

Approval confirms only the protected-checkpoint, durable-attestation, restart-safe-replay, trusted-producer, and recovery-assessment-linkage design. It grants no runtime authority, recovery action, evidence acceptance, legal verification, deletion, restoration, publication, or D9.5 permission. Approval is recorded in documentation and does not modify the fingerprinted `design_only_contract_freeze` root.

## Decision and boundary

Revision `1.0.0` defines correct source-bound requests, responses, projections, and append-time attestations, but names a protected prior-checkpoint store and protected operation journal without defining how either is bootstrapped, advanced, reconstructed, or linked durably to a D9.4 recovery assessment. Revision `1.1.0` closes that gap with three protected append-only namespaces:

- `d9.resolver.records.v1.1` retains exact canonical request, response, and attestation payloads plus their linkage;
- `d9.resolver.checkpoints.v1.1` retains one bootstrap record followed by a gapless checkpoint chain;
- `d9.resolver.assessment-links.v1.1` binds a D9.4 recovery assessment to one exact composite response, append attestation, and checkpoint.

The extension is technical recovery evidence only. It establishes no evidence acceptance, officiality, legal identity, legal status, legal effect, human legal verification, publication eligibility, compliance, cleanup, retry, restore, correction, restriction, deletion, or D9.5 authority.

## Contract inventory

| Artifact | Purpose |
|---|---|
| `common-v1-1.schema.json` | Closed identities, timestamps, source heads, and protected journal heads. |
| `bootstrap-source-observation-v1-1.schema.json` | Six bootstrap-only, double-collected genesis observations that do not depend on a prior checkpoint. |
| `checkpoint-bootstrap-permit-v1-1.schema.json` | One-time, expiring authorization to create the first checkpoint in an empty namespace. |
| `checkpoint-record-v1-1.schema.json` | Immutable bootstrap or advancement record over exactly six source heads. |
| `durable-resolver-record-v1-1.schema.json` | Immutable linkage for each retained v1 request, response, or append attestation. |
| `append-receipt-v1-1.schema.json` | Broker receipt binding expected predecessor, exact payload, and resulting journal head. |
| `append-result-v1-1.schema.json` | Noncanonical operational return distinguishing persistence, exact replay no-op, and rejection without rewriting a receipt. |
| `recovery-assessment-link-v1-1.schema.json` | Exact link from a D9.4 assessment to its composite, attestation, and checkpoint. |
| `classifications-v1-1.json` | Closed states, errors, producers, crash classifications, and authority denial. |
| `digest-profiles-v1-1.json` | Canonicalization and chain/source-set digest profiles. |
| `field-source-registry-v1-1.json` | Trusted producer, consumer, storage, and caller-claim policy. |
| `storage-profiles-v1-1.json` | Namespace ownership, atomic units, retention, reconstruction, and crash rules. |
| `contract-catalog-v1-1.json` | Frozen dependencies, artifact hashes, migrations, and design-only policy. |
| `root-inventory-v1-1.json` | Exact root inventory excluding only itself. |
| `fixtures/*` | Synthetic templates, closed invalid-mutation inventory, and independent golden vectors. |

## Bootstrap without circular trust

The checkpoint namespace must be empty and independently observed as empty. Six bootstrap-only genesis observations double-collect the frozen source namespaces without a prior checkpoint, bind the exact production-verified D9.0.1 generation, and are usable only in the one atomic bootstrap batch. This avoids pretending that an ordinary v1 request—which itself requires a checkpoint—can bootstrap that checkpoint. The authenticated `trusted_launcher` issues one expiring bootstrap permit bound to those six record digests, the exact empty head, operation/nonce, and source heads. The authenticated `independent_verifier` is the checkpoint's semantic actor, and the distinct authenticated `journal_broker` is its persistence actor.

The broker performs one atomic compare-and-append of the permit, sequence-1 checkpoint, and receipt. Existing content, a reused permit, a changed payload, a nonempty predecessor, or response loss followed by changed bytes fails closed. The deterministic initial checkpoint is therefore grounded in observed source state and an empty protected namespace, not in its own future result.

## Advancement and append-time revalidation

An advance record must name the exact current sequence and digest, increment sequence by one, contain the exact six heads from a successful v1 append-time attestation, and bind that attestation and its composite response. The broker revalidates the predecessor immediately before atomic persistence. A lower sequence is rollback; a skipped sequence is a gap; a current sequence with changed bytes is a fork; a changed expected predecessor is a concurrent mutation. None is automatically repaired.

`observed_at` is semantic time from the trusted-launcher clock; `persisted_at` is the broker's durable append time. Persistence must follow observation within the 1,000 ms frozen freshness window and cannot precede the predecessor's persistence time. These times remain distinct and both are reconstructed.

## Durable linkage and replay

Every v1 payload is retained as exact canonical UTF-8 bytes in the resolver-record namespace. Its durable record pins the payload format and digest, request→response→attestation linkage, operation/nonce, subject, exact runtime generation, original payload producer, independent semantic verifier, persistence actor, checkpoint, acceptance time, persistence time, sequence, and predecessor. The catalog also pins the exact approved v1 semantic-verifier path and SHA-256; validator drift fails before that verifier executes. The original producer may equal the persistence service on the frozen D9.3 route; separation applies between the independent semantic verifier and persistence actor, so the contract does not invent a new service identity. A recovery assessment has a separate immutable link to the exact durable wrappers, composite response, attestation, checkpoint, D9.4 assessment receipt/sequence/head, subject, and assessment digest.

Replay decisions use durable state only. Identical canonical bytes at the same identity return the existing immutable receipt plus a new operational `exact_replay_no_op` result only when that receipt names the actual namespace, exact predecessor sequence/digest, payload digest, and resulting record sequence/digest. A self-consistent receipt for another journal position is rejected. Neither the accepted record nor its receipt is rewritten. Reusing a code, operation, sequence, or payload identity with changed bytes is `replay_collision`. A crash before atomic append leaves no accepted record; a response lost after durable append is recovered by exact replay; partial or ambiguous state is `reconciliation_required` and forbids automatic retry.

## Trust and least privilege

All semantic and persistence actors resolve through the exact active D9.0.1 generation. Message fields are not authentication. The launcher owns trusted time and generation selection; the independent verifier owns technical correspondence; the journal broker alone owns the three protected append namespaces. The semantic actor and persistence actor must be distinct. Callers cannot supply source state, actor identity, trusted time, checkpoint state, journal sequence, or outcome through callbacks or arbitrary fields.

This approved design-only contract freeze defines contracts only. It does not allocate handles, implement a broker, add a writer, activate credentials, or resume D9.4.1. A later implementation must fit the already approved least-privilege partitions or stop for a separately versioned authority decision.

## Retention and reconstruction

Reconstruction begins from the empty head, verifies every canonical byte payload and self-digest, walks each sequence and predecessor without gaps, verifies the one-time bootstrap, replays every checkpoint advance, rebuilds request-response-attestation links, and finally verifies every assessment link. Superseded checkpoints and records remain retained. Missing bytes, missing receipts, corruption, forks, gaps, rollback, mixed generations, stale data, or contradictory heads produce no recovery snapshot and require reconciliation.

The contracts describe logical protected storage. They do not select a storage engine, backup medium, or D9.5 procedure. Backup, restore, deletion-aware reconstruction, independent rollback anchoring, and operational recovery authority remain D9.5 work.

## Validation and adversarial matrix

The offline validator pins and verifies the approved v1 validator bytes before reusing its production D9.0.1 generation path, then checks all extension schemas and hashes, exact frozen bindings/source fingerprints, independent canonicalization vectors including a complete append result, exact six-head ordering, bootstrap-only genesis observations, empty-only/no-replace bootstrap, semantic/persistence separation, chronology, permit expiry, freshness, gap/fork/rollback/concurrency rejection, exact payload bytes, payload-producer routes, request/response/attestation linkage, exact-replay/no-op identity and journal position, changed-byte collision, receipt matrices, cross-store assessment linkage, frozen v1.0.0 fingerprints, all predecessor catalogs, and migrations 001–005. A verifier-byte mutation and a self-consistent receipt for the wrong journal position are explicit negative tests.

The mutation inventory covers missing or substituted heads, nonempty bootstrap, permit reuse, wrong roles, changed predecessor, gap, rollback, fork, changed attestation heads, actor collision, payload mismatch, request/response/attestation mismatch, assessment mismatch, replay drift, response loss, stale/future time, corrupt chain, unknown field, authority escalation, and injected legal claims.

## Versioning

The approved `1.0.0` files remain historically valid and unchanged. Approved revision `1.1.0` references them as frozen dependencies and adds durability semantics; it does not rewrite or reapprove them. Revision `1.1.0` is the required design contract for any later, separately reviewed D9.4.1 recovery-assessment persistence implementation. Approval is recorded externally and does not rewrite `design_only_contract_freeze` or activate runtime use.

## Remaining prerequisites

Before D9.4.1 can resume under separate authorization, its implementation must provide authenticated adapters, protected stores, trusted-clock assurance, atomic compare-and-append, crash-safe receipts, independent append-time revalidation, and exact assessment linkage. D9.5 must later provide backup, restore, deletion-aware reconstruction, and recovery authority. No real evidence import or operational bootstrap may rely on this design-only contract freeze by itself.

## Independent review correction pass

The security review rejected circular bootstrap, placeholder source fingerprints, generation-by-integer, conflated producer/verifier/persister roles, and mutable replay disposition. The determinism review additionally rejected unretained payload bytes, unvalidated chains, underconstrained receipts, orphan assessment hashes, and generic-only golden vectors. The bounded correction pass added bootstrap-only genesis observations; exact D9.0.1 generation, role/build/endpoint, and source-profile checks; canonical payload retention; separate original producer, independent semantic verifier, and persistence actor; genuine gap/fork/rollback and link checks; immutable receipts plus separate operational results; D9.4 receipt linkage; cross-store crash states; and a complete independent golden vector. No finding was resolved by widening operational authority.

## Approved integrity anchors

The following values identify the exact reviewed bytes at commit `29157dd584c81ed421dfa52313f0763ce2e0b568`. The catalog pins every schema, registry, fixture, predecessor contract, implementation dependency, and migration; the root inventory pins every file in the contract root except its self-excluded inventory. These hashes are integrity anchors, not authentication or authority.

- Catalog: `aa846c01c5d055050c810249316d11eba7a48d1080681f9538be3e71d371bb26`
- Classifications: `62972ec8950fe4faea53ddb51343f31d3623ca02e159ea5eee41ebcfc2b0903c`
- Digest profiles: `e442c15574f6b7cffcc4f1576ad549ed06f96bf4e14460690a6cbb3182629522`
- Field/source registry: `71b377184580d9f8290e3726fca61505e282a0ac0f0d58c63dc27c891fece406`
- Storage profiles: `5fc9526f0f4cf740057a9036df94e28713ccd73b0479d31ea2b248434ad22cc7`
- Root inventory: `b3711db55ed73a1a74621a808014aae35b2e05319e5cf0aeba5df0d62b1933bf`
- Standalone validator: `f6e8aa1f242198febd6e3b5bfa0a93ddf0f9829bc4850d920a1ca9be941235c5`
- Golden-vector fixture: `a07bc80e56986b57a6106b660c6d11f5ddc7f8ab4dce57f2a790e232327bb326`
- Invalid-contract fixture: `45b538cc79c50962591a913ab46a6f0fb42151436936a7884f7d23cd452d094b`
- Valid-contract fixture: `854cc6e2cc396b90f7c49b6e7a75830ec40cf937169a85dac181ff42df8b9042`
