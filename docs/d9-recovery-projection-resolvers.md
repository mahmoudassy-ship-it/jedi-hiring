# D9 recovery-projection resolver contract freeze

Compatibility note: approved revision `1.0.0` remains frozen here. The separately versioned [durability extension 1.1.0](d9-recovery-resolver-durability-extension.md) is approved as a design-only contract freeze at reviewed commit `29157dd584c81ed421dfa52313f0763ce2e0b568`. It addresses checkpoint bootstrap/advancement, durable journal linkage, replay, and recovery-assessment linkage without modifying this root or granting operational authority.

Status: **approved design-only contract freeze**. Version `1.0.0` was approved externally at reviewed commit `d4f21787ebc4b99e032a9a2966cc828366159447`. The fingerprinted catalog retains the lifecycle-neutral `design_only_contract_freeze` value; approval is recorded in this documentation and must not modify the contract root. The version is isolated under [`docs/schema/d9-recovery-resolvers`](schema/d9-recovery-resolvers/) and changes no frozen D9 contract, migration, approved implementation, database row, runtime service, credential, API, or frontend. The unapproved D9.4.1 work at commit `7c44d7fdea7c398949c0bec3cc9f915c6cb41687` was inspected read-only and remains untouched.

## Approved decision

The separately versioned resolver protocol is approved to allow a future, separately reviewed D9.4.1 recovery classifier to obtain an exact, source-head-bound D9.4 recovery snapshot from the approved D9.1, D9.2, and D9.3 boundaries. Approval freezes messages and validation semantics only. It does not implement a resolver, resume D9.4.1, activate a service, or authorize any recovery action.

## Why this contract is required

D9.4.0 freezes the exact recovery snapshot fields and their digest profiles:

- `journal_namespace_code`;
- `known_through_receipt_sequence`;
- `known_through_persisted_at`;
- `control_ledger_head_receipt_digest_sha256`;
- `control_head_projection_sha256`;
- `access_head_projection_sha256`;
- `subject_lineage_projection_sha256`;
- `inventory_snapshot_sha256`;
- `custody_leaf_projection_sha256`.

The approved predecessors do not define an authenticated request/response protocol that combines those values. The read-only D9.4.1 audit confirmed that `reconstructD941RecoveryState()` deliberately leaves `snapshot_projection` null and `classifyD941Recovery()` returns `D941_RECOVERY_RESOLVER_UNAVAILABLE`. Earlier attempts to brand caller-provided hashes as resolver output were removed because they could create false technical attestations. This proposal closes only that message-contract gap.

## Frozen dependency anchors

The catalog pins, without modifying, the approved D9.0.1 catalog and three semantic fingerprints; the D9.3.0 catalog, classification, digest-profile, field-registry, effective-field-mapping, resolver-projection, and root fingerprints; all five approved D9.4.0 fingerprints; migrations 001–005; and these implementation commits:

- D9.1: `79046c27dfa6923383be33a1d0aaa5a7641f5d1f`;
- D9.2: `460547b7fe75a94f689dabc97fd91ee6f803934a`;
- D9.3.1: `d960a03f4b8ac8a78d3f6b40ba909eb24b5f3442`.

An unknown or substituted dependency fails closed. A future resolver implementation must pin its own reviewed executable builds and exact D9.0.1 identity generation; the contract itself neither creates bindings nor widens the approved handle partitions.

## Contract inventory

| Artifact | Purpose |
|---|---|
| `common-v1.schema.json` | Closed hashes, timestamps, identities, subjects, runtime generation, knowledge boundary, and source-head definitions. |
| `resolution-request-v1.schema.json` | One closed request union for the four resolver kinds. |
| `resolution-response-v1.schema.json` | One closed response union with typed projections and fail-closed non-success results. |
| `append-revalidation-attestation-v1.schema.json` | Separate non-authorizing proof that exact composite heads were reobserved inside the append window. |
| `classifications-v1.json` | Closed routes, result/error vocabulary, source sets, freshness limits, and authority denials. |
| `digest-profiles-v1.json` | Canonical JSON, record/projection/snapshot/idempotency payloads, and deterministic ordering. |
| `projection-profiles-v1.json` | Exact source selection, ordering, prefix completeness, and payload hashing for every projection output. |
| `field-source-registry-v1.json` | Trusted producer, consumer, storage, confidentiality, state class, and caller-claim status by field family. |
| `contract-catalog-v1.json` | Version, frozen dependencies, exact artifact hashes, migrations, and design-only policy. |
| `root-inventory-v1.json` | Exact raw-byte inventory of every regular contract-root file except its self-referential inventory file. |
| `fixtures/*` | Synthetic source state, valid records, invalid mutations, and independently fixed golden values. |
| `validate-d9-recovery-resolvers.mjs` | Offline schema, semantic, mutation, frozen-anchor, migration-integrity, FK, and empty-Atlas validator. |

The fingerprinted catalog lifecycle is permanently neutral: `design_only_contract_freeze`. Approval is external and must never rewrite that value. The schemas reject unknown fields and versions.

## Trust boundary

```text
protected D9.1 state + D9.4 control ledger
          | exact heads, complete projections
          v
  d901_control_access response -----------+
                                          |
accepted D9.2 SQLite + retained manifests | exact subject/generation/operation
          | exact receipt prefix          v
          v                         independent composite verifier
  d920_accepted_evidence response          |
                                          | exact frozen D9.4 snapshot
protected D9.3 journal/receipt stores      v
          | exact heads/receipts      future D9.4.1 classifier
          v                         (classification only; no action)
  d930_custody response ------------------+
```

Every arrow is a future authenticated, fixed-function interaction. A hash does not authenticate a sender. The request and response bind the production-verified D9.0.1 generation, exact reciprocal bindings, endpoints, executable builds, operation, nonce, subject, request digest, idempotency key, trusted time, knowledge boundary, source contract/profile fingerprints, and exact source heads. The offline validator uses the production D9.0.1 verification path against the frozen 19-role synthetic generation before evaluating messages. A future implementation must repeat that verification against the protected active generation and authenticated peer credentials; message fields alone are never authentication.

No new D9.0.1 runtime role is invented. The closed routes use existing identities:

| Resolver | Request route | Response route |
|---|---|---|
| D9.1 control/access | `independent_verifier -> trusted_launcher` | `trusted_launcher -> independent_verifier` |
| D9.2 accepted evidence | `trusted_launcher -> independent_verifier` | `independent_verifier -> trusted_launcher` |
| D9.3 custody | `independent_verifier -> journal_broker` | `journal_broker -> independent_verifier` |
| D9.4 composite | `trusted_launcher -> independent_verifier` | `independent_verifier -> trusted_launcher` |

These routes are protocol ownership, not a grant of filesystem, SQLite, recovery, restriction, deletion, or publication access. Any runtime transport and handle allocation remains a separately reviewed implementation question and must fit the approved D9.0.1 least-privilege partitions.

## Four resolution products

### 1. D9.1 control/access

The response resolves a complete bounded view across the D9.1 protected control/capability state, D9.3 descriptor lifecycle, and the D9.4 global control ledger. It produces only the D9.4 control-head digest, access-shutdown digest, and exact D9.4 journal head fields. Every digest is calculated from the all-and-only source records selected and ordered by `projection-profiles-v1.json`; it is not an opaque caller-supplied hash. The name identifies the control-plane entry point; it does not claim that D9.1 alone owns all source records. The complete cross-source inventory is deliberately derived only by the composite resolver from all six authenticated heads.

### 2. D9.2 accepted evidence

The response resolves the contiguous accepted-bundle prefix, accepted logical-state projection, and all-and-only acyclic subject lineage at the selected bundle sequence. The exact selection and ordering profiles are frozen and independently recomputed from synthetic source state by the validator. It preserves the distinction between technically accepted quarantined evidence and verified legal authority.

### 3. D9.3 custody

The response resolves the exact custody-journal head, complete primary-receipt prefix, and custody-leaf projection. The leaf must match a digest-valid primary receipt field for field, including profile, artifact, copy, backend, and exact SHA-256 fanout path. These outputs use the same frozen projection-profile mechanism. Physical custody and a durability receipt do not establish evidence acceptance, officiality, or legal effect.

### 4. D9.4 composite snapshot

The independent verifier accepts exactly the three preceding immutable response digests in D9.1, D9.2, D9.3 order. It rejects mixed subjects, operations, nonces, runtime generations, profiles, response ages, source heads, or inventory commitments. It alone derives the complete inventory projection from the six authenticated stable heads. A resolved response reproduces the nine frozen D9.4 recovery-snapshot fields byte-for-byte and hashes them with the already approved `d940_recovery_snapshot_v1` field order.

## Source-head, time, and consistency rules

A source head is the immutable tuple:

```text
(namespace, source-contract fingerprint, sequence, head digest,
 persisted time, complete inventory digest)
```

The request receives its prior accepted head from a protected checkpoint, never from a caller. Version 1 requires a resolved observation to equal that complete six-field tuple exactly; a source advance requires a new request with a newly protected checkpoint. Each source inventory digest commits to the exact raw payload families used by that namespace; the head digest commits to namespace, sequence, persistence time, and inventory digest. The projection profiles name each source namespace, raw payload, selected fields, ordering, and completeness rule. A lower sequence is rollback. The same sequence with any changed digest, persisted time, or inventory is a fork or substitution. An unproved higher sequence is a gap. Gaps, collisions, missing heads, future heads, contradictory inventories, and profile substitutions are closed failures.

Each successful resolver performs a double collection:

1. Open and validate the protected source.
2. Record the complete `before` head.
3. Compute the projection from the bounded source prefix.
4. Record the complete `after` head.
5. Return `resolved` only if every before/after tuple is identical.

`known_at` is issued by the trusted-launcher clock. `known_through_receipt_sequence` is a resolver output tied to the source prefix; it is not caller-selected state. Head persistence times cannot be later than `known_at` or actual observation. The response's `observed_at` must equal its earliest `observed_before_at`. Requests live at most 5,000 milliseconds. A resolved response has a 1,000-millisecond revalidation deadline, matching D9.4.0's maximum destructive snapshot age.

Append-time revalidation is a separate immutable attestation, not an inferred response property. Through reviewed fixed-function adapters and broker IPC—not direct backing-store handles—the independent verifier reopens all six protected sources, records their exact heads, and binds the result to the composite response digest, operation, nonce, subject, generation, and reciprocal D9.0.1 identities for the journal broker. `observed_at` and `completed_at` come from the trusted-launcher clock. `revalidated` is valid only when every head equals the composite head and the attestation completes before the deadline. A change produces only `failed/append_revalidation_failed`. The attestation is technical freshness evidence and grants no append or recovery authority. It does not prove that a later broker append met the deadline: a future broker must compare its own trusted acceptance and durable-persistence times with the deadline and reject late persistence.

There is no atomic global transaction spanning the protected D9.1 store, accepted-evidence SQLite database, D9.3 stores, and D9.4 ledger. Version 1 therefore permits only `stable_double_collect_no_atomic_global_snapshot`: each constituent response is independently schema-, digest-, projection-, request-, operation-, nonce-, peer-, generation-, and subject-validated; constituent final heads equal the composite anchors; composite before/after heads equal those same anchors; and the earliest actual before observation through the latest actual after observation fits within one 1,000-millisecond trusted-clock window. This is a bounded consistency observation, not a serializable global snapshot. A constituent failure is propagated deterministically from the first failed constituent in fixed D9.1/D9.2/D9.3 order, including its exact result, error, namespace, stability, and before/after heads; it cannot be relabelled. Composite observation times are fresh trusted-clock observations and are not copied from the constituent. `global_snapshot_unprovable` is a composite-only conclusion. If a consistent view cannot be proven, the only valid outcomes are `unavailable`, `ambiguous`, or `reconciliation_required`; no projection is returned.

## Replay and idempotency

The idempotency key hashes resolver kind, request code, operation/nonce, both exact peers, runtime generation, subject, request/expiry times, knowledge boundary, prior source heads, exact source-profile list, and—for a composite—ordered input response digests. The protected replay key includes request code, idempotency identity, and canonical request bytes. The same request code or idempotency identity with changed canonical bytes is `replay_collision`. A protected response for a request digest/idempotency identity is byte-stable; even a changed `response_code` requires a new request. Request and response self-digests omit only their own top-level `record_digest_sha256`; projection self-digests omit only top-level `projection_sha256`.

## Result and error vocabulary

The closed resolver results are `resolved`, `unavailable`, `ambiguous`, and `reconciliation_required`. Only `resolved` carries a projection and has `error_code=null`. Non-success responses carry no projection and exactly one closed resolver-time error covering unavailable/missing/moving/stale/future/forked/gapped/rolled-back/substituted/contradictory sources, mixed context, replay, or an unprovable global view. Expired requests are rejected before a response, and append failure belongs only to the later attestation. No “partial”, “best effort”, “assumed unchanged”, or placeholder-hash result exists.

## Field ownership and confidentiality

The machine registry is normative. In summary:

- authenticated runtime mapping owns sender, recipient, endpoint, role, build, and generation;
- the trusted-launcher clock owns request, observation, response, completion, expiry, and append deadline times;
- protected checkpoint and source adapters own prior/current heads, sequences, inventory, and prefix facts;
- fixed-function resolvers own projection fields;
- the independent verifier owns composite correspondence;
- reviewed constants own `technical_evidence_only=true` and `authority_granted=false`.

All messages and hashes are restricted operational or highly restricted integrity metadata. They do not belong in Atlas SQLite, public APIs, search, exports, or the frontend. Caller-provided values, arbitrary callbacks, and placeholder hashes cannot become resolver outputs.

## Canonicalization and golden vectors

Version 1 reuses the frozen D9 canonical profile: strict UTF-8, duplicate-key rejection, no Unicode normalization, UTF-16 code-unit object-key ordering, preserved array order, nonnegative safe integers only, ECMAScript string escaping, compact serialization, and no trailing line ending. Fixtures pin three independently fixed micro-vectors, including astral/BMP ordering and escaping, plus a complete composite-response byte length and SHA-256. The validator consumes these constants and never regenerates expected values.

## Threat and mutation matrix

| Mutation or threat | Disposition |
|---|---|
| Missing/unknown field or version | schema rejection |
| Wrong role, endpoint, build, generation, or profile | authenticated-context rejection |
| Subject or operation substitution | context rejection |
| Reordered source heads or composite inputs | deterministic-order rejection |
| Missing/stale/future/moving source | closed non-success; no projection |
| Lower sequence or same sequence/new digest | rollback/fork rejection |
| Gap or prefix mismatch | source/projection mismatch |
| Mixed source responses | composite rejection |
| Response replay with changed bytes | replay collision |
| Expired request or stale append | rejection and new resolution required |
| `authority_granted=true` or `technical_evidence_only=false` | schema rejection |
| Attempt to treat snapshot as cleanup/retry/restore/deletion/legal authority | capability-boundary rejection |

The offline validator exercises all these classes with synthetic data, including the production D9.0.1 identity verifier, reciprocal peers, genuine resealed replay collisions, mixed-operation composites, constituent-response tampering, exact six-field head correspondence, raw-payload-to-source-head commitments, source-access store-head recomputation, exact one-to-one capability/terminal and descriptor/leaf shutdown completeness, receipt/leaf correspondence, unique and fully grounded lineage with recomputed node/edge store heads, exact failure propagation, actual observation windows, projection recomputation, and append-attestation failure. It also verifies each pinned implementation file from its declared commit with `git show`, pins frozen contract/migration bytes, applies migrations 001–005 to a disposable database, runs SQLite integrity and foreign-key checks, and proves all 13 Atlas tables remain empty.

## Independent review correction pass

The security/least-privilege and determinism/source-binding reviews rejected the initial draft's message-only identity checks, partial replay identity, unvalidated constituent responses, unbound observation time, pre-projected hash fixtures, simulated append revalidation, unbound raw projection inputs, and underconstrained composite failures. One bounded correction pass accepted and corrected every concrete blocker: production-path D9.0.1 identity verification; exact reciprocal peers; complete replay identity; complete constituent/composite validation; exact head equality; raw payload commitments in every source inventory/head; frozen D9.4-compatible projection shapes derived by executing selection, ordering, store-head, exact shutdown completeness, unique grounded lineage, subject, receipt, and prefix rules; deterministic failure propagation including stable contradictions; implementation-path hashing at approved commits; explicit trusted-clock ownership; and a separate append-time attestation. The suggestion to create runtime access was rejected as out of scope: handles, activation, protected checkpoints, and real source adapters remain prerequisites.

## Explicit non-authority statement

The output is technical recovery evidence only. It establishes no evidence acceptance, officiality, legal identity, issuer identity, jurisdiction, legal status, binding force, legal effect, legal verification, publication eligibility, compliance, or legal advice. It grants no cleanup, retry, restore, correction, restriction, deletion, publication, or D9.5 authority. Recovery remains classification-only. A future D9.4.1 implementation must still produce the frozen D9.4.0 recovery assessment through its approved independent-verifier/journal-broker separation and must fail closed if any resolver is unavailable.

## Remaining prerequisites

Approval leaves these separate and unimplemented:

1. exact least-privilege IPC/handle allocation compatible with D9.0.1;
2. authenticated runtime activation and protected checkpoint storage;
3. real source adapters that independently validate complete prefixes and inventories;
4. rollback-resistant source-head anchoring and operational trusted-clock assurance;
5. append-time multi-source revalidation integrated with the D9.4 journal broker;
6. alerting and human reconciliation for every non-success outcome;
7. resumed D9.4.1 implementation and tests under a separately approved task;
8. all D9.5 backup/restore work.

No resolver should run against canonical data until those controls are implemented and separately reviewed.

## Approved fingerprints

- Catalog raw SHA-256: `df33cbf575f8f4b430ef22384f0d73350e521abed6443f07006d13bb3b968ba3`
- Classifications raw SHA-256: `9f137c1ca9905b5a02754292a1b828bbdd7174af78bd385b3b4a3584fd1abe04`
- Digest profiles raw SHA-256: `b7adfc736b04ef5c657e94bf2a621a602e518165cbf9b08f2b3c0653963abf90`
- Field/source registry raw SHA-256: `d6f9ec22ae8fdb6bbb998374680f13a89f02ffef2431d9eb8c6003294a3db1d8`
- Projection profiles raw SHA-256: `c9c7a09c4a29814b1a6b55112e9b11075f1e1cc654e393561e6e3d79ad1ae6ff`
- Root inventory raw SHA-256: `93832dc8a6f12ae030515781169fd8ac9dd5431aa68f62699168469da3da6f31`

These exact fingerprints are approved as the version `1.0.0` design-only contract freeze at commit `d4f21787ebc4b99e032a9a2966cc828366159447`. They are contract-integrity anchors, not authentication, activation, recovery authority, legal verification, publication eligibility, or operational permission.
