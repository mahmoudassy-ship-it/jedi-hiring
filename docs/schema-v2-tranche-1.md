# Tranche 1 foundation schema — exact physical specification

Status: proposed for approval; not a production migration. The executable counterpart is [`schema/tranche-1-foundations.proposed.sql`](schema/tranche-1-foundations.proposed.sql). It creates 45 `atlas_*` tables, 16 named indexes, and 56 named triggers. Counts are generated from the DDL in a temporary SQLite database.

Scope is limited to principals/reviewer authority, review-policy definitions, territorial jurisdictions/memberships, non-territorial coverage, and controlled vocabularies. It contains no instruments, sources, provisions, propositions, content reviews, publication decisions, monitoring records, backfill, API, frontend, credentials, or substantive legal assertions. Existing v1 objects are untouched.

## Conventions and lifecycle

`NN` means `NOT NULL`; omitted defaults mean no default. Dates are ISO `YYYY-MM-DD`, UTC timestamps are ISO-8601 text, `valid_from` is inclusive, and `valid_to` is exclusive/null for open-ended. All foreign keys use `ON UPDATE RESTRICT ON DELETE RESTRICT`. Stable identities may change display metadata but are not deleted after reference. Version/history rows are immutable or append-only. Interval overlap is `existing.valid_from < COALESCE(new.valid_to,'9999-12-31') AND new.valid_from < COALESCE(existing.valid_to,'9999-12-31')`.

## Exact table catalog

### Principals, roles, and qualifications

| Table and purpose | Exact columns, constraints, behavior, indexes | Future references |
|---|---|---|
| `atlas_principals` — auditable human/service identity, never credentials | `id INTEGER PK`; `principal_code TEXT NN UNIQUE`; `principal_kind_code TEXT NN CHECK human/service`; `display_name TEXT NN`; `external_subject TEXT UNIQUE`; `is_active INTEGER NN DEFAULT 1 CHECK 0/1`; `created_at TEXT NN`; `retired_at TEXT CHECK null or > created_at`. Stable mutable identity; restricted deletes. | reviews, authorship, publication, monitoring actors |
| `atlas_review_roles` — authority role vocabulary | `id PK`; `role_code TEXT NN UNIQUE`; label/description NN; `eligible_principal_kind_code CHECK human/service/either`; `is_human_review_role NN CHECK 0/1`; `is_publication_role NN DEFAULT 0 CHECK 0/1`; `is_active NN DEFAULT 1`; CHECK human gates and publication roles are human. Structural rows mutable by deprecation. | grants, policy requirements, review decisions |
| `atlas_principal_role_grants` — immutable time-bounded grants | `id PK`; principal, role, grantor FKs NN; `valid_from TEXT NN`; `valid_to TEXT`; `granted_at`, `rationale` NN; UNIQUE principal/role/from; valid interval CHECK. Immutable UPDATE/DELETE and overlap triggers; named `as_of` index. Principal-kind trigger rejects service grants to human roles. | reviewer authorization checks |
| `atlas_principal_role_revocations` — append-only early revocation | `id PK`; grant/grantor FKs NN; `revoked_on`, `recorded_at`, reason NN; UNIQUE grant/revoked date. Append-only triggers; grant/date index. | authorization checks at `as_of` |
| `atlas_qualification_types` — evolving qualification vocabulary | `id PK`; stable `qualification_type_code TEXT NN UNIQUE`; label/description NN; active boolean. Mutable by deprecation. | assertions, policy requirements |
| `atlas_qualification_assertions` — immutable scoped qualification claim/verification | `id PK`; principal/type/assertor FKs NN; verifier FK nullable; status CHECK asserted/verified/rejected; inclusive/exclusive validity; asserted timestamp NN; verified timestamp; supersedes self-FK; evidence reference; status/verifier consistency, interval and no-self-supersession CHECKs. Immutable triggers; principal/type/as-of index. | future exact-version review eligibility |
| `atlas_qualification_revocations` — append-only revocation | `id PK`; assertion/revoker FKs NN; revoked/recorded timestamps and reason NN; UNIQUE assertion/revoked date. Append-only triggers; assertion/date index. | eligibility predicate |
| `atlas_qualification_jurisdictions` | assertion/jurisdiction FKs NN composite PK. Immutable in practice; deletion restricted. | jurisdiction-matched gates |
| `atlas_qualification_coverage_scopes` | assertion/coverage FKs NN composite PK. | coverage-scoped gates |
| `atlas_qualification_subject_areas` | assertion/subject-area subtype FKs NN composite PK. | subject-matched gates |
| `atlas_qualification_languages` | assertion/language subtype FKs NN composite PK. | translation gates |

An assertion is effective at caller-supplied `as_of` only when verified, `valid_from <= as_of < valid_to` (or open), not superseded by an effective verified assertion, and without a revocation effective on/before `as_of`. Missing scope never implies qualification.

### Review-policy computation

| Table and purpose | Exact columns, constraints, behavior, indexes | Future references |
|---|---|---|
| `atlas_review_policies` — stable transition identity | `id PK`; `policy_code TEXT NN UNIQUE`; `transition_code TEXT NN UNIQUE CHECK candidate_to_draft/proposition_to_public`; label/description NN; active boolean; created timestamp NN. | content workflows |
| `atlas_review_policy_versions` — immutable effective policy | `id PK`; policy FK NN; `version_number INTEGER NN CHECK >0`; valid interval; 64-char `content_hash`; created timestamp/optional creator; UNIQUE policy/version and policy/from; immutable triggers; policy/as-of index. Later versions may supersede an open-ended earlier version without mutating it. | future decisions must pin this ID |
| `atlas_review_policy_version_seals` — append-only completion seal | policy-version PK/FK; sealed timestamp; optional sealer FK; canonical payload hash. Append-only triggers; once present, requirement/separation inserts are rejected. | policy selection and future decisions |
| `atlas_review_gates` — gate vocabulary | `id PK`; stable `gate_code UNIQUE`; label/description NN; active boolean. | policy requirements, future review results |
| `atlas_review_policy_requirements` — computable gate requirements | `id PK`; policy-version/gate/role FKs NN; optional qualification-type FK; `condition_code CHECK always/national_material/non_authoritative_translation`; `minimum_approvals >0`; human-only, qualification-required, jurisdiction-match and non-waivable booleans; optional positive maximum age; positive sequence; UNIQUE policy/gate and policy/sequence; qualification and jurisdiction consistency CHECKs. Human-only trigger prevents service/either gate roles. Policy/sequence index. | gate evaluator |
| `atlas_review_policy_separation_rules` — non-waivable separation of duty | `id PK`; policy-version, left/right role FKs NN; `rule_code CHECK different_principal`; `is_non_waivable CHECK =1`; UNIQUE policy/role pair; canonical `left_role_id < right_role_id` CHECK rejects self/reversed duplicates. | reviewer assignment evaluator |

The applicable policy version is the sealed row where `policy_code = ?`, `valid_from <= :as_of`, and (`valid_to IS NULL OR :as_of < valid_to`), ordered by `valid_from DESC, version_number DESC, id DESC LIMIT 1`. Latest-valid-from precedence makes selection deterministic without mutating an earlier open-ended version. Future publication decisions must store the exact `atlas_review_policy_versions.id` and evaluated sealed hash.

Seeded transition policies are:

- `candidate_to_draft`: independent, qualified, human official-source verification.
- `proposition_to_public`: non-waivable source, substantive legal, editorial/data-quality/accessibility and publication gates, plus conditional local-jurisdiction and translation gates. Separation rules require author ≠ substantive reviewer, author ≠ publisher, and substantive reviewer ≠ publisher.

There is no general bypass. Service principals remain auditable but cannot satisfy these human gates.

### Territorial jurisdiction and membership

| Table and purpose | Exact columns, constraints, behavior, indexes | Future references |
|---|---|---|
| `atlas_jurisdictions` — stable territorial identity | `id PK`; `jurisdiction_code TEXT NN UNIQUE`; kind CHECK supranational/state/regional/devolved/local; active boolean; created timestamp. No membership inference. | instruments, proposition scope, reviewer scope |
| `atlas_jurisdiction_versions` — immutable names/descriptions | `id PK`; jurisdiction FK NN; name NN; description; valid interval; content hash NN length 64; created timestamp/creator; UNIQUE jurisdiction/from; overlap and immutable triggers; as-of index. | localized display and historical lookup |
| `atlas_jurisdiction_containments` — territorial containment only | `id PK`; parent/child FKs NN; valid interval and recorded timestamp; UNIQUE parent/child/from; no-self and interval CHECKs. Insert triggers reject overlapping parentage and cycles; parent/child as-of indexes. Rows are historical assertions; correction is new interval. | territorial resolution |
| `atlas_membership_types` — association vocabulary | `id PK`; stable code UNIQUE; label/description; active boolean. | membership facts |
| `atlas_jurisdiction_memberships` — time-bounded EU/EEA/other association | `id PK`; member/organization/type FKs NN; valid interval, recorded timestamp; UNIQUE member/organization/type/from; no-self and interval CHECKs; overlap trigger; member and organization as-of indexes. | applicability context after sourced facts exist |

No membership facts are seeded because source-dependent authority records arrive later. Missing containment or membership means unknown/not recorded, never non-membership or equivalent law.

### Non-territorial coverage

| Table and purpose | Exact columns, constraints, behavior, indexes | Future references |
|---|---|---|
| `atlas_coverage_scopes` — stable non-territorial scope identity | `id PK`; `coverage_scope_code TEXT NN UNIQUE`; kind CHECK sector/employer_size/employer_type/collective_agreement/personal; active boolean; created timestamp. | applicability, qualifications |
| `atlas_coverage_scope_versions` — immutable scope meaning | `id PK`; scope FK NN; label/definition NN; valid interval; 64-char hash; created timestamp/creator; UNIQUE scope/from; overlap/immutable triggers; as-of index. | historical applicability |
| `atlas_sector_scopes` | `coverage_scope_id INTEGER PK/FK`. Type-safe marker. | sector predicates |
| `atlas_employer_size_scopes` | scope PK/FK; nullable nonnegative min/max workers; CHECK max ≥ min. | threshold predicates |
| `atlas_employer_type_scopes` | scope PK/FK. | employer-type predicates |
| `atlas_collective_agreement_scopes` | scope PK/FK. | agreement coverage predicates |
| `atlas_personal_scopes` | scope PK/FK. | personal coverage predicates |

The application must insert exactly one matching subtype; future migration may add deferred validation for completeness. Coverage never occupies the territorial hierarchy.

### Shared vocabulary with type-safe subtypes

| Table and purpose | Exact columns, constraints, behavior, indexes | Future references |
|---|---|---|
| `atlas_taxonomy_types` | `id PK`; type code UNIQUE; label/description; active boolean. | terms |
| `atlas_terms` | `id PK`; taxonomy FK; `term_code`; active boolean/default; created timestamp; UNIQUE taxonomy/code; type/code index. | term versions/subtypes |
| `atlas_term_versions` | `id PK`; term FK; label/definition; valid interval; 64-char hash; created timestamp/creator; UNIQUE term/from; overlap/immutable triggers; as-of index. | localized labels, historical display |
| `atlas_languages` | `term_id PK/FK`; `bcp47_code UNIQUE` length 2–35; subtype trigger. | translations/labels/qualifications |
| `atlas_hiring_stages`, `atlas_legal_lenses` | `term_id PK/FK`; positive unique `display_order`; subtype triggers. | proposition assignment junctions |
| `atlas_actor_types`, `atlas_normative_roles`, `atlas_protected_grounds`, `atlas_data_categories`, `atlas_lifecycle_states`, `atlas_subject_areas` | each `term_id PK/FK` with subtype trigger. | type-safe future FKs; grounds remain distinct from data categories |
| `atlas_term_labels` | `id PK`; term-version/language subtype FKs; label; preferred boolean/default; UNIQUE version/language/label. | multilingual display |
| `atlas_term_aliases` | `id PK`; term/language FKs; alias; valid interval; UNIQUE term/language/alias/from; alias/as-of index. | search normalization |
| `atlas_term_replacements` | `id PK`; old/new term FKs; valid-from; reason; UNIQUE old/new/from; no-self CHECK. | deprecation redirects |
| `atlas_term_change_events` | `id PK`; term/optional actor/optional before/after version FKs; kind CHECK created/versioned/deprecated/replaced/reactivated; changed timestamp/reason. Append-only triggers and term/date index. | audit/history |

Structural seeds include the approved stages, lenses, actor types, normative roles, protected grounds, data categories, `en`, lifecycle states, subject areas, review roles/gates/qualification types, and two policy definitions. These are classifications, not legal propositions or membership facts.

## Trigger inventory and update/delete rules

Named triggers enforce jurisdiction cycles and overlapping containment/membership; overlapping role grants and term, jurisdiction, and coverage versions; principal-kind compatibility; human-only gates; sealed policy composition; type-safe taxonomy/coverage subtypes; immutability of version/grant/assertion rows; and append-only revocation/change histories. UPDATE support for interval-bearing assertions is intentionally absent: corrections create successor rows or revocations. Future references use restricted deletion so history cannot be orphaned.

The 16 additional named indexes are `atlas_principal_role_grants_as_of_idx`, `atlas_principal_role_revocations_as_of_idx`, `atlas_qualification_assertions_as_of_idx`, `atlas_qualification_revocations_as_of_idx`, `atlas_terms_type_code_idx`, `atlas_term_versions_as_of_idx`, `atlas_term_aliases_lookup_idx`, `atlas_term_change_events_term_at_idx`, `atlas_jurisdiction_versions_as_of_idx`, `atlas_jurisdiction_containments_child_as_of_idx`, `atlas_jurisdiction_containments_parent_as_of_idx`, `atlas_jurisdiction_memberships_member_as_of_idx`, `atlas_jurisdiction_memberships_organization_as_of_idx`, `atlas_coverage_scope_versions_as_of_idx`, `atlas_review_policy_versions_as_of_idx`, and `atlas_review_policy_requirements_policy_idx`. All other lookup enforcement uses SQLite indexes generated by PK and UNIQUE constraints; no unstated application index is assumed.

## Validation result required before migration approval

Execute the proposed SQL against a disposable database containing migrations 001–003, compute v1 row digests before/after, enumerate `sqlite_master`, run integrity/FK checks, and run negative tests for cycles, intervals, stable-code uniqueness, immutable/append-only mutation, principal/gate compatibility, qualification effectiveness, separation rules, and policy selection. This file is not copied into `data/migrations` until separately approved.
