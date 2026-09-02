# Minimal Tranche 1A authority-entry foundations

Status: proposed, not a production migration. Both earlier physical proposals (45 tables and 7 tables) are rejected and superseded in Git history. The current proposal contains exactly four empty `STRICT` tables in [the proposed SQL](schema/tranche-1-foundations.proposed.sql) and is validated by [the committed harness](schema/validate-tranche-1a.mjs).

Its sole purpose is to provide stable attribution, language identity, jurisdiction identity, and correction-safe jurisdiction naming needed by the next authority/source tranche. Until that tranche provides quarantine and the later review-governance slice provides gates, no `atlas_*` row may be inserted operationally, reviewed, published, exported, or exposed by an API. The existing frontend remains explicitly v1-backed.

## Physical schema

All FKs use `ON UPDATE RESTRICT ON DELETE RESTRICT`. Dates are canonical `YYYY-MM-DD`; timestamps are canonical UTC `YYYY-MM-DDTHH:MM:SS.sssZ`. Checks include UTF-8 byte length through `CAST(value AS BLOB)`, embedded-NUL rejection, shape validation, and date/time round trips. The proposed body has no transaction control; the real migration runner owns the transaction and enables/asserts foreign keys and recursive triggers.

### `atlas_principals`

Atlas editorial/service attribution identity only—not candidates, client personnel, credentials, authentication, authorization, role, or qualification.

| Column | Definition |
|---|---|
| `id` | `INTEGER PRIMARY KEY` |
| `principal_code` | nonempty canonical lowercase `TEXT NOT NULL UNIQUE`, 1–80 bytes, `[a-z0-9._-]`, no whitespace edge/NUL |
| `principal_kind_code` | `TEXT NOT NULL CHECK ('human','service')`; immutable kind |
| `created_by_principal_id` | self-FK `INTEGER NOT NULL`; attribution |
| `created_at` | canonical UTC timestamp `TEXT NOT NULL` |

The sole bootstrap exception is an explicit first row with `id=1`, code `bootstrap`, kind `human`, and self-attribution. Every later principal must name a different existing creator. This establishes audit attribution only, not authority. UPDATE/DELETE and colliding INSERT—including `INSERT OR REPLACE`—are rejected. Future profile/display metadata and authentication identifiers belong in separate versioned/authentication structures.

### `atlas_languages`

| Column | Definition |
|---|---|
| `id` | `INTEGER PRIMARY KEY` |
| `language_code` | canonical BCP 47 tag `TEXT NOT NULL UNIQUE`, 2–35 bytes |
| `recorded_by_principal_id` | `INTEGER NOT NULL FK atlas_principals` |
| `recorded_at` | canonical UTC timestamp `TEXT NOT NULL` |

The database defensively rejects NUL, whitespace edges, non-ASCII shape, leading/trailing/repeated hyphens, and malformed primary shape. The committed `Intl.getCanonicalLocales` validator enforces full canonical form before insertion (for example, `en-US`, not `en-us`). Display labels are deferred. UPDATE/DELETE/REPLACE collisions are rejected.

### `atlas_jurisdictions`

Stable legal/territorial identity only; no containment, membership, succession, source identifier, or applicability claim.

| Column | Definition |
|---|---|
| `id` | `INTEGER PRIMARY KEY` |
| `jurisdiction_code` | nonempty canonical lowercase `TEXT NOT NULL UNIQUE`, 1–80 bytes, no whitespace edge/NUL |
| `jurisdiction_kind_code` | `TEXT NOT NULL CHECK international/supranational/state/territory/regional/devolved/local` |
| `recorded_by_principal_id` | `INTEGER NOT NULL FK atlas_principals` |
| `recorded_at` | canonical UTC timestamp `TEXT NOT NULL` |

Kinds mean: `international` is a treaty/intergovernmental legal track without its own supranational legal order; `supranational` is a legal order above participating states; `state` is a sovereign national jurisdiction; `territory` is a legally distinct territory; `regional`, `devolved`, and `local` are successively narrower substate kinds without asserting containment. Codes and kinds cannot be repurposed. UPDATE/DELETE/REPLACE collisions are rejected.

### `atlas_jurisdiction_versions`

Immutable jurisdiction name/description assertions with separate effective and record time.

| Column | Definition |
|---|---|
| `id` | `INTEGER PRIMARY KEY` |
| `jurisdiction_id` | `INTEGER NOT NULL FK atlas_jurisdictions` |
| `language_id` | `INTEGER NOT NULL FK atlas_languages` |
| `effective_from` | canonical date; natural effective point component |
| `record_kind_code` | `assertion`, `correction`, or `withdrawal` |
| `name` | nonblank/no-NUL for assertion/correction; null for withdrawal |
| `description` | nullable/no-NUL; null for withdrawal |
| `corrects_jurisdiction_version_id` | nullable unique self-FK; required for correction/withdrawal |
| `reason` | nonblank/no-NUL `TEXT NOT NULL` |
| `recorded_by_principal_id` | `INTEGER NOT NULL FK atlas_principals` |
| `recorded_at` | canonical UTC timestamp, later than corrected predecessor |

Natural effective point: `(jurisdiction_id, language_id, effective_from)`. Each point has exactly one root assertion. A correction or withdrawal must target the current leaf at the same point; one predecessor has at most one successor. Withdrawals are terminal. Different effective dates are substantive historical changes. Correcting an effective date requires withdrawing the erroneous point and inserting a new root. UPDATE/DELETE/REPLACE identity collisions are rejected. Content hashes are deferred until a canonical content serialization is defined.

## Bitemporal projection

Inputs are `:effective_as_of` and `:known_at`. First restrict rows by jurisdiction/language, `effective_from <= :effective_as_of`, and `recorded_at <= :known_at`. Within each natural effective point, select the row with no correction successor also known by `:known_at`. Exclude leaves whose kind is `withdrawal`. From remaining points select `ORDER BY effective_from DESC, recorded_at DESC, id DESC LIMIT 1`.

This answers “what name/history applied at the effective date, using only what Atlas had recorded by the knowledge timestamp?” A backdated correction changes results only for `known_at` values on or after its recording time.

## Generated object inventory

Tables (4): `atlas_principals`, `atlas_languages`, `atlas_jurisdictions`, `atlas_jurisdiction_versions`.

Named indexes (3):

- `atlas_jurisdiction_versions_one_root_idx`
- `atlas_jurisdiction_versions_bitemporal_idx`
- `atlas_jurisdiction_versions_correction_idx`

Named triggers (15): bootstrap and subsequent-principal attribution guards; four INSERT collision guards; jurisdiction-version correction validation; and UPDATE/DELETE rejection for every table. Collision guards prevent `INSERT OR REPLACE` from deleting/recreating rows even with recursive triggers disabled.

## Deferred work

- Principal lifecycle/status/replacement: review-governance tranche.
- Jurisdiction retirement, succession, split/merge, containment and membership: source-backed authority tranche.
- External identifiers: authority tranche with controlled scheme registry, entity-type scope, provenance, correction/withdrawal and deterministic resolution. ELI, EUR-Lex and CELEX identify instruments/sources, never jurisdictions.
- Semantic taxonomies: proposition/semantic tranche with reviewed seeds and legacy crosswalk.
- Coverage scopes: sourced applicability/national-context tranche.
- Roles, qualifications, policies, reviews, publication and evaluator: review-governance vertical slice.

No structural or legal row is seeded by Tranche 1A.
