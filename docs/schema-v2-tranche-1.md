# Tranche 1A authority-entry foundations

Status: proposed for approval; not a production migration. This seven-table proposal supersedes the rejected 45-table Tranche 1 design preserved in Git history. Its executable DDL is [`schema/tranche-1-foundations.proposed.sql`](schema/tranche-1-foundations.proposed.sql), and its reproducible validator is [`schema/validate-tranche-1a.mjs`](schema/validate-tranche-1a.mjs).

Tranche 1A enables safe attribution and jurisdiction naming for future quarantined official-source research. Until the review-governance vertical slice exists, later source records remain quarantined: nothing can become a reviewed proposition or public content.

## Included and deferred

Included: stable human/service principals for attribution only, append-only principal status, standalone languages, stable territorial/legal jurisdictions, immutable jurisdiction descriptions, and versioned external identifiers.

Deferred:

- jurisdiction containment and membership to the authority tranche, where assertions receive official-source provenance;
- hiring stages, lenses, actors, normative roles, grounds, data categories, and their legacy mapping to the proposition/semantic tranche;
- roles, grants, qualifications, policies, reviews, publication decisions, and evaluator to one review-governance vertical slice;
- sectors, employer thresholds/types, collective-agreement and personal coverage to the sourced applicability/national-context tranche;
- instruments, sources, provisions, propositions, monitoring, API, and backfill to their approved later tranches.

## Physical conventions

All tables are plural `snake_case` with `atlas_` prefix, `id` primary keys, and `<entity>_id` foreign keys. Dates are canonical `YYYY-MM-DD`; timestamps are canonical UTC `YYYY-MM-DDTHH:MM:SS.sssZ`. CHECK constraints round-trip values through SQLite date/time functions before lexical comparison is permitted. SHA-256 is lowercase 64-character hexadecimal. The SQL has no transaction-management statement; `applyMigrations` owns the transaction. There are no seeds because Tranche 1A requires no operational structural row and source-dependent facts are deferred.

Stable identity rows are immutable. Status/retirement/replacement is append-only. Jurisdiction descriptions and external identifiers use immutable successor chains rather than mutable open-ended intervals. At an `as_of` date, select eligible rows with `effective_from <= :as_of`, then the unsuperseded leaf (or deterministically the latest `recorded_at,id` while resolving a backdated correction). Missing records mean unknown/not recorded and never imply applicability, equivalence, membership, or qualification.

## Exact tables

### `atlas_principals`

Purpose: stable attribution identity only; not authentication or authorization.

Columns: `id INTEGER PRIMARY KEY`; `principal_code TEXT NOT NULL UNIQUE`; `principal_kind_code TEXT NOT NULL CHECK human/service`; `display_name TEXT NOT NULL`; nullable unique `external_subject TEXT`; canonical `created_at TEXT NOT NULL`. Code is lowercase `[a-z0-9._-]+`.

Behavior: entire row rejects UPDATE/DELETE. Principal kind and code cannot be repurposed. Named indexes: none beyond PK/UNIQUE. Future references: source observations, drafts, reviews, publications, monitor runs, and audit events.

### `atlas_principal_status_events`

Purpose: append-only active, retired, or replaced history for a principal.

Columns: `id PK`; `principal_id FK NOT NULL`; `status_code CHECK active/retired/replaced`; nullable replacement principal FK; canonical `effective_on` and `recorded_at`; reason; UNIQUE principal/effective/recorded. Replacement is required only for `replaced` and cannot be self.

Behavior: UPDATE/DELETE rejected; replacement-cycle insert rejected. Named index `atlas_principal_status_events_as_of_idx`. Current status derives from latest `(effective_on, recorded_at, id)` eligible at `as_of`. Future references: attribution eligibility and governance evaluator.

### `atlas_languages`

Purpose: standalone BCP 47-compatible language identity usable before generic taxonomies exist.

Columns: `id PK`; lowercase `language_code TEXT NOT NULL UNIQUE` using `[a-z0-9-]`, length 2–35; display name; canonical creation timestamp.

Behavior: UPDATE/DELETE rejected; new identity replaces any changed meaning. No named secondary index. Future references: source representations, translations, jurisdiction versions, and qualification scope.

### `atlas_jurisdictions`

Purpose: stable territorial/legal-jurisdiction identity, without containment or membership assertions.

Columns: `id PK`; lowercase `jurisdiction_code TEXT NOT NULL UNIQUE`; kind CHECK `supranational/state/regional/devolved/local`; canonical creation timestamp.

Behavior: UPDATE/DELETE rejected. No named secondary index. Future references: instruments, propositions, source mapping, applicability, qualifications, containment, memberships, and national comparisons.

### `atlas_jurisdiction_status_events`

Purpose: append-only retirement/replacement history for jurisdiction identities.

Columns and behavior mirror principal status events with jurisdiction FKs. UPDATE/DELETE and replacement cycles are rejected. Named index `atlas_jurisdiction_status_events_as_of_idx`. Status derives at caller-supplied `as_of`.

### `atlas_jurisdiction_versions`

Purpose: immutable effective-from name/description versions for one jurisdiction and language.

Columns: `id PK`; jurisdiction and language FKs; name; nullable description; canonical `effective_from` and `recorded_at`; lowercase hexadecimal `content_sha256`; nullable unique self-FK `supersedes_jurisdiction_version_id`; UNIQUE jurisdiction/language/effective/recorded.

Behavior: UPDATE/DELETE rejected. Successor trigger requires the same jurisdiction and language; immutable backward references plus cycle validation prevent cycles. Named index `atlas_jurisdiction_versions_as_of_idx`. A later or backdated correction is a new row that supersedes the prior row; no mutable `valid_to` is used. Future references: public jurisdiction labels and source-backed authority metadata.

### `atlas_jurisdiction_external_identifiers`

Purpose: immutable, effective-from mapping for ISO, ELI/EUR-Lex, or national-source identifiers without assuming a fixed scheme list.

Columns: `id PK`; jurisdiction FK; lowercase stable `scheme_code`; non-empty `identifier_value`; canonical `effective_from` and `recorded_at`; nullable unique self-FK `supersedes_external_identifier_id`; UNIQUE scheme/value/effective/recorded.

Behavior: UPDATE/DELETE rejected. Successor trigger requires the same jurisdiction and scheme and rejects cycles. Named indexes `atlas_jurisdiction_external_identifiers_as_of_idx` and `atlas_jurisdiction_external_identifiers_lookup_idx`. Scheme/value mappings are never silently repurposed; corrections or changes create successors. Future references: authority-source ingestion and identifier resolution.

## Exact generated objects

Tables (7):

1. `atlas_principals`
2. `atlas_principal_status_events`
3. `atlas_languages`
4. `atlas_jurisdictions`
5. `atlas_jurisdiction_status_events`
6. `atlas_jurisdiction_versions`
7. `atlas_jurisdiction_external_identifiers`

Named indexes (5): the two status `as_of` indexes, jurisdiction-version `as_of`, and external-identifier `as_of` plus lookup indexes. PK/UNIQUE constraints create SQLite autoindexes not counted as named proposal indexes.

Named triggers (18): fourteen UPDATE/DELETE immutability or append-only triggers, two replacement-cycle triggers, and two same-identity successor/cycle triggers.

## Validation contract

The committed validator copies frozen migrations 001–003 and the proposal into a temporary migration directory as temporary `004_tranche_1a_foundations.sql`. It invokes the real `applyMigrations` for a fresh database and for an independently constructed legacy database with the original two-column ledger. It verifies object counts, v1 row digests, integrity/FKs, format rejection, stable-identity immutability, successor insertion, append-only enforcement, and transactional rollback. No file under `data/migrations` is added or changed.
