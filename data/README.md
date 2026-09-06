# Data

The local SQLite database is built from ordered SQL migrations. Applied migration files are protected by SHA-256 checksums in `migration_checksums`; the runner validates filenames, ordering, missing files, and checksums before applying anything new. Migration `004_tranche_1a_foundations.sql` implements four empty, immutable `STRICT` Atlas foundation tables for attribution, canonical languages, jurisdictions, and correction-safe jurisdiction names. Migration `005_tranche_2a_source_quarantine.sql` implements nine empty `STRICT` source-evidence quarantine tables with 27 indexes and 27 history/integrity triggers; automated tests require its bytes to remain identical to the approved DDL audit artifact.

Neither migration contains Atlas seeds. Migration 005 imports no substantive evidence or legal data and does not implement the approved evidence-bundle importer, collector, artifact adapter, trusted identity binding, or operational controls. Until those components receive separate implementation approval, Atlas writes and any API, search, export, frontend, public, or production use of Tranche 2A remain prohibited. Schema implementation alone is not authorization to use it.

```bash
npm run data:build
npm run data:check
```

The schema separates:

- jurisdictions;
- official legal instruments and application dates;
- plain-language requirements;
- hiring stages, legal lenses, and responsible actors;
- requirement relationships and `country_overlays` in the legacy v1 model;
- official-source verification metadata.

The seed records are EU-level research entries checked on 2026-09-02. Plain-language summaries are editorial and remain connected to the official instrument and article/location. In v2, national laws will be first-class source-backed propositions connected to EU baselines through typed comparison relationships; absence of a comparison will not imply equivalence. Existing databases are safely bootstrapped only for the verified frozen 001–003 hashes; unknown applied migrations fail closed. Metadata initialization and checksum bootstrap are atomic, failed migrations roll back transactionally, and repeat runs are no-ops.
