# Data

The local SQLite database is built from ordered SQL migrations. Applied migration files are protected by SHA-256 checksums in `migration_checksums`; the runner validates filenames, ordering, missing files, and checksums before applying anything new.

```bash
npm run data:build
npm run data:check
```

The schema separates:

- jurisdictions;
- official legal instruments and application dates;
- plain-language requirements;
- hiring stages, legal lenses, and responsible actors;
- requirement relationships and future country overlays;
- official-source verification metadata.

The seed records are EU-level research entries checked on 2026-09-02. Plain-language summaries are editorial and remain connected to the official instrument and article/location. National implementation and legal advice must be added as explicit overlays rather than silently inferred. Existing databases are safely bootstrapped only for the verified frozen 001–003 hashes; unknown applied migrations fail closed. Failed migrations roll back transactionally and repeat runs are no-ops.
