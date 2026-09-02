# Data

The local SQLite database is built from ordered SQL migrations:

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

The seed records are EU-level research entries checked on 2026-09-02. Plain-language summaries are editorial and remain connected to the official instrument and article/location. National implementation and legal advice must be added as explicit overlays rather than silently inferred.
