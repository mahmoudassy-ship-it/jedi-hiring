# JEDI Hiring Legal Atlas

Source-backed workspace for organizing the legal layers that affect inclusive hiring in Europe.

The initial scaffold mirrors Parlamento's compact shape while adding a migration ledger, coordinated development, filtering, and automated database/API checks.

## Structure

- `frontend/` — React and Vite legal-atlas browser
- `backend/` — dependency-free Node HTTP API and production static server
- `data/` — SQLite migrations, seed records, and data checks
- `tests/` — database and API integration tests
- `docs/concepts/` — visual references for the initial product shell

## Requirements

- Node.js 22 or newer (`node:sqlite` is used by the API and data tools)

## Run locally

```bash
npm install
npm run data:build
npm run dev
```

Open <http://localhost:3100>. During development Vite proxies `/api` and `/health` to the backend on port `3101`, so Parlamento can continue using `3000/3001`.

## Production-style run

```bash
npm run check
npm start
```

The backend serves the built frontend and API on `127.0.0.1:3100` by default.

## Dataset

`npm run data:build` creates the ignored local database at `data/jedi-hiring.sqlite`. Migrations are applied once and recorded in `schema_migrations`.

The seed is an initial EU-level research set, verified against official URLs on 2026-09-02. It is a starting dataset, not a substitute for current national legal advice. Country overlays and counsel validation status are explicit parts of the schema.

Useful commands:

```bash
npm run data:build       # apply pending migrations
npm run data:check       # integrity, foreign-key, and seed checks
npm test                 # isolated database and HTTP API tests
npm run build            # type-check and build the frontend
npm run security:check   # check secret-file tracking and permissions
npm run check            # run the complete verification chain
```

## Environment

Copy `.env.example` only when local overrides or optional enrichment jobs are needed. Secret values belong in the ignored `.env` file with mode `0600`. Cloudflare domain, zone, tunnel, and token values are application-specific and must be rebound before deployment.
