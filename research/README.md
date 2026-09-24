# Local research candidates

This directory is a noncanonical, single-operator research workspace. Read the [full boundary and workflow](../docs/single-operator-research-track.md) before adding a manifest.

- Add only UTF-8 `candidates/*.research.json` files conforming to [`schema/research-candidate-manifest-v1.schema.json`](schema/research-candidate-manifest-v1.schema.json).
- Commit links, metadata candidates, paraphrased atomic drafts, locators and limitations—not downloaded documents, excerpts, binary bytes, credentials, secrets or personal data.
- Use only the four closed research statuses. No record here is accepted evidence, verified law, current-law assurance, legal advice or publishable content.
- Label all automation assistance. Automation cannot perform the single-researcher metadata check or any later independent review.
- Run `npm run research:validate`; optionally run `npm run research:build` for the ignored, disposable database.

The builder has fixed repository paths and writes only `generated/research-candidates.sqlite`. Delete that file freely and rebuild it from the manifests. Never copy its rows into the canonical Atlas database; later operational capture must begin again from the official landing URL candidate under the approved D9 pipeline.
