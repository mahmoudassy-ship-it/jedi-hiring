# First evidence pilot — one-document quarantine runbook

Status: runbook proposal, not source or import authorization. It deliberately separates a pre-fetch authorization from a post-capture import authorization. Execute only after an accepted bootstrap report and both exact authorizations at their stated boundaries.

## Approved shape

The first document bundle is sequence 2 and has exactly one bootstrap dependency, one retained artifact, one retrieval event, one HTTP 200 full representation, zero processing runs, zero processing outputs and zero unverified candidate occurrences. It may record zero to five ordered redirects. It creates quarantined evidence only.

Manifest v1 uses the frozen `GET|http_get_representation_v1` profile. The approved request pins exact `Accept`, `Accept-Language` and `Accept-Encoding` values; the recommended candidate uses `application/pdf`, `en` and `identity`. Requests contain no cookie, credential or authorization header. Retained bytes are exact response-body octets after transfer framing and before content-coding. `Content-Encoding`, 206 responses, personal-data-bearing artifacts, active content, archives, credentials, hidden transformations and unsupported media are NO-GO.

## Pre-fetch authorization

1. Resolve the pre-fetch `D` gates and approve the candidate institution/landing page, exact requested URL, redirect hosts, frozen request profile and exact negotiation headers, 25 MiB maximum, operation window, bounded hostile-staging retention and incident disposition path.
2. Independently confirm that URL approval is only egress/staging permission and neither officiality, document identity, final representation nor import approval.
3. Approve collector build/network namespace, DNS/TLS policy, redirect/SSRF protections, credential/cookie-free request, response/header limits, timeout and one-operation window.
4. Verify current scanner builds/rules, isolated scratch, secret/header redaction and fail-closed malware, passive-PDF and personal-data gates.
5. Verify bootstrap projection, journal/checkpoint heads, independent backup coverage, last successful drill, empty unresolved state and current human/runtime bindings.

## Retrieval and staging

1. The collector receives only the exact approved HTTPS target/allowlist and an operation-scoped staging descriptor. It has no canonical database, CAS-final, journal or credential access.
2. Record requested location, each ordered redirect, last attempted target and successfully resolved response location separately. Record the exact request negotiation values and observed `Vary`, `Content-Encoding`, content type, content length, ETag and Last-Modified values (including explicit nulls where the contract permits). Reject unapproved scheme/host/IP/port, downgrade, loop, credential-bearing URL, private/link-local/metadata address and excess redirect.
3. Preserve every retrieval attempt. A network failure has no response location/status or artifact; a response and later parser/scanner failure remain separate facts.
4. Accept only HTTP 200 with a complete body within 26,214,400 bytes, allowed media observations, no content coding and allowlisted secret-free metadata. Recompute exact byte length and SHA-256.
5. Place hostile bytes in isolated staging. Do not open them with desktop software, scripts, macros, external entities, network-capable renderers or unbounded parsers.

## Screening and post-capture authorization

1. Run independent scanners in bounded isolation. Record exact builds, configuration/rules, start/end times, outcomes and output digests; never put extracted secrets or personal data into logs.
2. A distinct human checks the negative personal-data result. Any name/signature or uncertainty blocks this v1 pilot; restricted custody is not an exception.
3. `clearance_decider` and `clearance_checker` independently bind the exact hash/length/byte layer to `restricted_store`, repository-ineligible, source-specific rights/retention limitations. They do not certify officiality or legal meaning.
4. The source-selection record distinguishes original Official Journal bytes from consolidated/current text and records currency/consolidation as unassessed. Safety scanner/parser executions are operational admission checks, not `atlas_processing_runs`.
5. The submitter creates a deterministic, strict, reviewed Git bundle manifest referencing staged bytes. Review rejects symlinks, root escapes, absolute/traversal paths, secrets, transient signed URLs, unknown fields and noncanonical content.
6. Obtain the separate post-capture/import authorization bound to the resolved response, exact request/response profile, hash/length/byte layer, safety/privacy/rights decisions, manifest digest, release generation, canonical pre-state and operation expiry.

## Import, backups and verification

1. The network-free importer reopens the manifest under the reviewed root, recomputes its digest, resolves internal references and obtains bytes only through scoped staged-artifact descriptors.
2. Complete semantic preflight and custody prepare/verify occur before mutation. Re-observe source heads and clearance at every append/promotion boundary.
3. Apply the deterministic plan to a disposable candidate through fixed statements. Verify every persisted column and relation against stable manifest codes.
4. Finalize the primary restricted CAS with no-replace semantics, append durability/journal receipts and independently verify the candidate and promotion inputs.
5. Create and independently verify the `prior_backup` of the exact pre-promotion canonical generation; append its receipt before promotion.
6. Atomically promote only the exact verified candidate. Response loss is resolved from source-state identity, journal-tip receipt identity and both backup stages; never blindly replay.
7. Independently verify the promoted generation, then create and verify the distinct `final_backup` of that exact state and append its receipt.
8. Perform a deletion-aware disposable restore drill from the final backup, and replay the identical bundle for complete no-op verification.
9. Revoke all capabilities, terminate/reap receivers, anchor heads, freeze ordinary writes and issue the verification report.

## Expected terminal projection

| Object | Expected state after sequence 2 |
|---|---|
| `atlas_principals` | unchanged 4 bootstrap principals |
| `atlas_evidence_bundle_receipts` | 2 receipts: bootstrap and document |
| Retrieval locations | exact requested/resolved locations and any ordered redirects required by the bundle |
| Retrieval events | 1 document event, retained full HTTP 200 representation |
| Artifact identities | 1 exact byte-layer/SHA-256/length identity |
| Artifact custody events | at least the exact verified restricted primary placement required by the accepted plan; history preserved |
| Processing runs/outputs | 0 |
| Candidate occurrences | 0 |
| Tranche 1A language/jurisdiction tables | 0 |
| Legacy v1 | unchanged and sole frontend/API data source |

The exact accepted plan and frozen projection verifier, not this summary, determine the authoritative technical projection.

## Fail-closed outcomes

Network failure, non-200/partial response, content coding, unsafe redirect, header controls, size mismatch, hash mismatch, parser/scanner failure, personal data, malware, secret, ambiguous rights, stale review, clock failure, source-head movement, CAS collision, unknown custody, journal gap/fork, backup failure or projection mismatch stops the operation. Before import, rejected bytes stay only in access-restricted hostile staging for the pre-approved short retention period while content-free incident evidence is preserved. They never become a Tranche 2A artifact/custody row, backup or canonical import. Removal requires the exact scoped privacy/security/legal-records decision and an auditable tombstone/cleanup result without claiming complete erasure. Do not transform, substitute, publish, infer legal identity or silently retry.
