# First evidence pilot — incident, shutdown and rollback runbook

Status: proposal. This runbook preserves evidence and returns the system to a fail-closed state. It grants no recovery, deletion, restoration, correction or publication authority. Only the exact approved D9.4/D9.5 role may authorize a bounded action.

## Universal first response

1. Stop admission of new operations and prevent permit issuance.
2. Preserve the operation lock, process identities, descriptor state, trusted time evidence and volatile facts where safe.
3. Revoke unconsumed capabilities; terminate and reap affected descriptor receivers through the authenticated broker.
4. Disable affected endpoints/egress without deleting files, receipts, journals, candidates, staging or backups.
5. Record the incident with trusted observation time, reporter binding, exact operation/subject, source-state heads, receipt heads, build/profile generations and limitations. Keep content and secrets out of the report.
6. Notify the incident commander, security authority and scoped records/privacy/recovery roles. Do not announce legal conclusions.
7. Classify from durable evidence. Unknown, mixed, stale, forked, gapped, rolled-back or contradictory state is `reconciliation_required` and stays unavailable.

## Decision table

| Condition | Immediate containment | Permitted next action | Prohibited shortcut |
|---|---|---|---|
| Failure before any durable effect | revoke handles; retain logs; isolate candidate/staging | prove no-effect from stable heads, then dispose only explicitly authorized temporary objects | retry with same nonce/permit |
| Response loss/timeout | freeze writer/promoter/custody endpoint | resolve from source-state identity, receipt identity, checkpoint progression and exact projection | assume failure or success; submit again |
| Possible/ambiguous promotion | freeze canonical directory and all writes | classification-only resolver; independent reconciliation | rename/delete/restore canonical files |
| Clock unhealthy/backward step | block permits/appends/promotion/backup/restore | repair clock out of band; create new generation and authorization | backdate or edit timestamps |
| Credential/binding compromise | revoke generation, stop endpoints, preserve peer/journal evidence | rotate through a newly reviewed protected generation; independently revalidate | edit accepted records or keep compromised session |
| Scanner or personal-data alert | isolate hostile staging and disable importer descriptor | privacy/security triage; controlled restriction/tombstone planning if authorized | open, redact, transform or commit bytes |
| Malware/secret detected | isolate bytes and hosts; rotate exposed secrets if applicable | bounded security response and custody restriction | publish scanner output or delete evidence ad hoc |
| Pre-import artifact rejected | keep bytes only in bounded hostile staging; record content-free incident evidence | scoped privacy/security/legal-records disposition; auditable cleanup/tombstone after retention | create Tranche 2A identity/custody, backup or canonical import |
| Storage corruption/hash mismatch | make copy unavailable; block promotion/restore | verify independent copy and classify; D9.5 authorization required for any restore | overwrite bad bytes from backup |
| Disk/inode exhaustion | block new writes; preserve mounts and heads | expand via reviewed procedure or select a new generation | delete unknown/orphaned files |
| Journal gap/fork/rollback | stop all mutation; protect all variants | independent reconciliation against external anchors | choose the newest-looking head |
| Backup missing/stale/failed | do not report operation complete; block next stage | recreate only through separately authorized D9.5 operation after classification | mark primary as backed up |
| Active restriction/hold/tombstone | shut down subject capabilities and withhold restore | exact D9.4 projection and authorized handling | bypass because bytes exist |
| Unexpected path/link/inode/mount | terminate descriptors; isolate root | forensic inventory and reprovision reviewed root | follow link, normalize path or unlink object |
| Public/API/frontend exposure | disable affected route/service and preserve access logs | security/privacy incident process; verify Atlas isolation before restart | merely hide UI while endpoint remains |

## Rollback meaning

Rollback means returning **execution** to a known fail-closed point, not erasing accepted history or overwriting canonical data:

- pre-effect: stop, prove no-effect and clean only explicitly named disposable resources;
- post-effect: retain append-only receipts and state, disable access and classify;
- executable/configuration rollback: select a previously approved, non-revoked protected generation only when compatible with the current data/contract state;
- data rollback: prohibited. Use a new authorized correction, restriction or D9.5 reconstruction path while retaining history;
- source/custody deletion: requires D9.4 authority and never implies complete erasure;
- restoration: requires D9.5 authorization, restrictions evaluation, independent verification and atomic promotion.

## Recovery and restart gate

Restart requires a written incident disposition that identifies the root cause, affected subjects/time interval, evidence preserved, exact current heads, credential/profile changes, residual uncertainty, required legal/privacy notification, and new stage authorization. Run the complete go/no-go checklist again. An incident cannot be cleared by the same person who caused or solely investigated it when separation is required.

## Evidence retention and communication

Store incident records in the protected audit store and reference artifacts by digest. Redact secrets and avoid source bytes, full URLs with query strings, headers and personal data. External statements must say what was technically observed and verified as of a time; never claim complete erasure, continuous availability, legal validity or compliance from a technical recovery result.
