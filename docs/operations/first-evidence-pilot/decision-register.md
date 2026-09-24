# First evidence pilot — unresolved decision register

Status: all rows are **pending** unless a later approval record supplies the decision, accountable role, date, scope and evidence. A recommendation is not approval. Personal names, credentials and contact details belong in the protected operational register, not this file.

Stage codes: `B` blocks bootstrap; `D` blocks the document bundle; `P` blocks publication. Publication is already structurally unavailable, but the column prevents an operational decision from being misread as publication authority.

| ID | Decision | Realistic options | Recommendation | Human owner role | Blocks |
|---|---|---|---|---|---|
| DR-01 | Pilot host OS/architecture | Ubuntu 24.04 x86-64; another reviewed Linux LTS | Ubuntu Server 24.04 LTS x86-64, kernel 6.8+ | system owner | B/D/P |
| DR-02 | Host isolation | dedicated VM; dedicated physical host; shared host | dedicated non-multitenant VM with verified boot and no unrelated workloads | security authority | B/D/P |
| DR-03 | Kernel primitive acceptance | approve tested primitive inventory; choose another host | require `openat2`, pidfd, peer credentials, descriptor passing, cgroup v2 and fail closed | security authority | B/D/P |
| DR-04 | Numeric service UID/GID allocation | local static range; centrally allocated identities | centrally allocate twelve unique non-login UIDs/GIDs; never reuse fixture values | system owner | B/D/P |
| DR-05 | Human authentication method | local OS+FIDO2; centrally managed PAM/SSO+MFA | phishing-resistant MFA with kernel-visible local account mapping | security authority | B/D/P |
| DR-06 | Human role assignments | eligible staff assigned outside Git | assign distinct people to all mandatory D9 roles; document recusals and backups | governance owner | B/D/P |
| DR-07 | D9.4 roster adoption | activate reviewed extension/roster; defer pilot | require separate, ordered decisions from the D9.0.1 `operational_witness` and distinct `d940_roster_adopter`; record exact bindings, separation, chronology and revocation state | operational witness + D9.4 roster adopter | B/D/P |
| DR-08 | Operational build process | isolated local builder; reproducible CI builder | isolated builder plus independent rebuild/hash comparison | release authority | B/D/P |
| DR-09 | Node/compiler/SQLite/OpenSSL pins | exact packaged builds; independently built toolchain | exact distro packages and binary hashes recorded in protected generation | release authority | B/D/P |
| DR-10 | IPC endpoint deployment | systemd socket activation; supervised fixed daemons | systemd-managed `SOCK_SEQPACKET` endpoints with exact UID/build allowlists | system owner | B/D/P |
| DR-11 | Runtime secret facility | TPM-backed systemd credentials; OS keyring; HSM | TPM-backed systemd credentials where available; no environment/argument secrets | security authority | B/D/P |
| DR-12 | Backup encryption key custody | single admin; two-person keystore; external KMS | two-person recovery with independently tested escrow | recovery authority | B/D/P |
| DR-13 | Credential rotation/expiry | fixed calendar; event-driven only | 90-day maximum human/service binding generation plus immediate incident rotation | security authority | B/D/P |
| DR-14 | Trusted clock sources and offset threshold | NTS upstreams and 1/2/5-second threshold; separately reviewed authenticated equivalent | two or more approved authenticated sources; fail closed above 2 seconds and never fall back unauthenticated | system owner | B/D/P |
| DR-15 | Primary filesystem | ext4; XFS; another tested local filesystem | ext4 or XFS after `fsync`/atomic-rename fault rehearsal | storage owner | B/D/P |
| DR-16 | Primary capacity/reserve | 4 GiB; larger reserved volume | dedicated 4 GiB minimum with 25% free-space and inode reserve | storage owner | B/D/P |
| DR-17 | Independent backup medium | second encrypted host/device; hosted restricted object store; removable offline media | separate host/power/root-compromise and administrative failure domain, not merely a second disk in the pilot host | recovery authority | B/D/P |
| DR-18 | External rollback anchor | immutable object/WORM; offline signed heads; hardware log | independently administered immutable receipt/checkpoint-head store | security authority | B/D/P |
| DR-19 | Operational RPO | zero accepted promotions; time-based window | zero accepted bundle promotions | governance owner | B/D/P |
| DR-20 | Operational RTO | 1h; 4h; next business day | four hours from valid authorization and available exact inputs | governance owner | B/D/P |
| DR-21 | Audit/log retention | 90 days; 1 year; longer legal schedule | one year for technical audit, subject to records/privacy review | legal-records authority | B/D/P |
| DR-22 | Backup retention and deletion | fixed generations/time; indefinite; manual only | retain every pilot generation until a separately approved schedule and deletion test exist | legal-records + privacy authorities | B/D/P |
| DR-23 | Restore-drill frequency | before each bundle; monthly; quarterly | before bootstrap, before document import, and after every protected profile change | recovery authority | B/D/P |
| DR-24 | Monitoring/alert destination | local-only; managed pager; security operations | independent missed-run heartbeat plus two-role alerting | incident commander | B/D/P |
| DR-25 | Incident commander and deputies | assigned eligible staff | name one primary and one independent deputy outside Git | governance owner | B/D/P |
| DR-26 | Recovery authority activation | activate exact D9 role; keep disabled | activate only for scheduled drill/incident windows, then revoke | recovery authority | B/D/P |
| DR-27 | Deletion authority activation | disabled; enabled for bounded tests | keep real deletion disabled for the first pilot | privacy + legal-records authorities | D/P |
| DR-28 | Source institution/document | proposed Directive 2000/78/EC; another approved EU source | review the proposed EUR-Lex source; reject rather than silently substitute | source research lead | D/P |
| DR-29 | Exact retrieval representation | passive PDF; inert XML; inert plain text | one passive PDF only if all admission checks pass; pin `GET` plus `http_get_representation_v1`, exact Accept/Accept-Language/Accept-Encoding, credential-free request, negotiation observations and original-versus-consolidated status | source research + security authorities | D/P |
| DR-30 | Exact landing/download URLs and redirect allowlist | EUR-Lex only; reviewed Publications Office hosts | approve exact URL and each allowed host immediately before retrieval | security + source research authorities | D/P |
| DR-31 | Rights and redistribution | restricted-store only; repository eligible; do not retain | restricted-store only; repository eligibility false | rights/clearance decider | D/P |
| DR-32 | Personal-data determination | no personal data; personal data present; uncertain | require independently reviewed “none”; presence or uncertainty is NO-GO | privacy authority | D/P |
| DR-32A | Rejected hostile-byte retention/disposition | immediate non-forensic purge; bounded quarantine then authorized removal | pre-approve a short bounded staging period, restricted access, incident evidence retained and exact cleanup authority; never admit rejected bytes to Tranche 2A/backup | privacy + security + legal-records authorities | D/P |
| DR-33 | Malware/passive-PDF scanner set | selected engines/rules and versions | independent malware, secret, personal-data and passive-PDF checks with pinned builds/rules | security authority | D/P |
| DR-33A | Hostile parser sandbox | pinned seccomp profile; separately approved equivalent kernel sandbox | require `no_new_privs`, no capabilities/network/inherited FDs, disposable mount/PID namespaces, read-only runtime and bounded/reaped process tree | security authority | D/P |
| DR-34 | Source retrieval maintenance window | staffed window; unattended schedule | staffed window with submitter, witness, security and recovery coverage | operational witness | D/P |
| DR-35 | Bootstrap authorization | authorize exact sequence-1 package; defer | decide only after all bootstrap blockers pass | bootstrap authority | B/D/P |
| DR-36A | Document pre-fetch authorization | authorize exact request/egress/staging envelope; defer | authorize only the requested URL, closed request/redirect profile, collector build, window and bounded hostile staging | governance + security authorities | D/P |
| DR-36B | Document post-capture import authorization | authorize exact sequence-2 bytes/manifest/pre-state; defer | decide only after screening and rights/privacy review; bind resolved representation, hash/length/layer, manifest, builds and heads | governance owner | D/P |
| DR-37 | Operational-release activation | approve exact protected generation; defer | separate release/activation review after operational rehearsal | security + release authorities | B/D/P |
| DR-38 | Backup/restore operational authority | activate exact scoped process; defer | permit only the scheduled pilot backup and disposable drill | recovery + legal-records + privacy authorities | B/D/P |
| DR-39 | Publication policy | publish evidence; expose internally; no exposure | no API, search, export, frontend or publication route | publication authority | P |
| DR-40 | Pilot acceptance | accept technical result; require remediation; reject | decide from the completed verification report only | governance owner | D/P |

## Decision-record minimum

Each approved row must record:

- decision ID, exact selected value and bounded scope;
- approving role and protected identity-binding reference;
- decision time, expiry/review date and conflict/recusal statement;
- supporting evidence digests and limitations;
- superseded decision, if any;
- bootstrap/document/publication effect; and
- revocation/escalation route.

No decision may be inferred from silence, a default value, a synthetic fixture, a Git author, an Atlas principal code, or successful tests.
