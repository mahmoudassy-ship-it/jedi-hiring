# First evidence pilot — protected environment inventory template

Status: template only. Complete this record in the access-controlled operational store; do not commit the completed inventory, personal names, credentials, secret handles, numeric authentication material, or sensitive host details to Git.

Inventory ID: `[assigned outside Git]`

Inventory version/digest: `[canonical digest]`

Prepared/independently checked at: `[canonical UTC timestamps]`

Applies to release commit/build: `[commit and immutable build digest]`

Supersedes: `[inventory ID or none]`

## Host and platform

| Field | Recorded value | Evidence reference | Independent check | Result |
|---|---|---|---|---|
| Host asset and failure domain |  | protected asset record | inventory verifier |  |
| OS image/package-set digest |  | signed image/SBOM | release authority |  |
| Architecture/kernel build |  | measured boot/package evidence | security authority |  |
| Secure/verified boot state |  | attestation reference | security authority |  |
| Required Linux primitives |  | `openat2`, pidfd, `SO_PEERCRED`, `SCM_RIGHTS`, `SOCK_SEQPACKET`, cgroup-v2 test report | platform verifier |  |
| Node/SQLite/OpenSSL/compiler builds |  | binary hashes and package attestations | release authority |  |
| Repository commit and dependency lock |  | commit and lock digest | release authority |  |
| Clock service and approved sources |  | protected chrony/NTS configuration digest | system owner |  |
| Maximum clock offset/health |  | signed health sample | operational witness |  |
| Swap/core-dump policy |  | host-policy evidence | security authority |  |
| Network policy |  | firewall/namespace policy digest and test | security authority |  |

## Runtime identities and bindings

Record numeric identities and human identity references only in the protected copy.

| Frozen role | Local account or protected human reference | UID/GID or binding generation | Executable/build | Endpoint | Active/revoked/expiry | Evidence |
|---|---|---|---|---|---|---|
| `trusted_launcher` |  |  |  |  |  |  |
| `collector` |  |  |  |  |  |  |
| `handoff_broker` |  |  |  |  |  |  |
| `bundle_importer` |  |  |  |  |  |  |
| `database_writer` |  |  |  |  |  |  |
| `cloner_promoter` |  |  |  |  |  |  |
| `independent_verifier` |  |  |  |  |  |  |
| `custody_adapter` |  |  |  |  |  |  |
| `clearance_broker` |  |  |  |  |  |  |
| `journal_broker` |  |  |  |  |  |  |
| `scanner` |  |  |  |  |  |  |
| `backup_adapter` |  |  |  |  |  |  |
| `human_submitter` |  |  | n/a | launcher-mediated |  |  |
| `operational_witness` |  |  | n/a | launcher-mediated |  |  |
| `bootstrap_authority` |  |  | n/a | launcher-mediated |  |  |
| `clearance_decider` |  |  | n/a | launcher-mediated |  |  |
| `clearance_checker` |  |  | n/a | launcher-mediated |  |  |
| `recovery_operator` |  |  | n/a | launcher-mediated |  |  |
| `recovery_authority` |  |  | n/a | launcher-mediated |  |  |
| D9.4 `d940_roster_adopter` |  | extension/adoption binding | n/a | protected D9.4 adoption endpoint |  |  |
| D9.4 semantic authority: requester |  | exact adopted-roster assignment | n/a | protected D9.4 endpoint |  |  |
| D9.4 semantic authority: legal records |  | exact adopted-roster assignment | n/a | protected D9.4 endpoint |  |  |
| D9.4 semantic authority: privacy |  | exact adopted-roster assignment | n/a | protected D9.4 endpoint |  |  |
| D9.4 semantic authority: deletion |  | exact adopted-roster assignment | n/a | protected D9.4 endpoint |  |  |
| D9.5 backup producer mapping |  | `backup_adapter` generation/process |  | fixed backup endpoint |  |  |
| D9.5 restore executor mapping |  | fresh `cloner_promoter` process |  | fixed restore endpoint |  |  |
| D9.5 backup/restored-state verifiers |  | distinct `independent_verifier` process instances |  | fixed verifier endpoint |  |  |
| D9.5 persistence mapping |  | `journal_broker` generation/process |  | fixed journal endpoint |  |  |

For every binding, attach proof of exact D9.0.1/D9.4 generation verification, separation of duties, qualification/expiry where required, revocation status, peer-credential test, release digest, endpoint inode/owner/mode and process-bound descriptor revocation.

## Protected roots and storage

| Logical root | Exact path/device | Device/inode, owner/mode | Mount options/failure domain | Capacity/reserve | Encryption/key reference | Verification evidence |
|---|---|---|---|---|---|---|
| Reviewed releases | `/srv/jedi-atlas-pilot/releases` |  |  |  | n/a |  |
| Reviewed manifests | `/srv/jedi-atlas-pilot/reviewed-manifests` |  |  |  | n/a |  |
| Active protected generation | `/etc/jedi-atlas-pilot/active` |  |  |  | protected reference only |  |
| IPC/runtime | `/run/jedi-atlas-pilot` |  |  |  | n/a |  |
| Canonical database | `/var/lib/jedi-atlas-pilot/canonical` |  |  |  |  |  |
| Candidate databases | `/var/lib/jedi-atlas-pilot/candidates` |  |  |  |  |  |
| Primary CAS | `/var/lib/jedi-atlas-pilot/cas-primary` |  |  |  |  |  |
| Hostile staging | `/var/lib/jedi-atlas-pilot/hostile-staging` |  |  |  |  |  |
| Scan scratch | `/var/lib/jedi-atlas-pilot/scan-scratch` |  |  |  |  |  |
| Journals/checkpoints | `/var/lib/jedi-atlas-pilot/journals` |  |  |  |  |  |
| Clearance store | `/var/lib/jedi-atlas-pilot/clearance` |  |  |  |  |  |
| Restore staging | `/var/lib/jedi-atlas-pilot/restore-staging` |  |  |  |  |  |
| Independent backup | `/mnt/jedi-atlas-pilot-backup` |  |  |  | separate key reference |  |
| External rollback anchor |  |  | separate administration |  |  |  |

For each root, record root-confined/no-follow test results, unexpected-name inventory, hardlink/reflink checks, atomic rename and `fsync` fault tests, quota/reserve alarms, backup independence and rollback-anchor reachability. Do not record secret values.

## Configuration and operational limits

| Control | Approved value | Protected configuration digest | Verification result |
|---|---|---|---|
| D9.0.1 catalog/profile/fingerprint set |  |  |  |
| D9.3–D9.5 contract/fingerprint set |  |  |  |
| Manifest/artifact/count/path/IPC limits | frozen values |  |  |
| Operation/scanner/hash/backup/DB timeouts | frozen values |  |  |
| Scanner builds and rule-age ceiling |  |  |  |
| Hostile-input sandbox profile | `no_new_privs`; empty caps; pinned syscall policy; disposable mount/PID namespaces; no network/inherited FDs; bounded/reaped tree |  |  |
| Clock offset and source-age limits |  |  |  |
| RPO/RTO and measurement boundaries |  |  |  |
| Backup/technical-audit retention |  |  |  |
| Alert destinations and missed-run heartbeat |  |  |  |
| Incident commander and deputies | protected identity references |  |  |

## State baseline and authorization

Record the canonical database generation, hash, migration ledger, all 13 Atlas table counts, all legacy digests, journal/checkpoint/receipt heads, primary inventory, most recent prior- and final-backup receipt identities, unresolved incidents and holds. The expected pre-bootstrap Atlas count is zero in every Atlas table.

Attach approved decision-register records and stage-specific authorization IDs. Inventory completion is evidence only; it does not authorize bootstrap, collection, import, recovery, deletion, publication, or legal use.
