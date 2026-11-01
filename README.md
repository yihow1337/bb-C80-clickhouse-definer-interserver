# ClickHouse — DEFINER refreshable MV over Distributed authentication bypass (interserver secret)

**Program:** ClickHouse Managed Bug Bounty (Bugcrowd)  
**Asset:** github.com/ClickHouse/ClickHouse (self-hosted / cluster builds)  
**Severity (researcher):** High / Critical (privilege escalation)  
**Suggested VRT:** Broken Access Control > Privilege Escalation  
**Affected version tested:** 26.10.2.103 (official Linux amd64 static build)  
**Fix:** PR [#117798](https://github.com/ClickHouse/ClickHouse/pull/117798) / commit `25631f3775a5ebaebae8ddbecbbd367f3cf310cd` (merged 2026-11-01; not in published 26.10.2 / 26.9.x / 26.8 LTS / 26.3 LTS tags)

## Vulnerability

A scheduled refresh of a `SQL SECURITY DEFINER` refreshable materialized view whose query reads a `Distributed` table is sent to remote shards with an **empty** `ClientInfo.initial_user` when the refresh context is built from the global context. On clusters that configure an interserver `<secret>`, the receiving shard treats an empty `initial_user` as interserver mode, **skips authentication**, and executes the query with **full access**.

An attacker with only ordinary grants on their own database (`CREATE TABLE`, `SELECT`, `INSERT`, plus `TABLE ENGINE ON Distributed`) can therefore read arbitrary remote tables they are not granted on, by wrapping them in `Distributed` and letting the MV scheduler copy the rows into a table they own.

## Trust-boundary failure

| Layer | Expected | Actual (26.10.2.103) |
|---|---|---|
| Local DEFINER context | Query runs as definer (`user_id`) | `setUser(definer)` sets `user_id` only |
| ClientInfo for refresh | Definer identity in `initial_user` / `current_user` | Empty (inherited from global context) |
| Remote shard with `<secret>` | Authenticate as definer; enforce grants | Empty `initial_user` → interserver mode → no auth, full access |

Relevant sink: `TCPHandler::receiveQuery` interserver branch; `Context::getAccess` with `full_access = !user_id`.

## Proof of concept (e2e against released binary)

Environment: official `clickhouse-common-static-26.10.2.103` + `clickhouse-keeper-26.10.2.103`, two local servers + keeper, `remote_servers.secure.secret` set. Script: `poc_e2e.sh`.

**Negative control — direct read denied:**

```
Code: 497. ... tenant: Not enough privileges. ... SELECT ON lab.secrets. (ACCESS_DENIED)
```

**Exploit — refresh copies secrets anyway:**

```
SELECT count() FROM tenant_db.target  →  3
SELECT * FROM tenant_db.target ORDER BY id
1  SYNTH-SECRET-A   <empty current_user>  <empty authenticated_user>
2  SYNTH-SECRET-B   ...
3  SYNTH-SECRET-C   ...
SYSTEM WAIT VIEW tenant_db.rmv         →  success (exit 0)
```

Empty identity columns confirm the remote leg ran in unauthenticated interserver mode rather than as the definer.

Upstream’s post-fix integration test (`tests/integration/test_refreshable_mv_definer_interserver_secret/test.py`) expects `ACCESS_DENIED` on `SYSTEM WAIT VIEW` until `GRANT SELECT ON lab.secrets TO tenant` is issued on the remote node.

## Code references

Vulnerable (tag `v26.10.2.103-stable`): `StorageInMemoryMetadata::getSQLSecurityOverriddenContext` — DEFINER branch calls `setUser` without filling empty ClientInfo names.

Fixed: same function stamps definer into empty `current_user` / `initial_user` / `authenticated_user`, and related Distributed async-insert batching preserves per-user `ClientInfo`.

Diff excerpt is in the evidence package (`diff/`).

## Impact

- Confidentiality: read any table reachable via Distributed on the secret-enabled cluster.
- Integrity: append attacker-chosen data into attacker-owned tables from privileged sources.
- No need for admin / `GRANT` on the victim database.
- Multi-tenant shared clusters are the realistic deployment for this class.

## Remediation

Ship the #117798 fix in 26.10.x and active LTS lines. Until then, mitigate by not granting `TABLE ENGINE ON Distributed` / refreshable MV DDL to untrusted tenants on secret-enabled clusters, or temporarily disable refreshable MVs for those users.

## Novelty notes

Distinct from earlier DEFINER/ATTACH issues (e.g. #94865) and from open parallel-replicas identity work (#123729). No CVE/GHSA was found for this empty-`initial_user` + refreshable-MV + interserver-secret path at report time. The fix PR is public but **unreleased** on current stables.

## Evidence checklist

- [x] Exact vulnerable release binary (`26.10.2.103`)
- [x] Harmless synthetic payloads only
- [x] Negative control (direct Distributed ACCESS_DENIED)
- [x] Differential vs fix commit / upstream test expectations
- [x] Reproducible `poc_e2e.sh`
