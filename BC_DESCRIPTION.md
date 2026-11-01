## Summary

On ClickHouse **26.10.2.103** (and other current stables/LTS without the fix), a scheduled refresh of a `SQL SECURITY DEFINER` refreshable materialized view that reads a `Distributed` table against a cluster configured with an interserver `<secret>` is executed on the remote shard **without authentication**, with **full access**.

A low-privilege user who can create tables in their own database can wrap any remote table in `Distributed`, point a DEFINER refreshable MV at it, and have the scheduler copy rows they have **no grant** on into a table they own.

## Root cause

`StorageInMemoryMetadata::getSQLSecurityOverriddenContext` builds the DEFINER context from the **global** context and calls `Context::setUser(definer)`, which sets only `user_id`. For a scheduled refresh there is no invoker, so `ClientInfo.current_user` / `initial_user` / `authenticated_user` remain **empty**.

`RemoteQueryExecutor` forwards those empty names. On a shard that accepts the interserver `<secret>`, an empty `initial_user` is treated as **interserver mode** (`TCPHandler::receiveQuery`), which **skips authentication** and runs with full access (`Context::getAccess`, `full_access = !user_id`).

## Affected

- Confirmed: official build **26.10.2.103** (latest 26.10 stable at time of testing).
- Likely: 26.9.x stable, 26.8 LTS, 26.3 LTS (fix not present in those tags).
- Fixed in: commit `25631f3775a5ebaebae8ddbecbbd367f3cf310cd` / PR #117798 (merged 2026-11-01 into master / 26.11 line; **not** in any published stable/LTS tag tested).

## Prerequisites

1. ClickHouse cluster with `remote_servers` `<secret>` configured.
2. Attacker authenticated with: `CREATE TABLE`, `SELECT`, `INSERT` on own database; `TABLE ENGINE ON Distributed`.
3. Ability to create a refreshable materialized view (`SQL SECURITY DEFINER`).
4. Target data reachable via `Distributed` from the attacker’s node (typical multi-tenant / shared-cluster layout).

## Steps to reproduce (synthetic)

See `poc_e2e.sh` in the evidence package (spins up local 2-node + keeper using the official 26.10.2.103 static binaries).

Abbreviated:

1. Node2 holds `lab.secrets` (synthetic payloads). User `tenant` exists on both nodes with **no** `SELECT` on `lab.secrets`.
2. As `tenant` on node1: create `Distributed('secure','lab','secrets',…)` and a DEFINER refreshable MV selecting from it into `tenant_db.target`.
3. `SELECT * FROM tenant_db.dist` as `tenant` → **ACCESS_DENIED**.
4. `SYSTEM WAIT VIEW tenant_db.rmv` → **succeeds**; `tenant_db.target` contains all secret rows.
5. Copied rows show empty `currentUser()` / `authenticatedUser()`, consistent with unauthenticated interserver mode.

## Negative controls

- Direct `Distributed` read by the same user is correctly denied (grant enforcement works when identity is present).
- Upstream integration test `tests/integration/test_refreshable_mv_definer_interserver_secret/test.py` (in PR #117798) asserts `ACCESS_DENIED` on `SYSTEM WAIT VIEW` after the fix, and success only after an explicit `GRANT SELECT` on the remote table.

## Impact

**Privilege escalation / authorization bypass (Critical–High).** Cross-database / cross-tenant read of arbitrary remote tables on the cluster; integrity impact if the MV writes attacker-controlled targets. No admin role required beyond ordinary DDL in the attacker’s database.

## Suggested fix

Already landed upstream: stamp the definer into empty `ClientInfo` user name fields in `getSQLSecurityOverriddenContext` (and related Distributed async-insert identity preservation). Please release a patched 26.10 / LTS build.

## CVSS (proposed)

`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` ≈ **8.5 High** (scope change via cluster shards).

## VRT

Broken Access Control > Privilege Escalation
