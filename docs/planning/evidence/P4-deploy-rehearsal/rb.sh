#!/bin/bash
# dep4 — diễn tập hoàn tác lô Phase 4.
#   fast  (A) không đụng DB: edge về Caddyfile v8, agent/api/worker/mail-bridge về image cũ, gỡ web, ~/mg về bản cũ —
#             api/worker cũ chạy trên schema 26 (migration expand-only)
#   full  (B) restore bộ pre-migration (backup-restore.md 6.3 + 6.5): bảo trì → dừng api/worker → giữ DB cũ (đổi tên) →
#             globals → pg_restore → bảo trì trong DB vừa restore → khởi động (image cũ) → post-restore-reconcile →
#             tắt bảo trì → backup manual
source /root/dep4x/up.sh
T=$(cat "$X/backup-ts" 2>/dev/null || true)

st_fast() {
  mark "rollback A: edge v8 (reload), agent + api/worker/mail-bridge image cũ, gỡ web, ~/mg cũ"
  [ -n "$T" ] || { echo "thiếu $X/backup-ts"; exit 1; }
  local cur; cur=$(grep -m1 -o 'template_version [0-9]*' /opt/meshguard/core/caddy/Caddyfile | awk '{print $2}')
  cp -a /opt/meshguard/core/caddy/Caddyfile "/root/Caddyfile.v$cur.rollback.$(ts)"
  install -m 0644 "/root/Caddyfile.v8.$T" /opt/meshguard/core/caddy/Caddyfile
  install -m 0644 "/root/compose.edge.yaml.$T" /opt/meshguard/core/compose.edge.yaml
  docker exec mg-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1
  timed docker exec mg-edge caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock
  install -m 0644 "/root/compose.agent.yaml.$T" /opt/meshguard/core/compose.agent.yaml
  timed $AGENT up -d --wait --wait-timeout 120
  install -m 0644 "/root/compose.app.yaml.$T" /opt/meshguard/core/compose.app.yaml
  timed $APP up -d --wait --wait-timeout 240 --remove-orphans api worker mail-bridge
  echo "web còn: $(docker ps -a --format '{{.Names}}' | grep -c '^mg-app-web-1$' || true)"
  rm -rf "$MG"; cp -a "$(ls -d /root/mg.bak-* | sort | tail -1)" "$MG"
  for c in mg-app-api-1 mg-app-worker-1 mg-app-mail-bridge-1; do echo "$c $(docker exec "$c" /usr/local/bin/meshguard healthcheck 2>&1 | head -c 160)"; done
  docker logs --since 2m mg-app-api-1 2>&1 | grep -iE '"level":"(ERROR|WARN)"' | cut -c1-240 | head -5
  docker logs --since 2m mg-app-worker-1 2>&1 | grep -iE '"level":"ERROR"' | cut -c1-240 | head -5
}

st_full() {
  loadenv
  local B PG AGE RP TS2 rc
  B=$(ls -1 /opt/meshguard/backups/postgres/*-pre-migration.manifest.json | sort | tail -1); B=${B%.manifest.json}
  PG=$($CORE ps -q postgres)
  AGE="infrastructure/host/key-ceremony/bin/age --decrypt --identity /run/mg-restore/identity"
  mark "rollback B: restore $(basename "$B") (backup-restore.md 6.3/6.5) — image cũ đang chạy"
  ( cd /opt/meshguard/backups/postgres && python3 -c 'import json,sys,hashlib,os
m=json.load(open(sys.argv[1])); bad=[f["name"] for f in m["files"] if hashlib.sha256(open(f["name"],"rb").read()).hexdigest()!=f["sha256"]]
print("manifest", m.get("id"), "started_at", m.get("started_at"), "sha256 lệch:", bad or "không")' "$(basename "$B").manifest.json" )
  mark "B1 bảo trì + dừng api/worker"
  timed $APP exec -T api /usr/local/bin/meshguard admin maintenance on --reason pg-restore | tail -1
  sleep 11
  $APP logs --since 1m worker 2>&1 | grep -c 'stopping the job worker' | xargs echo "worker dừng job:"
  timed $APP stop api worker
  mark "B2 giữ DB hiện tại (đổi tên) + globals + pg_restore"
  TS2=$(date -u +%Y%m%d%H%M)
  docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'meshguard' AND pid <> pg_backend_pid()" \
    -c "ALTER DATABASE meshguard RENAME TO meshguard_before_restore_$TS2" >/dev/null
  cat "$B.globals.sql.age" | $AGE | sed -E '/^CREATE ROLE [a-z_][a-z0-9_]*;$/d' \
    | docker exec -i "$PG" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1 | grep -v '^$' | head -5
  timed bash -c "cat '$B.pgdump.age' | $AGE | docker exec -i '$PG' pg_restore -U postgres -d postgres --create --exit-on-error"
  echo "schema sau restore: $(pg -c "SELECT max(version_id) FROM goose_db_version WHERE is_applied")"
  mark "B3 migrate status (image cũ) + bảo trì trong DB vừa restore + khởi động"
  rc=0; $APP --profile migrate run --rm -T migrate migrate status 2>/dev/null | tail -1 | cut -c1-160 || rc=$?; echo "migrate status exit $rc"
  $APP run --rm --no-deps -T api admin maintenance on --reason post-restore 2>&1 | tail -1
  timed $APP up -d --wait --wait-timeout 240 api worker
  RP=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["started_at"])' "$B.manifest.json")
  mark "B4 post-restore-reconcile --restore-point $RP (dry-run rồi thật)"
  $APP exec -T worker /usr/local/bin/meshguard admin post-restore-reconcile --restore-point "$RP" --dry-run > "$X/post-restore-dry.json" 2>"$X/post-restore-dry.err" || true
  rc=0; $APP exec -T worker /usr/local/bin/meshguard admin post-restore-reconcile --restore-point "$RP" > "$X/post-restore.json" 2>"$X/post-restore.err" || rc=$?
  echo "post-restore-reconcile exit $rc"
  python3 - "$X/post-restore.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:  # noqa: BLE001
    print("báo cáo không đọc được:", e); sys.exit(0)
print("status", d.get("status"), "incomplete", d.get("incomplete"), "review_required", [ (r.get("tenant") or r.get("slug"), r.get("reason")) for r in d.get("review_required") or []])
for k in ("sessions", "approvals", "invitations", "support_grants", "instances", "api_keys", "policies", "open_jobs"):
    v = d.get(k)
    print(" ", k, json.dumps(v, ensure_ascii=False)[:220] if v is not None else "-")
PY
  mark "B5 tắt bảo trì + backup manual"
  $APP exec -T api /usr/local/bin/meshguard admin maintenance off 2>&1 | tail -1
  $BK run --rm -T pg-backup once --label manual 2>&1 | tail -1 | cut -c1-200
  for c in mg-app-api-1 mg-app-worker-1; do echo "$c $(docker exec "$c" /usr/local/bin/meshguard healthcheck 2>&1 | head -c 160)"; done
}

for s in "$@"; do "st_$s"; done
