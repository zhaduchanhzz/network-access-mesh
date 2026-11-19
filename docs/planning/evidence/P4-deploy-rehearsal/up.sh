#!/bin/bash
# dep4 — nâng staging-giả từ 8840590 (Phase 3) lên 9736636 (lô Phase 4) theo trình tự đề xuất của diễn tập.
#   bash /root/dep4x/up.sh <stage>…   stage: snap:<nhãn> sync preflight render migrate agent app edge9 edge10
# Mỗi bước ghi mốc thời gian (epoch UTC) vào $X/steps.log để đối chiếu với probe.py ở ngoài.
source /root/dep4x/p3.sh
NEW=/root/src/new
V9=/root/src/v9
mark() { echo "$(date -u +%s.%N | cut -c1-14) $*" >> "$X/steps.log"; say "$*"; }
timed() { local t0 t1; t0=$(date +%s.%N); "$@"; t1=$(date +%s.%N); printf '  ⏱ %.1f s: %s\n' "$(echo "$t1 - $t0" | bc)" "$*"; }

st_snap() {  # dấu vân tay trước/sau: container, Headscale A/B, DB, edge
  local lbl=$1 f=$X/snap-$1.txt
  loadenv
  {
    echo "## container (tên, image, StartedAt, trạng thái)"
    docker ps -a --format '{{.Names}}' | sort | while read -r c; do
      docker inspect -f '{{.Name}} {{.Image}} {{.State.StartedAt}} {{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$c" | cut -c2- | sed -E 's/sha256:([0-9a-f]{12})[0-9a-f]+/\1/'
    done
    for s in tenant-a tenant-b; do
      echo "## $s"
      echo "policy sha256 $(docker exec "mg-hs-$s" headscale policy get | head -c -1 | sha256sum | cut -c1-16)"
      docker exec "mg-hs-$s" headscale nodes list -o json | python3 -c 'import json,sys
for n in json.load(sys.stdin) or []: print("node", n["id"], n["given_name"], "online" if n.get("online") else "offline", n["node_key"][:20])'
      docker exec "mg-hs-$s" headscale apikeys list -o json | python3 -c 'import json,sys,time
def exp(x):
    e = x.get("expiration")
    return float(e.get("seconds", 0)) if isinstance(e, dict) else time.mktime(time.strptime(str(e)[:19], "%Y-%m-%dT%H:%M:%S"))
k=[x["prefix"] for x in json.load(sys.stdin) or [] if exp(x) > time.time()]
print("apikeys valid", len(k), " ".join(sorted(k)))'
    done
    echo "## db"
    pg -c "SELECT 'schema', max(version_id) FROM goose_db_version WHERE is_applied" | tr '|' ' '
    for tb in tenants tenant_instances identities tenant_memberships platform_users policy_versions policy_applications device_inventory_cache sessions provisioning_jobs approval_requests tenant_invitations backups; do
      echo "$tb $(pg -c "SELECT count(*) FROM $tb")"
    done
    echo "audit_events $(pg -c "SELECT count(*) FROM audit_events")"
    pg -c "SELECT t.slug, t.status, i.status, coalesce(t.desired_policy_version_id::text,'-') FROM tenants t JOIN tenant_instances i ON i.tenant_id=t.id ORDER BY 1" | tr '|' ' '
    echo "## edge"
    echo "Caddyfile $(sha256sum /opt/meshguard/core/caddy/Caddyfile | cut -c1-16) $(grep -m1 -o 'template_version [0-9]*' /opt/meshguard/core/caddy/Caddyfile)"
    docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' mg-edge
  } > "$f" 2>&1
  echo "snapshot $lbl → $f ($(wc -l < "$f") dòng)"
}

st_sync() {
  local T; T=$(ts)
  mark "sync: ~/mg = 9736636 (bản cũ /root/mg.bak-$T), lưu compose/Caddyfile đang chạy vào /root/*.$T"
  cp -a "$MG" "/root/mg.bak-$T"
  rm -rf "$MG"; mkdir -p "$MG"; cp -a "$NEW/." "$MG/"
  mkdir -p "$MG/$ENVD"; cp -a "$X/env-dep4/." "$MG/$ENVD/"
  for f in app agent edge idp backup monitoring; do cp -a "/opt/meshguard/core/compose.$f.yaml" "/root/compose.$f.yaml.$T"; done
  cp -a /opt/meshguard/core/caddy/Caddyfile "/root/Caddyfile.v8.$T"
  echo "$T" > "$X/backup-ts"
}

st_preflight() {
  loadenv
  mark "preflight: test render của cây mới + dữ liệu chặn migration 0020/0024/0025"
  local t rc
  for t in test_render_app test_render_edge test_render_agent test_render_backup test_render_monitoring test_render_idp test_migrate_sh; do
    rc=0; python3 "tools/$t.py" > "$X/pre-$t.log" 2>&1 || rc=$?
    echo "$t exit $rc ($(grep -c '^PASS' "$X/pre-$t.log") PASS, $(grep -c '^FAIL' "$X/pre-$t.log") FAIL) $(grep -m1 '^INFO' "$X/pre-$t.log" | cut -c1-140)"
  done
  echo "membership status: $(pg -c "SELECT string_agg(status||'='||n, ' ') FROM (SELECT status, count(*) n FROM tenant_memberships GROUP BY 1) s")  (0024 chỉ nhận active|locked|offboarded)"
  echo "platform_users status: $(pg -c "SELECT string_agg(status||'='||n, ' ') FROM (SELECT status, count(*) n FROM platform_users GROUP BY 1) s")  (0025 chỉ nhận active|disabled)"
  echo "device_inventory_cache có enrollment_request_id: $(pg -c "SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id IS NOT NULL")  (0020 thêm FK — phải 0)"
  echo "job đang chạy/queued: $(pg -c "SELECT count(*) FROM provisioning_jobs WHERE status IN ('queued','running')")"
  echo "đĩa /var: $(df -h /var | tail -1 | awk '{print $4}') trống"
}

st_render() {
  loadenv
  mark "render: mg-app (template 4 + web), mg-agent (image mới), edge v9 (cây f7ceb5d) + v10 (cây mới)"
  local T; T=$(cat "$X/backup-ts")
  python3 tools/render_app.py "$ENVF" /tmp/mg-app --api-image "$(img api:new)" --worker-image "$(img worker:new)" --web-image "$(img web:new)" >/dev/null
  diff "/root/compose.app.yaml.$T" /tmp/mg-app/compose.app.yaml > "$X/diff-app.txt" || true
  echo "compose.app: $(grep -c '^[<>]' "$X/diff-app.txt") dòng khác; $(grep -m1 template_version /tmp/mg-app/compose.app.yaml | cut -c1-120)"
  python3 tools/render_agent.py "$ENVF" /tmp/agent --agent-image "$(img agent:new)" >/dev/null
  diff "/root/compose.agent.yaml.$T" /tmp/agent/compose.agent.yaml > "$X/diff-agent.txt" || true
  diff /opt/meshguard/core/agent/allowlist /tmp/agent/agent/allowlist > "$X/diff-allowlist.txt" && echo "allowlist không đổi"
  echo "compose.agent: $(grep -c '^[<>]' "$X/diff-agent.txt") dòng khác: $(grep '^[<>]' "$X/diff-agent.txt" | cut -c1-90 | tr '\n' ' ')"
  edge_render "/root/mg.bak-$T" /tmp/edge8
  edge_render "$V9" /tmp/edge9
  edge_render "$NEW" /tmp/edge10
  cmp -s /tmp/edge8/caddy/Caddyfile /opt/meshguard/core/caddy/Caddyfile && echo "v8 render == Caddyfile đang chạy"
  for v in 9 10; do
    diff /opt/meshguard/core/compose.edge.yaml "/tmp/edge$v/compose.edge.yaml" > "$X/diff-edge-compose-v$v.txt" || true
    echo "compose.edge v$v: $(grep '^[<>]' "$X/diff-edge-compose-v$v.txt" | tr '\n' ' ')"
    diff /tmp/edge$((v == 9 ? 8 : 9))/caddy/Caddyfile.render "/tmp/edge$v/caddy/Caddyfile.render" > "$X/diff-caddy-v$v.txt" || true
    echo "Caddyfile v$((v == 9 ? 8 : 9))→v$v: $(grep -c '^[<>]' "$X/diff-caddy-v$v.txt") dòng khác"
  done
  for s in api worker web agent; do echo "image $s:new $(img $s:new | cut -c8-19)"; done
}

st_migrate() {
  loadenv
  mark "migrate: cài compose.app.yaml mới (image migrate = api mới) rồi migrate.sh (backup pre-migration → 0020–0026)"
  install -m 0644 /tmp/mg-app/compose.app.yaml /opt/meshguard/core/compose.app.yaml
  timed bash infrastructure/host/migrate.sh > "$X/migrate.log" 2>&1
  grep -E '"state"|OK:|DỪNG|LỖI|backup done' "$X/migrate.log" | sed -E 's/.*"state":\{([^}]*)\}.*/state: \1/' | cut -c1-240
  $APP --profile migrate run --rm -T migrate migrate status 2>/dev/null | tail -1 | cut -c1-200
  ls -1 /opt/meshguard/backups/postgres/ | grep pre-migration | tail -2
  mark "migrate xong — api/worker CŨ vẫn chạy trên schema mới"
  for c in mg-app-api-1 mg-app-worker-1; do echo "$c (image cũ) $(docker exec "$c" /usr/local/bin/meshguard healthcheck 2>&1 | head -c 120)"; done
}

st_agent() {
  loadenv
  mark "agent: compose.agent.yaml mới (WriteDnsRecords — P4-T12), recreate"
  install -m 0644 /tmp/agent/compose.agent.yaml /opt/meshguard/core/compose.agent.yaml
  timed $AGENT up -d --wait --wait-timeout 120
  docker logs --since 1m mg-agent 2>&1 | grep -oE '"msg":"(agent_started|edge_supervisor_started|edge_cycle)[^"]*"' | sort | uniq -c | head
}

st_app() {
  loadenv
  mark "app: api/worker/mail-bridge image mới + web (mới) — up --wait"
  timed $APP up -d --wait --wait-timeout 240 api worker web mail-bridge
  for c in mg-app-api-1 mg-app-worker-1 mg-app-mail-bridge-1; do echo "$c $(docker exec "$c" /usr/local/bin/meshguard healthcheck 2>&1 | head -c 120)"; done
  docker exec mg-app-web-1 /usr/bin/healthprobe http://127.0.0.1:8080/ 200 && echo "web healthprobe 200"
  sleep 15
  $APP logs --since 2m worker 2>&1 | grep -oE '"msg":"[^"]*(wired|schedul|configured)[^"]*"' | sort | uniq -c | head -20
}

edge_reload() {  # <render dir> <phiên bản cũ>
  local d=$1 old=$2 T; T=$(ts)
  diff /opt/meshguard/core/compose.edge.yaml "$d/compose.edge.yaml" | grep '^[<>]' | grep -v '^[<>] #' && { echo "compose.edge đổi ngoài chú thích ⇒ phải recreate — dừng"; exit 1; }
  cp -a /opt/meshguard/core/caddy/Caddyfile "/root/Caddyfile.v$old.$T"
  cp -a /opt/meshguard/core/compose.edge.yaml "/root/compose.edge.yaml.v$old.$T"
  install -m 0644 "$d/compose.edge.yaml" /opt/meshguard/core/compose.edge.yaml
  install -m 0644 "$d/caddy/Caddyfile" /opt/meshguard/core/caddy/Caddyfile
  docker exec mg-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1
  timed docker exec mg-edge caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock
  grep -m1 -o 'template_version [0-9]*' /opt/meshguard/core/caddy/Caddyfile
}

st_edge9() { loadenv; mark "edge v8 → v9 (reload; render từ cây f7ceb5d — cây 9736636 chỉ render được v10)"; edge_reload /tmp/edge9 8; }
st_edge10() { loadenv; mark "edge v9 → v10 (reload; render từ cây 9736636)"; edge_reload /tmp/edge10 9; }

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  for s in "$@"; do
    case $s in snap:*) st_snap "${s#snap:}" ;; *) "st_$s" ;; esac
  done
fi
true
