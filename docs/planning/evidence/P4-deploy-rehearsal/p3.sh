#!/bin/bash
# dep4 — dựng lại trạng thái staging Phase 3 (commit 8840590, image d8a4223-tương-đương build từ cây) trong host lồng,
# theo đúng thứ tự current.md §3 + deploy-backend a–l + RUNBOOK + nhật ký current.md (đợt 1–12). Mỗi stage một hàm:
#   bash /root/dep4x/p3.sh <stage>…        (stage: env base edge tenants idp app registry agent obs backfill)
source /root/dep4x/lib.sh

edge_render() {   # <tree dir> <out>: render_edge của cây đó + đổi khối tls ACME DNS-01 ⇒ chứng chỉ CA thử (stack.ci_tls)
  local tree=$1 out=$2
  rm -rf "$out"
  (cd "$tree" && python3 tools/render_edge.py "$MG/$ENVD/edge.json" "$out" >/dev/null)
  cp "$out/caddy/Caddyfile" "$out/caddy/Caddyfile.render"
  (cd "$MG" && python3 -I -c 'import pathlib, sys
sys.path.insert(0, "tests/e2e/harness")
import stack
p = pathlib.Path(sys.argv[1])
p.write_text(stack.ci_tls(p.read_text(encoding="utf-8")), encoding="utf-8")' "$out/caddy/Caddyfile")
}

st_env() {
  say "env: ~/mg = cây 8840590 + môi trường thử dep4 (không secret, giá trị hư cấu)"
  rm -rf "$MG"; mkdir -p "$MG"; cp -a /root/src/old/. "$MG/"
  mkdir -p "$MG/$ENVD/tenants"
  local ids ida idb idc
  ids=$(cd "$MG" && python3 tools/render_idp.py new-ids | grep -oE '[0-9a-f]{8}-[0-9a-f-]{27}' | tr '\n' ' ')
  read -r ida idb idc <<<"$ids"
  [ -n "$idc" ] || { echo "new-ids: '$ids'"; exit 1; }
  cat > "$MG/$ENVF" <<EOF
# Môi trường DIỄN TẬP dep4 (VM 110, host lồng) — KHÔNG phải staging. Giá trị hư cấu: domain .test (RFC 2606), LAN/tunnel
# là network Docker của VM 110, "IP công khai" 192.88.99.10 (dải 6to4 relay anycast đã bỏ — RFC 7526; Python xếp global, không ai dùng). Không secret.
MG_ENV=staging
MG_BASE_DOMAIN=dep4.test
MG_DNS_ZONE=dep4.test
MG_PUBLIC_IPV4=192.88.99.10
MG_LAN_IPV4=10.77.4.10
MG_LAN_CIDR=10.77.4.0/24
MG_TUNNEL_HOST_IPV4=10.77.5.2
MG_TUNNEL_VPS_IPV4=10.77.5.3
MG_TUNNEL_PORT=51820
MG_TUNNEL_HTTP_PORT=8080
MG_TUNNEL_HTTPS_PORT=8443
MG_ACME=staging
MG_ACME_ACCOUNT_URI=https://acme-staging-v02.api.letsencrypt.org/acme/acct/0
MG_DNS_RESOLVERS=1.1.1.1,8.8.8.8
MG_TENANT_NAMESERVERS=1.1.1.1,1.0.0.1
MG_IDP_ID_PLATFORM=$ida
MG_IDP_ID_TENANT_A=$idb
MG_IDP_ID_TENANT_B=$idc
MG_IDP_MAIL_SINK=mailrelay
MG_MAILRELAY_URL=https://mailrelay.invalid/v1/send
MG_SMTP_FROM=
MG_MAILRELAY_WORKER_NAME=
MG_BACKUP_RECOVERY_RECIPIENT=
MG_BACKUP_MANIFEST_PUBKEY=
MG_PROBER_URL=http://10.249.2.3:8080
MG_ALERT_SINK=on
MG_ALERT_EMAIL_TO=
MG_ALERT_SMTP_SMARTHOST=
MG_ALERT_SMTP_CA_FILE=
MG_ALERT_SMTP_USERNAME=
MG_ALERT_SMTP_REQUIRE_TLS=true
MG_ALERT_TELEGRAM_CHAT_ID=
MG_ALERT_WEBHOOK=off
EOF
  cp "$MG/infrastructure/environments/staging/edge.json" "$MG/infrastructure/environments/staging/gateway.json" "$MG/$ENVD/"
  cp "$MG/infrastructure/environments/staging/tenants/"tenant-{a,b}.json "$MG/$ENVD/tenants/"
  cp -a "$MG/$ENVD" "$X/env-dep4"           # bản giữ lại để chép vào cây mới khi nâng cấp
  (cd "$MG" && python3 tools/mgenv.py show "$ENVF" | head -3)
}

st_base() {
  loadenv
  say "layout.sh + networks.sh"
  bash infrastructure/host/layout.sh >/dev/null
  bash infrastructure/host/networks.sh
  say "firewall host (template của repo; nested không có systemd ⇒ nft -c rồi nft -f thay cho apply-firewall.sh)"
  python3 tools/mgenv.py render infrastructure/host/mg-staging-firewall.nft "$ENVF" > "$X/fw.nft"
  # apply-firewall.sh từ chối mọi '${MG_' — kể cả dòng chú thích 1 của template (lỗi F-1 của diễn tập): ở đây chỉ xét dòng lệnh
  if grep -q '\${MG_' "$X/fw.nft"; then echo "F-1: apply-firewall.sh sẽ từ chối: $(grep -n '\${MG_' "$X/fw.nft" | cut -c1-60)"; fi
  grep -v '^[[:space:]]*#' "$X/fw.nft" | grep -q '\${MG_' && { echo "còn placeholder"; exit 1; }
  nft -c -f "$X/fw.nft" && nft -f "$X/fw.nft"
  nft list table inet mg_host | grep -cE 'accept|drop' | xargs echo "rules inet mg_host:"
  say "core: postgres + crowdsec (nạp hub qua mg-egress một lần, rồi bỏ đường ra)"
  install -m 0644 infrastructure/compose/compose.core.yaml infrastructure/compose/compose.crowdsec-hub.yaml /opt/meshguard/core/
  install -m 0644 infrastructure/crowdsec/config.yaml.local /opt/meshguard/core/crowdsec/
  install -m 0644 infrastructure/crowdsec/acquis.d/caddy.yaml /opt/meshguard/core/crowdsec/acquis.d/
  docker compose -p mg-core -f /opt/meshguard/core/compose.core.yaml -f /opt/meshguard/core/compose.crowdsec-hub.yaml up -d crowdsec
  wait_healthy mg-crowdsec 300
  docker exec mg-crowdsec cscli collections list -o raw | head -5
  $CORE up -d
  wait_healthy mg-core-postgres-1 120; wait_healthy mg-crowdsec 300
}

st_keys() {
  loadenv
  say "nghi thức khóa (ceremony.sh, MGKC_ENV_FILE=dep4.env): build age, preflight, generate"
  if [ ! -d /opt/meshguard/secrets/kek-app ]; then
    bash infrastructure/host/key-ceremony/build-age.sh infrastructure/host/key-ceremony/bin > "$X/build-age.log" 2>&1 || { tail -20 "$X/build-age.log"; exit 1; }
    tail -3 "$X/build-age.log"
    export MGKC_ENV_FILE=$MG/$ENVF MGKC_WORKER_IMAGE=$(img worker:old)
    bash infrastructure/host/key-ceremony/ceremony.sh preflight | tail -3
    bash infrastructure/host/key-ceremony/ceremony.sh generate | grep -E 'KCV|recipient|SPKI|công khai ký' || true
  fi
  # Identity khôi phục: trên staging là bản giấy của chủ dự án; ở diễn tập giữ bản trên tmpfs /run (không ra đĩa) cho
  # bước rollback (backup-restore.md 6.2), xóa khi dọn.
  install -d -m 0700 /run/mg-restore
  install -m 0400 /run/mg-key-ceremony/recovery.agekey /run/mg-restore/identity
  local rec spki
  rec=$(grep -v '^#' /opt/meshguard/core/keys/backup-recovery.age-recipient)
  spki=$(grep -v '^-----' /opt/meshguard/core/keys/manifest-signing.pub.pem | tr -d '\n')
  [ "$(infrastructure/host/key-ceremony/bin/age-keygen -y /run/mg-restore/identity)" = "$rec" ] && echo "identity khớp recipient"
  sed -i "s|^MG_BACKUP_RECOVERY_RECIPIENT=.*|MG_BACKUP_RECOVERY_RECIPIENT=$rec|; s|^MG_BACKUP_MANIFEST_PUBKEY=.*|MG_BACKUP_MANIFEST_PUBKEY=$spki|" "$MG/$ENVF"
  cp "$MG/$ENVF" "$X/env-dep4/dep4.env"
  bash infrastructure/host/key-ceremony/ceremony.sh status | tail -8
}

st_edge() {
  loadenv
  say "edge: CA thử + chứng chỉ (thay ACME DNS-01 — chỉ kiểm được trên staging), render template của cây 8840590"
  local s=/opt/meshguard/secrets/edge c=$X/ca
  test -s $s/cloudflare_dns_token || { umask 077; printf 'dep4-not-a-token\n' > $s/cloudflare_dns_token; }
  chown root:mg-sec-edge $s/cloudflare_dns_token; chmod 0440 $s/cloudflare_dns_token
  mkdir -p "$c"; chmod 0700 "$c"
  if [ ! -s "$c/ca.crt" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 -subj "/CN=dep4 rehearsal CA" \
      -keyout "$c/ca.key" -out "$c/ca.crt" -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "nameConstraints=critical,permitted;DNS:$MG_BASE_DOMAIN" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=*.mesh.$MG_BASE_DOMAIN" \
      -keyout "$c/leaf.key" -out "$c/leaf.csr" 2>/dev/null
    printf 'subjectAltName=DNS:*.mesh.%s,DNS:app.%s,DNS:admin.%s,DNS:auth.%s\nextendedKeyUsage=serverAuth\n' \
      "$MG_BASE_DOMAIN" "$MG_BASE_DOMAIN" "$MG_BASE_DOMAIN" "$MG_BASE_DOMAIN" > "$c/leaf.ext"
    openssl x509 -req -in "$c/leaf.csr" -CA "$c/ca.crt" -CAkey "$c/ca.key" -CAcreateserial -days 7 -extfile "$c/leaf.ext" \
      -out "$c/leaf.crt" 2>/dev/null
    shred -u "$c/ca.key"
  fi
  install -o root -g mg-sec-edge -m 0440 "$c/leaf.crt" $s/dep4_tls_cert
  install -o root -g mg-sec-edge -m 0440 "$c/leaf.key" $s/dep4_tls_key
  edge_render "$MG" /tmp/edge
  grep -m1 template_version /tmp/edge/caddy/Caddyfile.render
  install -m 0644 /tmp/edge/caddy/Caddyfile /opt/meshguard/core/caddy/Caddyfile
  install -m 0644 /tmp/edge/compose.edge.yaml /opt/meshguard/core/compose.edge.yaml
  cat > /opt/meshguard/core/compose.edge.dep4tls.yaml <<'EOF'
# DIỄN TẬP dep4: chứng chỉ của CA thử thay ACME DNS-01 (Caddyfile đã qua stack.ci_tls) — không có trên staging.
services:
  edge:
    secrets:
      - {source: dep4_tls_cert, target: edge_tls_cert}
      - {source: dep4_tls_key, target: edge_tls_key}
secrets:
  dep4_tls_cert: {file: /opt/meshguard/secrets/edge/dep4_tls_cert}
  dep4_tls_key: {file: /opt/meshguard/secrets/edge/dep4_tls_key}
EOF
  install -d -m 0755 /opt/meshguard/core/dep4-ca && install -m 0644 "$c/ca.crt" /opt/meshguard/core/dep4-ca/ca.crt
  local svc
  { echo "# DIỄN TẬP dep4: tin CA thử (staging: chứng chỉ ACME công khai, không có file này)"; echo "services:"
    for svc in api worker; do
      printf '  %s:\n    environment: {SSL_CERT_FILE: /etc/dep4-ca/ca.crt, SSL_CERT_DIR: /etc/dep4-ca}\n' "$svc"
      printf '    volumes: [{type: bind, source: /opt/meshguard/core/dep4-ca, target: /etc/dep4-ca, read_only: true}]\n'
    done; } > /opt/meshguard/core/compose.app.dep4ca.yaml
  { echo "# DIỄN TẬP dep4: prober tin CA thử"; echo "services:"; echo "  prober:"
    echo "    environment: {MG_PROBE_CA_FILE: /etc/dep4-ca/ca.crt}"
    echo "    volumes: [{type: bind, source: /opt/meshguard/core/dep4-ca, target: /etc/dep4-ca, read_only: true}]"; } \
    > /opt/meshguard/core/compose.monitoring.dep4ca.yaml
  $EDGE config -q
  $EDGE up -d
  wait_healthy mg-edge 120
  docker exec mg-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1
}

st_tenants() {
  loadenv
  for S in tenant-a tenant-b; do
    say "tenant $S: render_instance → tenant-deploy → reattach-edge → fixture test-allow-intra (như Phase 1)"
    python3 tools/render_instance.py "$ENVD/tenants/$S.json" "/tmp/render/$S" >/dev/null
    bash infrastructure/host/tenant-deploy.sh "/tmp/render/$S" | tail -2
    bash infrastructure/host/reattach-edge.sh "$S"
    bash infrastructure/host/tenant-policy.sh "$S" infrastructure/headscale/templates/test-allow-intra.hujson
  done
  python3 tools/health_probe.py "$MG_LAN_IPV4" "mesh.$MG_BASE_DOMAIN" tenant-a tenant-b 2>&1 | tail -4 || true
}

st_idp() {
  loadenv
  say "relay thư: mail-secrets.sh (khóa HMAC, CA nội bộ) — Worker Cloudflare KHÔNG có (MG_MAILRELAY_URL .invalid)"
  bash infrastructure/host/mail-secrets.sh | tail -3
  say "IdP: secrets.sh, render_idp (image pin [images.mg-idp]), up"
  bash infrastructure/idp/secrets.sh | tail -2
  python3 tools/render_idp.py "$ENVF" /tmp/mg-idp >/dev/null
  install -d -o root -g root -m 0755 /opt/meshguard/core/idp/realms /opt/meshguard/core/idp/initdb
  install -m 0644 /tmp/mg-idp/compose.idp.yaml /opt/meshguard/core/compose.idp.yaml
  install -m 0644 /tmp/mg-idp/idp/realms/*.json /opt/meshguard/core/idp/realms/
  install -m 0644 /tmp/mg-idp/idp/initdb/*.sql /opt/meshguard/core/idp/initdb/
  $IDP config --quiet
  $IDP up -d
  wait_healthy mg-idp-idp-1 400
  $IDP ps --format '{{.Service}} {{.Status}}'
}

st_app() {
  loadenv
  say "app: app-secrets.sh + check-secrets.sh"
  bash infrastructure/host/app-secrets.sh | tail -1
  bash infrastructure/host/check-secrets.sh | grep -cE '^PASS' | xargs echo "check-secrets PASS:"
  bash infrastructure/host/check-secrets.sh | grep -E '^FAIL' || true
  say "mg-backup: render (image backup:old), check ×3"
  python3 tools/render_backup.py "$ENVF" /tmp/mg-backup --image "$(img backup:old)" >/dev/null
  install -m 0644 /tmp/mg-backup/compose.backup.yaml /opt/meshguard/core/compose.backup.yaml
  say "mg-app: render (api/worker :old — template 3), db-bootstrap, migrate.sh, up"
  python3 tools/render_app.py "$ENVF" /tmp/mg-app --api-image "$(img api:old)" --worker-image "$(img worker:old)" >/dev/null
  install -m 0644 /tmp/mg-app/compose.app.yaml /opt/meshguard/core/compose.app.yaml
  $APP config -q
  $APP --profile bootstrap run --rm -T db-bootstrap | tail -1
  for s in pg-backup idp-backup edge-backup; do $BK run --rm -T "$s" check >/dev/null && echo "check $s ok"; done
  bash infrastructure/host/migrate.sh 2>&1 | grep -E '"current"|OK:|DỪNG|LỖI' | cut -c1-300
  $APP up -d --wait --wait-timeout 240 api worker mail-bridge
  docker exec mg-app-api-1 /usr/local/bin/meshguard healthcheck | head -c 300; echo
  docker exec mg-app-worker-1 /usr/local/bin/meshguard healthcheck | head -c 300; echo
}

uid() { bash infrastructure/idp/user-id.sh "$1" "$2" | python3 -c 'import json,sys; u=json.load(sys.stdin); assert len(u)==1; print(u[0]["id"])'; }

st_registry() {
  loadenv
  local CORE2="$APP" RANGE POOL S NAME IID T
  RANGE=$(python3 -c 'import tomllib; print(tomllib.load(open("versions.lock","rb"))["ids"]["tenant_run_uid_range"])')
  POOL=$(python3 -c 'import tomllib; print(tomllib.load(open("versions.lock","rb"))["ids"]["tenant_net_pool"])')
  say "register-platform-idp + adopt A/B (deploy-backend e)"
  $CORE2 run --rm --no-deps -T -e "MG_IDP_ID_PLATFORM=$MG_IDP_ID_PLATFORM" api admin register-platform-idp | tail -1
  for S in tenant-a tenant-b; do
    NAME="Tenant ${S: -1}"; NAME=${NAME^^}; NAME="Tenant ${NAME: -1}"
    IID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["instance_id"])' "$ENVD/tenants/$S.json")
    T=$(mktemp -d); install -m 0444 "/opt/meshguard/tenants/$IID/meta/instance.json" "$T/instance.json"
    docker exec "mg-hs-$S" headscale apikeys create -e 2160h -o json \
      | $CORE2 run --rm --no-deps -T -e "MG_IDP_ID_TENANT_A=$MG_IDP_ID_TENANT_A" -e "MG_IDP_ID_TENANT_B=$MG_IDP_ID_TENANT_B" \
          -v "$T/instance.json:/run/mg-adopt/instance.json:ro" \
          api admin adopt-instance --host mg-staging --host-region lab --run-uid-range "$RANGE" --tenant-net-pool "$POOL" \
          --name "$NAME" /run/mg-adopt/instance.json | grep -E 'activated|valid keys|OK'
    rm -rf "$T"
  done
  for r in platform:$MG_IDP_ID_PLATFORM tenant-a:$MG_IDP_ID_TENANT_A tenant-b:$MG_IDP_ID_TENANT_B; do
    bash infrastructure/host/idp-client-secret.sh "${r%%:*}" | $CORE2 run --rm --no-deps -T api admin set-idp-client-secret "${r#*:}" | tail -1
  done
}

st_people() {
  loadenv
  local CORE2="$APP"
  say "tài khoản thử (create-user.sh; mật khẩu sinh tại chỗ, chỉ trong $X/creds 0600) + SA ×2 + TO/TA A/B"
  install -d -m 0700 "$X/creds"
  for u in platform:dep4-sa1 platform:dep4-sa2 tenant-a:dep4-a-owner tenant-a:dep4-a-admin tenant-b:dep4-b-owner tenant-b:dep4-b-admin; do
    local realm=${u%%:*} user=${u#*:} f="$X/creds/${u%%:*}-${u#*:}.pw"
    [ -s "$f" ] || (umask 077; set +o pipefail; tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 > "$f")
    bash infrastructure/idp/create-user.sh "$realm" "$user" "$user@example.invalid" Dep4 "$user" < "$f" | cut -c1-60
  done
  SA1=$(uid platform dep4-sa1); SA2=$(uid platform dep4-sa2)
  $CORE2 run --rm --no-deps -T -e "MG_IDP_ID_PLATFORM=$MG_IDP_ID_PLATFORM" api admin bootstrap-super-admin --subject "$SA1" --display-name "Dep4 SA1" | grep -E 'active Super|OK'
  $CORE2 run --rm --no-deps -T -e "MG_IDP_ID_PLATFORM=$MG_IDP_ID_PLATFORM" api admin bootstrap-super-admin --subject "$SA2" --display-name "Dep4 SA2" | grep -E 'active Super|OK'
  for t in a b; do
    $CORE2 run --rm --no-deps -T api admin seed-membership --tenant "tenant-$t" --role tenant_owner --subject "$(uid tenant-$t dep4-$t-owner)" | tail -1
    $CORE2 run --rm --no-deps -T api admin seed-membership --tenant "tenant-$t" --role tenant_admin --subject "$(uid tenant-$t dep4-$t-admin)" | tail -1
  done
  say "mg-backup theo lịch + bộ manual (deploy-backend g)"
  $BK up -d; sleep 20
  $BK run --rm -T pg-backup once --label manual | tail -1
}

st_idpboot() {
  loadenv
  say "idp-bootstrap (mg-provisioner) qua worker đang chạy (deploy-backend h4) + realm-update.sh (master: gia cố, frontendUrl)"
  local U; U=$(sed -n 's/^bootstrap-admin-username=//p' /opt/meshguard/secrets/idp/keycloak.conf)
  sed -n 's/^bootstrap-admin-password=//p' /opt/meshguard/secrets/idp/keycloak.conf \
    | $APP exec -T worker /usr/local/bin/meshguard admin idp-bootstrap --admin-username "$U" --adopt-realm tenant-a --adopt-realm tenant-b | tail -2
}

st_realm() {
  loadenv
  say "realm-update.sh --check / áp / --check (gia cố master, frontendUrl, view-events)"
  local rc=0
  bash infrastructure/idp/realm-update.sh --check > "$X/realm-check-p3-before.log" 2>&1 || rc=$?; echo "realm-update --check exit $rc"; rc=0
  bash infrastructure/idp/realm-update.sh > "$X/realm-update-p3.log" 2>&1 || rc=$?; echo "realm-update exit $rc"; rc=0
  bash infrastructure/idp/realm-update.sh --check > "$X/realm-check-p3-after.log" 2>&1 || rc=$?; echo "realm-update --check exit $rc (mong đợi 0)"
  grep -E 'thay đổi|OK' "$X/realm-update-p3.log" | tail -8
  $APP restart worker >/dev/null; sleep 8
  $APP logs --since 1m worker 2>&1 | grep -o '"keycloak_provisioner_bootstrapped":[a-z]*' | tail -1
}

st_agent() {
  loadenv
  say "Host Agent (render_agent, agent:old) + host-set public entry (P3-T02 §7, P3-T04)"
  python3 tools/render_agent.py "$ENVF" /tmp/agent --agent-image "$(img agent:old)" >/dev/null
  install -m 0644 /tmp/agent/compose.agent.yaml /opt/meshguard/core/compose.agent.yaml
  install -d -m 0755 /opt/meshguard/core/agent
  install -m 0644 /tmp/agent/agent/allowlist /opt/meshguard/core/agent/allowlist
  $AGENT up -d
  wait_healthy mg-agent 120
  stat -c '%a %u:%g %n' /opt/meshguard/run/agent.sock
  $APP run --rm --no-deps -T -e "MG_PUBLIC_IPV4=$MG_PUBLIC_IPV4" api admin host-set --name mg-staging \
    --public-ipv4-env MG_PUBLIC_IPV4 --mode vps_gateway | grep -E 'placement|OK'
}

st_obs() {
  loadenv
  say "mg-obs (render_monitoring probe:old, node-exporter:old) + obs-targets một lượt (không systemd)"
  bash infrastructure/host/obs-secrets.sh check | tail -2
  python3 tools/render_monitoring.py "$ENVF" /tmp/mg-obs --probe-image "$(img probe:old)" --node-exporter-image "$(img node-exporter:old)" >/dev/null
  local M=/opt/meshguard/core/monitoring
  install -m 0644 /tmp/mg-obs/compose.monitoring.yaml /opt/meshguard/core/compose.monitoring.yaml
  install -m 0644 /tmp/mg-obs/monitoring/prometheus/prometheus.yml $M/prometheus/
  install -m 0644 /tmp/mg-obs/monitoring/prometheus/rules/meshguard.rules.yml $M/prometheus/rules/
  install -m 0644 /tmp/mg-obs/monitoring/alertmanager/alertmanager.yml $M/alertmanager/
  bash infrastructure/host/obs-targets.sh
  $OBS up -d --wait --wait-timeout 240
  $OBS ps --format '{{.Service}} {{.Status}}'
}

st_backfill() {
  loadenv
  say "P3-T14b backfill A/B + policy-apply fixture (current.md đợt 11)"
  for S in tenant-a tenant-b; do
    $APP exec -T worker /usr/local/bin/meshguard admin backfill-instance --tenant "$S" --node-expiry-days 90 \
      --derp-region-id 901 --log-level info --memory-mib 512 --cpu-millis 1000 --pids 256 2>&1 | tail -3
    $APP exec -T worker /usr/local/bin/meshguard admin policy-apply --tenant "$S" --file - \
      <"infrastructure/headscale/templates/test-allow-intra.hujson" 2>&1 | tail -2 || true
  done
}

[[ "${BASH_SOURCE[0]}" == "$0" ]] && for s in "$@"; do "st_$s"; done
true
