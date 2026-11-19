#!/bin/bash
# dep4 — phía NGOÀI host lồng (trên VM 110): "VPS" (HAProxy render bằng render_gateway.py, PROXY v2 qua tunnel giả) và
# client Tailscale chính thức ([images.tailscale]): a1/b1 qua "VPS" (dep4-inet), a2/b2 LAN-direct (dep4-lan) — như
# lab client của staging. Pre-auth key dùng một lần, hạn 1 giờ, đi thẳng qua ống từ CLI Headscale vào file 0400 trên
# tmpfs của container client (không in, không nằm trong env/argv).
#   bash outer.sh vps | clients | status | down
set -euo pipefail
O="sudo -n docker"
N="sudo -n docker exec -i dep4-host"
W=$HOME/dep4
TS=docker.io/tailscale/tailscale@sha256:72c1e19e0aedca96b8533bbb0b4368564410ff20b17e53b804eb6c1f04a31be4
HAP=docker.io/library/haproxy@sha256:b9fe316f718d5015c5cfebd8ca019591f3e44656f61d93cb8b59a1028961e530
DOM=dep4.test

vps() {
  $O image inspect "$HAP" >/dev/null 2>&1 || $O pull -q "$HAP" >/dev/null
  $N bash -c 'cd /root/src/new && rm -rf /tmp/gw && python3 tools/render_gateway.py /root/mg/infrastructure/environments/dep4/gateway.json /tmp/gw >/dev/null && cat /tmp/gw/haproxy.cfg' > "$W/haproxy.cfg"
  grep -m1 template_version "$W/haproxy.cfg" || true
  $O rm -f dep4-vps >/dev/null 2>&1 || true
  $O create --name dep4-vps --label dep4=1 --network dep4-inet --ip 192.88.99.10 --read-only --tmpfs /tmp \
    -v "$W/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" --cap-drop ALL --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges:true --user 0:0 \
    "$HAP" >/dev/null
  $O network connect --ip 10.77.5.3 dep4-tun dep4-vps
  $O start dep4-vps >/dev/null; sleep 2
  # stund của VPS (UDP 3478) trong cùng netns với l4proxy — như compose.gateway.yaml (network_mode host trên VPS)
  local STUND=ghcr.io/zhaduchanhzz/network-access-mesh/stund@sha256:30a359fddac7027dc9abd794c0405ebfff72c2ce79043e331353c5060483fce0
  $O rm -f dep4-stund >/dev/null 2>&1 || true
  $O run -d --name dep4-stund --label dep4=1 --network container:dep4-vps --read-only --cap-drop ALL     --security-opt no-new-privileges:true "$STUND" >/dev/null
  $O logs --tail 5 dep4-vps 2>&1
}

client() {  # <name> <slug> <network> <ip của tenant-x.mesh>
  local n=$1 s=$2 net=$3 entry=$4 uid key
  $O rm -f "dep4-$n" >/dev/null 2>&1 || true
  $N docker exec "mg-hs-$s" headscale users create "lab-$n" >/dev/null 2>&1 || true
  uid=$($N docker exec "mg-hs-$s" headscale users list -o json | python3 -c 'import json,sys
print(next(u["id"] for u in json.load(sys.stdin) if u["name"] == sys.argv[1]))' "lab-$n")
  $O run -d --name "dep4-$n" --label dep4=1 --network "$net" --add-host "$s.mesh.$DOM:$entry" \
    --tmpfs /tmp --tmpfs /var/lib/tailscale --tmpfs /run/k:mode=0700 \
    -e TS_USERSPACE=true -e TS_STATE_DIR=/var/lib/tailscale -e TS_SOCKET=/tmp/ts.sock -e TS_NO_LOGS_NO_SUPPORT=true \
    -e SSL_CERT_FILE=/ca/ca.crt -v "$W/ca.crt:/ca/ca.crt:ro" --entrypoint tailscaled "$TS" \
    --tun=userspace-networking --statedir=/var/lib/tailscale --socket=/tmp/ts.sock --no-logs-no-support >/dev/null
  # client "LAN" cũng ra được "Internet" (như a2/b2 sau NAT của OPNsense): DERP/STUN tới IP công khai giả
  [ "$net" = dep4-lan ] && $O network connect dep4-inet "dep4-$n"
  # key: CLI Headscale → ống → file trên tmpfs của client (không in)
  $N docker exec "mg-hs-$s" headscale preauthkeys create -u "$uid" -e 1h -o json \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["key"])' \
    | $O exec -i "dep4-$n" sh -c 'umask 077; cat > /run/k/authkey'
  $O exec "dep4-$n" tailscale --socket=/tmp/ts.sock up --login-server="https://$s.mesh.$DOM" \
    --auth-key=file:/run/k/authkey --hostname="lab-$n" --accept-dns=false --timeout=60s >/dev/null
  $O exec "dep4-$n" sh -c 'rm -f /run/k/authkey'
  echo "$n $($O exec "dep4-$n" tailscale --socket=/tmp/ts.sock status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["BackendState"], d["Self"]["TailscaleIPs"][0])')"
}

clients() {
  $N cat /root/dep4x/ca/ca.crt > "$W/ca.crt"
  client a1 tenant-a dep4-inet 192.88.99.10
  client a2 tenant-a dep4-lan 10.77.4.10
  client b1 tenant-b dep4-inet 192.88.99.10
  client b2 tenant-b dep4-lan 10.77.4.10
}

status() {
  for n in a1 a2 b1 b2; do
    printf '%s ' "$n"; $O exec "dep4-$n" tailscale --socket=/tmp/ts.sock status --json 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin); peers=[p for p in (d.get("Peer") or {}).values()]
print(d["BackendState"], "peers", len(peers), "online", sum(1 for p in peers if p.get("Online")))' || echo "?"
  done
}

down() { $O rm -f dep4-stund dep4-vps dep4-a1 dep4-a2 dep4-b1 dep4-b2 >/dev/null 2>&1 || true; }

"$@"
