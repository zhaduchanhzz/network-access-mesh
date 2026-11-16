#!/bin/bash
# IT-09 (P1-T12b): ma trận derpprobe chạy trên một VM client của lab (root). Tạo HAI node tạm (một trong tenant A,
# một trong tenant B) bằng tailscaled userspace với state trên tmpfs, dừng chúng, đọc khóa node riêng từ state
# (file 0600 trên tmpfs, không in ra), rồi thử /derp của từng tenant qua edge:
#   random → A, random → B, khóa B → A, khóa A → B  ⇒ phải bị từ chối
#   khóa A → A, khóa B → B                          ⇒ phải được nhận (đối chứng)
#   printf '%s\n%s\n' "<pre-auth key A>" "<pre-auth key B>" | sudo bash run_lab.sh <derpprobe> <url A> <url B>
# Sau đó phải xóa hai node tạm (dp-tmp-a, dp-tmp-b) ở phía Headscale.
set -euo pipefail
PROBE=${1:?usage: run_lab.sh <derpprobe binary> <login url A> <login url B>}; URL_A=${2:?}; URL_B=${3:?}
read -r KEY_A; read -r KEY_B
D=$(mktemp -d /dev/shm/dp.XXXXXX); chmod 0700 "$D"; trap 'pkill -f "tailscaled .*--socket=$D/" 2>/dev/null || true; rm -rf "$D"' EXIT
mknode() {  # <tag> <login url> <pre-auth key>
  local d="$D/$1"; mkdir -m 0700 "$d"; printf '%s' "$3" > "$d/authkey"; chmod 0600 "$d/authkey"
  tailscaled --tun=userspace-networking --state="$d/tailscaled.state" --socket="$d/sock" --port=0 --statedir="$d" >"$d/log" 2>&1 &
  for _ in $(seq 1 30); do [ -S "$d/sock" ] && break; sleep 0.3; done
  timeout 45 tailscale --socket="$d/sock" up --login-server="$2" --auth-key="file:$d/authkey" --hostname="dp-tmp-$1" \
    --accept-dns=false --timeout=30s >/dev/null 2>&1
  rm -f "$d/authkey"
  echo "node dp-tmp-$1 registered: $(tailscale --socket="$d/sock" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["BackendState"])')"
  pkill -f "tailscaled .*--socket=$d/sock"; sleep 1
  python3 - "$d/tailscaled.state" "$d/nodekey" <<'PY'
import base64, json, os, sys
state = json.load(open(sys.argv[1]))
cur = base64.b64decode(state["_current-profile"]).decode()
prof = json.loads(base64.b64decode(state[cur]))
priv = prof["Config"]["PrivateNodeKey"]
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, priv.encode()); os.close(fd)
PY
}
mknode a "$URL_A" "$KEY_A"; mknode b "$URL_B" "$KEY_B"; unset KEY_A KEY_B
fail=0
probe() {  # <label> <expect accepted|rejected> <derpprobe args...>
  local label=$1 want=$2; shift 2
  out=$("$PROBE" "$@" 2>&1) && got=accepted || got=rejected
  [ "$got" = "$want" ] && echo "PASS $label: $out" || { echo "FAIL $label (want $want): $out"; fail=1; }
}
probe "random key → A" rejected -url "$URL_A/derp" -random
probe "random key → B" rejected -url "$URL_B/derp" -random
probe "node key of B → A" rejected -url "$URL_A/derp" -key-file "$D/b/nodekey"
probe "node key of A → B" rejected -url "$URL_B/derp" -key-file "$D/a/nodekey"
probe "node key of A → A (control)" accepted -url "$URL_A/derp" -key-file "$D/a/nodekey"
probe "node key of B → B (control)" accepted -url "$URL_B/derp" -key-file "$D/b/nodekey"
exit $fail
