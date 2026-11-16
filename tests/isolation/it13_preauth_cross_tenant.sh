#!/bin/bash
# IT-13 / AC-14 (phần pre-auth key): credential do tenant A phát hành không đăng ký được vào tenant B và ngược lại.
# Chạy trên một VM client của lab (cần quyền root). Dùng một tailscaled TẠM thứ hai (userspace networking, state chỉ
# trong RAM, socket và cổng riêng) nên client chính trên máy không bị ảnh hưởng.
#   printf '%s\n%s\n' "<key do A phát hành>" "<key do B phát hành>" | sudo bash it13_preauth_cross_tenant.sh <url A> <url B>
# Key đọc từ stdin, chỉ chuyển cho tailscale qua file tmpfs 0600 (--auth-key=file:), không in ra.
# Thứ tự: key A → B, key B → A (phải bị từ chối, và vì bị từ chối nên key không bị tiêu), rồi key A → A, key B → B
# (đối chứng: phải đăng ký được — chứng minh key hợp lệ). Node đối chứng phải được xóa ở phía Headscale sau đó.
set -euo pipefail
URL_A=${1:?usage: it13_preauth_cross_tenant.sh <login url A> <login url B>}; URL_B=${2:?}
read -r KEY_A; read -r KEY_B
D=$(mktemp -d /dev/shm/it13.XXXXXX); chmod 0700 "$D"
printf '%s' "$KEY_A" > "$D/a"; printf '%s' "$KEY_B" > "$D/b"; chmod 0600 "$D/a" "$D/b"; unset KEY_A KEY_B
SOCK="$D/tailscaled.sock"
start() { tailscaled --tun=userspace-networking --state=mem: --socket="$SOCK" --port=0 --statedir="$D/state" >"$D/log" 2>&1 & PID=$!
          for _ in $(seq 1 30); do tailscale --socket="$SOCK" status >/dev/null 2>&1 && return 0; [ -S "$SOCK" ] && sleep 0.5 && return 0; sleep 0.3; done; }
stop() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -rf "$D/state"; }
trap 'stop; rm -rf "$D"' EXIT
fail=0
try() {   # <key file> <url> <expect: reject|accept> <label>
  start
  out=$(timeout 45 tailscale --socket="$SOCK" up --login-server="$2" --auth-key="file:$1" --hostname="it13-$4" \
        --accept-dns=false --timeout=30s 2>&1) && rc=0 || rc=$?
  state=$(tailscale --socket="$SOCK" status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("BackendState"))' 2>/dev/null || echo "?")
  msg=$(printf '%s' "$out" | tr '\n' ' ' | sed -E 's/hskey-auth-[A-Za-z0-9_-]+/<redacted>/g' | cut -c1-160)
  if [ "$3" = reject ]; then
    if [ "$rc" != 0 ] && [ "$state" != Running ]; then echo "PASS $4: rejected (exit $rc, state $state) — $msg"; else echo "FAIL $4: accepted (state $state)"; fail=1; fi
  else
    if [ "$rc" = 0 ] && [ "$state" = Running ]; then echo "PASS $4: accepted (control) as it13-$4"; tailscale --socket="$SOCK" logout >/dev/null 2>&1 || true
    else echo "FAIL $4: control enrollment failed (exit $rc, state $state) — $msg"; fail=1; fi
  fi
  stop
}
try "$D/a" "$URL_B" reject key-A-on-B
try "$D/b" "$URL_A" reject key-B-on-A
try "$D/a" "$URL_A" accept key-A-on-A
try "$D/b" "$URL_B" accept key-B-on-B
exit $fail
