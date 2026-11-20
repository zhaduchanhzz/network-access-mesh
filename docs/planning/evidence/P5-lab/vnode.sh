#!/bin/sh
# P5-T03/T04/T06/T07 — node Tailscale TẠM thứ hai trên một VM lab cho tenant thử, KHÔNG đụng tailscaled của hệ thống:
# tailscaled chính thức (cùng binary 1.104.7) chạy userspace (`--tun=userspace-networking`) dưới user hiện tại (không
# root), state + socket trong /dev/shm/p5v-$USER/<tên>/ (0700, tmpfs — mất khi reboot, xóa ở `rm`), cổng UDP ngẫu nhiên
# (`--port=0`), SOCKS5 trên 127.0.0.1 cho lưu lượng đi; lưu lượng tới IP tailnet của node được chuyển tới 127.0.0.1:<cổng>
# của VM (listener tạm của collect.sh). Biến môi trường riêng của node (vd. TS_DEBUG_ALWAYS_USE_DERP=true,
# TS_NO_LOGS_NO_SUPPORT=true) chỉ áp cho tiến trình này.
#
#   sh vnode.sh start <tên> <cổng socks> [KEY=VAL…]   chạy tailscaled (giữ state cũ nếu có)
#   sh vnode.sh up <tên> <login url> <hostname>        key từ stdin ⇒ file 0600 ⇒ --auth-key=file: (xóa ngay sau)
#   sh vnode.sh login <tên> <login url> <hostname>     web-auth nền; link ở <dir>/up.log
#   sh vnode.sh ts <tên> <tham số tailscale…>          tailscale --socket=<dir>/sock …
#   sh vnode.sh stop <tên>                             dừng tailscaled (giữ state — "peer offline")
#   sh vnode.sh rm <tên>                               dừng + xóa thư mục (state, khóa)
#   sh vnode.sh list                                   các node tạm đang có
set -u
ROOT="/dev/shm/p5v-$(id -un)"
mkdir -p "$ROOT" && chmod 0700 "$ROOT"
cmd=${1:-}; shift || true
name=${1:-}
case "$name" in ""|*[!a-z0-9-]*) [ "$cmd" = list ] || { echo "tên: [a-z0-9-]" >&2; exit 2; } ;; esac
D="$ROOT/$name"
pid() { [ -f "$D/pid" ] && kill -0 "$(cat "$D/pid")" 2>/dev/null && cat "$D/pid"; }
# tailscaled userspace đôi khi không thoát với SIGTERM (thấy ở node ép relay, 2026-11-20) ⇒ chờ 5 s rồi SIGKILL
halt() { p=$(pid); [ -n "$p" ] || return 0; kill "$p"; i=0; while kill -0 "$p" 2>/dev/null && [ $i -lt 25 ]; do sleep 0.2; i=$((i+1)); done; kill -9 "$p" 2>/dev/null; true; }
TS() { tailscale --socket="$D/sock" "$@"; }
case "$cmd" in
start)
  sport=${2:?cổng socks}; shift 2
  mkdir -p "$D" && chmod 0700 "$D"
  if [ -n "$(pid)" ]; then echo "đang chạy pid $(pid)"; exit 0; fi
  printf '%s\n' "$@" >"$D/env"
  # shellcheck disable=SC2046
  setsid nohup env "$@" tailscaled --tun=userspace-networking --state="$D/state" --statedir="$D" --socket="$D/sock" \
    --port=0 --socks5-server="127.0.0.1:$sport" </dev/null >"$D/tailscaled.log" 2>&1 &
  echo $! >"$D/pid"
  i=0; while [ ! -S "$D/sock" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
  echo "started $name pid $(cat "$D/pid") socks 127.0.0.1:$sport env [$(tr '\n' ' ' <"$D/env")]"
  ;;
up)
  login=${2:?login}; host=${3:?hostname}
  umask 077; cat >"$D/authkey"
  timeout 90 tailscale --socket="$D/sock" up --login-server="$login" --auth-key="file:$D/authkey" --hostname="$host" \
    --accept-dns=false --timeout=75s 2>&1; rc=$?
  rm -f "$D/authkey"; exit $rc
  ;;
login)
  login=${2:?login}; host=${3:?hostname}
  rm -f "$D/up.log"
  setsid nohup tailscale --socket="$D/sock" login --login-server="$login" --hostname="$host" --accept-dns=false \
    --timeout=600s </dev/null >"$D/up.log" 2>&1 &
  echo "login started"
  ;;
ts)
  shift; TS "$@"
  ;;
stop)
  halt; rm -f "$D/pid"; echo "stopped $name"
  ;;
rm)
  halt
  rm -rf "$D"; echo "removed $name"
  ;;
list)
  for d in "$ROOT"/*/; do [ -d "$d" ] || continue; n=$(basename "$d"); p=""; [ -f "$d/pid" ] && kill -0 "$(cat "$d/pid")" 2>/dev/null && p=$(cat "$d/pid"); echo "$n pid=${p:-none}"; done
  ;;
*) sed -n '2,17p' "$0"; exit 2 ;;
esac
