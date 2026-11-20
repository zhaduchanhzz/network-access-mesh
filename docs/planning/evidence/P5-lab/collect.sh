#!/bin/sh
# P5-T02 — thu bằng chứng trên MỘT client lab (Linux, Tailscale chính thức); dùng lại cho P5-T04…T07.
#
#   sh collect.sh <lệnh> <nhãn> [tham số…]          (mgdeploy, sudo -n không mật khẩu; output: ~/p5lab/out/<nhãn>/)
#
#   snapshot <nhãn>                    hệ điều hành, phiên bản client, cờ tailscaled (/etc/default/tailscaled + môi trường
#                                      thật của tiến trình: TS_DEBUG_ALWAYS_USE_DERP), prefs, `status --json`, `netcheck`
#                                      (JSON), `debug derp-map`, `debug derp <region của map>`, cách phân giải control
#                                      host, route mặc định, `exit-node list`, `metrics print` (bộ đếm theo path)
#   ping <nhãn> <peer> [n]             `tailscale ping --until-direct=false -c n` (via DERP(<region>) hay direct ip:port)
#   tcp <nhãn> <ip> <port> [giây]      TCP thật (python3 socket): kết nối + đọc banner, thời gian ms; không dùng
#                                      `tailscale ping` cho policy (CL-09)
#   bulk <nhãn> <ip> <port> [MiB]      gửi N MiB qua TCP tới listener `sink` (sha256 + thời gian ⇒ thông lượng)
#   listen <port> [banner]             listener tạm (python3, nền, pidfile ~/p5lab/listen-<port>.pid): trả banner rồi đóng
#   sink <port>                        listener tạm nhận dữ liệu, trả "<bytes> <sha256>"
#   unlisten <port>                    dừng listener tạm của cổng đó
#   dnsq <nhãn> <tên> [type]           `tailscale dns query` (resolver nội bộ của client — không đổi DNS hệ thống)
#   relay <on|direct|off|status>       ép relay: `on` thêm TS_DEBUG_ALWAYS_USE_DERP=true vào /etc/default/tailscaled,
#                                      `direct` bỏ dòng đó (bản sao /etc/default/tailscaled.p5lab-orig ở lần đổi đầu) +
#                                      restart tailscaled; `off` trả lại bản sao. Hoàn tác bắt buộc sau phép thử
#   pack <nhãn>                        tar.gz của ~/p5lab/out/<nhãn> ra stdout (máy vận hành che IP công khai/domain)
#
# Mỗi lệnh ghi một dòng vào <nhãn>/index.tsv: thời điểm UTC, lệnh, mã thoát, thời gian ms. Không in secret: output có
# thể chứa domain, IP công khai của LAN/VPS ⇒ chỉ đưa ra khỏi máy qua `pack` rồi che ở máy vận hành (p5lab.py).
set -u
BASE="$HOME/p5lab"
OUTROOT="$BASE/out"
mkdir -p "$OUTROOT"
chmod 0700 "$BASE"

now_ms() { date +%s%3N; }
utc() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }

# run <dir> <file> <cmd…>: chạy, lưu stdout+stderr vào file, ghi index
run() {
  d=$1; f=$2; shift 2
  t0=$(now_ms)
  "$@" >"$d/$f" 2>&1
  rc=$?
  t1=$(now_ms)
  printf '%s\t%s\t%s\t%s\n' "$(utc)" "$f" "$rc" "$((t1 - t0))" >>"$d/index.tsv"
  return $rc
}

outdir() {
  [ -n "${1:-}" ] || { echo "thiếu nhãn" >&2; exit 2; }
  case "$1" in *[!A-Za-z0-9._-]*) echo "nhãn chỉ gồm [A-Za-z0-9._-]" >&2; exit 2;; esac
  mkdir -p "$OUTROOT/$1"
  echo "$OUTROOT/$1"
}

ts_env() {   # môi trường thật của tailscaled của systemd (không lẫn tailscaled trong container) — chỉ biến TS_*
  pid=$(systemctl show -p MainPID --value tailscaled 2>/dev/null)
  [ -n "$pid" ] && [ "$pid" != 0 ] && sudo -n cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep '^TS_' || true
}

ctl_host() {  # host control của profile hiện tại (từ prefs)
  sudo -n tailscale debug prefs 2>/dev/null | python3 -c 'import json,sys,urllib.parse; print(urllib.parse.urlsplit(json.load(sys.stdin).get("ControlURL","")).hostname or "")'
}

region_code() {
  tailscale debug derp-map 2>/dev/null | python3 -c 'import json,sys; m=json.load(sys.stdin).get("Regions") or {}; print(" ".join(r.get("RegionCode","") for r in m.values()))'
}

cmd=${1:-}; shift || true
case "$cmd" in
snapshot)
  d=$(outdir "${1:-}")
  { . /etc/os-release; echo "os=$PRETTY_NAME"; echo "kernel=$(uname -r)"; echo "hostname=$(hostname)"; } >"$d/os.txt"
  run "$d" version.txt tailscale version
  { echo "# /etc/default/tailscaled"; grep -v '^#' /etc/default/tailscaled 2>/dev/null | grep -v '^$';
    echo "# môi trường tiến trình tailscaled (TS_*)"; ts_env; } >"$d/tailscaled-flags.txt"
  run "$d" prefs.json sudo -n tailscale debug prefs
  run "$d" status.json tailscale status --json
  run "$d" status.txt tailscale status
  run "$d" netcheck.json tailscale netcheck --format=json
  run "$d" netcheck.txt tailscale netcheck
  run "$d" derp-map.json tailscale debug derp-map
  for rc_ in $(region_code); do run "$d" "debug-derp-$rc_.json" sudo -n tailscale debug derp "$rc_"; done
  h=$(ctl_host)
  { echo "control_host=$h"; echo "getent=$(getent ahostsv4 "$h" 2>/dev/null | awk 'NR==1{print $1}')";
    echo "etc_hosts=$(grep -c " $h" /etc/hosts 2>/dev/null)"; echo "default_route=$(ip -4 route show default | head -1)";
    echo "addr=$(ip -4 -br addr show scope global | grep -v -e tailscale -e docker -e br- | head -3 | tr '\n' ';')"; } >"$d/net.txt"
  run "$d" exit-nodes.txt tailscale exit-node list
  run "$d" metrics.txt tailscale metrics print
  echo "$d"
  ;;
ping)
  d=$(outdir "${1:-}"); peer=${2:?peer}; n=${3:-5}
  f="ping-$peer-$(date -u +%H%M%S).txt"
  run "$d" "$f" tailscale ping --until-direct=false -c "$n" --timeout=5s "$peer"
  cat "$d/$f"
  ;;
tcp)
  d=$(outdir "${1:-}"); ip=${2:?ip}; port=${3:?port}; w=${4:-5}
  f="tcp-$ip-$port-$(date -u +%H%M%S).txt"
  run "$d" "$f" python3 - "$ip" "$port" "$w" <<'PY'
import socket, sys, time
ip, port, w = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
t0 = time.time()
try:
    s = socket.create_connection((ip, port), timeout=w)
    t1 = time.time()
    s.settimeout(w)
    data = s.recv(200).decode("utf-8", "replace").strip()
    print(f"OPEN connect_ms={1000 * (t1 - t0):.1f} total_ms={1000 * (time.time() - t0):.1f} banner={data!r}")
except Exception as e:  # noqa: BLE001
    print(f"FAIL {type(e).__name__} after_ms={1000 * (time.time() - t0):.1f}")
    sys.exit(1)
PY
  rc=$?; cat "$d/$f"; exit $rc
  ;;
bulk)
  d=$(outdir "${1:-}"); ip=${2:?ip}; port=${3:?port}; mib=${4:-20}
  run "$d" "bulk-$ip-$port.txt" python3 - "$ip" "$port" "$mib" <<'PY'
import hashlib, os, socket, sys, time
ip, port, mib = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
buf = os.urandom(1 << 20)
h = hashlib.sha256()
t0 = time.time()
s = socket.create_connection((ip, port), timeout=20)
for _ in range(mib):
    s.sendall(buf); h.update(buf)
s.shutdown(socket.SHUT_WR)
s.settimeout(60)
ans = s.recv(200).decode().strip()
dt = time.time() - t0
ok = ans.split()[-1] == h.hexdigest() if ans else False
print(f"{'OK' if ok else 'MISMATCH'} sent={mib}MiB secs={dt:.2f} MBps={mib * 1.048576 / dt:.1f} sha256={h.hexdigest()[:16]} peer={ans[:40]}")
sys.exit(0 if ok else 1)
PY
  rc=$?; cat "$d/bulk-$ip-$port.txt"; exit $rc
  ;;
listen|sink)
  port=${1:?port}; banner=${2:-"p5lab $(hostname) tcp/$port"}
  pidf="$BASE/listen-$port.pid"
  [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null
  cat >"$BASE/listen-$port.py" <<'PY'
import hashlib, socket, sys, threading
mode, port, banner = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port)); srv.listen(16)
def serve(c):
    try:
        if mode == "listen":
            c.sendall(banner + b"\n")
        else:
            h, n = hashlib.sha256(), 0
            c.settimeout(60)
            while True:
                b = c.recv(1 << 16)
                if not b:
                    break
                h.update(b); n += len(b)
            c.sendall(f"{n} {h.hexdigest()}\n".encode())
    finally:
        c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
  setsid nohup python3 "$BASE/listen-$port.py" "$cmd" "$port" "$banner" </dev/null >/dev/null 2>&1 &
  echo $! >"$pidf"
  sleep 0.5
  kill -0 "$(cat "$pidf")" 2>/dev/null && echo "listening $port pid $(cat "$pidf")" || { echo "listener $port không chạy"; exit 1; }
  ;;
unlisten)
  port=${1:?port}; pidf="$BASE/listen-$port.pid"
  if [ -f "$pidf" ]; then kill "$(cat "$pidf")" 2>/dev/null; rm -f "$pidf" "$BASE/listen-$port.py"; echo "stopped $port"; else echo "no listener $port"; fi
  ;;
dnsq)
  d=$(outdir "${1:-}"); name=${2:?name}; typ=${3:-A}
  f="dnsq-$name-$typ-$(date -u +%H%M%S).txt"
  run "$d" "$f" sudo -n tailscale dns query "$name" "$typ"
  cat "$d/$f"
  ;;
relay)
  f=/etc/default/tailscaled
  case "${1:-status}" in
  on)
    [ -f "$f.p5lab-orig" ] || sudo -n cp -p "$f" "$f.p5lab-orig"
    grep -q '^TS_DEBUG_ALWAYS_USE_DERP=true' "$f" || echo 'TS_DEBUG_ALWAYS_USE_DERP=true' | sudo -n tee -a "$f" >/dev/null
    sudo -n systemctl restart tailscaled ;;
  direct)
    [ -f "$f.p5lab-orig" ] || sudo -n cp -p "$f" "$f.p5lab-orig"
    sudo -n sed -i '/^TS_DEBUG_ALWAYS_USE_DERP=/d' "$f"
    sudo -n systemctl restart tailscaled ;;
  off)
    if [ -f "$f.p5lab-orig" ]; then sudo -n cp -p "$f.p5lab-orig" "$f" && sudo -n rm -f "$f.p5lab-orig" && sudo -n systemctl restart tailscaled
    else echo "không có bản sao $f.p5lab-orig (trạng thái gốc chưa bị đổi bởi script này)"; fi ;;
  status) ;;
  *) echo "relay on|off|status" >&2; exit 2 ;;
  esac
  i=0; while [ $i -lt 30 ]; do tailscale status --json 2>/dev/null | grep -q '"BackendState": "Running"' && break; sleep 1; i=$((i+1)); done
  echo "file: $(grep -c '^TS_DEBUG_ALWAYS_USE_DERP=true' "$f") process: $(ts_env | tr '\n' ' ')"
  ;;
pack)
  d=$(outdir "${1:-}")
  tar -czf - -C "$OUTROOT" "$(basename "$d")"
  ;;
*)
  sed -n '2,26p' "$0"; exit 2 ;;
esac
