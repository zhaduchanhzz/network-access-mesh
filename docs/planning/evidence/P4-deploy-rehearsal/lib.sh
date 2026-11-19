# dep4 — biến/hàm chung của diễn tập (source từ p3.sh, up.sh, rb.sh), chạy BÊN TRONG host lồng (root).
set -euo pipefail
export LC_ALL=C.UTF-8
X=/root/dep4x                       # script, log, credential thử (0600) — xóa khi dọn
MG=/root/mg                         # "~/mg" của staging: bản đồng bộ repo của commit đang triển khai
ENVD=infrastructure/environments/dep4
ENVF=$ENVD/dep4.env
# DIỄN TẬP: api/worker/prober tin CA thử qua file override (staging dùng chứng chỉ ACME công khai — không có override)
APP="docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml -f /opt/meshguard/core/compose.app.dep4ca.yaml"
BK="docker compose -p mg-backup -f /opt/meshguard/core/compose.backup.yaml"
IDP="docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml"
OBS="docker compose -p mg-obs -f /opt/meshguard/core/compose.monitoring.yaml -f /opt/meshguard/core/compose.monitoring.dep4ca.yaml"
AGENT="docker compose -f /opt/meshguard/core/compose.agent.yaml"
EDGE="docker compose -p mg-edge -f /opt/meshguard/core/compose.edge.yaml -f /opt/meshguard/core/compose.edge.dep4tls.yaml"
CORE="docker compose -p mg-core -f /opt/meshguard/core/compose.core.yaml"
img() { docker image inspect -f '{{.Id}}' "dep4/$1"; }       # img api:old → sha256:… (ID image cục bộ)
ts() { date -u +%Y%m%dT%H%M%SZ; }
say() { printf '\n=== [%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
loadenv() {   # biến của tiến trình ghi đè env file (mgenv) ⇒ xóa MG_* cũ trước khi nạp lại (file có thể vừa đổi)
  local v; for v in $(compgen -e | grep '^MG_' || true); do unset "$v"; done
  cd "$MG" && eval "$(python3 tools/mgenv.py export "$ENVF")"
}
pg() { docker exec -i mg-core-postgres-1 psql -X -q -v ON_ERROR_STOP=1 -U postgres -d meshguard -tA "$@"; }
wait_healthy() {  # <container> [timeout]
  local c=$1 t=${2:-240} s
  for _ in $(seq 1 "$t"); do
    s=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$c" 2>/dev/null || echo missing)
    [ "$s" = healthy ] && return 0
    sleep 1
  done
  echo "TIMEOUT $c: $s"; return 1
}
