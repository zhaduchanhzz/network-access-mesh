#!/bin/bash
# P3-T16 — danh sách instance tenant cho Prometheus (file_sd của job headscale và probe-key-*, project mg-obs): mỗi
# container mg-hs-<slug> mang nhãn meshguard.tenant_id/meshguard.instance_id (do Host Agent đặt — §14.5) thành một đích
# {slug, tenant_id, instance_id}. HTTP SD của api (/internal/prometheus/sd) thuộc P6-T01; tới lúc đó file này là nguồn.
# Container dừng VẪN là đích (instance dừng ngoài ý muốn ⇒ TenantInstanceDown); container bị gỡ (deprovision) thì rời
# danh sách ở lượt kế tiếp. Ghi nguyên tử (Prometheus tự nạp lại file_sd khi file đổi). Không đọc secret, không in IP.
#
# Dùng (root):
#   sudo bash infrastructure/host/obs-targets.sh            một lượt → /opt/meshguard/core/monitoring/prometheus/targets/instances.json
#   sudo bash infrastructure/host/obs-targets.sh install    chép script vào /usr/local/sbin/mg-obs-targets + timer systemd
#                                                           mg-obs-targets.timer (mỗi phút) và chạy một lượt
# Hoàn tác install: sudo systemctl disable --now mg-obs-targets.timer && sudo rm -f /etc/systemd/system/mg-obs-targets.*
#                   /usr/local/sbin/mg-obs-targets && sudo systemctl daemon-reload
#
# Quy tắc kiểm (giống tools/render_monitoring.py instance_targets — tools/test_render_monitoring.py đối chiếu hai bản):
# tên container đúng mg-hs-<slug> với slug ^[a-z][a-z0-9-]{1,30}[a-z0-9]$ không chứa "--", hai nhãn là UUID; dòng sai
# hoặc slug trùng bị bỏ qua kèm cảnh báo trên stderr.
set -euo pipefail
OUT=${MG_OBS_TARGETS_FILE:-/opt/meshguard/core/monitoring/prometheus/targets/instances.json}
[ "$(id -u)" = 0 ] || { echo "cần chạy bằng root (sudo)"; exit 1; }

if [ "${1:-}" = install ]; then
  install -o root -g root -m 0755 "$0" /usr/local/sbin/mg-obs-targets
  cat > /etc/systemd/system/mg-obs-targets.service <<'UNIT'
[Unit]
Description=MeshGuard: danh sách instance tenant cho Prometheus (P3-T16)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mg-obs-targets
UNIT
  cat > /etc/systemd/system/mg-obs-targets.timer <<'UNIT'
[Unit]
Description=MeshGuard: làm mới danh sách instance cho Prometheus mỗi phút (P3-T16)

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now mg-obs-targets.timer
  shift
fi
[ $# -eq 0 ] || { echo "dùng: obs-targets.sh [install]"; exit 2; }

docker ps -a --filter label=meshguard.instance_id \
  --format '{{.Label "meshguard.tenant_id"}} {{.Label "meshguard.instance_id"}} {{.Names}}' |
python3 -I -c '
import json, os, re, sys, uuid
SLUG = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
out, path = {}, sys.argv[1]
for line in sys.stdin.read().splitlines():
    parts = line.split()
    if not parts:
        continue
    tenant, instance, name = (parts + ["", "", ""])[:3] if len(parts) == 3 else ("", "", " ".join(parts))
    slug = name[len("mg-hs-"):] if name.startswith("mg-hs-") else ""
    try:
        t, i = str(uuid.UUID(tenant)), str(uuid.UUID(instance))
    except ValueError:
        t = i = ""
    if not SLUG.fullmatch(slug) or "--" in slug or not t or not i or slug in out:
        if name.startswith("mg-hs-") or len(parts) != 3:
            print("obs-targets: bỏ qua dòng không hợp lệ: " + name[:80], file=sys.stderr)
        continue
    out[slug] = {"targets": [slug], "labels": {"slug": slug, "tenant_id": t, "instance_id": i}}
entries = [out[s] for s in sorted(out)]
tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
with open(tmp, "w", encoding="utf-8") as f:
    f.write(json.dumps(entries, indent=2) + "\n")
os.chmod(tmp, 0o644)
os.replace(tmp, path)
print("obs-targets: %d instance(s) -> %s" % (len(entries), path))
' "$OUT"
