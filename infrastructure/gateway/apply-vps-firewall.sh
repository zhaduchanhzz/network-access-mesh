#!/bin/bash
# Áp firewall VPS (P1-T15) với lưới an toàn: tự hoàn tác sau 180 giây nếu không được xác nhận.
#   Bước 1 (script này):  bash apply-vps-firewall.sh < vps-firewall.nft
#   Bước 2 (phiên SSH MỚI vẫn vào được):  sudo systemctl stop mg-vps-fw-rollback.timer && sudo systemctl enable --now mg-vps-firewall.service
# Hoàn tác tay: sudo systemctl disable --now mg-vps-firewall.service   (ExecStop xóa bảng inet mg_vps)
set -euo pipefail
RULES=/etc/meshguard/vps-firewall.nft
UNIT=/etc/systemd/system/mg-vps-firewall.service

tmp=$(mktemp)
cat > "$tmp"
sudo nft -c -f "$tmp"                                   # chỉ kiểm cú pháp, chưa áp
sudo install -d -m 0755 /etc/meshguard
sudo install -m 0644 "$tmp" "$RULES"
rm -f "$tmp"

sudo tee "$UNIT" >/dev/null <<'UNIT'
[Unit]
Description=MeshGuard VPS firewall (nftables table inet mg_vps)
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/meshguard/vps-firewall.nft
ExecStop=/usr/sbin/nft delete table inet mg_vps

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload

sudo systemctl stop mg-vps-fw-rollback.timer 2>/dev/null || true
sudo systemd-run --quiet --unit=mg-vps-fw-rollback --on-active=180 /usr/sbin/nft delete table inet mg_vps
sudo nft -f "$RULES"
echo "firewall applied; automatic rollback in 180 s unless 'sudo systemctl stop mg-vps-fw-rollback.timer' is run"
sudo nft list table inet mg_vps | grep -cE "accept|drop" | xargs echo "rules in inet mg_vps:"
