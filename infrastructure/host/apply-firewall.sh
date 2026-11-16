#!/bin/bash
# Áp firewall host (P1-T02) với lưới an toàn: tự hoàn tác sau 180 giây nếu không được xác nhận.
#   Bước 1 (script này):  bash apply-firewall.sh < mg-staging-firewall.nft
#   Bước 2 (phiên SSH MỚI vẫn vào được):  sudo systemctl stop mg-fw-rollback.timer && sudo systemctl enable --now mg-host-firewall.service
# Hoàn tác tay: sudo systemctl disable --now mg-host-firewall.service   (ExecStop xóa bảng inet mg_host và bridge mg_bridge)
set -euo pipefail
RULES=/etc/meshguard/host-firewall.nft
UNIT=/etc/systemd/system/mg-host-firewall.service

tmp=$(mktemp)
cat > "$tmp"
sudo nft -c -f "$tmp"                                   # chỉ kiểm cú pháp, chưa áp
sudo install -d -m 0755 /etc/meshguard
sudo install -m 0644 "$tmp" "$RULES"
rm -f "$tmp"

sudo tee "$UNIT" >/dev/null <<'UNIT'
[Unit]
Description=MeshGuard host firewall (nftables table inet mg_host)
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/meshguard/host-firewall.nft
ExecStop=/bin/sh -c '/usr/sbin/nft delete table inet mg_host; /usr/sbin/nft delete table bridge mg_bridge; true'

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload

sudo systemctl stop mg-fw-rollback.timer 2>/dev/null || true
sudo systemd-run --quiet --unit=mg-fw-rollback --on-active=180 /bin/sh -c \
  '/usr/sbin/nft delete table inet mg_host; /usr/sbin/nft delete table bridge mg_bridge; true'
sudo nft -f "$RULES"
echo "firewall applied; automatic rollback in 180 s unless 'sudo systemctl stop mg-fw-rollback.timer' is run"
sudo nft list table inet mg_host | grep -cE "accept|drop" | xargs echo "rules in inet mg_host:"
sudo nft list table bridge mg_bridge 2>/dev/null | grep -cE "accept|drop" | xargs echo "rules in bridge mg_bridge:"
