#!/bin/bash
# Tunnel WireGuard site-to-site giữa host LAN và VPS gateway (P1-T16, §14.9). Chạy trên TỪNG máy (root).
#   sudo bash wg-setup.sh key                                   # sinh khóa (nếu chưa có), in public key
#   sudo bash wg-setup.sh vps  <local /32> <peer /32> <peer pubkey>
#   sudo bash wg-setup.sh host <local /32> <peer /32> <peer pubkey> <vps ip:port>
# - Khóa riêng sinh tại máy, nằm ở /etc/wireguard/mg-wg0.key (0600) và KHÔNG có trong file cấu hình: wg-quick nạp
#   bằng PostUp. Chỉ public key được trao đổi.
# - VPS lắng nghe UDP 51820; host LAN chủ động kết nối (PersistentKeepalive) nên không cần port forwarding ở LAN.
# - AllowedIPs chỉ là địa chỉ /32 của đầu kia.
# Hoàn tác: sudo systemctl disable --now wg-quick@mg-wg0 && sudo rm /etc/wireguard/mg-wg0.{conf,key,pub}
set -euo pipefail
IF=mg-wg0; DIR=/etc/wireguard; KEY=$DIR/$IF.key; PUB=$DIR/$IF.pub; CONF=$DIR/$IF.conf
mode=${1:?usage: wg-setup.sh key | vps <local> <peer> <peer_pub> | host <local> <peer> <peer_pub> <endpoint>}
install -d -m 0700 "$DIR"
if [ ! -s "$KEY" ]; then (umask 077; wg genkey > "$KEY"); fi
wg pubkey < "$KEY" > "$PUB"; chmod 0644 "$PUB"
if [ "$mode" = key ]; then cat "$PUB"; exit 0; fi
LOCAL=${2:?local address}; PEER=${3:?peer address}; PEER_PUB=${4:?peer public key}
[[ "$PEER_PUB" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] || { echo "peer public key không hợp lệ"; exit 1; }
{
  echo "# MeshGuard tunnel ($mode end) — sinh bởi infrastructure/gateway/wg-setup.sh (P1-T16). Không chứa khóa riêng."
  echo "[Interface]"
  echo "Address = $LOCAL/32"
  [ "$mode" = vps ] && echo "ListenPort = 51820"
  echo "PostUp = wg set %i private-key $KEY"
  echo
  echo "[Peer]"
  echo "PublicKey = $PEER_PUB"
  echo "AllowedIPs = $PEER/32"
  if [ "$mode" = host ]; then echo "Endpoint = ${5:?vps endpoint ip:port}"; echo "PersistentKeepalive = 25"; fi
} > "$CONF.new"
chmod 0600 "$CONF.new"; mv "$CONF.new" "$CONF"
systemctl enable wg-quick@$IF >/dev/null 2>&1
systemctl restart wg-quick@$IF
wg show $IF | sed -E 's/(private key: ).*/\1(hidden)/'
