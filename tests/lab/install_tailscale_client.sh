#!/bin/bash
# Cài official Tailscale client (Linux) trên VM client của lab (P1-T05a, P1-T12, Phase 5) từ kho apt chính thức:
# kiểm vân tay khóa ký trước khi tin, pin đúng phiên bản và giữ (apt-mark hold).
#   sudo bash install_tailscale_client.sh <version> [--force-derp] [--hosts "<ip> <name> ..."]
#   --force-derp : TS_DEBUG_ALWAYS_USE_DERP=true cho tailscaled (không bind UDP ⇒ mọi lưu lượng đi qua DERP — CL-10)
#   --hosts      : thêm dòng vào /etc/hosts (Local Development: tên control/DERP trỏ IP LAN, không đổi DNS public)
# Hoàn tác: sudo tailscale logout; sudo apt-get purge -y tailscale; sudo rm -f /etc/apt/sources.list.d/tailscale.list \
#           /usr/share/keyrings/tailscale-archive-keyring.gpg; xóa dòng "# meshguard-lab" trong /etc/hosts
set -euo pipefail
TS_VERSION=${1:?usage: install_tailscale_client.sh <version> [--force-derp] [--hosts "<ip> <name>"]}; shift
FORCE_DERP=0; HOSTS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force-derp) FORCE_DERP=1 ;;
    --hosts) HOSTS=$2; shift ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
  shift
done
FPR=2596A99EAAB33821893C0A79458CA832957F5868   # Tailscale Inc. (Package repository signing key) — đối chiếu 2 nguồn
KEYRING=/usr/share/keyrings/tailscale-archive-keyring.gpg
CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")   # subshell: os-release cũng định nghĩa VERSION

tmp=$(mktemp)
curl -fsSL -o "$tmp" "https://pkgs.tailscale.com/stable/ubuntu/${CODENAME}.noarmor.gpg"
got=$(gpg --show-keys --with-colons "$tmp" | awk -F: '/^fpr/{print $10; exit}')
[ "$got" = "$FPR" ] || { echo "vân tay khóa không khớp: $got"; exit 1; }
install -m 0644 "$tmp" "$KEYRING"; rm -f "$tmp"
echo "deb [signed-by=$KEYRING] https://pkgs.tailscale.com/stable/ubuntu ${CODENAME} main" \
  > /etc/apt/sources.list.d/tailscale.list
apt-get update -qq -o Dir::Etc::sourcelist=sources.list.d/tailscale.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades "tailscale=${TS_VERSION}" >/dev/null
apt-mark hold tailscale >/dev/null

if [ "$FORCE_DERP" = 1 ]; then
  grep -q '^TS_DEBUG_ALWAYS_USE_DERP=' /etc/default/tailscaled \
    && sed -i 's/^TS_DEBUG_ALWAYS_USE_DERP=.*/TS_DEBUG_ALWAYS_USE_DERP=true/' /etc/default/tailscaled \
    || echo 'TS_DEBUG_ALWAYS_USE_DERP=true' >> /etc/default/tailscaled
else
  sed -i '/^TS_DEBUG_ALWAYS_USE_DERP=/d' /etc/default/tailscaled
fi
if [ -n "$HOSTS" ]; then
  sed -i '/# meshguard-lab$/d' /etc/hosts
  echo "$HOSTS # meshguard-lab" >> /etc/hosts
fi
systemctl restart tailscaled
echo "tailscale $(tailscale version | head -1); force-derp=$FORCE_DERP; hosts=${HOSTS:-none}"
