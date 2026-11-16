#!/bin/bash
# Download the current Ubuntu 24.04 (noble) cloud image to Proxmox "import" storage and verify it:
# 1) GPG-verify SHA256SUMS with the Ubuntu cloud image signing key (fingerprint pinned below),
# 2) check the image against the signed SHA256SUMS.
# Read-only for existing VMs; writes only into /var/lib/vz/import/meshguard/.
set -euo pipefail
BASE="https://cloud-images.ubuntu.com/noble/current"
IMG="noble-server-cloudimg-amd64.img"
KEY_FPR="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"   # UEC Image Automatic Signing Key <cdimage@ubuntu.com>
DEST="/var/lib/vz/import/meshguard"
mkdir -p "$DEST"
cd "$DEST"
export GNUPGHOME="$(mktemp -d)"
trap 'rm -rf "$GNUPGHOME"' EXIT

curl -fsSL -o SHA256SUMS "$BASE/SHA256SUMS"
curl -fsSL -o SHA256SUMS.gpg "$BASE/SHA256SUMS.gpg"
gpg --batch --quiet --keyserver hkps://keyserver.ubuntu.com --recv-keys "$KEY_FPR" 2>/dev/null
if gpg --batch --status-fd 1 --verify SHA256SUMS.gpg SHA256SUMS 2>/dev/null | grep -q "VALIDSIG $KEY_FPR"; then
  echo "SHA256SUMS: chữ ký GPG hợp lệ (key $KEY_FPR)"
else
  echo "SHA256SUMS: KHÔNG xác minh được chữ ký GPG — dừng"; exit 1
fi
EXPECTED="$(grep " \*\?$IMG\$" SHA256SUMS | awk '{print $1}')"
[ -n "$EXPECTED" ] || { echo "không tìm thấy $IMG trong SHA256SUMS"; exit 1; }
if [ -f "$IMG" ] && echo "$EXPECTED  $IMG" | sha256sum -c --status; then
  echo "image đã có và khớp checksum — không tải lại"
else
  curl -fsSL -o "$IMG.part" "$BASE/$IMG"
  echo "$EXPECTED  $IMG.part" | sha256sum -c --status || { echo "checksum KHÔNG khớp — dừng"; rm -f "$IMG.part"; exit 1; }
  mv "$IMG.part" "$IMG"
  echo "đã tải và kiểm checksum"
fi
qemu-img info "$IMG" | grep -E "^(file format|virtual size)"
echo "sha256: $EXPECTED"
ls -la "$DEST"
