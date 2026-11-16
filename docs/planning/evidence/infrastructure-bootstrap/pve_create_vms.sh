#!/bin/bash
# Create the MeshGuard VMs on Proxmox storage nvme01 from the verified Ubuntu 24.04 cloud image.
# Never touches existing VMs: refuses any VMID that already exists. No passwords: cloud-init user
# "mgdeploy" gets only the project's SSH public key.
set -euo pipefail
IMG="/var/lib/vz/import/meshguard/noble-server-cloudimg-amd64.img"
STORAGE="nvme01"
KEYFILE="$(mktemp)"
trap 'rm -f "$KEYFILE"' EXIT
echo "ssh-ed25519 PUBKEY_PLACEHOLDER" > "$KEYFILE"

# id name cores memMB diskGB bridge onboot role
VMS=(
  "104 mg-staging 8 24576 250 vmbr0 1 staging-host"
  "105 mg-ci-runner 6 16384 150 vmbr0 1 ci-runner"
  "106 mg-client-a1 2 2048 20 vmbr0 0 test-client-tenant-a-lan"
  "107 mg-client-b1 2 2048 20 vmbr0 0 test-client-tenant-b-lan"
  "108 mg-client-a2 2 2048 20 lan10 0 test-client-tenant-a-nat"
  "109 mg-client-b2 2 2048 20 lan10 0 test-client-tenant-b-nat"
)

[ -f "$IMG" ] || { echo "image không có: $IMG"; exit 1; }
for spec in "${VMS[@]}"; do
  read -r id name cores mem disk bridge onboot role <<<"$spec"
  if qm status "$id" >/dev/null 2>&1; then
    echo "VMID $id đã tồn tại — dừng, không ghi đè"; exit 1
  fi
done

for spec in "${VMS[@]}"; do
  read -r id name cores mem disk bridge onboot role <<<"$spec"
  echo "== $id $name"
  qm create "$id" --name "$name" --tags "meshguard;$role" \
    --description "MeshGuard ZTNA - $role - created 2026-11-16 at the project owner's request (Ubuntu 24.04 cloud image, sha256 verified)" \
    --memory "$mem" --cores "$cores" --sockets 1 --cpu host --ostype l26 \
    --scsihw virtio-scsi-single --net0 "virtio,bridge=$bridge" \
    --serial0 socket --vga serial0 --agent enabled=1 --onboot "$onboot"
  qm set "$id" --scsi0 "$STORAGE:0,import-from=$IMG,discard=on,ssd=1,iothread=1" >/dev/null
  qm resize "$id" scsi0 "${disk}G" >/dev/null
  qm set "$id" --ide2 "$STORAGE:cloudinit" --boot order=scsi0 \
    --ciuser mgdeploy --sshkeys "$KEYFILE" --ipconfig0 ip=dhcp >/dev/null
  qm start "$id"
  echo "   started; MAC: $(qm config "$id" | sed -n 's/^net0: virtio=\([^,]*\),.*/\1/p')"
done
qm list | awk 'NR==1 || $1>=104'
