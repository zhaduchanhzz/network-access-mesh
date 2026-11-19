#!/bin/bash
# dep4 — "VM con" cho diễn tập nâng staging Phase 3 → Phase 4 trên VM 110 (KHÔNG phải staging).
# Một container privileged mang userland Ubuntu 24.04 của chính VM (/usr chỉ đọc — cùng Docker 29.9.3 như staging),
# /etc, /opt, /root, /var riêng dưới ~/dep4/root ⇒ /opt/meshguard, nhóm mg-sec-*, dockerd lồng bên trong hoàn toàn
# tách khỏi VM. Mạng ngoài: dep4-lan (LAN giả), dep4-tun (tunnel giả, đổi tên mg-wg0 bên trong), dep4-inet (Internet giả).
set -euo pipefail
D="sudo -n docker"
W=$HOME/dep4
lan_ip=10.77.4.10; tun_ip=10.77.5.2
for spec in "dep4-lan 10.77.4.0/24 10.77.4.1 " "dep4-tun 10.77.5.0/24 10.77.5.1 --internal" "dep4-inet 192.88.99.0/24 192.88.99.1 "; do
  read -r n sub gw extra <<<"$spec"
  $D network inspect "$n" >/dev/null 2>&1 || $D network create $extra --subnet "$sub" --gateway "$gw" --label dep4=1 "$n" >/dev/null
done
if ! $D image inspect dep4-host:skel >/dev/null 2>&1; then
  rm -rf "$W/skel"; mkdir -p "$W/skel"; cd "$W/skel"
  mkdir -p usr etc opt root home tmp var run proc sys dev mnt srv
  ln -s usr/bin bin; ln -s usr/lib lib; ln -s usr/lib64 lib64; ln -s usr/sbin sbin
  tar -C "$W/skel" -c . | $D import -c 'LABEL dep4=1' - dep4-host:skel >/dev/null
fi
if [ ! -d "$W/root/etc" ]; then
  sudo mkdir -p "$W/root"/{opt,rootdir,home,var/lib,var/log,var/tmp,var/cache,var/spool}
  sudo ln -sfn /run "$W/root/var/run"; sudo ln -sfn /run/lock "$W/root/var/lock"
  sudo cp -a /etc "$W/root/etc"
  sudo rm -f "$W/root"/etc/ssh/ssh_host_* "$W/root"/etc/sudoers.d/90-cloud-init-users
  sudo install -d -m 0755 "$W/root/etc/docker"
  sudo rm -f "$W/root/etc/docker/"*
  # daemon.json của host staging (P1-T02): cùng nội dung với VM 110 và docs/planning/evidence/infrastructure-bootstrap
  printf '%s\n' '{' '  "default-address-pools": [{"base": "172.24.0.0/13", "size": 24}],' '  "ip": "127.0.0.1",' \
    '  "log-driver": "json-file",' '  "log-opts": {"max-size": "10m", "max-file": "5"},' '  "live-restore": true' '}' \
    | sudo tee "$W/root/etc/docker/daemon.json" >/dev/null
fi
sudo tee "$W/root/rootdir/dep4-init.sh" >/dev/null <<'INIT'
#!/bin/bash
set -e
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then        # cgroup v2 lồng (như entrypoint của docker:dind)
  mkdir -p /sys/fs/cgroup/init
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || :
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control || :
fi
dev=$(ip -o -4 addr show | awk '$4=="10.77.5.2/24"{print $2}')
if [ -n "$dev" ] && [ "$dev" != mg-wg0 ]; then
  ip link set "$dev" down; ip link set "$dev" name mg-wg0; ip link set mg-wg0 up
fi
mkdir -p /run/lock
mount --make-rshared /       # node-exporter của mg-obs mount / với rslave (như host thật)
exec /usr/bin/dockerd >>/var/log/dockerd.log 2>&1
INIT
if ! $D container inspect dep4-host >/dev/null 2>&1; then
  $D create --name dep4-host --hostname mg-staging --privileged --cgroupns=private --label dep4=1 \
    -e container=docker --network dep4-lan --ip "$lan_ip" \
    --tmpfs /run:rw,mode=0755,size=512m --tmpfs /tmp:rw,mode=1777,size=4g \
    -v /usr:/usr:ro -v "$W/root/etc:/etc" -v "$W/root/opt:/opt" -v "$W/root/rootdir:/root" \
    -v "$W/root/var:/var" -v "$W/root/home:/home" \
    dep4-host:skel /usr/libexec/docker/docker-init -- /usr/bin/bash /root/dep4-init.sh >/dev/null
  $D network connect --ip "$tun_ip" dep4-tun dep4-host
  # host staging ra Internet tới IP công khai của chính VPS (STUN, probe-key-public, relay.probe — như staging)
  $D network connect --ip 192.88.99.20 dep4-inet dep4-host
fi
$D start dep4-host >/dev/null
for _ in $(seq 1 60); do $D exec dep4-host docker info >/dev/null 2>&1 && break; sleep 1; done
$D exec dep4-host docker info --format '{{.ServerVersion}} {{.Driver}} {{json .DriverStatus}} cgroup={{.CgroupVersion}}/{{.CgroupDriver}}'
$D exec dep4-host ip -4 -o addr show | awk '{print $2, $4}'
