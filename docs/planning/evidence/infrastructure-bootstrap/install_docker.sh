#!/bin/bash
# Install Docker Engine + Compose plugin at the versions pinned in versions.lock, from Docker's official apt
# repository, after checking the repository signing key fingerprint. daemon.json is written BEFORE the first
# start so Docker never creates networks from its default pools (which include 192.168.0.0/16).
# Undo: sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
#       && sudo rm -rf /var/lib/docker /var/lib/containerd /etc/docker /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
set -euo pipefail
ENGINE="29.9.3"
COMPOSE="5.7.1"
KEY_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"   # Docker Release (CE deb) <docker@docker.com>

if command -v docker >/dev/null; then echo "docker already installed: $(docker --version)"; exit 0; fi

# 1. daemon.json first
sudo install -d -m 0755 /etc/docker
sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'
{
  "default-address-pools": [{"base": "172.24.0.0/13", "size": 24}],
  "ip": "127.0.0.1",
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "5"},
  "live-restore": true
}
JSON
python3 -m json.tool /etc/docker/daemon.json >/dev/null && echo "daemon.json written"

# 2. repository key, verified by fingerprint
tmp=$(mktemp)
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$tmp"
fpr=$(gpg --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: '/^fpr:/ && !n++ {print $10}')
[ "$fpr" = "$KEY_FPR" ] || { echo "Docker repo key fingerprint mismatch ($fpr) — aborting"; rm -f "$tmp"; exit 1; }
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 "$tmp" /etc/apt/keyrings/docker.asc
rm -f "$tmp"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update -qq

# 3. exact versions only — never fall back to something else
eng=$(apt-cache madison docker-ce | awk -v v="$ENGINE" '$3 ~ ":"v"-" && !n++ {print $3}')
cmp=$(apt-cache madison docker-compose-plugin | awk -v v="$COMPOSE" '$3 ~ "^"v"-" && !n++ {print $3}')
[ -n "$eng" ] || { echo "docker-ce $ENGINE not in repo — aborting"; apt-cache madison docker-ce | head -3; exit 1; }
[ -n "$cmp" ] || { echo "docker-compose-plugin $COMPOSE not in repo — aborting"; apt-cache madison docker-compose-plugin | head -3; exit 1; }
echo "installing docker-ce=$eng docker-compose-plugin=$cmp"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  "docker-ce=$eng" "docker-ce-cli=$eng" containerd.io docker-buildx-plugin "docker-compose-plugin=$cmp" >/dev/null
sudo apt-mark hold docker-ce docker-ce-cli docker-compose-plugin >/dev/null

# 4. verify
sudo docker version --format 'engine {{.Server.Version}}, client {{.Client.Version}}'
sudo docker compose version
echo "containerd: $(dpkg-query -W -f='${Version}' containerd.io), buildx: $(dpkg-query -W -f='${Version}' docker-buildx-plugin)"
sudo docker info --format 'storage={{.Driver}} cgroup={{.CgroupDriver}} live-restore={{.LiveRestoreEnabled}} logging={{.LoggingDriver}}'
sudo docker run --rm --network none docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf echo "test container ok (alpine pinned by digest)"
echo "listening sockets of dockerd: $(sudo ss -Htlnp | grep -c dockerd || true)"
