#!/bin/bash
# P1-T03 — bố cục /opt/meshguard (§14.2), nhóm secret với GID cố định (versions.lock [ids]) và secret ban đầu của
# Phase 1. Giá trị secret sinh ngay trên host, KHÔNG bao giờ in ra. Chạy lại an toàn: secret đã có thì giữ nguyên.
# Hoàn tác: sudo rm -rf /opt/meshguard && for g in mg-sec-app mg-sec-api mg-sec-worker mg-sec-migrate mg-sec-edge \
#           mg-sec-obs mg-sec-backup mg-sec-ship; do sudo groupdel "$g"; done
set -euo pipefail
R=/opt/meshguard
declare -A GIDS=([mg-sec-app]=20001 [mg-sec-api]=20002 [mg-sec-worker]=20003 [mg-sec-migrate]=20004
                 [mg-sec-edge]=20005 [mg-sec-obs]=20006 [mg-sec-backup]=20007 [mg-sec-ship]=20008)
for g in "${!GIDS[@]}"; do
  want=${GIDS[$g]}
  have=$(getent group "$g" | cut -d: -f3 || true)
  if [ -n "$have" ]; then
    [ "$have" = "$want" ] || { echo "group $g has GID $have, expected $want — aborting"; exit 1; }
  else
    getent group "$want" >/dev/null && { echo "GID $want already used — aborting"; exit 1; }
    sudo groupadd --system --gid "$want" "$g"
  fi
done

sudo install -d -o root -g root -m 0755 "$R" "$R/core" "$R/tenants"
sudo install -d -o root -g root -m 0750 "$R/run"
sudo install -d -o root -g root -m 0700 "$R/secrets" "$R/backups"
for d in postgres idp edge tenants; do sudo install -d -o root -g root -m 0700 "$R/backups/$d"; done
for d in postgres crowdsec edge app obs; do sudo install -d -o root -g root -m 0700 "$R/secrets/$d"; done

new_secret() {   # <file>: 40 ký tự [A-Za-z0-9] ngẫu nhiên; giữ nguyên nếu đã có
  sudo test -s "$1" && return 0
  sudo sh -c "umask 077; tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 > '$1'"
}
copy_secret() {  # <src> <dst>: bản cho consumer khác, cùng giá trị (xoay cùng lúc — §14.2)
  sudo test -s "$2" || sudo cp "$1" "$2"
}
own() { sudo chown "$2:$3" "$1"; sudo chmod "$4" "$1"; }

new_secret "$R/secrets/postgres/superuser_password"
own        "$R/secrets/postgres/superuser_password" root 999 0440               # postgres (999:999)
new_secret "$R/secrets/crowdsec/bouncer_key"
own        "$R/secrets/crowdsec/bouncer_key" root root 0400                     # crowdsec (image chạy root)
copy_secret "$R/secrets/crowdsec/bouncer_key" "$R/secrets/edge/bouncer_key"
own        "$R/secrets/edge/bouncer_key" root mg-sec-edge 0440                  # edge (10001 + mg-sec-edge)
new_secret "$R/secrets/edge/admin_token"
own        "$R/secrets/edge/admin_token" root mg-sec-edge 0440
copy_secret "$R/secrets/edge/admin_token" "$R/secrets/app/edge_admin_token"
own        "$R/secrets/app/edge_admin_token" root mg-sec-app 0440               # api, worker (65532 + mg-sec-app)
new_secret "$R/secrets/edge/metrics_token"
own        "$R/secrets/edge/metrics_token" root mg-sec-edge 0440
copy_secret "$R/secrets/edge/metrics_token" "$R/secrets/obs/edge_metrics_token"
own        "$R/secrets/obs/edge_metrics_token" root mg-sec-obs 0440            # prometheus (65534 + mg-sec-obs)

sudo find "$R" -mindepth 1 -maxdepth 3 -printf '%M %u:%g %p\n' | sort -k3
