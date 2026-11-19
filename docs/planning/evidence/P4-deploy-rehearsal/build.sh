#!/bin/bash
# dep4 — build image tự build từ cây (như workflow images: APP/VERSION/COMMIT), BÊN TRONG host lồng. Chạy nền:
#   sudo docker exec dep4-host setsid nohup bash /root/dep4x/build.sh > /root/dep4x/build.log 2>&1 &
set -uo pipefail
declare -A SHA=([old]=884059066920bd9a327058b5b547f8cd995e1faf [new]=973663662742b3198c6bbd853738dae58926f6ae)
b() {  # <tree> <name> <dockerfile> <context-rel> [APP]
  local t=$1 n=$2 f=$3 c=$4 app=${5:-} s=${SHA[$1]} args=() t0
  [ -n "$app" ] && args=(--build-arg "APP=$app" --build-arg "VERSION=${s:0:12}" --build-arg "COMMIT=$s")
  t0=$(date +%s)
  if docker build -q -f "/root/src/$t/$f" "${args[@]}" -t "dep4/$n:$t" \
      --label "org.opencontainers.image.revision=$s" --label dep4=1 "/root/src/$t/$c" >/dev/null 2>"/root/dep4x/build-$n-$t.err"; then
    echo "OK $n:$t $(( $(date +%s) - t0 ))s $(docker image inspect -f '{{.Id}}' "dep4/$n:$t")"
  else
    echo "FAIL $n:$t $(( $(date +%s) - t0 ))s (xem /root/dep4x/build-$n-$t.err)"
  fi
}
echo "start $(date -u +%FT%TZ)"
b old api infrastructure/docker/app/Dockerfile . api
b old worker infrastructure/docker/app/Dockerfile . worker
b new api infrastructure/docker/app/Dockerfile . api
b new worker infrastructure/docker/app/Dockerfile . worker
b old agent infrastructure/docker/agent/Dockerfile . agent
b new agent infrastructure/docker/agent/Dockerfile . agent
b new web infrastructure/docker/web/Dockerfile .
b old probe infrastructure/docker/probe/Dockerfile . probe
b old backup infrastructure/docker/backup/Dockerfile . backup
b old node-exporter infrastructure/docker/node-exporter/Dockerfile infrastructure/docker/node-exporter
echo "done $(date -u +%FT%TZ)"
