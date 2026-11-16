#!/bin/bash
# Read-only snapshot of the three compose projects on the VPS before they are stopped.
# Records names, images, restart policies, ports and compose locations — never environment
# variables or file contents (they may hold secrets). Output is printed and also saved to
# /root/meshguard-decommission-2026-11-16/state.txt on the VPS for the undo procedure.
set -euo pipefail
OUT=/root/meshguard-decommission-2026-11-16
sudo mkdir -p "$OUT"
{
  echo "# snapshot $(date -u +%FT%TZ)"
  for p in vnflashlearner-production viettrimarket-production house-studio; do
    echo "## project $p"
    ids=$(sudo docker ps -a -q --filter "label=com.docker.compose.project=$p")
    first=$(echo "$ids" | head -1)
    if [ -n "$first" ]; then
      echo "working_dir: $(sudo docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$first")"
      echo "config_files: $(sudo docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$first")"
    fi
    for id in $ids; do
      sudo docker inspect -f '{{.Name}} | {{.Config.Image}} | state={{.State.Status}} | restart={{.HostConfig.RestartPolicy.Name}} | ports={{range $k, $v := .HostConfig.PortBindings}}{{$k}} {{end}}' "$id"
    done
    echo "volumes:"; sudo docker volume ls -q --filter "label=com.docker.compose.project=$p" | sed 's/^/  /'
  done
} | sudo tee "$OUT/state.txt"
echo "## memory before"; free -h | head -2
