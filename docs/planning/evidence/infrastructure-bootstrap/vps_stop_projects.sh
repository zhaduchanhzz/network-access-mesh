#!/bin/bash
# Stop — not delete — the three compose projects on the VPS, at the owner's request (2026-11-16),
# so the MeshGuard gateway can use TCP 80/443 and UDP 3478.
# Kept: containers (stopped), images, volumes, /opt/<project> files, host mail services.
# Each container's restart policy is set to "no" so a reboot does not bring it back.
# The undo script is written BEFORE anything is stopped.
set -euo pipefail
OUT=/root/meshguard-decommission-2026-11-16
PROJECTS="vnflashlearner-production viettrimarket-production house-studio"

names=()
for p in $PROJECTS; do
  while read -r n; do [ -n "$n" ] && names+=("$n"); done < <(sudo docker ps -a --filter "label=com.docker.compose.project=$p" --format '{{.Names}}')
done
[ "${#names[@]}" -eq 15 ] || { echo "expected 15 containers, found ${#names[@]} — stopping without changes"; exit 1; }

# Undo: data stores first, then apps, then the edge (caddy, livekit).
ordered=()
for pass in 'postgres|redis|registry' 'backend|frontend|tts' 'caddy|livekit'; do
  for n in "${names[@]}"; do [[ "$n" =~ -($pass)-1$ ]] && ordered+=("$n"); done
done
[ "${#ordered[@]}" -eq 15 ] || { echo "undo ordering incomplete (${#ordered[@]}/15) — stopping without changes"; exit 1; }
{
  echo '#!/bin/bash'
  echo '# Undo for the 2026-11-16 stop: restore the restart policy and start the containers again.'
  echo 'set -e'
  echo "docker update --restart=unless-stopped ${ordered[*]}"
  echo "for c in ${ordered[*]}; do docker start \"\$c\"; sleep 2; done"
  echo "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
} | sudo tee "$OUT/undo.sh" >/dev/null
sudo chmod 700 "$OUT/undo.sh"
echo "undo script: $OUT/undo.sh"

# Stop the edge first so no new requests reach the apps, then everything else (30 s for clean DB shutdown).
sudo docker update --restart=no "${names[@]}" >/dev/null
for n in "${ordered[@]}"; do [[ "$n" =~ -(caddy|livekit)-1$ ]] && sudo docker stop -t 30 "$n" >/dev/null && echo "stopped $n"; done
for n in "${ordered[@]}"; do [[ "$n" =~ -(caddy|livekit)-1$ ]] || { sudo docker stop -t 30 "$n" >/dev/null && echo "stopped $n"; }; done

echo "## still running"; sudo docker ps --format '{{.Names}}' | sed 's/^/  /'; echo "  (end)"
echo "## restart policy"; for n in "${names[@]}"; do sudo docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}} {{.State.Status}}' "$n"; done
echo "## listeners on 80/443/3478/7881/7882"; sudo ss -Htulpn | awk '$5 ~ /:(80|443|3478|7881|7882)$/' || true; echo "  (end)"
echo "## memory after"; free -h | head -2
