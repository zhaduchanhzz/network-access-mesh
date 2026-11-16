#!/bin/bash
# Find the DHCP-assigned IPv4 of the new VMs by MAC: ping-sweep the two subnets to fill the ARP
# table, then match MAC addresses. Read-only apart from ICMP echo requests.
declare -A MACS=(
  [104]="bc:24:11:49:76:f8" [105]="bc:24:11:af:4b:9f" [106]="bc:24:11:df:54:32"
  [107]="bc:24:11:30:13:86" [108]="bc:24:11:80:c7:bd" [109]="bc:24:11:88:6f:09"
)
for attempt in $(seq 1 12); do
  for i in $(seq 1 254); do
    (ping -c1 -W1 "192.168.1.$i" >/dev/null 2>&1 &)
    (ping -c1 -W1 -I lan10 "192.168.10.$i" >/dev/null 2>&1 &)
  done
  sleep 4
  found=0; out=""
  for id in 104 105 106 107 108 109; do
    ip=$(ip neigh | awk -v m="${MACS[$id]}" 'tolower($5)==m && $1 ~ /^192\.168\./ {print $1; exit}')
    [ -n "$ip" ] && found=$((found+1))
    out+="$id ${MACS[$id]} ${ip:-?}"$'\n'
  done
  if [ "$found" -eq 6 ]; then break; fi
  sleep 10
done
echo "attempts: $attempt"
printf '%s' "$out"
