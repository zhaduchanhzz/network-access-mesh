#!/bin/sh
# quan sát trạng thái node tạm $1 mỗi 15 s tới epoch $2, ghi ~/p5lab/obs-$1.jsonl
n=$1; until=$2; S=/dev/shm/p5v-$(id -un)/$n/sock
while [ "$(date +%s)" -lt "$until" ]; do
  tailscale --socket=$S status --json 2>/dev/null | python3 -c '
import json,sys,time
try: d=json.load(sys.stdin)
except Exception: d={}
s=d.get("Self") or {}
print(json.dumps({"t":round(time.time(),1),"state":d.get("BackendState"),"self_expired":s.get("Expired"),"key_expiry":s.get("KeyExpiry"),
 "peers":[[p.get("HostName"),p.get("Online"),p.get("Expired"),p.get("KeyExpiry")] for p in (d.get("Peer") or {}).values()]}))' >> ~/p5lab/obs-$n.jsonl
  sleep 15
done
