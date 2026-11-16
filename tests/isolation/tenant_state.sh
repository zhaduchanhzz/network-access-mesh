#!/bin/bash
# Dấu vân tay trạng thái của một tenant (AC-18, AC-19 — Phase 1, lấy qua CLI trong container):
# StartedAt của container, sha256 (16 ký tự đầu) của khóa Noise/DERP, hash đã chuẩn hóa của danh sách node, user và
# của policy. Bỏ trường biến động last_seen/online. Không in khóa hay dữ liệu node nào.
#   sudo bash tenant_state.sh <slug>          # so sánh output trước/sau một thao tác trên tenant KHÁC
set -euo pipefail
S=${1:?usage: tenant_state.sh <slug>}; C=mg-hs-$S
IID=$(docker inspect -f '{{index .Config.Labels "meshguard.instance_id"}}' "$C")
D=/opt/meshguard/tenants/$IID/data
echo "container_started_at=$(docker inspect -f '{{.State.StartedAt}}' "$C")"
for f in noise_private.key derp_server_private.key db.sqlite; do
  [ "$f" = db.sqlite ] && continue
  echo "$f.sha256=$(sha256sum "$D/$f" | cut -c1-16)"
done
docker exec "$C" headscale nodes list -o json | python3 -c '
import hashlib, json, sys
nodes = sorted(json.load(sys.stdin) or [], key=lambda n: n["id"])
for n in nodes:
    for k in ("last_seen", "online"):
        n.pop(k, None)
print("nodes.count=%d nodes.sha256=%s" % (len(nodes), hashlib.sha256(json.dumps(nodes, sort_keys=True).encode()).hexdigest()[:16]))
print("node_ids_keys.sha256=%s" % hashlib.sha256(json.dumps([(n["id"], n["node_key"]) for n in nodes]).encode()).hexdigest()[:16])'
docker exec "$C" headscale users list -o json | python3 -c '
import hashlib, json, sys
users = sorted(json.load(sys.stdin) or [], key=lambda u: u["id"])
print("users.count=%d users.sha256=%s" % (len(users), hashlib.sha256(json.dumps(users, sort_keys=True).encode()).hexdigest()[:16]))'
echo "policy.sha256=$(docker exec "$C" headscale policy get | sha256sum | cut -c1-16)"
