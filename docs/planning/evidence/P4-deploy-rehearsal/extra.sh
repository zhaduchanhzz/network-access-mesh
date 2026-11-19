#!/bin/bash
# dep4 — phần riêng của diễn tập (KHÔNG có trên staging): "DNS công khai" giả cho bước 4 của tenant.provision và file
# override của mg-app (CA thử + MG_PROVISION_DNS_SERVER). Chạy trong host lồng.
#   bash /root/dep4x/extra.sh fakedns | override
source /root/dep4x/lib.sh

st_fakedns() {
  if ! docker image inspect dep4/skel:1 >/dev/null 2>&1; then
    local d; d=$(mktemp -d); (cd "$d" && mkdir -p usr etc tmp dep4 && ln -s usr/bin bin && ln -s usr/lib lib && ln -s usr/lib64 lib64 && ln -s usr/sbin sbin)
    tar -C "$d" -c . | docker import - dep4/skel:1 >/dev/null; rm -rf "$d"
  fi
  docker rm -f dep4-fakedns >/dev/null 2>&1 || true
  install -d -m 0755 /srv/dep4 && install -m 0644 /root/dep4x/fakedns.py /srv/dep4/fakedns.py
  docker run -d --name dep4-fakedns --label dep4=1 --network mg-egress --ip 10.249.5.53 --read-only --tmpfs /tmp \
    -v /usr:/usr:ro -v /srv/dep4/fakedns.py:/dep4/fakedns.py:ro --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --user 65534:65534 dep4/skel:1 /usr/bin/python3 -I /dep4/fakedns.py 0.0.0.0 mesh.dep4.test 192.88.99.10 >/dev/null
  sleep 1; docker ps --filter name=dep4-fakedns --format '{{.Names}} {{.Status}}'
}

st_override() {   # compose.app.dep4ca.yaml: CA thử cho api/worker + resolver giả cho bước 4 (worker)
  cat > /opt/meshguard/core/compose.app.dep4ca.yaml <<'EOF'
# DIỄN TẬP dep4 — KHÔNG có trên staging: api/worker tin CA thử (staging: chứng chỉ ACME công khai); bước 4 của
# tenant.provision hỏi "DNS công khai" giả (staging: resolver của container thấy bản ghi wildcard *.mesh thật).
services:
  api:
    environment: {SSL_CERT_FILE: /etc/dep4-ca/ca.crt, SSL_CERT_DIR: /etc/dep4-ca}
    volumes: [{type: bind, source: /opt/meshguard/core/dep4-ca, target: /etc/dep4-ca, read_only: true}]
  worker:
    environment: {SSL_CERT_FILE: /etc/dep4-ca/ca.crt, SSL_CERT_DIR: /etc/dep4-ca, MG_PROVISION_DNS_SERVER: "10.249.5.53:53"}
    volumes: [{type: bind, source: /opt/meshguard/core/dep4-ca, target: /etc/dep4-ca, read_only: true}]
EOF
  echo "override ghi xong"
}

for s in "$@"; do "st_$s"; done
