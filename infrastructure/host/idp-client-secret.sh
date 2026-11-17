#!/bin/bash
# P2-T16 — đưa client secret của `mg-portal` trong một realm Keycloak vào `meshguard admin set-idp-client-secret`
# MÀ KHÔNG HIỆN RA ĐÂU CẢ: script in secret ra stdout CHỈ KHI stdout là một pipe (từ chối terminal và file), để dùng
# đúng một cách:
#
#   sudo bash infrastructure/host/idp-client-secret.sh <realm> \
#     | sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml run --rm --no-deps -T api \
#         admin set-idp-client-secret <MG_IDP_ID_… của realm đó>
#
# Đọc qua Admin REST API BÊN TRONG container idp (kcadm.sh, http://localhost:8080 — không qua edge, không mở cổng)
# bằng admin khởi tạo của realm master: mật khẩu đọc trong container từ secret đã mount (/run/secrets/keycloak.conf)
# vào biến môi trường của riêng tiến trình kcadm — không qua host, không nằm trong argv, không in ra, không ghi đĩa;
# token tạm của kcadm ở tmpfs /tmp của container, xóa khi thoát. Cùng cách với infrastructure/idp/user-id.sh (P2-T11a).
# Chỉ ĐỌC (GET clients, GET client-secret), không đổi gì ở Keycloak.
#
# Biến: MG_IDP_PROJECT (mặc định mg-idp), DOCKER (mặc định docker).
set -euo pipefail
REALM=${1:-}
PROJECT=${MG_IDP_PROJECT:-mg-idp}
read -r -a D <<< "${DOCKER:-docker}"
[[ $REALM =~ ^[a-z0-9][a-z0-9-]{0,62}$ && $REALM != master ]] || { echo "realm không hợp lệ (platform, tenant-a, tenant-b)" >&2; exit 2; }
[[ $PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo "MG_IDP_PROJECT không hợp lệ" >&2; exit 2; }
if [ ! -p /dev/stdout ]; then   # terminal (hiện lên màn hình, scrollback) hoặc file (nằm trên đĩa) ⇒ từ chối
  echo "stdout không phải pipe: chỉ được pipe thẳng vào \`meshguard admin set-idp-client-secret\`" >&2
  exit 2
fi
mapfile -t KC < <("${D[@]}" ps -q -f "label=com.docker.compose.project=$PROJECT" -f label=com.docker.compose.service=idp)
[ "${#KC[@]}" -eq 1 ] || { echo "cần đúng một container idp đang chạy của project $PROJECT (thấy ${#KC[@]})" >&2; exit 1; }

"${D[@]}" exec -i "${KC[0]}" bash -s -- "$REALM" <<'IN'
set -euo pipefail
cfg=$(mktemp /tmp/kcadm.XXXXXX)
trap 'rm -f "$cfg"' EXIT
conf=/run/secrets/keycloak.conf
admin=$(sed -n 's/^bootstrap-admin-username=//p' "$conf")
KC_CLI_PASSWORD=$(sed -n 's/^bootstrap-admin-password=//p' "$conf") \
  /opt/keycloak/bin/kcadm.sh config credentials --config "$cfg" --server http://localhost:8080 --realm master \
  --user "$admin" >/dev/null
id=$(/opt/keycloak/bin/kcadm.sh get clients --config "$cfg" -r "$1" -q clientId=mg-portal --fields id --format csv --noquotes)
[ -n "$id" ] && [ "$(printf '%s\n' "$id" | wc -l)" = 1 ] || { echo "không thấy đúng một client mg-portal trong realm $1" >&2; exit 1; }
/opt/keycloak/bin/kcadm.sh get "clients/$id/client-secret" --config "$cfg" -r "$1" --fields value --format csv --noquotes
IN
