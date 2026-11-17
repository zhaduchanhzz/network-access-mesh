#!/bin/bash
# P2-T11a — in `sub` của một user Keycloak (= id của user, UUID chữ thường — P2-T05a ca 5) để đưa vào
# `meshguard admin bootstrap-super-admin --subject` / `seed-membership --subject`: nền tảng khớp danh tính theo
# (IdP, sub), KHÔNG BAO GIỜ theo email (§8.2). Chỉ ĐỌC (GET /admin/realms/<realm>/users), không sửa gì ở Keycloak.
#
#   sudo bash infrastructure/idp/user-id.sh <realm> <username | email>
#   ví dụ: sudo bash infrastructure/idp/user-id.sh platform an.nguyen
#
# In ra mảng JSON [{id, username, email, enabled}] của user khớp CHÍNH XÁC (exact=true) — không có secret. Không có
# user nào ⇒ `[]` (kiểm lại realm/username); `id` là giá trị cần dùng.
#
# Danh tính đọc: admin khởi tạo của realm master (bootstrap-admin-* trong keycloak.conf — thông tin break-glass của
# người vận hành, P2-T05). Mật khẩu KHÔNG đi qua host: kcadm chạy TRONG container idp và đọc nó từ secret đã mount
# (/run/secrets/keycloak.conf) vào biến môi trường KC_CLI_PASSWORD của riêng tiến trình kcadm — không in ra, không
# nằm trong argv (`ps`), không qua terminal, không ghi đĩa. Token của kcadm nằm trong một file tạm trên tmpfs /tmp của
# container, xóa khi thoát (trap). Gọi qua http://localhost:8080 bên trong container: không qua edge, không mở cổng.
#
# Biến: MG_IDP_PROJECT (mặc định mg-idp — `name:` của compose.idp.yaml.tmpl) để chạy với stack thử (tests/idp).
set -euo pipefail
REALM=${1:-}
WHO=${2:-}
PROJECT=${MG_IDP_PROJECT:-mg-idp}
[[ $REALM =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo "realm không hợp lệ (ví dụ: platform, tenant-a)" >&2; exit 2; }
[[ $WHO =~ ^[A-Za-z0-9._@+-]{1,255}$ ]] || { echo "username/email không hợp lệ" >&2; exit 2; }
[[ $PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo "MG_IDP_PROJECT không hợp lệ" >&2; exit 2; }
FIELD=username
[[ $WHO == *@* ]] && FIELD=email
mapfile -t KC < <(docker ps -q -f "label=com.docker.compose.project=$PROJECT" -f label=com.docker.compose.service=idp)
[ "${#KC[@]}" -eq 1 ] || { echo "cần đúng một container idp đang chạy của project $PROJECT (thấy ${#KC[@]})" >&2; exit 1; }

docker exec -i "${KC[0]}" bash -s -- "$REALM" "$FIELD=$WHO" <<'IN'
set -euo pipefail
cfg=$(mktemp /tmp/kcadm.XXXXXX)
trap 'rm -f "$cfg"' EXIT
conf=/run/secrets/keycloak.conf
admin=$(sed -n 's/^bootstrap-admin-username=//p' "$conf")
KC_CLI_PASSWORD=$(sed -n 's/^bootstrap-admin-password=//p' "$conf") \
  /opt/keycloak/bin/kcadm.sh config credentials --config "$cfg" --server http://localhost:8080 --realm master \
  --user "$admin" >/dev/null
/opt/keycloak/bin/kcadm.sh get users --config "$cfg" -r "$1" -q "$2" -q exact=true --fields id,username,email,enabled
IN
