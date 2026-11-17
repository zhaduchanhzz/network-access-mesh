#!/bin/bash
# Tạo một user người (tài khoản mẫu / người vận hành) trong một realm Keycloak, mật khẩu đọc từ STDIN — dùng ở P2-T16
# để có tài khoản cho `bootstrap-super-admin` / `seed-membership` (RUNBOOK, mục Super Admin đầu tiên). Thay cho thao tác
# tay ở Admin Console khi người vận hành muốn sinh mật khẩu tự động và lưu ở kho riêng của họ.
#
#   <mật khẩu> | sudo bash infrastructure/idp/create-user.sh <realm> <username> <email> <tên> <họ>
#
# - Mật khẩu: 16–128 ký tự [A-Za-z0-9] (đúng passwordPolicy của realm: length(12), notUsername, notEmail), một dòng trên
#   stdin. KHÔNG bao giờ nằm trong argv (`ps`), terminal hay đĩa của host: đi qua pipe ssh → docker exec → biến của bash
#   trong container → pipe (printf là builtin) vào `kcadm.sh create users -f -`.
# - User: enabled, emailVerified, mật khẩu KHÔNG tạm (temporary: false — chủ dự án giữ nó trong kho secret của họ),
#   required action CONFIGURE_TOTP: người dùng đăng ký TOTP ở lần đăng nhập đầu (seed TOTP chỉ nằm trong app
#   authenticator của họ — không ai khác có cả hai yếu tố).
# - Idempotent: user đã có (username khớp chính xác) ⇒ in `exists <id>` và KHÔNG đổi gì (kể cả mật khẩu); mới ⇒ in
#   `created <id>`. `id` = `sub` cho bootstrap-super-admin / seed-membership (không phải secret).
# - Danh tính dùng để ghi: admin khởi tạo của realm master, đọc trong container từ secret đã mount (như user-id.sh).
#
# Hoàn tác (chỉ khi chưa gắn membership/SA cho user này): sudo bash infrastructure/idp/user-id.sh <realm> <username>
#   rồi xóa user ở Admin Console (realm → Users → Delete), hoặc kcadm `delete users/<id> -r <realm>` trong container.
# Biến: MG_IDP_PROJECT (mặc định mg-idp) để chạy với stack thử.
set -euo pipefail
REALM=${1:-}; USERNAME=${2:-}; EMAIL=${3:-}; FIRST=${4:-}; LAST=${5:-}
PROJECT=${MG_IDP_PROJECT:-mg-idp}
[[ $REALM =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo "realm không hợp lệ (ví dụ: platform, tenant-a)" >&2; exit 2; }
[[ $USERNAME =~ ^[a-z0-9][a-z0-9._-]{1,62}$ ]] || { echo "username không hợp lệ ([a-z0-9._-], 2–63 ký tự)" >&2; exit 2; }
[[ $EMAIL =~ ^[A-Za-z0-9._+-]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,24}$ ]] || { echo "email không hợp lệ" >&2; exit 2; }
[[ $FIRST =~ ^[A-Za-z0-9\ ._-]{1,64}$ && $LAST =~ ^[A-Za-z0-9\ ._-]{1,64}$ ]] || { echo "tên/họ: chỉ [A-Za-z0-9 ._-]" >&2; exit 2; }
[[ $PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo "MG_IDP_PROJECT không hợp lệ" >&2; exit 2; }
mapfile -t KC < <(docker ps -q -f "label=com.docker.compose.project=$PROJECT" -f label=com.docker.compose.service=idp)
[ "${#KC[@]}" -eq 1 ] || { echo "cần đúng một container idp đang chạy của project $PROJECT (thấy ${#KC[@]})" >&2; exit 1; }

# Script chạy TRONG container (không chứa secret — chỉ tham số đã kiểm). stdin của docker exec = mật khẩu.
read -r -d '' IN <<'IN' || true
set -euo pipefail
IFS= read -r pw || true
pw=${pw%$'\r'}   # pipe từ Windows (text mode) có thể kèm CR cuối dòng
[[ $pw =~ ^[A-Za-z0-9]{16,128}$ ]] || { echo "mật khẩu trên stdin phải là 16–128 ký tự [A-Za-z0-9]" >&2; exit 2; }
cfg=$(mktemp /tmp/kcadm.XXXXXX)
trap 'rm -f "$cfg"' EXIT
conf=/run/secrets/keycloak.conf
admin=$(sed -n 's/^bootstrap-admin-username=//p' "$conf")
KC_CLI_PASSWORD=$(sed -n 's/^bootstrap-admin-password=//p' "$conf") \
  /opt/keycloak/bin/kcadm.sh config credentials --config "$cfg" --server http://localhost:8080 --realm master \
  --user "$admin" >/dev/null
kc() { /opt/keycloak/bin/kcadm.sh "$@" --config "$cfg"; }
found=$(kc get users -r "$1" -q "username=$2" -q exact=true --fields id --format csv --noquotes)
if [ -n "$found" ]; then
  echo "exists $found"
  exit 0
fi
printf '{"username":"%s","email":"%s","firstName":"%s","lastName":"%s","enabled":true,"emailVerified":true,"requiredActions":["CONFIGURE_TOTP"],"credentials":[{"type":"password","value":"%s","temporary":false}]}' \
  "$2" "$3" "$4" "$5" "$pw" | kc create users -r "$1" -f - -i | sed 's/^/created /'
IN
docker exec -i "${KC[0]}" bash -c "$IN" create-user "$REALM" "$USERNAME" "$EMAIL" "$FIRST" "$LAST"
