#!/bin/bash
# P2-T05 — secret dạng file của IdP (§7.6, §14.2). Sinh ngay trên host, KHÔNG bao giờ in ra; chạy lại an toàn (file đã
# có thì giữ nguyên). Quyền đặt theo UID/GID mà image dùng (ST-05: compose bỏ qua uid/gid/mode của secret dạng file):
#   keycloak.conf          root:1000 0440  Keycloak (chạy 1000:1000) — db-password + bootstrap-admin-* (đọc qua --config-file)
#   db_password            root:999  0440  idp-db: initdb/10-keycloak-db.sql đặt mật khẩu cho role keycloak (cùng giá trị)
#   db_superuser_password  root:999  0440  idp-db: superuser "postgres" (POSTGRES_PASSWORD_FILE) — chỉ để bảo trì
# GID 1000/999 trên host có thể là nhóm của user khác (mgdeploy, systemd-journal) — vô hại vì thư mục cha root 0700.
# Giá trị chỉ gồm [A-Za-z0-9]: Keycloak diễn giải ${...} trong file cấu hình (value expression), nên không dùng ký tự đặc biệt.
# bootstrap-admin-* chỉ được dùng khi Keycloak tạo realm master lần đầu (admin TẠM của Keycloak); sau đó là thông tin
# break-glass của người vận hành (đọc bằng sudo), không phải credential của IdP driver (driver dùng service account
# theo realm — §8.2). Xoay mật khẩu DB: ALTER ROLE keycloak trong idp-db, ghi cùng giá trị vào db_password và
# keycloak.conf, rồi khởi động lại idp.
#
# Dùng:    sudo bash infrastructure/idp/secrets.sh [<thư mục>]     (mặc định /opt/meshguard/secrets/idp)
# Hoàn tác: sudo rm -rf <thư mục>   (chỉ khi volume idp-db-data cũng bị xóa — mật khẩu đã nằm trong DB)
set -euo pipefail
D=${1:-/opt/meshguard/secrets/idp}
[ "$(id -u)" = 0 ] || { echo "cần chạy bằng root (sudo)"; exit 1; }
install -d -o root -g root -m 0700 "$(dirname "$D")"
install -d -o root -g root -m 0700 "$D"
umask 077

gen() {   # 40 ký tự [A-Za-z0-9] từ /dev/urandom (pipefail tắt cục bộ: head đóng ống trước tr)
  (set +o pipefail; tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)
}
new_secret() {   # <file>: tạo nếu chưa có hoặc rỗng
  [ -s "$1" ] && return 0
  gen > "$1.tmp" && mv "$1.tmp" "$1"
}
own() { chown "$2" "$1"; chmod "$3" "$1"; }

new_secret "$D/db_superuser_password"
new_secret "$D/db_password"
if [ ! -s "$D/keycloak.conf" ]; then
  {
    echo "# Sinh bởi infrastructure/idp/secrets.sh — KHÔNG commit, KHÔNG in ra (P2-T05, §7.6)."
    echo "db-password=$(cat "$D/db_password")"
    echo "bootstrap-admin-username=mg-bootstrap-admin"
    echo "bootstrap-admin-password=$(gen)"
  } > "$D/keycloak.conf.tmp"
  mv "$D/keycloak.conf.tmp" "$D/keycloak.conf"
fi
# db-password trong keycloak.conf phải trùng db_password (hai consumer, một giá trị). Chỉ so bằng builtin của bash:
# giá trị secret không bao giờ nằm trong argv của một tiến trình ngoài (/proc/<pid>/cmdline đọc được bởi mọi user).
want=$(cat "$D/db_password")
have=$(sed -n 's/^db-password=//p' "$D/keycloak.conf")
[ -n "$want" ] && [ "$have" = "$want" ] \
  || { echo "keycloak.conf và db_password lệch nhau — sửa tay (xem phần xoay mật khẩu ở đầu file)"; exit 1; }
unset want have

own "$D/db_superuser_password" root:999 0440
own "$D/db_password"           root:999 0440
own "$D/keycloak.conf"         root:1000 0440
stat -c '%A %U:%G %s byte  %n' "$D"/*
