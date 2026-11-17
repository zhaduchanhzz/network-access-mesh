#!/bin/bash
# P2-T16 — secret dạng file của project mg-app (api, worker, migrate, db-bootstrap — infrastructure/compose/
# compose.app.yaml.tmpl) theo §14.2: mỗi secret một file root:<nhóm> 0440, nhóm = GID cố định của service dùng nó
# (versions.lock [ids]); mật khẩu role DB lưu MỖI CONSUMER MỘT BẢN và xoay cùng lúc. Giá trị sinh ngay trên host
# (40 ký tự [A-Za-z0-9] — store.ReadPasswordFile: ASCII in được, ≥ 16), KHÔNG bao giờ in ra. Chạy lại an toàn: file đã
# có thì giữ nguyên; bản sao lệch bản gốc ⇒ dừng.
#
#   api/db_api_tenant_password, api/db_api_platform_password          root:mg-sec-api 0440     (api)
#   worker/db_worker_tenant_password, …platform…, db_partition_password root:mg-sec-worker 0440  (worker)
#   worker/agent_token                                                 root:mg-sec-worker 0440  (worker; Host Agent đọc
#                                                                      với tư cách owner — §11.1, P3-T02)
#   app/db_audit_writer_password                                       root:mg-sec-app 0440     (api — mg_audit_writer)
#   app/edge_admin_token                                               (có sẵn từ layout.sh — P1-T03)
#   migrate/ (thư mục root:mg-sec-migrate 0750): mg_migrator (mới) + BẢN của job migrate cho 6 role đăng nhập
#                                                (mg_migrator đặt mật khẩu các role đó sau migration)
#   backup/pg_backup_password (mg_backup)                              (có sẵn từ layout.sh — P2-T03a)
#   postgres/superuser_password                                        (có sẵn từ layout.sh — P1-T03)
#
# Dùng:    sudo bash infrastructure/host/app-secrets.sh            Kiểm: sudo bash infrastructure/host/check-secrets.sh
# Hoàn tác (CHỈ trước `migrate bootstrap`/`migrate up` — sau đó mật khẩu đã nằm trong PostgreSQL dạng verifier):
#   sudo rm -rf /opt/meshguard/secrets/{api,worker,migrate} /opt/meshguard/secrets/app/db_audit_writer_password
set -euo pipefail
R=${MG_SECRETS_ROOT:-/opt/meshguard/secrets}
[ "$(id -u)" = 0 ] || { echo "cần chạy bằng root (sudo)"; exit 1; }
for g in mg-sec-app:20001 mg-sec-api:20002 mg-sec-worker:20003 mg-sec-migrate:20004; do
  have=$(getent group "${g%%:*}" | cut -d: -f3 || true)
  [ "$have" = "${g##*:}" ] || { echo "nhóm ${g%%:*} phải có GID ${g##*:} (layout.sh, P1-T03) — dừng"; exit 1; }
done
for f in app/edge_admin_token backup/pg_backup_password postgres/superuser_password; do
  [ -s "$R/$f" ] || { echo "thiếu $R/$f (layout.sh) — dừng"; exit 1; }
done
umask 077
install -d -o root -g root -m 0700 "$R/api" "$R/worker"
install -d -o root -g mg-sec-migrate -m 0750 "$R/migrate"

gen() {   # 40 ký tự [A-Za-z0-9] từ /dev/urandom (pipefail tắt cục bộ: head đóng ống trước tr)
  (set +o pipefail; tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)
}
new_secret() {   # <file>: tạo nếu chưa có hoặc rỗng
  [ -s "$1" ] && return 0
  gen > "$1.tmp" && mv "$1.tmp" "$1"
}
copy_secret() {  # <src> <dst>: bản của consumer khác, cùng giá trị (xoay cùng lúc — §14.2); lệch ⇒ dừng
  [ -s "$2" ] || cp "$1" "$2"
  cmp -s "$1" "$2" || { echo "$2 khác $1 — xoay dở dang? dừng (không in giá trị)"; exit 1; }
}
own() { chown "root:$2" "$1"; chmod 0440 "$1"; }

new_secret "$R/api/db_api_tenant_password";          own "$R/api/db_api_tenant_password" mg-sec-api
new_secret "$R/api/db_api_platform_password";        own "$R/api/db_api_platform_password" mg-sec-api
new_secret "$R/worker/db_worker_tenant_password";    own "$R/worker/db_worker_tenant_password" mg-sec-worker
new_secret "$R/worker/db_worker_platform_password";  own "$R/worker/db_worker_platform_password" mg-sec-worker
new_secret "$R/worker/db_partition_password";        own "$R/worker/db_partition_password" mg-sec-worker
new_secret "$R/worker/agent_token";                  own "$R/worker/agent_token" mg-sec-worker   # token Agent (P3-T02)
new_secret "$R/app/db_audit_writer_password";        own "$R/app/db_audit_writer_password" mg-sec-app
new_secret "$R/migrate/mg_migrator";                 own "$R/migrate/mg_migrator" mg-sec-migrate
while read -r role src; do
  copy_secret "$R/$src" "$R/migrate/$role"
  own "$R/migrate/$role" mg-sec-migrate
done <<'MAP'
mg_api_tenant api/db_api_tenant_password
mg_api_platform api/db_api_platform_password
mg_worker_tenant worker/db_worker_tenant_password
mg_worker_platform worker/db_worker_platform_password
mg_partition_maint worker/db_partition_password
mg_audit_writer app/db_audit_writer_password
MAP
find "$R/api" "$R/worker" "$R/migrate" "$R/app/db_audit_writer_password" -printf '%M %u:%g %p\n' | sort -k3
