#!/bin/bash
# P2-T16 — bước migrate của MỖI lần nâng cấp backend (§6.1, P2-T03a): (1) dump PostgreSQL trước migration bằng service
# pg-backup của project mg-backup (`once --label pre-migration` — mã hóa tới recovery recipient trước khi ghi);
# backup lỗi ⇒ DỪNG, không migrate; (2) job `migrate` của project mg-app (mg_migrator: goose + seed + River, mật khẩu
# các role đăng nhập, kiểm trạng thái). Hai project khác nhau nên không dùng depends_on (§14.4).
#
# Dùng:   sudo bash infrastructure/host/migrate.sh
# Biến (tùy chọn): MG_CORE_DIR (mặc định /opt/meshguard/core), DOCKER (mặc định "docker"),
#                  MG_BACKUP_PROJECT (mg-backup), MG_APP_PROJECT (mg-app) — cho stack thử/test.
# Hoàn tác: migration là forward-only — quay lại = restore dump pre-migration vừa tạo (docs/operations/backup-restore.md)
# rồi triển khai lại image trước.
set -euo pipefail
CORE=${MG_CORE_DIR:-/opt/meshguard/core}
read -r -a D <<< "${DOCKER:-docker}"
BACKUP=("${D[@]}" compose -p "${MG_BACKUP_PROJECT:-mg-backup}" -f "$CORE/compose.backup.yaml")
APP=("${D[@]}" compose -p "${MG_APP_PROJECT:-mg-app}" -f "$CORE/compose.app.yaml")
for f in compose.backup.yaml compose.app.yaml; do
  [ -s "$CORE/$f" ] || { echo "thiếu $CORE/$f — render và cài trước (RUNBOOK mục P2-T16)"; exit 1; }
done
echo "== 1/2 backup trước migration: ${BACKUP[*]} run --rm -T pg-backup once --label pre-migration"
if ! "${BACKUP[@]}" run --rm -T pg-backup once --label pre-migration; then
  echo "DỪNG: backup trước migration thất bại — KHÔNG migrate (P2-T03a)"
  exit 1
fi
echo "== 2/2 migrate: ${APP[*]} --profile migrate run --rm -T migrate"
if ! "${APP[@]}" --profile migrate run --rm -T migrate; then
  echo "LỖI: migrate thất bại — dump pre-migration vừa tạo dùng để restore (docs/operations/backup-restore.md)"
  exit 1
fi
echo "OK: backup pre-migration + migrate xong"
