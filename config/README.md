# config/ — cấu hình cục bộ của máy vận hành

- `config/secrets/` — **chỉ ở máy vận hành**, bị `.gitignore` bỏ qua, không bao giờ commit. Chứa bản rõ các khóa
  của nghi thức khóa P2-T04a (`staging/`: KEK `kek-app`, `kek-ops`, khóa khôi phục backup), theo lựa chọn của chủ dự án
  ngày 2026-11-17. Ghi chú đầy đủ (giá trị kiểm KCV, recipient, cách dựng lại keyring) nằm trong
  `config/secrets/staging/README.md` — cũng không commit.
- Lưu ý: thư mục dự án nằm trong OneDrive ⇒ `config/secrets/` được đồng bộ lên cloud dù không vào git.
- Giá trị **không bí mật** (recipient `age1…`, khóa công khai ký manifest) nằm trong
  `infrastructure/environments/staging/staging.env` (`MG_BACKUP_RECOVERY_RECIPIENT`, `MG_BACKUP_MANIFEST_PUBKEY`).
