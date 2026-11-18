-- Backup/restore v1 của instance tenant (P3-T11; §17.1–§17.2, §6.3 `backups`, T-15). Sổ `backups` (0011) giữ
-- thêm những gì restore cần mà không đọc lại đĩa của Agent:
--   sequence            số thứ tự tăng dần của archive trong thư mục backups/tenants/<instance_id>/ (đặt tên file; ghi
--                       trong manifest ký) — UNIQUE theo instance;
--   wrapped_data_key    data key ngẫu nhiên của archive, BỌC bằng khóa backup của tenant (secret `backup-key` trong
--                       SecretStore, dưới DEK của tenant — key_ref trỏ đúng version): AES-256-GCM, AAD = tenant|instance|
--                       sequence (đường online — §17.1). Không phải secret: không mở được nếu thiếu khóa của chính tenant;
--   manifest, manifest_signature, manifest_sha256
--                       manifest chuẩn hóa (JSON) và chữ ký Ed25519 của Agent: worker kiểm lại (MG_BACKUP_MANIFEST_PUBKEY)
--                       lúc ghi sổ VÀ trước mọi restore — trước khi mở bọc data key (Worker + Agent cùng kiểm, §17.1);
--   method              vacuum_into (instance đang chạy) | cold_copy (instance đang dừng).
-- Hàng instance mới bắt buộc sequence + wrapped_data_key; hàng succeeded/purged bắt buộc manifest. CHECK đặt NOT VALID:
-- hàng có sẵn (nếu có, trước P3-T11 không job nào ghi hàng instance) không bị kiểm lại.
-- Expand-only: cột NULL-able + CHECK + index + quyền cột, không đổi truy vấn nào của bản đang chạy. Forward-only.

-- +goose Up

ALTER TABLE backups
    ADD COLUMN sequence           bigint CHECK (sequence > 0),
    ADD COLUMN wrapped_data_key   bytea  CHECK (octet_length(wrapped_data_key) = 60),
    ADD COLUMN manifest           bytea  CHECK (octet_length(manifest) BETWEEN 1 AND 65536),
    ADD COLUMN manifest_signature bytea  CHECK (octet_length(manifest_signature) = 64),
    ADD COLUMN manifest_sha256    text   CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN method             text   CHECK (method IN ('vacuum_into', 'cold_copy'));

ALTER TABLE backups
    ADD CONSTRAINT backups_instance_key CHECK (kind <> 'instance' OR (sequence IS NOT NULL AND wrapped_data_key IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT backups_instance_manifest CHECK (kind <> 'instance' OR status NOT IN ('succeeded', 'purged')
        OR (manifest IS NOT NULL AND manifest_signature IS NOT NULL AND manifest_sha256 IS NOT NULL AND method IS NOT NULL)) NOT VALID;

CREATE UNIQUE INDEX backups_instance_sequence ON backups (instance_id, sequence) WHERE sequence IS NOT NULL;

-- manifest + method ghi khi backup xong (cùng lúc size/sha256); sequence, wrapped_data_key bất biến từ lúc chèn.
GRANT UPDATE (manifest, manifest_signature, manifest_sha256, method) ON backups TO mg_worker_tenant, mg_worker_platform;
