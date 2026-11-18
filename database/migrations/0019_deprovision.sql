-- 0019 — Deprovision tenant (P3-T09; §11.4 hàng Deprovision, §6.1 crypto-shredding). Viết với số tạm 0021 khi `main` có
-- tới 0017; đánh lại thành 0019 khi gộp `main` có 0018 (P3-T17) — staging đang ở schema 18.
--   tenants.keys_destroy_after  mốc hủy DEK của một tenant đã `deleted`: bước keys.schedule của job tenant.deprovision
--                               đặt = deleted_at + grace period (MG_DEPROVISION_KEY_GRACE); job định kỳ
--                               tenant.keys_destroy (worker) purge issuer IdP rồi hủy mọi DEK + mọi version secret của
--                               tenant khi mốc đã qua (crypto-shredding — đường restore online của bản backup cuối mất
--                               theo). NULL ⇔ chưa lên lịch; chỉ có trên tenant `deleted`, không sớm hơn deleted_at.
--   sessions                    bước access.revoke thu hồi mọi session Portal của identity thuộc tenant (đặt revoked_at
--                               như đăng xuất) bằng quyền UPDATE (revoked_at, id_token_hint_enc) mà 0018 (P3-T17) đã cấp
--                               cho mg_worker_platform — migration này không cấp lại.
-- Expand-only: một cột NULL-able + CHECK + quyền cột; không đổi truy vấn nào của bản đang chạy (sqlc liệt kê cột tường
-- minh, bản cũ không đọc cột mới). Forward-only.

-- +goose Up

ALTER TABLE tenants ADD COLUMN keys_destroy_after timestamptz;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_keys_destroy_after_deleted CHECK (keys_destroy_after IS NULL
        OR (status = 'deleted' AND deleted_at IS NOT NULL AND keys_destroy_after >= deleted_at));

-- Chỉ worker (job tenant.deprovision, pool platform) lên lịch hủy khóa; api không có quyền này.
GRANT UPDATE (keys_destroy_after) ON tenants TO mg_worker_platform;
