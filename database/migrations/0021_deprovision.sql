-- 0021 — Deprovision tenant (P3-T09; §11.4 hàng Deprovision, §6.1 crypto-shredding). SỐ HIỆU TẠM: viết khi `main` có
-- tới 0017 và các nhánh song song có thể dùng 0018–0020; người điều phối đánh lại số khi gộp (số migration phải liên tục
-- — goose từ chối migration số nhỏ hơn số đã áp).
--   tenants.keys_destroy_after  mốc hủy DEK của một tenant đã `deleted`: bước keys.schedule của job tenant.deprovision
--                               đặt = deleted_at + grace period (MG_DEPROVISION_KEY_GRACE); job định kỳ
--                               tenant.keys_destroy (worker) purge issuer IdP rồi hủy mọi DEK + mọi version secret của
--                               tenant khi mốc đã qua (crypto-shredding — đường restore online của bản backup cuối mất
--                               theo). NULL ⇔ chưa lên lịch; chỉ có trên tenant `deleted`, không sớm hơn deleted_at.
--   sessions                    worker platform được UPDATE (revoked_at, id_token_hint_enc): bước access.revoke thu hồi
--                               mọi session Portal của identity thuộc tenant (đặt revoked_at như đăng xuất — session.gc
--                               xóa hàng sau 30 ngày như mọi session đã thu hồi), không xóa hàng.
-- Expand-only: một cột NULL-able + CHECK + quyền cột; không đổi truy vấn nào của bản đang chạy (sqlc liệt kê cột tường
-- minh, bản cũ không đọc cột mới). Forward-only.

-- +goose Up

ALTER TABLE tenants ADD COLUMN keys_destroy_after timestamptz;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_keys_destroy_after_deleted CHECK (keys_destroy_after IS NULL
        OR (status = 'deleted' AND deleted_at IS NOT NULL AND keys_destroy_after >= deleted_at));

-- Chỉ worker (job tenant.deprovision, pool platform) lên lịch hủy khóa; api không có quyền này.
GRANT UPDATE (keys_destroy_after) ON tenants TO mg_worker_platform;

-- Thu hồi session của identity thuộc tenant bị xóa (bước access.revoke): đúng hai cột mà đăng xuất ghi.
GRANT UPDATE (revoked_at, id_token_hint_enc) ON sessions TO mg_worker_platform;
