-- 0020 — Đối soát sau khi restore PostgreSQL về thời điểm cũ hơn (P3-T17, §17.2): lệnh host `meshguard admin
-- post-restore-reconcile` chạy trong container worker (cần Host Agent, kek-app, policy_applications, tenant_invitations —
-- quyền của mg_worker_*) và bước đầu của nó là thu hồi MỌI session có trong DB vừa restore (quyền đã bị thu hồi trong
-- khoảng mất dữ liệu không được sống lại). Role mg_worker_platform tới nay chỉ có SELECT, DELETE trên sessions (job
-- session.gc — 0002): thêm UPDATE đúng hai cột của phép thu hồi (như RevokeIdentitySessions của module identity: đặt
-- revoked_at và xóa hint đăng xuất id_token_hint_enc — 0008). Không cột nào khác (id_hash, identity_id, các mốc hạn…).
-- Số hiệu 0020 tạm thời — người điều phối đánh số lại khi gộp (bản đồ §6.3; 0016–0019 đang dành cho các task Phase 3
-- chạy song song). Expand-only: chỉ thêm quyền, không đổi bảng hay hàng nào. Forward-only.

-- +goose Up

GRANT UPDATE (revoked_at, id_token_hint_enc) ON sessions TO mg_worker_platform;
