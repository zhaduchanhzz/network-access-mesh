-- 0028 — Support Access Grant: ảnh chụp tên hiển thị của grantee (P4-T13; §8.7 bước 3 "audit hiển thị cho tenant").
-- Số hiệu TẠM (sau 0025 của P4-T03a; 0026/0027 dành cho task đang song song) — người điều phối có thể đánh số lại khi gộp.
--
-- Tenant phải thấy AI đang xin/đang giữ quyền hỗ trợ vào mình (GET /tenants/{t}/support-grants, Portal). Grantee là một
-- platform user; pool tenant không đọc được platform_users / identities phạm vi platform (RLS — §6.1), nên tên hiển thị
-- được chụp lại lúc xin (POST /platform/support-grants, pool platform — đã có quyền INSERT mọi cột), giống
-- audit_events.actor_display. Cột KHÔNG được cấp UPDATE cho role nào (bất biến như lý do, ticket — quyền cột của 0023).
-- Forward-only, expand-only: hàng cũ (không có trong môi trường nào ngoài dev/CI — API xin grant có từ P4-T13) nhận ''.

-- +goose Up
ALTER TABLE support_access_grants
    ADD COLUMN grantee_display text NOT NULL DEFAULT '' CHECK (length(grantee_display) <= 200);
