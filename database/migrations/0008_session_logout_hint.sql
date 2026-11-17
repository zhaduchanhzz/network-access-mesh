-- 0008 — Đăng xuất kết thúc cả phiên SSO của IdP (G2 vòng 2, A-1 — docs/planning/evidence/G2-security-review.md):
-- POST /auth/logout chuyển trình duyệt tới end_session_endpoint của issuer (OIDC RP-Initiated Logout 1.0) kèm
-- id_token_hint. Không có hint, Keycloak 26 dừng ở trang "Bạn có muốn đăng xuất?": người dùng đóng tab ở đó thì phiên
-- SSO còn sống và người kế tiếp trên cùng trình duyệt đăng nhập không cần mật khẩu, không OTP — đúng kịch bản A-1.
-- sessions.id_token_hint_enc giữ ID token của lần đăng nhập, ĐÃ MÃ HÓA AES-256-GCM bằng khóa dẫn xuất (HKDF-SHA256) từ
-- session id thô — giá trị chỉ có trong cookie của trình duyệt, DB chỉ lưu SHA-256 của nó (id_hash) — với AAD là
-- id_hash + idp_id: bản sao của bảng (dump, backup, superuser) không mở được; chỉ một request mang đúng cookie mở được,
-- và chỉ lúc đăng xuất. Cột về NULL khi session bị thu hồi (đăng xuất, xoay khi đăng nhập lại, DELETE /auth/sessions/{id},
-- `meshguard admin revoke-sessions`); hàng bị session.gc xóa như cũ. NULL = không có hint (session tạo trước 0008, IdP
-- không công bố end_session_endpoint, token quá lớn) ⇒ đăng xuất chỉ gửi client_id.
-- Expand-only: thêm một cột NULL không default (chỉ đổi metadata, không ghi lại hàng nào); quyền cấp ở mức bảng (0002:
-- mg_api_platform SELECT/INSERT/UPDATE, mg_worker_platform SELECT/DELETE) phủ cột mới. Forward-only.

-- +goose Up

ALTER TABLE sessions
    ADD COLUMN id_token_hint_enc bytea CHECK (octet_length(id_token_hint_enc) BETWEEN 29 AND 16412);
