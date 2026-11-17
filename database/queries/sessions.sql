-- Truy vấn của module identity (P2-T06): luồng đăng nhập OIDC (auth_requests), session phía server (BFF, §8.3) và
-- job session.gc (§6.4). sessions/auth_requests không có RLS và chỉ cấp cho role platform (0002) ⇒ mọi truy vấn ở đây
-- chạy trong store.WithPlatformTx, trừ ListActiveMembershipsForIdentity (bảng T — store.WithTenantTx với tenant của
-- chính identity). Mọi mốc thời gian do ứng dụng truyền vào (đồng hồ của module identity), không dùng now() của DB.

-- name: ListLoginIdPsForTenant :many
-- IdP đang active của tenant theo slug (§8.3 bước 1: IdP chọn từ DB theo tenant, không nhận từ client). LIMIT 2 để
-- phát hiện cấu hình mơ hồ (index một-active-mỗi-tenant đã chặn ở DB).
SELECT sqlc.embed(p), t.status AS tenant_status
FROM identity_providers p
JOIN tenants t ON t.id = p.tenant_id
WHERE t.slug = sqlc.arg(slug) AND t.status <> 'deleted' AND p.scope = 'tenant' AND p.status = 'active'
ORDER BY p.created_at, p.id
LIMIT 2;

-- name: ListActivePlatformIdPs :many
-- IdP đang active của nền tảng (đăng nhập scope=platform trên origin admin). Hơn một hàng ⇒ cấu hình mơ hồ, từ chối.
SELECT * FROM identity_providers
WHERE scope = 'platform' AND status = 'active'
ORDER BY created_at, id
LIMIT 2;

-- name: InsertAuthRequest :exec
-- §8.3 bước 2: state chỉ lưu hash; nonce; PKCE verifier đã mã hóa (khóa dẫn xuất từ state + cookie ràng buộc — không
-- có trong DB); hạn ≤ 10 phút (CHECK của 0002).
INSERT INTO auth_requests (state_hash, idp_id, tenant_id, scope, origin, nonce, pkce_verifier_enc, return_to,
                           browser_binding_hash, created_at, expires_at)
VALUES (sqlc.arg(state_hash), sqlc.arg(idp_id), sqlc.narg(tenant_id), sqlc.arg(scope), sqlc.arg(origin),
        sqlc.arg(nonce), sqlc.arg(pkce_verifier_enc), sqlc.narg(return_to), sqlc.arg(browser_binding_hash),
        sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: ConsumeAuthRequest :one
-- Dùng một lần: chỉ lần gọi đầu tiên nhận được hàng, lần sau (replay) không có hàng. Hàng đã hết hạn cũng bị đánh dấu
-- đã dùng — người gọi kiểm expires_at.
UPDATE auth_requests SET consumed_at = sqlc.arg(now)::timestamptz
WHERE state_hash = sqlc.arg(state_hash) AND consumed_at IS NULL
RETURNING *;

-- name: UpsertLoginIdentity :one
-- Chỉ chạy sau khi mọi kiểm tra của callback đạt (§8.3 bước 3). tenant_id/scope sao chép từ IdP (FK ghép từ chối giá
-- trị lệch). Identity đã tồn tại nhưng không active ⇒ không cập nhật, không trả hàng (người gọi từ chối đăng nhập).
INSERT INTO identities (idp_id, tenant_id, scope, subject, email, email_verified, display_name, last_login_at,
                        updated_at)
VALUES (sqlc.arg(idp_id), sqlc.narg(tenant_id), sqlc.arg(scope), sqlc.arg(subject), sqlc.narg(email),
        sqlc.arg(email_verified), sqlc.narg(display_name), sqlc.arg(now)::timestamptz, sqlc.arg(now)::timestamptz)
ON CONFLICT (idp_id, subject) DO UPDATE
SET email = EXCLUDED.email, email_verified = EXCLUDED.email_verified, display_name = EXCLUDED.display_name,
    last_login_at = EXCLUDED.last_login_at, updated_at = EXCLUDED.updated_at
WHERE identities.status = 'active'
RETURNING *;

-- name: InsertSession :one
-- §8.3 bước 4: chỉ lưu hash của session id; session chỉ mang danh tính (không role). id_token_hint_enc (0008, G2 vòng 2
-- A-1): ID token của lần đăng nhập đã mã hóa bằng khóa dẫn xuất từ session id thô — NULL khi IdP không có
-- end_session_endpoint.
INSERT INTO sessions (id_hash, identity_id, idp_id, origin, created_at, last_seen_at, auth_time, idle_expires_at,
                      absolute_expires_at, ip, user_agent, acr, amr, id_token_hint_enc)
VALUES (sqlc.arg(id_hash), sqlc.arg(identity_id), sqlc.arg(idp_id), sqlc.arg(origin), sqlc.arg(now), sqlc.arg(now),
        sqlc.arg(auth_time), sqlc.arg(idle_expires_at), sqlc.arg(absolute_expires_at), sqlc.narg(ip),
        sqlc.narg(user_agent), sqlc.narg(acr), sqlc.arg(amr), sqlc.narg(id_token_hint_enc))
RETURNING *;

-- name: GetSessionForRequest :one
-- Phân giải cookie session ở mỗi request (§8.3 bước 8): session + trạng thái identity và IdP; người gọi kiểm thu hồi,
-- hạn idle/tuyệt đối, origin.
SELECT sqlc.embed(s), i.scope AS identity_scope, i.tenant_id AS identity_tenant_id, i.status AS identity_status,
       i.subject AS identity_subject, i.email AS identity_email, i.display_name AS identity_display_name,
       p.status AS idp_status
FROM sessions s
JOIN identities i ON i.id = s.identity_id
JOIN identity_providers p ON p.id = s.idp_id
WHERE s.id_hash = sqlc.arg(id_hash);

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = sqlc.arg(now), idle_expires_at = sqlc.arg(idle_expires_at)
WHERE id_hash = sqlc.arg(id_hash) AND revoked_at IS NULL;

-- name: GetSessionLogoutHint :one
-- POST /auth/logout (G2 vòng 2 A-1): id_token_hint đã mã hóa của session còn chưa thu hồi, khóa hàng tới khi
-- RevokeSessionByHash trong cùng transaction xóa nó. Không có hàng ⇒ session đã bị thu hồi giữa chừng.
SELECT id_token_hint_enc FROM sessions
WHERE id_hash = sqlc.arg(id_hash) AND revoked_at IS NULL
FOR UPDATE;

-- name: RevokeSessionByHash :execrows
-- Đăng xuất / xoay session khi đăng nhập lại: thu hồi có hiệu lực ngay (§8.3 bước 6); hint đăng xuất bị xóa cùng lúc.
UPDATE sessions SET revoked_at = sqlc.arg(now)::timestamptz, id_token_hint_enc = NULL
WHERE id_hash = sqlc.arg(id_hash) AND revoked_at IS NULL;

-- name: RevokeOwnSession :execrows
-- DELETE /auth/sessions/{id}: chỉ session còn hiệu lực của chính identity; session của identity khác ⇒ 0 hàng (404).
UPDATE sessions SET revoked_at = sqlc.arg(now)::timestamptz, id_token_hint_enc = NULL
WHERE public_id = sqlc.arg(public_id) AND identity_id = sqlc.arg(identity_id) AND revoked_at IS NULL
  AND idle_expires_at > sqlc.arg(now)::timestamptz AND absolute_expires_at > sqlc.arg(now)::timestamptz;

-- name: RevokeIdentitySessions :execrows
-- Khóa / offboard / đổi role: thu hồi mọi session của một identity (§8.3 bước 8; `meshguard admin revoke-sessions` —
-- G2 vòng 2 A-2). Đếm mọi session chưa thu hồi (kể cả đã hết hạn idle — vô hại) và xóa hint đăng xuất của chúng.
UPDATE sessions SET revoked_at = sqlc.arg(now)::timestamptz, id_token_hint_enc = NULL
WHERE identity_id = sqlc.arg(identity_id) AND revoked_at IS NULL;

-- name: ListLiveSessionsForIdentity :many
-- GET /auth/sessions: session còn hiệu lực của chính identity, thứ tự ổn định (created_at, public_id), con trỏ là
-- cặp giá trị của phần tử cuối trang trước.
SELECT * FROM sessions
WHERE identity_id = sqlc.arg(identity_id) AND revoked_at IS NULL
  AND idle_expires_at > sqlc.arg(now) AND absolute_expires_at > sqlc.arg(now)
  AND (created_at > sqlc.arg(after_created_at)
       OR (created_at = sqlc.arg(after_created_at) AND public_id > sqlc.arg(after_public_id)))
ORDER BY created_at, public_id
LIMIT sqlc.arg(page_limit);

-- name: GetPlatformRoleKeyForIdentity :one
-- Role platform đang hoạt động của identity (chỉ hiển thị ở GET /auth/session — quyết định authz đọc lại ở mỗi request).
SELECT r.key
FROM platform_users u
JOIN roles r ON r.id = u.role_id
WHERE u.identity_id = sqlc.arg(identity_id) AND u.status = 'active';

-- name: ListActiveMembershipsForIdentity :many
-- Pool tenant (WithTenantTx với tenant của identity): membership đang hoạt động, kèm slug/tên tenant và khóa role.
SELECT m.id, m.tenant_id, t.slug, t.name, r.key AS role_key, m.status
FROM tenant_memberships m
JOIN tenants t ON t.id = m.tenant_id
JOIN roles r ON r.id = m.role_id
WHERE m.identity_id = sqlc.arg(identity_id) AND m.status = 'active'
ORDER BY m.created_at, m.id;

-- name: DeleteDeadSessions :execrows
-- session.gc (§6.4): xóa theo lô session đã thu hồi/hết hạn trước cutoff (= now − 30 ngày). Role worker platform.
DELETE FROM sessions
WHERE id_hash IN (
    SELECT d.id_hash FROM sessions d
    WHERE LEAST(COALESCE(d.revoked_at, 'infinity'::timestamptz), d.idle_expires_at, d.absolute_expires_at)
          < sqlc.arg(cutoff)::timestamptz
    LIMIT sqlc.arg(batch_size)::integer
);

-- name: DeleteStaleAuthRequests :execrows
-- session.gc (§6.4): xóa theo lô auth_requests có expires_at trước cutoff (= now − 1 giờ).
DELETE FROM auth_requests
WHERE state_hash IN (
    SELECT d.state_hash FROM auth_requests d
    WHERE d.expires_at < sqlc.arg(cutoff)::timestamptz
    LIMIT sqlc.arg(batch_size)::integer
);
