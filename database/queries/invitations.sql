-- P3-T05a — lời mời (tenant_invitations của 0009, P3-T06) và gắn (idp_id, sub) ở lần đăng nhập đầu (§6.3, §8.2). Không
-- migration mới: 0009 cấp cho api tenant SELECT, INSERT, UPDATE (token_hash, expires_at, status, accepted_identity_id,
-- accepted_at, updated_at, version); tenant_memberships INSERT (0002); notification_outbox INSERT (0009). Mọi truy vấn
-- tenant chạy trong WithTenantTx của tenant (bảng T, không nhánh platform) và lọc tenant_id tường minh (lớp 5 của §8.8).
-- Chỉ lưu SHA-256 của token.

-- name: GetActiveTenantIdP :one
-- Pool tenant: IdP đang active của tenant (partial UNIQUE (tenant_id) WHERE status = 'active' của 0002) — lời mời ghi
-- IdP này; chỉ identity của đúng IdP đó nhận được lời mời (FK (accepted_identity_id, idp_id) của 0009).
SELECT id FROM identity_providers
WHERE tenant_id = sqlc.arg(tenant_id) AND status = 'active';

-- name: CountMembersWithEmail :one
-- Pool tenant: membership của tenant có identity mang email này (không phân biệt hoa thường — citext).
SELECT count(*) FROM tenant_memberships m
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND i.email = sqlc.arg(email)::citext;

-- name: LockPendingInvitationByEmail :one
-- Pool tenant: lời mời pending của (tenant, email) — tối đa một (partial UNIQUE của 0009), khóa tới hết transaction:
-- hai lần nhận đồng thời tuần tự hóa, lần sau không còn thấy hàng pending (dùng một lần).
SELECT * FROM tenant_invitations
WHERE tenant_id = sqlc.arg(tenant_id) AND email = sqlc.arg(email)::citext AND status = 'pending'
FOR UPDATE;

-- name: InsertInvitation :one
INSERT INTO tenant_invitations (tenant_id, idp_id, email, role_id, invited_by_identity_id, token_hash, expires_at,
                                created_at, updated_at)
VALUES (sqlc.arg(tenant_id), sqlc.arg(idp_id), sqlc.arg(email), sqlc.arg(role_id), sqlc.narg(invited_by_identity_id),
        sqlc.arg(token_hash), sqlc.arg(expires_at), sqlc.arg(now)::timestamptz, sqlc.arg(now)::timestamptz)
RETURNING *;

-- name: GetInvitationView :one
-- Một lời mời của tenant trong path (lớp 2: hàng của tenant khác ⇒ không có hàng ⇒ 404), kèm khóa role và tên hiển
-- thị của người mời.
SELECT sqlc.embed(inv), r.key AS role_key,
       COALESCE(ii.display_name, ii.email::text, ii.subject, '')::text AS invited_by_display
FROM tenant_invitations inv
JOIN roles r ON r.id = inv.role_id AND r.scope = inv.role_scope
LEFT JOIN identities ii ON ii.id = inv.invited_by_identity_id
WHERE inv.tenant_id = sqlc.arg(tenant_id) AND inv.id = sqlc.arg(id);

-- name: LockInvitation :one
SELECT sqlc.embed(inv), r.key AS role_key
FROM tenant_invitations inv
JOIN roles r ON r.id = inv.role_id AND r.scope = inv.role_scope
WHERE inv.tenant_id = sqlc.arg(tenant_id) AND inv.id = sqlc.arg(id)
FOR UPDATE OF inv;

-- name: ListInvitations :many
-- Mới nhất trước, thứ tự ổn định (created_at, id). Trạng thái hiệu lực: pending đã quá expires_at hiển thị (và lọc)
-- là expired.
SELECT sqlc.embed(inv), r.key AS role_key,
       COALESCE(ii.display_name, ii.email::text, ii.subject, '')::text AS invited_by_display
FROM tenant_invitations inv
JOIN roles r ON r.id = inv.role_id AND r.scope = inv.role_scope
LEFT JOIN identities ii ON ii.id = inv.invited_by_identity_id
WHERE inv.tenant_id = sqlc.arg(tenant_id)
  AND (sqlc.narg(status)::text IS NULL OR
       (CASE WHEN inv.status = 'pending' AND inv.expires_at <= sqlc.arg(now)::timestamptz THEN 'expired'
             ELSE inv.status END) = sqlc.narg(status)::text)
  AND (inv.created_at, inv.id) < (sqlc.arg(before_created_at)::timestamptz, sqlc.arg(before_id)::uuid)
ORDER BY inv.created_at DESC, inv.id DESC
LIMIT sqlc.arg(page_limit);

-- name: RevokeInvitation :one
UPDATE tenant_invitations SET status = 'revoked', updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND status = 'pending'
RETURNING *;

-- name: ReissueInvitation :one
-- Gửi lại: token mới (link cũ mất hiệu lực) + hạn mới; lời mời đã hết hạn trở lại pending (partial UNIQUE của 0009 từ
-- chối nếu email đã có lời mời pending khác).
UPDATE tenant_invitations
SET token_hash = sqlc.arg(token_hash), expires_at = sqlc.arg(expires_at), status = 'pending',
    updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND status IN ('pending', 'expired')
RETURNING *;

-- name: ExpireInvitation :exec
UPDATE tenant_invitations SET status = 'expired', updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND status = 'pending';

-- name: AcceptInvitation :one
-- pending → accepted, đúng một lần; FK (accepted_identity_id, idp_id) → identities(id, idp_id): identity của IdP khác
-- (kể cả IdP khác của chính tenant) bị DB từ chối.
UPDATE tenant_invitations
SET status = 'accepted', accepted_identity_id = sqlc.arg(identity_id), accepted_at = sqlc.arg(now)::timestamptz,
    updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND status = 'pending'
RETURNING *;

-- name: InsertInvitedMembership :one
-- Membership tạo từ lời mời: role của lời mời, invited_by = người mời (NULL = hệ thống — lời mời Owner của bước
-- tenant.configure, §11.3). FK ghép (tenant_id, identity_id) → identities(tenant_id, id) như mọi membership.
INSERT INTO tenant_memberships (tenant_id, identity_id, role_id, invited_by)
VALUES (sqlc.arg(tenant_id), sqlc.arg(identity_id), sqlc.arg(role_id), sqlc.narg(invited_by))
RETURNING *;

-- name: InsertInvitationNotice :one
-- Outbox (P3-T05b gửi): người nhận là địa chỉ email của lời mời (chưa có membership); payload không chứa secret.
INSERT INTO notification_outbox (tenant_id, recipient_email, kind, payload)
VALUES (sqlc.arg(tenant_id), sqlc.arg(recipient_email), sqlc.arg(kind), sqlc.arg(payload))
RETURNING id;

-- name: InsertFirstLoginIdentity :exec
-- Pool platform (module identity, P3-T05a): lần đăng nhập đầu của identity tenant tạo hàng (idp_id, sub) TRƯỚC khi gắn
-- lời mời (FK của membership và lời mời) — không đặt last_login_at: chỉ lần đăng nhập hoàn tất (UpsertLoginIdentity,
-- cùng transaction với session) mới đặt. Đã có hàng ⇒ không ghi.
INSERT INTO identities (idp_id, tenant_id, scope, subject, email, email_verified, display_name, updated_at)
VALUES (sqlc.arg(idp_id), sqlc.narg(tenant_id), sqlc.arg(scope), sqlc.arg(subject), sqlc.narg(email),
        sqlc.arg(email_verified), sqlc.narg(display_name), sqlc.arg(now)::timestamptz)
ON CONFLICT (idp_id, subject) DO NOTHING;
