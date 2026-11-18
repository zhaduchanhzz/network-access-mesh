-- Truy vấn của module notifications (P3-T05b — §4.2, §6.3 notification_outbox, §13.5 notification.send): phân giải
-- người nhận trong transaction của sự kiện, ghi outbox, job gửi, đọc hộp thông báo của chính người gọi. Thông báo của
-- tenant: pool tenant (RLS tenant); thông báo phạm vi platform (tenant_id NULL): pool platform. Điều kiện tenant_id
-- tường minh là lớp thứ hai sau RLS. Không truy vấn nào đọc hay ghi secret.

-- name: ListNotificationMembersByRole :many
-- Thành viên đang hoạt động của tenant có một trong các role (Tenant Owner, Tenant Admin…), kèm email của identity.
SELECT m.id AS membership_id, r.key AS role_key, i.email, i.email_verified
FROM tenant_memberships m
JOIN roles r ON r.id = m.role_id AND r.scope = 'tenant'
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.status = 'active' AND i.status = 'active'
  AND r.key = ANY (sqlc.arg(role_keys)::text[])
ORDER BY m.id;

-- name: ListNotificationMembersByPermission :many
-- Thành viên đang hoạt động có quyền (role_permissions, phạm vi any) — người duyệt của một yêu cầu phê duyệt (§6.3).
SELECT m.id AS membership_id, r.key AS role_key, i.email, i.email_verified
FROM tenant_memberships m
JOIN roles r ON r.id = m.role_id AND r.scope = 'tenant'
JOIN role_permissions rp ON rp.role_id = r.id AND rp.role_scope = r.scope AND rp.scope = 'any'
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.status = 'active' AND i.status = 'active'
  AND rp.permission_key = sqlc.arg(permission_key) AND rp.condition IS NULL
ORDER BY m.id;

-- name: ListNotificationMembersByID :many
-- Thành viên được chỉ định (chủ thiết bị…) — chỉ của tenant này, đang hoạt động.
SELECT m.id AS membership_id, r.key AS role_key, i.email, i.email_verified
FROM tenant_memberships m
JOIN roles r ON r.id = m.role_id AND r.scope = 'tenant'
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.status = 'active' AND i.status = 'active'
  AND m.id = ANY (sqlc.arg(ids)::uuid[])
ORDER BY m.id;

-- name: ListNotificationPlatformStaff :many
-- Pool platform: nhân sự nền tảng đang hoạt động có một trong các role platform, kèm email của identity.
SELECT p.id AS platform_user_id, r.key AS role_key, i.email, i.email_verified
FROM platform_users p
JOIN roles r ON r.id = p.role_id AND r.scope = 'platform'
JOIN identities i ON i.id = p.identity_id AND i.scope = 'platform'
WHERE p.status = 'active' AND i.status = 'active' AND r.key = ANY (sqlc.arg(role_keys)::text[])
ORDER BY p.id;

-- name: GetTenantNotificationSettings :one
-- TenantSettings.notifications (§13.3) và tên/slug cho nội dung thông báo.
SELECT slug::text AS slug, name, COALESCE(settings -> 'notifications', '{}'::jsonb)::jsonb AS notifications
FROM tenants
WHERE id = sqlc.arg(tenant_id);

-- name: LockNotificationRef :exec
-- Chống trùng theo (tenant, kind, ref): khóa advisory phạm vi transaction, nhả khi commit/rollback.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 0));

-- name: NotificationRefExists :one
-- Sự kiện đã có thông báo (payload.ref) — producer chạy lại (retry job, lặp lệnh) không tạo bản thứ hai.
SELECT EXISTS (
    SELECT 1 FROM notification_outbox
    WHERE tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid AND kind = sqlc.arg(kind)
      AND payload ->> 'ref' = sqlc.arg(ref)::text
) AS found;

-- name: InsertNotification :one
-- Một hàng mỗi người nhận. Hàng không có email (chỉ in-portal) được ghi thẳng ở trạng thái sent: bản ghi Portal là
-- kênh giao duy nhất của nó và đã có ngay khi commit.
INSERT INTO notification_outbox (tenant_id, recipient_membership_id, recipient_email, kind, payload, status, sent_at)
VALUES (sqlc.narg(tenant_id), sqlc.narg(recipient_membership_id), sqlc.narg(recipient_email), sqlc.arg(kind),
        sqlc.arg(payload), sqlc.arg(status),
        CASE WHEN sqlc.arg(status)::text = 'sent' THEN now() END)
RETURNING *;

-- name: LockNotificationForSend :one
-- notification.send: khóa hàng của lượt gửi (hai lượt cùng hàng không gửi song song).
SELECT * FROM notification_outbox
WHERE id = sqlc.arg(id) AND tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid
FOR UPDATE;

-- name: CountNotificationAttempt :exec
UPDATE notification_outbox SET attempts = attempts + 1
WHERE id = sqlc.arg(id) AND status = 'pending';

-- name: FinishNotification :execrows
-- sent (sent_at = now()), failed hoặc cancelled — chỉ từ pending (hàng đã kết thúc không đổi nữa).
UPDATE notification_outbox
SET status = sqlc.arg(status), sent_at = CASE WHEN sqlc.arg(status)::text = 'sent' THEN now() END
WHERE id = sqlc.arg(id) AND status = 'pending';

-- name: ListMyNotificationsPage :many
-- GET /tenants/{t}/notifications: chỉ thông báo gửi cho chính membership của người gọi; mới nhất trước; con trỏ =
-- phần tử cuối của trang trước (index notification_outbox_recipient_idx).
SELECT * FROM notification_outbox
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND recipient_membership_id = sqlc.arg(membership_id)::uuid
  AND (sqlc.narg(unread)::boolean IS NULL OR (read_at IS NULL) = sqlc.narg(unread)::boolean)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(row_limit);

-- name: LockTenantNotification :one
-- POST /tenants/{t}/notifications/{id}/read (P4-T04): khóa hàng của một thông báo của tenant (RLS + điều kiện tenant
-- tường minh); service kiểm người nhận là membership của chính người gọi trước khi ghi.
SELECT * FROM notification_outbox
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id = sqlc.arg(id)
FOR UPDATE;

-- name: MarkNotificationRead :one
-- Đặt read_at một lần (lũy đẳng: hàng đã đọc giữ read_at cũ) — chỉ hàng gửi cho đúng membership đó (mg_api_tenant chỉ
-- có UPDATE (read_at), 0009).
UPDATE notification_outbox SET read_at = COALESCE(read_at, now())
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND id = sqlc.arg(id)
  AND recipient_membership_id = sqlc.arg(membership_id)::uuid
RETURNING *;

-- name: DeleteOldNotifications :execrows
-- retention.sweep (§6.4: 90 ngày sau sent_at; hàng failed/cancelled — không có sent_at — 90 ngày sau created_at).
-- Pool platform (mg_worker_platform có DELETE; RLS nhánh platform thấy mọi hàng).
DELETE FROM notification_outbox
WHERE id IN (SELECT n.id FROM notification_outbox n
             WHERE n.sent_at < sqlc.arg(before)::timestamptz
                OR (n.status IN ('failed', 'cancelled') AND n.created_at < sqlc.arg(before)::timestamptz)
             ORDER BY n.created_at
             LIMIT sqlc.arg(row_limit));
