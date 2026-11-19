-- Support Access Grant (P4-T13, §8.7; bảng 0023 + 0026). Trạng thái HIỆU LỰC tính ở đây cho mọi danh sách: grant
-- 'approved' (hoặc 'pending') đã quá expires_at là 'expired' kể cả trước khi job grant.expire ghi lại (§13.5) — quyết
-- định truy cập không bao giờ dựa vào status một mình (GetSupportAccess, SupportGrantLive kiểm cửa sổ thời gian).

-- name: GetSupportGrantTarget :one
-- Pool platform: tenant đích của một yêu cầu (registry, T+P).
SELECT id, slug, status FROM tenants WHERE id = sqlc.arg(id);

-- name: GetSupportGrantRequester :one
-- Pool platform: platform user của identity người gọi (role, trạng thái) + tên hiển thị để chụp vào grant.
SELECT pu.id, pu.status, i.status AS identity_status, r.key AS role_key,
       coalesce(nullif(i.display_name, ''), i.email::text, i.subject)::text AS display
FROM platform_users pu
JOIN identities i ON i.id = pu.identity_id
JOIN roles r ON r.id = pu.role_id
WHERE pu.identity_id = sqlc.arg(identity_id);

-- name: CountGranteeOpenSupportGrants :one
-- Grant còn mở (đang chờ hoặc đang hiệu lực, trong cửa sổ) của một grantee vào một tenant — mỗi người một grant mở.
SELECT count(*) FROM support_access_grants
WHERE grantee_platform_user_id = sqlc.arg(grantee) AND tenant_id = sqlc.arg(tenant_id)
  AND status IN ('pending', 'approved') AND expires_at > now();

-- name: InsertSupportGrant :one
-- Pool platform (quyền INSERT của 0023): grant mới luôn 'pending' (trigger); người xin = grantee; cửa sổ [now, now+n).
INSERT INTO support_access_grants (tenant_id, grantee_platform_user_id, requested_by_platform_user_id, effective_role_key,
                                   reason, ticket_ref, starts_at, expires_at, grantee_display)
VALUES (sqlc.arg(tenant_id), sqlc.arg(grantee), sqlc.arg(grantee), sqlc.arg(effective_role_key), sqlc.arg(reason),
        sqlc.arg(ticket_ref), now(), now() + make_interval(mins => sqlc.arg(duration_minutes)::int),
        sqlc.arg(grantee_display))
RETURNING id;

-- name: GetPlatformSupportGrant :one
-- Pool platform: một grant + slug tenant + tên Super Admin đã duyệt break-glass (người quyết định kiểu tenant là
-- membership — pool platform không đọc được tenant_memberships). locked = FOR UPDATE của hàng grant.
SELECT g.id, g.tenant_id, t.slug AS tenant_slug, g.grantee_platform_user_id, g.requested_by_platform_user_id,
       g.effective_role_key, g.reason, g.ticket_ref, g.approval_kind, g.decided_at, g.starts_at, g.expires_at,
       g.revoked_at, g.status, g.created_at, g.grantee_display,
       (g.status = 'approved' AND g.starts_at <= now() AND g.expires_at > now())::boolean AS active,
       (g.expires_at <= now())::boolean AS window_closed,
       coalesce(nullif(di.display_name, ''), di.email::text, di.subject, '')::text AS decided_by_display
FROM support_access_grants g
JOIN tenants t ON t.id = g.tenant_id
LEFT JOIN platform_users dp ON dp.id = g.approved_by_platform_user_id
LEFT JOIN identities di ON di.id = dp.identity_id
WHERE g.id = sqlc.arg(id);

-- name: LockPlatformSupportGrant :one
SELECT id FROM support_access_grants WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListPlatformSupportGrants :many
-- GET /platform/support-grants: mới nhất trước, cursor (created_at, id); lọc theo trạng thái hiệu lực.
SELECT g.id, g.tenant_id, t.slug AS tenant_slug, g.grantee_platform_user_id, g.requested_by_platform_user_id,
       g.effective_role_key, g.reason, g.ticket_ref, g.approval_kind, g.decided_at, g.starts_at, g.expires_at,
       g.revoked_at, g.status, g.created_at, g.grantee_display,
       (g.status = 'approved' AND g.starts_at <= now() AND g.expires_at > now())::boolean AS active,
       (g.expires_at <= now())::boolean AS window_closed,
       coalesce(nullif(di.display_name, ''), di.email::text, di.subject, '')::text AS decided_by_display
FROM support_access_grants g
JOIN tenants t ON t.id = g.tenant_id
LEFT JOIN platform_users dp ON dp.id = g.approved_by_platform_user_id
LEFT JOIN identities di ON di.id = dp.identity_id
WHERE (sqlc.narg(before_at)::timestamptz IS NULL OR (g.created_at, g.id) < (sqlc.narg(before_at)::timestamptz, sqlc.narg(before_id)::uuid))
  AND (sqlc.narg(status)::text IS NULL
       OR (sqlc.narg(status)::text = 'expired' AND (g.status = 'expired' OR (g.status IN ('pending', 'approved') AND g.expires_at <= now())))
       OR (sqlc.narg(status)::text IN ('pending', 'approved') AND g.status = sqlc.narg(status)::text AND g.expires_at > now())
       OR (sqlc.narg(status)::text IN ('rejected', 'revoked') AND g.status = sqlc.narg(status)::text))
ORDER BY g.created_at DESC, g.id DESC
LIMIT sqlc.arg(row_limit);

-- name: GetTenantSupportGrant :one
-- Pool tenant (RLS: chỉ grant vào chính tenant): một grant + slug + tên thành viên tenant đã duyệt/từ chối.
SELECT g.id, g.tenant_id, t.slug AS tenant_slug, g.grantee_platform_user_id, g.requested_by_platform_user_id,
       g.effective_role_key, g.reason, g.ticket_ref, g.approval_kind, g.decided_at, g.starts_at, g.expires_at,
       g.revoked_at, g.status, g.created_at, g.grantee_display,
       (g.status = 'approved' AND g.starts_at <= now() AND g.expires_at > now())::boolean AS active,
       (g.expires_at <= now())::boolean AS window_closed,
       coalesce(nullif(mi.display_name, ''), mi.email::text, mi.subject, '')::text AS decided_by_display
FROM support_access_grants g
JOIN tenants t ON t.id = g.tenant_id
LEFT JOIN tenant_memberships m ON m.tenant_id = g.tenant_id AND m.id = g.approved_by_membership_id
LEFT JOIN identities mi ON mi.id = m.identity_id
WHERE g.tenant_id = sqlc.arg(tenant_id) AND g.id = sqlc.arg(id);

-- name: LockTenantSupportGrant :one
SELECT id FROM support_access_grants WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListTenantSupportGrants :many
-- GET /tenants/{t}/support-grants: như ListPlatformSupportGrants, chỉ một tenant (điều kiện tường minh + RLS).
SELECT g.id, g.tenant_id, t.slug AS tenant_slug, g.grantee_platform_user_id, g.requested_by_platform_user_id,
       g.effective_role_key, g.reason, g.ticket_ref, g.approval_kind, g.decided_at, g.starts_at, g.expires_at,
       g.revoked_at, g.status, g.created_at, g.grantee_display,
       (g.status = 'approved' AND g.starts_at <= now() AND g.expires_at > now())::boolean AS active,
       (g.expires_at <= now())::boolean AS window_closed,
       coalesce(nullif(mi.display_name, ''), mi.email::text, mi.subject, '')::text AS decided_by_display
FROM support_access_grants g
JOIN tenants t ON t.id = g.tenant_id
LEFT JOIN tenant_memberships m ON m.tenant_id = g.tenant_id AND m.id = g.approved_by_membership_id
LEFT JOIN identities mi ON mi.id = m.identity_id
WHERE g.tenant_id = sqlc.arg(tenant_id)
  AND (sqlc.narg(before_at)::timestamptz IS NULL OR (g.created_at, g.id) < (sqlc.narg(before_at)::timestamptz, sqlc.narg(before_id)::uuid))
  AND (sqlc.narg(status)::text IS NULL
       OR (sqlc.narg(status)::text = 'expired' AND (g.status = 'expired' OR (g.status IN ('pending', 'approved') AND g.expires_at <= now())))
       OR (sqlc.narg(status)::text IN ('pending', 'approved') AND g.status = sqlc.narg(status)::text AND g.expires_at > now())
       OR (sqlc.narg(status)::text IN ('rejected', 'revoked') AND g.status = sqlc.narg(status)::text))
ORDER BY g.created_at DESC, g.id DESC
LIMIT sqlc.arg(row_limit);

-- name: DecideTenantSupportGrant :execrows
-- Pool tenant (quyền cột của 0023): pending → approved | rejected bởi một membership; trigger kiểm người quyết định
-- (đang hoạt động, có tenant.support_grant:decide) và cấm duyệt khi cửa sổ đã hết.
UPDATE support_access_grants
SET status = sqlc.arg(status), approval_kind = 'tenant', approved_by_membership_id = sqlc.arg(membership_id),
    decided_at = now(), updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND status = 'pending' AND expires_at > now();

-- name: ApproveSupportGrantBreakglass :execrows
-- Pool platform: pending → approved kiểu breakglass; CHECK: người duyệt ≠ người yêu cầu, ≠ grantee; trigger: cả hai là
-- Super Admin đang hoạt động.
UPDATE support_access_grants
SET status = 'approved', approval_kind = 'breakglass', approved_by_platform_user_id = sqlc.arg(approver),
    decided_at = now(), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND status = 'pending' AND expires_at > now();

-- name: RevokeTenantSupportGrant :execrows
-- Pool tenant: pending | approved → revoked (kể cả grant đã quá cửa sổ nhưng job chưa ghi expired — thu hồi vẫn đúng).
UPDATE support_access_grants
SET status = 'revoked', revoked_at = now(), updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND status IN ('pending', 'approved');

-- name: RevokePlatformSupportGrant :execrows
-- Pool platform: như RevokeTenantSupportGrant, mọi tenant.
UPDATE support_access_grants
SET status = 'revoked', revoked_at = now(), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND status IN ('pending', 'approved');

-- name: ExpireSupportGrants :many
-- Job grant.expire (pool worker platform — quyền cột status, updated_at, version của 0023): grant pending/approved đã
-- hết cửa sổ ⇒ expired, theo lô; trả về để ghi audit.
UPDATE support_access_grants
SET status = 'expired', updated_at = now(), version = version + 1
WHERE id IN (SELECT g.id FROM support_access_grants g
             WHERE g.status IN ('pending', 'approved') AND g.expires_at <= now()
             ORDER BY g.expires_at, g.id
             LIMIT sqlc.arg(batch)
             FOR UPDATE SKIP LOCKED)
RETURNING id, tenant_id, grantee_platform_user_id, effective_role_key, expires_at;

-- name: RevokeTenantSupportGrantsForDeprovision :execrows
-- tenant.deprovision bước access.revoke (P3-T09 — pool worker platform): mọi grant còn mở của tenant ⇒ revoked.
UPDATE support_access_grants
SET status = 'revoked', revoked_at = sqlc.arg(now)::timestamptz, updated_at = sqlc.arg(now)::timestamptz,
    version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND status IN ('pending', 'approved');

-- name: CountLiveTenantSupportGrants :one
SELECT count(*) FROM support_access_grants
WHERE tenant_id = sqlc.arg(tenant_id) AND status IN ('pending', 'approved');

-- name: ListSessionSupportGrants :many
-- GET /auth/session của nhân sự (pool platform): grant đang hiệu lực của chính người đó — chỉ hiển thị; quyết định truy
-- cập đọc lại ở mỗi request (GetSupportAccess).
SELECT g.id, g.tenant_id, g.effective_role_key, g.expires_at
FROM support_access_grants g
JOIN platform_users pu ON pu.id = g.grantee_platform_user_id
WHERE pu.identity_id = sqlc.arg(identity_id) AND pu.status = 'active'
  AND g.status = 'approved' AND g.starts_at <= now() AND g.expires_at > now()
ORDER BY g.expires_at DESC, g.id;
