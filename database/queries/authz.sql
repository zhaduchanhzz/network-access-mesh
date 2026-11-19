-- name: GetTenantAccess :one
-- internal/authz (P2-T07): session chỉ mang danh tính (§8.3 bước 8) nên mỗi request nạp lại membership, role, trạng
-- thái và grant của đúng permission được hỏi — một truy vấn, không cache. Pool tenant, WithTenantTx(tenant của path):
-- RLS giới hạn tenant_memberships, tenants, identities vào tenant đang đặt, nên identity của tenant khác (hay tenant
-- không tồn tại) không khớp hàng nào ⇒ 404 (§8.4 bất biến 6). Cột grant_* NULL khi role không có permission này.
SELECT t.status AS tenant_status,
       m.id AS membership_id, m.status AS membership_status,
       i.status AS identity_status,
       r.id AS role_id, r.key AS role_key, r.rank AS role_rank,
       rp.scope AS grant_scope, rp.condition AS grant_condition
FROM tenant_memberships m
JOIN tenants t ON t.id = m.tenant_id
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
JOIN roles r ON r.id = m.role_id AND r.scope = m.role_scope
LEFT JOIN role_permissions rp ON rp.role_id = r.id AND rp.permission_key = sqlc.arg(permission_key)
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.identity_id = sqlc.arg(identity_id);

-- name: GetPlatformAccess :one
-- Pool platform, WithPlatformTx: role platform của identity (bảng P platform_users) và grant của permission.
SELECT pu.id AS platform_user_id, pu.status AS platform_user_status,
       i.status AS identity_status,
       r.id AS role_id, r.key AS role_key, r.rank AS role_rank,
       rp.scope AS grant_scope, rp.condition AS grant_condition
FROM platform_users pu
JOIN identities i ON i.id = pu.identity_id AND i.scope = pu.identity_scope
JOIN roles r ON r.id = pu.role_id AND r.scope = pu.role_scope
LEFT JOIN role_permissions rp ON rp.role_id = r.id AND rp.permission_key = sqlc.arg(permission_key)
WHERE pu.identity_id = sqlc.arg(identity_id);

-- name: GetSupportAccess :one
-- internal/authz (P4-T13, §8.7): nhân sự nền tảng trên một route của tenant — platform user của identity, Support
-- Access Grant ĐANG HIỆU LỰC của chính người đó vào tenant của path (approved ∧ starts_at ≤ now() < expires_at — cửa sổ
-- kiểm ở đây, không chờ job grant.expire; thu hồi ⇒ status đổi ⇒ không khớp ở request kế tiếp) và grant của permission
-- trên role hiệu lực (support_operator / support_admin). Pool platform (bảng T+P support_access_grants, platform_users,
-- tenants). Nhiều grant cùng hiệu lực: grant có permission thắng, rồi grant hết hạn muộn nhất. Không có grant ⇒ không hàng.
SELECT pu.id AS platform_user_id, pu.status AS platform_user_status,
       i.status AS identity_status,
       t.status AS tenant_status,
       g.id AS grant_id,
       r.id AS role_id, r.key AS role_key, r.rank AS role_rank,
       rp.scope AS grant_scope, rp.condition AS grant_condition
FROM platform_users pu
JOIN identities i ON i.id = pu.identity_id AND i.scope = pu.identity_scope
JOIN support_access_grants g ON g.grantee_platform_user_id = pu.id AND g.tenant_id = sqlc.arg(tenant_id)
     AND g.status = 'approved' AND g.starts_at <= now() AND g.expires_at > now()
JOIN tenants t ON t.id = g.tenant_id
JOIN roles r ON r.scope = g.effective_role_scope AND r.key = g.effective_role_key
LEFT JOIN role_permissions rp ON rp.role_id = r.id AND rp.permission_key = sqlc.arg(permission_key)
WHERE pu.identity_id = sqlc.arg(identity_id)
ORDER BY (rp.scope IS NOT NULL) DESC, g.expires_at DESC, g.id
LIMIT 1;

-- name: GetRoleByScopeKey :one
SELECT * FROM roles
WHERE scope = sqlc.arg(scope) AND key = sqlc.arg(key);

-- name: LockActiveTenantOwners :many
-- Bất biến "Owner cuối cùng" (§8.4 bất biến 3): khóa mọi membership Owner đang hoạt động của tenant theo thứ tự id
-- trong transaction ghi; hai lần hạ/khóa Owner đồng thời phải chờ nhau, lần sau đọc lại tập Owner đã đổi.
SELECT id FROM tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id) AND role_id = sqlc.arg(owner_role_id) AND status = sqlc.arg(active_status)
ORDER BY id
FOR UPDATE;

-- name: LockTenantMembershipRoles :many
-- Khóa membership của người thao tác và của đích (theo thứ tự id, sau khi đã khóa tập Owner) rồi trả role hiện tại.
SELECT m.id, m.status, r.id AS role_id, r.scope AS role_scope, r.key AS role_key, r.rank AS role_rank
FROM tenant_memberships m
JOIN roles r ON r.id = m.role_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.id = ANY(sqlc.arg(ids)::uuid[])
ORDER BY m.id
FOR UPDATE OF m;

-- name: CountGrantsNotCovered :one
-- Grant của role role_id mà role giver_role_id không có (scope any phủ own; grant không điều kiện phủ grant có điều
-- kiện cùng loại): > 0 ⇒ người giữ giver_role_id không được trao role_id — không role nào trao nhiều hơn mình có.
SELECT count(*) FROM role_permissions n
WHERE n.role_id = sqlc.arg(role_id)
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions g
      WHERE g.role_id = sqlc.arg(giver_role_id) AND g.permission_key = n.permission_key
        AND (g.scope = 'any' OR n.scope = 'own')
        AND (g.condition IS NULL OR g.condition = n.condition));

-- name: ListRoleGrants :many
-- Toàn bộ danh mục RBAC (role + grant; role không có grant nào vẫn có một hàng với permission_key NULL).
SELECT r.id AS role_id, r.scope AS role_scope, r.key AS role_key, r.rank AS role_rank, r.is_system,
       rp.permission_key, rp.scope AS grant_scope, rp.condition AS grant_condition
FROM roles r
LEFT JOIN role_permissions rp ON rp.role_id = r.id
ORDER BY r.scope, r.rank DESC, r.key, rp.permission_key;
