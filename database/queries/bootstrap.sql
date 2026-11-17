-- P2-T11a — `meshguard admin bootstrap-super-admin` và `meshguard admin seed-membership` (§8.2 "Khởi tạo ban đầu",
-- §8.4 bất biến 1 và 3). Không migration mới: quyền INSERT đã có ở 0002 (identities, platform_users: mg_api_platform;
-- tenant_memberships: mg_api_tenant); issuer binding do FK ghép của 0002 bảo đảm, không do các truy vấn này.

-- name: LockSuperAdminAssignment :exec
-- Pool platform. Khóa advisory phạm vi transaction tuần tự hóa MỌI lần gán role Super Admin: hai lần bootstrap đồng
-- thời không cùng đếm "1 SA" rồi cùng tạo (thành 3). Lần chờ khóa đếm lại bằng snapshot mới (READ COMMITTED: mỗi câu
-- lệnh một snapshot, câu đếm chạy SAU khi có khóa). Đường gán SA qua API + 2P (P4-T03a) phải lấy cùng khóa này.
SELECT pg_advisory_xact_lock(hashtextextended('meshguard:platform_users:super_admin', 0));

-- name: CountActiveSuperAdmins :one
-- Pool platform. Super Admin "đang hoạt động" đúng như Authorizer quyết định (GetPlatformAccess + decidePlatform của
-- internal/authz): platform_users.status = 'active' và identities.status = 'active', role platform super_admin.
SELECT count(*) FROM platform_users pu
JOIN identities i ON i.id = pu.identity_id AND i.scope = pu.identity_scope
JOIN roles r ON r.id = pu.role_id AND r.scope = pu.role_scope
WHERE r.key = 'super_admin' AND pu.status = 'active' AND i.status = 'active';

-- name: InsertSeededIdentity :one
-- Pool platform. Danh tính tạo sẵn theo (IdP, sub) — lần đăng nhập đầu khớp đúng hàng này theo (idp_id, subject)
-- (UpsertLoginIdentity), không bao giờ theo email. tenant_id/scope chép từ IdP; FK ghép (idp_id, scope) và
-- (idp_id, tenant_id) từ chối giá trị lệch. Đã có hàng (đăng nhập trước đó, chạy lại) ⇒ không ghi, không trả hàng.
INSERT INTO identities (idp_id, tenant_id, scope, subject, display_name)
VALUES (sqlc.arg(idp_id), sqlc.narg(tenant_id), sqlc.arg(scope), sqlc.arg(subject), sqlc.narg(display_name))
ON CONFLICT (idp_id, subject) DO NOTHING
RETURNING *;

-- name: GetPlatformUserRole :one
-- Pool platform: hàng platform_users của identity (UNIQUE identity_id) và khóa role của nó.
SELECT pu.id, pu.status, r.key AS role_key
FROM platform_users pu
JOIN roles r ON r.id = pu.role_id AND r.scope = pu.role_scope
WHERE pu.identity_id = sqlc.arg(identity_id);

-- name: InsertPlatformUser :one
-- Pool platform. identity_scope/role_scope mặc định 'platform' + FK ghép tới identities(id, scope) và roles(id, scope):
-- identity của IdP tenant, hay role không thuộc phạm vi platform, bị DB từ chối (§8.4 bất biến 1).
INSERT INTO platform_users (identity_id, role_id)
VALUES (sqlc.arg(identity_id), sqlc.arg(role_id))
RETURNING *;

-- name: InsertSeededMembership :one
-- Pool tenant. FK ghép (tenant_id, identity_id) → identities(tenant_id, id): identity của IdP tenant khác (hay của IdP
-- platform) bị DB từ chối; role_scope 'tenant' + FK (role_id, role_scope) từ chối role platform/support. Đã có
-- membership của identity trong tenant ⇒ không ghi, không trả hàng.
INSERT INTO tenant_memberships (tenant_id, identity_id, role_id)
VALUES (sqlc.arg(tenant_id), sqlc.arg(identity_id), sqlc.arg(role_id))
ON CONFLICT (tenant_id, identity_id) DO NOTHING
RETURNING *;

-- name: GetMembershipRole :one
-- Pool tenant: membership của identity trong tenant (UNIQUE (tenant_id, identity_id)) và khóa role của nó.
SELECT m.id, m.status, r.key AS role_key
FROM tenant_memberships m
JOIN roles r ON r.id = m.role_id AND r.scope = m.role_scope
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.identity_id = sqlc.arg(identity_id);
