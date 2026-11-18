-- Module members (P4-T09, §13.2 users + groups, §8.2 vòng đời danh tính): ghi membership (khóa/mở khóa, đổi role,
-- chuyển Owner, offboard), groups + thành viên. Mọi lệnh ghi membership chạy SAU authz.GuardMembershipChange trong cùng
-- transaction pool tenant (guard khóa tập Owner rồi người thao tác + đích — §8.4 bất biến 3, 3a). Không truy vấn nào
-- nhận tenant ngoài tham số tenant_id của path (RLS + điều kiện tường minh — §8.8 lớp 3, 4).

-- name: GetMemberForChange :one
-- Pool tenant: membership đích (đã bị guard khóa trong cùng transaction) kèm role, identity và IdP của identity.
SELECT m.id, m.tenant_id, m.identity_id, m.status, m.version, m.headscale_username, m.headscale_user_id,
       r.key AS role_key, i.idp_id, i.subject
FROM tenant_memberships m
JOIN roles r ON r.id = m.role_id AND r.scope = m.role_scope
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.id = sqlc.arg(id);

-- name: RemoveMemberFromGroups :many
-- Offboard: membership rời mọi group của nó (FK group_members → tenant_memberships không ON DELETE — §6.3, 0021);
-- trả các group bị đổi để tăng version và áp lại policy (group_change).
DELETE FROM group_members
WHERE tenant_id = sqlc.arg(tenant_id) AND membership_id = sqlc.arg(membership_id)
RETURNING group_id;

-- name: BumpGroupVersions :exec
UPDATE groups SET version = version + 1, updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = ANY(sqlc.arg(ids)::uuid[]);

-- name: GetLatestResourceJob :one
-- Job mới nhất của một kind trên một tài nguyên (index provisioning_jobs_resource_idx của 0024): trạng thái hai pha của
-- offboard (pending/applied/failed) là trạng thái của job member.offboard mới nhất của membership.
SELECT id, status, created_at, finished_at, COALESCE(error ->> 'code', '')::text AS error_code
FROM provisioning_jobs
WHERE tenant_id = sqlc.arg(tenant_id) AND resource_type = sqlc.arg(resource_type)
  AND resource_id = sqlc.arg(resource_id) AND kind = sqlc.arg(kind)
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: LockIdentityByID :one
-- Pool platform: khóa identity tới hết transaction — trạng thái disabled và việc thu hồi session commit cùng nhau (một
-- lần đăng nhập đồng thời chờ rồi thấy identity disabled — như `meshguard admin revoke-sessions`).
SELECT * FROM identities WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: GetOffboardSubject :one
-- Pool worker tenant (job member.offboard): membership, identity và hàng IdP của identity (driver vô hiệu user ở IdP).
SELECT m.id, m.status, m.headscale_username, m.headscale_user_id, i.subject, i.status AS identity_status,
       p.id AS idp_id, p.scope AS idp_scope, p.tenant_id AS idp_tenant_id, p.driver, p.driver_ref, p.issuer,
       p.client_id, p.client_secret_ref
FROM tenant_memberships m
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
JOIN identity_providers p ON p.id = i.idp_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.id = sqlc.arg(id);

-- name: ListMemberDevices :many
-- Pool worker tenant: thiết bị còn sống của membership trong sổ — gồm node đã bị gắn tag sau khi đăng ký dưới tên
-- user đó (sổ giữ owner cũ khi node thành tagged — devices.normalise, V-28).
SELECT id, headscale_node_id, machine_key FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND owner_membership_id = sqlc.arg(membership_id) AND removed_at IS NULL
ORDER BY headscale_node_id;

-- name: GetInvitationForIdP :one
-- Pool worker tenant (job member.idp_invite): lời mời + hàng IdP nó ghi (tạo user ở IdP do nền tảng host).
SELECT i.id, i.email, i.status, i.expires_at, p.id AS idp_id, p.scope AS idp_scope, p.tenant_id AS idp_tenant_id,
       p.driver, p.driver_ref, p.issuer, p.client_id, p.client_secret_ref
FROM tenant_invitations i
JOIN identity_providers p ON p.id = i.idp_id
WHERE i.tenant_id = sqlc.arg(tenant_id) AND i.id = sqlc.arg(id);

-- ---------------------------------------------------------------- groups

-- name: ListGroupsPage :many
-- GET /tenants/{t}/groups: thứ tự ổn định (created_at, id) (§13.1), lọc theo tên.
SELECT sqlc.embed(g), (SELECT count(*) FROM group_members gm WHERE gm.tenant_id = g.tenant_id AND gm.group_id = g.id)::bigint AS member_count
FROM groups g
WHERE g.tenant_id = sqlc.arg(tenant_id)
  AND (sqlc.narg(pattern)::text IS NULL OR g.name ILIKE sqlc.narg(pattern)::text)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (g.created_at, g.id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY g.created_at, g.id
LIMIT sqlc.arg(row_limit);

-- name: GetGroup :one
SELECT * FROM groups WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: LockGroup :one
SELECT * FROM groups WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: InsertGroup :one
INSERT INTO groups (tenant_id, name, description)
VALUES (sqlc.arg(tenant_id), sqlc.arg(name), sqlc.narg(description))
RETURNING *;

-- name: UpdateGroup :one
-- PATCH /groups/{id}: chỉ tên và mô tả (quyền cột của 0021); version tăng (If-Match).
UPDATE groups
SET name = sqlc.arg(name), description = sqlc.narg(description), updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: BumpGroupVersion :one
UPDATE groups SET version = version + 1, updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: DeleteGroup :execrows
DELETE FROM groups WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: ListGroupMembers :many
-- Thành viên của một group kèm danh tính (thứ tự theo tên hiển thị rồi id — ổn định).
SELECT gm.membership_id, m.status, r.key AS role_key, i.display_name, i.email, i.subject
FROM group_members gm
JOIN tenant_memberships m ON m.tenant_id = gm.tenant_id AND m.id = gm.membership_id
JOIN roles r ON r.id = m.role_id AND r.scope = m.role_scope
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE gm.tenant_id = sqlc.arg(tenant_id) AND gm.group_id = sqlc.arg(group_id)
ORDER BY gm.membership_id;

-- name: ListGroupMemberIDs :many
SELECT membership_id FROM group_members
WHERE tenant_id = sqlc.arg(tenant_id) AND group_id = sqlc.arg(group_id)
ORDER BY membership_id;

-- name: DeleteGroupMembersExcept :execrows
-- PUT /groups/{id}/members: gỡ thành viên không có trong tập mới.
DELETE FROM group_members
WHERE tenant_id = sqlc.arg(tenant_id) AND group_id = sqlc.arg(group_id)
  AND NOT (membership_id = ANY(sqlc.arg(keep)::uuid[]));

-- name: InsertGroupMembers :execrows
-- PUT /groups/{id}/members: thêm thành viên mới (FK ghép: membership của tenant khác ⇒ 23503).
INSERT INTO group_members (tenant_id, group_id, membership_id)
SELECT sqlc.arg(tenant_id), sqlc.arg(group_id), x FROM unnest(sqlc.arg(ids)::uuid[]) AS x
ON CONFLICT (group_id, membership_id) DO NOTHING;

-- name: CountActiveMemberships :one
-- Thành viên mới của group phải là membership active của chính tenant (khóa FOR SHARE: không bị offboard giữa chừng).
SELECT count(*) FROM (
    SELECT id FROM tenant_memberships
    WHERE tenant_id = sqlc.arg(tenant_id) AND id = ANY(sqlc.arg(ids)::uuid[]) AND status = 'active'
    FOR SHARE
) a;

-- name: CountGroupResources :one
-- Group còn sở hữu network resource (FK của 0022 không ON DELETE) ⇒ không xóa được (409).
SELECT count(*) FROM network_resources WHERE tenant_id = sqlc.arg(tenant_id) AND owner_group_id = sqlc.arg(group_id);

-- name: GetTenantSensitiveGroups :one
-- Cờ sensitive của group (§13.3 TenantSettings.policy.sensitive_groups: mảng group_id) — không phải cột (0021).
SELECT COALESCE(settings -> 'policy' -> 'sensitive_groups', '[]'::jsonb)::jsonb AS sensitive_groups
FROM tenants WHERE id = sqlc.arg(tenant_id);
