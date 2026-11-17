-- name: CreateIdentityProvider :one
-- Pool platform.
INSERT INTO identity_providers (scope, tenant_id, issuer, client_id, client_secret_ref, required_claims, driver, status)
VALUES (sqlc.arg(scope), sqlc.narg(tenant_id), sqlc.arg(issuer), sqlc.arg(client_id), sqlc.narg(client_secret_ref),
        sqlc.arg(required_claims), sqlc.arg(driver), sqlc.arg(status))
RETURNING *;

-- name: GetIdentityProvider :one
SELECT * FROM identity_providers
WHERE id = sqlc.arg(id);

-- name: CreateIdentity :one
-- Pool platform (module identity tạo identity ở lần đăng nhập đầu — §8.2). tenant_id/scope sao chép từ IdP; FK ghép
-- (idp_id, scope) và (idp_id, tenant_id) từ chối giá trị lệch.
INSERT INTO identities (idp_id, tenant_id, scope, subject, email, email_verified, display_name)
VALUES (sqlc.arg(idp_id), sqlc.narg(tenant_id), sqlc.arg(scope), sqlc.arg(subject), sqlc.narg(email),
        sqlc.arg(email_verified), sqlc.narg(display_name))
RETURNING *;

-- name: GetIdentityBySubject :one
SELECT * FROM identities
WHERE idp_id = sqlc.arg(idp_id) AND subject = sqlc.arg(subject);

-- name: GetIdentityBySubjectForUpdate :one
-- `meshguard admin revoke-sessions` / `enable-identity` (G2 vòng 2 A-2): khóa hàng identity tới hết transaction để
-- trạng thái và việc thu hồi session commit cùng nhau (một lần đăng nhập đồng thời chờ, rồi thấy trạng thái mới).
SELECT * FROM identities
WHERE idp_id = sqlc.arg(idp_id) AND subject = sqlc.arg(subject)
FOR UPDATE;

-- name: SetIdentityStatus :execrows
-- Pool platform (quyền UPDATE (status, updated_at) của 0002). 0 hàng ⇒ identity đã ở trạng thái đó.
UPDATE identities SET status = sqlc.arg(status), updated_at = sqlc.arg(now)::timestamptz
WHERE id = sqlc.arg(id) AND status <> sqlc.arg(status);

-- name: CreateTenantMembership :one
-- Pool tenant. FK ghép (tenant_id, identity_id) → identities: identity của tenant khác bị DB từ chối.
INSERT INTO tenant_memberships (tenant_id, identity_id, role_id)
VALUES (sqlc.arg(tenant_id), sqlc.arg(identity_id), sqlc.arg(role_id))
RETURNING *;

-- name: UpdateTenantMembershipRole :one
-- Pool tenant. Chỉ chạy sau authz.GuardMembershipChange trong cùng transaction (§8.4 bất biến 3, 3a, Owner cuối
-- cùng); FK ghép (role_id, role_scope) từ chối role không thuộc phạm vi tenant.
UPDATE tenant_memberships
SET role_id = sqlc.arg(role_id), updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: UpdateTenantMembershipStatus :one
-- Pool tenant. Khóa/offboard (status rời 'active') cũng phải qua authz.GuardMembershipChange trước.
UPDATE tenant_memberships
SET status = sqlc.arg(status), updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: ListTenantMemberships :many
SELECT * FROM tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY created_at, id;

-- name: ListRolesByScope :many
SELECT * FROM roles
WHERE scope = sqlc.arg(scope)
ORDER BY key;
