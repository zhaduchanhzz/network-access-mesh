-- name: GetActiveDEK :one
-- SecretStore (P2-T04): chỉ module secrets dùng các truy vấn của file này (§6.3) — theo tenant trong WithTenantTx,
-- platform/platform_ops và job toàn cục (rewrap, quét hết hạn, probe) trong WithPlatformTx.
-- DEK hiện hành của một phạm vi (tenant: tenant_id = $tenant; platform/platform_ops: tenant_id NULL).
SELECT * FROM tenant_keys
WHERE scope = sqlc.arg(scope) AND tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid AND state = 'active';

-- name: GetLatestDEK :one
-- Phiên bản DEK lớn nhất của phạm vi (kể cả đã retired/destroyed): tính version kế tiếp, nhận ra tenant đã bị hủy khóa.
SELECT * FROM tenant_keys
WHERE scope = sqlc.arg(scope) AND tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid
ORDER BY version DESC
LIMIT 1;

-- name: GetDEK :one
SELECT * FROM tenant_keys
WHERE id = sqlc.arg(id);

-- name: InsertDEK :one
-- Không có hàng trả về (pgx.ErrNoRows) ⇒ một transaction khác vừa tạo DEK cùng phạm vi/version: đọc lại GetActiveDEK.
INSERT INTO tenant_keys (scope, tenant_id, version, wrapped_dek, wrap_nonce, kek_id)
VALUES (sqlc.arg(scope), sqlc.narg(tenant_id), sqlc.arg(version), sqlc.arg(wrapped_dek), sqlc.arg(wrap_nonce),
        sqlc.arg(kek_id))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: LockActiveDEK :one
-- Xoay DEK (worker): khóa DEK hiện hành. FOR UPDATE cần quyền UPDATE — role api không có (0003).
SELECT * FROM tenant_keys
WHERE scope = sqlc.arg(scope) AND tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid AND state = 'active'
FOR UPDATE;

-- name: RetireDEK :execrows
UPDATE tenant_keys
SET state = 'retired'
WHERE id = sqlc.arg(id) AND state = 'active';

-- name: ListDEKsToRewrap :many
-- Xoay KEK (worker, pool platform): DEK còn vật liệu khóa của các scope thuộc một keyring mà chưa bọc bằng KEK hiện hành.
SELECT * FROM tenant_keys
WHERE scope = ANY (sqlc.arg(scopes)::text[]) AND state <> 'destroyed' AND kek_id <> sqlc.arg(active_kek_id)
ORDER BY id
LIMIT sqlc.arg(row_limit)
FOR UPDATE;

-- name: RewrapDEK :execrows
UPDATE tenant_keys
SET wrapped_dek = sqlc.arg(wrapped_dek), wrap_nonce = sqlc.arg(wrap_nonce), kek_id = sqlc.arg(new_kek_id)
WHERE id = sqlc.arg(id) AND kek_id = sqlc.arg(old_kek_id) AND state <> 'destroyed';

-- name: DestroyTenantDEKs :execrows
-- Crypto-shredding khi xóa tenant (§6.1, §11.4): xóa vật liệu khóa của mọi DEK của tenant.
UPDATE tenant_keys
SET wrapped_dek = NULL, wrap_nonce = NULL, state = 'destroyed', destroyed_at = now()
WHERE scope = 'tenant' AND tenant_id = sqlc.arg(tenant_id) AND state <> 'destroyed';

-- name: CountDEKsByKEK :many
-- Số DEK còn vật liệu khóa theo (scope, kek_id): KEK cũ chỉ được gỡ khỏi keyring khi không còn DEK nào dùng nó.
SELECT scope, kek_id, count(*)::bigint AS deks
FROM tenant_keys
WHERE state <> 'destroyed'
GROUP BY scope, kek_id
ORDER BY scope, kek_id;

-- name: ListDEKProbes :many
-- Probe: một DEK cho mỗi (scope, kek_id) còn dùng — giải mã thử để biết keyring đã nạp khớp DB.
SELECT DISTINCT ON (scope, kek_id) *
FROM tenant_keys
WHERE state <> 'destroyed'
ORDER BY scope, kek_id, version DESC;

-- name: InsertSecret :one
INSERT INTO secrets (tenant_id, scope, name, version, ciphertext, nonce, aad, dek_id, expires_at)
VALUES (sqlc.narg(tenant_id), sqlc.arg(scope), sqlc.arg(name), sqlc.arg(version), sqlc.arg(ciphertext),
        sqlc.arg(nonce), sqlc.arg(aad), sqlc.arg(dek_id), sqlc.narg(expires_at))
RETURNING id;

-- name: GetTenantSecret :one
SELECT * FROM secrets
WHERE tenant_id = sqlc.arg(tenant_id) AND name = sqlc.arg(name) AND version = sqlc.arg(version);

-- name: GetPlatformSecret :one
-- tenant_id IS NULL (không dùng IS NOT DISTINCT FROM) để dùng được index UNIQUE (tenant_id, name, version).
SELECT * FROM secrets
WHERE tenant_id IS NULL AND name = sqlc.arg(name) AND version = sqlc.arg(version);

-- name: GetLatestTenantSecret :one
SELECT * FROM secrets
WHERE tenant_id = sqlc.arg(tenant_id) AND name = sqlc.arg(name)
ORDER BY version DESC
LIMIT 1;

-- name: GetLatestPlatformSecret :one
SELECT * FROM secrets
WHERE tenant_id IS NULL AND name = sqlc.arg(name)
ORDER BY version DESC
LIMIT 1;

-- name: DestroySecret :execrows
UPDATE secrets
SET ciphertext = NULL, nonce = NULL, destroyed_at = now()
WHERE id = sqlc.arg(id) AND destroyed_at IS NULL;

-- name: DestroyTenantSecrets :execrows
UPDATE secrets
SET ciphertext = NULL, nonce = NULL, destroyed_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND destroyed_at IS NULL;

-- name: DestroyExpiredSecrets :execrows
-- Job quét TTL (worker, pool platform): mọi tenant + platform (+ platform_ops với role worker).
UPDATE secrets
SET ciphertext = NULL, nonce = NULL, destroyed_at = now()
WHERE destroyed_at IS NULL AND expires_at <= now();
