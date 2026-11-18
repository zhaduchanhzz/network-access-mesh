-- Deprovision tenant (P3-T09, §11.4 hàng Deprovision): truy vấn của job tenant.deprovision (worker) và của job định kỳ
-- tenant.keys_destroy (crypto-shredding sau grace period). Mỗi truy vấn chạy được lại (job idempotent theo bước).

-- name: GetLiveInstanceOfTenant :one
-- Instance chưa removed của tenant (tối đa một — tenant_instances_one_live_per_tenant). Pool platform.
SELECT id, tenant_id, host_id, status, api_key_secret_ref
FROM tenant_instances
WHERE tenant_id = sqlc.arg(tenant_id) AND status <> 'removed';

-- name: GetDeprovisionInstance :one
-- Instance của job (id ghi trong input lúc yêu cầu), kèm slug của tenant — mọi trạng thái, removed cũng thấy.
SELECT ti.id, ti.tenant_id, ti.status, ti.api_key_secret_ref, t.slug
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.id = sqlc.arg(id) AND ti.tenant_id = sqlc.arg(tenant_id);

-- name: GetSucceededBackupOfJob :one
-- Bản backup cuối mà chính job này đã ghi sổ (worker chết sau khi backup xong, trước khi bước ghi succeeded): lần chạy
-- lại dùng đúng bản đó thay vì lấy bản mới. Pool tenant.
SELECT id, sequence, expires_at, manifest_sha256, sha256, method
FROM backups
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND instance_id = sqlc.arg(instance_id)::uuid AND job_id = sqlc.arg(job_id)::uuid
  AND kind = 'instance' AND status = 'succeeded' AND sequence IS NOT NULL
ORDER BY sequence DESC
LIMIT 1;

-- name: RevokeTenantSessions :execrows
-- Bước access.revoke: mọi session Portal chưa thu hồi của identity thuộc tenant (đúng hai cột như đăng xuất — hint đăng
-- xuất bị xóa). Pool platform (sessions không có RLS; identities T+P).
UPDATE sessions SET revoked_at = sqlc.arg(now)::timestamptz, id_token_hint_enc = NULL
WHERE revoked_at IS NULL
  AND identity_id IN (SELECT i.id FROM identities i WHERE i.tenant_id = sqlc.arg(tenant_id)::uuid);

-- name: CountLiveTenantSessions :one
-- Đọc lại sau khi thu hồi: session chưa thu hồi của identity thuộc tenant (phải là 0).
SELECT count(*)::bigint AS sessions
FROM sessions s
JOIN identities i ON i.id = s.identity_id
WHERE i.tenant_id = sqlc.arg(tenant_id)::uuid AND s.revoked_at IS NULL;

-- name: DeleteTenantAuthRequests :execrows
-- Lần đăng nhập đang dở của tenant (auth_requests chưa dùng): không bao giờ hoàn tất được nữa. Pool platform.
DELETE FROM auth_requests WHERE tenant_id = sqlc.arg(tenant_id)::uuid;

-- name: RevokeTenantPendingInvitations :execrows
-- Mọi lời mời còn pending của tenant ⇒ revoked. Pool tenant (tenant_invitations là bảng T).
UPDATE tenant_invitations SET status = 'revoked', updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND status = 'pending';

-- name: ExpireTenantApprovals :execrows
-- Yêu cầu dual control còn mở (pending/approved chưa thực thi) liên quan tới tenant: phạm vi tenant của nó, và phạm vi
-- platform đặt trên chính tenant hoặc trên instance của nó (restore, release…) — trừ yêu cầu deprovision đã thực thi
-- (executed, không thuộc tập này). Pool platform (worker chỉ UPDATE được cột status — 0009).
UPDATE approval_requests SET status = 'expired'
WHERE status IN ('pending', 'approved')
  AND (tenant_id = sqlc.arg(tenant_id)::uuid
       OR (tenant_id IS NULL AND resource_type = 'tenant' AND resource_id = sqlc.arg(tenant_id)::uuid::text)
       OR (tenant_id IS NULL AND resource_type = 'instance'
           AND resource_id IN (SELECT ti.id::text FROM tenant_instances ti WHERE ti.tenant_id = sqlc.arg(tenant_id)::uuid)));

-- name: ListTenantIdentityProviders :many
-- IdP của tenant (mọi trạng thái), cũ trước. Pool platform.
SELECT id, tenant_id, issuer, client_id, client_secret_ref, driver, driver_ref, status
FROM identity_providers
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
ORDER BY created_at, id;

-- name: DeleteTenantRelayAssignments :execrows
-- Bước relay.remove: mọi assignment của tenant, rồi (truy vấn kế) region embedded của nó. Pool platform.
DELETE FROM relay_assignments WHERE tenant_id = sqlc.arg(tenant_id);

-- name: DeleteTenantEmbeddedRelayRegions :execrows
DELETE FROM relay_regions r
WHERE r.tenant_id = sqlc.arg(tenant_id)::uuid AND r.kind = 'embedded'
  AND NOT EXISTS (SELECT 1 FROM relay_assignments a WHERE a.relay_region_id = r.id);

-- name: CountTenantRelayRows :one
SELECT (SELECT count(*) FROM relay_assignments a WHERE a.tenant_id = sqlc.arg(tenant_id)::uuid)::bigint AS assignments,
       (SELECT count(*) FROM relay_regions r WHERE r.tenant_id = sqlc.arg(tenant_id)::uuid AND r.kind = 'embedded')::bigint AS regions;

-- name: RemoveTenantInstances :execrows
-- Bước registry.delete: mọi instance chưa removed của tenant ⇒ removed (hàng giữ lại: run_uid không bao giờ cấp lại).
UPDATE tenant_instances SET status = 'removed', updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND status <> 'removed';

-- name: MarkTenantDeleted :one
-- Bước registry.delete: deprovisioning ⇒ deleted (hàng giữ lại; slug giữ chỗ — SlugHeldByDeletedTenant).
UPDATE tenants SET status = 'deleted', deleted_at = sqlc.arg(now)::timestamptz, updated_at = sqlc.arg(now)::timestamptz,
    version = version + 1
WHERE id = sqlc.arg(id) AND status = 'deprovisioning'
RETURNING *;

-- name: CancelTenantSubscriptions :execrows
-- Subscription còn hiệu lực của tenant bị xóa ⇒ cancelled (không còn tính vào kỳ thanh toán).
UPDATE subscriptions SET status = 'cancelled', updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND status IN ('trialing', 'active', 'past_due');

-- name: ScheduleTenantKeysDestruction :one
-- Bước keys.schedule: mốc hủy DEK (chỉ đặt một lần — lần chạy lại giữ mốc đã đặt).
UPDATE tenants SET keys_destroy_after = sqlc.arg(after)::timestamptz, updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND status = 'deleted' AND keys_destroy_after IS NULL
RETURNING *;

-- name: ListTenantsDueForKeyDestruction :many
-- Job tenant.keys_destroy: tenant `deleted` đã qua mốc mà còn DEK chưa hủy hoặc version secret chưa hủy. Pool platform.
SELECT t.id, t.slug, t.deleted_at, t.keys_destroy_after
FROM tenants t
WHERE t.status = 'deleted' AND t.keys_destroy_after IS NOT NULL AND t.keys_destroy_after <= sqlc.arg(now)::timestamptz
  AND (EXISTS (SELECT 1 FROM tenant_keys k WHERE k.tenant_id = t.id AND k.state <> 'destroyed')
       OR EXISTS (SELECT 1 FROM secrets s WHERE s.tenant_id = t.id AND s.destroyed_at IS NULL))
ORDER BY t.keys_destroy_after, t.id
LIMIT sqlc.arg(row_limit);

-- name: CountTenantLiveKeys :one
-- Đọc lại sau khi hủy: DEK còn vật liệu khóa và version secret còn ciphertext của tenant (phải cùng là 0).
SELECT (SELECT count(*) FROM tenant_keys k WHERE k.tenant_id = sqlc.arg(tenant_id)::uuid AND k.state <> 'destroyed')::bigint AS deks,
       (SELECT count(*) FROM secrets s WHERE s.tenant_id = sqlc.arg(tenant_id)::uuid AND s.destroyed_at IS NULL)::bigint AS secrets;
