-- Truy vấn của lõi policy (P3-T08a — §7.2, §7.3; bảng của 0013): version từ HuJSON thô (policy_versions.source_hujson)
-- và các lần áp dụng (policy_applications). Mọi truy vấn chạy trên pool tenant (bảng T) trong khóa advisory theo tenant
-- (store.WithTenantLock); điều kiện tenant_id tường minh là lớp thứ hai sau RLS.

-- name: GetTenantPolicyState :one
-- Version mong muốn hiện tại của tenant (NULL khi chưa có).
SELECT desired_policy_version_id FROM tenants
WHERE id = sqlc.arg(tenant_id);

-- name: GetPolicyVersion :one
SELECT * FROM policy_versions
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: LatestHuJSONPolicyVersion :one
-- Version HuJSON gần nhất của một kind có đúng nội dung này và đã được duyệt (dùng lại khi áp lại đúng nội dung).
SELECT * FROM policy_versions
WHERE tenant_id = sqlc.arg(tenant_id) AND kind = sqlc.arg(kind) AND content_sha256 = sqlc.arg(content_sha256)
  AND source_hujson IS NOT NULL AND state IN ('approved', 'superseded')
ORDER BY version DESC
LIMIT 1;

-- name: NextPolicyVersionNumber :one
SELECT (COALESCE(MAX(version), 0) + 1)::integer AS next_version FROM policy_versions
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: InsertHuJSONPolicyVersion :one
-- Version do nền tảng phát hành (baseline/suspension/fixture — kind baseline|suspension): hệ thống duyệt ngay
-- (approved_by NULL, review_mode NULL — CHECK của 0013 chỉ đòi người duyệt với kind user). content_sha256 = sha256 của
-- đúng chuỗi source_hujson (DB kiểm).
INSERT INTO policy_versions (tenant_id, version, kind, source_hujson, content_sha256, state, validation_report,
                             parent_version_id, approved_at, approved_content_sha256)
VALUES (sqlc.arg(tenant_id), sqlc.arg(version), sqlc.arg(kind), sqlc.arg(source_hujson), sqlc.arg(content_sha256),
        'approved', sqlc.arg(validation_report), sqlc.narg(parent_version_id), now(), sqlc.arg(content_sha256))
RETURNING *;

-- name: SetPolicyVersionState :exec
-- approved ↔ superseded của version do nền tảng phát hành (khi version khác trở thành / thôi là desired).
UPDATE policy_versions
SET state = sqlc.arg(state), revision = revision + 1, updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND state IN ('approved', 'superseded');

-- name: SetTenantDesiredPolicy :exec
-- Role tenant chỉ có UPDATE (desired_policy_version_id) trên tenants (0013); FK ghép chặn version của tenant khác.
UPDATE tenants SET desired_policy_version_id = sqlc.arg(version_id)
WHERE id = sqlc.arg(tenant_id);

-- name: GetCurrentPolicyApplication :one
-- Lần áp dụng hiện hành của instance (partial unique policy_applications_current_key).
SELECT * FROM policy_applications
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id)
  AND state = 'applied' AND superseded_at IS NULL;

-- name: InsertPolicyApplication :one
INSERT INTO policy_applications (tenant_id, instance_id, policy_version_id, trigger, inputs_sha256, applied_hujson,
                                 applied_sha256, state, requested_by_identity_id)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id), sqlc.arg(policy_version_id), sqlc.arg(trigger),
        sqlc.arg(inputs_sha256), sqlc.arg(applied_hujson), sqlc.arg(applied_sha256), 'pending',
        sqlc.narg(requested_by_identity_id))
RETURNING *;

-- name: MarkPolicyApplicationUnknown :exec
-- Phản hồi của SetPolicy không phải 2xx / timeout (§7.3): chưa biết Headscale đã nhận chưa.
UPDATE policy_applications SET state = 'unknown'
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND state = 'pending';

-- name: SupersedeCurrentPolicyApplication :execrows
-- Áp thành công lần mới: hàng hiện hành cũ của instance được đặt superseded_at TRƯỚC khi hàng mới thành applied (cùng
-- transaction — 0013).
UPDATE policy_applications SET superseded_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND state = 'applied'
  AND superseded_at IS NULL AND id <> sqlc.arg(keep_id);

-- name: FinishPolicyApplication :one
-- applied (đọc lại khớp sha256) hoặc failed (error_code) — chỉ từ pending/unknown.
UPDATE policy_applications
SET state = sqlc.arg(state), finished_at = now(), error_code = sqlc.narg(error_code),
    headscale_updated_at = sqlc.narg(headscale_updated_at)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND state IN ('pending', 'unknown')
RETURNING *;

-- name: ListPolicyApplications :many
-- Lịch sử áp dụng của tenant, mới nhất trước (lệnh nội bộ, test; API đọc là P4-T10).
SELECT * FROM policy_applications
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(row_limit);
