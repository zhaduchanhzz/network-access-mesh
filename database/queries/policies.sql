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

-- name: InsertAdoptedPolicyVersion :one
-- P3-T17 (§17.2, đối soát sau restore PostgreSQL — khác InsertImportedPolicyVersion của restore một instance, P3-T11):
-- chuỗi policy ĐANG CHẠY trên Headscale, mới hơn bản DB vừa restore biết, nhập lại thành version kind user ở trạng thái
-- validated (lint đạt) hoặc draft (lint không đạt) — không bao giờ approved: chỉ Owner/Admin duyệt được nó (§7.3), nên
-- không job nào áp nó thay người. content_sha256 = sha256 của đúng chuỗi source_hujson (DB kiểm); parent = version
-- mong muốn trước đó.
INSERT INTO policy_versions (tenant_id, version, kind, source_hujson, content_sha256, state, validation_report,
                             parent_version_id)
VALUES (sqlc.arg(tenant_id), sqlc.arg(version), 'user', sqlc.arg(source_hujson), sqlc.arg(content_sha256),
        sqlc.arg(state), sqlc.arg(validation_report), sqlc.narg(parent_version_id))
RETURNING *;

-- name: ListActiveHeadscaleUsernames :many
-- P3-T17: những tên Headscale user `mg-<membership_uuid>` nêu trong policy đang chạy còn ánh xạ được về membership đang
-- hoạt động của tenant (tên không có ở đây ⇒ liệt kê trong báo cáo).
SELECT headscale_username FROM tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id) AND status = 'active' AND headscale_username = ANY(sqlc.arg(usernames)::text[])
ORDER BY headscale_username;

-- ---------------------------------------------------------------------------------------------------- P4-T10
-- Đầu vào của render (§7.2): đọc trong một transaction tenant (api: validate/diff; worker: policy.apply).

-- name: ListPolicyGroups :many
SELECT id, name FROM groups
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY name;

-- name: ListPolicyGroupMembers :many
-- Thành viên group được render: membership chưa offboarded (locked vẫn giữ mạng — 0024).
SELECT gm.group_id, gm.membership_id FROM group_members gm
JOIN tenant_memberships m ON m.tenant_id = gm.tenant_id AND m.id = gm.membership_id
WHERE gm.tenant_id = sqlc.arg(tenant_id) AND m.status <> 'offboarded'
ORDER BY gm.group_id, gm.membership_id;

-- name: ListPolicyMemberships :many
SELECT id, status FROM tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: ListPolicyTags :many
SELECT id, name, platform_managed FROM tenant_tags
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY name;

-- name: ListPolicyResources :many
SELECT id, name, address::text AS address FROM network_resources
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY name;

-- name: GetTenantPolicySettings :one
-- TenantSettings (§13.3) mà vòng đời policy đọc: identity_mode (L13), policy.four_eyes (duyệt peer + step-up khi apply)
-- — chỉ đọc; đường ghi là PUT /settings/security (P4-T03a) — và số thiết bị chưa removed (L8).
SELECT COALESCE(t.settings -> 'enrollment' ->> 'identity_mode', 'portal')::text AS identity_mode,
       COALESCE(jsonb_typeof(t.settings -> 'policy' -> 'four_eyes') = 'boolean'
                AND (t.settings -> 'policy' ->> 'four_eyes')::boolean, false)::boolean AS four_eyes,
       (SELECT count(*) FROM device_inventory_cache d WHERE d.tenant_id = t.id AND d.removed_at IS NULL)::bigint AS devices
FROM tenants t WHERE t.id = sqlc.arg(tenant_id);

-- name: ListPolicyVersions :many
-- GET /tenants/{t}/policies: mới nhất trước; con trỏ = số version cuối của trang trước (0 = trang đầu).
SELECT * FROM policy_versions
WHERE tenant_id = sqlc.arg(tenant_id) AND (sqlc.arg(before_version)::integer = 0 OR version < sqlc.arg(before_version)::integer)
ORDER BY version DESC
LIMIT sqlc.arg(page_limit);

-- name: LockTenantDesiredPolicy :one
-- Khóa hàng tenant trong transaction đặt version mong muốn (stale base — §7.3): hai lần apply đồng thời nối tiếp nhau.
SELECT desired_policy_version_id FROM tenants
WHERE id = sqlc.arg(tenant_id)
FOR UPDATE;

-- name: LockPolicyVersion :one
SELECT * FROM policy_versions
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: InsertTypedPolicyVersion :one
-- Version kind user có nội dung kiểu (source — §13.3): bản nháp (state draft) hoặc bản rollback kế thừa phê duyệt
-- (state approved, các trường duyệt chép từ version đã duyệt cùng nội dung — §7.3).
INSERT INTO policy_versions (tenant_id, version, kind, source, content_sha256, state, parent_version_id, rollback_of,
                             created_by, submitted_by, submitted_at, approved_by, approved_at, approved_content_sha256,
                             review_mode, validation_report)
VALUES (sqlc.arg(tenant_id), sqlc.arg(version), 'user', sqlc.arg(source), sqlc.arg(content_sha256), sqlc.arg(state),
        sqlc.narg(parent_version_id), sqlc.narg(rollback_of), sqlc.narg(created_by), sqlc.narg(submitted_by),
        sqlc.narg(submitted_at), sqlc.narg(approved_by), sqlc.narg(approved_at), sqlc.narg(approved_content_sha256),
        sqlc.narg(review_mode), sqlc.narg(validation_report))
RETURNING *;

-- name: UpdatePolicyVersionSource :one
-- PATCH (§6.3): mọi sửa đổi đưa version về draft và xóa phê duyệt, báo cáo lint; revision tăng (ETag).
UPDATE policy_versions
SET source = sqlc.arg(source), content_sha256 = sqlc.arg(content_sha256), state = 'draft', validation_report = NULL,
    submitted_by = NULL, submitted_at = NULL, approved_by = NULL, approved_at = NULL, approved_content_sha256 = NULL,
    review_mode = NULL, revision = revision + 1, updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revision = sqlc.arg(revision)
RETURNING *;

-- name: SetPolicyVersionValidation :one
-- validate: draft|validated → validated (lint + render + CheckPolicy đạt) hoặc draft (báo cáo có lỗi).
UPDATE policy_versions
SET state = sqlc.arg(state), validation_report = sqlc.arg(validation_report), revision = revision + 1, updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revision = sqlc.arg(revision)
  AND state IN ('draft', 'validated')
RETURNING *;

-- name: SubmitPolicyVersion :one
UPDATE policy_versions
SET state = 'pending_approval', submitted_by = sqlc.arg(submitted_by), submitted_at = now(), revision = revision + 1,
    updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revision = sqlc.arg(revision) AND state = 'validated'
RETURNING *;

-- name: ApprovePolicyVersion :one
-- approved_content_sha256 = content_sha256 (CHECK của 0013) — người duyệt đã xác nhận đúng nội dung này.
UPDATE policy_versions
SET state = 'approved', approved_by = sqlc.arg(approved_by), approved_at = now(), approved_content_sha256 = content_sha256,
    review_mode = sqlc.arg(review_mode), revision = revision + 1, updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revision = sqlc.arg(revision)
  AND state IN ('validated', 'pending_approval')
RETURNING *;

-- name: RejectPolicyVersion :one
UPDATE policy_versions
SET state = 'rejected', rejected_by = sqlc.arg(rejected_by), rejected_at = now(), rejected_reason = sqlc.arg(rejected_reason),
    revision = revision + 1, updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revision = sqlc.arg(revision) AND state = 'pending_approval'
RETURNING *;

-- name: SupersedePolicyVersion :exec
-- Version mong muốn cũ khi version khác trở thành desired (§7.3 approved → superseded).
UPDATE policy_versions
SET state = 'superseded', revision = revision + 1, updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND state IN ('approved', 'validated');

-- name: LatestApprovalOfContent :one
-- Rollback (§7.3): phê duyệt chỉ được kế thừa khi nội dung trùng một nội dung đã từng được duyệt.
SELECT * FROM policy_versions
WHERE tenant_id = sqlc.arg(tenant_id) AND kind = 'user' AND approved_content_sha256 = sqlc.arg(content_sha256)
  AND approved_by IS NOT NULL AND review_mode IS NOT NULL
ORDER BY approved_at DESC, version DESC
LIMIT 1;

-- name: GetLatestPolicyApplication :one
SELECT * FROM policy_applications
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: GetMembershipRoleKey :one
-- Role của người duyệt (L4/L12 cần Tenant Owner — §7.2).
SELECT r.key FROM tenant_memberships m
JOIN roles r ON r.id = m.role_id AND r.scope = m.role_scope
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.identity_id = sqlc.arg(identity_id) AND m.status = 'active';

-- name: ListPolicyDriftTargets :many
-- policy.drift_check theo lịch (§13.5): instance running của tenant active/suspended có version mong muốn (pool platform).
SELECT i.id AS instance_id, i.tenant_id FROM tenant_instances i
JOIN tenants t ON t.id = i.tenant_id
WHERE i.status = 'running' AND t.status IN ('active', 'suspended') AND t.desired_policy_version_id IS NOT NULL
ORDER BY i.id;
