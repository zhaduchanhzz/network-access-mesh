-- Danh mục tag của tenant (P4-T15 — §6.3 tenant_tags, §7.2 tagOwners, §13.2 "tags"; bảng của 0021). Mọi truy vấn chạy
-- trên pool tenant (bảng T); điều kiện tenant_id tường minh là lớp thứ hai sau RLS. api: CRUD (tag platform_managed bị
-- policy RESTRICTIVE của 0021 chặn ghi); worker: đọc (renderer tagOwners của policy.apply).

-- name: ListTenantTags :many
-- Thứ tự ổn định (created_at, id) tăng dần (§13.1 "Pagination").
SELECT * FROM tenant_tags
WHERE tenant_id = sqlc.arg(tenant_id)
  AND (created_at, id) > (sqlc.arg(after_created_at)::timestamptz, sqlc.arg(after_id)::uuid)
ORDER BY created_at, id
LIMIT sqlc.arg(page_limit);

-- name: GetTenantTag :one
SELECT * FROM tenant_tags
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: LockTenantTag :one
-- Sửa/xóa: khóa hàng (FOR UPDATE) — người đang kiểm danh mục bằng LockTenantTagsByName (FOR SHARE) trong transaction
-- của mình (gắn tag, phát key) chặn việc xóa cho tới khi transaction đó kết thúc.
SELECT * FROM tenant_tags
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: InsertTenantTag :one
-- Tag do tenant khai báo (platform_managed = false — tag nền tảng chỉ do nền tảng tạo; RESTRICTIVE của 0021). Trùng tên
-- ⇒ unique_violation (tenant_tags_tenant_id_name_key).
INSERT INTO tenant_tags (tenant_id, name, purpose, description)
VALUES (sqlc.arg(tenant_id), sqlc.arg(name), sqlc.arg(purpose), sqlc.narg(description))
RETURNING *;

-- name: UpdateTenantTagDescription :one
-- name/purpose/platform_managed bất biến (quyền cột của 0021); version = khóa lạc quan (ETag).
UPDATE tenant_tags
SET description = sqlc.narg(description), updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: DeleteTenantTag :execrows
DELETE FROM tenant_tags
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: ListTenantTagNames :many
-- Renderer tagOwners (§7.2: mọi tag của danh mục, owner rỗng) và L6 — theo tên, thứ tự tất định.
SELECT name FROM tenant_tags
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY name;

-- name: TenantTagsByName :many
-- Kiểm danh mục (PUT /devices/{id}/tags, requested_tags của enrollment — P4-T06): các tên CÓ trong danh mục, kể cả tag
-- platform_managed.
SELECT name FROM tenant_tags
WHERE tenant_id = sqlc.arg(tenant_id) AND name = ANY (sqlc.arg(names)::text[])
ORDER BY name;

-- name: LockTenantTagsByName :many
-- Sau TenantTagsByName, trong cùng transaction của người gọi: khóa FOR SHARE các tag đó tới hết transaction — một lần xóa
-- đồng thời (LockTenantTag, FOR UPDATE) chờ rồi thấy tham chiếu mới. Với role api, policy RESTRICTIVE UPDATE của 0021
-- cũng áp lên FOR SHARE nên tag platform_managed không được trả/khóa ở đây — api không xóa được chúng.
SELECT name FROM tenant_tags
WHERE tenant_id = sqlc.arg(tenant_id) AND name = ANY (sqlc.arg(names)::text[])
ORDER BY name
FOR SHARE;

-- name: CountDevicesWithTag :one
-- Tham chiếu chặn xóa (§6.3 — 409): thiết bị còn trong sổ (chưa removed) mang tag.
SELECT count(*)::bigint AS n FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND removed_at IS NULL AND sqlc.arg(name)::text = ANY (tags);

-- name: CountEnrollmentKeysWithTag :one
-- Tham chiếu chặn xóa: yêu cầu enrollment còn có thể phát/dùng key gắn tag — chưa phát (requested, pending_approval,
-- approved), key đã phát (credential_issued), key reusable đã dùng nhưng còn hạn. Key đã dùng một lần thì thiết bị của
-- nó là tham chiếu (CountDevicesWithTag).
SELECT count(*)::bigint AS n FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND sqlc.arg(name)::text = ANY (requested_tags)
  AND (status IN ('requested', 'pending_approval', 'approved', 'credential_issued')
       OR (status = 'consumed' AND reusable AND credential_expires_at > now()));

-- name: CountResourcesWithTag :one
-- Tham chiếu chặn xóa: tài nguyên mạng (0022) mang tag.
SELECT count(*)::bigint AS n FROM network_resources
WHERE tenant_id = sqlc.arg(tenant_id) AND sqlc.arg(name)::text = ANY (tags);

-- name: ListReferencingPolicyContents :many
-- Nội dung policy còn có thể được áp: mọi version chưa superseded/rejected, version desired (kể cả superseded — không
-- xảy ra với lõi, phòng thủ) và chuỗi đang áp dụng hiện hành của mỗi instance. Service quét tham chiếu tag trong đó
-- (ngoài tagOwners — phần render từ chính danh mục).
SELECT v.id, v.source_hujson, v.source, NULL::text AS applied_hujson
FROM policy_versions v
WHERE v.tenant_id = sqlc.arg(tenant_id)
  AND (v.state NOT IN ('superseded', 'rejected')
       OR v.id = (SELECT t.desired_policy_version_id FROM tenants t WHERE t.id = sqlc.arg(tenant_id)))
UNION ALL
SELECT a.id, NULL::text, NULL::jsonb, a.applied_hujson
FROM policy_applications a
WHERE a.tenant_id = sqlc.arg(tenant_id) AND a.state = 'applied' AND a.superseded_at IS NULL;
