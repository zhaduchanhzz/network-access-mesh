-- name: InsertAuditEvent :one
-- Pool tenant: tenant_id phải = app.tenant_id; pool platform: tenant_id phải NULL (sự kiện platform).
INSERT INTO audit_events (occurred_at, tenant_id, actor_type, actor_identity_id, support_grant_id, actor_ip, action,
                          resource_type, resource_id, request_id, operation_id, target_tenant_id, actor_display,
                          outcome, details)
VALUES (COALESCE(sqlc.narg(occurred_at)::timestamptz, now()), sqlc.narg(tenant_id), sqlc.arg(actor_type),
        sqlc.narg(actor_identity_id), sqlc.narg(support_grant_id), sqlc.narg(actor_ip), sqlc.arg(action),
        sqlc.arg(resource_type), sqlc.narg(resource_id), sqlc.narg(request_id), sqlc.narg(operation_id),
        sqlc.narg(target_tenant_id), sqlc.narg(actor_display), sqlc.arg(outcome), sqlc.arg(details))
RETURNING id, occurred_at;

-- name: AppendAuditEvent :exec
-- Mọi đường ghi của internal/audit (P2-T08): id do ứng dụng sinh (UUIDv7), không RETURNING — role của đường detached
-- (mg_audit_writer) chỉ có INSERT, không đọc lại được. Pool tenant/platform: RLS như InsertAuditEvent.
INSERT INTO audit_events (id, occurred_at, tenant_id, actor_type, actor_identity_id, support_grant_id, actor_ip, action,
                          resource_type, resource_id, request_id, operation_id, target_tenant_id, actor_display,
                          outcome, details)
VALUES (sqlc.arg(id), COALESCE(sqlc.narg(occurred_at)::timestamptz, now()), sqlc.narg(tenant_id), sqlc.arg(actor_type),
        sqlc.narg(actor_identity_id), sqlc.narg(support_grant_id), sqlc.narg(actor_ip), sqlc.arg(action),
        sqlc.arg(resource_type), sqlc.narg(resource_id), sqlc.narg(request_id), sqlc.narg(operation_id),
        sqlc.narg(target_tenant_id), sqlc.narg(actor_display), sqlc.arg(outcome), sqlc.arg(details));

-- name: ListTenantAuditEvents :many
-- GET /tenants/{tenantId}/audit (P2-T08): sự kiện của một tenant, mới nhất trước, trang theo cursor (occurred_at, id)
-- (§13.1). Lớp 1: điều kiện tenant_id tường minh; lớp 2: RLS của pool tenant (chỉ tenant đang đặt). Không có giới hạn
-- thời gian thì ứng dụng truyền biên rất xa (from/to/before luôn có giá trị — giữ được partition pruning và index).
SELECT * FROM audit_events
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND occurred_at >= sqlc.arg(from_at)::timestamptz AND occurred_at < sqlc.arg(to_at)::timestamptz
  AND (occurred_at, id) < (sqlc.arg(before_at)::timestamptz, sqlc.arg(before_id)::uuid)
  AND (sqlc.narg(actor)::uuid IS NULL OR actor_identity_id = sqlc.narg(actor)::uuid)
  AND (sqlc.narg(actor_type)::text IS NULL OR actor_type = sqlc.narg(actor_type)::text)
  AND (sqlc.narg(action)::text IS NULL OR action = sqlc.narg(action)::text)
  AND (sqlc.narg(outcome)::text IS NULL OR outcome = sqlc.narg(outcome)::text)
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg(row_limit);

-- name: ListPlatformAuditEvents :many
-- GET /platform/audit (P2-T08): chỉ sự kiện platform (tenant_id NULL — §6.3 "P (sự kiện platform)", §8.5), cùng thứ
-- tự và bộ lọc như ListTenantAuditEvents; RLS của pool platform cũng chỉ để lộ hàng tenant_id NULL.
SELECT * FROM audit_events
WHERE tenant_id IS NULL
  AND occurred_at >= sqlc.arg(from_at)::timestamptz AND occurred_at < sqlc.arg(to_at)::timestamptz
  AND (occurred_at, id) < (sqlc.arg(before_at)::timestamptz, sqlc.arg(before_id)::uuid)
  AND (sqlc.narg(actor)::uuid IS NULL OR actor_identity_id = sqlc.narg(actor)::uuid)
  AND (sqlc.narg(actor_type)::text IS NULL OR actor_type = sqlc.narg(actor_type)::text)
  AND (sqlc.narg(action)::text IS NULL OR action = sqlc.narg(action)::text)
  AND (sqlc.narg(outcome)::text IS NULL OR outcome = sqlc.narg(outcome)::text)
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg(row_limit);

-- name: AuditEventPartition :one
-- Partition chứa một sự kiện (kiểm định tuyến theo tháng — P2-T03; không lộ dữ liệu ngoài RLS của bảng cha).
SELECT tableoid::regclass::text AS partition_name
FROM audit_events
WHERE occurred_at = sqlc.arg(occurred_at) AND id = sqlc.arg(id);

-- name: CountCrossTenantDenials :one
-- Quy tắc chuỗi từ chối chéo tenant (§8.8, P2-T08): số lần một actor bị từ chối trên một tenant khác tenant của nó trong
-- cửa sổ window_seconds (đồng hồ DB) và số tenant đích khác nhau. Chạy trong phạm vi của chính actor: pool tenant với
-- tenant của actor, hoặc pool platform khi actor là nhân sự nền tảng (tenant_id NULL).
SELECT count(*) AS denials, count(DISTINCT target_tenant_id) AS targets
FROM audit_events
WHERE tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid
  AND actor_identity_id = sqlc.arg(actor_identity_id)::uuid
  AND outcome = 'denied'
  AND target_tenant_id IS NOT NULL AND target_tenant_id IS DISTINCT FROM tenant_id
  AND occurred_at >= now() - make_interval(secs => sqlc.arg(window_seconds)::float8);

-- name: OperationState :one
-- Trạng thái một cặp sự kiện (P2-T08): *.requested đã commit chưa, đã có *.succeeded/*.failed chưa (trong phạm vi RLS).
SELECT EXISTS (SELECT 1 FROM audit_events r WHERE r.operation_id = sqlc.arg(operation_id)::uuid
                 AND r.action LIKE '%.requested')::bool AS requested,
       EXISTS (SELECT 1 FROM audit_events f WHERE f.operation_id = sqlc.arg(operation_id)::uuid
                 AND (f.action LIKE '%.succeeded' OR f.action LIKE '%.failed'))::bool AS finished;

-- name: ListOpenOperations :many
-- *.requested chưa có sự kiện kết quả, cũ hơn older_than_seconds — tiến trình chết giữa chừng (§6.1), đầu vào của
-- reconcile. Phạm vi: tenant_id tường minh (NULL = platform) + RLS.
SELECT * FROM audit_events r
WHERE r.tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid
  AND r.operation_id IS NOT NULL AND r.action LIKE '%.requested'
  AND r.occurred_at < now() - make_interval(secs => sqlc.arg(older_than_seconds)::float8)
  AND NOT EXISTS (SELECT 1 FROM audit_events f WHERE f.operation_id = r.operation_id
                    AND (f.action LIKE '%.succeeded' OR f.action LIKE '%.failed'))
ORDER BY r.occurred_at, r.id
LIMIT sqlc.arg(row_limit);

-- name: InsertSecurityEvent :one
INSERT INTO security_events (tenant_id, kind, severity, source, details)
VALUES (sqlc.narg(tenant_id), sqlc.arg(kind), sqlc.arg(severity), sqlc.arg(source), sqlc.arg(details))
RETURNING *;

-- name: LockSecurityEventKey :exec
-- Tuần tự hóa việc chống trùng một security event theo khóa (khóa advisory phạm vi transaction, nhả khi commit/rollback).
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(dedupe_key)::text, 0));

-- name: SecurityEventExists :one
-- Đã có security event cùng kind và cùng dedupe_key (trong details) trong window_seconds gần nhất chưa.
SELECT EXISTS (
    SELECT 1 FROM security_events
    WHERE tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid AND kind = sqlc.arg(kind)
      AND details ->> 'dedupe_key' = sqlc.arg(dedupe_key)::text
      AND occurred_at >= now() - make_interval(secs => sqlc.arg(window_seconds)::float8)
)::bool AS found;

-- name: ListAuditActorIdentities :many
-- G4b-E13: tên hiển thị và e-mail HIỆN TẠI của các danh tính là actor trên một trang audit — chỉ danh tính thuộc phạm
-- vi của list (tenant_id của tenant; NULL = nhân sự nền tảng ở GET /platform/audit). Điều kiện tường minh + RLS của pool
-- (danh tính nền tảng trong audit của tenant — support — không đọc được ở pool tenant: giữ ảnh chụp lúc ghi).
SELECT id, COALESCE(display_name, '')::text AS display_name, COALESCE(email::text, '')::text AS email
FROM identities
WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid;
