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

-- name: ListTenantAuditEvents :many
SELECT * FROM audit_events
WHERE tenant_id = sqlc.arg(tenant_id) AND occurred_at >= sqlc.arg(since)
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg(row_limit);

-- name: AuditEventPartition :one
-- Partition chứa một sự kiện (kiểm định tuyến theo tháng — P2-T03; không lộ dữ liệu ngoài RLS của bảng cha).
SELECT tableoid::regclass::text AS partition_name
FROM audit_events
WHERE occurred_at = sqlc.arg(occurred_at) AND id = sqlc.arg(id);

-- name: InsertSecurityEvent :one
INSERT INTO security_events (tenant_id, kind, severity, source, details)
VALUES (sqlc.narg(tenant_id), sqlc.arg(kind), sqlc.arg(severity), sqlc.arg(source), sqlc.arg(details))
RETURNING *;
