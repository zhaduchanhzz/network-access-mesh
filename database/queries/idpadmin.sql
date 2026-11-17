-- P3-T15 — kiểm soát quản trị IdP (§8.2 "không là cửa sau vào tenant"). Không migration mới: bảng và quyền của 0002
-- (identity_providers, identities), 0004 (audit_events, security_events), 0001 (system_settings), 0009
-- (approval_requests, notification_outbox) đủ.
--
-- Job idp.audit_sync (worker): mỗi sự kiện Keycloak được nhập đúng một lần — một hàng audit_events (tenant của realm,
-- hoặc platform cho realm platform/master) có occurred_at = thời điểm của sự kiện và details.idp_event_id = id của nó;
-- kiểm tồn tại + ghi trong CÙNG transaction, tuần tự hóa bằng khóa advisory theo id sự kiện (job định kỳ và lệnh
-- `admin idp-audit-sync` có thể chạy chồng nhau). Con trỏ đọc (thời điểm + id) nằm ở system_settings (pool platform) —
-- chỉ để đỡ đọc lại; trùng lặp đã được chặn ở audit_events.

-- name: ListKeycloakIdentityProviders :many
-- Pool platform (bảng T+P): mọi IdP do nền tảng host (driver keycloak), kể cả đã retiring/disabled — sự kiện quản trị
-- trên realm của chúng vẫn phải tới audit của tenant.
SELECT id, scope, tenant_id, issuer, status FROM identity_providers
WHERE driver = 'keycloak'
ORDER BY created_at, id;

-- name: LockIdPEvent :exec
-- Tuần tự hóa việc nhập một sự kiện Keycloak (khóa advisory phạm vi transaction, nhả khi commit/rollback).
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(lock_key)::text, 0));

-- name: TenantIdPEventImported :one
-- Pool tenant: sự kiện đã có hàng audit của tenant chưa. occurred_at bằng đúng thời điểm của sự kiện ⇒ chạm đúng một
-- partition và index (tenant_id, occurred_at …) của 0004.
SELECT EXISTS (
    SELECT 1 FROM audit_events
    WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND occurred_at = sqlc.arg(occurred_at)::timestamptz
      AND action LIKE 'idp.%' AND details ->> 'idp_event_id' = sqlc.arg(event_id)::text
)::bool AS imported;

-- name: PlatformIdPEventImported :one
-- Pool platform: như trên cho sự kiện platform (realm platform, realm master — tenant_id NULL).
SELECT EXISTS (
    SELECT 1 FROM audit_events
    WHERE tenant_id IS NULL AND occurred_at = sqlc.arg(occurred_at)::timestamptz
      AND action LIKE 'idp.%' AND details ->> 'idp_event_id' = sqlc.arg(event_id)::text
)::bool AS imported;

-- name: ListIdPConsoleGrants :many
-- Pool platform (api — cổng console, GET /internal/edge/idp-console): phê duyệt đã thực thi của một người cho phiên
-- console Keycloak, quyết định từ `since` (cửa sổ dài nhất), mới nhất trước. Payload (identity_id, source_cidr,
-- duration_minutes) được giải mã và kiểm lại ở internal/idp/console.
SELECT id, payload, decided_at, approved_by_identity_id
FROM approval_requests
WHERE scope = 'platform' AND tenant_id IS NULL AND action = sqlc.arg(action) AND status = 'executed'
  AND requested_by_identity_id = sqlc.arg(identity_id) AND decided_at >= sqlc.arg(since)::timestamptz
ORDER BY decided_at DESC, id DESC
LIMIT 20;
