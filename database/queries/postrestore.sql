-- Đối soát sau khi restore PostgreSQL về thời điểm cũ hơn (P3-T17, §17.2): lệnh host `meshguard admin
-- post-restore-reconcile` trong container worker (role mg_worker_*). `cutoff` = đồng hồ DB lúc lệnh bắt đầu: mọi hàng
-- "còn mở" tạo trước mốc đó (tức mọi hàng có trong bản dump, và những gì tạo ra trong lúc bảo trì trước lần chạy) bị
-- đóng lại — quyền đã bị thu hồi trong khoảng mất dữ liệu không được sống lại. Mỗi phép ghi có bản đếm tương ứng cho
-- --dry-run. Cột tường minh, không SELECT *.

-- name: PostRestoreNow :one
-- Đồng hồ DB của một lần chạy (cutoff của mọi bước).
SELECT statement_timestamp()::timestamptz AS now;

-- name: CountSessionsToRevoke :one
-- Pool platform: session chưa thu hồi tạo trước cutoff — tổng và số còn hạn (idle + tuyệt đối) lúc cutoff.
SELECT count(*)::bigint AS total,
       count(*) FILTER (WHERE idle_expires_at > sqlc.arg(cutoff)::timestamptz
                          AND absolute_expires_at > sqlc.arg(cutoff)::timestamptz)::bigint AS live
FROM sessions
WHERE revoked_at IS NULL AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: RevokeSessionsBefore :execrows
-- Pool platform (quyền UPDATE (revoked_at, id_token_hint_enc) của 0018): thu hồi như RevokeIdentitySessions — kể cả
-- session đã hết hạn idle (vô hại) — và xóa hint đăng xuất.
UPDATE sessions SET revoked_at = sqlc.arg(cutoff)::timestamptz, id_token_hint_enc = NULL
WHERE revoked_at IS NULL AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: CountAuthRequestsBefore :one
SELECT count(*)::bigint FROM auth_requests WHERE created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: DeleteAuthRequestsBefore :execrows
-- Lượt đăng nhập đang dở có trong bản dump (hạn ≤ 10 phút — thường đã hết): xóa, như session.gc (quyền DELETE của 0002).
DELETE FROM auth_requests WHERE created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: CountOpenApprovals :many
-- Pool platform (T+P — thấy mọi hàng): yêu cầu 2P còn mở (pending, approved chưa thực thi) tạo trước cutoff, theo scope
-- và trạng thái.
SELECT scope, status, count(*)::bigint AS requests
FROM approval_requests
WHERE status IN ('pending', 'approved') AND created_at <= sqlc.arg(cutoff)::timestamptz
GROUP BY scope, status
ORDER BY scope, status;

-- name: ExpireOpenApprovals :execrows
-- Quyền UPDATE (status) của mg_worker_platform (0009); index approval_requests_open_idx. Không CHECK nào cấm
-- approved → expired (người duyệt + decided_at giữ nguyên làm lịch sử).
UPDATE approval_requests SET status = 'expired'
WHERE status IN ('pending', 'approved') AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: CountConsoleGrants :one
-- Phiên console Keycloak đã thực thi (P3-T15 — chính yêu cầu executed là grant) có thể còn trong cửa sổ: quyết định từ
-- `since` (cutoff − thời lượng dài nhất). job_id luôn NULL ở loại này (không enqueue gì).
SELECT count(*)::bigint FROM approval_requests
WHERE scope = 'platform' AND tenant_id IS NULL AND action = sqlc.arg(action) AND status = 'executed' AND job_id IS NULL
  AND decided_at >= sqlc.arg(since)::timestamptz AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: ExpireConsoleGrants :execrows
-- executed → expired: cổng console chỉ nhận yêu cầu executed (ListIdPConsoleGrants) ⇒ phiên bị đóng ngay. CHECK của 0009
-- (job_id chỉ ở executed) thỏa vì job_id NULL.
UPDATE approval_requests SET status = 'expired'
WHERE scope = 'platform' AND tenant_id IS NULL AND action = sqlc.arg(action) AND status = 'executed' AND job_id IS NULL
  AND decided_at >= sqlc.arg(since)::timestamptz AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: SupportGrantsTablePresent :one
-- support_access_grants đến với migration 0023 (P4-T05): DB restore từ bản dump của schema cũ hơn (chưa migrate) chưa
-- có bảng ⇒ bước support grant báo not_in_schema.
SELECT (to_regclass('public.support_access_grants') IS NOT NULL)::boolean AS present;

-- name: CountOpenSupportGrants :many
-- Pool platform (T+P — thấy mọi hàng): Support Access Grant còn mở (pending, approved) tạo trước cutoff, theo trạng thái.
SELECT status, count(*)::bigint AS grants
FROM support_access_grants
WHERE status IN ('pending', 'approved') AND created_at <= sqlc.arg(cutoff)::timestamptz
GROUP BY status
ORDER BY status;

-- name: RevokeApprovedSupportGrants :execrows
-- Quyền UPDATE (status, revoked_at, updated_at, version) của mg_worker_platform (0023): grant đã duyệt của bản dump —
-- kể cả grant đã bị thu hồi trong khoảng mất dữ liệu — bị thu hồi (approved → revoked, trigger của 0023 cho phép; quyết
-- định giữ nguyên làm lịch sử).
UPDATE support_access_grants SET status = 'revoked', revoked_at = sqlc.arg(cutoff)::timestamptz,
    updated_at = sqlc.arg(cutoff)::timestamptz, version = version + 1
WHERE status = 'approved' AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: ExpirePendingSupportGrants :execrows
-- Yêu cầu chưa quyết định của bản dump (có thể đã bị từ chối trong khoảng mất dữ liệu): pending → expired, không mang
-- quyết định — staff phải yêu cầu lại.
UPDATE support_access_grants SET status = 'expired', updated_at = sqlc.arg(cutoff)::timestamptz, version = version + 1
WHERE status = 'pending' AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: ListTenantsForPostRestore :many
-- Pool platform: mọi tenant chưa deleted (lời mời, policy, audit.gap theo tenant).
SELECT id, slug, status FROM tenants
WHERE status <> 'deleted'
ORDER BY slug;

-- name: CountPendingInvitations :one
-- Pool tenant (bảng T): lời mời còn chờ tạo trước cutoff.
SELECT count(*)::bigint FROM tenant_invitations
WHERE tenant_id = sqlc.arg(tenant_id) AND status = 'pending' AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: RevokePendingInvitations :execrows
-- Quyền UPDATE (status, updated_at, version) của mg_worker_tenant (0009).
UPDATE tenant_invitations SET status = 'revoked', updated_at = sqlc.arg(cutoff)::timestamptz, version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND status = 'pending' AND created_at <= sqlc.arg(cutoff)::timestamptz;

-- name: ListInstancesForPostRestore :many
-- Pool platform: instance chưa removed của registry cùng trạng thái tenant (bước API key, policy, inventory.sync).
SELECT ti.id, ti.tenant_id, t.slug, ti.status, t.status AS tenant_status
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.status <> 'removed'
ORDER BY t.slug, ti.id;

-- name: MarkInstanceLost :execrows
-- §17.2 bước 2: instance có trong registry nhưng không còn gì trên host (đã deprovision trong khoảng mất dữ liệu) ⇒
-- failed, KHÔNG tự provision lại. Chỉ từ starting/running/stopped (trạng thái reconcile kiểm).
UPDATE tenant_instances SET status = 'failed', updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id) AND status IN ('starting', 'running', 'stopped');

-- name: ListOpenJobsBefore :many
-- Job còn mở có trong bản dump: chỉ BÁO CÁO (người vận hành xem trước khi tắt bảo trì — worker sẽ chạy tiếp chúng).
SELECT id, kind, status, tenant_id, created_at FROM provisioning_jobs
WHERE status IN ('queued', 'running', 'compensating', 'failed_resumable') AND created_at <= sqlc.arg(cutoff)::timestamptz
ORDER BY created_at, id
LIMIT 200;

-- name: LockSystemSettingKey :exec
-- Khóa advisory theo transaction cho người ghi một khóa system_settings (cờ bảo trì: `admin maintenance` và
-- post-restore-reconcile không ghi đè nhau).
SELECT pg_advisory_xact_lock(hashtextextended('system_settings:' || sqlc.arg(key)::text, 0));

-- name: AuditGapRecorded :one
-- audit.gap của một điểm khôi phục đã ghi chưa (chạy lại lệnh không ghi lần hai): sự kiện platform (tenant_id NULL, pool
-- platform) hoặc của một tenant (pool tenant — RLS chỉ cho thấy hàng của chính nó).
SELECT EXISTS (
    SELECT 1 FROM audit_events
    WHERE action = 'audit.gap' AND tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid
      AND details ->> 'restore_point_unix' = sqlc.arg(restore_point_unix)::text
)::boolean AS recorded;
