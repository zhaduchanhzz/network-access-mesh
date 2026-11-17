-- P3-T04a — dual control (2P, §8.5/§8.6; bảng approval_requests của 0009, P3-T06). Không migration mới: quyền của 0009
-- đủ (api: SELECT, INSERT, UPDATE (status, approved_by_identity_id, decided_at, job_id)).
-- Pool tenant (WithTenantTx của tenant trong path): RLS chỉ cho thấy hàng tenant_id = tenant đó (scope 'tenant'). Pool
-- platform thấy MỌI hàng (T+P), nên mọi truy vấn lọc tường minh (scope, tenant_id): /platform/approvals chỉ thấy yêu cầu
-- scope 'platform' — yêu cầu nội bộ của tenant (payload là thiết lập của tenant) không bao giờ hiện cho nhân sự nền tảng.
-- approved_by_identity_id là NGƯỜI QUYẾT ĐỊNH: người duyệt (approved/executed) hoặc người từ chối (rejected) — CHECK
-- approved_by <> requested_by của 0009 chặn cả tự duyệt lẫn tự từ chối ở DB.

-- name: InsertApprovalRequest :one
-- payload = JSON chuẩn hóa (khóa sắp xếp, không khoảng trắng) do internal/authz/approvals sinh; payload_sha256 = hex
-- SHA-256 của chính chuỗi đó. created_at lấy từ đồng hồ của ứng dụng (cùng đồng hồ tính expires_at).
INSERT INTO approval_requests (scope, tenant_id, action, resource_type, resource_id, payload, payload_sha256,
                               requested_by_identity_id, reason, expires_at, created_at)
VALUES (sqlc.arg(scope), sqlc.narg(tenant_id), sqlc.arg(action), sqlc.arg(resource_type), sqlc.narg(resource_id),
        sqlc.arg(payload), sqlc.arg(payload_sha256), sqlc.arg(requested_by_identity_id), sqlc.narg(reason),
        sqlc.arg(expires_at), sqlc.arg(created_at))
RETURNING *;

-- name: FindOpenApprovalRequest :one
-- Yêu cầu còn mở (pending/approved, chưa hết hạn) cho cùng thao tác trên cùng tài nguyên: không mở yêu cầu thứ hai.
SELECT id FROM approval_requests
WHERE scope = sqlc.arg(scope) AND tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id) AND action = sqlc.arg(action)
  AND resource_type = sqlc.arg(resource_type) AND resource_id IS NOT DISTINCT FROM sqlc.narg(resource_id)
  AND status IN ('pending', 'approved') AND expires_at > sqlc.arg(now)::timestamptz
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: GetApprovalRequestView :one
-- Một yêu cầu kèm tên hiển thị của người yêu cầu và người quyết định (snapshot lúc đọc). Lớp 2 của §8.8: hàng phải
-- thuộc đúng phạm vi và đúng tenant của path, nếu không ⇒ không có hàng (404).
SELECT sqlc.embed(a),
       COALESCE(ri.display_name, ri.email::text, ri.subject, '')::text AS requested_by_display,
       COALESCE(di.display_name, di.email::text, di.subject, '')::text AS decided_by_display
FROM approval_requests a
LEFT JOIN identities ri ON ri.id = a.requested_by_identity_id
LEFT JOIN identities di ON di.id = a.approved_by_identity_id
WHERE a.id = sqlc.arg(id) AND a.scope = sqlc.arg(scope) AND a.tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id);

-- name: LockApprovalRequest :one
-- Khóa hàng trong transaction quyết định / thực thi: hai lần duyệt đồng thời tuần tự hóa, lần sau thấy trạng thái mới.
SELECT * FROM approval_requests
WHERE id = sqlc.arg(id) AND scope = sqlc.arg(scope) AND tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)
FOR UPDATE;

-- name: ListApprovalRequests :many
-- Mới nhất trước, thứ tự ổn định (created_at, id). Trạng thái hiệu lực: pending/approved đã quá expires_at hiển thị
-- (và lọc) là expired, kể cả khi hàng chưa được chuyển sang expired.
SELECT sqlc.embed(a),
       COALESCE(ri.display_name, ri.email::text, ri.subject, '')::text AS requested_by_display,
       COALESCE(di.display_name, di.email::text, di.subject, '')::text AS decided_by_display
FROM approval_requests a
LEFT JOIN identities ri ON ri.id = a.requested_by_identity_id
LEFT JOIN identities di ON di.id = a.approved_by_identity_id
WHERE a.scope = sqlc.arg(scope) AND a.tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)
  AND (sqlc.narg(status)::text IS NULL OR
       (CASE WHEN a.status IN ('pending', 'approved') AND a.expires_at <= sqlc.arg(now)::timestamptz THEN 'expired'
             ELSE a.status END) = sqlc.narg(status)::text)
  AND (sqlc.narg(action)::text IS NULL OR a.action = sqlc.narg(action)::text)
  AND (a.created_at, a.id) < (sqlc.arg(before_created_at)::timestamptz, sqlc.arg(before_id)::uuid)
ORDER BY a.created_at DESC, a.id DESC
LIMIT sqlc.arg(page_limit);

-- name: DecideApprovalRequest :one
-- pending → approved | rejected; người quyết định + thời điểm (CHECK của 0009: approved ⇒ có cả hai, khác người yêu cầu).
UPDATE approval_requests
SET status = sqlc.arg(status), approved_by_identity_id = sqlc.arg(decided_by), decided_at = sqlc.arg(now)::timestamptz
WHERE id = sqlc.arg(id) AND status = 'pending' AND sqlc.arg(status)::text IN ('approved', 'rejected')
RETURNING *;

-- name: MarkApprovalExecuted :one
-- approved → executed + job_id, trong CÙNG transaction đã enqueue job (§6.3): dùng một lần, không replay.
UPDATE approval_requests SET status = 'executed', job_id = sqlc.narg(job_id)
WHERE id = sqlc.arg(id) AND status = 'approved'
RETURNING *;

-- name: ExpireApprovalRequest :one
-- pending/approved đã quá hạn ⇒ expired (đánh dấu khi bị chạm tới; job dọn định kỳ thuộc retention.sweep/P3-T17).
UPDATE approval_requests SET status = 'expired'
WHERE id = sqlc.arg(id) AND status IN ('pending', 'approved')
RETURNING *;
