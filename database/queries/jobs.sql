-- Job nghiệp vụ (P2-T12, §6.3, §11.3, §13.5) — khung job ở internal/jobs. provisioning_jobs là read model của
-- GET /jobs cho mọi job kind; River chỉ chở tham chiếu provisioning_jobs.id (+ kind).
-- Đồng hồ: now() là thời điểm BẮT ĐẦU transaction, không phải lúc câu lệnh chạy; transaction chờ khóa (partial unique
-- index lock_key) có thể bắt đầu sớm hơn lúc bên giữ khóa kết thúc. Mốc ghi LÚC TRẠNG THÁI ĐỔI (started_at, finished_at
-- của job và step, và hạn timeout_at tính từ mốc đó) dùng clock_timestamp() — đồng hồ thực tại lúc câu lệnh chạy; riêng
-- started_at của job đặt bằng câu lệnh riêng (MarkJobStarted) sau khi đã giữ khóa, vì AcquireJob có thể chờ bên giữ
-- khóa commit ngay ở bước chèn index. Nhờ vậy khoảng chạy của hai job cùng khóa không chồng nhau trong DB. now() giữ
-- ở nơi so sánh với ảnh chụp của chính transaction (reaper, idempotency_keys) và ở created_at mặc định.

-- name: InsertJob :one
-- Enqueue trong cùng transaction với thay đổi nghiệp vụ. ON CONFLICT DO NOTHING không chỉ định đích nên bắt cả
-- UNIQUE (requested_by, kind, request_key) lẫn partial unique dedupe_key của job chưa kết thúc: trùng ⇒ 0 hàng
-- (store.ErrNoRows), caller tra job đang giữ khóa.
INSERT INTO provisioning_jobs (tenant_id, instance_id, kind, request_key, dedupe_key, lock_key, max_attempts, input,
                               requested_by, resource_type, resource_id)
VALUES (sqlc.narg(tenant_id), sqlc.narg(instance_id), sqlc.arg(kind), sqlc.narg(request_key), sqlc.narg(dedupe_key),
        sqlc.narg(lock_key), sqlc.arg(max_attempts), sqlc.arg(input), sqlc.narg(requested_by), sqlc.narg(resource_type),
        sqlc.narg(resource_id))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: InsertRunningJob :one
-- Một lượt của job định kỳ (River periodic job, chưa có hàng nghiệp vụ): hàng tạo thẳng ở trạng thái running khi worker
-- nhận job; lượt cùng slot còn chưa kết thúc (trùng dedupe_key) ⇒ 0 hàng.
INSERT INTO provisioning_jobs (kind, dedupe_key, status, attempt, max_attempts, queue_job_id, started_at, timeout_at)
VALUES (sqlc.arg(kind), sqlc.arg(dedupe_key)::text, 'running', 1, sqlc.arg(max_attempts), sqlc.arg(queue_job_id)::bigint,
        clock_timestamp(), clock_timestamp() + sqlc.arg(timeout_secs)::float8 * interval '1 second')
ON CONFLICT DO NOTHING
RETURNING *;

-- name: GetJob :one
SELECT * FROM provisioning_jobs
WHERE id = sqlc.arg(id);

-- name: GetActiveJobByDedupeKey :one
SELECT * FROM provisioning_jobs
WHERE dedupe_key = sqlc.arg(dedupe_key)::text AND status IN ('queued', 'running', 'compensating', 'failed_resumable');

-- name: GetJobByRequestKey :one
SELECT * FROM provisioning_jobs
WHERE requested_by = sqlc.arg(requested_by)::uuid AND kind = sqlc.arg(kind) AND request_key = sqlc.arg(request_key)::text;

-- name: SetJobQueueID :exec
-- id của job River chèn cùng transaction (hoặc của job River mới khi /retry — P3-T05).
UPDATE provisioning_jobs SET queue_job_id = sqlc.arg(queue_job_id)::bigint
WHERE id = sqlc.arg(id);

-- name: AcquireJob :one
-- Worker nhận job: queued → running — đồng thời chiếm khóa chạy lifecycle: đụng partial unique index lock_key ⇒ 23505,
-- job tự hoãn (snooze) rồi thử lại, không advisory lock (§11.3, §13.5 mục d) — hoặc running → running (lượt retry,
-- rescue của chính job queue đó). Chỉ job River đang chở job (queue_job_id) được chạy. Không đặt mốc thời gian ở đây:
-- câu lệnh này có thể chờ bên giữ khóa commit ngay tại bước chèn index, nên mọi mốc tính trong câu lệnh có thể cũ hơn
-- lúc bên giữ khóa kết thúc — MarkJobStarted (câu lệnh sau, trong cùng transaction) đặt started_at/timeout_at.
UPDATE provisioning_jobs
SET status = 'running', attempt = attempt + 1
WHERE id = sqlc.arg(id) AND queue_job_id = sqlc.arg(queue_job_id)::bigint AND status IN ('queued', 'running')
RETURNING *;

-- name: MarkJobStarted :one
-- Sau AcquireJob, cùng transaction: started_at và timeout_at đặt ở lần nhận đầu (clock_timestamp() — chạy sau khi đã
-- giữ khóa, tức sau lúc bên giữ khóa trước commit finished_at của nó).
UPDATE provisioning_jobs
SET started_at = COALESCE(started_at, clock_timestamp()),
    timeout_at = COALESCE(timeout_at, clock_timestamp() + sqlc.arg(timeout_secs)::float8 * interval '1 second')
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: GetLockHolder :one
SELECT * FROM provisioning_jobs
WHERE lock_key = sqlc.arg(lock_key)::text AND status IN ('running', 'compensating', 'failed_resumable');

-- name: TransitionJob :one
-- Chuyển trạng thái có điều kiện theo (status, attempt) đã quan sát: worker kết thúc lượt chạy của chính nó, reaper thu
-- hồi job — bên đến sau nhận 0 hàng. finished_at chỉ đặt ở trạng thái kết thúc.
UPDATE provisioning_jobs
SET status        = sqlc.arg(to_status)::text,
    output        = COALESCE(sqlc.narg(output), output),
    error         = sqlc.narg(error),
    resource_type = COALESCE(sqlc.narg(resource_type), resource_type),
    resource_id   = COALESCE(sqlc.narg(resource_id), resource_id),
    finished_at   = CASE WHEN sqlc.arg(to_status)::text IN ('succeeded', 'failed', 'cancelled', 'rolled_back') THEN clock_timestamp() END
WHERE id = sqlc.arg(id) AND status = sqlc.arg(from_status)::text AND attempt = sqlc.arg(attempt)
RETURNING *;

-- name: BeginCompensation :one
-- Lỗi không phục hồi được của job nhóm lifecycle có compensation: running → compensating (vẫn giữ khóa chạy), hạn mới.
UPDATE provisioning_jobs
SET status = 'compensating', error = sqlc.arg(error),
    timeout_at = clock_timestamp() + sqlc.arg(timeout_secs)::float8 * interval '1 second'
WHERE id = sqlc.arg(id) AND status = 'running' AND attempt = sqlc.arg(attempt)
RETURNING *;

-- name: RecordJobError :exec
-- Lỗi tạm thời còn lượt retry: job vẫn running (giữ khóa chạy), lưu lỗi gần nhất.
UPDATE provisioning_jobs SET error = sqlc.arg(error)
WHERE id = sqlc.arg(id) AND status = 'running' AND attempt = sqlc.arg(attempt);

-- name: InterruptJob :exec
-- Lượt chạy bị cắt vì worker dừng (shutdown có kiểm soát): không tính lượt, job vẫn running (giữ khóa chạy) và chạy
-- tiếp sau khi worker khởi động lại; worker không quay lại ⇒ job.reaper xử lý khi quá timeout_at.
UPDATE provisioning_jobs SET attempt = attempt - 1, error = sqlc.arg(error)
WHERE id = sqlc.arg(id) AND status = 'running' AND attempt = sqlc.arg(attempt) AND attempt > 0;

-- name: SetJobCurrentStep :exec
UPDATE provisioning_jobs SET current_step = sqlc.arg(current_step)::text
WHERE id = sqlc.arg(id) AND status IN ('running', 'compensating') AND attempt = sqlc.arg(attempt);

-- name: ListJobsToReap :many
-- job.reaper (pool platform): job running/compensating đã quá timeout_at, và job queued/running đủ cũ để đối chiếu job
-- River của nó (job mà queue đã loại bỏ — §11.3, §13.5).
SELECT * FROM provisioning_jobs
WHERE (status IN ('running', 'compensating') AND timeout_at < now())
   OR (status IN ('queued', 'running') AND created_at < now() - sqlc.arg(min_age_secs)::float8 * interval '1 second')
ORDER BY created_at
LIMIT sqlc.arg(row_limit);

-- name: CountUnfinishedJobs :many
-- Gauge meshguard_jobs_unfinished (§16.1): số job chưa kết thúc theo trạng thái.
SELECT status, count(*)::bigint AS jobs FROM provisioning_jobs
WHERE status IN ('queued', 'running', 'compensating', 'failed_resumable')
GROUP BY status;

-- name: StartJobStep :one
-- Bắt đầu hoặc chạy lại một step (seq = thứ tự xuất hiện đầu tiên). Step đã succeeded ⇒ 0 hàng: bỏ qua — /retry tiếp
-- tục từ step lỗi (§11.3).
INSERT INTO provisioning_job_steps (tenant_id, job_id, seq, name, status, attempt, started_at)
VALUES (sqlc.narg(tenant_id), sqlc.arg(job_id),
        (SELECT COALESCE(max(s.seq) + 1, 0) FROM provisioning_job_steps s WHERE s.job_id = sqlc.arg(job_id)),
        sqlc.arg(name), 'running', 1, clock_timestamp())
ON CONFLICT (job_id, name) DO UPDATE
SET status = 'running', attempt = provisioning_job_steps.attempt + 1, started_at = clock_timestamp(), finished_at = NULL,
    error_code = NULL
WHERE provisioning_job_steps.status <> 'succeeded'
RETURNING *;

-- name: FinishJobStep :exec
UPDATE provisioning_job_steps
SET status = sqlc.arg(status)::text, finished_at = clock_timestamp(), error_code = sqlc.narg(error_code),
    detail = COALESCE(sqlc.narg(detail), detail)
WHERE job_id = sqlc.arg(job_id) AND name = sqlc.arg(name) AND status = 'running';

-- name: SetJobStepResources :exec
-- created_resources ghi TRƯỚC khi tạo tài nguyên: compensation chỉ gỡ đúng thứ job này đã tạo (§11.3).
UPDATE provisioning_job_steps SET created_resources = sqlc.arg(created_resources)
WHERE job_id = sqlc.arg(job_id) AND name = sqlc.arg(name) AND status = 'running';

-- name: ListJobSteps :many
SELECT * FROM provisioning_job_steps
WHERE job_id = ANY (sqlc.arg(job_ids)::uuid[])
ORDER BY job_id, seq;

-- name: ListJobsPage :many
-- GET /tenants/{t}/jobs (pool tenant; tenant_id lọc ở truy vấn ngoài RLS — §8.8) và GET /platform/jobs (pool platform,
-- tenant_id NULL = mọi job). Thứ tự ổn định (created_at, id) giảm dần; con trỏ = phần tử cuối của trang trước.
SELECT * FROM provisioning_jobs
WHERE (sqlc.narg(tenant_id)::uuid IS NULL OR tenant_id = sqlc.narg(tenant_id)::uuid)
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
  AND (sqlc.narg(kind)::text IS NULL OR kind = sqlc.narg(kind)::text)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(row_limit);

-- name: DeleteFinishedJobs :execrows
-- retention.sweep (§6.4, job 180 ngày): chỉ job đã kết thúc, theo lô; step xóa theo cascade,
-- device_inventory_cache.revocation_job_id → NULL (FK ở trên).
DELETE FROM provisioning_jobs
WHERE id IN (SELECT j.id FROM provisioning_jobs j
             WHERE j.status IN ('succeeded', 'failed', 'cancelled', 'rolled_back')
               AND j.finished_at < sqlc.arg(finished_before)::timestamptz
             ORDER BY j.finished_at
             LIMIT sqlc.arg(row_limit));

-- name: DeleteExpiredIdempotencyKeys :execrows
-- retention.sweep (§6.4, 24 giờ: expires_at = thời điểm nhận khóa + 24 giờ).
DELETE FROM idempotency_keys k
USING (SELECT e.tenant_id, e.identity_id, e.operation_id, e.key FROM idempotency_keys e
       WHERE e.expires_at < sqlc.arg(expired_before)::timestamptz
       ORDER BY e.expires_at
       LIMIT sqlc.arg(row_limit)) d
WHERE k.tenant_id IS NOT DISTINCT FROM d.tenant_id AND k.identity_id = d.identity_id
  AND k.operation_id = d.operation_id AND k.key = d.key;

-- name: DeleteOldSecurityEvents :execrows
-- retention.sweep (§6.4: ≥ 400 ngày như audit; security_events là bảng thường). audit_events KHÔNG BAO GIỜ đi qua
-- retention.sweep — chỉ drop partition (§6.1).
DELETE FROM security_events
WHERE id IN (SELECT s.id FROM security_events s
             WHERE s.occurred_at < sqlc.arg(occurred_before)::timestamptz
             ORDER BY s.occurred_at
             LIMIT sqlc.arg(row_limit));

-- name: DeleteRemovedDevices :execrows
-- retention.sweep (§6.4: hàng cache đã có removed_at, 90 ngày). Pool tenant (bảng T — mg_worker_tenant).
DELETE FROM device_inventory_cache
WHERE id IN (SELECT d.id FROM device_inventory_cache d
             WHERE d.tenant_id = sqlc.arg(tenant_id) AND d.removed_at < sqlc.arg(removed_before)::timestamptz
             ORDER BY d.removed_at
             LIMIT sqlc.arg(row_limit));

-- name: ListTenantIDs :many
-- Pool platform: tenant cần quét bảng T (retention.sweep quét từng tenant qua WithTenantTx).
SELECT id FROM tenants
ORDER BY id;

-- name: InsertIdempotencyKey :one
-- Idempotency-Key (§13.1): request đầu tiên với khóa ⇒ hàng in_progress giữ đến locked_until; đã có hàng ⇒ 0 hàng.
INSERT INTO idempotency_keys (tenant_id, identity_id, operation_id, key, request_hash, status, locked_until, expires_at)
VALUES (sqlc.narg(tenant_id), sqlc.arg(identity_id), sqlc.arg(operation_id), sqlc.arg(key), sqlc.arg(request_hash),
        'in_progress', now() + sqlc.arg(lock_secs)::float8 * interval '1 second',
        now() + sqlc.arg(ttl_secs)::float8 * interval '1 second')
ON CONFLICT DO NOTHING
RETURNING *;

-- name: GetIdempotencyKeyForUpdate :one
SELECT sqlc.embed(idempotency_keys),
       (expires_at <= now())::boolean AS expired,
       COALESCE(EXTRACT(EPOCH FROM (locked_until - now())), 0)::float8 AS locked_for_secs
FROM idempotency_keys
WHERE tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid AND identity_id = sqlc.arg(identity_id)
  AND operation_id = sqlc.arg(operation_id) AND key = sqlc.arg(key)
FOR UPDATE;

-- name: ClaimIdempotencyKey :one
-- Nhận lại khóa: hàng đã hết hạn (retention.sweep chưa kịp xóa), request trước thất bại, hoặc in_progress đã quá
-- locked_until (tiến trình chết giữa chừng).
UPDATE idempotency_keys
SET request_hash = sqlc.arg(request_hash), status = 'in_progress', response_status = NULL, response_body = NULL,
    secret_ref = NULL, resource_type = NULL, resource_id = NULL,
    locked_until = now() + sqlc.arg(lock_secs)::float8 * interval '1 second',
    expires_at = now() + sqlc.arg(ttl_secs)::float8 * interval '1 second'
WHERE tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid AND identity_id = sqlc.arg(identity_id)
  AND operation_id = sqlc.arg(operation_id) AND key = sqlc.arg(key)
RETURNING *;

-- name: FinishIdempotencyKey :one
-- Kết quả của request đang giữ khóa (in_progress, cùng request_hash): completed ⇒ lưu response (đã loại secret) để trả
-- lại khi lặp; failed ⇒ nhả khóa cho lần thử lại.
UPDATE idempotency_keys
SET status = sqlc.arg(status)::text, response_status = sqlc.narg(response_status), response_body = sqlc.narg(response_body),
    secret_ref = sqlc.narg(secret_ref), resource_type = sqlc.narg(resource_type), resource_id = sqlc.narg(resource_id),
    locked_until = NULL
WHERE tenant_id IS NOT DISTINCT FROM sqlc.narg(tenant_id)::uuid AND identity_id = sqlc.arg(identity_id)
  AND operation_id = sqlc.arg(operation_id) AND key = sqlc.arg(key)
  AND status = 'in_progress' AND request_hash = sqlc.arg(request_hash)
RETURNING *;

-- ---------------------------------------------------------------- điều khiển job vòng đời (P3-T05, §11.3, 0015)

-- name: GetJobStep :one
-- Một step của job (created_resources của step trước — ví dụ instance_id mà placement.allocate đã chọn).
SELECT * FROM provisioning_job_steps
WHERE job_id = sqlc.arg(job_id) AND name = sqlc.arg(name);

-- name: JobCancelRequested :one
-- Trước mỗi step: người vận hành đã gọi /cancel chưa (handler dừng SAU step hiện tại — §11.3).
SELECT (cancel_requested_at IS NOT NULL)::boolean AS requested FROM provisioning_jobs
WHERE id = sqlc.arg(id);

-- name: RequestJobCancel :one
-- /cancel trên job đang chạy: chỉ đặt mốc (giữ mốc đầu tiên); handler thấy ở đầu step kế tiếp.
UPDATE provisioning_jobs SET cancel_requested_at = COALESCE(cancel_requested_at, clock_timestamp())
WHERE id = sqlc.arg(id) AND status = 'running'
RETURNING *;

-- name: CancelQueuedJob :one
-- /cancel trên job chưa bắt đầu chạy ⇒ cancelled (trạng thái kết thúc — nhả dedupe_key). Lần giao của job River sau đó
-- gặp job đã kết thúc nên không chạy gì.
UPDATE provisioning_jobs
SET status = 'cancelled', error = sqlc.arg(error), finished_at = clock_timestamp(), cancel_requested_at = clock_timestamp()
WHERE id = sqlc.arg(id) AND status = 'queued'
RETURNING *;

-- name: ResumeJob :one
-- /retry trên job failed_resumable: chuyển THẲNG sang running (không qua queued) nên khóa chạy lifecycle không bao giờ
-- rời job — không job nào chen vào giữa (§13.5 mục d); lượt mới: max_attempts = attempt + số lượt của kind (attempt tăng
-- đơn điệu, không bao giờ đặt lại — lần giao cũ còn sống không trùng (status, attempt) với lượt mới); timeout_at đặt lại ở
-- lần nhận kế tiếp (MarkJobStarted); job River mới ⇒ queue_job_id mới. Step đã succeeded được bỏ qua: job tiếp tục từ
-- step lỗi.
UPDATE provisioning_jobs
SET status = 'running', max_attempts = attempt + sqlc.arg(attempts)::integer, error = NULL, timeout_at = NULL,
    cancel_requested_at = NULL, queue_job_id = sqlc.arg(queue_job_id)::bigint
WHERE id = sqlc.arg(id) AND status = 'failed_resumable'
RETURNING *;

-- name: RollbackJob :one
-- /rollback trên job failed_resumable: compensating (vẫn giữ khóa chạy) + job River mới; worker chạy compensation ngược
-- thứ tự các step đã làm. timeout_at đặt ngay để job.reaper thu hồi lần compensation không ai chạy.
UPDATE provisioning_jobs
SET status = 'compensating', cancel_requested_at = NULL, queue_job_id = sqlc.arg(queue_job_id)::bigint,
    timeout_at = clock_timestamp() + sqlc.arg(timeout_secs)::float8 * interval '1 second'
WHERE id = sqlc.arg(id) AND status = 'failed_resumable'
RETURNING *;

-- name: AcquireCompensation :one
-- Worker nhận một lần giao của job đang compensating (sau /rollback, hoặc lần giao lại sau khi worker dừng giữa
-- compensation): chỉ job River đang chở job; hạn mới cho lần chạy này.
UPDATE provisioning_jobs
SET attempt = attempt + 1, timeout_at = clock_timestamp() + sqlc.arg(timeout_secs)::float8 * interval '1 second'
WHERE id = sqlc.arg(id) AND queue_job_id = sqlc.arg(queue_job_id)::bigint AND status = 'compensating'
RETURNING *;

-- name: SetJobStepCompensation :exec
-- Trạng thái compensation của một step (running → succeeded/failed/skipped); detail thêm lỗi compensation đã redaction.
UPDATE provisioning_job_steps
SET compensation_status = sqlc.arg(compensation_status)::text, detail = COALESCE(sqlc.narg(detail), detail)
WHERE job_id = sqlc.arg(job_id) AND name = sqlc.arg(name);

-- name: InsertFinishedJobStep :exec
-- Step chạy ngoài worker (bước 1–2 của tenant.provision chạy ở API, trong transaction enqueue job) hoặc bỏ qua (job mới
-- của /retry sau rolled_back bắt đầu từ bước 3): ghi thẳng trạng thái cuối.
INSERT INTO provisioning_job_steps (tenant_id, job_id, seq, name, status, attempt, started_at, finished_at, detail)
VALUES (sqlc.narg(tenant_id), sqlc.arg(job_id),
        (SELECT COALESCE(max(s.seq) + 1, 0) FROM provisioning_job_steps s WHERE s.job_id = sqlc.arg(job_id)),
        sqlc.arg(name), sqlc.arg(status)::text, sqlc.arg(attempt)::integer, clock_timestamp(), clock_timestamp(),
        sqlc.narg(detail));
