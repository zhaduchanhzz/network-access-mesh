-- 0006 — Job nghiệp vụ + idempotency (bản đồ migration §6.3, §13.5): provisioning_jobs/provisioning_job_steps
-- (read model của GET /jobs cho MỌI job kind; tên bảng giữ theo lịch sử), idempotency_keys; FK
-- device_inventory_cache.revocation_job_id (cột tạo ở 0005); schema `river` của job queue. Bảng của River do chính
-- rivermigrate tạo trong schema này ngay sau goose (store.MigrateQueue, P2-T12), quyền trên chúng cấp tường minh ở
-- database/river/grants.sql. Forward-only.

-- +goose Up

CREATE TABLE provisioning_jobs (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid        REFERENCES tenants (id),  -- NULL = job phạm vi platform
    instance_id   uuid,
    kind          text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    request_key   text        CHECK (length(request_key) BETWEEN 1 AND 255),  -- Idempotency-Key của client (chống lặp request)
    dedupe_key    text        CHECK (length(dedupe_key) BETWEEN 1 AND 255),   -- chống trùng job đang chạy (có chứa kind)
    lock_key      text,       -- khóa chạy của nhóm lifecycle: tenant:<id>:lifecycle
    status        text        NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'failed_resumable', 'compensating', 'rolled_back', 'succeeded', 'failed', 'cancelled')),
    current_step  text,
    attempt       integer     NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts  integer     NOT NULL DEFAULT 1 CHECK (max_attempts > 0),
    input         jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(input) = 'object'),
    output        jsonb,
    -- {code, message?, detail?}: code là mã ổn định (phía tenant chỉ nhận code — §13.3); message/detail đã redaction,
    -- chỉ trả ở GET /platform/jobs/{id}.
    error         jsonb       CHECK (error IS NULL OR (jsonb_typeof(error) = 'object' AND (error ->> 'code') ~ '^[a-z][a-z0-9_]{0,63}$')),
    resource_type text        CHECK (resource_type ~ '^[a-z][a-z_]{0,31}$'),  -- tài nguyên job tạo ra (Job.resource, §13.3)
    resource_id   text        CHECK (length(resource_id) BETWEEN 1 AND 128),
    queue_job_id  bigint,     -- river.river_job.id đang chở job này; không FK (schema river do River quản lý)
    requested_by  uuid,       -- identity yêu cầu (NULL = system); tham chiếu actor, không FK
    created_at    timestamptz NOT NULL DEFAULT now(),
    timeout_at    timestamptz,  -- đặt ở lần queued → running đầu tiên (timeout toàn job, §11.3)
    started_at    timestamptz,
    finished_at   timestamptz,  -- chỉ trạng thái kết thúc (succeeded, failed, cancelled, rolled_back)
    UNIQUE (tenant_id, id),
    UNIQUE (requested_by, kind, request_key),
    FOREIGN KEY (tenant_id, instance_id) REFERENCES tenant_instances (tenant_id, id),
    -- khóa chạy luôn là khóa của chính tenant của job: không job nào chiếm được khóa của tenant khác
    CHECK (lock_key IS NULL OR (tenant_id IS NOT NULL AND lock_key = 'tenant:' || tenant_id::text || ':lifecycle')),
    CHECK ((resource_type IS NULL) = (resource_id IS NULL))
);
-- Job đã kết thúc không chặn job mới; failed_resumable chưa kết thúc nên vẫn giữ khóa (§6.3, §13.5).
CREATE UNIQUE INDEX provisioning_jobs_dedupe_key ON provisioning_jobs (dedupe_key)
    WHERE status IN ('queued', 'running', 'compensating', 'failed_resumable');
-- Một job nhóm lifecycle đang chạy cho mỗi tenant: chiếm khóa bằng chính lệnh queued → running (§11.3, §13.5 mục d).
CREATE UNIQUE INDEX provisioning_jobs_lock_key ON provisioning_jobs (lock_key)
    WHERE status IN ('running', 'compensating', 'failed_resumable');
CREATE INDEX provisioning_jobs_tenant_created_idx ON provisioning_jobs (tenant_id, created_at DESC, id DESC);
CREATE INDEX provisioning_jobs_created_idx ON provisioning_jobs (created_at DESC, id DESC);  -- GET /platform/jobs
CREATE INDEX provisioning_jobs_active_idx ON provisioning_jobs (created_at)                -- job.reaper
    WHERE status IN ('queued', 'running', 'compensating');
CREATE INDEX provisioning_jobs_finished_idx ON provisioning_jobs (finished_at)             -- retention.sweep
    WHERE finished_at IS NOT NULL;

CREATE TABLE provisioning_job_steps (
    id                  uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id           uuid,       -- = tenant_id của job (NULL với job platform)
    job_id              uuid        NOT NULL REFERENCES provisioning_jobs (id) ON DELETE CASCADE,
    seq                 integer     NOT NULL CHECK (seq >= 0),
    name                text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
    status              text        NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'skipped')),
    attempt             integer     NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    started_at          timestamptz,
    finished_at         timestamptz,
    error_code          text        CHECK (error_code ~ '^[a-z][a-z0-9_]{0,63}$'),  -- nguồn của message phía tenant
    detail              jsonb,      -- thô (đã redaction), chỉ trả ở GET /platform/jobs/{id} (§13.3)
    created_resources   jsonb,      -- ghi TRƯỚC khi tạo tài nguyên (§11.3)
    compensation_status text        CHECK (compensation_status IN ('running', 'succeeded', 'failed', 'skipped')),
    UNIQUE (job_id, seq),
    UNIQUE (job_id, name),
    FOREIGN KEY (tenant_id, job_id) REFERENCES provisioning_jobs (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE idempotency_keys (
    tenant_id       uuid        REFERENCES tenants (id),
    identity_id     uuid        NOT NULL,  -- tham chiếu actor, không FK (retention 24 giờ)
    operation_id    text        NOT NULL,  -- operationId của OpenAPI
    key             text        NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
    request_hash    bytea       NOT NULL CHECK (octet_length(request_hash) = 32),
    status          text        NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'completed', 'failed')),
    response_status integer,
    response_body   jsonb,      -- đã loại secret; secret hiển-thị-một-lần chỉ qua secret_ref có TTL (§13.1)
    secret_ref      text        CHECK (secret_ref ~ '^mgsec://[^/]+/[^#]+#[0-9]+$'),
    resource_type   text,
    resource_id     text,
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    UNIQUE NULLS NOT DISTINCT (tenant_id, identity_id, operation_id, key)
);
CREATE INDEX idempotency_keys_expires_idx ON idempotency_keys (expires_at);

-- FK của cột tạo ở 0005; xóa job (retention 180 ngày) chỉ gỡ tham chiếu, không đụng tenant_id.
ALTER TABLE device_inventory_cache
    ADD CONSTRAINT device_inventory_cache_revocation_job_fkey
    FOREIGN KEY (tenant_id, revocation_job_id) REFERENCES provisioning_jobs (tenant_id, id)
    ON DELETE SET NULL (revocation_job_id);

-- ---------------------------------------------------------------- RLS (T+P)
ALTER TABLE provisioning_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE provisioning_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY provisioning_jobs_tenant ON provisioning_jobs TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY provisioning_jobs_platform ON provisioning_jobs TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE provisioning_job_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE provisioning_job_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY provisioning_job_steps_tenant ON provisioning_job_steps TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY provisioning_job_steps_platform ON provisioning_job_steps TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY idempotency_keys_tenant ON idempotency_keys TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY idempotency_keys_platform ON idempotency_keys TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

-- ---------------------------------------------------------------- quyền bảng
-- id, tenant_id, instance_id, kind, request_key, requested_by, input, created_at của job bất biến; name/seq của step
-- bất biến. queue_job_id: enqueue ghi id job River sau khi chèn (cùng transaction).
REVOKE ALL ON provisioning_jobs, provisioning_job_steps, idempotency_keys FROM PUBLIC;
GRANT SELECT, INSERT ON provisioning_jobs, provisioning_job_steps
    TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT UPDATE (dedupe_key, lock_key, status, current_step, attempt, max_attempts, output, error, resource_type, resource_id,
              queue_job_id, timeout_at, started_at, finished_at)
    ON provisioning_jobs TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT UPDATE (status, attempt, started_at, finished_at, error_code, detail, created_resources, compensation_status)
    ON provisioning_job_steps TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT DELETE ON provisioning_jobs, provisioning_job_steps TO mg_worker_platform;  -- retention 180 ngày

GRANT SELECT, INSERT ON idempotency_keys TO mg_api_tenant, mg_api_platform;
-- request_hash cập nhật được để tái dùng một khóa đã hết hạn (expires_at) mà retention.sweep chưa kịp xóa.
GRANT UPDATE (request_hash, status, response_status, response_body, secret_ref, resource_type, resource_id, locked_until,
              expires_at)
    ON idempotency_keys TO mg_api_tenant, mg_api_platform;
GRANT SELECT, DELETE ON idempotency_keys TO mg_worker_platform;  -- retention 24 giờ

-- ---------------------------------------------------------------- schema của job queue (River)
-- §6.3: bảng của queue nằm ở schema riêng, không chứa dữ liệu nghiệp vụ ngoài tham chiếu provisioning_jobs.id.
-- Owner = mg_migrator (rivermigrate chạy bằng role này). USAGE và quyền trên bảng: database/river/grants.sql.
CREATE SCHEMA river;
REVOKE ALL ON SCHEMA river FROM PUBLIC;
