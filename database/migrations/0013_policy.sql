-- 0013 — Policy (bản đồ migration §6.3, P3-T06; vòng đời §7.3): policy_versions (nội dung — T), policy_applications
-- (mỗi lần đẩy lên Headscale — T), FK ghép tenants (id, desired_policy_version_id) → policy_versions (tenant_id, id)
-- (cột tạo ở 0001 không kèm FK; chú thích ở đó còn ghi "0011" theo bản đồ trước khi G2 dùng 0007/0008).
-- Người dùng: lõi policy P3-T08a (lưu version từ HuJSON thô, lint L1/L2, advisory lock theo tenant, CheckPolicy →
-- SetPolicy → GetPolicy khớp sha256, ghi policy_applications), bước policy.verify của provisioning (§11.3 bước 15),
-- suspend/resume (P3-T08), P3-T17, rồi module policies đầy đủ (P4-T10). Forward-only, expand-only (không ghi lại hàng
-- nào; FK mới kiểm trên cột đang NULL ở mọi hàng).

-- +goose Up

-- ---------------------------------------------------------------- policy_versions (T — bảng nội bộ tenant)
-- version = số thứ tự policy của tenant; revision = bộ đếm khóa lạc quan của bản nháp (nguồn ETag — §6.1).
-- Nội dung có đúng MỘT dạng: source (jsonb, mô hình PolicySource có kiểu — §7.2/§13.3, P4-T10) hoặc source_hujson (văn
-- bản HuJSON do nền tảng sinh/nhập: baseline, suspension, fixture của lõi P3-T08a, chuỗi đang chạy nhập lại ở P3-T17).
-- Với source_hujson, content_sha256 = sha256 hex của đúng chuỗi đó (UTF-8) — DB kiểm; L2 (chuỗi rỗng) bị chặn cả ở DB.
-- Vòng đời §7.3: phê duyệt chỉ tồn tại ở approved/superseded (mọi chỉnh sửa đưa về draft và xóa phê duyệt); approved ⇒
-- approved_at + approved_content_sha256 = content_sha256; version user được duyệt luôn có người duyệt + review_mode
-- (baseline/suspension do hệ thống duyệt: approved_by NULL); peer ⇒ người duyệt khác người submit. Cột actor
-- (created_by, submitted_by, approved_by, rejected_by) là tham chiếu actor, không FK (như audit — §6.1).
CREATE TABLE policy_versions (
    id                      uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id               uuid        NOT NULL REFERENCES tenants (id),
    version                 integer     NOT NULL CHECK (version > 0),
    revision                bigint      NOT NULL DEFAULT 1 CHECK (revision > 0),
    kind                    text        NOT NULL DEFAULT 'user' CHECK (kind IN ('user', 'baseline', 'suspension')),
    source                  jsonb       CHECK (jsonb_typeof(source) = 'object'),
    source_hujson           text        CHECK (source_hujson ~ '\S' AND octet_length(source_hujson) <= 1048576),
    content_sha256          text        NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    state                   text        NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft', 'validated', 'pending_approval', 'approved', 'rejected', 'superseded')),
    validation_report       jsonb       CHECK (jsonb_typeof(validation_report) = 'object'),
    parent_version_id       uuid,
    rollback_of             uuid,
    created_by              uuid,       -- NULL = system (baseline/suspension)
    submitted_by            uuid,
    submitted_at            timestamptz,
    approved_by             uuid,
    approved_at             timestamptz,
    approved_content_sha256 text        CHECK (approved_content_sha256 ~ '^[0-9a-f]{64}$'),
    review_mode             text        CHECK (review_mode IN ('peer', 'self')),
    rejected_by             uuid,
    rejected_at             timestamptz,
    rejected_reason         text        CHECK (length(rejected_reason) <= 2000),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CHECK ((source IS NULL) <> (source_hujson IS NULL)),
    CHECK (source_hujson IS NULL OR content_sha256 = encode(sha256(convert_to(source_hujson, 'UTF8')), 'hex')),
    CHECK (state IN ('approved', 'superseded')
           OR (approved_by IS NULL AND approved_at IS NULL AND approved_content_sha256 IS NULL AND review_mode IS NULL)),
    CHECK (state <> 'approved' OR (approved_at IS NOT NULL AND approved_content_sha256 = content_sha256)),
    CHECK (state <> 'approved' OR kind <> 'user' OR (approved_by IS NOT NULL AND review_mode IS NOT NULL)),
    CHECK (review_mode <> 'peer' OR (submitted_by IS NOT NULL AND approved_by IS NOT NULL AND approved_by <> submitted_by)),
    CHECK (state <> 'pending_approval' OR (submitted_by IS NOT NULL AND submitted_at IS NOT NULL)),
    CHECK (state <> 'rejected' OR rejected_at IS NOT NULL),
    CHECK (parent_version_id <> id AND rollback_of <> id),
    UNIQUE (tenant_id, version),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, parent_version_id) REFERENCES policy_versions (tenant_id, id),
    FOREIGN KEY (tenant_id, rollback_of) REFERENCES policy_versions (tenant_id, id)
);
CREATE INDEX policy_versions_tenant_state_idx ON policy_versions (tenant_id, state);

-- Version mong muốn của tenant: chỉ trỏ được version của chính tenant đó.
ALTER TABLE tenants
    ADD CONSTRAINT tenants_desired_policy_version_fkey
    FOREIGN KEY (id, desired_policy_version_id) REFERENCES policy_versions (tenant_id, id);

-- ---------------------------------------------------------------- policy_applications (T — bảng nội bộ tenant)
-- Mỗi lần job policy.apply chạy (§7.3, §13.5): applied_hujson = ĐÚNG chuỗi byte gửi tới Headscale (nội dung đã duyệt +
-- phần render từ bảng + tests sinh lúc apply), applied_sha256 = sha256 hex của chuỗi đó (DB kiểm) — mốc của drift check
-- và post-start gate. Lần áp dụng "hiện hành" của một instance = hàng applied có superseded_at NULL (partial unique:
-- một hàng mỗi instance); áp thành công lần mới ⇒ đặt superseded_at cho hàng cũ trước, rồi mới đánh dấu hàng mới
-- applied (cùng transaction). unknown: không biết Headscale đã nhận chưa — luôn gửi lại bản applied hiện hành rồi mới ghi
-- failed (V-26). requested_by_identity_id: tham chiếu actor, không FK (NULL = system/lịch).
CREATE TABLE policy_applications (
    id                       uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id                uuid        NOT NULL REFERENCES tenants (id),
    instance_id              uuid        NOT NULL,
    policy_version_id        uuid        NOT NULL,
    trigger                  text        NOT NULL CHECK (trigger IN ('bootstrap', 'manual', 'group_change', 'resource_change',
                                                                     'tag_change', 'suspend', 'resume', 'restore',
                                                                     'drift_repair', 'rollback')),
    inputs_sha256            text        CHECK (inputs_sha256 ~ '^[0-9a-f]{64}$'),
    applied_hujson           text        NOT NULL CHECK (applied_hujson ~ '\S' AND octet_length(applied_hujson) <= 1048576),
    applied_sha256           text        NOT NULL CHECK (applied_sha256 ~ '^[0-9a-f]{64}$'),
    state                    text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'applied', 'failed', 'unknown')),
    headscale_updated_at     timestamptz,
    error_code               text        CHECK (error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    requested_by_identity_id uuid,
    created_at               timestamptz NOT NULL DEFAULT now(),
    finished_at              timestamptz,
    superseded_at            timestamptz,
    CHECK (applied_sha256 = encode(sha256(convert_to(applied_hujson, 'UTF8')), 'hex')),
    CHECK ((state IN ('applied', 'failed')) = (finished_at IS NOT NULL)),
    CHECK (state <> 'failed' OR error_code IS NOT NULL),
    CHECK (superseded_at IS NULL OR state = 'applied'),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, instance_id) REFERENCES tenant_instances (tenant_id, id),
    FOREIGN KEY (tenant_id, policy_version_id) REFERENCES policy_versions (tenant_id, id)
);
CREATE UNIQUE INDEX policy_applications_current_key ON policy_applications (instance_id)
    WHERE state = 'applied' AND superseded_at IS NULL;
CREATE INDEX policy_applications_tenant_created_idx ON policy_applications (tenant_id, created_at DESC, id DESC);

-- ---------------------------------------------------------------- RLS (T: không nhánh platform — §6.1)
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_versions_tenant ON policy_versions TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE policy_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_applications FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_applications_tenant ON policy_applications TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

-- ---------------------------------------------------------------- quyền
-- Chỉ role tenant (bảng T). id, tenant_id, version, kind, parent_version_id, rollback_of, created_by, created_at của
-- version bất biến. api: soạn/sửa/validate/submit/duyệt/từ chối (P4-T10; lõi P3-T08a). worker: tạo version baseline/
-- suspension/nhập lại (§11.3 bước 15, P3-T08, P3-T17), đổi trạng thái (validated qua CheckPolicy, superseded).
-- policy_applications chỉ do job policy.apply ghi (worker); nội dung đã gửi (applied_hujson/applied_sha256/inputs) bất biến.
REVOKE ALL ON policy_versions, policy_applications FROM PUBLIC;
GRANT SELECT, INSERT ON policy_versions TO mg_api_tenant, mg_worker_tenant;
GRANT UPDATE (revision, source, source_hujson, content_sha256, state, validation_report, submitted_by, submitted_at,
              approved_by, approved_at, approved_content_sha256, review_mode, rejected_by, rejected_at, rejected_reason,
              updated_at)
    ON policy_versions TO mg_api_tenant;
GRANT UPDATE (revision, state, validation_report, updated_at) ON policy_versions TO mg_worker_tenant;

GRANT SELECT ON policy_applications TO mg_api_tenant, mg_worker_tenant;
GRANT INSERT ON policy_applications TO mg_worker_tenant;
GRANT UPDATE (state, headscale_updated_at, error_code, finished_at, superseded_at) ON policy_applications TO mg_worker_tenant;

-- Đặt version mong muốn là thao tác của tenant (POST /policies/{versionId}/apply, bước policy.verify) chạy trong
-- WithTenantTx — policy_versions là bảng T nên pool platform không đọc được version để kiểm. Role tenant chỉ được UPDATE
-- đúng cột này của hàng tenant của mình (RLS tenants_tenant); FK ghép ở trên chặn version của tenant khác.
GRANT UPDATE (desired_policy_version_id) ON tenants TO mg_api_tenant, mg_worker_tenant;
