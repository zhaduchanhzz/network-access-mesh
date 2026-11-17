-- 0011 — Sổ backup (bản đồ migration §6.3, P3-T06; §17.1): backups (T+P). Forward-only, expand-only.
--
-- Mỗi bản backup của một instance tenant ghi một hàng (job instance.backup / upgrade / restore của worker — P3-T11;
-- GET /platform/backups — P6-T04). Hàng phạm vi platform (tenant_id NULL: postgres, idp, edge) dành cho việc nhập sổ về
-- sau: service mg-backup của P2-T03a (pg-backup/idp-backup/edge-backup) KHÔNG ghi bảng này — role mg_backup chỉ đọc
-- (§6.1) — nguồn sự thật của các bản đó là manifest + status.json trong /opt/meshguard/backups (runbook backup-restore).
-- Không secret: storage_uri là vị trí archive (CHECK cấm userinfo `scheme://user[:pw]@…`), key_ref là secret reference
-- mgsec://… của khóa backup của tenant (đường online — §17.1), owner segment = tenant_id của hàng (cùng quy tắc 0007):
-- sổ của tenant A không trỏ được khóa backup của tenant B (T-15). Archive DR chỉ bọc bằng recovery public key ⇒ hàng
-- platform không có key_ref.

-- +goose Up

CREATE TABLE backups (
    id                uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id         uuid        REFERENCES tenants (id),  -- NULL = backup phạm vi platform
    instance_id       uuid,
    kind              text        NOT NULL CHECK (kind IN ('instance', 'postgres', 'idp', 'edge')),
    status            text        NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'failed', 'purged')),
    storage_uri       text        NOT NULL CHECK (length(storage_uri) BETWEEN 1 AND 1024
                                                  AND storage_uri ~ '^[a-z][a-z0-9+.-]*:'
                                                  AND storage_uri !~ '^[a-z][a-z0-9+.-]*://[^/?#]*@'),
    size_bytes        bigint      CHECK (size_bytes >= 0),
    sha256            text        CHECK (sha256 ~ '^[0-9a-f]{64}$'),  -- của ciphertext (manifest ký — §17.1)
    key_ref           text        CHECK (key_ref ~ '^mgsec://[^/]+/[^#]+#[0-9]+$'),
    headscale_version text        CHECK (length(headscale_version) BETWEEN 1 AND 64),
    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    expires_at        timestamptz,  -- archive hết hạn theo lịch của plan; hàng sổ giữ thêm 400 ngày sau khi purge (§6.4)
    verified_at       timestamptz,  -- lần kiểm restore gần nhất (V-12)
    job_id            uuid,
    CHECK ((kind = 'instance') = (instance_id IS NOT NULL)),
    CHECK ((instance_id IS NULL) = (tenant_id IS NULL)),
    CHECK (kind <> 'instance' OR (key_ref IS NOT NULL AND headscale_version IS NOT NULL)),
    CHECK (key_ref IS NULL OR starts_with(key_ref, 'mgsec://' || COALESCE(tenant_id::text, 'platform') || '/')),
    CHECK ((status = 'running') = (finished_at IS NULL)),
    CHECK (finished_at IS NULL OR finished_at >= started_at),
    CHECK (status NOT IN ('succeeded', 'purged') OR (size_bytes IS NOT NULL AND sha256 IS NOT NULL)),
    CHECK (verified_at IS NULL OR status IN ('succeeded', 'purged')),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, instance_id) REFERENCES tenant_instances (tenant_id, id),
    -- job xóa theo retention (180 ngày) chỉ gỡ tham chiếu; hàng tenant chỉ trỏ job của chính tenant
    FOREIGN KEY (job_id) REFERENCES provisioning_jobs (id) ON DELETE SET NULL,
    FOREIGN KEY (tenant_id, job_id) REFERENCES provisioning_jobs (tenant_id, id) ON DELETE SET NULL (job_id)
);
CREATE INDEX backups_instance_finished_idx ON backups (instance_id, finished_at DESC);  -- §6.3
CREATE INDEX backups_kind_finished_idx ON backups (kind, finished_at DESC);  -- bản mới nhất theo loại (cảnh báo quá hạn)

-- ---------------------------------------------------------------- RLS (T+P)
ALTER TABLE backups ENABLE ROW LEVEL SECURITY;
ALTER TABLE backups FORCE ROW LEVEL SECURITY;
CREATE POLICY backups_tenant ON backups TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY backups_platform ON backups TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

-- ---------------------------------------------------------------- quyền bảng
-- Ghi sổ là việc của job (worker, cả hai pool — job backup/restore phạm vi tenant); api platform chỉ đọc (GET
-- /platform/backups, người duyệt restore xem backup_id); api tenant không có endpoint backup ⇒ không cấp. id, tenant,
-- instance, kind, storage_uri, key_ref, headscale_version, started_at, job_id bất biến. Xóa hàng (400 ngày sau purge):
-- pool platform của worker.
REVOKE ALL ON backups FROM PUBLIC;
GRANT SELECT ON backups TO mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON backups TO mg_worker_tenant, mg_worker_platform;
GRANT UPDATE (status, size_bytes, sha256, finished_at, expires_at, verified_at) ON backups TO mg_worker_tenant, mg_worker_platform;
GRANT DELETE ON backups TO mg_worker_platform;
