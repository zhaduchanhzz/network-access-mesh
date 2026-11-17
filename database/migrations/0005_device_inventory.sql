-- 0005 — Sổ thiết bị + cache node từ Headscale (bản đồ migration §6.3, §6.4): device_inventory_cache,
-- device_inventory_sync_state (P2-T13). Cột id, owner_membership_id, enrollment_request_id, first_seen_at, revocation_*
-- là dữ liệu authoritative của nền tảng (không truncate/dựng lại); các cột còn lại là cache dựng lại được từ Headscale.
-- Forward-only.

-- +goose Up

CREATE TABLE device_inventory_cache (
    id                      uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id               uuid        NOT NULL REFERENCES tenants (id),
    instance_id             uuid        NOT NULL,
    headscale_node_id       bigint      NOT NULL CHECK (headscale_node_id > 0),
    machine_key             text        NOT NULL,
    node_key                text,
    name                    text,
    given_name              text,
    ip_addresses            inet[]      NOT NULL DEFAULT '{}',
    headscale_user_id       bigint,
    owner_membership_id     uuid,
    tags                    text[]      NOT NULL DEFAULT '{}',
    register_method         text,
    online                  boolean     NOT NULL DEFAULT false,
    last_seen               timestamptz,
    expiry                  timestamptz,
    approved_routes         cidr[]      NOT NULL DEFAULT '{}',
    available_routes        cidr[]      NOT NULL DEFAULT '{}',
    subnet_routes           cidr[]      NOT NULL DEFAULT '{}',
    hs_created_at           timestamptz,
    first_seen_at           timestamptz NOT NULL DEFAULT now(),
    last_synced_at          timestamptz NOT NULL DEFAULT now(),
    sync_generation         bigint      NOT NULL DEFAULT 0,
    removed_at              timestamptz,
    enrollment_request_id   uuid,       -- FK thêm ở 0012 (enrollment_requests)
    revocation_state        text        NOT NULL DEFAULT 'none' CHECK (revocation_state IN ('none', 'pending', 'applied', 'failed')),
    revocation_kind         text        CHECK (revocation_kind IN ('expire', 'delete')),
    revocation_requested_at timestamptz,
    revocation_verified_at  timestamptz,
    revocation_job_id       uuid,       -- FK thêm ở 0006 (provisioning_jobs)
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, instance_id) REFERENCES tenant_instances (tenant_id, id),
    FOREIGN KEY (tenant_id, owner_membership_id) REFERENCES tenant_memberships (tenant_id, id)
);
-- Cùng headscale_node_id nhưng khác machine_key ⇒ đặt removed_at cho hàng cũ và chèn hàng mới (§6.3).
CREATE UNIQUE INDEX device_inventory_cache_node_live_key ON device_inventory_cache (instance_id, headscale_node_id)
    WHERE removed_at IS NULL;
CREATE INDEX device_inventory_cache_tenant_online_idx ON device_inventory_cache (tenant_id, online);
CREATE INDEX device_inventory_cache_tenant_owner_idx ON device_inventory_cache (tenant_id, owner_membership_id);

-- RLS — T: bảng nội bộ tenant, không có nhánh platform (§6.1).
ALTER TABLE device_inventory_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_inventory_cache FORCE ROW LEVEL SECURITY;
CREATE POLICY device_inventory_cache_tenant ON device_inventory_cache TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

-- id, tenant_id, instance_id, headscale_node_id, machine_key, first_seen_at bất biến; worker xóa hàng removed quá
-- 90 ngày (retention.sweep chạy theo từng tenant).
REVOKE ALL ON device_inventory_cache FROM PUBLIC;
GRANT SELECT, INSERT ON device_inventory_cache TO mg_api_tenant, mg_worker_tenant;
GRANT UPDATE (node_key, name, given_name, ip_addresses, headscale_user_id, owner_membership_id, tags, register_method,
              online, last_seen, expiry, approved_routes, available_routes, subnet_routes, hs_created_at,
              last_synced_at, sync_generation, removed_at, enrollment_request_id, revocation_state, revocation_kind,
              revocation_requested_at, revocation_verified_at, revocation_job_id)
    ON device_inventory_cache TO mg_api_tenant, mg_worker_tenant;
GRANT DELETE ON device_inventory_cache TO mg_worker_tenant;

-- Trạng thái đồng bộ theo instance (P2-T13): thế hệ và thời điểm snapshot (đồng hồ DB lúc ngay trước ListNodes) của
-- lần inventory.sync gần nhất ĐÃ ÁP DỤNG. Lần sync khóa hàng này (FOR UPDATE) rồi bỏ qua snapshot không mới hơn
-- synced_at — snapshot cũ không bao giờ đè snapshot mới (sync theo lịch, POST …/devices/sync và ?fresh=true chạy song
-- song được); synced_at là nguồn "lần sync gần nhất" của dashboard kể cả khi tailnet chưa có node nào (P2-T13a). Cache:
-- dựng lại được.
CREATE TABLE device_inventory_sync_state (
    instance_id uuid        PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    generation  bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    synced_at   timestamptz,  -- NULL = chưa có lần sync nào được áp dụng
    node_count  integer     NOT NULL DEFAULT 0 CHECK (node_count >= 0),
    FOREIGN KEY (tenant_id, instance_id) REFERENCES tenant_instances (tenant_id, id)
);

ALTER TABLE device_inventory_sync_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_inventory_sync_state FORCE ROW LEVEL SECURITY;
CREATE POLICY device_inventory_sync_state_tenant ON device_inventory_sync_state TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

-- instance_id, tenant_id bất biến.
REVOKE ALL ON device_inventory_sync_state FROM PUBLIC;
GRANT SELECT, INSERT ON device_inventory_sync_state TO mg_api_tenant, mg_worker_tenant;
GRANT UPDATE (generation, synced_at, node_count) ON device_inventory_sync_state TO mg_api_tenant, mg_worker_tenant;
