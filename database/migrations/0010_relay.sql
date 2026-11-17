-- 0010 — Relay plane (bản đồ migration §6.3, P3-T06; thiết kế §10): relay_regions, relay_assignments (T+P).
-- Người dùng: bước relay.assign của provisioning (§11.3 bước 17 — worker), RelayService + GET /tenants/{t}/relay,
-- GET /platform/relay-regions chỉ đọc (P3-T05c). Ghi /platform/relay-regions là P7-T04. Forward-only, expand-only.

-- +goose Up

-- MVP (ADR-11, §10.1): mỗi tenant một region embedded (DERP trong chính Headscale của tenant, verify_clients in-process,
-- region_id 900–999 dùng lại được giữa các tenant, region_code riêng theo tenant) ⇒ kind embedded ⇒ tenant_id NOT NULL.
-- standalone = derper riêng của một tenant (phương án lùi §10.3 c/e) cũng thuộc một tenant; shared = relay dùng chung/
-- vùng (§10.5, Phase 7 — chưa được dùng ở production) ⇔ tenant_id NULL, chỉ pool platform thấy. verify_mode:
-- in_process (verify_clients của embedded DERP) | verify_url (derper --verify-client-url, fail-closed — §10.5); không có
-- giá trị "không xác minh". ipv4/ipv6 = địa chỉ quảng bá của điểm vào (Agent suy ra từ hosts.public_entry — §10.1), không
-- phải secret. status là trạng thái quản trị (pending tới khi Prober xác nhận — §11.3 bước 17); sức khỏe đo được nằm ở
-- kết quả Prober, không ở đây.
CREATE TABLE relay_regions (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    code           text        NOT NULL CHECK (code ~ '^[a-z0-9][a-z0-9-]{0,62}$'),  -- region_code, ví dụ mg-<slug>
    name           text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind           text        NOT NULL CHECK (kind IN ('embedded', 'standalone', 'shared')),
    derp_region_id integer     NOT NULL CHECK (derp_region_id BETWEEN 900 AND 999),
    hostname       text        NOT NULL CHECK (hostname ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    ipv4           inet        CHECK (family(ipv4) = 4 AND masklen(ipv4) = 32),
    ipv6           inet        CHECK (family(ipv6) = 6 AND masklen(ipv6) = 128),
    stun_port      integer     CHECK (stun_port BETWEEN 1 AND 65535),
    derp_port      integer     NOT NULL DEFAULT 443 CHECK (derp_port BETWEEN 1 AND 65535),
    verify_mode    text        NOT NULL CHECK (verify_mode IN ('in_process', 'verify_url')),
    host_id        uuid        REFERENCES hosts (id),
    tenant_id      uuid        REFERENCES tenants (id),
    status         text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disabled')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    version        bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK ((kind = 'shared') = (tenant_id IS NULL)),            -- embedded/standalone ⇒ tenant_id NOT NULL (§6.3)
    CHECK (kind <> 'embedded' OR verify_mode = 'in_process'),
    UNIQUE NULLS NOT DISTINCT (tenant_id, code),
    UNIQUE (tenant_id, id)
);

-- Gán region cho instance. FK ghép (tenant_id, relay_region_id) → relay_regions (tenant_id, id): ở MVP một instance chỉ
-- được gán region của CHÍNH tenant của nó — region shared (tenant_id NULL) không gán được; mở gán region dùng chung
-- (Phase 7, §10.5) cần migration riêng.
CREATE TABLE relay_assignments (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    instance_id     uuid        NOT NULL,
    relay_region_id uuid        NOT NULL,
    priority        smallint    NOT NULL DEFAULT 0 CHECK (priority >= 0),
    status          text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disabled')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (instance_id, relay_region_id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, instance_id) REFERENCES tenant_instances (tenant_id, id),
    FOREIGN KEY (tenant_id, relay_region_id) REFERENCES relay_regions (tenant_id, id)
);

-- ---------------------------------------------------------------- RLS (T+P)
ALTER TABLE relay_regions ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_regions FORCE ROW LEVEL SECURITY;
CREATE POLICY relay_regions_tenant ON relay_regions TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY relay_regions_platform ON relay_regions TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE relay_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY relay_assignments_tenant ON relay_assignments TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY relay_assignments_platform ON relay_assignments TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

-- ---------------------------------------------------------------- quyền bảng
-- Đọc: mọi pool (GET /tenants/{t}/relay qua pool tenant — RLS; GET /platform/relay-regions qua pool platform). Ghi: chỉ
-- pool platform của worker (bước relay.assign + compensation "xóa hàng" — §11.3 bước 17); api chưa ghi (P7-T04).
-- code, kind, derp_region_id, verify_mode, host_id, tenant_id của region và instance/region/tenant của assignment bất
-- biến (đổi = xóa và tạo lại — region_id đổi buộc render lại config instance).
REVOKE ALL ON relay_regions, relay_assignments FROM PUBLIC;
GRANT SELECT ON relay_regions, relay_assignments TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT, DELETE ON relay_regions, relay_assignments TO mg_worker_platform;
GRANT UPDATE (name, hostname, ipv4, ipv6, stun_port, derp_port, status, updated_at, version)
    ON relay_regions TO mg_worker_platform;
GRANT UPDATE (priority, status, updated_at) ON relay_assignments TO mg_worker_platform;
