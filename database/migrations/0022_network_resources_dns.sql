-- 0022 — Network Resource Catalog và extra DNS records (bản đồ migration §6.3, P4-T05): network_resources, dns_records
-- (cả hai T — bảng nội bộ tenant).
-- Người dùng: module network (P4-T12 — resource catalog, DNS records ghi extra-records.json qua Agent, không restart),
-- renderer của policy.apply (P4-T10: khóa `hosts` render từ network_resources; đổi catalog ⇒ trigger resource_change).
-- Forward-only, expand-only.

-- +goose Up

-- ---------------------------------------------------------------- network_resources (T)
-- name render thành alias của khóa `hosts` trong policy (§7.2): chữ thường, số, gạch nối (không ký tự cần escape,
-- không trùng khác hoa thường). address là prefix (Headscale `hosts` chỉ nhận IP/prefix, không nhận tên DNS): host và
-- service là đúng một địa chỉ (/32, /128), subnet là prefix ngắn hơn; không có prefix độ dài 0 (cả Internet — L4 là việc
-- của exit node/route, không của catalog). ports: danh sách cổng/dải "443", "8000-8100" (rỗng = mọi cổng); không đi với
-- icmp; service phải khai báo ít nhất một cổng. protocol NULL = mọi giao thức. tags theo định dạng tenant_tags.name,
-- thuộc danh mục — kiểm ở service (P4-T15); hai mảng được kiểm trên dạng văn bản như enrollment_requests.requested_tags
-- (0020). owner_group_id: group của chính tenant chịu trách nhiệm tài nguyên (không
-- ON DELETE — xóa group còn sở hữu tài nguyên bị từ chối). version = khóa lạc quan (If-Match — §6.1).
CREATE TABLE network_resources (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid        NOT NULL REFERENCES tenants (id),
    name           text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
    kind           text        NOT NULL CHECK (kind IN ('host', 'subnet', 'service')),
    address        cidr        NOT NULL CHECK (masklen(address) > 0),
    ports          text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(ports) <= 64
        AND ports::text ~ '^\{([0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*)?\}$'),
    protocol       text        CHECK (protocol IN ('tcp', 'udp', 'icmp')),
    tags           text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 64
        AND tags::text ~ '^\{(tag:[a-z][a-z0-9-]{0,49}(,tag:[a-z][a-z0-9-]{0,49})*)?\}$'),
    owner_group_id uuid,
    description    text        CHECK (length(description) <= 1000),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    version        bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK ((kind = 'subnet') = (masklen(address) < CASE family(address) WHEN 4 THEN 32 ELSE 128 END)),
    CHECK (cardinality(ports) = 0 OR protocol IS DISTINCT FROM 'icmp'),
    CHECK (kind <> 'service' OR cardinality(ports) > 0),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, owner_group_id) REFERENCES groups (tenant_id, id)
);
CREATE INDEX network_resources_owner_group_idx ON network_resources (tenant_id, owner_group_id)
    WHERE owner_group_id IS NOT NULL;

-- ---------------------------------------------------------------- dns_records (T)
-- Extra DNS records của tenant (Headscale dns.extra_records_path — file extra-records.json do Agent ghi atomically,
-- §14.2): name là FQDN chữ thường (≥ 2 nhãn, mỗi nhãn ≤ 63, tổng ≤ 253, không wildcard); A ⇔ IPv4 đơn, AAAA ⇔ IPv6
-- đơn. Bản ghi chỉ tạo/xóa (không sửa — không có version). created_by: tham chiếu actor, không FK (như audit — §6.1).
CREATE TABLE dns_records (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id  uuid        NOT NULL REFERENCES tenants (id),
    name       text        NOT NULL CHECK (length(name) <= 253
        AND name ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    type       text        NOT NULL CHECK (type IN ('A', 'AAAA')),
    value      inet        NOT NULL,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (CASE type WHEN 'A' THEN family(value) = 4 AND masklen(value) = 32
                     ELSE family(value) = 6 AND masklen(value) = 128 END),
    UNIQUE (tenant_id, name, type, value),
    UNIQUE (tenant_id, id)
);

-- ---------------------------------------------------------------- RLS (T: không nhánh platform — §6.1)
ALTER TABLE network_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY network_resources_tenant ON network_resources TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE dns_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_records FORCE ROW LEVEL SECURITY;
CREATE POLICY dns_records_tenant ON dns_records TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

-- ---------------------------------------------------------------- quyền
-- Chỉ role tenant (bảng T). api: CRUD catalog, tạo/xóa bản ghi DNS (P4-T12). worker: đọc — policy.apply render `hosts`
-- (P4-T10), job ghi extra-records.json qua Agent. id, tenant_id, created_at bất biến; dns_records không có UPDATE.
REVOKE ALL ON network_resources, dns_records FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON network_resources, dns_records TO mg_api_tenant;
GRANT UPDATE (name, kind, address, ports, protocol, tags, owner_group_id, description, updated_at, version)
    ON network_resources TO mg_api_tenant;
GRANT SELECT ON network_resources, dns_records TO mg_worker_tenant;
