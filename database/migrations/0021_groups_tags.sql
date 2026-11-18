-- 0021 — Nhóm người dùng và danh mục tag của tenant (bản đồ migration §6.3, P4-T05; mô hình policy §7.2): groups,
-- group_members, tenant_tags (cả ba T — bảng nội bộ tenant).
-- Người dùng: groups + thành viên (P4-T09 — đổi thành viên ⇒ policy.apply trigger group_change; group sensitive đi qua
-- approval_requests phạm vi tenant, cờ sensitive nằm ở TenantSettings.policy.sensitive_groups — §13.3, không ở bảng),
-- danh mục tag (P4-T15 — nguồn render tagOwners, đích của tag_id trong policy, đổi danh mục ⇒ trigger tag_change),
-- renderer của policy.apply (P4-T10: groups/tagOwners render từ hai bảng này lúc áp dụng). Forward-only, expand-only.

-- +goose Up

-- ---------------------------------------------------------------- groups (T)
-- name render thành khóa `group:<name>` của policy (§7.2): chỉ chữ thường, số, gạch nối — không trùng khác hoa thường,
-- không ký tự nào cần escape trong HuJSON. Policy tham chiếu group bằng group_id (principal có kiểu), nên đổi tên chỉ đổi
-- chuỗi render. source: portal = quản lý trong Portal (MVP); idp = dành cho đồng bộ nhóm từ IdP (chưa có task — không
-- module nào ghi giá trị này ở MVP). version = khóa lạc quan (If-Match — §6.1).
CREATE TABLE groups (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    name        text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,49}$'),
    description text        CHECK (length(description) <= 1000),
    source      text        NOT NULL DEFAULT 'portal' CHECK (source IN ('portal', 'idp')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    version     bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);

-- Thành viên = membership của CHÍNH tenant (FK ghép). Xóa group xóa luôn danh sách thành viên của nó; membership không
-- tự rời group khi bị xóa (không ON DELETE) — việc gỡ thành viên phải đi qua module members để sinh một lần policy.apply
-- (offboard là khóa membership, không xóa — §13.2 users).
CREATE TABLE group_members (
    tenant_id     uuid        NOT NULL REFERENCES tenants (id),
    group_id      uuid        NOT NULL,
    membership_id uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, membership_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, membership_id) REFERENCES tenant_memberships (tenant_id, id)
);
CREATE INDEX group_members_membership_idx ON group_members (tenant_id, membership_id);  -- các group của một thành viên

-- ---------------------------------------------------------------- tenant_tags (T)
-- Danh mục tag (§6.3): mọi tag được tham chiếu (policy, PUT /devices/{id}/tags, requested_tags của enrollment, tags của
-- network_resources) phải có ở đây — kiểm ở service; render tagOwners với danh sách owner rỗng (§7.2, L12). name bất biến
-- (thiết bị đã gắn tag ở Headscale mang đúng chuỗi này); purpose bất biến (router/exit là tag nền tảng kiểm soát cho
-- autoApprovers — §7.2). platform_managed = tag do nền tảng tạo và quản lý: role api tenant không tạo, sửa hay xóa được
-- (policy RESTRICTIVE bên dưới). Không xóa được khi còn thiết bị, key hoặc grant tham chiếu — kiểm ở service (409).
CREATE TABLE tenant_tags (
    id               uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id        uuid        NOT NULL REFERENCES tenants (id),
    name             text        NOT NULL CHECK (name ~ '^tag:[a-z][a-z0-9-]{0,49}$'),
    purpose          text        NOT NULL DEFAULT 'custom' CHECK (purpose IN ('router', 'exit', 'server', 'custom')),
    platform_managed boolean     NOT NULL DEFAULT false,
    description      text        CHECK (length(description) <= 1000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    version          bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);

-- ---------------------------------------------------------------- RLS (T: không nhánh platform — §6.1)
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_tenant ON groups TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY group_members_tenant ON group_members TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE tenant_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_tags FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_tags_tenant ON tenant_tags TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
-- Tag do nền tảng quản lý: api tenant không chèn, sửa, xóa được (RESTRICTIVE — AND với policy trên; đọc vẫn được).
CREATE POLICY tenant_tags_api_insert_unmanaged ON tenant_tags AS RESTRICTIVE FOR INSERT TO mg_api_tenant
    WITH CHECK (NOT platform_managed);
CREATE POLICY tenant_tags_api_update_unmanaged ON tenant_tags AS RESTRICTIVE FOR UPDATE TO mg_api_tenant
    USING (NOT platform_managed) WITH CHECK (NOT platform_managed);
CREATE POLICY tenant_tags_api_delete_unmanaged ON tenant_tags AS RESTRICTIVE FOR DELETE TO mg_api_tenant
    USING (NOT platform_managed);

-- ---------------------------------------------------------------- quyền
-- Chỉ role tenant (bảng T). api: CRUD (P4-T09 groups, P4-T15 tags). worker: đọc — job policy.apply render groups và
-- tagOwners (P4-T10). id, tenant_id, created_at bất biến; groups.source, tenant_tags.name/purpose/platform_managed bất
-- biến; group_members chỉ chèn/xóa.
REVOKE ALL ON groups, group_members, tenant_tags FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON groups, group_members, tenant_tags TO mg_api_tenant;
GRANT UPDATE (name, description, updated_at, version) ON groups TO mg_api_tenant;
GRANT UPDATE (description, updated_at, version) ON tenant_tags TO mg_api_tenant;
GRANT SELECT ON groups, group_members, tenant_tags TO mg_worker_tenant;
