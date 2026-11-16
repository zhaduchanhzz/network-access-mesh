-- 0003 — SecretStore mặc định (bản đồ migration §6.3, §7.6): tenant_keys (DEK của tenant và của nền tảng),
-- secrets (ciphertext; bảng nghiệp vụ chỉ giữ reference mgsec://…). Chỉ module secrets dùng (P2-T04).
-- Forward-only.
--
-- Policy theo ROLE (§6.1): các role mg_api_* không thấy DEK phạm vi platform_ops và secret dùng DEK đó — policy
-- RESTRICTIVE trên cột scope. secrets.scope (không có trong danh sách cột của §6.3) là bản sao scope của DEK,
-- ràng buộc bằng FK ghép (dek_id, scope) → tenant_keys(id, scope): policy không thể tra tenant_keys bằng truy vấn
-- con vì truy vấn con cũng bị RLS lọc theo chính role đang bị ẩn.

-- +goose Up

CREATE TABLE tenant_keys (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    scope        text        NOT NULL CHECK (scope IN ('tenant', 'platform', 'platform_ops')),
    tenant_id    uuid        REFERENCES tenants (id),
    version      integer     NOT NULL CHECK (version > 0),
    wrapped_dek  bytea,      -- NULL sau khi hủy (crypto-shredding)
    wrap_nonce   bytea,
    kek_id       text        NOT NULL,
    state        text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired', 'destroyed')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    destroyed_at timestamptz,
    CHECK ((scope = 'tenant') = (tenant_id IS NOT NULL)),
    CHECK ((state = 'destroyed') = (destroyed_at IS NOT NULL)),
    CHECK (state = 'destroyed' OR (wrapped_dek IS NOT NULL AND wrap_nonce IS NOT NULL)),
    -- AAD khi bọc DEK = scope|tenant_id|version ⇒ không hoán đổi được wrapped DEK giữa các tenant (§7.6)
    UNIQUE NULLS NOT DISTINCT (scope, tenant_id, version),
    UNIQUE (id, scope),
    UNIQUE (tenant_id, id)
);
-- Một DEK hiện hành cho mỗi (scope, tenant); khi xoay: chuyển bản cũ sang retired trước rồi mới chèn bản mới.
CREATE UNIQUE INDEX tenant_keys_one_active ON tenant_keys (scope, tenant_id) NULLS NOT DISTINCT WHERE state = 'active';

CREATE TABLE secrets (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid        REFERENCES tenants (id),
    scope        text        NOT NULL CHECK (scope IN ('tenant', 'platform', 'platform_ops')),
    name         text        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    version      integer     NOT NULL CHECK (version > 0),
    ciphertext   bytea,      -- NULL sau khi hủy
    nonce        bytea,
    aad          bytea       NOT NULL,  -- tenant_id|name|version (§7.6)
    dek_id       uuid        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    destroyed_at timestamptz,
    CHECK ((scope = 'tenant') = (tenant_id IS NOT NULL)),
    CHECK (destroyed_at IS NOT NULL OR (ciphertext IS NOT NULL AND nonce IS NOT NULL)),
    -- hàng platform có tenant_id NULL vẫn bị ràng buộc (cần PostgreSQL ≥ 15)
    UNIQUE NULLS NOT DISTINCT (tenant_id, name, version),
    FOREIGN KEY (dek_id, scope) REFERENCES tenant_keys (id, scope),
    FOREIGN KEY (tenant_id, dek_id) REFERENCES tenant_keys (tenant_id, id)  -- DEK của đúng tenant
);

-- ---------------------------------------------------------------- RLS (T+P + ẩn platform_ops khỏi mg_api_*)
ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_keys_tenant ON tenant_keys TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY tenant_keys_platform ON tenant_keys TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());
CREATE POLICY tenant_keys_hide_platform_ops ON tenant_keys AS RESTRICTIVE TO mg_api_tenant, mg_api_platform
    USING (scope <> 'platform_ops') WITH CHECK (scope <> 'platform_ops');

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY secrets_tenant ON secrets TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY secrets_platform ON secrets TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());
CREATE POLICY secrets_hide_platform_ops ON secrets AS RESTRICTIVE TO mg_api_tenant, mg_api_platform
    USING (scope <> 'platform_ops') WITH CHECK (scope <> 'platform_ops');

-- ---------------------------------------------------------------- quyền bảng
-- id, scope, tenant_id, version, created_at bất biến. Hủy = UPDATE (xóa wrapped_dek/ciphertext), không DELETE.
REVOKE ALL ON tenant_keys, secrets FROM PUBLIC;
GRANT SELECT, INSERT ON tenant_keys, secrets TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT UPDATE (wrapped_dek, wrap_nonce, kek_id, state, destroyed_at)
    ON tenant_keys TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT UPDATE (ciphertext, nonce, aad, dek_id, expires_at, destroyed_at)
    ON secrets TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
