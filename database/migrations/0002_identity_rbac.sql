-- 0002 — Identity & RBAC (bản đồ migration §6.3): identity_providers, identities, platform_users, tenant_memberships,
-- roles/permissions/role_permissions, sessions, auth_requests.
-- Issuer binding và scope của role dùng FK ghép, không dùng trigger (§6.3, P2-T07). Forward-only.

-- +goose Up

-- ---------------------------------------------------------------- RBAC (bảng tham chiếu toàn cục — RLS "—")
-- Seed role/permission từ code ở P2-T07. roles.scope ∈ {platform, tenant}; role_permissions.scope ∈ {any, own}
-- (own = ô ○ của §8.6).
CREATE TABLE roles (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    scope      text        NOT NULL CHECK (scope IN ('platform', 'tenant')),
    key        text        NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,63}$'),
    name       text        NOT NULL,
    is_system  boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope, key),
    UNIQUE (id, scope)  -- đích FK ghép kiểm scope của role
);

CREATE TABLE permissions (
    key         text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    scope       text NOT NULL CHECK (scope IN ('platform', 'tenant')),
    description text NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_id        uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_key text NOT NULL REFERENCES permissions (key),
    scope          text NOT NULL DEFAULT 'any' CHECK (scope IN ('any', 'own')),
    PRIMARY KEY (role_id, permission_key)
);

-- ---------------------------------------------------------------- IdP và danh tính
CREATE TABLE identity_providers (
    id                     uuid        PRIMARY KEY DEFAULT uuidv7(),
    scope                  text        NOT NULL CHECK (scope IN ('platform', 'tenant')),
    tenant_id              uuid        REFERENCES tenants (id),
    issuer                 text        NOT NULL,
    client_id              text        NOT NULL,
    client_secret_ref      text        CHECK (client_secret_ref ~ '^mgsec://[^/]+/[^#]+#[0-9]+$'),
    required_claims        jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(required_claims) = 'object'),
    require_email_verified boolean     NOT NULL DEFAULT true,
    allowed_email_domains  text[]      NOT NULL DEFAULT '{}',
    claim_mapping          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(claim_mapping) = 'object'),
    driver                 text        NOT NULL CHECK (driver IN ('keycloak', 'external')),
    driver_ref             text,
    status                 text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'retiring', 'disabled')),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    version                bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK ((scope = 'platform') = (tenant_id IS NULL)),
    UNIQUE (issuer, client_id),  -- một issuer có thể phục vụ nhiều tổ chức (required_claims phân biệt)
    UNIQUE (id, scope),          -- đích FK ghép từ identities
    UNIQUE (id, tenant_id)       -- đích FK ghép từ identities (hàng tenant)
);
CREATE UNIQUE INDEX identity_providers_one_active_per_tenant ON identity_providers (tenant_id) WHERE status = 'active';

CREATE TABLE identities (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    idp_id         uuid        NOT NULL,
    tenant_id      uuid,       -- sao chép từ IdP; NULL ⇔ scope platform
    scope          text        NOT NULL CHECK (scope IN ('platform', 'tenant')),
    subject        text        NOT NULL,
    email          citext,
    email_verified boolean     NOT NULL DEFAULT false,
    display_name   text,
    status         text        NOT NULL DEFAULT 'active',  -- tập giá trị chốt ở P2-T06
    last_login_at  timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope = 'platform') = (tenant_id IS NULL)),
    UNIQUE (idp_id, subject),
    UNIQUE (tenant_id, id),
    UNIQUE (id, scope),
    FOREIGN KEY (idp_id, scope) REFERENCES identity_providers (id, scope),
    FOREIGN KEY (idp_id, tenant_id) REFERENCES identity_providers (id, tenant_id)  -- chỉ kiểm khi tenant_id NOT NULL
);

CREATE TABLE platform_users (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    identity_id    uuid        NOT NULL UNIQUE,
    identity_scope text        NOT NULL DEFAULT 'platform' CHECK (identity_scope = 'platform'),
    role_id        uuid        NOT NULL,
    role_scope     text        NOT NULL DEFAULT 'platform' CHECK (role_scope = 'platform'),
    status         text        NOT NULL DEFAULT 'active',  -- tập giá trị chốt ở P4-T03a
    created_by     uuid,       -- tham chiếu actor, không FK
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    version        bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    FOREIGN KEY (identity_id, identity_scope) REFERENCES identities (id, scope),
    FOREIGN KEY (role_id, role_scope) REFERENCES roles (id, scope)
);

CREATE TABLE tenant_memberships (
    id                 uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id          uuid        NOT NULL REFERENCES tenants (id),
    identity_id        uuid        NOT NULL,
    role_id            uuid        NOT NULL,
    role_scope         text        NOT NULL DEFAULT 'tenant' CHECK (role_scope = 'tenant'),
    status             text        NOT NULL DEFAULT 'active',  -- tập giá trị chốt ở P4-T09
    headscale_user_id  bigint      CHECK (headscale_user_id > 0),
    -- mg-<membership_uuid>: tính được trước khi Headscale user tồn tại (§6.3); sinh từ id nên bất biến
    headscale_username text        NOT NULL GENERATED ALWAYS AS ('mg-' || id::text) STORED,
    invited_by         uuid,       -- tham chiếu actor, không FK
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    version            bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, identity_id),
    UNIQUE (tenant_id, headscale_username),
    -- issuer binding khai báo: identity phải thuộc cùng tenant (identities.tenant_id sao chép từ IdP)
    FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
    FOREIGN KEY (role_id, role_scope) REFERENCES roles (id, scope)
);
CREATE UNIQUE INDEX tenant_memberships_hs_user_key ON tenant_memberships (tenant_id, headscale_user_id)
    WHERE headscale_user_id IS NOT NULL;

-- ---------------------------------------------------------------- phiên đăng nhập (RLS "—": chỉ module identity, pool platform)
CREATE TABLE sessions (
    id_hash             bytea       PRIMARY KEY CHECK (octet_length(id_hash) = 32),  -- chỉ lưu hash của session id
    public_id           uuid        NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    identity_id         uuid        NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    idp_id              uuid        NOT NULL REFERENCES identity_providers (id),
    origin              text        NOT NULL CHECK (origin IN ('app', 'admin')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    auth_time           timestamptz NOT NULL,
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    ip                  inet,
    user_agent          text,
    acr                 text,
    amr                 text[]      NOT NULL DEFAULT '{}',
    revoked_at          timestamptz
);
CREATE INDEX sessions_identity_live_idx ON sessions (identity_id) WHERE revoked_at IS NULL;

CREATE TABLE auth_requests (
    state_hash           bytea       PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    idp_id               uuid        NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    tenant_id            uuid,
    scope                text        NOT NULL CHECK (scope IN ('platform', 'tenant')),
    origin               text        NOT NULL CHECK (origin IN ('app', 'admin')),
    nonce                text        NOT NULL,
    pkce_verifier_enc    bytea       NOT NULL,
    return_to            text,
    browser_binding_hash bytea       NOT NULL CHECK (octet_length(browser_binding_hash) = 32),
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,
    consumed_at          timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    CHECK ((scope = 'platform') = (tenant_id IS NULL)),
    FOREIGN KEY (idp_id, scope) REFERENCES identity_providers (id, scope),
    FOREIGN KEY (idp_id, tenant_id) REFERENCES identity_providers (id, tenant_id)
);

-- ---------------------------------------------------------------- RLS
-- identity_providers (T+P) · identities (T+P) · platform_users (P) · tenant_memberships (T)
ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_providers_tenant ON identity_providers TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY identity_providers_platform ON identity_providers TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE identities FORCE ROW LEVEL SECURITY;
CREATE POLICY identities_tenant ON identities TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY identities_platform ON identities TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE platform_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_users FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_users_platform ON platform_users TO mg_app_platform
    USING (app_is_platform()) WITH CHECK (app_is_platform());

-- Bảng nội bộ tenant: không có nhánh platform (§6.1 "Platform scope").
ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_memberships_tenant ON tenant_memberships TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

-- ---------------------------------------------------------------- quyền bảng
REVOKE ALL ON roles, permissions, role_permissions, identity_providers, identities, platform_users,
              tenant_memberships, sessions, auth_requests FROM PUBLIC;

-- RBAC: chỉ đọc (seed chạy bằng mg_migrator ở P2-T07).
GRANT SELECT ON roles, permissions, role_permissions TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;

-- issuer, client_id, driver, tenant_id, scope bất biến (§6.3, §13.2).
GRANT SELECT ON identity_providers TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON identity_providers TO mg_api_platform, mg_worker_platform;
GRANT UPDATE (client_secret_ref, required_claims, require_email_verified, allowed_email_domains, claim_mapping,
              driver_ref, status, updated_at, version)
    ON identity_providers TO mg_api_platform, mg_worker_platform;

-- idp_id, tenant_id, scope, subject bất biến: role ứng dụng không có quyền UPDATE trên các cột này (§6.3).
GRANT SELECT ON identities TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON identities TO mg_api_platform;
GRANT UPDATE (email, email_verified, display_name, status, last_login_at, updated_at)
    ON identities TO mg_api_platform;

GRANT SELECT ON platform_users TO mg_api_platform, mg_worker_platform;
GRANT INSERT, UPDATE (role_id, status, updated_at, version) ON platform_users TO mg_api_platform;

GRANT SELECT, INSERT ON tenant_memberships TO mg_api_tenant, mg_worker_tenant;
GRANT UPDATE (role_id, status, headscale_user_id, updated_at, version) ON tenant_memberships TO mg_api_tenant, mg_worker_tenant;

-- sessions/auth_requests: chỉ pool platform (module identity phân giải session trong WithPlatformTx — §6.3);
-- worker (session.gc) chỉ đọc và xóa.
GRANT SELECT, INSERT, UPDATE ON sessions, auth_requests TO mg_api_platform;
GRANT SELECT, DELETE ON sessions, auth_requests TO mg_worker_platform;
