-- 0001 — Registry (bản đồ migration §6.3): extension, DB roles, helper RLS app_tenant_id()/app_is_platform(),
-- tenants, hosts, tenant_instances, instance_config_versions, system_settings.
--
-- Chạy bằng mg_migrator (CREATEROLE, không superuser) sau bootstrap database/bootstrap/superuser.sql.
-- Forward-only (§6.1): không có phần Down — rollback = restore dump lấy trước migration (P2-T03a) hoặc migration bù.
-- Không có mật khẩu nào ở đây: role đăng nhập được tạo KHÔNG mật khẩu (không đăng nhập được) cho tới khi bước
-- triển khai đặt mật khẩu từ file secret (database/README.md).

-- +goose Up

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;

-- ---------------------------------------------------------------- DB roles (§6.1)
-- Hai role nhóm NOLOGIN mang policy RLS; bốn role đăng nhập theo tiến trình × phạm vi, mỗi role thuộc đúng MỘT
-- nhóm; mg_readonly chỉ dành cho view báo cáo trong schema report. Tạo idempotent (role là đối tượng của cả cụm:
-- database khác trong cùng cụm có thể đã tạo). Role đã tồn tại với thuộc tính nguy hiểm ⇒ migration thất bại.
-- +goose StatementBegin
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('mg_app_tenant', false), ('mg_app_platform', false),
      ('mg_api_tenant', true), ('mg_worker_tenant', true),
      ('mg_api_platform', true), ('mg_worker_platform', true),
      ('mg_readonly', true)) AS t(rolname, can_login)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.rolname) THEN
      EXECUTE format('CREATE ROLE %I %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',
                     r.rolname, CASE WHEN r.can_login THEN 'LOGIN' ELSE 'NOLOGIN' END);
    ELSIF EXISTS (SELECT 1 FROM pg_roles
                  WHERE rolname = r.rolname
                    AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
                         OR rolcanlogin <> r.can_login)) THEN
      RAISE EXCEPTION 'role % đã tồn tại với thuộc tính không mong đợi', r.rolname;
    END IF;
  END LOOP;
END
$$;
-- +goose StatementEnd

GRANT mg_app_tenant TO mg_api_tenant, mg_worker_tenant;
GRANT mg_app_platform TO mg_api_platform, mg_worker_platform;

-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1
             FROM unnest(ARRAY['mg_api_tenant', 'mg_worker_tenant', 'mg_api_platform', 'mg_worker_platform']) AS r(n)
             WHERE pg_has_role(r.n, 'mg_app_tenant', 'MEMBER') = pg_has_role(r.n, 'mg_app_platform', 'MEMBER')) THEN
    RAISE EXCEPTION 'mỗi role đăng nhập của ứng dụng phải thuộc đúng một trong mg_app_tenant / mg_app_platform';
  END IF;
  IF pg_has_role('mg_readonly', 'mg_app_tenant', 'MEMBER') OR pg_has_role('mg_readonly', 'mg_app_platform', 'MEMBER') THEN
    RAISE EXCEPTION 'mg_readonly không được thuộc role nhóm của ứng dụng';
  END IF;
  -- Database: chỉ role được liệt kê mới CONNECT; không ai ngoài owner được TEMPORARY (không DDL — §6.1).
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO mg_app_tenant, mg_app_platform, mg_readonly', current_database());
END
$$;
-- +goose StatementEnd

-- Schema public: không role nào ngoài owner được CREATE; mg_readonly không có USAGE (chỉ thấy schema report).
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO mg_app_tenant, mg_app_platform;

CREATE SCHEMA report;
COMMENT ON SCHEMA report IS 'View/bảng tổng hợp phục vụ báo cáo — nơi duy nhất mg_readonly đọc được (§6.1); view đầu tiên đến cùng bảng tổng hợp ở 0016 (P6-T11)';
GRANT USAGE ON SCHEMA report TO mg_readonly;

-- ---------------------------------------------------------------- helper RLS (§6.1)
-- Không ép kiểu thẳng current_setting(...)::uuid: trên kết nối pool đã từng SET LOCAL, biến còn lại là chuỗi rỗng.
-- Thân hàm dạng SQL chuẩn (RETURN …) được phân tích lúc tạo ⇒ không phụ thuộc search_path lúc chạy.
CREATE FUNCTION app_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN NULLIF(current_setting('app.tenant_id', true), '')::uuid;

CREATE FUNCTION app_is_platform() RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN COALESCE(current_setting('app.scope', true), '') = 'platform';

REVOKE ALL ON FUNCTION app_tenant_id(), app_is_platform() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_tenant_id(), app_is_platform() TO mg_app_tenant, mg_app_platform;

-- ---------------------------------------------------------------- bảng
-- Quy ước: khóa chính uuidv7() (PostgreSQL 18); enum là text + CHECK khi §6.3 đã chốt tập giá trị (chưa chốt ⇒
-- chưa CHECK, task của module bổ sung); hash dùng để tra cứu là bytea 32 byte; secret chỉ ở dạng reference
-- mgsec://<tenant_id|platform>/<name>#<version> (§6.1); version = bộ đếm khóa lạc quan (ETag).

CREATE TABLE tenants (
    id                        uuid        PRIMARY KEY DEFAULT uuidv7(),
    slug                      citext      NOT NULL CHECK (slug::text ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    name                      text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    status                    text        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'provisioning', 'active', 'suspended', 'deprovisioning', 'deleted', 'failed')),
    deployment_region         text,
    settings                  jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(settings) = 'object'),
    desired_policy_version_id uuid,  -- FK thêm ở 0011 (policy_versions)
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now(),
    deleted_at                timestamptz,
    version                   bigint      NOT NULL DEFAULT 1 CHECK (version > 0)
);
-- slug của tenant đã xóa chỉ được dùng lại khi không còn object nào của instance cũ (§11.4)
CREATE UNIQUE INDEX tenants_slug_live_key ON tenants (slug) WHERE status <> 'deleted';

CREATE TABLE hosts (
    id                uuid        PRIMARY KEY DEFAULT uuidv7(),
    name              text        NOT NULL UNIQUE,
    region            text        NOT NULL,
    agent_endpoint    text,
    agent_identity    text,
    status            text        NOT NULL DEFAULT 'active',  -- tập giá trị chốt ở P3-T04
    capacity          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(capacity) = 'object'),
    public_entry      jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(public_entry) = 'object'),
    run_uid_range     int4range   NOT NULL CHECK (NOT isempty(run_uid_range) AND lower(run_uid_range) > 0),
    stun_port_range   int4range,
    tenant_net_pool   cidr        NOT NULL,
    last_heartbeat_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_instances (
    id                    uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id             uuid        NOT NULL REFERENCES tenants (id),
    host_id               uuid        NOT NULL REFERENCES hosts (id),
    status                text        NOT NULL DEFAULT 'allocated'
        CHECK (status IN ('allocated', 'starting', 'running', 'stopped', 'failed', 'removed', 'quarantined')),
    headscale_version     text        NOT NULL,
    image_digest          text        NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    control_hostname      text        NOT NULL,
    server_url            text        NOT NULL,
    base_domain           text        NOT NULL,
    internal_address      text        NOT NULL,
    stun_port             integer     CHECK (stun_port BETWEEN 1 AND 65535),  -- NULL khi dùng STUN chung
    derp_region_id        integer,
    config_version_id     uuid,       -- FK ghép thêm sau khi tạo instance_config_versions (bên dưới)
    api_key_secret_ref    text        CHECK (api_key_secret_ref ~ '^mgsec://[^/]+/[^#]+#[0-9]+$'),
    api_key_prefix        text,
    api_key_expires_at    timestamptz,
    noise_key_fingerprint text,
    run_uid               integer     NOT NULL CHECK (run_uid > 0),
    net_cidr              cidr        NOT NULL,
    data_path             text        NOT NULL,
    last_health_at        timestamptz,
    last_health           jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    version               bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (tenant_id, id),
    UNIQUE (host_id, run_uid)  -- UID không tái sử dụng, kể cả sau khi instance removed
);
CREATE UNIQUE INDEX tenant_instances_hostname_live_key ON tenant_instances (control_hostname) WHERE status <> 'removed';
CREATE UNIQUE INDEX tenant_instances_stun_port_live_key ON tenant_instances (host_id, stun_port)
    WHERE stun_port IS NOT NULL AND status <> 'removed';
CREATE UNIQUE INDEX tenant_instances_one_live_per_tenant ON tenant_instances (tenant_id) WHERE status <> 'removed';
CREATE UNIQUE INDEX tenant_instances_net_live_key ON tenant_instances (host_id, net_cidr) WHERE status <> 'removed';

CREATE TABLE instance_config_versions (
    id               uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id        uuid        NOT NULL,
    instance_id      uuid        NOT NULL,
    version          integer     NOT NULL CHECK (version > 0),
    template_version text        NOT NULL,
    params           jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object'),
    rendered_config  text        NOT NULL,  -- không chứa secret (§6.3)
    config_sha256    text        NOT NULL CHECK (config_sha256 ~ '^[0-9a-f]{64}$'),
    status           text        NOT NULL DEFAULT 'rendered',  -- tập giá trị chốt ở P3-T06
    created_by       uuid,       -- tham chiếu actor, không FK (như audit — §6.1)
    created_at       timestamptz NOT NULL DEFAULT now(),
    applied_at       timestamptz,
    UNIQUE (instance_id, version),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, instance_id) REFERENCES tenant_instances (tenant_id, id)
);

ALTER TABLE tenant_instances
    ADD CONSTRAINT tenant_instances_config_version_fkey
    FOREIGN KEY (tenant_id, config_version_id) REFERENCES instance_config_versions (tenant_id, id);

CREATE TABLE system_settings (
    key        text        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.]{0,99}$'),
    value      jsonb       NOT NULL,
    updated_by uuid,
    updated_at timestamptz NOT NULL DEFAULT now(),
    version    bigint      NOT NULL DEFAULT 1 CHECK (version > 0)
);

-- ---------------------------------------------------------------- RLS (§6.1, ký hiệu ở §6.3)
-- tenants (T+P, so cột id) · hosts (P) · tenant_instances (T+P) · instance_config_versions (T+P) · system_settings (P)
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_tenant ON tenants TO mg_app_tenant
    USING (id = app_tenant_id()) WITH CHECK (id = app_tenant_id());
CREATE POLICY tenants_platform ON tenants TO mg_app_platform
    USING (id = app_tenant_id() OR app_is_platform()) WITH CHECK (id = app_tenant_id() OR app_is_platform());

ALTER TABLE hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY hosts_platform ON hosts TO mg_app_platform
    USING (app_is_platform()) WITH CHECK (app_is_platform());

ALTER TABLE tenant_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_instances_tenant ON tenant_instances TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY tenant_instances_platform ON tenant_instances TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE instance_config_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE instance_config_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY instance_config_versions_tenant ON instance_config_versions TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY instance_config_versions_platform ON instance_config_versions TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY system_settings_platform ON system_settings TO mg_app_platform
    USING (app_is_platform()) WITH CHECK (app_is_platform());

-- ---------------------------------------------------------------- quyền bảng (theo tiến trình — §6.1)
-- Ma trận khởi đầu cho các luồng của Phase 2; task của từng module thu hẹp/bổ sung bằng migration của nó.
-- Chỉ GRANT tường minh (không default privileges); không bao giờ TRUNCATE; cột bất biến không có quyền UPDATE.
REVOKE ALL ON tenants, hosts, tenant_instances, instance_config_versions, system_settings FROM PUBLIC;

GRANT SELECT ON tenants TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON tenants TO mg_api_platform, mg_worker_platform;
GRANT UPDATE (name, status, deployment_region, settings, desired_policy_version_id, updated_at, deleted_at, version)
    ON tenants TO mg_api_platform, mg_worker_platform;

GRANT SELECT, INSERT ON hosts TO mg_api_platform, mg_worker_platform;
GRANT UPDATE (region, agent_endpoint, agent_identity, status, capacity, public_entry, run_uid_range, stun_port_range,
              tenant_net_pool, last_heartbeat_at, updated_at)
    ON hosts TO mg_api_platform, mg_worker_platform;

GRANT SELECT ON tenant_instances TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON tenant_instances TO mg_api_platform, mg_worker_platform;
GRANT UPDATE (status, headscale_version, image_digest, server_url, base_domain, internal_address, stun_port,
              derp_region_id, config_version_id, api_key_secret_ref, api_key_prefix, api_key_expires_at,
              noise_key_fingerprint, last_health_at, last_health, updated_at, version)
    ON tenant_instances TO mg_api_platform, mg_worker_platform;

GRANT SELECT ON instance_config_versions TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON instance_config_versions TO mg_api_platform, mg_worker_platform;
GRANT UPDATE (status, applied_at) ON instance_config_versions TO mg_api_platform, mg_worker_platform;

GRANT SELECT, INSERT ON system_settings TO mg_api_platform, mg_worker_platform;
GRANT UPDATE (value, updated_by, updated_at, version) ON system_settings TO mg_api_platform, mg_worker_platform;
