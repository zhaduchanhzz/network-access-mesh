-- 0012 — Gói & quota (bản đồ migration §6.3, P3-T06): subscription_plans (bảng tham chiếu toàn cục — RLS "—"),
-- subscriptions (T+P); hàm kiểm tài liệu PlanLimits (§13.3); giá trị khởi đầu của trần số tenant toàn nền tảng
-- (system_settings quota.max_tenants — §13.3). Gói mặc định nạp bằng seed database/seeds/plans.sql (chỉ chèn khi chưa có).
-- Người dùng: QuotaChecker (P3-T06a — bước validate của provisioning và enrollment), registry.create (§11.3 bước 2),
-- GET /tenants/{t}/billing (P6-T11), /platform/plans (P4-T03a). Forward-only, expand-only (một hàng system_settings
-- chèn khi chưa có; không ghi lại hàng nào).

-- +goose Up

-- ---------------------------------------------------------------- PlanLimits (§13.3)
-- mg_plan_limits_valid(limits, partial): object chỉ gồm khóa của PlanLimits; bốn khóa quota max_devices, max_users,
-- max_tagged_devices, max_live_enrollment_credentials là số nguyên 0…2147483647; backup_interval_minutes số nguyên
-- 1…2147483647; instance là object con của {cpus (số > 0, ≤ 1024), memory_mb, pids (số nguyên 1…2147483647)}.
-- partial = false (subscription_plans.limits): bắt buộc đủ bốn khóa quota — QuotaChecker không bao giờ phải đoán giá
-- trị thiếu; partial = true (subscriptions.overrides): khóa nào cũng tùy chọn, mỗi khóa có mặt ghi đè đúng khóa đó.
-- IMMUTABLE, search_path cố định (CHECK cũng chạy trong pg_restore với search_path rỗng). Role ghi bảng cần EXECUTE.
-- +goose StatementBegin
CREATE FUNCTION mg_plan_limits_valid(p_limits jsonb, p_partial boolean) RETURNS boolean
    LANGUAGE plpgsql
    IMMUTABLE PARALLEL SAFE
    SET search_path = pg_catalog
AS $$
DECLARE
  quota constant text[] := ARRAY['max_devices', 'max_users', 'max_tagged_devices', 'max_live_enrollment_credentials'];
  k     text;
  v     jsonb;
  ik    text;
  iv    jsonb;
  n     numeric;
BEGIN
  IF p_limits IS NULL OR p_partial IS NULL OR jsonb_typeof(p_limits) <> 'object' THEN
    RETURN false;
  END IF;
  IF NOT p_partial AND NOT (p_limits ?& quota) THEN
    RETURN false;
  END IF;
  FOR k, v IN SELECT e.key, e.value FROM jsonb_each(p_limits) AS e LOOP
    IF k = ANY (quota) OR k = 'backup_interval_minutes' THEN
      IF jsonb_typeof(v) <> 'number' THEN
        RETURN false;
      END IF;
      n := v::numeric;
      IF n <> trunc(n) OR n < 0 OR n > 2147483647 OR (k = 'backup_interval_minutes' AND n < 1) THEN
        RETURN false;
      END IF;
    ELSIF k = 'instance' THEN
      IF jsonb_typeof(v) <> 'object' THEN
        RETURN false;
      END IF;
      FOR ik, iv IN SELECT e.key, e.value FROM jsonb_each(v) AS e LOOP
        IF ik NOT IN ('cpus', 'memory_mb', 'pids') OR jsonb_typeof(iv) <> 'number' THEN
          RETURN false;
        END IF;
        n := iv::numeric;
        IF ik = 'cpus' THEN
          IF n <= 0 OR n > 1024 THEN
            RETURN false;
          END IF;
        ELSIF n <> trunc(n) OR n < 1 OR n > 2147483647 THEN
          RETURN false;
        END IF;
      END LOOP;
    ELSE
      RETURN false;  -- khóa ngoài PlanLimits: thêm khóa phải sửa §13.3, §6.3 và hàm này trước
    END IF;
  END LOOP;
  RETURN true;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION mg_plan_limits_valid(jsonb, boolean) FROM PUBLIC;

-- ---------------------------------------------------------------- subscription_plans ("—": bảng tham chiếu toàn cục)
-- key bất biến (TenantCreate.plan_key — §13.3). Gói chỉnh qua /platform/plans (P4-T03a) — seed không ghi đè gói đã có.
CREATE TABLE subscription_plans (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    key        text        NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_-]{0,62}$'),
    name       text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    limits     jsonb       NOT NULL CHECK (mg_plan_limits_valid(limits, false)),
    is_active  boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version    bigint      NOT NULL DEFAULT 1 CHECK (version > 0)
);

-- ---------------------------------------------------------------- subscriptions (T+P)
-- Một subscription còn hiệu lực (trialing/active/past_due) cho mỗi tenant; cancelled/expired là trạng thái cuối, giữ
-- lại làm lịch sử. overrides ghi đè từng khóa của limits (PlanLimits, partial). Hạn mức hiệu lực = limits của plan ⊕
-- overrides.
CREATE TABLE subscriptions (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid        NOT NULL REFERENCES tenants (id),
    plan_id      uuid        NOT NULL REFERENCES subscription_plans (id),
    status       text        NOT NULL DEFAULT 'active'
        CHECK (status IN ('trialing', 'active', 'past_due', 'cancelled', 'expired')),
    period_start timestamptz NOT NULL DEFAULT now(),
    period_end   timestamptz,  -- NULL = không thời hạn
    overrides    jsonb       NOT NULL DEFAULT '{}' CHECK (mg_plan_limits_valid(overrides, true)),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    version      bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (period_end IS NULL OR period_end > period_start),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX subscriptions_one_live_per_tenant ON subscriptions (tenant_id)
    WHERE status IN ('trialing', 'active', 'past_due');
CREATE INDEX subscriptions_plan_idx ON subscriptions (plan_id);

ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY subscriptions_tenant ON subscriptions TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY subscriptions_platform ON subscriptions TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

-- ---------------------------------------------------------------- quyền
-- plans: mọi tiến trình đọc (QuotaChecker); chỉ api platform ghi (/platform/plans); key bất biến.
-- subscriptions: mọi tiến trình đọc; api platform tạo (registry.create — §11.3 bước 2) và đổi plan/override/kỳ/trạng thái
-- (PATCH /platform/tenants/{id}); worker platform đổi trạng thái/kỳ (deprovision, hết hạn); tenant_id/plan bất biến với
-- worker. Role tenant chỉ có UPDATE (updated_at) để chạy được `SELECT … FOR UPDATE` trên hàng subscription của tenant
-- (khóa hạn mức enrollment — §7.4 bước 3; PostgreSQL đòi quyền UPDATE trên ≥ 1 cột cho mệnh đề khóa) — role tenant không
-- có EXECUTE trên mg_plan_limits_valid nên mọi lệnh UPDATE thật của nó vẫn bị từ chối (CHECK được tính lại ở mỗi UPDATE).
REVOKE ALL ON subscription_plans, subscriptions FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mg_plan_limits_valid(jsonb, boolean) TO mg_api_platform, mg_worker_platform;

GRANT SELECT ON subscription_plans TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON subscription_plans TO mg_api_platform;
GRANT UPDATE (name, limits, is_active, updated_at, version) ON subscription_plans TO mg_api_platform;

GRANT SELECT ON subscriptions TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT UPDATE (updated_at) ON subscriptions TO mg_api_tenant, mg_worker_tenant;
GRANT INSERT ON subscriptions TO mg_api_platform;
GRANT UPDATE (plan_id, status, period_start, period_end, overrides, updated_at, version) ON subscriptions TO mg_api_platform;
GRANT UPDATE (status, period_end, updated_at, version) ON subscriptions TO mg_worker_platform;

-- ---------------------------------------------------------------- trần số tenant toàn nền tảng (§13.3)
-- quota.max_tenants = số tenant chưa `deleted` tối đa (QuotaChecker — P3-T06a, bước validate). 10 = mức "10 tenant — MVP"
-- của §5.5 (1 host). Giá trị khởi đầu, chủ dự án chỉnh được (PUT /platform/settings/{key} — P4-T03a); chỉ chèn khi chưa
-- có, không ghi đè. system_settings là bảng FORCE RLS và owner (mg_migrator) không có policy ⇒ tạm NO FORCE trong cùng
-- transaction rồi FORCE lại (mẫu "migration dữ liệu" của database/README.md).
ALTER TABLE system_settings NO FORCE ROW LEVEL SECURITY;
INSERT INTO system_settings (key, value) VALUES ('quota.max_tenants', '10') ON CONFLICT (key) DO NOTHING;
ALTER TABLE system_settings FORCE ROW LEVEL SECURITY;
