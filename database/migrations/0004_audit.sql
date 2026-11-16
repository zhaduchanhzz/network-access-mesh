-- 0004 — Audit (bản đồ migration §6.3): audit_events (partition theo tháng, append-only), security_events (không
-- partition) + role mg_audit_writer, mg_partition_maint và hàm của job partition.maintain (§6.1, §13.5).
-- Forward-only.
--
-- Partition nằm trong schema riêng `partitions`: role ứng dụng không có USAGE trên schema này và không có quyền
-- trên partition nào (RLS của bảng cha KHÔNG áp dụng khi truy vấn thẳng partition — §6.1). Quyền chỉ cấp trên
-- bảng cha, không qua default privileges; kiểm bằng database/checks/partition_grants.sql trong CI.
-- mg_partition_maint sở hữu bảng cha (CREATE TABLE … PARTITION OF đòi quyền owner của bảng cha) và các partition.

-- +goose Up

-- ---------------------------------------------------------------- role (§6.1)
-- +goose StatementBegin
DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['mg_audit_writer', 'mg_partition_maint'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT', r);
    ELSIF EXISTS (SELECT 1 FROM pg_roles
                  WHERE rolname = r
                    AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR NOT rolcanlogin)) THEN
      RAISE EXCEPTION 'role % đã tồn tại với thuộc tính không mong đợi', r;
    END IF;
    IF pg_has_role(r, 'mg_app_tenant', 'MEMBER') OR pg_has_role(r, 'mg_app_platform', 'MEMBER') THEN
      RAISE EXCEPTION 'role % không được thuộc role nhóm của ứng dụng', r;
    END IF;
  END LOOP;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO mg_audit_writer, mg_partition_maint', current_database());
END
$$;
-- +goose StatementEnd

GRANT USAGE ON SCHEMA public TO mg_audit_writer, mg_partition_maint;

CREATE SCHEMA partitions;
COMMENT ON SCHEMA partitions IS 'Partition của audit_events (và usage_records từ 0016) — chỉ mg_partition_maint dùng; role ứng dụng không có quyền (§6.1)';
REVOKE ALL ON SCHEMA partitions FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA partitions TO mg_partition_maint;

-- ---------------------------------------------------------------- audit_events
-- PRIMARY KEY phải chứa khóa partition (occurred_at). Không FK (§6.3): actor_identity_id, tenant_id… là ảnh chụp
-- lúc ghi; identity/tenant bị xóa không ảnh hưởng audit.
CREATE TABLE audit_events (
    id                uuid        NOT NULL DEFAULT uuidv7(),
    occurred_at       timestamptz NOT NULL DEFAULT now(),
    tenant_id         uuid,       -- tenant của actor; NULL = sự kiện platform (actor là nhân sự nền tảng)
    actor_type        text        NOT NULL CHECK (actor_type IN ('identity', 'system', 'support')),
    actor_identity_id uuid,
    support_grant_id  uuid,
    actor_ip          inet,
    action            text        NOT NULL CHECK (length(action) BETWEEN 1 AND 200),
    resource_type     text        NOT NULL,
    resource_id       text,
    request_id        text        CHECK (length(request_id) <= 200),
    operation_id      uuid,       -- nối *.requested với *.succeeded/*.failed
    target_tenant_id  uuid,       -- tenant trong path (từ chối chéo tenant — §6.1)
    actor_display     text,
    outcome           text        NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    details           jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object'),
    prev_hash         bytea,      -- hash-chain theo tenant: Phase 6
    hash              bytea,
    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);
CREATE INDEX audit_events_tenant_time_idx ON audit_events (tenant_id, occurred_at DESC);

-- append-only: REVOKE UPDATE/DELETE/TRUNCATE (không cấp) + trigger chặn cả owner. Retention chỉ bằng drop partition.
-- +goose StatementBegin
CREATE FUNCTION mg_audit_append_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'audit_events là append-only: % bị chặn', TG_OP
    USING ERRCODE = 'restrict_violation',
          HINT = 'retention của audit chỉ thực hiện bằng drop partition (job partition.maintain)';
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION mg_audit_append_only() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mg_audit_append_only() TO mg_partition_maint;  -- để chép trigger TRUNCATE sang partition mới

CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION mg_audit_append_only();  -- trigger ROW được nhân bản xuống mọi partition
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION mg_audit_append_only();  -- trigger TRUNCATE KHÔNG tự nhân bản: mg_partition_guard chép

-- RLS — T (sự kiện tenant) / P (sự kiện platform): pool tenant chỉ thấy sự kiện của tenant đang đặt; pool platform chỉ
-- thấy sự kiện platform (tenant_id NULL); mg_audit_writer (đường ghi detached) chỉ INSERT, không đọc.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_tenant ON audit_events TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY audit_events_platform ON audit_events TO mg_app_platform
    USING (tenant_id IS NULL AND app_is_platform()) WITH CHECK (tenant_id IS NULL AND app_is_platform());
CREATE POLICY audit_events_detached_insert ON audit_events FOR INSERT TO mg_audit_writer
    WITH CHECK (true);

REVOKE ALL ON audit_events FROM PUBLIC;
GRANT SELECT, INSERT ON audit_events TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON audit_events TO mg_audit_writer;

-- ---------------------------------------------------------------- security_events (T+P, không partition)
-- Bảng thường: retention ≥ 400 ngày bằng retention.sweep (§6.4). Không FK tới tenants (giống audit).
CREATE TABLE security_events (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id       uuid,
    kind            text        NOT NULL,
    severity        text        NOT NULL,  -- tập giá trị chốt ở P2-T08 (§16.3)
    source          text        NOT NULL,
    details         jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object'),
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    acknowledged_by uuid
);
CREATE INDEX security_events_tenant_time_idx ON security_events (tenant_id, occurred_at DESC);

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events FORCE ROW LEVEL SECURITY;
CREATE POLICY security_events_tenant ON security_events TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY security_events_platform ON security_events TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

REVOKE ALL ON security_events FROM PUBLIC;
GRANT SELECT, INSERT ON security_events TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT UPDATE (acknowledged_by) ON security_events TO mg_api_platform;
GRANT DELETE ON security_events TO mg_worker_platform;  -- retention.sweep

-- ---------------------------------------------------------------- job partition.maintain (§6.1, §13.5)
-- mg_partition_guard: bật RLS (không FORCE — owner cần đọc để đếm hàng ở DEFAULT và export trước khi drop) trên một
-- partition mới, thu hồi mọi quyền của PUBLIC và chép các trigger TRUNCATE của bảng cha (PostgreSQL chỉ tự nhân bản
-- trigger ROW). Không cấp quyền cho role nào.
-- +goose StatementBegin
CREATE FUNCTION mg_partition_guard(p_partition regclass, p_parent regclass) RETURNS void
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
DECLARE
  t record;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = p_partition AND inhparent = p_parent) THEN
    RAISE EXCEPTION '% không phải partition của %', p_partition, p_parent USING ERRCODE = 'invalid_parameter_value';
  END IF;
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', p_partition);
  EXECUTE format('REVOKE ALL ON TABLE %s FROM PUBLIC', p_partition);
  FOR t IN
    SELECT tgname, tgfoid::regproc AS fn, (tgtype & 2) <> 0 AS is_before
    FROM pg_trigger
    WHERE tgrelid = p_parent AND NOT tgisinternal AND (tgtype & 32) <> 0  -- 32 = TRIGGER_TYPE_TRUNCATE
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = p_partition AND tgname = t.tgname) THEN
      EXECUTE format('CREATE TRIGGER %I %s TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION %s()',
                     t.tgname, CASE WHEN t.is_before THEN 'BEFORE' ELSE 'AFTER' END, p_partition, t.fn);
    END IF;
  END LOOP;
END
$$;
-- +goose StatementEnd

-- mg_partition_maintain: tạo (idempotent) partition DEFAULT partitions.<bảng>_default nếu chưa có, rồi partition
-- theo tháng UTC cho tháng hiện tại và p_months_ahead tháng tới, tên partitions.<bảng>_pYYYYMM. Bảng cha phải
-- partition RANGE trên một cột timestamptz hoặc date. Trả về tên các partition vừa tạo. lock_timeout ngắn:
-- CREATE … PARTITION OF khóa bảng cha — job lỗi rồi chạy lại hôm sau thay vì chặn ghi audit (partition được tạo
-- trước 3 tháng). Mọi DDL partition là SQL động: partition không thuộc schema mà sqlc cần biết.
-- +goose StatementBegin
CREATE FUNCTION mg_partition_maintain(p_parent regclass, p_months_ahead integer DEFAULT 3) RETURNS text[]
    LANGUAGE plpgsql
    SET search_path = pg_catalog
    SET lock_timeout = '5s'
AS $$
DECLARE
  v_parent   text;
  v_key_type regtype;
  v_month    timestamp;
  v_from     timestamp;
  v_to       timestamp;
  v_name     text;
  v_created  text[] := '{}';
BEGIN
  IF p_months_ahead IS NULL OR p_months_ahead < 0 OR p_months_ahead > 24 THEN
    RAISE EXCEPTION 'p_months_ahead phải trong 0..24' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT c.relname, a.atttypid::regtype
    INTO v_parent, v_key_type
  FROM pg_partitioned_table pt
  JOIN pg_class c ON c.oid = pt.partrelid
  JOIN pg_attribute a ON a.attrelid = pt.partrelid AND a.attnum = pt.partattrs[0]
  WHERE pt.partrelid = p_parent AND pt.partstrat = 'r' AND pt.partnatts = 1;
  IF NOT FOUND OR v_key_type NOT IN ('timestamptz'::regtype, 'date'::regtype) THEN
    RAISE EXCEPTION '% không phải bảng partition RANGE theo một cột timestamptz/date', p_parent
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_partitioned_table WHERE partrelid = p_parent AND partdefid <> 0) THEN
    v_name := v_parent || '_default';
    EXECUTE format('CREATE TABLE partitions.%I PARTITION OF %s DEFAULT', v_name, p_parent);
    PERFORM public.mg_partition_guard(format('partitions.%I', v_name)::regclass, p_parent);
    v_created := v_created || v_name;
  END IF;
  v_month := date_trunc('month', now() AT TIME ZONE 'UTC');
  FOR i IN 0 .. p_months_ahead LOOP
    v_from := v_month + make_interval(months => i);
    v_to   := v_month + make_interval(months => i + 1);
    v_name := format('%s_p%s', v_parent, to_char(v_from, 'YYYYMM'));
    CONTINUE WHEN to_regclass(format('partitions.%I', v_name)) IS NOT NULL;
    IF v_key_type = 'date'::regtype THEN
      EXECUTE format('CREATE TABLE partitions.%I PARTITION OF %s FOR VALUES FROM (%L) TO (%L)',
                     v_name, p_parent, v_from::date, v_to::date);
    ELSE
      EXECUTE format('CREATE TABLE partitions.%I PARTITION OF %s FOR VALUES FROM (%L) TO (%L)',
                     v_name, p_parent, to_char(v_from, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), to_char(v_to, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'));
    END IF;
    PERFORM public.mg_partition_guard(format('partitions.%I', v_name)::regclass, p_parent);
    v_created := v_created || v_name;
  END LOOP;
  RETURN v_created;
END
$$;
-- +goose StatementEnd

-- Số hàng trong partition DEFAULT (> 0 ⇒ cảnh báo: thiếu partition cho khoảng thời gian đó — §6.1).
-- +goose StatementBegin
CREATE FUNCTION mg_partition_default_rows(p_parent regclass) RETURNS bigint
    LANGUAGE plpgsql
    STABLE
    SET search_path = pg_catalog
AS $$
DECLARE
  v_default regclass;
  v_rows    bigint;
BEGIN
  SELECT NULLIF(partdefid, 0)::regclass INTO v_default FROM pg_partitioned_table WHERE partrelid = p_parent;
  IF v_default IS NULL THEN
    RETURN 0;
  END IF;
  EXECUTE format('SELECT count(*) FROM %s', v_default) INTO v_rows;
  RETURN v_rows;
END
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION mg_partition_guard(regclass, regclass), mg_partition_maintain(regclass, integer),
                       mg_partition_default_rows(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mg_partition_guard(regclass, regclass), mg_partition_maintain(regclass, integer),
                          mg_partition_default_rows(regclass) TO mg_partition_maint;

-- ---------------------------------------------------------------- chuyển owner + partition ban đầu
-- ALTER … OWNER đòi: SET ROLE được sang owner mới và owner mới có CREATE trên schema của bảng ⇒ cấp tạm CREATE
-- trên public rồi thu hồi ngay trong cùng transaction.
GRANT mg_partition_maint TO mg_migrator WITH INHERIT FALSE, SET TRUE;
GRANT CREATE ON SCHEMA public TO mg_partition_maint;
ALTER TABLE audit_events OWNER TO mg_partition_maint;
REVOKE CREATE ON SCHEMA public FROM mg_partition_maint;

-- Partition DEFAULT + tháng hiện tại + 3 tháng tới, tạo bằng chính role của job (owner của partition).
SET LOCAL ROLE mg_partition_maint;
SELECT mg_partition_maintain('audit_events', 3);
RESET ROLE;
