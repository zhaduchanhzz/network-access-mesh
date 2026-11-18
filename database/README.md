# database

PostgreSQL của Management Plane (§6 của [bản master](../docs/planning/implementation-master-plan.md)): một database
`meshguard`, dữ liệu chung có `tenant_id` + Row-Level Security. Bắt đầu ở P2-T03 — bằng chứng:
[`docs/planning/evidence/P2-T03.md`](../docs/planning/evidence/P2-T03.md).

| Đường dẫn | Nội dung |
|---|---|
| `bootstrap/superuser.sql` | Chạy **một lần** bằng superuser của cụm, trong database `meshguard`, trước migration đầu tiên (chạy lại được): tạo `mg_migrator` (CREATEROLE, owner database) và `mg_backup` (BYPASSRLS + `pg_read_all_data`) — hai role chỉ superuser tạo được |
| `migrations/0001…0015_*.sql`, `0020_*.sql` | Migration goose, forward-only (không có phần Down), nhúng vào binary qua `embed.go`; bản đồ bảng ở §6.3. `0007` (G2 vòng 1, F3) chỉ thêm CHECK: owner segment của `identity_providers.client_secret_ref` = `tenant_id` (hoặc `platform`); `0008` (G2 vòng 2, A-1) chỉ thêm cột `sessions.id_token_hint_enc`; `0009`–`0013` (P3-T06) `0014` (P3-T04, chỉ CHECK/DEFAULT cho placement) `0015` (P3-T05, chỉ cột `provisioning_jobs.cancel_requested_at`) và `0020` (P3-T17, số tạm — chỉ quyền thu hồi session của worker) — xem mục "Bảng của Phase 3" |
| `queries/*.sql` + `sqlc.yaml` | Truy vấn sqlc → mã sinh ở `internal/store/sqlcdb` (không sửa tay); `jobs.sql` = khung job + idempotency (P2-T12); `devices.sql` = sổ thiết bị + trạng thái sync + thu hồi hai pha (P2-T13); `placement.sql` = khóa host + trạng thái cấp phát (P3-T04); `hosts.sql` = API `/platform/hosts` và lệnh `host-set` (P3-T04); `usage.sql` = QuotaChecker (P3-T06a) |
| `river/grants.sql` | Quyền trên schema `river` của job queue (P2-T12), chạy lại sau mỗi lần migrate River — xem mục "Job queue (River)" |
| `checks/partition_grants.sql` | Truy vấn CI: mỗi hàng là một vi phạm (quyền trên partition, partition chưa bật RLS, default privileges) |
| `embed.go` | Package Go `database`: `Migrations`, `Seeds`, `Bootstrap`, `Checks`, `River` (embed.FS) |
| `seeds/*.sql` | Dữ liệu tham chiếu áp **sau mỗi lần migrate** (`store.Migrate` → `store.Seed`: theo tên file, một transaction, `pg_advisory_xact_lock`, chạy bằng `mg_migrator`, idempotent). `seeds/rbac.sql` (P2-T07) là file **sinh** từ §8.4–§8.6 bằng `make authz-gen` — không sửa tay, spec-lint fail khi lệch; `seeds/plans.sql` (P3-T06, viết tay) chèn gói mặc định `standard` **chỉ khi chưa có** (không ghi đè gói chủ dự án đã chỉnh) |

## RBAC (P2-T07)

`roles` (11 role hệ thống: SA/PO/PS/PV phạm vi `platform`, TO/TA/TP/TV/EU phạm vi `tenant`, `support_operator`/`support_admin`
phạm vi `support` — chỉ là role hiệu lực của Support Access Grant), `permissions` (mọi khóa của §8.5/§8.6, tiền tố khóa =
phạm vi), `role_permissions` (`scope` any/own = ô ✔/○, `condition` = ô có điều kiện). Mọi ràng buộc phạm vi là **FK ghép**,
không trigger: `tenant_memberships (tenant_id, identity_id) → identities (tenant_id, id)` (issuer binding) và
`(role_id, role_scope='tenant') → roles (id, scope)`; `platform_users` tương tự với `'platform'`; `role_permissions` chép
`role_scope` + `permission_scope` (FK ghép tới `roles`/`permissions`) với CHECK: role platform chỉ mang quyền platform,
`own` chỉ ở role tenant. Seed đồng bộ đúng nội dung file: grant thừa của role hệ thống bị xóa, permission rời ma trận bị xóa
cùng grant; role hệ thống không còn trong seed ⇒ seed dừng (gỡ role cần migration riêng). Role ứng dụng chỉ `SELECT`.

## Role (§6.1)

| Role | LOGIN | Thuộc nhóm | Dùng bởi | Quyền | File mật khẩu (§14.2) |
|---|---|---|---|---|---|
| `mg_app_tenant` | — | — | (nhóm) | mang policy RLS nhánh `tenant_id = app_tenant_id()` | — |
| `mg_app_platform` | — | — | (nhóm) | mang policy RLS thêm nhánh `app_is_platform()` | — |
| `mg_api_tenant`, `mg_worker_tenant` | có | `mg_app_tenant` | pool tenant của api / worker | bảng T, T+P (theo tiến trình) | `mg-sec-api` / `mg-sec-worker` |
| `mg_api_platform`, `mg_worker_platform` | có | `mg_app_platform` | pool platform của api / worker; `mg_worker_platform` cũng là role của River client trong worker (pool riêng) | bảng T+P, P, `sessions`…; schema `river` (xem dưới) | `mg-sec-api` / `mg-sec-worker` |
| `mg_audit_writer` | có | — | đường ghi audit detached (P2-T08) | chỉ `INSERT` vào `audit_events` | `mg-sec-app` |
| `mg_partition_maint` | có | — | job `partition.maintain` | owner `audit_events` + partition; `CREATE` trên schema `partitions` | `mg-sec-worker` |
| `mg_readonly` | có | — | báo cáo | chỉ schema `report` (chưa có view — đến cùng 0016/P6-T11); không có cả `USAGE` trên `public` | (chưa cấp) |
| `mg_migrator` | có | — | job `migrate` | owner database, CREATEROLE (ADMIN trên role nó tạo) | `mg-sec-migrate` |
| `mg_backup` | có | — | `pg-backup` (P2-T03a) | `pg_read_all_data` + BYPASSRLS, `default_transaction_read_only` — không gì khác (kiểm ở `internal/store/backup_role_test.go`, xem dưới) | `mg-sec-backup` |

**`mg_backup` (P2-T03a):** `pg_dump` đặt `row_security = off`, điều mà trên bảng `FORCE ROW LEVEL SECURITY` chỉ role
`BYPASSRLS` làm được (owner và role ứng dụng nhận lỗi 42501 thay vì dump thiếu hàng — `TestRowSecurityOffNeedsBypassRLS`).
Ngoài đọc, role này không làm được gì: `default_transaction_read_only` chỉ là mặc định (role tự tắt được), nên
`TestBackupRoleCannotWriteOrEscalate` tắt nó trước rồi chứng minh quyền đơn thuần từ chối 33 câu lệnh (ghi mọi loại bảng,
partition, schema `river`, sequence, DDL, `TEMP`, `CREATE ROLE/DATABASE`, `ALTER ROLE`, `SET ROLE`/`SESSION
AUTHORIZATION`, khóa độc quyền, `COPY` file/program, `pg_read_file`, `pg_terminate_backend`, hàm `mg_partition_*`/`app_*`);
`TestBackupRoleCatalog` kiểm thuộc tính, membership (chỉ `pg_read_all_data`, không ADMIN, không với tới role nào khác) và
quyền theo catalog trên mọi đối tượng. Còn lại (như mọi role, không chặn được bằng quyền): tự `ALTER ROLE mg_backup SET …`,
`NOTIFY`, advisory lock, large object khi đã tự tắt read-only — chỉ là DoS trong chính DB, không sửa được dữ liệu.

Mọi role ứng dụng `NOSUPERUSER NOBYPASSRLS`, không DDL (không `CREATE` trên schema, không `TEMPORARY`), không bao giờ
`TRUNCATE`; quyền chỉ cấp tường minh (không default privileges); cột bất biến (vd. `identities.idp_id/tenant_id/scope`)
không có quyền `UPDATE`. `store.Open` từ chối khởi động khi role của pool tenant không thuộc `mg_app_tenant` (hoặc thuộc
cả `mg_app_platform`), và ngược lại.

## RLS

- Helper `app_tenant_id()` = `NULLIF(current_setting('app.tenant_id', true), '')::uuid`, `app_is_platform()` =
  `COALESCE(current_setting('app.scope', true), '') = 'platform'` — biến chưa đặt hoặc rỗng ⇒ 0 hàng, không lỗi.
- Mọi bảng có ký hiệu T, T+P, P ở §6.3: `ENABLE` + `FORCE ROW LEVEL SECURITY`. Ký hiệu "—": `roles`, `permissions`,
  `role_permissions`, `subscription_plans`, `sessions`, `auth_requests` (hai bảng sau chỉ cấp cho role platform).
- Truy vấn chỉ chạy qua `store.WithTenantTx(ctx, tenantID, fn)` (pool tenant, `app.scope='tenant'` + `app.tenant_id`)
  hoặc `store.WithPlatformTx(ctx, fn)` (pool platform, `app.scope='platform'`, xóa `app.tenant_id`), biến đặt bằng
  `set_config(…, true)` nên hết hiệu lực khi transaction kết thúc. Test kiến trúc (`internal/archtest`) cấm mọi package
  ngoài `internal/store` import driver DB (`pgx`, `database/sql`, `goose`).
- `secrets`/`tenant_keys`: policy `RESTRICTIVE` theo role ẩn phạm vi `platform_ops` khỏi `mg_api_*` (§7.6); chỉ role
  worker có `UPDATE` trên `tenant_keys` (xoay DEK, rewrap khi xoay KEK, hủy DEK của tenant — job của worker), api chỉ
  `SELECT`/`INSERT`. Chỉ module `internal/secrets` dùng hai bảng này (truy vấn ở `queries/secrets.sql`; thiết kế
  envelope encryption, AAD và keyring: [bằng chứng P2-T04](../docs/planning/evidence/P2-T04.md)).
- `audit_events`: pool tenant thấy sự kiện của tenant đang đặt; pool platform chỉ thấy sự kiện platform (`tenant_id`
  NULL); append-only (không cấp `UPDATE/DELETE/TRUNCATE` + trigger chặn cả owner).

## Partition và job `partition.maintain`

`audit_events` partition theo tháng (UTC) trong schema riêng `partitions` (`partitions.audit_events_pYYYYMM` +
`partitions.audit_events_default`). Role ứng dụng không có `USAGE` trên schema này và không có quyền trên partition
nào — RLS của bảng cha **không** áp dụng khi truy vấn thẳng partition. Hàm `mg_partition_maintain(bảng, số_tháng)`
(chạy bằng `mg_partition_maint`) tạo idempotent partition DEFAULT + tháng hiện tại + N tháng tới, bật RLS (không
FORCE) và chép trigger `TRUNCATE` của bảng cha sang partition mới; migration 0004 đã tạo sẵn tháng hiện tại + 3.
Trong Go: `store.OpenPartitionMaintainer(...).Maintain(ctx, store.PartitionMonthsAhead)` trả về partition vừa tạo và
số hàng nằm trong DEFAULT (> 0 ⇒ cảnh báo). Job hằng ngày `partition.maintain` (P2-T12, `internal/jobs`: River periodic
job, chạy cả khi worker khởi động — `RunOnStart`; hàng DEFAULT > 0 ⇒ cảnh báo `partition_default_rows`). Export + drop partition quá
retention: chưa làm (lần đầu cần sau ≥ 400 ngày — §6.4). `usage_records` (0016, P6-T11) thêm vào
`store.PartitionedTables`.

## Audit (P2-T08)

Module `internal/audit` (bằng chứng: [`P2-T08.md`](../docs/planning/evidence/P2-T08.md)); truy vấn ở `queries/audit.sql`.

- **Ba đường ghi**: `audit.Record(ctx, q, ev)` trong transaction nghiệp vụ (role ứng dụng, RLS kiểm tenant);
  `Logger.RecordDetached` cho sự kiện `denied`/`failure` trên pool riêng `store.OpenAuditWriter` (role
  `mg_audit_writer`: chỉ `INSERT` trên `audit_events`, không đọc lại — truy vấn `AppendAuditEvent` không `RETURNING`,
  id sinh ở ứng dụng; tách khỏi hủy của request); `Logger.RecordCommitted` cho sự kiện báo sau commit (identity).
- **CHECK `audit_events_operation_pair`** (0004): hậu tố `.requested`/`.succeeded` ⇔ có `operation_id` + `success`,
  `.failed` ⇔ có `operation_id` + `failure`, sự kiện khác không mang `operation_id`. Index `(operation_id)` cho việc đóng
  cặp và reconcile (`ListOpenOperations`).
- **`security_events`**: `severity ∈ {low, medium, high, critical}`; chống trùng theo `details.dedupe_key` trong một
  cửa sổ, tuần tự hóa bằng `pg_advisory_xact_lock` (khóa phạm vi transaction, chỉ quanh lệnh kiểm + chèn).
- **Đọc**: `ListTenantAuditEvents` (điều kiện `tenant_id` tường minh + RLS pool tenant) và `ListPlatformAuditEvents`
  (`tenant_id IS NULL` + RLS pool platform), cursor `(occurred_at, id)` — index `(tenant_id, occurred_at DESC, id DESC)`.

## Job queue (River) — P2-T12

River v0.51.0 (`go.mod`, `versions.lock`) — bảng của queue ở schema riêng `river` (§6.3), không chứa dữ liệu nghiệp vụ
ngoài tham chiếu `provisioning_jobs.id` (+ kind) trong args. Bằng chứng: [`P2-T12.md`](../docs/planning/evidence/P2-T12.md).

- **Tạo bảng**: migration 0006 chỉ tạo schema `river` (owner `mg_migrator`). Bảng do **chính migrator của River**
  (`rivermigrate`, driver pgx) tạo ngay sau goose: `store.MigrateQueue(ctx, url, cred)` — mỗi version một transaction,
  khóa phiên riêng chống hai job `migrate` chạy cùng lúc —, rồi chạy `river/grants.sql`. `store.MigrateAll` = goose
  (`Migrate`) + `MigrateQueue`, là thứ job `migrate` gọi (P2-T16).
- **Quyền** (`river/grants.sql`, tường minh theo tên bảng, không default privileges): `mg_worker_platform` —
  `SELECT/INSERT/UPDATE/DELETE` trên `river_job`, `river_leader`, `river_queue`, `river_notification` (River client của
  worker: lấy/hoàn tất job, bầu leader, rescue, lập lịch, job định kỳ, dọn dẹp); `mg_api_tenant`, `mg_api_platform`,
  `mg_worker_tenant` — `SELECT, INSERT` + `UPDATE (kind)` trên `river_job` (enqueue cùng transaction: `INSERT … ON
  CONFLICT … DO UPDATE SET kind … RETURNING`); `river_migration` chỉ `mg_migrator`. Không ai có `TRUNCATE`;
  `mg_readonly`, `mg_audit_writer`, `mg_partition_maint` không có `USAGE` trên schema. Bản River mới thêm bảng ⇒ sửa
  `river/grants.sql` và `queueTables` trong `internal/store/queue_test.go` (test fail khi gặp bảng chưa xếp loại).
- **Reindexer của River tắt** (`REINDEX` cần owner hoặc `MAINTAIN`, `mg_worker_platform` không có); khi cần thì chạy
  `REINDEX` bằng `mg_migrator`.
- **Enqueue**: module nghiệp vụ gọi `jobs.Enqueue(ctx, tx, spec)` trong `store.WithTenantJobTx` /
  `WithPlatformJobTx` — hàng `provisioning_jobs` và job River cùng commit/rollback với thay đổi nghiệp vụ.

## Sổ thiết bị (P2-T13)

Module `internal/devices` (bằng chứng: [`P2-T13.md`](../docs/planning/evidence/P2-T13.md)); truy vấn ở `queries/devices.sql`
(pool tenant — cả hai bảng là T).

- `device_inventory_cache`: hàng được chuẩn hóa từ `ListNodes` ở mỗi `inventory.sync`; cùng `headscale_node_id` khác
  `machine_key` ⇒ `removed_at` cho hàng cũ + hàng mới (partial unique `(instance_id, headscale_node_id) WHERE removed_at IS
  NULL`); `revocation_*` chỉ do luồng thu hồi hai pha ghi (`StartDeviceRevocation` → `SettleDeviceRevocation` theo đúng
  `revocation_job_id`, một lần).
- `device_inventory_sync_state` (thêm vào 0005 ở P2-T13): một hàng mỗi instance — `generation`, `synced_at` (đồng hồ DB
  ngay trước `ListNodes`), `node_count`. Lần sync khóa hàng này (`FOR UPDATE`) và bỏ qua snapshot không mới hơn
  `synced_at`; là nguồn "lần sync gần nhất" của dashboard (P2-T13a) kể cả khi tailnet chưa có node nào. `instance_id`,
  `tenant_id` bất biến; role ứng dụng tenant `SELECT/INSERT` + `UPDATE (generation, synced_at, node_count)`.

## Health của instance (P2-T13a)

Module `internal/monitoring` (bằng chứng: [`P2-T13a.md`](../docs/planning/evidence/P2-T13a.md)); truy vấn ở
`queries/monitoring.sql`. Không bảng mới: job `health.probe` (pool platform của worker — chỉ role platform có
`UPDATE (last_health, last_health_at)`) ghi `tenant_instances.last_health` = tài liệu
`{"schema":1,"status":"healthy|unhealthy","reason"?,"version"?,"database"?,"breaker"?,"duration_ms"}` (mã ổn định,
không có thông điệp thô của Headscale) và `last_health_at` = đồng hồ DB lúc probe **bắt đầu**; kết quả của lần probe bắt
đầu sớm hơn kết quả đã ghi bị bỏ qua. `version`/`updated_at` của instance (ETag) không đổi. Dashboard tenant đọc qua
pool tenant (RLS), Platform Health qua pool platform; số thiết bị chỉ đến từ service của `devices`.

## Bảng của Phase 3 (P3-T06, migration 0009–0013; P3-T04, 0014; P3-T05, 0015; P3-T17, 0020)

Bằng chứng: [`P3-T06.md`](../docs/planning/evidence/P3-T06.md). Mọi bảng có FK ghép theo tenant, `ENABLE` + `FORCE` RLS
theo ký hiệu §6.3, quyền cấp tường minh theo tiến trình (ma trận đầy đủ: `TestP3GrantMatrix` trong
`internal/store/schema_p3_test.go`), không role nào có `TRUNCATE`, không secret (chỉ secret reference/hash).

| Migration | Bảng (RLS) | Ghi | Điểm cần biết |
|---|---|---|---|
| `0009` | `approval_requests` (T+P), `tenant_invitations` (T), `notification_outbox` (T+P) | approvals: api (tạo/duyệt/thực thi), worker platform (hết hạn, retention); lời mời: api tenant, worker tenant (lời mời Owner — §11.3 bước 16); outbox: mọi tiến trình chèn, api tenant đánh dấu đã đọc, worker gửi | 2P: `scope='platform'` ⇔ `tenant_id` NULL (yêu cầu của nền tảng về một tenant ghi đích ở `resource_type/resource_id` — pool tenant không thấy); người yêu cầu/duyệt ràng buộc bằng FK `(id, scope)` + `(tenant_id, id)` tới `identities`; không tự duyệt (CHECK); `payload`/`payload_sha256` bất biến. Lời mời: FK `(accepted_identity_id, idp_id) → identities(id, idp_id)` (UNIQUE mới trên `identities`) — chỉ identity của đúng IdP ghi trong lời mời nhận được |
| `0010` | `relay_regions`, `relay_assignments` (T+P) | chỉ `mg_worker_platform` (bước `relay.assign`); mọi pool đọc | embedded/standalone thuộc một tenant, `shared` ⇔ `tenant_id` NULL; ở MVP assignment chỉ trỏ region của chính tenant (FK ghép) |
| `0011` | `backups` (T+P) | worker (cả hai pool); api platform đọc; api tenant không có quyền | `key_ref` owner = `tenant_id`; `storage_uri` cấm userinfo. Service `mg-backup` (P2-T03a) **không** ghi bảng này (role `mg_backup` chỉ đọc) — bản PostgreSQL/IdP/edge có nguồn là manifest + `status.json` |
| `0012` | `subscription_plans` (—), `subscriptions` (T+P) | plans: api platform; subscriptions: api platform (tạo/đổi), worker platform (trạng thái/kỳ) | CHECK `mg_plan_limits_valid` (khóa của `PlanLimits` §13.3; plan bắt buộc đủ 4 khóa quota). Role ghi cần `EXECUTE` hàm này (chỉ hai role platform có). Role tenant có `UPDATE (updated_at)` **chỉ** để `SELECT … FOR UPDATE` hàng subscription của mình (§7.4 bước 3); không có `EXECUTE` nên mọi `UPDATE` thật của nó vẫn bị từ chối. 0012 chèn `system_settings` `quota.max_tenants = 10` khi chưa có (tạm `NO FORCE` trong transaction — mẫu "migration dữ liệu" dưới) |
| `0013` | `policy_versions`, `policy_applications` (T) + FK `tenants(id, desired_policy_version_id)` | versions: api tenant (soạn/duyệt), worker tenant (baseline/suspension, trạng thái); applications: chỉ worker tenant (job `policy.apply`); role tenant `UPDATE (desired_policy_version_id)` trên hàng tenant của mình | Nội dung: `source` (jsonb có kiểu, P4-T10) **hoặc** `source_hujson` (HuJSON do nền tảng sinh — lõi P3-T08a); DB kiểm sha256 của HuJSON/`applied_hujson` và chặn chuỗi rỗng (L2). "Lần áp dụng hiện hành" = hàng `applied` có `superseded_at` NULL (một hàng mỗi instance) |

**`0014` (P3-T04 — placement, không bảng mới):** CHECK/DEFAULT của các cột `hosts` mà placement đọc — `status ∈ {active,
draining, disabled}`; `capacity` = đúng `{"max_instances": <0…2³¹−1>}` (DEFAULT 100, điền cho host đã có — mức tạm tính
P1-T20; `UPDATE` tạm `NO FORCE` như 0012); `public_entry` ⊆ {`ipv4` thập phân chuẩn, unicast, ngoài pool; `mode` ∈ {`direct`,
`vps_gateway`}} (chưa nhận `ipv6`); `tenant_net_pool` IPv4 /8…/29 ngoài `100.64.0.0/10`; `run_uid_range` hữu hạn trong
1000…2³¹−2; `stun_port_range` hữu hạn trong 1024…65535 — và của `tenant_instances`: `net_cidr` đúng một /29 IPv4 (partial
unique theo host ⇒ không chồng nhau), `run_uid` trong 1000…2³¹−2. DB có hàng vi phạm (instance không phải /29, `capacity`
có khóa lạ) không migrate được cho tới khi sửa hàng đó. Trước khi placement chọn được host staging: đặt
`hosts.public_entry` = `{"ipv4": <MG_PUBLIC_IPV4>, "mode": "vps_gateway"}` (giá trị theo `<env>.env`, không nằm trong
migration) bằng `meshguard admin host-set --name mg-staging --public-ipv4-env MG_PUBLIC_IPV4 --mode vps_gateway`
([RUNBOOK](../infrastructure/host/RUNBOOK.md)) hoặc `PATCH /api/v1/platform/hosts/{hostId}` — không sửa bằng SQL: hai
đường đó kiểm đúng các CHECK trên, khóa hàng host như placement và ghi audit `platform.host.update` — bằng chứng
[`P3-T04.md`](../docs/planning/evidence/P3-T04.md).

**`0015` (P3-T05 — điều khiển job vòng đời, không bảng mới):** cột `provisioning_jobs.cancel_requested_at`
(NULL-able) = lúc người vận hành gọi `POST /platform/jobs/{id}/cancel` trên job đang chạy — handler dừng sau step hiện
tại rồi `failed_resumable`; job `queued` chuyển thẳng `cancelled` và cũng mang mốc này (CHECK: không có mốc ở hàng
`queued`); `/retry` xóa mốc. Chỉ `mg_api_platform`, `mg_worker_platform` có `UPDATE` cột này. Expand-only, số hiệu tạm
(người điều phối có thể đánh lại khi gộp) — bằng chứng [`P3-T05.md`](../docs/planning/evidence/P3-T05.md).

**`0020` (P3-T17 — đối soát sau restore PostgreSQL, không bảng mới; số hiệu tạm):** `GRANT UPDATE (revoked_at,
id_token_hint_enc) ON sessions TO mg_worker_platform` — lệnh `meshguard-worker admin post-restore-reconcile` thu hồi mọi
phiên của DB vừa restore như `RevokeIdentitySessions` của module identity (mốc thu hồi + xóa hint đăng xuất), không cột
nào khác (worker trước đó chỉ có `SELECT, DELETE` cho `session.gc`). Expand-only — bằng chứng
[`P3-T17.md`](../docs/planning/evidence/P3-T17.md).

Gói tối thiểu (`seeds/plans.sql`): `standard` = `max_devices` 100, `max_users` 100, `max_tagged_devices` 25,
`max_live_enrollment_credentials` 25, `backup_interval_minutes` 60, `instance` {cpus 1, memory_mb 512, pids 256} — giá trị
khởi đầu chủ dự án chỉnh được (lý do từng số: chú thích trong file). QuotaChecker (P3-T06a) đọc hạn mức hiệu lực =
`subscription_plans.limits || subscriptions.overrides` của subscription còn hiệu lực, và trần số tenant ở
`system_settings` `quota.max_tenants` (pool platform).

## Triển khai (P2-T16 nối vào job `migrate` của `mg-core`)

1. Superuser: `psql -U postgres -d meshguard -v ON_ERROR_STOP=1 < database/bootstrap/superuser.sql` (hoặc `store.Bootstrap`).
2. **Mật khẩu role** — không bao giờ nằm trong repo, biến môi trường hay URL: mỗi role một file secret trên host
   (`/opt/meshguard/secrets/<service>/…`, nhóm `mg-sec-*` ở §14.2; mật khẩu DB lưu mỗi consumer một bản và xoay cùng
   lúc). Mật khẩu là một dòng ASCII in được, không khoảng trắng, ≥ 16 ký tự, ví dụ sinh bằng
   `openssl rand -hex 32 > <file>` (umask 077). Bên đặt mật khẩu dùng `store.SetRolePassword`: verifier
   SCRAM-SHA-256 được tính ở client nên plaintext không tới server (log, `pg_stat_activity`). Superuser đặt cho
   `mg_migrator`, `mg_backup`; `mg_migrator` (ADMIN trên các role nó tạo) đặt cho các role còn lại sau migration.
   Lệnh quản trị gói các bước này chưa có — P2-T16.
3. `mg_migrator`: `store.MigrateAll(ctx, url, store.Credentials{User: "mg_migrator", PasswordFile: …})` — goose
   (`store.OpenMigrator` + `store.Migrate`, session lock), rồi `seeds/*.sql` (`store.Seed`, cùng lệnh `store.Migrate`),
   rồi schema River (`store.MigrateQueue`) và quyền của nó; **luôn có dump trước migration** — P2-T03a: bước migrate
   chạy trước `docker compose -p mg-backup … run --rm -T pg-backup once --label pre-migration` và dừng nếu exit ≠ 0
   ([runbook backup/restore](../docs/operations/backup-restore.md) mục 5).
4. Tiến trình: `store.Open(ctx, store.Config{URL: "postgres://postgres:5432/meshguard?sslmode=…", Tenant: …,
   Platform: …})` — URL không chứa user/mật khẩu; mật khẩu đọc lại từ file ở mỗi kết nối mới (xoay không cần restart).
   Đường audit detached (api và worker): `store.OpenAuditWriter(ctx, url, store.Credentials{User: "mg_audit_writer",
   PasswordFile: …})` — mật khẩu trong `mg-sec-app` (§14.2); hàm từ chối role không phải chỉ-`INSERT`.

Migration sau này: forward-only, expand → migrate → contract. Do `FORCE ROW LEVEL SECURITY`, chính owner
(`mg_migrator`) cũng bị RLS lọc (không có policy cho nó ⇒ 0 hàng): migration dữ liệu phải tạm `NO FORCE` trong cùng
transaction rồi `FORCE` lại. Bảng mới phải được xếp loại trong `internal/store/rls_test.go` (`rlsTables` /
`noRLSTables`), nếu không test catalog sẽ fail.

## Test

```sh
# PostgreSQL pin theo digest (versions.lock [images.postgres]); mật khẩu dùng một lần
docker run -d --name pg -e POSTGRES_PASSWORD_FILE=/run/secrets/pw -v "$PWD/pw:/run/secrets/pw:ro" -p 127.0.0.1:5432:5432 \
  docker.io/library/postgres@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc
MG_TEST_PG_ADMIN_URL="postgres://postgres:$(cat pw)@127.0.0.1:5432/postgres?sslmode=disable" MG_TEST_PG_REQUIRED=1 \
  go test -race -count=1 ./internal/store/ ./internal/jobs/
make sqlc        # sinh lại internal/store/sqlcdb (cần CGO)
make sqlc-diff   # như CI
```

Không có `MG_TEST_PG_ADMIN_URL` thì test tích hợp được bỏ qua — trừ khi `MG_TEST_PG_REQUIRED=1` (CI đặt biến này,
nên thiếu PostgreSQL là FAIL). CI (`.github/workflows/go.yml`) chạy PostgreSQL bằng service container pin theo digest.
Cùng cách đó cho test tích hợp của `internal/secrets` (P2-T04), `internal/authz` (P2-T07) và `internal/identity`
(P2-T06). Package khác cần PostgreSQL thật dùng harness chung `internal/store/storetest` (mỗi lần gọi một database mới
đã bootstrap + `MigrateAll`) — như `internal/jobs` (P2-T12) và test lắp API `internal/httpapi/authzhook`.

**Nhiều package test dùng chung một cụm:** `go test ./...` chạy các package song song, mà role là đối tượng của cả
cụm — hai package cùng bootstrap/migrate (`CREATE ROLE`, `GRANT` role) hoặc đặt mật khẩu role (`ALTER ROLE`) một lúc
sẽ lỗi (`duplicate key … pg_authid_rolname_index`, `tuple concurrently updated`; đối chứng ở bằng chứng P2-T04,
P2-T06). Hai quy tắc chung nằm ở **một** chỗ — package `internal/store/storetest/pgcluster` (lá, chỉ phụ thuộc `pgx`,
để chính test của `internal/store` import được mà không vòng import):

- `pgcluster.Lock` — giữ advisory lock phiên `pgcluster.LockKey` (`0x6d675f74657374`, "mg_test", lấy trong database
  `postgres`) từ `CREATE DATABASE` tới khi đặt xong mật khẩu role (bootstrap, migrate, `SetRolePassword`);
- `pgcluster.RolePassword` — mật khẩu role dẫn xuất `sha256("meshguard-test|" + mật khẩu superuser + "|" + role)`
  (hex), nên package này đặt lại mật khẩu không làm hỏng đăng nhập của package khác.

Harness mới (của package mới) phải dùng `storetest` hoặc hai hàm trên — không tự đặt khóa hay công thức khác.
