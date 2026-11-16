# database

PostgreSQL của Management Plane (§6 của [bản master](../docs/planning/implementation-master-plan.md)): một database
`meshguard`, dữ liệu chung có `tenant_id` + Row-Level Security. Bắt đầu ở P2-T03 — bằng chứng:
[`docs/planning/evidence/P2-T03.md`](../docs/planning/evidence/P2-T03.md).

| Đường dẫn | Nội dung |
|---|---|
| `bootstrap/superuser.sql` | Chạy **một lần** bằng superuser của cụm, trong database `meshguard`, trước migration đầu tiên (chạy lại được): tạo `mg_migrator` (CREATEROLE, owner database) và `mg_backup` (BYPASSRLS + `pg_read_all_data`) — hai role chỉ superuser tạo được |
| `migrations/0001…0006_*.sql` | Migration goose, forward-only (không có phần Down), nhúng vào binary qua `embed.go`; bản đồ bảng ở §6.3 |
| `queries/*.sql` + `sqlc.yaml` | Truy vấn sqlc → mã sinh ở `internal/store/sqlcdb` (không sửa tay) |
| `checks/partition_grants.sql` | Truy vấn CI: mỗi hàng là một vi phạm (quyền trên partition, partition chưa bật RLS, default privileges) |
| `embed.go` | Package Go `database`: `Migrations`, `Seeds`, `Bootstrap`, `Checks` (embed.FS) |
| `seeds/*.sql` | Dữ liệu tham chiếu áp **sau mỗi lần migrate** (`store.Migrate` → `store.Seed`: theo tên file, một transaction, `pg_advisory_xact_lock`, chạy bằng `mg_migrator`, idempotent). `seeds/rbac.sql` (P2-T07) là file **sinh** từ §8.4–§8.6 bằng `make authz-gen` — không sửa tay, spec-lint fail khi lệch; seed gói/plan ở P3-T06 |

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
| `mg_api_platform`, `mg_worker_platform` | có | `mg_app_platform` | pool platform của api / worker | bảng T+P, P, `sessions`… | `mg-sec-api` / `mg-sec-worker` |
| `mg_audit_writer` | có | — | đường ghi audit detached (P2-T08) | chỉ `INSERT` vào `audit_events` | `mg-sec-app` |
| `mg_partition_maint` | có | — | job `partition.maintain` | owner `audit_events` + partition; `CREATE` trên schema `partitions` | `mg-sec-worker` |
| `mg_readonly` | có | — | báo cáo | chỉ schema `report` (chưa có view — đến cùng 0016/P6-T11); không có cả `USAGE` trên `public` | (chưa cấp) |
| `mg_migrator` | có | — | job `migrate` | owner database, CREATEROLE (ADMIN trên role nó tạo) | `mg-sec-migrate` |
| `mg_backup` | có | — | `pg-backup` (P2-T03a) | `pg_read_all_data` + BYPASSRLS, `default_transaction_read_only` | `mg-sec-backup` |

Mọi role ứng dụng `NOSUPERUSER NOBYPASSRLS`, không DDL (không `CREATE` trên schema, không `TEMPORARY`), không bao giờ
`TRUNCATE`; quyền chỉ cấp tường minh (không default privileges); cột bất biến (vd. `identities.idp_id/tenant_id/scope`)
không có quyền `UPDATE`. `store.Open` từ chối khởi động khi role của pool tenant không thuộc `mg_app_tenant` (hoặc thuộc
cả `mg_app_platform`), và ngược lại.

## RLS

- Helper `app_tenant_id()` = `NULLIF(current_setting('app.tenant_id', true), '')::uuid`, `app_is_platform()` =
  `COALESCE(current_setting('app.scope', true), '') = 'platform'` — biến chưa đặt hoặc rỗng ⇒ 0 hàng, không lỗi.
- Mọi bảng có ký hiệu T, T+P, P ở §6.3: `ENABLE` + `FORCE ROW LEVEL SECURITY`. Ký hiệu "—": `roles`, `permissions`,
  `role_permissions`, `sessions`, `auth_requests` (hai bảng sau chỉ cấp cho role platform).
- Truy vấn chỉ chạy qua `store.WithTenantTx(ctx, tenantID, fn)` (pool tenant, `app.scope='tenant'` + `app.tenant_id`)
  hoặc `store.WithPlatformTx(ctx, fn)` (pool platform, `app.scope='platform'`, xóa `app.tenant_id`), biến đặt bằng
  `set_config(…, true)` nên hết hiệu lực khi transaction kết thúc. Test kiến trúc (`internal/archtest`) cấm mọi package
  ngoài `internal/store` import driver DB (`pgx`, `database/sql`, `goose`).
- `secrets`/`tenant_keys`: policy `RESTRICTIVE` theo role ẩn phạm vi `platform_ops` khỏi `mg_api_*` (§7.6).
- `audit_events`: pool tenant thấy sự kiện của tenant đang đặt; pool platform chỉ thấy sự kiện platform (`tenant_id`
  NULL); append-only (không cấp `UPDATE/DELETE/TRUNCATE` + trigger chặn cả owner).

## Partition và job `partition.maintain`

`audit_events` partition theo tháng (UTC) trong schema riêng `partitions` (`partitions.audit_events_pYYYYMM` +
`partitions.audit_events_default`). Role ứng dụng không có `USAGE` trên schema này và không có quyền trên partition
nào — RLS của bảng cha **không** áp dụng khi truy vấn thẳng partition. Hàm `mg_partition_maintain(bảng, số_tháng)`
(chạy bằng `mg_partition_maint`) tạo idempotent partition DEFAULT + tháng hiện tại + N tháng tới, bật RLS (không
FORCE) và chép trigger `TRUNCATE` của bảng cha sang partition mới; migration 0004 đã tạo sẵn tháng hiện tại + 3.
Trong Go: `store.OpenPartitionMaintainer(...).Maintain(ctx, store.PartitionMonthsAhead)` trả về partition vừa tạo và
số hàng nằm trong DEFAULT (> 0 ⇒ cảnh báo). Đăng ký thành job hằng ngày: P2-T12. Export + drop partition quá
retention: chưa làm (lần đầu cần sau ≥ 400 ngày — §6.4). `usage_records` (0016, P6-T11) thêm vào
`store.PartitionedTables`.

## Triển khai (P2-T16 nối vào job `migrate` của `mg-core`)

1. Superuser: `psql -U postgres -d meshguard -v ON_ERROR_STOP=1 < database/bootstrap/superuser.sql` (hoặc `store.Bootstrap`).
2. **Mật khẩu role** — không bao giờ nằm trong repo, biến môi trường hay URL: mỗi role một file secret trên host
   (`/opt/meshguard/secrets/<service>/…`, nhóm `mg-sec-*` ở §14.2; mật khẩu DB lưu mỗi consumer một bản và xoay cùng
   lúc). Mật khẩu là một dòng ASCII in được, không khoảng trắng, ≥ 16 ký tự, ví dụ sinh bằng
   `openssl rand -hex 32 > <file>` (umask 077). Bên đặt mật khẩu dùng `store.SetRolePassword`: verifier
   SCRAM-SHA-256 được tính ở client nên plaintext không tới server (log, `pg_stat_activity`). Superuser đặt cho
   `mg_migrator`, `mg_backup`; `mg_migrator` (ADMIN trên các role nó tạo) đặt cho các role còn lại sau migration.
   Lệnh quản trị gói các bước này chưa có — P2-T16.
3. `mg_migrator`: `store.OpenMigrator(url, store.Credentials{User: "mg_migrator", PasswordFile: …})` rồi
   `store.Migrate` (goose, session lock; luôn có dump trước migration — P2-T03a), rồi `seeds/*.sql` trong cùng lệnh.
4. Tiến trình: `store.Open(ctx, store.Config{URL: "postgres://postgres:5432/meshguard?sslmode=…", Tenant: …,
   Platform: …})` — URL không chứa user/mật khẩu; mật khẩu đọc lại từ file ở mỗi kết nối mới (xoay không cần restart).

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
  go test -race -count=1 ./internal/store/
make sqlc        # sinh lại internal/store/sqlcdb (cần CGO)
make sqlc-diff   # như CI
```

Không có `MG_TEST_PG_ADMIN_URL` thì test tích hợp được bỏ qua — trừ khi `MG_TEST_PG_REQUIRED=1` (CI đặt biến này,
nên thiếu PostgreSQL là FAIL). CI (`.github/workflows/go.yml`) chạy PostgreSQL bằng service container pin theo digest.

**Nhiều package cùng một cụm thử:** role là đối tượng của cả cụm và `go test ./...` chạy các package song song, nên hai
package cùng migrate (`CREATE ROLE`) hoặc đặt mật khẩu role (`ALTER ROLE`) một lúc sẽ đua nhau. Harness của mọi package
tạo database thử (`internal/store`, `internal/authz`, …) phải giữ advisory lock phiên `pg_advisory_lock(0x6d6774657374)`
trên database `postgres` trong lúc tạo database, migrate và đặt mật khẩu, và dùng cùng công thức mật khẩu dẫn xuất
(`sha256("meshguard-test|" + mật khẩu superuser + "|" + role)`).
