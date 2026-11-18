# Runbook — Backup và restore PostgreSQL, IdP, edge

> **File viết tay — không sinh từ master.** Runbook của task **P2-T03a** (service `pg-backup`), **P2-T05b** (dump DB của IdP, sao lưu volume ACME của edge) và **P3-T17** (chế độ bảo trì + đối soát sau khi restore PostgreSQL về thời điểm cũ hơn — mục 6.5) — §14.4, §16.3, §17.1–§17.3 của [bản master](../planning/implementation-master-plan.md). Bằng chứng và kết quả diễn tập: [P2-T03a](../planning/evidence/P2-T03a.md). Mã nguồn: [`apps/backup`](../../apps/backup/main.go), [`infrastructure/docker/backup`](../../infrastructure/docker/backup/Dockerfile), [`compose.backup.yaml.tmpl`](../../infrastructure/compose/compose.backup.yaml.tmpl), [`tools/render_backup.py`](../../tools/render_backup.py), diễn tập [`tests/backup/drill.sh`](../../tests/backup/drill.sh). Khóa khôi phục: [nghi thức khóa](key-ceremony.md).

**Trạng thái:** functional, **chưa lên host**. Kích hoạt trên host ở P2-T16, sau nghi thức khóa P2-T04a (mục 4).

## 1. Tổng quan

Ba dịch vụ có lịch riêng trong project compose **`mg-backup`** (một image; không cron/systemd trên host; không phải job của Worker hay Agent):

| Dịch vụ | Nguồn | Chạy bằng | Network | Ghi vào (duy nhất) | Lịch (UTC) | Bộ backup |
|---|---|---|---|---|---|---|
| `pg-backup` | DB `meshguard` của `postgres` (mg-core) | `10007:20007`, role DB `mg_backup` (BYPASSRLS + `pg_read_all_data`, mặc định read-only) | `mg-data` | `/opt/meshguard/backups/postgres` | 02:30 | `globals.sql.age` (`pg_dumpall --globals-only --no-role-passwords`) + `pgdump.age` (`pg_dump --format=custom`) |
| `idp-backup` | DB `keycloak` của `idp-db` (mg-idp) | `10007:20007`, role DB `idp_backup` (chỉ `pg_read_all_data`) | `mg-idp-data` | `/opt/meshguard/backups/idp` | 02:40 | như trên |
| `edge-backup` | volume ACME `mg-edge_edge-data`, mount **chỉ-đọc** | `10001:20007` (UID của edge — đọc được khóa 0600, không cần capability) | không có | `/opt/meshguard/backups/edge` | 02:50 | `tar.age` (owner số, mode, mtime, symlink) |

Bất biến (kiểm bằng test và diễn tập):

- **Mã hóa trước khi ghi.** Plaintext chỉ đi qua pipe (`pg_dump` → `age`, hoặc bộ ghi tar → `age`); thứ duy nhất được ghi xuống đĩa là output của `age --encrypt --recipient <khóa khôi phục>` (age X25519, `MG_BACKUP_RECOVERY_RECIPIENT`). Không có file plaintext tạm, kể cả khi lỗi.
- **Không bao giờ ghi bản không mã hóa.** Recipient trống, sai định dạng/mã kiểm bech32, chứa private key, hoặc khác recipient trong file của nghi thức khóa trên host (`/opt/meshguard/core/keys/backup-recovery.age-recipient`, mount chỉ-đọc) ⇒ tiến trình **dừng với exit 2 và không ghi gì** (không cả file trạng thái). Container khởi động lại liên tục và log nói rõ lý do; cảnh báo quá hạn backup bắn sau 26 giờ.
- **Không giữ bộ dở dang.** Mỗi file ghi vào `.<tên>.partial` rồi đổi tên khi `pg_dump`/tar, `age` và việc ghi đều thành công; manifest ghi **cuối cùng** — bộ không có manifest là bộ dở và bị xóa ở lượt sau. Dump bị cắt giữa chừng không bao giờ được giữ, dù `age` đã mã hóa phần đã nhận.
- **Không secret trong biến môi trường.** Mật khẩu DB là Docker secret dạng file (`/opt/meshguard/secrets/backup/*`, `root:mg-sec-backup 0440`); libpq nhận nó qua file pgpass `0600` trên tmpfs riêng của container, xóa sau mỗi lượt.
- Hardening: rootfs chỉ-đọc, `cap_drop: ALL`, `no-new-privileges`, giới hạn RAM/PID, không cổng, không Docker socket; mỗi dịch vụ chỉ mount ghi **một** thư mục đích.

Image: `meshguard-backup` (Go tĩnh) + `pg_dump`/`pg_dumpall`/`pg_restore` **18.7** chép từ đúng image `postgres` đang chạy + `age` v1.3.2 build tái lập (sha256 = `versions.lock [sources.age]`, kiểm trong build) trên distroless `base-debian13`. Shell duy nhất là `dash` làm `/bin/sh`, vì `pg_dumpall` gọi `popen("pg_dump -V")`; không bash/perl/coreutils.

## 2. Bộ backup, manifest và file trạng thái (nguồn của cảnh báo)

Tên file: `<target>-<YYYYMMDDTHHMMSSZ>-<nhãn>.<phần>` — target `postgres|idp|edge`, nhãn `scheduled` (lịch hằng ngày), `pre-migration` (trigger trước migration), `manual` (người vận hành); phần `globals.sql.age`, `pgdump.age`, `tar.age`, `manifest.json`. File `0640`, owner = UID của dịch vụ, nhóm `mg-sec-backup`.

`<id>.manifest.json` (plaintext, không secret): `format` = `meshguard-backup/v1`, `id`, `target`, `label`, `started_at`, `finished_at`, `recipient`, `source` (`postgresql://<user>@<host>:<port>/<db>` hoặc thư mục), `tools` (phiên bản `pg_dump`, `pg_dumpall`, `age`, `meshguard-backup`), `files[]` (`name`, `content`, `size`, `sha256` **của ciphertext**).

`status.json` — **hook cảnh báo quá hạn backup (§16.3)** cho P3-T16/P6-T01; ghi lại nguyên tử sau mỗi lượt chạy (thành công hay thất bại); lượt dừng vì lỗi cấu hình không ghi:

| Trường | Ý nghĩa |
|---|---|
| `format` | `meshguard-backup-status/v1` |
| `target`, `updated_at` | target; thời điểm ghi |
| `max_age_seconds` | ngưỡng quá hạn (`MG_BACKUP_MAX_AGE`, mặc định 26 giờ = 24 giờ + 2 giờ ân hạn) |
| `consecutive_failures` | số lượt thất bại liên tiếp từ lần thành công gần nhất |
| `last_attempt` | `id`, `label`, `started_at`, `finished_at`, `ok`, `error` (đã che secret) |
| `last_success` | như trên + `total_bytes` và `files[]` (`name`, `size`, `sha256` của ciphertext) |

`status.prom` — cùng số liệu ở định dạng text của Prometheus (textfile collector): `meshguard_backup_last_success_timestamp_seconds`, `meshguard_backup_last_success_bytes`, `meshguard_backup_last_attempt_success`, `meshguard_backup_consecutive_failures`, `meshguard_backup_max_age_seconds` (nhãn `target`). Rule gợi ý cho P3-T16:

```text
# High: quá hạn hoặc chưa từng thành công (status thiếu = dịch vụ chưa chạy được lần nào)
time() - meshguard_backup_last_success_timestamp_seconds > meshguard_backup_max_age_seconds
absent(meshguard_backup_last_success_timestamp_seconds{target="postgres"})   # tương tự idp, edge
meshguard_backup_consecutive_failures >= 2
```

Xem nhanh trên host: `sudo docker compose -p mg-backup -f /opt/meshguard/core/compose.backup.yaml run --rm pg-backup status` (exit 1 nếu quá hạn).

## 3. Retention

| Nhãn | Giữ | Biến |
|---|---|---|
| `scheduled` | mọi bộ trong **14 ngày**, và luôn ≥ **7** bộ mới nhất | `MG_BACKUP_KEEP_DAYS`, `MG_BACKUP_KEEP_MIN` |
| `pre-migration`, `manual` | **5** bộ mới nhất của mỗi nhãn (không xóa theo tuổi) | `MG_BACKUP_KEEP_ONDEMAND` |

Các con số trên được chủ dự án duyệt ngày 2026-11-17 (§17.1 không nêu số); đổi chúng là thay đổi cần duyệt lại.

Retention chỉ chạy **sau một lượt thành công** (dịch vụ đang lỗi không làm mòn các bộ đang có), chỉ xóa file đúng mẫu tên của target đó, xóa manifest trước (gián đoạn giữa chừng để lại bộ dở, bị dọn ở lượt sau — không bao giờ để lại manifest trỏ tới file đã mất). Đây là retention **cục bộ**; offsite và retention dài hơn do `backup-shipper` (P6-T03/P6-T04). Hệ quả cần biết (§6.1 "Retention"): wrapped DEK của tenant đã xóa còn trong dump PostgreSQL tới hết retention này (14 ngày cục bộ + retention offsite). Dung lượng: `backups/` phải là filesystem riêng hoặc có quota + cảnh báo (§14.2).

## 4. Kích hoạt trên host (P2-T16)

Điều kiện: nghi thức khóa P2-T04a đã xong — host có `/opt/meshguard/core/keys/backup-recovery.age-recipient` và `MG_BACKUP_RECOVERY_RECIPIENT` đã ghi vào `infrastructure/environments/staging/staging.env` (`ceremony.sh status`).

1. Workflow `images` build image `backup` trên `main`; ghi digest vào `versions.lock` bằng commit riêng (như `[images.mg-idp]`):

   ```toml
   [images.mg-backup]
   image = "ghcr.io/zhaduchanhzz/network-access-mesh/backup"
   tag = "<commit SHA>"
   index = "sha256:<digest từ GHCR>"
   user = "10007:20007"
   ```

2. Bố cục và secret: `sudo bash infrastructure/host/layout.sh` (thư mục `backups/postgres|idp` thuộc `10007:mg-sec-backup 0750`, `backups/edge` thuộc `10001:mg-sec-backup 0750`, sinh `secrets/backup/pg_backup_password`); `sudo bash infrastructure/idp/secrets.sh` (sinh `secrets/idp/backup_db_password` và bản `secrets/backup/idp_backup_password`, cùng giá trị).
3. Mật khẩu `mg_backup`: superuser đặt verifier SCRAM từ `secrets/backup/pg_backup_password` bằng `store.SetRolePassword` (lệnh quản trị của P2-T16 — `database/README.md`, mục "Triển khai" bước 2). Không bao giờ đưa mật khẩu lên dòng lệnh.
4. Role `idp_backup`: idp-db **mới** — `initdb/20-idp-backup-role.sql` tự chạy. idp-db **đã khởi tạo** — render lại compose IdP (thêm secret `idp_backup_db_password`), recreate `idp-db` (giữ volume), rồi chạy một lần:

   ```bash
   sudo docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml up -d --wait idp-db
   sudo docker exec -i "$(sudo docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml ps -q idp-db)" \
     psql -X -v ON_ERROR_STOP=1 -U postgres -d keycloak < /opt/meshguard/core/idp/initdb/20-idp-backup-role.sql
   ```

5. Render và kiểm (render từ chối khi recipient trống/sai; `check` không ghi gì):

   ```bash
   python3 tools/render_backup.py infrastructure/environments/staging/staging.env /tmp/mg-backup   # rồi chép compose.backup.yaml sang /opt/meshguard/core/
   C="sudo docker compose -p mg-backup -f /opt/meshguard/core/compose.backup.yaml"
   for s in pg-backup idp-backup edge-backup; do $C run --rm -T "$s" check; done              # exit 0 cả ba
   $C up -d                                                                                    # chưa có status ⇒ lượt bù chạy ngay
   ```

6. Xác nhận: `sudo cat /opt/meshguard/backups/{postgres,idp,edge}/status.json` — `last_attempt.ok = true`; ghi id các bộ đầu tiên vào bằng chứng P2-T16.

Hoàn tác: `$C down` (các bộ backup đã có giữ nguyên). Volume ACME là `external` — `down -v` không xóa nó.

## 5. Trigger trước migration (bắt buộc — P2-T03a)

Job `migrate` của P2-T16 **phải** chạy lệnh này ngay trước `store.MigrateAll` và dừng nếu exit ≠ 0:

```bash
sudo docker compose -p mg-backup -f /opt/meshguard/core/compose.backup.yaml run --rm -T pg-backup once --label pre-migration
```

| Exit | Nghĩa | Migrate |
|---|---|---|
| 0 | bộ `postgres-<thời điểm>-pre-migration` đã ghi đủ, manifest + `status.json` cập nhật | được chạy; ghi id bộ vào log triển khai |
| 1 | backup thất bại (DB, mật khẩu, đĩa) — không giữ file nào | **không** |
| 2 | cấu hình sai (recipient, công cụ, đường dẫn) — không ghi gì | **không** |

Lệnh dùng đúng cấu hình của dịch vụ (network, secret, mount, user) và chờ nếu lượt theo lịch đang chạy (khóa `flock` trên thư mục đích). Rollback sau migration lỗi = restore bộ này (mục 6.3) + triển khai lại image trước (§17.6).

## 6. Restore PostgreSQL

### 6.1 Chọn bộ

`sudo ls /opt/meshguard/backups/postgres/*.manifest.json` — bộ trước migration để rollback; bộ `scheduled` mới nhất cho sự cố dữ liệu. Kiểm sha256 trong manifest khớp file (`sudo sha256sum …`). Bản offsite (từ P6) dùng cùng định dạng.

### 6.2 Identity khôi phục (đường DR — §17.1)

Bộ backup chỉ mở được bằng **identity khôi phục offline** (2 bản giấy của P2-T04a). Chủ dự án nhập trong terminal của mình, **không echo**, vào tmpfs; người vận hành không nhìn màn hình:

```bash
sudo install -d -m 0700 /run/mg-restore            # /run là tmpfs
sudo bash -c 'umask 077; read -rs v; printf "AGE-SECRET-KEY-1%s\n" "$(printf %s "${v//[ -]/}" | tr a-z A-Z)" > /run/mg-restore/identity'
# gõ các nhóm sau "AGE-SECRET-KEY-1" trên giấy, liền một dòng, rồi Enter. Kiểm khớp recipient (công khai):
sudo infrastructure/host/key-ceremony/bin/age-keygen -y /run/mg-restore/identity   # phải = MG_BACKUP_RECOVERY_RECIPIENT
```

`age` dùng bản build tái lập của bộ kit (`infrastructure/host/key-ceremony/bin/age`, sha256 kiểm như `ceremony.sh`). Xong việc: `sudo shred -u /run/mg-restore/identity`. Giải mã luôn **ghép ống thẳng** vào `psql`/`pg_restore` — không bao giờ giải mã ra file.

Biến dùng ở dưới: `B=/opt/meshguard/backups/postgres/<id>`, `AGE="sudo infrastructure/host/key-ceremony/bin/age --decrypt --identity /run/mg-restore/identity"`, `PG=$(sudo docker compose -p mg-core -f /opt/meshguard/core/compose.core.yaml ps -q postgres)`.

### 6.3 Restore vào môi trường đang dùng (rollback sau migration, sự cố dữ liệu)

Restore vào môi trường đang dùng **luôn** là restore về thời điểm cũ hơn: theo đúng trình tự của mục 6.5 (bảo trì →
restore → migrate nếu cần → đối soát → rà báo cáo → tắt bảo trì). Các bước 1–4 dưới đây là phần "restore" của trình tự đó.

1. Bật chế độ bảo trì rồi dừng api và worker (không để ghi vào DB đang thay — mục 6.5 bước 1–2):
   `$APP exec -T api /usr/local/bin/meshguard admin maintenance on --reason pg-restore` rồi `$APP stop api worker`
   (`APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"`).
2. Giữ DB hiện tại để điều tra (đổi tên, không xóa):

   ```bash
   sudo docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres \
     -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'meshguard' AND pid <> pg_backend_pid()" \
     -c "ALTER DATABASE meshguard RENAME TO meshguard_before_restore_$(date -u +%Y%m%d%H%M)"
   ```

3. Globals — role đã có, nên bỏ mọi `CREATE ROLE` và áp lại thuộc tính/thành viên/thiết lập của role đúng như lúc backup:

   ```bash
   sudo cat "$B.globals.sql.age" | $AGE | sed -E '/^CREATE ROLE [a-z_][a-z0-9_]*;$/d' \
     | sudo docker exec -i "$PG" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres
   ```

   Lỗi "role … does not exist" nghĩa là migration sau bộ backup đã xóa role đó — tạo lại role (`CREATE ROLE <tên>;`) rồi chạy lại bước này.
4. Dữ liệu (tạo lại DB `meshguard` cùng owner, ACL và thiết lập của DB):

   ```bash
   sudo cat "$B.pgdump.age" | $AGE | sudo docker exec -i "$PG" pg_restore -U postgres -d postgres --create --exit-on-error
   ```

5. **Đối soát sau restore** — bắt buộc: migrate nếu cần, bật cờ bảo trì trong DB vừa restore, khởi động api/worker ở chế
   độ bảo trì, `meshguard admin post-restore-reconcile`, rà báo cáo, tắt bảo trì: **mục 6.5 bước 3–9**. Quyền/phiên bị thu
   hồi sau thời điểm backup không được sống lại; API không mở lại trước khi đối soát xong.
6. Kiểm `/readyz` của api/worker (SecretStore mở được DEK trong DB đã restore — KEK không nằm trong backup). Giữ
   `meshguard_before_restore_*` tới khi chắc chắn, rồi `DROP DATABASE`.
7. Chạy ngay một backup `manual` (mục 5, `--label manual`) để có điểm khôi phục mới.

### 6.4 Restore lên cụm mới (mất host — DR)

Theo `current.md` mục 3 dựng host, KEK từ giấy ([nghi thức khóa](key-ceremony.md) mục 10), `layout.sh`, compose `mg-core` với **chỉ** `postgres` chạy. `POSTGRES_DB=meshguard` đã tạo một DB rỗng:

```bash
sudo docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres -c "DROP DATABASE meshguard"
sudo cat "$B.globals.sql.age" | $AGE | sed '/^CREATE ROLE postgres;$/d' \
  | sudo docker exec -i "$PG" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres
sudo cat "$B.pgdump.age" | $AGE | sudo docker exec -i "$PG" pg_restore -U postgres -d postgres --create --exit-on-error
```

Backup **không** chứa mật khẩu role (`--no-role-passwords`): đặt lại verifier cho mọi role đăng nhập từ các file secret (mục 4 bước 3; superuser cho `mg_migrator`/`mg_backup`, `mg_migrator` cho các role còn lại — `database/README.md`). Rồi làm bước 5–7 của mục 6.3 — tức mục 6.5 từ bước 3 (cụm mới luôn là "restore về thời điểm cũ hơn"; api/worker chưa
từng chạy trên cụm này nên bỏ qua bước 1–2 của mục 6.5). Kiểm tra sau restore: `SELECT count(*)` các bảng chính; `database/checks/partition_grants.sql` trả 0 hàng.

### 6.5 Restore về thời điểm cũ hơn — chế độ bảo trì và đối soát (P3-T17, §17.2)

Sau khi restore (dump đêm — RPO 24 giờ tới P6-T03 —, hoặc bộ `pre-migration` khi lùi một migration) registry **cũ hơn**
trạng thái thật của các instance: session, support grant, phê duyệt, lời mời bị thu hồi trong khoảng mất dữ liệu sống
lại; tenant tạo trong khoảng đó chỉ còn trên host; API key xoay trong khoảng đó không còn trong SecretStore; policy áp
trong khoảng đó mới hơn bản DB biết. Headscale vẫn phục vụ client suốt quá trình (§17.4) và **là nguồn đúng** cho node,
key và policy đang hiệu lực (§6.4). Thiết kế, kết quả diễn tập và giới hạn: [P3-T17](../planning/evidence/P3-T17.md). Mục này là restore **PostgreSQL**
— các instance giữ nguyên; restore **một instance Headscale** từ backup của nó (P3-T11, 2P
`POST /platform/instances/{id}/restore`, §17.2) là thao tác khác, làm sau khi đã tắt bảo trì.

**Chế độ bảo trì** (api: `503 maintenance` + `Retry-After: 60` cho mọi request — kể cả cổng console Keycloak — trừ đăng
nhập platform trên `admin.<domain>`; worker: không job nào của hàng đợi chạy, không lịch nào enqueue) bật khi **một
trong hai** công tắc bật:

| Công tắc | Đặt bằng | Dùng khi |
|---|---|---|
| Cờ lưu `system_settings` khóa `maintenance` | `meshguard admin maintenance on`, `off`, `status` (binary api — `exec` vào api đang chạy, hoặc `run --rm --no-deps` khi api đã dừng; audit `platform.maintenance.enable`/`.disable`, `actor_type=system`); bước đầu của `post-restore-reconcile` cũng đặt nó trong DB vừa restore | mặc định của runbook; mọi tiến trình đọc lại mỗi 5 giây |
| Biến `MG_MAINTENANCE=1` lúc khởi động | file override `infrastructure/compose/compose.app.maintenance.yaml` (chép sang `/opt/meshguard/core/`) | khi không ghi được DB trước lúc khởi động; thoát chỉ bằng khởi động lại không kèm file override |

`maintenance off` **bị từ chối** khi bản ghi `post_restore` của cờ đang `running` hoặc `failed` (lệnh đối soát chưa
xong hoặc lỗi — chạy lại nó); `--force` bỏ qua (audit ghi `forced`). Lệnh đối soát xong nhưng `incomplete` không chặn
(người vận hành đã rà báo cáo) — `status` nhắc lại số mục chưa xong.

```bash
cd ~/mg && sudo -v
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
B=/opt/meshguard/backups/postgres/<id>            # bộ sẽ restore (mục 6.1)

# 1. bảo trì trên DB đang dùng (sự kiện audit ở lại trong DB cũ — giữ để điều tra); ≤ 10 s sau: api 503, worker dừng job
$APP exec -T api /usr/local/bin/meshguard admin maintenance on --reason pg-restore
$APP logs --since 1m worker | grep -c 'stopping the job worker'                     # ≥ 1

# 2. dừng api + worker, rồi restore: mục 6.3 bước 2–4 (hoặc 6.4 cho cụm mới)
$APP stop api worker

# 3. migrate nếu bộ backup cũ hơn schema của image đang chạy (luôn qua migrate.sh: backup pre-migration trước)
$APP --profile migrate run --rm -T migrate migrate status  # exit ≠ 0 (schema cũ hơn bản này) ⇒ chạy dòng dưới
sudo bash infrastructure/host/migrate.sh

# 4. cờ bảo trì trong DB VỪA RESTORE, trước khi api/worker khởi động (DB của bản dump không có cờ)
$APP run --rm --no-deps -T api admin maintenance on --reason post-restore
#    (cách khác: thêm -f /opt/meshguard/core/compose.app.maintenance.yaml vào lệnh up ở bước 5)

# 5. khởi động — vẫn ở chế độ bảo trì
$APP up -d --wait api worker
curl -sk --resolve "app.$MG_BASE_DOMAIN:443:127.0.0.1" "https://app.$MG_BASE_DOMAIN/api/v1/tenants" | grep -c '"maintenance"'   # 1

# 6. điểm khôi phục = started_at trong manifest của bộ đã restore (RFC 3339)
RP=$(sudo python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["started_at"])' "$B.manifest.json")

# 7. đối soát: chạy thử (không ghi gì, không đụng instance) rồi chạy thật; báo cáo JSON lưu lại để rà
TS=$(date -u +%Y%m%dT%H%M%SZ)
$APP exec -T worker /usr/local/bin/meshguard admin post-restore-reconcile --restore-point "$RP" --dry-run \
  | sudo tee "/root/post-restore-$TS-dry.json" >/dev/null
$APP exec -T worker /usr/local/bin/meshguard admin post-restore-reconcile --restore-point "$RP" \
  | sudo tee "/root/post-restore-$TS.json" >/dev/null; echo "exit ${PIPESTATUS[0]}"

# 8. rà báo cáo (mục dưới) — chạy lại bước 7 sau mỗi lần sửa (lệnh idempotent)

# 9. tắt bảo trì (từ chối nếu lần chạy cuối của bước 7 chưa xong hoặc lỗi), rồi backup manual (mục 6.3 bước 7)
$APP exec -T api /usr/local/bin/meshguard admin maintenance off
#    nếu đã khởi động bằng file override: $APP up -d --wait api worker   (tạo lại container không có MG_MAINTENANCE)
```

Mã thoát của `post-restore-reconcile`: `0` hoàn tất (báo cáo vẫn có thể nêu mục cần rà); `3` chưa đủ — `incomplete` nêu
bước và đối tượng không làm được (Agent không cấu hình/không tới được, instance không tới được, key không cấp lại được) —
sửa rồi chạy lại; `1` lỗi (cờ ghi `post_restore.status = failed` ⇒ `maintenance off` bị chặn); `2` sai cú pháp hoặc
điểm khôi phục ở tương lai. Lệnh dùng quyền của worker (Host Agent — `MG_AGENT_*`, kek-app, policy, lời mời; migration
0018 cho nó quyền thu hồi session, migration 0023 quyền `UPDATE (status, revoked_at, …)` trên `support_access_grants`).
Từ P4-T05 lệnh thu hồi cả Support Access Grant của bản dump (trước đó nó từ chối chạy khi schema có bảng này).

Các bước của lệnh (`cutoff` = đồng hồ DB lúc lệnh bắt đầu; mọi bước idempotent; `--dry-run` chỉ đọc và đếm):

| # | Bước | Ghi gì | Báo cáo (khóa JSON) |
|---|---|---|---|
| 1 | Cờ bảo trì ON + bản ghi `post_restore` (`running`) trong DB vừa restore | `system_settings`, audit `platform.restore.reconcile.requested` (+ `platform.maintenance.enable` nếu cờ chưa bật) | `maintenance` |
| 2 | Thu hồi mọi session tạo trước `cutoff` (kể cả đã hết hạn), xóa `auth_requests` của bản dump; yêu cầu phê duyệt `pending`/`approved` ⇒ `expired`; phiên console Keycloak đã thực thi còn trong cửa sổ ⇒ `expired`; lời mời `pending` ⇒ `revoked`; Support Access Grant `approved` ⇒ `revoked`, `pending` ⇒ `expired` (P4-T05) | `sessions.revoked_at`, `approval_requests.status`, `tenant_invitations.status`, `support_access_grants.status`/`revoked_at` | `sessions`, `approvals`, `invitations`, `support_grants` (`checked` + `revoked`/`expired`/`by_status`; `not_in_schema` với bản dump của schema trước `0023`) |
| 3 | Inventory của Host Agent so với registry: instance trên host không có trong registry ⇒ **mồ côi** — chỉ báo cáo (không xóa, không adopt; `security_event` `reconcile.unknown_instance`); instance trong registry không còn gì trên host ⇒ **mất** — `failed` (audit `platform.instance.lost`), không provision lại | `tenant_instances.status` | `instances.orphans`, `instances.lost` |
| 4 | API key mỗi instance đang chạy: phép xoay của P3-T10 dưới khóa `instance.apikey`, `AllowBootstrap`, trigger `post_restore` — key đang lưu dùng được và chưa tới hạn ⇒ không đổi; bị từ chối (đã xoay trong khoảng mất dữ liệu) hoặc mất ⇒ Agent `BootstrapApiKey` cấp key mới, expire mọi key khác | SecretStore, `tenant_instances.api_key_*`, audit `instance.apikey.rotate.*` | `api_keys` |
| 5 | `GetPolicy` so với lần áp dụng hiện hành: khác ⇒ **không bao giờ áp bản cũ**: ghi chuỗi đang chạy thành lần áp dụng hiện hành (`trigger=restore`), nhập thành version `user` trạng thái `validated` (lint lỗi ⇒ `draft`) làm desired, cờ rà soát `policy.restore_review_required` (tenant thấy được); user `mg-<uuid>` không còn membership được liệt kê | `policy_versions`, `policy_applications`, `tenants.desired_policy_version_id`, audit `policy.restore_adopted` | `policies` |
| 6 | `inventory.sync` cho mọi instance đang chạy (chạy khi worker ra khỏi bảo trì) | `provisioning_jobs` (queued) | `inventory_sync` |
| 7 | Job còn mở trong bản dump — chỉ liệt kê (worker sẽ chạy tiếp chúng khi tắt bảo trì) | — | `open_jobs` |
| 8 | `audit.gap` (một sự kiện platform + một mỗi tenant, `from`/`to` = điểm khôi phục/`cutoff`, một lần mỗi điểm khôi phục), `post_restore.status = reconciled`, audit `.succeeded` | `audit_events`, `system_settings` | `audit_gap`, `status`, `incomplete`, `review_required` |

**Rà báo cáo trước khi tắt bảo trì:**

- `review_required[]` — mỗi tenant/instance kèm lý do: `orphan_instance_on_host` (tenant tạo trong khoảng mất dữ liệu:
  quyết định 2P — adopt bằng `meshguard admin adopt-instance` với key mới tạo bằng CLI, hoặc deprovision; lệnh **không**
  tự làm), `instance_lost` (đã bị deprovision trong khoảng đó: xác nhận rồi xử lý tenant),
  `policy_differs_from_restored_database` (Owner/Admin rà version `validated` mới — policy đang chạy giữ nguyên tới khi
  được duyệt), `instance_runs_no_policy` (instance không lưu policy — allow-all ở lần khởi động sau: áp lại baseline sau
  khi rà), `api_key_not_reissued`, `policy_names_unknown_members` (token không ánh xạ được về membership).
- `incomplete[]` không rỗng ⇒ sửa nguyên nhân (Agent, edge, instance) và chạy lại bước 7. Không có Host Agent (stack
  dev/CI, host chưa nối socket agent): key bị từ chối không cấp lại được qua Agent — cách thủ công của Phase 1–2 là giao
  một key tạo bằng CLI qua `adopt-instance` (mục "Đưa tenant A/B vào registry" của
  [RUNBOOK](../../infrastructure/host/RUNBOOK.md), chỉ `--host`), rồi chạy lại bước 7.
- `open_jobs[]` — job `queued`/`running`/`failed_resumable` của bản dump (ví dụ thông báo đã gửi sau thời điểm backup sẽ
  gửi lại): xem từng job; `/cancel` sau khi API mở lại nếu không muốn nó chạy tiếp.
- Backup instance (P3-T11) lấy trong khoảng mất dữ liệu: archive còn trên đĩa (`backups/tenants/<instance_id>/`) nhưng
  DB vừa restore không có hàng `backups` của nó — không restore được qua API; `sequence` theo thời gian nên lần backup
  kế tiếp không trùng tên archive, và retention của các lần sau dọn nó như bản cũ. Nếu sau đó cần restore một instance
  từ bản backup **mới hơn** DB vừa restore: đặt `restore_point_older_than_backup` trong yêu cầu 2P (§17.2 — Agent giữ
  policy của archive, Owner rà lại).
- Khi chưa có bản sao audit ngoài host (P6-T02): thông báo Owner của mọi tenant tự rà lại thành viên, thiết bị và policy
  (offboard, đổi role, hủy DEK trong khoảng `gap` không khôi phục được).

Diễn tập: E2E-70, E2E-71 trên stack dev/CI (`make e2e-functional` — không có Host Agent) và E2E-72 với Host Agent,
Headscale và PostgreSQL thật (`make provisioning-it`): [P3-T17](../planning/evidence/P3-T17.md).

## 7. Restore IdP (Keycloak)

1. Nếu idp-db còn đọc được: chạy trước `… run --rm -T idp-backup once --label manual` (giữ trạng thái hiện tại).
2. Dừng Keycloak và dựng idp-db **mới** (initdb tạo lại role `keycloak`, `idp_backup` với mật khẩu từ file secret, và DB `keycloak` rỗng):

   ```bash
   I="sudo docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml"
   $I stop idp && $I rm -sf idp-db && sudo docker volume rm mg-idp_idp-db-data && $I up -d --wait idp-db
   sudo cat /opt/meshguard/backups/idp/<id>.pgdump.age | $AGE \
     | sudo docker exec -i "$($I ps -q idp-db)" pg_restore -U postgres -d keycloak --exit-on-error
   $I up -d --wait idp
   ```

3. Kiểm: discovery của `platform`, `tenant-a`, `tenant-b` trả issuer `https://auth.<domain>/realms/<realm>`; đăng nhập thử một tài khoản có TOTP; IdP driver (P2-T05a) gọi được Admin API.
4. Hệ quả của restore về thời điểm cũ hơn: user, mật khẩu, đăng ký MFA, client secret được xoay sau thời điểm backup bị mất — client secret phải khớp lại với SecretStore; đăng xuất mọi session của từng realm (Admin Console → Sessions → Sign out all) và, nếu PostgreSQL không được restore cùng lúc (khi có: mục 6.5 đã thu hồi), thu hồi mọi session Portal:

   ```bash
   sudo docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -d meshguard -c "SET ROLE mg_migrator" \
     -c "UPDATE sessions SET revoked_at = now(), id_token_hint_enc = NULL WHERE revoked_at IS NULL" -c "DELETE FROM auth_requests"
   ```

## 8. Restore volume ACME của edge

Chứng chỉ và tài khoản ACME **cấp lại được** (§17.1) — restore chủ yếu để tránh giới hạn tần suất của Let's Encrypt và giữ tài khoản ACME đã được CAA cho phép (`MG_ACME_ACCOUNT_URI`). Chỉ restore vào volume **rỗng** (host mới) hoặc khi edge đã dừng (gián đoạn mọi tenant — §17.4):

```bash
sudo docker compose -p mg-edge -f /opt/meshguard/core/compose.edge.yaml stop edge     # host đang chạy: chỉ khi thật cần
sudo docker volume create mg-edge_edge-data
sudo cat /opt/meshguard/backups/edge/<id>.tar.age | $AGE \
  | sudo tar -x --numeric-owner -p -C "$(sudo docker volume inspect -f '{{.Mountpoint}}' mg-edge_edge-data)"
sudo docker compose -p mg-edge -f /opt/meshguard/core/compose.edge.yaml up -d edge
```

Sau đó gắn lại network tenant (`infrastructure/host/reattach-edge.sh`, Phase 1–2) và kiểm `/key?v=<capver>` của A, B (§17.6).

## 9. Diễn tập

- `tests/backup/drill.sh` (máy build/CI — không bao giờ trên host): khóa dùng một lần, chạy đúng image và compose đã render, restore cả ba target và đối chiếu số hàng/băm nội dung, catalog, file/mode/owner; các ca âm tính. Kết quả gần nhất: [P2-T03a](../planning/evidence/P2-T03a.md).
- Diễn tập restore trên dữ liệu thật của host cần identity offline (đường DR) — theo lịch của §16.3 "kiểm tra restore định kỳ" và P6-T04a; ghi kết quả vào bằng chứng của đợt đó.

## 10. Sự cố

| Triệu chứng | Nguyên nhân thường gặp | Xử lý |
|---|---|---|
| Container `*-backup` khởi động lại liên tục, log `refusing to start — nothing written` | recipient trống/sai/lệch file của host; thiếu file secret; thư mục đích không ghi được | sửa đúng mục log nêu; render lại compose từ env file; `run --rm <dịch vụ> check` phải exit 0 |
| `status.json`: `last_attempt.ok=false`, `password authentication failed` | mật khẩu role lệch file secret | đặt lại verifier từ file (mục 4 bước 3–4) |
| `status.json`: lỗi `lock: another backup is still running` | lượt khác giữ khóa quá `MG_BACKUP_TIMEOUT` (2 giờ) | xem log lượt kia; không xóa `.lock` khi còn container đang chạy |
| `edge` thất bại `permission denied` / `unsupported file type` | file trong volume ACME không thuộc UID 10001 hoặc không phải file thường/thư mục/symlink | sửa owner trong volume (edge ghi bằng 10001); không archive gì cho tới khi sửa (fail closed) |
| Đĩa đầy | retention + dung lượng `backups/` | giảm `MG_BACKUP_KEEP_*` có duyệt; mở rộng filesystem/quota (§14.2) |
