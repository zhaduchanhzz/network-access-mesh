# Runbook — Backup và restore PostgreSQL, IdP, edge

> **File viết tay — không sinh từ master.** Runbook của task **P2-T03a** (service `pg-backup`) và **P2-T05b** (dump DB của IdP, sao lưu volume ACME của edge) — §14.4, §16.3, §17.1–§17.3 của [bản master](../planning/implementation-master-plan.md). Bằng chứng và kết quả diễn tập: [P2-T03a](../planning/evidence/P2-T03a.md). Mã nguồn: [`apps/backup`](../../apps/backup/main.go), [`infrastructure/docker/backup`](../../infrastructure/docker/backup/Dockerfile), [`compose.backup.yaml.tmpl`](../../infrastructure/compose/compose.backup.yaml.tmpl), [`tools/render_backup.py`](../../tools/render_backup.py), diễn tập [`tests/backup/drill.sh`](../../tests/backup/drill.sh). Khóa khôi phục: [nghi thức khóa](key-ceremony.md).

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

1. Dừng api và worker (không để ghi vào DB đang thay): `sudo docker compose -p mg-core … stop api worker`.
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

5. **Thu hồi toàn bộ session** — bắt buộc khi restore vào môi trường đang dùng: quyền/phiên bị thu hồi sau thời điểm backup không được sống lại.
   - **Phase 2** (trước P3-T17):

     ```bash
     sudo docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -d meshguard -c "SET ROLE mg_migrator" \
       -c "UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL" -c "DELETE FROM auth_requests"
     ```

     Sau đó thông báo người dùng đăng nhập lại; rà audit ngoài host (nếu có) cho các thao tác trong khoảng mất dữ liệu (offboard, đổi role) và làm lại.
   - **Từ Phase 3:** khởi động api/worker ở **chế độ bảo trì** rồi chạy `meshguard admin post-restore-reconcile` (P3-T17, §17.2): thu hồi session/grant/phê duyệt/lời mời, phát hiện instance mồ côi/đã mất, cấp lại API key đã xoay, không áp policy cũ, `inventory.sync`, ghi `audit.gap` — chỉ tắt bảo trì khi lệnh hoàn tất.
6. Khởi động api/worker; kiểm `/readyz` (SecretStore mở được DEK trong DB đã restore — KEK không nằm trong backup). Giữ `meshguard_before_restore_*` tới khi chắc chắn, rồi `DROP DATABASE`.
7. Chạy ngay một backup `manual` (mục 5, `--label manual`) để có điểm khôi phục mới.

### 6.4 Restore lên cụm mới (mất host — DR)

Theo `current.md` mục 3 dựng host, KEK từ giấy ([nghi thức khóa](key-ceremony.md) mục 10), `layout.sh`, compose `mg-core` với **chỉ** `postgres` chạy. `POSTGRES_DB=meshguard` đã tạo một DB rỗng:

```bash
sudo docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres -c "DROP DATABASE meshguard"
sudo cat "$B.globals.sql.age" | $AGE | sed '/^CREATE ROLE postgres;$/d' \
  | sudo docker exec -i "$PG" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres
sudo cat "$B.pgdump.age" | $AGE | sudo docker exec -i "$PG" pg_restore -U postgres -d postgres --create --exit-on-error
```

Backup **không** chứa mật khẩu role (`--no-role-passwords`): đặt lại verifier cho mọi role đăng nhập từ các file secret (mục 4 bước 3; superuser cho `mg_migrator`/`mg_backup`, `mg_migrator` cho các role còn lại — `database/README.md`). Rồi làm bước 5–7 của mục 6.3 (cụm mới luôn là "restore về thời điểm cũ hơn"). Kiểm tra sau restore: `SELECT count(*)` các bảng chính; `database/checks/partition_grants.sql` trả 0 hàng.

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
4. Hệ quả của restore về thời điểm cũ hơn: user, mật khẩu, đăng ký MFA, client secret được xoay sau thời điểm backup bị mất — client secret phải khớp lại với SecretStore; đăng xuất mọi session của từng realm (Admin Console → Sessions → Sign out all) và, nếu PostgreSQL không được restore cùng lúc, thu hồi session Portal như mục 6.3 bước 5.

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
