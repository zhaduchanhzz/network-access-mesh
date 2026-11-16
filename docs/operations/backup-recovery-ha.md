# Backup, Recovery & High Availability

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §17. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 17. Backup, Recovery & High Availability

### 17.1 Đối tượng và phương pháp backup

| Đối tượng | Phương pháp | Tần suất (MVP → hardened) | Mã hóa / nơi lưu |
|---|---|---|---|
| PostgreSQL (SaaS) | MVP: logical dump nén mỗi đêm, do service `pg-backup` thực hiện (§14.4). Phase 6: base backup + WAL archiving để có PITR | 24 giờ → liên tục | Mã hóa ngay khi tạo, **chỉ** bằng recovery public key của nền tảng (đường DR — không dùng được khóa trong SecretStore vì chính chúng nằm trong bản dump); hệ quả: rollback sau migration và diễn tập restore cần private key offline theo nghi thức P2-T04a; `/opt/meshguard/backups/postgres` + offsite |
| SQLite của từng tenant | **`VACUUM INTO`** — phương pháp online duy nhất được chọn (ST-06) — chạy trong **container trợ giúp dùng một lần** (`user: run_uid`, `network_mode: none`, `cap_drop: ALL`, chỉ mount `data/` của đúng instance ở chế độ đọc + thư mục staging có trần dung lượng); đặt `PRAGMA trusted_schema=OFF; cell_size_check=ON; mmap_size=0` và `quick_check` trước khi chạy (file DB do tenant ghi được phải coi là không tin cậy); sau đó `integrity_check` trên bản sao. **Không** `cp` file đang có transaction. Điều kiện của mount chỉ-đọc với DB đang ở WAL (sqlite.org/wal.html, theo phản biện): chỉ đọc được khi `-shm`/`-wal` **đã tồn tại và đọc được**, tức instance đang chạy (SQLite ≥ 3.22). Quy tắc: instance **đang dừng** ⇒ cold copy (`db.sqlite` cùng `-wal`/`-shm` nếu còn); instance **đang chạy** mà `VACUUM INTO` lỗi ⇒ backup **thất bại rõ ràng** (fail-closed), không bao giờ copy file đang được ghi. **Không** dùng `immutable=1`, không chạy `wal_checkpoint` hay bất kỳ lệnh ghi nào trên nguồn. Lệnh: `sqlite3 -readonly` + `.timeout 10000` + `VACUUM INTO` tới **đường dẫn mới, duy nhất** trong staging (file đích không được tồn tại; file của lần chạy dở bị xóa trước khi thử lại); `fsync` file và thư mục rồi mới `integrity_check` + `foreign_key_check` và mã hóa. Container trợ giúp dùng image do ta build (mặc định dùng lại image của Agent), thuộc allowlist digest, có `sqlite3` ≥ 3.51.3 (bản sửa lỗi WAL-reset khi hai kết nối cùng ghi/checkpoint; kết nối chỉ-đọc của ta không ghi nên đây là phòng thủ nhiều lớp). Backup không chạy chồng lên stop/start/restore/upgrade của cùng instance (khóa theo instance). **REQUIRES VALIDATION** (V-12); nếu V-12 cho thấy mount chỉ-đọc không dùng được thì container trợ giúp mount `data/` đọc-ghi — nó chạy bằng `run_uid` nên file phụ tạo ra vẫn thuộc `run_uid` | 1 giờ → 15 phút (theo plan) | Archive riêng từng tenant; mô hình khóa hai đường (bên dưới) |
| Noise key, DERP key, `config.yaml`, `extra-records.json`, `meta/` | Sao chép vào **cùng archive** với bản SQLite, cũng trong container trợ giúp: chỉ nhận **file thường** (mở với `O_NOFOLLOW`; từ chối symlink, FIFO, device, `nlink > 1`), có trần kích thước từng file và tổng; vi phạm ⇒ backup thất bại (fail-closed) + `security_event` | Cùng lịch SQLite | Như trên |
| Cold backup trước upgrade | Dừng instance → copy toàn bộ `config/` + `data/` → khởi động (đúng hướng dẫn upstream — HS-04) | Mỗi lần upgrade/relocation | Như trên |
| Secrets (ciphertext trong PostgreSQL) | Đi cùng backup PostgreSQL | — | Chỉ ciphertext |
| **KEK + khóa giải mã backup** | Bản sao offline ở ≥ 2 nơi, **không** nằm trong bất kỳ backup tự động nào | Khi tạo/xoay | Bảo vệ vật lý; cân nhắc chia khóa |
| Edge (ACME account, chứng chỉ) | Copy volume dữ liệu Caddy | 24 giờ | Mã hóa như PostgreSQL (volume chứa khóa riêng TLS và khóa tài khoản ACME); `/opt/meshguard/backups/edge` + offsite; có thể cấp lại nếu mất |
| IdP database | Dump theo công cụ của IdP | 24 giờ | Như PostgreSQL; `/opt/meshguard/backups/idp` + offsite |
| Monitoring | Không backup dữ liệu chuỗi thời gian; dashboard/rule nằm trong Git | — | — |

**Mô hình khóa backup hai đường (thống nhất cho §7.6, T-14, T-15):** mỗi archive được mã hóa bằng một **data key ngẫu nhiên**, và data key được bọc hai lần — (a) bằng khóa backup của tenant nằm trong SecretStore (dưới DEK của tenant): **đường online**, dùng cho restore tự động, rollback sau upgrade và kiểm tra restore định kỳ — Worker mở bọc và trao data key cho Agent qua Unix socket chỉ trong thời gian của job (không ghi đĩa, không ghi log); (b) bằng **recovery public key** của nền tảng (private key giữ offline): **đường DR**, chỉ người vận hành dùng khi mất host. Hệ quả phải nói rõ: host bị chiếm cùng với KEK + PostgreSQL thì mở được các archive qua đường (a); mục tiêu RTO ≤ 15 phút chỉ áp dụng cho đường (a). Hủy DEK của tenant vô hiệu đường (a); các bản DR ở kho offsite chỉ biến mất khi job `backup.purge` (§13.5, P6-T04) chạy xong theo retention (có bước xác minh).

Mỗi archive có **manifest được ký** (Ed25519, khóa chỉ Agent giữ): `tenant_id`, `instance_id`, `headscale_version`, thời điểm, số thứ tự tăng dần, sha256 của từng file và của ciphertext. Worker **và** Agent cùng kiểm chữ ký và sự trùng khớp tenant/instance đích **trước khi giải mã/giải nén** bất cứ thứ gì. Việc đẩy archive ra kho offsite do service `backup-shipper` đảm nhiệm (§14.4). Mỗi bản backup ghi một hàng `backups`; cảnh báo khi quá hạn lịch (§16). Căn cứ về tính nhất quán của `VACUUM INTO` với WAL và writer đồng thời: ST-06 (§2.6); phép thử bắt buộc là restore định kỳ bản backup lấy lúc instance đang có client hoạt động (V-12).

### 17.2 Restore một tenant (không ảnh hưởng tenant khác)

Nguyên tắc: **lặp lại đúng thứ tự của provisioning** — instance được khôi phục không được có đường mạng nào cho tới khi quyền đã thu hồi được thu hồi lại.

1. Kiểm tra quyền (2P qua `approval_requests`) → tạo job `instance.restore` với `backup_id`.
2. Worker và Agent kiểm chữ ký manifest; `tenant_id`/`instance_id` phải trùng đích; quy tắc phiên bản: bản backup **cùng minor** với image đang chạy hoặc **chậm đúng một minor** (Headscale từ chối khởi động trên DB chậm hơn — RT-10; chậm hơn nữa phải restore qua các image trung gian đã pin). Worker mở bọc data key (đường online) và trao cho Agent; container trợ giúp giải mã vào **staging** của đúng instance, từ chối thành phần không phải file thường; `integrity_check`.
3. Agent **xóa cờ `edge_attach`, detach edge**, dừng instance → đổi tên `data/` hiện tại thành bản an toàn (giữ N ngày) → hoán đổi staging vào (đúng owner/mode).
4. Trước khi start: đặt policy bằng CLI ở chế độ `--bypass-grpc-and-access-database-directly --force` (thiếu `--force` lệnh dừng lại hỏi xác nhận tương tác — RT-15) trong container một-lần không network, để DB vừa khôi phục **không bao giờ** phục vụ policy cũ. Policy được đặt là bản đang áp dụng theo PostgreSQL — **trừ** trường hợp điểm khôi phục của PostgreSQL cũ hơn bản backup (khôi phục sau mất host: PostgreSQL RPO 24 giờ, tenant RPO 1 giờ): khi đó giữ policy trong bản backup, nhập nó vào PostgreSQL thành một version mới cần rà soát, và không replay audit. Ở nhánh này bước 5 **không** đặt lại route/tag/user theo PostgreSQL và không lập danh sách node thu hồi từ PostgreSQL (dữ liệu PostgreSQL cũ hơn instance): vẫn expire mọi API key và pre-auth key; ở bước 6 `inventory.sync` nhập trạng thái của instance làm chuẩn thay vì đối soát ngược về PostgreSQL; tenant được đánh dấu "cần Owner rà soát" (`security_event` + thông báo cho Tenant Owner) và báo cáo chênh lệch nêu rõ các thu hồi thực hiện sau thời điểm backup **không khôi phục được** — Owner phải xác nhận lại danh sách node và thành viên (tùy chọn: expire toàn bộ node để buộc đăng nhập lại).
5. Start instance **vẫn chưa gắn edge**; Agent chạy `PostRestoreReconcile` qua Unix socket: expire **mọi** API key có trong DB khôi phục và bootstrap key mới vào SecretStore; expire mọi pre-auth key; expire/xóa các node mà Worker liệt kê là đã thu hồi sau thời điểm backup — **đối chiếu theo `machine_key`**, không theo ID số (ID của node/user trong bản khôi phục có thể trùng ID mà nền tảng đã ghi cho đối tượng khác); đặt lại route đã duyệt và tag theo trạng thái trong PostgreSQL; xử lý Headscale user của thành viên đã offboard.
6. Gắn lại edge (ghi cờ) → Worker xác minh hash policy và key qua API → `inventory.sync` → đối soát **theo trạng thái** (so node/user/route/tag với trạng thái mong muốn, không chỉ dựa vào audit); trong cùng bước: phân giải lại mọi `tenant_memberships.headscale_user_id` theo tên `mg-<membership_uuid>` trong **một** transaction (đặt NULL trước rồi gán lại; không thấy ⇒ để NULL, user được tạo lại ở lần enrollment kế), và đặt `removed_at` cho thiết bị không còn trong Headscale.
7. Ghi audit + báo cáo chênh lệch (node đăng ký sau thời điểm backup phải enroll lại).

Đường dẫn restore luôn suy ra từ `instance_id`; Agent từ chối archive có manifest của instance khác ⇒ restore tenant A **không thể** ghi đè dữ liệu tenant B (AC-19).

**Đối soát sau khi restore PostgreSQL về thời điểm cũ hơn** (dump hằng đêm — RPO 24 giờ cho tới P6-T03 — hoặc dump lấy trước migration ở P2-T03a; task P3-T17). Sau restore, registry **cũ hơn** trạng thái thật của các instance, nên api và worker được khởi động ở **chế độ bảo trì** (cờ cấu hình lúc khởi động, không lưu trong DB vừa restore: API trả `503` cho mọi request ngoài `healthz`, Worker không chạy job nào) cho tới khi lệnh host `meshguard admin post-restore-reconcile` hoàn tất các bước sau:

1. Thu hồi **mọi** session; đưa mọi support grant, yêu cầu phê duyệt (`approval_requests`) và lời mời còn mở về `revoked`/`expired` — quyền đã bị thu hồi trong khoảng mất dữ liệu không được sống lại.
2. Agent liệt kê instance trên đĩa theo label `meshguard.instance_id` và so với registry: instance không có trong registry (tenant tạo trong khoảng mất dữ liệu) được đánh dấu **mồ côi** — không tự adopt, không tự xóa; xử lý bằng `adopt-instance` hoặc deprovision sau quyết định 2P. Instance có trong registry nhưng không còn trên đĩa (đã deprovision trong khoảng đó) được đánh dấu `failed`, **không** tự provision lại.
3. Với từng instance: thử API key đang lưu; lỗi (key đã xoay trong khoảng mất dữ liệu) ⇒ `apikey.bootstrap` qua Agent rồi expire các key còn lại (§11.4).
4. So sha256 của `GetPolicy` với `applied_sha256` mới nhất. Lệch ⇒ **không bao giờ tự áp bản cũ hơn**: ghi một hàng `policy_applications` (`trigger=restore`, `state=applied`) mang đúng chuỗi đang chạy để drift detection và post-start gate lấy nó làm mốc; nhập chuỗi đó thành một `policy_versions` mới ở trạng thái `validated` và đặt làm desired. Job `policy.apply` chỉ áp version `approved`, nên policy đang chạy được giữ nguyên cho tới khi Owner/Admin rà soát và duyệt (§7.3); token không ánh xạ được về membership được liệt kê trong báo cáo.
5. `inventory.sync` đầy đủ; đối chiếu bản sao audit ngoài host (có từ P6-T02) để liệt kê thao tác trong khoảng mất dữ liệu cần làm lại (offboard, đổi role, hủy DEK của tenant đã xóa). Khi chưa có bản sao: thông báo Owner của mọi tenant tự rà lại thành viên, thiết bị và policy.
6. Ghi `audit_events` loại `audit.gap` kèm khoảng thời gian bị mất, rồi mới tắt chế độ bảo trì.

Cửa sổ mất dữ liệu tới 24 giờ trước khi có PITR là nợ TD-05; kịch bản này được diễn tập ở P3-T17 (stack dev/CI) và P6-T03.

### 17.3 Mục tiêu RPO/RTO (mục tiêu thiết kế, **chưa** là SLA — phải đo bằng diễn tập)

| Thành phần | RPO mục tiêu | RTO mục tiêu | Ghi chú |
|---|---|---|---|
| PostgreSQL | 24 giờ (MVP) → ≤ 5 phút (PITR) | 1–2 giờ | Headscale các tenant vẫn phục vụ client khi PostgreSQL ngừng |
| Một Headscale instance | 1 giờ → 15 phút | ≤ 15 phút | Restore độc lập theo tenant |
| Mất toàn bộ host | Như trên (nếu có offsite) | 4–8 giờ (dựng host mới, restore, trỏ DNS) | Phụ thuộc offsite backup + KEK offline |

### 17.4 Phân tích sự cố

| Sự cố | Control plane | Tunnel P2P đã thiết lập | Kết nối qua relay | Khôi phục |
|---|---|---|---|---|
| Restart Headscale của tenant A | Client của A mất kết nối control vài giây rồi tự nối lại; tenant khác không bị ảnh hưởng (AC-18) | Tiếp tục hoạt động — **REQUIRES VALIDATION** (đo trong AC-18) | Embedded DERP khởi động lại theo ⇒ phiên relay bị ngắt rồi thiết lập lại | Tự động |
| Edge (Caddy) ngừng | Control + relay + portal của **mọi** tenant ngừng | Tiếp tục | Ngắt | Restart; đây là SPOF |
| VPS gateway hoặc tunnel ngừng | Mọi truy cập từ Internet (control, relay, Portal, STUN) ngừng; truy cập LAN-direct không ảnh hưởng | Tiếp tục | Ngắt với client ngoài LAN | Tunnel tự nối lại; dựng lại gateway từ repo (stateless); nếu VPS mất hẳn: đổi DNS sang gateway khác **và** chạy `instance.reconfigure` hàng loạt để cập nhật `derp.server.ipv4` (kèm phản hồi tĩnh `/bootstrap-dns` của edge) — relay và STUN của mọi tenant chỉ phục hồi sau bước này (§10.1) |
| Host ngừng | Tất cả ngừng | Tiếp tục cho tới khi endpoint đổi hoặc key hết hạn | Ngắt | DR (§17.3) |
| PostgreSQL ngừng | Portal/API ngừng; Headscale vẫn phục vụ client | Không ảnh hưởng | Không ảnh hưởng | Restart / restore |
| PostgreSQL hỏng hoặc được khôi phục về thời điểm cũ hơn (dump đêm, lùi migration) | Portal/API ở chế độ bảo trì cho tới khi đối soát xong; Headscale vẫn phục vụ client; registry có thể **cũ hơn** trạng thái thật của các instance (tenant mới tạo, API key đã xoay, policy mới, quyền đã thu hồi) | Không ảnh hưởng | Không ảnh hưởng | Restore + **đối soát sau restore PostgreSQL** (§17.2, P3-T17) trước khi mở lại API |
| DERP ngừng | — | Không ảnh hưởng | Ngắt; kết nối mới có thể không thiết lập được | Restart instance |
| SQLite hỏng | Instance của tenant đó lỗi | Tiếp tục tới khi cần cập nhật netmap | Ngắt | Restore (§17.2) |
| Mất secret (KEK) | Không giải mã được SecretStore | Không ảnh hưởng | Không ảnh hưởng | Lấy KEK từ bản offline; nếu mất hẳn: bootstrap lại API key qua Agent, nhập lại OIDC/DNS secret |
| Mất Noise key của instance | Client có thể phải đăng ký lại — **REQUIRES VALIDATION** (V-11) | Tiếp tục | — | Restore từ backup (key nằm trong archive) |
| Hỏng persistent storage | Tất cả tenant trên host | Tiếp tục | Ngắt | DR |
| Relocation tenant | Gián đoạn ngắn | Tiếp tục | Ngắt tạm thời | Runbook §11.4 |

### 17.5 Phân biệt bốn loại "HA"

| Lớp | Trạng thái ở MVP | Hướng mở rộng |
|---|---|---|
| SaaS Backend (API/Worker/Portal) | Single instance trên một host | API stateless nhân bản + PostgreSQL có replica (Phase 7) |
| Headscale Control Plane | **Không HA** (upstream: một tiến trình, một SQLite; không có tuyên bố HA — HS-23) | Warm standby bằng backup/restore sang host khác. **Không** thiết kế active-active nhiều Headscale ghi chung một SQLite |
| DERP | Một relay mỗi tenant ⇒ SPOF cho đường relay (upstream cảnh báo khi bỏ DERP của Tailscale — HS-17) | Thêm region/derper độc lập (Phase 7) |
| Tính liên tục của P2P | Không phụ thuộc Management Plane; phụ thuộc control plane chỉ khi cần cập nhật netmap/khóa | Đo và ghi nhận ở AC-18 |

### 17.6 Upgrade & rollback

- **Headscale:** §11.4 (bản vá cùng minor hoặc tuần tự từng minor, cold backup, preflight `configtest` bằng binary đích trên bản sao dữ liệu, canary, health + contract smoke, rollback bằng restore vì upstream không hỗ trợ downgrade schema).
- **Management Plane:** migration chạy trước (expand), triển khai image mới, contract sau (contract) ở bản phát hành kế tiếp; rollback = image cũ (schema vẫn tương thích ngược) hoặc restore PostgreSQL nếu migration lỗi (kèm đối soát sau restore — §17.2).
- **Edge/IdP/monitoring:** pin digest, nâng từng thành phần, có bước kiểm tra sau nâng và đường lùi về digest cũ. Riêng **edge**: recreate làm rớt stream của mọi tenant và mất mọi attach lúc chạy ⇒ **runbook nâng cấp/recreate edge**: pre-pull image → thông báo → recreate project `mg-edge` → chờ edge supervisor gắn lại (§11.4) → khẳng định số network tenant đã gắn = số instance có `edge_attach: true` → probe `/key?v=<capver>` mọi tenant; đường lùi = recreate với digest cũ theo đúng trình tự này. Ở Phase 1–2 (chưa có Agent) **không có gì tự gắn lại**: sau mỗi lần recreate edge phải chạy script `reattach-edge` (runbook P1-T08) rồi kiểm lại `/key?v=<capver>` của A và B.

Runbook DR được viết ở Phase 6 (`docs/operations/`): mất host, restore PostgreSQL, restore một tenant, xoay KEK, xoay toàn bộ API key, policy lỗi khiến instance không khởi động (lệnh `--bypass-grpc-and-access-database-directly` — HS-09).
