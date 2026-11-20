# G4a — báo cáo gate giữa Phase 4 (P4-T10a, chờ ký)

> **File viết tay — không sinh từ master.** Báo cáo Go/No-Go **G4a** (§19 Phase 4 của [bản master](../implementation-master-plan.md):
> enrollment — kèm gate web-auth V-07 hoặc phương án lùi "dán Auth ID" —, policy apply, devices, audit chạy end-to-end
> qua API + UI tối thiểu; hàng P4-T10a ở §20; V-07 ở §22.4). Quy ước: [README](README.md). Script đã chạy (không
> secret, không IP/domain): [G4a/](G4a/).

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-19, kiểm 16:19–16:41 UTC (lô Phase 4 lên staging lúc 16:00–16:03 UTC, reload edge v10 16:02:44) |
| Người lập | Agent (Claude Code), theo brief của người điều phối |
| Mã | `main` @ `6baf645` trên host (`~/mg`); image api/worker/web/agent `b8097f3` (pin trong `versions.lock` @ `6baf645`); schema **27**; edge Caddyfile template **v10** |
| Môi trường | **staging** — VM 104 `mg-staging` (host, `MG_LAN_IPV4`), VPS (điểm vào công khai), **VM 105** (máy client, khác host Headscale — HS-24), máy vận hành (trình duyệt), 4 client lab a1/a2/b1/b2 (chỉ đọc/kiểm) |
| Phiên bản | Headscale v0.29.7 + bản vá V-26 (`mg-headscale`, commit `f9cc62be…`); Tailscale **1.104.7** trên VM 105 (Ubuntu 24.04.5, gói chính thức, `tailscaled` của systemd) và container client chính thức `[images.tailscale]` v1.104.7 (`sha256:72c1e19e…`); trình duyệt Chromium 158.0.8127.18 (Chrome for Testing 1254, `playwright-core` 1.65.0 — integrity khớp `apps/web/package-lock.json`) trên Windows |
| Tenant thử | `g4a-06bd` (provision 16:20:02, deprovision 2P 16:39:25 — đã `deleted`) |
| Tài khoản | SA thử `g3-sa1`/`g3-sa2` (realm `platform`, credential chỉ ở máy vận hành); Owner của tenant thử `g4a-owner` (tạo bằng `create-user.sh`, e-mail `owner@<slug>.example.invalid` — không hộp thư thật; mật khẩu/TOTP chỉ trong tiến trình + file 0600 ở máy vận hành, đã xóa) |

## Kết luận đề xuất

**Go G4a** — 4/4 tiêu chí đạt end-to-end trên staging, qua API và qua UI (Chromium thật, qua DNS công khai → VPS →
tunnel → edge). **V-07 đạt với Linux** (client chính thức cài trên VM 105 và client container): link `/register/<auth_id>`
⇒ `302` về trang claim (LAN-direct và đường công khai), claim ⇒ client `Running`, node đúng tên/chủ — cả khi claim qua
API chỉ bằng tham số của `Location`, cả khi người dùng xác nhận trên trang claim của SPA trong trình duyệt có phiên
Portal. Phương án lùi "dán Auth ID" **không cần** cho Linux. **Windows/macOS chưa chạy** (không có máy thử nào ngoài máy
vận hành, mà Tailscale của máy này không được đụng) ⇒ V-07 "từng OS" còn mở cho hai OS này — đề xuất chạy cùng ma trận
client P5-T03; nếu app GUI mở trình duyệt không có phiên Portal thì OS đó dùng "dán Auth ID" (đã có trong UI P4-T08).

Một phát hiện **Low** (F-G4a-1): bấm xác nhận claim quá nhanh sau khi tạo lệnh ⇒ `429` (bucket `enrollment` chung cho
GET và POST); UI xử lý đúng, người dùng bấm lại. Không chặn gate.

## Tiêu chí G4a (§19, Phase 4)

| # | Tiêu chí | Kết quả | Bằng chứng (mục) |
|---|---|---|---|
| 1 | **Enrollment** — web-auth do Portal môi giới (§7.4 luồng A) kèm **V-07**; pre-auth key (phương thức B) | **Đạt** — D1 (VM 105, `tailscale login --hostname mg-<mã>`): link ⇒ `302` đúng `Location`, `no-store` (LAN + công khai); claim `200 verified`, client `Running` sau **5,7 s**, node đổi tên `g4a-vm105`, chủ `mg-<membership Owner>`, sổ thiết bị có `enrollment_request_id`, audit `enrollment.claim.requested → .succeeded`, `device.new`; D3 qua trang claim của SPA ⇒ "Device g4a-ui added.", `Running`; D2 (pre-auth key 10 phút) ⇒ `Running`, `enrollment.reconcile` ⇒ `consumed` sau 41 s với đúng node, liên kết sổ thiết bị, `device.new`; 0 key/mã trong DB | 2.2, 2.6, 4 |
| 2 | **Policy apply** | **Đạt** — allow (`autogroup:member → autogroup:member tcp:8000`) và deny-all: `POST /policies` ⇒ draft → validate (CheckPolicy trên instance `passed`) → approve (self-review) → apply ⇒ job `policy.apply` succeeded (0,4–0,9 s), `applied_sha256` = sha của `headscale policy get`; TCP thật D1→D2:8000: trước khi áp chặn, allow ⇒ thông (0,9 s), deny ⇒ chặn, rollback ⇒ thông | 2.3 |
| 3 | **Devices** | **Đạt** — rename `PATCH` ⇒ 200, Headscale đọc lại `g4a-d2-renamed`; expire ⇒ `202`, `revocation` **pending → applied** (4,1 s, `device.revoke` 0,39 s), client D2 `NeedsLogin` / `Self.Expired`, TCP mất; suspend/resume của tenant chặn/mở lại lưu lượng | 2.4, 2.5 |
| 4 | **Audit** | **Đạt** — `GET /tenants/{g4a}/audit`: 93 sự kiện, đủ mọi hành động của luồng thử (enrollment, policy, device, lifecycle, đăng nhập); Owner đọc audit của A/B ⇒ 404; audit của A/B không có hàng nào nhắc tới tenant thử | 2.7 |
| — | **qua API + UI tối thiểu** | **Đạt** — API: mọi bước trên qua API công khai bằng đăng nhập thật (Keycloak + TOTP). UI (Chromium thật): đăng nhập Owner, Devices (D1 Online, D2 "revocation (expire) applied" + Expired), Access policies (desired v4, Applied on Headscale), Audit log, Add device ⇒ lệnh ⇒ link ⇒ trang claim ⇒ xác nhận ⇒ verified; 0 vi phạm CSP | 2.6 |

## 1. Kiểm API sau nâng — 81/81

Đăng nhập thật qua edge (LAN-direct, SNI): `g3-sa1` trên `admin.<domain>` (mật khẩu + TOTP), Owner của tenant thử trên
`app.<domain>`. Tương đương bộ 34 kiểm của diễn tập ([P4-deploy-rehearsal](P4-deploy-rehearsal.md) mục 5), mở rộng:

| Nhóm | Kết quả |
|---|---|
| SA: `GET /platform/{tenants, health, instances, hosts, jobs, approvals, users, plans, settings, identity-providers, support-grants, relay-regions, backups, audit}` + `GET /platform/tenants/{g4a}` | **15/15** ⇒ 200 |
| Owner tenant thử: `GET /tenants/{g4a}` và `/{devices, policies, policies/current, tags, users, groups, dns, dns/records, routes, resources, enrollment/requests, enrollment/instructions?os=linux, audit, support-grants, approvals, settings, dashboard, jobs, notifications, relay, invitations}` | **22/22** ⇒ 200 |
| Cùng 22 route của **tenant-a** bằng Owner tenant thử | **22/22** ⇒ 404 |
| Cùng 22 route của **tenant-b** bằng Owner tenant thử | **22/22** ⇒ 404 |

Khác diễn tập: không dùng TO/TA của A/B (credential của họ nằm trong kho secret của chủ dự án — không đọc) ⇒ chiều chéo
tenant kiểm bằng Owner của tenant thử tới A và B. 44 lần từ chối được audit dưới tenant của actor (`*.list`/`*.read`
`denied`, §6.1) và sinh **một** `security_event` `authz.cross_tenant_denials` (High) — đúng thiết kế phát hiện dò chéo
tenant.

## 2. Tenant thử `g4a-06bd` — end-to-end (16:19–16:39 UTC)

Thiết bị: **D1** = `tailscaled` của hệ thống trên VM 105 (kernel TUN, `--accept-dns=false`); **D2**, **D3** = container
client chính thức trên VM 105 (userspace networking, state trong bộ nhớ, read-only, `cap-drop ALL`). Client mở
`https://<slug>.mesh.<domain>` qua DNS công khai → VPS (`l4proxy`) → tunnel → edge.

### 2.1 Provision + Owner

| Bước | Kết quả | Chi tiết |
|---|---|---|
| SA1 `POST /platform/tenants` ⇒ `tenant.provision` | PASS | 202; job succeeded **8,7 s**, 19/19 bước (lâu nhất `instance.wait_healthy` 2,78 s, `idp.ensure` 1,43 s); `mg-hs-g4a-06bd` healthy; subscription `active` (`standard`) |
| User Keycloak của Owner | PASS | `create-user.sh g4a-06bd g4a-owner owner@<slug>.example.invalid` (mật khẩu 32 ký tự sinh tại chỗ, chỉ qua stdin) ⇒ `created` |
| Owner đăng nhập lần đầu | PASS | `password` + `configure_totp`; lời mời Owner do provision tạo được gắn ở lần đăng nhập đầu ⇒ membership `tenant_owner` |

### 2.2 Enrollment + V-07 (client chính thức thật)

| Bước | Kết quả | Chi tiết |
|---|---|---|
| `GET /enrollment/instructions?os=linux` | PASS | `login_server` = `https://<slug>.mesh.<domain>` |
| D1: `POST /enrollment/requests {web_auth, device_label: g4a-vm105}` | PASS | 201 `issued`; `hostname` = `mg-<12 ký tự>`, lệnh có `--hostname`; hạn 10 phút |
| D1: `sudo tailscale login --login-server=https://<slug>.mesh.<domain> --hostname=mg-<mã> --accept-dns=false` | PASS | link `https://<slug>.mesh.<domain>/register/<auth_id>` sau 2,5 s; `NeedsLogin` |
| Edge v10: `GET` link | PASS | LAN-direct **và** qua DNS công khai/VPS: `302`, `Location` = `https://app.<domain>/enroll/claim?tenant=<slug>&auth_id=<auth_id>` (đúng từng ký tự), `Cache-Control: no-store` |
| `Location` / `?via=portal` | PASS | `Location` ⇒ 200 `index.html` của SPA (có CSP); `?via=portal` ⇒ 200 trang Headscale chứa đúng Auth ID |
| **V-07 (API)**: claim chỉ bằng tham số của `Location` | PASS | `tenant` ⇒ `tenant_id` qua `GET /auth/session` (`memberships[].tenant_slug`); `POST /tenants/{id}/enrollment/web-auth/claim {auth_id}` ⇒ **200 `verified`**; D1 `Running` sau **5,7 s**; node #1 `name` = `mg-<mã>`, `given_name` = `g4a-vm105`, user `mg-<membership Owner>`, `register_method` CLI (`AuthRegister`) |
| D1: sổ thiết bị, audit, thông báo | PASS | `device_inventory_cache.enrollment_request_id` = yêu cầu; `GET /devices` thấy `g4a-vm105` (owner Owner, online); audit `enrollment.request` → `enrollment.claim.requested` → `enrollment.claim.succeeded`; outbox `device.new` 1 (sent) |
| D2: `POST /enrollment/requests {preauth_key, g4a-d2, ttl 10}` | PASS | 201; key hiển thị một lần, lệnh không chứa key |
| D2: `tailscale up --auth-key=file:…` (key qua stdin vào tmpfs 0700, xóa ngay) | PASS¹ | `Running`; node #2 `register_method` = 1 (`REGISTER_METHOD_AUTH_KEY`), user `mg-<membership Owner>` |
| D2: `enrollment.reconcile` | PASS | `consumed` sau 41 s, `consumed_node_id` = node #2; sổ thiết bị có liên kết; `device.new` 1; API `GET /enrollment/requests/{id}` ⇒ `consumed`; key ở Headscale `used=true`, không reusable/ephemeral |
| Không có credential trong DB | PASS | hàng chứa `hskey-` trong `enrollment_requests`/`idempotency_keys`/`audit_events`: **0**; mã web-auth trong `idempotency_keys`/`audit_events`: **0** |

¹ Lượt chạy ghi FAIL vì script so `register_method` với chuỗi trong khi JSON của Headscale là enum số; đánh giá lại
cùng lúc (node #2 = 1 = AUTH_KEY) ⇒ PASS; script trong [G4a/](G4a/) đã sửa phép so.

### 2.3 Policy apply + TCP thật

| Bước | Kết quả | Chi tiết |
|---|---|---|
| Trước khi áp | PASS | desired v1 (`baseline` của `policy.bootstrap`), applied; TCP D1→D2:8000 **timeout**; listener trên D2 trả lời cục bộ |
| allow: draft → validate → approve | PASS | `POST /policies` 201 draft v2; validate 200 `validated`, `result passed`, CheckPolicy `passed`; approve 200 `approved` (`review_mode self` — four_eyes tắt) |
| allow: apply | PASS | 202 + `Location` job; `policy.apply` succeeded **0,85 s**; application `manual applied`, `applied_sha256` `6b2d123d…` = sha Headscale; `policies/current.desired` = v2 |
| allow ⇒ TCP | PASS | D1→D2:8000 trả lời `g4a d2 tcp/8000` sau 0,9 s |
| deny-all (`grants: []`): draft → validate → approve → apply | PASS | v3; job 0,69 s; sha `57d0747a…` = Headscale |
| deny ⇒ TCP | PASS | timeout sau 4,8 s; D1 còn 0 peer; listener vẫn trả lời cục bộ |
| rollback về allow | PASS | `POST /policies/{v2}/rollback` 202 ⇒ v4 `rollback_of` v2; job 0,43 s; application `rollback applied`, sha `6b2d123d…` = Headscale; TCP thông lại sau 0,9 s |

### 2.4 Suspend / resume

| Bước | Kết quả | Chi tiết |
|---|---|---|
| SA1 suspend | PASS | 202; `tenant.suspend` 1,05 s + `policy.apply` (trigger `suspend`) 0,49 s; tenant `suspended`; TCP timeout; Owner `POST /enrollment/requests` ⇒ **403 `tenant_suspended`**; `GET /devices` 200 |
| SA1 resume | PASS | 202; `tenant.resume` 0,65 s; `active`; desired v4 áp lại (trigger `resume`); TCP thông sau 1,3 s |

Policy suspension được ghi hai lần (16:23:57,69 và 16:23:58,15, cùng version/sha): job `policy.apply` trigger
`suspend` do API xếp và bước `policy.suspend` của `tenant.suspend` khẳng định lại — đúng thiết kế
(`internal/provisioning/lifecycle/request.go`), vô hại.

### 2.5 Devices

| Bước | Kết quả | Chi tiết |
|---|---|---|
| rename D2 | PASS | `PATCH /devices/{id} {given_name: g4a-d2-renamed}` ⇒ 200; Headscale đọc lại `g4a-d2-renamed`; audit `device.rename.requested → .succeeded` |
| expire D2 | PASS | `POST /devices/{id}/expire` ⇒ 202 + `Location`; `revocation` **pending → applied** sau 4,1 s (`verified_at` có), `device.revoke` 0,39 s; Headscale `expiry` = thời điểm expire; audit `device.expire.requested → .succeeded` |
| D2 mất kết nối | PASS | TCP trước: thông; sau: timeout; D2 `BackendState NeedsLogin`, `Self.Expired true` |

### 2.6 UI tối thiểu — Chromium thật

Chromium headless trên máy vận hành, locale `en-US`, mở `https://app.<domain>` qua **DNS công khai → VPS → tunnel →
edge** (không host-resolver tùy chỉnh); mật khẩu/TOTP đọc từ file 0600, không vào trace/ảnh.

| Bước | Lượt 2 (16:33) | Chi tiết |
|---|---|---|
| Đăng nhập Owner (SPA `/login` → Keycloak mật khẩu + TOTP → SPA) | PASS | CSP `default-src 'self'`; 1 cookie `__Host-` HttpOnly + Secure, `document.cookie` không thấy |
| Devices | PASS | `g4a-vm105` Online; `g4a-d2-renamed` Offline + "revocation (expire) applied" + Expired; sau claim thêm `g4a-ui` Online |
| Access policies | PASS | "Desired version — Version 4", "Applied on Headscale — Applied" |
| Audit log | PASS | có `device.expire…`, `policy.…`, `enrollment.…` |
| Add device: Linux + web-auth, nhãn `g4a-ui` ⇒ "Create the enrollment command" | PASS | lệnh có login server của tenant + `--hostname mg-<mã>`; localStorage/sessionStorage rỗng, mã không ở URL |
| D3 chạy đúng lệnh đó (không key) ⇒ link; **mở link trong chính trình duyệt** | PASS | điều hướng `302 <slug>.mesh/register/<id> (no-store)` → `200 app/enroll/claim`; SPA gỡ `auth_id` khỏi URL (còn `?tenant=<slug>`); "Waiting request: g4a-ui" |
| Tích "I just ran the command…" ⇒ "Confirm device" | PASS | "Device g4a-ui added." ở lần bấm đầu; Auth ID không còn trong DOM/URL/Storage; D3 `Running`, node #3 `given_name` `g4a-ui`, user `mg-<membership Owner>`; sổ thiết bị: yêu cầu `verified` + liên kết |
| CSP / lỗi JS | PASS | 0 vi phạm CSP, 0 lỗi JS chưa bắt (1 dòng console = `401` của `GET /auth/session` trước đăng nhập — đúng) |

**Lượt 1 (16:27)**: các bước giống hệt, nhưng script mở link **7 s** sau khi tạo lệnh và bấm "Confirm device" ngay ⇒
`POST …/web-auth/claim` ⇒ **429**; UI hiện "Too many requests — wait, then try again. Try again in 3 seconds." rồi "You
can try again now." và giữ nút (cùng Idempotency-Key) — script lượt 1 không bấm lại, yêu cầu đó hết hạn (`expired` qua
reconcile), client D3 của lượt 1 bị gỡ. Lượt 2 chờ 30 s trước khi mở link (như người dùng chạy lệnh trên máy) ⇒ không
429. Xem F-G4a-1.

### 2.7 Audit

`GET /tenants/{g4a}/audit` (phân trang): **93 sự kiện, 45 loại**. Có đủ: `auth.login` ×9, `invitation.create`/`.accept`,
`idp.user.create`, `idp.client.update`, `enrollment.request` (+ `.requested/.succeeded`), `enrollment.claim.requested`
×2 / `.succeeded` ×2, `enrollment.consume`, `policy.create` ×2, `policy.validate` ×2, `policy.approved` ×2,
`policy.desired_set` ×2, `policy.rollback`, `policy.apply.requested/.succeeded` ×6, `device.rename.requested/.succeeded`,
`device.expire.requested/.succeeded`, `enrollment.request` `denied` (lúc suspend), và 44 `denied` của các lần dò chéo
tenant ở mục 1 (ghi dưới tenant của actor). Owner tenant thử `GET /tenants/{A|B}/audit` ⇒ **404 / 404**; trong DB, audit
của tenant-a/b từ 16:19 không có hàng nào mang id/slug của tenant thử (**0**; A và B không có sự kiện nào trong cửa sổ).

### 2.8 Deprovision và dọn

| Bước | Kết quả | Chi tiết |
|---|---|---|
| D1 rời tenant trước khi xóa | PASS | `sudo tailscale logout` (control còn sống ⇒ node key bị expire) ⇒ "Logged out." |
| D2, D3, thư mục làm việc trên VM 105 | PASS | `docker rm -f g4a-d2 g4a-d3`, `rm -rf ~/g4a` |
| Deprovision 2P | PASS | SA1 `DELETE` ⇒ 202; SA1 tự duyệt ⇒ **403** (`approval.self_decision` medium); SA2 duyệt ⇒ 200; `tenant.deprovision` **3,3 s**, 15/15 bước (gồm `backup.final`, `nodes.expire`, `edge.detach`, `instance.remove`, `storage.remove`, `idp.disable`, `keys.schedule`); tenant `deleted` |
| Host không còn tài nguyên | PASS | container 0, network 0, volume 0 mang slug; thư mục instance 0; secret 0; edge chỉ còn `mg-t-tenant-a`, `mg-t-tenant-b` (+ network nền tảng); `mg-hs-*` còn 2 |
| VM 105 không thuộc tailnet nào | PASS | `tailscale switch --list` rỗng, `NeedsLogin`, `tailscale0` không còn IPv4; 0 container `g4a-client` |

## 3. Sau ≥ 15 phút kể từ 16:03 UTC (kiểm lúc 16:40)

| Kiểm | Kết quả |
|---|---|
| Policy tenant-a | sha Headscale **`46206234ae7c6484…`** = `applied_sha256` hiện hành (bản `restore` 2026-11-18 13:31 — không có application mới); `policy.drift_check` **3/3 succeeded** từ 16:03 (16:04, 16:19, 16:34), **0** job `policy.apply`, **0** `security_event` `instance.policy*`; lab-a1, lab-a2 online |
| Policy tenant-b | sha **`46206234ae7c6484…`** = `applied_sha256` (bản `manual` 2026-11-18 13:30); `policy.drift_check` **3/3 succeeded** (16:07, 16:22, 16:37); 0 `policy.apply`; 0 sự kiện drift; lab-b1, lab-b2 online |
| Log `ERROR` từ 16:00 UTC | worker **0**, api **0**, mail-bridge **0**, Host Agent **0**. WARN của worker: 1 `maintenance mode changed` (lúc triển khai) + 10 `idp.audit_sync: security event idp.console_login` (kcadm của `realm-update.sh` lúc 16:04–16:05 và của `create-user.sh` lúc 16:20 — gộp thư F-G3-2: 3 thư cho lần 16:20) |
| TCP a1→a2:8000, b1→b2:8000 (từ a1/b1, chỉ đọc) | `BackendState Running`, peer online; cổng **8000** (có grant `test-allow-intra`) ⇒ **RST sau 0,19 s** — SYN đi qua WireGuard tới a2/b2 và kernel của đích trả lời; cổng **8001** (không có grant) ⇒ **timeout 5 s** (bộ lọc của Tailscale bỏ gói); ICMP 3/3 cả hai cặp |

Giới hạn của dòng cuối: a2/b2 hiện **không có listener** trên 8000 (dịch vụ thử của lab không chạy), nên không có trao
đổi dữ liệu tầng ứng dụng; cặp phép đo 8000 ⇒ RST / 8001 ⇒ timeout cho thấy grant tcp:8000 vẫn được áp đúng và đường
tunnel thông. Mở listener tạm trên a2/b2 cần SSH qua Proxmox (lan10) — ngoài phạm vi "chỉ đọc" của lượt này.

## 4. V-07 — kết quả theo hệ điều hành

| OS / client | Đường đi | Kết quả |
|---|---|---|
| **Linux** — Ubuntu 24.04.5, Tailscale 1.104.7 (gói chính thức, `tailscaled` systemd), VM 105 | `tailscale login` ⇒ link ⇒ edge v10 `302` (LAN + công khai) ⇒ claim qua API bằng tham số của `Location` | **Đạt** — `Running` 5,7 s sau claim |
| **Linux** — container client chính thức 1.104.7 | lệnh do SPA hiển thị ⇒ link mở trong Chromium có phiên Portal ⇒ trang claim ⇒ xác nhận | **Đạt** — "Device g4a-ui added.", `Running` |
| Windows, macOS (app GUI tự mở trình duyệt) | — | **Chưa chạy** — không có máy thử (Tailscale của máy vận hành không được đổi profile). Cần ghi: trình duyệt app GUI mở có dùng phiên Portal hiện có không; không ⇒ "dán Auth ID" là đường chính cho OS đó |
| iOS/Android | pre-auth key (§7.4 giới hạn (4)) | Không thuộc V-07 |

Pending registration không bị ảnh hưởng bởi chuyển hướng (client vẫn `NeedsLogin` cho tới claim; `?via=portal` vẫn mở
được trang gốc của Headscale) — khớp lý giải ở [P4-T07](P4-T07.md) mục 2.

## Phát hiện còn mở

| ID | Mức | Mô tả | Đề xuất |
|---|---|---|---|
| F-G4a-1 | Low | Rate limit `enrollment` (5 + 1/5 s mỗi danh tính, **cả GET**) dùng chung cho các GET của Add device/trang claim và `POST …/web-auth/claim`: người dùng tạo lệnh rồi mở link và bấm xác nhận trong ~10 s (lượt 1: 7 s) nhận `429` ở lần bấm đầu. UI xử lý đúng (thông báo, đếm `Retry-After`, giữ nút + Idempotency-Key, không mất trạng thái); bấm lại là xong. Người dùng thật thường mất > 20 s để chạy lệnh ⇒ ít gặp | Đã có đề xuất ở P4-T08: tách GET khỏi bucket chặt (P6-T07). Tùy chọn sớm hơn: trang claim tự thử lại một lần sau `Retry-After` khi người dùng đã xác nhận |

Ghi nhận (không phải lỗi):

- **VM 105 chưa sạch như brief giả định**: `tailscaled` còn profile `lab-c1` của tenant-c demo (đã gỡ 2026-11-18, control
  server 404). `tailscale logout` thất bại ("fetch control key: 404"); D1 dùng `tailscale login` (profile mới), profile
  cũ gỡ bằng `tailscale switch remove`. Sau dọn VM 105 không còn profile nào — dòng VM 105 trong `current.md` (node
  `lab-c1`) cần người điều phối cập nhật.
- Devices hiển thị cache theo `synced_at`: ngay sau expire (16:27, 3 phút) D2 vẫn "Online" + "revocation (expire)
  applied" + Expired; lần đồng bộ sau (16:33) "Offline". Đúng thiết kế (badge thu hồi/Expired đọc từ trạng thái hai pha).
- Thư của tenant thử (`tenant.invitation`, `tenant.activated`, `device.new` ×3, `policy.applied` ×6,
  `tenant.suspended/resumed`, `idp.admin_change` ×2) đi tới `<slug>.example.invalid` qua relay (`sent`) — không hộp thư thật.

## Phần chỉ là functional / giới hạn

- TCP của mục 2.3–2.5 đi giữa **hai node trên cùng VM 105** (D1 kernel TUN, D2 container userspace) — đúng chính sách,
  nhưng đường mạng không phải hai máy (§22.1: functional về mạng). Control plane (đăng ký, policy, expire) là của staging
  thật: client khác host Headscale, qua DNS công khai → VPS → tunnel → edge v10.
- V-07: chỉ Linux (mục 4). Phương án lùi "dán Auth ID" chưa chạy trên staging (đã có Vitest ở P4-T08).
- UI: một trình duyệt (Chromium), một ngôn ngữ (en), một vai trò (Owner) — không phải G4b (hai vai trò, hai ngôn ngữ, axe).
- Chiều chéo tenant chỉ kiểm từ tenant thử tới A/B (không dùng tài khoản của A/B).

## Dấu vết thử nghiệm còn trên staging

- Tenant `g4a-06bd`: `deleted` (slug giữ chỗ); backup cuối + DEK tự hủy sau grace 720 h (`tenant.keys_destroy`); realm
  Keycloak `g4a-06bd` bị vô hiệu hóa ở bước `idp.disable` (cùng user `g4a-owner` — mật khẩu/TOTP không còn ở đâu).
- Hàng lịch sử: 4 `enrollment_requests` (2 `verified`, 1 `consumed`, 1 `expired`), 5 `policy_versions`, audit, security
  event (`authz.cross_tenant_denials` High, `approval.self_decision` medium, `idp.console_login` High).
- VM 105: không profile Tailscale, `tailscaled` `NeedsLogin`; không container/thư mục của lượt thử (image `[images.tailscale]`,
  `[images.alpine]` có từ trước).
- Máy vận hành: file credential tạm (`g4a-creds.json`, `g4a-ui.json`, bộ đếm TOTP) đã xóa; SA thử `g3-sa1/g3-sa2` giữ nguyên.
- Không đổi: DNS, cổng, OPNsense, VPS, Proxmox, Tailscale của máy vận hành, `staging.env`, image/compose, edge (không
  reload), migration, dịch vụ nền tảng, cấu hình client lab.

## Lệnh

Script: [G4a/g4a.py](G4a/g4a.py) (bước `provision`, `apicheck`, `enroll`, `policy`, `lifecycle`, `devices`, `ui`,
`audit`, `cleanup`, `after`) và [G4a/ui.mjs](G4a/ui.mjs) (Chromium). Dùng lại harness của repo: `tests/g3`
(`Target`, `Platform` — 2P, step-up), `tests/e2e/harness/backend.py` (`portal_login`, `TOTP`), `tools/mgenv.py`;
`infrastructure/idp/create-user.sh`. Mỗi bước ghi `results.json` + `run.log` đã che (tập che + mẫu `hskey-`).

```bash
export G4A_CLIENT=mgdeploy@<máy client> G4A_LAB_A1=mgdeploy@<a1> G4A_LAB_B1=mgdeploy@<b1>
for s in provision apicheck enroll policy lifecycle devices; do python -B docs/planning/evidence/G4a/g4a.py $s; done
G4A_PW_DIR=<thư mục có ui.mjs + node_modules/playwright-core 1.65.0> G4A_PAUSE_MS=30000 python -B docs/planning/evidence/G4a/g4a.py ui
for s in audit cleanup after; do python -B docs/planning/evidence/G4a/g4a.py $s; done
```

## Chủ dự án duyệt

| Vai trò | Quyết định | Ngày |
|---|---|---|
| Chủ dự án | **Go** — "Ký G4a ngay, G4b tự động" (sau khi tự thử staging: "Tôi đã Test qua stagging khi hoàn thành có thể thực hiện luôn phase 5"). G4b coi là Go nếu báo cáo G4b xanh và không có phát hiện Cao/Nghiêm trọng (có ⇒ dừng hỏi lại). Lab Phase 5: "Chỉ dùng VM lab" ⇒ V-07 Windows/macOS/iOS/Android và tiêu chí "≥ 2 hệ điều hành" của P5-T02 ghi là ngoại lệ chờ thiết bị (P5-T03) | 2026-11-20 |
