# P4-T14 (phần chuẩn bị) — E2E Playwright: hai vai trò, hai ngôn ngữ, axe

> **File viết tay — không sinh từ master.** Bằng chứng phần chuẩn bị của task P4-T14 (§20 của
> [bản master](../implementation-master-plan.md); §12.4 "kiểm bằng axe trong E2E", §19 Phase 4 hàng "E2E tests", §22.1
> lớp "E2E (UI)"). **Chưa phải báo cáo G4b**: luồng enrollment (P4-T06/P4-T07/P4-T08) chưa gộp nên chỉ được chừa chỗ
> (mục 5); báo cáo G4b viết khi toàn bộ Phase 4 đã vào `main`. Quy ước: [README](README.md). Task không chạm staging,
> VPS, DNS, firewall, OPNsense, Tailscale, Proxmox.

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-19 (UTC+7) |
| Người thực hiện | Agent (Claude Code), worktree nhánh `p4-t14` (từ `main` cục bộ @ `a34260f`) |
| Môi trường | dev/CI — VM 110 `mg-ci-runner-2`: stack e2e của `tests/e2e/harness` tiền tố `p4t14e2e`, `MG_E2E_NET_BASE=10.244`, tenant `10.250.244.0/28`; image Playwright, Node `26.13.1-trixie-slim`, `golang` pin digest (`versions.lock`) |
| Commit | `2d44d70` (hạ tầng + spec + harness + sửa a11y), commit tài liệu này `[skip ci]`. Kiểm chứng cuối (mục 4) chạy trên cây **`2d44d70`** |
| Migration / API | Không |
| Ca | `PW-1`, `PW-2` (hai lượt liên tiếp của bộ Playwright), `PW-S` (artifact không chứa secret) — nhãn của harness, không dùng số E2E-nn (số do điều phối cấp khi viết báo cáo G4b) |
| Nhãn kết quả | **functional** (dev/CI, §22.1) |

## 1. Đầu ra

| Thành phần | Nội dung |
|---|---|
| `versions.lock` | `[images.playwright]` — `mcr.microsoft.com/playwright:v1.65.0-noble`, index `sha256:9beb5460…3dbe`, amd64 `sha256:f6fe3cf9…7366` (Ubuntu 24.04, Node 26.13.1, Chromium 1254); `[npm]` thêm `@playwright/test` 1.65.0, `@axe-core/playwright` 4.14.0 |
| `apps/web/package.json` + lockfile | devDependencies `@playwright/test` 1.65.0, `@axe-core/playwright` 4.14.0 (dùng chung `axe-core` 4.14.0); override `playwright-core` 1.65.0 (peer `>=1.0.0` của `@axe-core/playwright` nếu không sẽ kéo 1.65.1 — lệch phiên bản trình duyệt của image); script `e2e`; lockfile cập nhật bằng `npm install` trong Node pin digest |
| `apps/web/playwright.config.ts` | 1 worker, `retries: 0`, project `setup` → `vi` (`vi-VN`, giao diện sáng, `Asia/Ho_Chi_Minh`) và `en` (`en-US`, giao diện tối, UTC); Chromium với `--host-resolver-rules` (app./admin./auth.<domain> ⇒ địa chỉ do harness đưa) và `--ignore-certificate-errors-spki-list` = SPKI của chứng chỉ edge của lượt chạy (không tắt kiểm TLS cho mọi host); báo cáo `list` + HTML + JSON; trace/ảnh chỉ khi lỗi |
| `apps/web/e2e/` | `env.ts` (config của lượt, TOTP RFC 6238 với bộ đếm tăng nghiêm ngặt lưu ra tệp), `support.ts` (fixture `guard`, `checkA11y`, `checkI18n`, `checkBrowserStorage`, `login`, `apiStatus`), `auth.setup.ts`, `auth.spec.ts`, `logout.spec.ts`, `platform.spec.ts`, `tenant.spec.ts`, `isolation.spec.ts`, `enrollment.spec.ts` (chừa chỗ) |
| `tests/e2e/harness/playwrightui.py` | `prepare` / `run` / `all` (mục 3); ca `PW-1`, `PW-2`, `PW-S` |
| `Makefile` | `make e2e-playwright` — `e2e.py up` → `playwrightui.py all` → `e2e.py down` (down chạy cả khi lỗi); cần `WEB_NODE_MODULES` |
| `tests/e2e/harness/stack.py` | `teardown` gỡ thêm container `pw*` và mạng `<prefix>-pw` |
| `tests/e2e/harness/test_stack.py` | `[images.playwright]` là image chính thức pin digest; tag của image = mọi bản `@playwright/test`/`playwright`/`playwright-core` trong `package-lock.json`; harness lấy image từ `versions.lock` |
| `.github/workflows/e2e-playwright.yml` | **chỉ `workflow_dispatch`** (input `runs`, mặc định 2) — không chạy theo push/PR; action pin commit SHA (`checkout` v7.0.1, `upload-artifact` v7.0.2); `npm ci` trong Node pin digest; artifact = `E2E_OUT` (báo cáo HTML, `results.json`, log đã che, trace khi lỗi) |
| `apps/web/eslint.config.js`, `tsconfig.json` | `e2e/**` + `playwright.config.ts` vào typecheck và ESLint (`strictTypeChecked`, globals Node + browser) |
| `apps/web/src/tenant/settings/IdentityProviderPage.tsx` | Sửa lỗi a11y (mục 6) |

Không đổi: API, migration, Go, edge/Caddyfile, compose, workflow chạy theo push (`ci.yml`, `e2e-functional.yml`).

## 2. Bộ spec

Mỗi trang được kiểm bằng `checkScreen` = chờ xong (`h1`, không còn "Đang tải…", mạng yên) → **axe** (tag `wcag2a`,
`wcag2aa`, `wcag21a`, `wcag21aa`, trong Chromium thật nên có cả `color-contrast` mà jsdom không tính được; vi phạm
`serious`/`critical` ⇒ fail, mức khác đính kèm báo cáo) → **i18n** (`<html lang>` đúng ngôn ngữ; không văn bản/nhãn ARIA/
`title`/`placeholder` nào là chuỗi CHỈ có ở catalog ngôn ngữ kia — chuỗi chưa dịch hay hardcode; không khóa i18n thô —
khóa thiếu; bỏ qua `<code>`/`<pre>` là dữ liệu). Fixture `guard` (tự bật cho mọi test) fail test khi có sự kiện
`securitypolicyviolation` hay log CSP của Chromium, lỗi JavaScript chưa bắt, hoặc response 5xx của `/api/v1/*`; lỗi
console khác (vd. 401 của `GET /auth/session` khi chưa đăng nhập) chỉ đính kèm.

| File | Vai trò (origin) | Nội dung | Số test / project |
|---|---|---|---|
| `auth.setup.ts` (project `setup`) | SA (`admin.`), Owner, Admin, End User (`app.`) | Đăng nhập thật: `/login` → `GET /api/v1/auth/login` → Keycloak (mật khẩu, TOTP) → callback → SPA; ngay sau đó `checkBrowserStorage`; lưu storage state vào thư mục làm việc của stack | 4 |
| `auth.spec.ts` | khách | `/` ⇒ `/login` (CSP có `frame-ancestors 'none'`), `h1` đúng ngôn ngữ, `GET /auth/session` 401, axe + i18n — hai console; slug sai ⇒ lỗi gắn với ô nhập (`aria-invalid`), không rời trang | 3 |
| `logout.spec.ts` | SA2 (`admin.`), Admin 2 (`app.`) | Đăng nhập thật → trang chủ (axe) → Đăng xuất → end_session Keycloak → `/login`; `GET /auth/session` 401, cookie `__Host-mg_session` bị xóa, **cookie cũ đặt vào một trình duyệt khác ⇒ 401** (phiên thu hồi ở server) | 2 |
| `platform.spec.ts` | SA (`admin.`) | 16 mục nav của `super_admin` (13 màn hình đã xây: render từ API thật + `aria-current`; 3 mục sau MVP: trang "chưa khả dụng"); chi tiết tenant, job (timeline), instance, host, IdP; wizard tạo tenant (bước 1, lỗi kiểm hợp lệ, **không gửi** — kiểm không có `POST /platform/tenants`); hộp sửa thiết lập (mở, axe, Escape); hàng chờ 2P → chi tiết yêu cầu của SA khác: hash payload tính **trong trình duyệt** (`crypto.subtle`) = hash của server | 24 |
| `tenant.spec.ts` | Owner, Admin, End User (`app.`, tenant-a) | Mọi mục nav role thấy: Owner 22, Admin 21, End User 3 (gồm mục "chưa khả dụng": `enroll`, `enrollment-keys` — P4-T08, `diagnostics` — P5-T08, `usage`/`billing` — Phase 6); Owner: chi tiết thiết bị (dữ liệu thật sau `inventory.sync`), thành viên, group, version policy (editor form/HuJSON, lint, diff), hộp thoại mời (mở, axe, Escape — không gửi), form tài nguyên mạng (không lưu) | 52 |
| `isolation.spec.ts` | Owner, SA, End User | Owner A mở `/t/<B>/{overview,devices,users,policies,audit}` ⇒ 404 thống nhất, không lộ slug của B; `GET /api/v1/tenants/<B>`, `/devices`, `/audit` từ trong trang ⇒ 404; `/platform/tenants` trên `app.` ⇒ 404; ID không phải UUID, đường dẫn lạ ⇒ 404; SA mở route tenant trên `admin.` khi chưa có Support Access Grant ⇒ 404 (API 403); End User mở Users/Audit ⇒ trang không có quyền; bất biến lưu trữ sau khi duyệt nhiều màn hình (`app.`, `admin.`) | 12 |
| `enrollment.spec.ts` | — | 5 ca `test.fixme` có lý do (mục 5) | 5 (skip) |

**Tổng: 200 test** = 4 (setup) + 98 × 2 project (`vi`, `en`); mỗi project 93 chạy + 5 fixme. Theo vai trò (mỗi
ngôn ngữ): Platform SA 27 (24 + 2 isolation + 1 logout), Tenant Owner 37 (28 + 9 isolation), Tenant Admin 22 (21 + 1
logout), End User 4 (3 + 1 isolation), khách 3; cộng 4 lần đăng nhập ở setup.

Bất biến trình duyệt (`checkBrowserStorage`, gọi sau mỗi lần đăng nhập và sau khi duyệt nhiều màn hình): `localStorage`
chỉ có `mg.pref.theme`/`mg.pref.lang`, `sessionStorage` rỗng, không IndexedDB; mọi cookie `__Host-` của origin là
`HttpOnly` + `Secure` + host-only + `Path=/` và `document.cookie` không thấy chúng; HTML không chứa mẫu `hskey-…`/`Bearer …`.
Spec chỉ đọc: thao tác ghi duy nhất là đăng nhập/đăng xuất (không tạo tenant, không gửi lời mời, không lưu thiết lập,
không duyệt).

## 3. Cách chạy

```text
# một lệnh (dựng → chuẩn bị → PW_RUNS lượt, mặc định 2 → gỡ); cần Docker, openssl, python3
make e2e-playwright WEB_NODE_MODULES=$PWD/apps/web/node_modules   # node_modules: npm ci trong Node pin digest

# từng bước (stack đã `e2e.py up` với cùng E2E_PREFIX/E2E_WORK/E2E_OUT/MG_E2E_NET_BASE/DOCKER)
python3 tests/e2e/harness/playwrightui.py prepare   # một lần mỗi stack (E2E-21 không lặp lại được)
PW_RUNS=2 python3 tests/e2e/harness/playwrightui.py run   # chạy lại được; PW_ARGS="--grep …" để lọc
```

- **Chuẩn bị** (`prepare`): E2E-17/20/21 của `backend.py`; Super Admin 1 (`check_platform`) và Super Admin 2
  (`bootstrap-super-admin`); version policy mong muốn của tenant-a (`policy-apply` bootstrap); Tenant Owner, hai Tenant
  Admin (`seed-membership`), một End User (mời qua API + đăng nhập lần đầu); một group; `inventory.sync` của tenant-a
  (Devices có dữ liệu thật); SA2 tạo một yêu cầu 2P `platform.user.super_admin` cho một platform user mới (để chờ).
  Mỗi user đã đăng nhập một lần qua harness (TOTP đã cấu hình). `config.json` (domain, tenant, user test kèm mật khẩu +
  khóa TOTP + bộ đếm cuối, SPKI) được ghi `0600` trong `<E2E_WORK>/state/pw/` (thư mục `0700`, bị xóa khi `down`) —
  không bao giờ trong `E2E_OUT`, không commit.
- **Trình duyệt trong container, không cài lên host**: image Playwright pin digest, `-u <uid>:<gid>`, `HOME=/tmp`, cây
  repo và `node_modules` gắn **chỉ-đọc**, kết quả ra `E2E_OUT/playwright/run<i>/`. Chromium chạy trên mạng riêng
  `<prefix>-pw` (`<base>.9.0/24`) và phân giải `app.`/`admin.`/`auth.<domain>` về gateway của mạng đó, nơi bộ chuyển
  tiếp TCP thuần `<prefix>-pwfwd` (Node pin digest, `--network host`, `--read-only`, `cap_drop ALL` + `NET_BIND_SERVICE`,
  chỉ bind `<gateway>:443`) nối tới `edge:443`. TLS đầu-cuối giữa Chromium và edge; nguồn edge thấy là host (`<base>.0.1`
  — nguồn duy nhất được vào `admin.`, như mọi ca e2e khác).
- **Thu artifact**: `E2E_OUT/playwright/run<i>/html/` (báo cáo HTML), `results.json`, `playwright.log` (đã che),
  `artifacts/` (trace + ảnh + `error-context.md` chỉ khi lỗi; test đăng nhập/đăng xuất tắt trace và ảnh vì mật khẩu nằm
  trong thao tác `fill`). Trước khi kết thúc, harness che mọi giá trị cookie phiên (của storage state) và giá trị secret
  của lượt trong artifact — cả bên trong trace `.zip` và zip base64 nhúng trong `index.html` của báo cáo — rồi dò lại
  (ca `PW-S`).

## 4. Kết quả

### 4.1 Lượt cuối — cây `2d44d70`, stack dựng mới, đúng recipe của `make e2e-playwright`

`git diff` của `2d44d70` so với `a34260f` gửi lên VM (gzip, md5 khớp) trên cây `git archive` LF của `a34260f`; một lệnh
nền chạy `e2e.py up` → `playwrightui.py all` → `e2e.py down` (08:57–09:19 UTC 2026-11-19, `E2E_PREFIX=p4t14e2e`):

| Bước | Kết quả |
|---|---|
| `e2e.py up` | build api/worker/web/idp/probe/node-exporter từ cây, stack healthy, 4 client enroll (08:57–09:01) |
| `prepare` | xong 09:02:39 — SA1, SA2, Owner, 2 Admin, End User, group, `inventory.sync` `succeeded`, `policy-apply` `applied`, một yêu cầu 2P đang chờ. (Dòng `FAIL [E2E-24]` trong log là kết quả bị bỏ của `check_platform` dùng làm bước chuẩn bị — thiếu `sync_job` của E2E-23, như `platformui.py`) |
| **PW-1** | **PASS** — exit 0, **190 pass, 0 fail, 0 flaky, 10 skip** (5 fixme × 2 ngôn ngữ), 491 s; `setup` 4, `vi` 93 + 5 skip, `en` 93 + 5 skip |
| **PW-2** | **PASS** — exit 0, **190 pass, 0 fail, 0 flaky, 10 skip**, 495 s; cùng phân bố |
| **PW-S** | **PASS** — 8 tệp; giá trị phiên có trong dữ liệu zip nhúng của `run1/html/index.html`, `run2/html/index.html` đã được che; dò lại: 0 trúng |
| axe (cả hai lượt) | 0 vi phạm ở **mọi** mức (không có tệp đính kèm `axe-*.json` nào) |
| Thời gian | test dài nhất 11,5 s; mỗi lượt ~8 phút 10 s (1 worker) |
| `e2e.py down` | `dọn xong: còn 0 container, 0 network` (2 volume cache Go giữ do `E2E_KEEP_CACHE=1` — xóa tay sau đó, mục 8) |

### 4.2 Web (job CI `web`) trên cây `2d44d70`, Node pin digest

| Bước | Kết quả |
|---|---|
| `npm ci`, `npm run lint` (ESLint, gồm `e2e/**`), `npm run typecheck` (gồm `e2e/**`, `playwright.config.ts`) | exit 0 |
| `npm run test` (Vitest, cây repo đầy đủ gắn vào container) | exit 0 — **31 file / 366 test pass** (+4 file / 13 test skip — ca live), 37 s. (Lượt đầu chỉ gắn `apps/web` ⇒ 3 test đọc `api/openapi.yaml`, `database/seeds/rbac.sql`, mã Go báo lỗi — lỗi của cách chạy; một lượt khi VM tải 21 có 2 test axe của jsdom hết giờ — chạy lại khi tải 2: sạch) |
| `npm run build` + `check-dist` | exit 0 — 33 file, không inline script/style, không tài nguyên ngoài origin, không sourcemap |
| `npm audit --audit-level=high` | exit 0 — 9 moderate (như `main`), không high/critical |
| Python của `ci.yml` (`docs_check`, `test_mgenv`, `test_render_*`, `test_host_migrate`, `tests/g3/test_g3.py`, `openapi_lint` — 144 operation 0 problem, `test_openapi_lint`) + `test_stack.py` (60 PASS, gồm 3 kiểm mới của Playwright) + `py_compile playwrightui.py` | exit 0 |

### 4.3 Các lượt phát triển (stack `p4t14e2e` dựng lúc 07:57 UTC, cây trước `2d44d70`)

| Lượt | Kết quả | Ghi chú |
|---|---|---|
| dev 1 | 0 test chạy — `net::ERR_CERT_AUTHORITY_INVALID` | SPKI của **CA** không được Chromium nhận (server chỉ gửi chứng chỉ lá) ⇒ harness lấy SPKI của chứng chỉ edge qua bắt tay TLS đã kiểm theo CA của lượt |
| dev 2 | 171 pass, 17 fail, 10 skip | 12 fail: `page.request` (APIRequestContext chạy trong Node — không theo `--host-resolver-rules`/SPKI của Chromium) ⇒ `apiStatus` gọi `fetch` cùng origin từ trong trang; 2: chọn nhầm link `/platform/tenants/new` ⇒ chỉ link trong `tbody`; 1: `net::ERR_NETWORK_CHANGED` (Chromium `--network host` trên VM dùng chung, stack khác tạo/xóa mạng Docker) ⇒ mạng riêng + bộ chuyển tiếp; **2: lỗi a11y thật** (mục 6) |
| dev 3 | **188 pass, 0 fail, 0 flaky**, 10 skip | sau các sửa trên; image web build lại với bản sửa a11y |
| dev 4 + 5 (`PW_RUNS=2`, thêm ca 2P) | **190 + 190 pass, 0 fail, 0 flaky**, 10 skip mỗi lượt (497 s, 513 s); `PW-S` PASS | báo cáo HTML (zip nhúng) mang giá trị phiên ⇒ được che, dò lại sạch |

## 5. Chừa cho enrollment (P4-T06, P4-T07, P4-T08 chưa gộp)

`apps/web/e2e/enrollment.spec.ts` — 5 ca `test.fixme` (hiện là "skipped" trong báo cáo, lý do ghi trong file), thay thân
test khi các task vào `main`:

1. End User: wizard enrollment theo OS + axe.
2. End User: trang claim web-auth (mã enrollment trong hostname, yêu cầu đang chờ trong cùng phiên — §7.4).
3. Admin: phát hành pre-auth key — key hiển thị **một lần**, không còn trong DOM/storage sau khi đóng (checklist G4b).
4. Admin: hàng chờ duyệt yêu cầu enrollment (approve/reject/issue) + step-up.
5. End-to-end với client thật: claim → node đăng ký → thiết bị hiện trong Devices (trạng thái hai pha).

Hiện tại `tenant.spec.ts` kiểm hai mục nav `enroll`/`enrollment-keys` ở trạng thái "chưa khả dụng" (P4-T08) — khi P4-T08
bật `available: true`, các test đó tự chuyển sang kiểm màn hình thật (danh sách test sinh từ `TENANT_NAV`).

## 6. Lỗi UI/a11y/i18n tìm thấy

| # | Lỗi | Mức | Xử lý |
|---|---|---|---|
| 1 | Trang Identity Provider của tenant, nhánh chỉ-đọc (Tenant Admin — không có quyền sửa): `Field` (`<div><dt/><dd/></div>`) nằm ngoài `<dl>` ⇒ axe `dlitem` (**serious**) ở cả vi/en. Owner (form sửa) không bị | serious | **Đã sửa**: bọc `Field` trong `<dl>` (`IdentityProviderPage.tsx`) — dev 3 trở đi PASS |
| 2 | Không vi phạm axe nào khác ở mọi mức (kể cả minor/moderate, gồm `color-contrast` ở giao diện sáng và tối) trên 93 trang/trạng thái × 2 ngôn ngữ; không chuỗi chưa dịch / khóa thô; không vi phạm CSP, không lỗi JS chưa bắt, không 5xx | — | — |
| 3 | Quan sát (không sửa, nhỏ): ô slug của trang đăng nhập thay gợi ý bằng thông báo lỗi tại chỗ (`aria-describedby` + `aria-invalid`) nhưng không có vùng `aria-live` — trình đọc màn hình không tự đọc lỗi khi bấm "Tiếp tục" | gợi ý | Ghi lại cho rà soát UX G4b |

## 7. Hạn chế, bàn giao

- Kết quả **functional** (§22.1): stack dev/CI một host, Chromium (không Firefox/WebKit — image có sẵn, thêm project khi
  cần). Không có Host Agent ⇒ không thao tác vòng đời (như E2E-46).
- Spec chỉ đọc theo chủ ý (chạy lại được nhiều lượt trên cùng stack); các luồng ghi qua UI đã có ca E2E riêng
  (E2E-89/90, 108–112, 114–116 — Vitest + jsdom sau proxy). Báo cáo G4b có thể chuyển dần các luồng đó sang Playwright.
- `make e2e-playwright` không nằm trong `e2e-functional` (cần `node_modules`); workflow `e2e-playwright.yml` chỉ chạy
  tay (§22.1 ghi "hằng đêm + trước gate" — bật lịch khi chủ dự án đồng ý dùng phút Actions).
- VM 110 không có `make` ⇒ lượt cuối chạy đúng ba lệnh của recipe.

## 8. Tài nguyên VM

Đã dọn trên VM 110 (tiền tố `p4t14`): stack `p4t14e2e` (`e2e.py down`: 0 container, 0 network), volume
`p4t14e2e-gomod`/`p4t14e2e-gocache`, image build từ cây (`p4t14e2e-*`, do `down`), image Playwright đã pull
(`mcr.microsoft.com/playwright@sha256:9beb5460…`), thư mục `~/p4t14` (cây, kết quả, log, config tạm có credential test)
và `/tmp/p4t14-*`. Kiểm sau cùng: 0 container, 0 network, 0 volume, 0 image, 0 thư mục, 0 tiến trình mang `p4t14`. Không
`prune`; không chạm tài nguyên của `p4t07`, `fug3`, `mainm`, `mainv`. Cache build của Docker (dùng chung, không tên) không
xóa. Đĩa `/` sau khi dọn: 64 GB trống.

## 9. Gộp với `main` @ `92839f9` (P4-T06, P4-T07)

`git merge-tree` của `2d44d70` với `main` @ `92839f9`: **một xung đột** — `tests/e2e/harness/stack.py`, dòng tiền tố
container của `teardown` (P4-T07 thêm `"wa-"`, task này thêm `"pw"`) ⇒ giữ cả hai. `navModel.ts` không đổi trên `main`
(mục `enroll`/`enrollment-keys` vẫn "chưa khả dụng" tới P4-T08); i18n vi/en có thêm khóa (không ảnh hưởng spec). Bộ
Playwright chưa chạy lại trên cây đã gộp.
