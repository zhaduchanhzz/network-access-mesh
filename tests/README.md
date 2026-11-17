# tests

`integration/`, `isolation/` (IT-01…IT-20), `e2e/`, `security/`, `load/` (§22), `backup/` (diễn tập backup → restore của P2-T03a/P2-T05b với khóa dùng một lần: `drill.sh`, chỉ trên máy build/CI). Unit test Go đặt cạnh mã nguồn (`*_test.go`).

Mã Go trong `security/` dùng fixture phiên kiểm thử `security/sessionfixture` (P2-T15a: session cho từng role của §8.4, không
cần trình duyệt hay IdP) và **chỉ build với tag `mgtestfixture`** — mọi file của fixture và của package import nó bắt đầu bằng
`//go:build mgtestfixture` (`internal/archtest` kiểm, và kiểm binary `api`/`worker` không phụ thuộc fixture). Chạy:
`go test -race -count=1 -tags mgtestfixture ./tests/...` (cần `MG_TEST_PG_ADMIN_URL` như mọi test PostgreSQL; bài đăng nhập
Keycloak thật `security/oidclogin` tự bỏ qua khi thiếu `MG_TEST_KEYCLOAK_URL`). `security/bootstrapseed` (P2-T11a): Super
Admin và TO/TA tạo bằng `bootstrap-super-admin`/`seed-membership` đăng nhập và hành động qua API ghép (khớp theo
`(idp_id, sub)`, không theo email; SA không vào dữ liệu nội bộ tenant; TO của A nhận 404 ở B).

Isolation suite v1 (P2-T15, `make isolation`; bằng chứng: `docs/planning/evidence/P2-T15.md`):

| Thư mục | Nội dung |
|---|---|
| `security/authzmatrix` (tag) | Ma trận authz **sinh từ OpenAPI** (IT-02): mọi operation của `authz.Operations()` × 9 role + ẩn danh + session ở origin kia + request khác site × tenant của path (của mình, tenant kia, không tồn tại) × object của path (của mình, của thành viên khác, của tenant kia, không tồn tại). Kỳ vọng lấy từ §8.5/§8.6 mã hóa tay trong `master_test.go` (test đối chiếu từng ô với master; operation mới không có kỳ vọng ⇒ fail). Handler thật đã mount: identity, `tenantsapi`, `devicesapi` (Headscale qua `Locator` thật, edge không tới được), `auditapi`, `monitoringapi` (P2-T13a, chỉ đọc DB); khi có handler mới (API job — P2-T16): chỉ thêm handler set vào `handlerSets` trong `world_test.go` |
| `isolation` (tag) | IT-01 qua API ghép với IdP giả, IT-03 (mọi FK giữa bảng tenant phải ghép `tenant_id`), IT-12a qua `GET …/audit` |
| `isolation/headscale` | IT-06, IT-10 (API key), IT-20 (mức target và trên `Locator` thật, registry trong PostgreSQL của lần chạy) trên **hai Headscale thật**: `bash tests/isolation/headscale/run.sh` (`make isolation-headscale`; không có môi trường của script ⇒ test tự bỏ qua) |

## `e2e/harness` — stack dev/CI và kiểm thử functional (P2-T01a)

Stack [`compose.yaml`](../compose.yaml) ở gốc repo — **chỉ cho máy dev và runner CI**, mọi kết quả chỉ được ghi
**"functional"** (client, Headscale và edge cùng một host Docker — HS-24, §22.1), không bao giờ "network E2E verified".
Bằng chứng: [`P2-T01a.md`](../docs/planning/evidence/P2-T01a.md).

```bash
make e2e-functional                                   # = test_stack.py rồi e2e.py all (dựng → E2E-01…16 → gỡ)
DOCKER="sudo docker" E2E_PREFIX=p2t01a make e2e-functional            # máy cần sudo cho docker, tiền tố riêng
python3 tests/e2e/harness/e2e.py up|test|down         # từng bước khi phát triển (test chạy lại được trên stack đang chạy)
python3 tests/e2e/harness/e2e.py render               # chỉ render, không cần Docker
MG_E2E_NET_BASE=10.232 MG_E2E_TENANT_NET=10.250.232.0/28 E2E_PREFIX=dev2 make e2e-functional   # stack thứ hai song song
```

| File | Vai trò |
|---|---|
| `e2e.py` | Điều phối: chuẩn bị, khởi động theo thứ tự §11.3 (deny-all trước khi edge gắn network tenant), enroll 4 client, chạy các ca, lưu log đã che secret vào `E2E_OUT`, gỡ mọi đối tượng mang tiền tố. Khóa theo tiền tố: hai lượt không bao giờ dùng chung một stack |
| `stack.py` | Tham số (môi trường `ci`: [`infrastructure/environments/ci`](../infrastructure/environments/ci/ci.env)), render bằng `tools/render_instance.py`, `render_edge.py`, `render_idp.py`; CA nội bộ dùng-một-lần (openssl); secret dạng file theo UID của consumer; network; image từ `versions.lock` |
| `checks.py` | E2E-01…E2E-15 (E2E-16 — artifact không chứa secret — ở `e2e.py`) |
| `test_stack.py` | Tự kiểm không cần Docker: tham số, render, Caddyfile của CI chỉ khác khối `tls`, chọn image Headscale, che secret |
| `dbinit/` | Migration bằng đường của repo: `store.Bootstrap` → `SetRolePassword` → `store.MigrateAll` (build trong `[images.golang]`, chạy trên distroless nonroot) |

Ca kiểm (đều "functional"): PostgreSQL đã migrate (E2E-01), 3 realm Keycloak (E2E-02), baseline deny-all (E2E-03),
enrollment (E2E-04), IT-05 trên `status --json` (E2E-05), DERP map theo tenant (E2E-06), STUN tại điểm vào (E2E-07), TCP
thật cổng được phép / bị chặn (E2E-08/09 — không dùng `tailscale ping` làm bằng chứng policy), relay ép buộc qua DERP của
tenant (E2E-10), đường trực tiếp (E2E-11), allow-list của edge trên cả hai hostname (E2E-12/12b), API key chỉ dùng được
trên instance của nó qua listener admin (E2E-13), pre-auth key chéo tenant bị từ chối — AC-14/IT-13 (E2E-14), policy
chuyển về deny-all chặn lại TCP (E2E-15).

Headscale: image lấy từ `versions.lock` — `[images.mg-headscale]` (bản vá của P2-T10a) nếu đã pin, ngược lại
`[images.headscale]`; ép bản chính thức bằng `E2E_HEADSCALE_LOCK_KEY=headscale`.
