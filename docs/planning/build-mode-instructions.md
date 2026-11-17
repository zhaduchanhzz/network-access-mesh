# Build Mode Execution Instructions

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §25. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 25. Build Mode Execution Instructions

Phần này dành cho Coding Agent khi người dùng chuyển sang BUILD MODE. **Không tự chuyển mode**; chỉ bắt đầu sau khi plan được phê duyệt.

### 25.1 Nguyên tắc thực thi

1. **Thứ tự**: thực hiện task theo §20 đúng phụ thuộc (bảng ở §20 là nguồn sự thật). Mỗi task một nhánh/PR nhỏ mang task ID (Git hosting chốt ở P0-T07; trước đó làm việc trên nhánh cục bộ); không gộp nhiều phase. Ngoại lệ duy nhất về thứ tự phase: các task Phase 2 không chạm host được chạy song song Phase 1 sau G0 (§19).
2. **Gate**: dừng ở mỗi Go/No-Go (G0…G7), nộp bằng chứng vào `docs/planning/evidence/`, **chờ người dùng xác nhận** rồi mới sang phase kế. Gate thất bại ⇒ dừng, báo cáo, đề xuất sửa ADR; không tự ứng biến kiến trúc.
3. **Không tái thiết kế**: các quyết định ở §24 là cố định cho tới khi người dùng duyệt ADR thay thế. Chỗ nào plan ghi REQUIRES VALIDATION thì phải chạy phép thử ở §22.4 và cập nhật nhãn trong `docs/`.
4. **Server**: chỉ thao tác host sau khi người dùng cho phép **theo từng loại hành động**; bắt đầu bằng discovery chỉ-đọc (Appendix A.2). Chỉ dùng SSH key; không bao giờ dùng/ghi mật khẩu. Mọi lệnh thay đổi host (cài gói, `daemon.json`, firewall, SSH, DNS, router) phải được hiển thị trước và có lệnh hoàn tác.
5. **Không mở public**: không mở firewall/port forwarding, không trỏ DNS public tới host khi chưa qua kiểm tra nội bộ (AC-20) và chưa có chấp thuận.
6. **Repository tham khảo**: không chạy script/compose/image từ bốn repo tham khảo; **không tải `h.tar`**; chỉ port code từ `headscale-admin` sau khi review từng file và giữ thông báo MIT. **Ngoại lệ duy nhất** (chủ dự án duyệt ngày 2026-11-16): bản demo tham khảo `headscale-admin` 1.3.0, build từ mã nguồn ở commit đã pin, chạy cô lập trên staging với tenant demo `tenant-c` để xem UI trước Phase 4. Chi tiết ở `infrastructure/demo/headscale-admin/` và `docs/planning/evidence/ref-headscale-admin-demo.md`. ADR-16 không đổi; `h.tar` vẫn cấm.
7. **Headscale**: source chỉ được đổi bằng **bản vá bảo mật tối thiểu** trong `infrastructure/docker/headscale/patches/` (ADR-02 sửa đổi 2026-11-17): mỗi bản vá một lý do bảo mật, header ghi lý do + mục kiểm chứng + điều kiện gỡ, có unit test chạy trong build, có contract test trên image, không đổi hành vi nào khác, rebase ở mỗi lần nâng Headscale và gỡ khi upstream sửa; không báo/công bố bản vá ra ngoài repo khi chủ dự án chưa quyết (V-26: «Chưa báo», 2026-11-17). Không ghi trực tiếp SQLite, không import module Headscale; mọi thao tác qua REST API hoặc CLI trong container bằng Agent. Ngoại lệ Phase 1–2 (trước khi có Agent): chạy `docker exec <container> headscale …` theo runbook đã được duyệt; từ Phase 3 chỉ qua Agent.
8. **Supply chain**: mọi image pin theo digest, mọi CI action pin theo commit SHA; cập nhật `versions.lock`; chỉ image trong allowlist.
9. **Secrets**: không commit, không đặt trong biến môi trường/compose/log; dùng file secret; test "canary secret" phải xanh trước khi merge code có ghi log.
10. **Kiểm thử**: task có code phải kèm test theo §22.1; mọi operation mới trong OpenAPI phải có `x-permission` và xuất hiện trong ma trận authz; thay đổi liên quan tenant phải chạy bộ isolation.
11. **Dữ liệu thật**: không dùng mock metrics trong UI; tính năng chưa có nguồn dữ liệu hiển thị "không khả dụng".
12. **Ngôn từ**: không mô tả hệ thống là production-ready trước G6; không công bố SLA/giới hạn node chưa đo.
13. **Tài liệu**: mỗi nhận định kỹ thuật mới phải gắn nhãn bằng chứng; khi một mục REQUIRES VALIDATION có kết quả, cập nhật tài liệu và ADR liên quan trong cùng PR. Chỉ sửa bản master rồi chạy `python tools/split_plan.py`; không sửa tay file sinh trong `docs/` (ngoại lệ: `review-findings.md`, `research-evidence.md`, `evidence/` và runbook viết ở Build Mode).
14. **Bằng chứng**: che `hskey-…`, `Authorization`, cookie và email người dùng thật trước khi commit; secret scan có rule cho `hskey-`.
15. **Task bị chặn bởi phụ thuộc ngoài**: dừng task, ghi vào `docs/planning/evidence/blocked.md`, chỉ chuyển sang task không phụ thuộc vào nó; không thay phép thử thật bằng mô phỏng.
16. **Task tùy chọn**: task ghi "(Tùy chọn)" chỉ chạy khi người dùng yêu cầu.

### 25.2 Trình tự khởi động cụ thể

| Bước | Hành động | Task |
|---|---|---|
| 0 | **Đã thực hiện (2026-11-16):** plan được ghi vào `docs/planning/implementation-master-plan.md` và tách thành cây `docs/` bằng `tools/split_plan.py` | P0-T01 |
| 1 | Khởi tạo Git repo cục bộ (nhánh làm việc); xin người dùng trả lời Appendix A.1 và các quyết định mở (§25.4); chốt Git hosting, CI runner và registry — **đang thực hiện** (2026-11-16): chủ dự án đã tạo repo trên GitHub, chốt CI (GitHub Actions, runner tự host — D-12) và registry (GHCR); chờ trả lời A.1, gồm máy chạy runner (`docs/planning/evidence/blocked.md`) | P0-T05, P0-T02, P0-T07 |
| 2 | Dựng khung repo (Makefile, pre-commit, CI khung, `make docs-check`); khung test strategy và sổ đăng ký kiểm chứng | P0-T04, P0-T06 |
| 3 | Pin phiên bản/digest vào `versions.lock` | P0-T03 |
| 4 | Sau G0: chạy discovery chỉ-đọc trên host, cập nhật inventory | P1-T01 |
| 5 | Trình đề xuất chuẩn bị host để duyệt rồi thực hiện; firewall của host LAN chỉ được thay đổi trong phạm vi tunnel (P1-T16) sau khi duyệt, kèm rule chặn pool tenant → host (§14.1, tiền điều kiện của IT-14); allow-list đích của `mg-egress` để ở P6-T07 | P1-T02, P1-T03 |
| 6 | Build image edge/`stund`; dựng core tối thiểu; cấp wildcard certificate (CA staging trước); template instance; **spike sớm DERP qua Caddy** — thất bại thì dừng và báo cáo | P1-T04, P1-T06, P1-T05, P1-T07, P1-T05a |
| 7 | PoC non-root, Tenant A rồi Tenant B, cấu hình edge + conformance test | P1-T11, P1-T08…T10a |
| 8 | Áp policy thử; chạy các phép thử với client thật trong LAN (V-01…V-05, IT-09, IT-14); restart độc lập; diễn tập dựng lại | P1-T12a, P1-T12, P1-T12b…T13, P1-T19 |
| 9 | VPS (SSH key đã có từ 2026-11-16; chủ dự án không đổi mật khẩu root — D-10): discovery, hardening gồm tắt đăng nhập bằng mật khẩu, tunnel, gateway, DNS public; kiểm thử từ mạng ngoài (V-02, V-16…V-19); viết báo cáo G1 | P1-T15…T18, P1-T14 |
| 10 | Song song từ sau G0: các task backend không chạm host (P2-T01…); **chỉ khi G1 đạt** mới triển khai backend lên host (P2-T16) | Phase 2 |

### 25.3 File trọng yếu sẽ được tạo trước (không có file nào tồn tại hiện nay)

| File | Vai trò |
|---|---|
| `docs/**` (Appendix B) | Hồ sơ kiến trúc đã duyệt |
| `versions.lock` | Phiên bản + digest được phép |
| `infrastructure/headscale/templates/config.yaml.tmpl`, `compose.tenant.yaml.tmpl`, `bootstrap-policy.hujson` | Template instance của tenant (§14.5) |
| `infrastructure/caddy/Caddyfile` + manifest build xcaddy | Edge: allow-list, upstream động, listener nội bộ, listener tunnel-facing (§14.6) |
| `infrastructure/gateway/` (compose `mg-gateway`, cấu hình `l4proxy`, Dockerfile `stund`, mẫu cấu hình tunnel **không chứa khóa**) | VPS Public Gateway (§14.9) |
| `infrastructure/compose/compose.core.yaml` | Management Plane (project `mg-core`); edge nằm ở `compose.edge.yaml`, project riêng `mg-edge` (§14.4) |
| `infrastructure/compose/compose.edge.yaml` | Edge trong project riêng `mg-edge`, để deploy `mg-core` không recreate edge (§14.4) |
| `api/openapi.yaml` | Contract SaaS API (§13) |
| `database/migrations/0001…` | Schema + RLS (§6) |
| `internal/headscale/` | Adapter — ranh giới duy nhất của api/worker tới Headscale (§13.4) |
| `internal/store/tenant_tx.go` | `WithTenantTx` — bắt buộc cho mọi truy vấn tenant-scoped |
| `internal/authz/` + `database/seeds/permissions.sql` | Permission matrix (§8.5–8.6) |
| `apps/agent/` + `api/agent/v1/agent.proto` | Host Agent (§11) |
| `tests/isolation/` | IT-01…IT-14 |
| `infrastructure/headscale/templates/test-allow-intra.hujson` | Policy thử cho mọi phép thử có client (§22.1) |
| `compose.yaml` + `tests/e2e/harness` | Stack dev/CI cho phép thử "functional" (P2-T01a) |

### 25.4 Quyết định cần người dùng xác nhận trước/ở G0

| # | Quyết định | Khuyến nghị của plan | Trạng thái |
|---|---|---|---|
| D-1 | Domain + DNS provider có API cho DNS-01 | Bắt buộc để nghiệm thu MVP (ADR-09) | **Đã quyết** (2026-11-16): domain `gta5web.online`, DNS tại Cloudflare (có API cho DNS-01). Đã kiểm ngày 2026-11-16: nameserver của Cloudflare, không có bản ghi CAA, các tên `app.`, `admin.`, `auth.`, `*.mesh.` chưa được dùng (Appendix A.4). Domain là giá trị của biến môi trường `MG_BASE_DOMAIN`, không ghi cứng trong source hay template. Bản ghi phải ở chế độ DNS only, không bật proxy của Cloudflare (HS-15). Token cho DNS-01 **đã có** (2026-11-16): file secret `/opt/meshguard/secrets/edge/cloudflare_dns_token` trên host staging, chỉ edge đọc được (kiểm quyền 8/8). Token do chủ dự án cung cấp là token cấp account, thấy 2 zone và đọc được Workers — **rộng hơn yêu cầu**; nên thay bằng token chỉ "Edit zone DNS" cho zone này |
| D-2 | Exposure path cho giai đoạn Internet-facing (A / B / C) | **Đã quyết: B — VPS Public Gateway** (người dùng chỉ định VPS cho các endpoint cần public, 2026-11-16) | **Đã quyết** (2026-11-16) |
| D-9 | Vai trò của VPS: gateway tầng 4 không state (ADR-25) hay chạy luôn edge + Headscale của tenant trên VPS (Path C) | Gateway tầng 4 — không đặt khóa TLS/dữ liệu tenant trên VPS; xem lại khi có số đo V-20 | **Chấp nhận** theo khuyến nghị khi duyệt plan (2026-11-16) |
| D-10 | Đổi mật khẩu root của VPS và của Proxmox (cả hai đã lộ trong hội thoại ngày 2026-11-16) và cấp SSH key cho user triển khai | **Bắt buộc trước P1-T15** và trước mọi triển khai lên host staging | **Đã quyết — chấp nhận rủi ro** (2026-11-16): chủ dự án quyết định **không đổi** mật khẩu root của VPS và của Proxmox, thay bằng việc xóa các bản sao mật khẩu. Đã xóa toàn bộ 13 bản sao dạng rõ còn trên máy vận hành (đều nằm trong transcript của phiên làm việc; repo, memory, log và file tạm không có bản nào). Bản đã đi qua dịch vụ AI trong hội thoại nằm ngoài khả năng xóa, nên mật khẩu vẫn dùng được trên hai máy (R-23, T-19). SSH key của dự án đã có trên Proxmox (root) và VPS (user `mgdeploy`). Biện pháp bù: tắt đăng nhập SSH bằng mật khẩu trên VPS ở P1-T15 (hiện chủ dự án chọn **chưa tắt**); Proxmox không có IPv6 công khai, IPv4 nằm trong LAN |
| D-3 | IdP: Keycloak do nền tảng host, hay IdP sẵn có của tổ chức | Sơ bộ ở G0, chốt sau P1-T01: Keycloak 3 realm (platform, tenant-a, tenant-b) nếu host còn đủ RAM sau khi dành ~1,5 GB cho IdP (ST-04); nếu không: IdP nhẹ một-issuer cho mỗi tenant (chỉ cho lab), hoặc IdP sẵn có **chỉ khi** cung cấp được ≥ 3 issuer tách biệt (platform + 2 tenant) — một issuer duy nhất không đủ cho IT-01 và AC-06/07 | **Đã chốt** (2026-11-16): Keycloak tự host, 3 realm (platform, tenant-a, tenant-b). Điều kiện RAM đạt: host staging (VM 104) có 24 GB RAM (Appendix A.4) |
| D-4 | `node.expiry` mặc định | 90 ngày | **Chấp nhận** theo khuyến nghị khi duyệt plan (2026-11-16) |
| D-5 | Chấp nhận rủi ro single-host (ADR-24) cho dev/staging | Chấp nhận, không dùng cho production | **Chấp nhận** theo khuyến nghị khi duyệt plan (2026-11-16) |
| D-14 | Host cho môi trường production: máy nào, ở đâu (theo Path C — edge + tenant runtime trên host có IP công khai, Management Plane đặt cùng host hay tách riêng — hoặc multi-host) | Chốt **trước G6** (không chặn G0); cho tới khi chốt, plan chỉ tuyên bố "đủ điều kiện go-live" và không có môi trường production (§19) | **Chấp nhận** lộ trình khi duyệt plan (2026-11-16): chốt host production trước G6; chưa chọn máy |
| D-6 | Tư vấn pháp lý R-01 | Ý kiến sơ bộ bằng văn bản trước G2; đầy đủ trước G6 | **Chấp nhận** khi duyệt plan (2026-11-16): chủ dự án đã đọc R-01 (G0(8)) và tự mở yêu cầu tư vấn pháp lý; ý kiến sơ bộ bằng văn bản trước G2, đầy đủ trước G6. **2026-11-16: chủ dự án xác nhận R-01 thông qua và được đồng ý** — điều kiện trước G2 đạt (`docs/planning/evidence/R-01.md`) |
| D-7 | Ngôn ngữ tài liệu `docs/` | Giữ như plan (tiếng Việt + thuật ngữ tiếng Anh) | **Chấp nhận** theo khuyến nghị khi duyệt plan (2026-11-16) |
| D-8 | Bật chia sẻ tín hiệu CrowdSec Central API | Tắt mặc định | **Chấp nhận** theo khuyến nghị khi duyệt plan (2026-11-16) |
| D-11 | Số người vận hành nền tảng cho dual control (2P) | ≥ 2 người; nếu chỉ có 1: chọn chế độ thay thế "trì hoãn thực thi có thông báo cho Tenant Owner" và ghi vào ADR-13 | **Đã quyết** (2026-11-16): từ 2 người vận hành trở lên — dual control đúng thiết kế, không cần chế độ thay thế |
| D-12 | Git hosting, CI runner có Docker, container registry | Chốt ở P0-T07 trước khi pin digest | **Đã quyết** (2026-11-16): GitHub + GitHub Actions chạy trên **runner tự host** + GHCR (image private, pin theo digest). Điều kiện (R-28): runner đặt trên máy hoặc VM riêng, **không** phải host LAN staging, không mount `/opt/meshguard` hay Docker socket của host đó; runner ephemeral (mỗi job một runner dùng một lần); workflow từ fork phải được duyệt trước khi chạy; token GHCR quyền tối thiểu. Máy chạy runner: VM 105 `mg-ci-runner`, tách khỏi host staging, đã có Docker (Appendix A.4). **Quyết định lại** (2026-11-16): chủ dự án giữ repo GitHub **public** và push ⇒ CI chạy trên runner do GitHub cung cấp (`ubuntu-24.04`), **không** gắn self-hosted runner vào repo này (PR từ fork có thể chạy code trên máy runner); GHCR giữ nguyên, đẩy image bằng `GITHUB_TOKEN`. VM 105 `mg-ci-runner` (Docker + runner 2.338.2, chưa đăng ký) giữ lại làm máy build/thử cục bộ, không kết nối GitHub. Workflow `ci` (docs-check + gitleaks) và `runner-smoke` (push/pull GHCR) chạy trên runner của GitHub. Rủi ro công khai thông tin: R-29 |
| D-13 | Cơ chế nâng quyền không dùng mật khẩu trên host LAN và VPS | sudoers `NOPASSWD` có phạm vi cho user triển khai, hoặc người dùng tự chạy script đặc quyền do agent sinh rồi trả output | **Đã thực hiện tạm** (2026-11-16): user `mgdeploy` có `sudo` NOPASSWD **toàn quyền** trên VPS và trên các VM (mặc định của cloud-init); Proxmox dùng SSH key của root. Thu hẹp sudoers về phạm vi cần thiết ở P1-T02 (host staging) và P1-T15 (VPS) |
