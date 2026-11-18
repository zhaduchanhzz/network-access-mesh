# Roadmap & Milestones

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §19, §22.3. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 19. Development Roadmap

Quy tắc chung: **không bắt đầu phase kế tiếp khi Go/No-Go gate của phase trước chưa đạt**; mỗi gate cần bằng chứng (log test, ảnh chụp lệnh, báo cáo) lưu trong `docs/planning/evidence/`. Task ID tham chiếu §20.

Ba điều chỉnh có chủ đích để tránh phát hiện muộn (bổ sung sau phản biện — Appendix D): (a) **spike sớm** P1-T05a kiểm chứng DERP qua Caddy (R-05) ngay khi có chứng chỉ, trước khi dựng phần còn lại của Phase 1; (b) các task Phase 2 **không chạm host** được chạy song song với Phase 1 sau G0 (danh sách ở §20), nhưng không triển khai gì lên host trước G1; (c) G4 tách thành **G4a** (enrollment, policy apply, devices, audit ở mức API + UI tối thiểu — mở các task lab của Phase 5) và **G4b** (phần UI còn lại, i18n, a11y — điều kiện của G5).

Ở **mỗi gate**: rà lại phiên bản đã pin (bản vá Headscale và client; client di động không pin được ⇒ ghi phiên bản thực tế vào bằng chứng), rà lại sổ rủi ro §23.1 và sổ kiểm chứng §22.4. Rà soát bảo mật ở gate do người **không viết** phần được rà thực hiện (người dùng hoặc một agent review độc lập), theo checklist nêu trong gate; kết quả lưu ở `docs/planning/evidence/`.

**Môi trường:** *dev/CI* = stack `compose.yaml` trên máy phát triển hoặc runner (kết quả chỉ được ghi "functional"); *staging* = host LAN `/opt/meshguard` + VPS gateway — nơi chạy mọi gate tới G5; *production* = chưa tồn tại trước G6 và không đặt trên single host LAN (D-5, ADR-24).

Chi tiết từng môi trường (bổ sung cho đoạn trên):

| Môi trường | Nơi chạy | Domain / TLS | Nguồn secret | Dữ liệu | Ai triển khai | Điều kiện thăng cấp |
|---|---|---|---|---|---|---|
| dev/CI | Máy phát triển hoặc CI runner — stack `compose.yaml` (P2-T01a) | Tên nội bộ + CA nội bộ **chỉ cho CI** | Sinh lúc chạy, chỉ dùng cho stack này | Seed thử; không có dữ liệu khách | Coding Agent / CI | Kết quả chỉ được ghi "functional" (§22.1) |
| staging | Host LAN `/opt/meshguard` + VPS gateway | Domain thật của D-1: `*.mesh.<domain>`, `app.`, `auth.` (qua VPS), `admin.` (chỉ trong LAN); wildcard DNS-01 | File secret trên host (§14.2); KEK và khóa backup của riêng staging (P2-T04a); khóa tunnel sinh tại từng máy (P1-T16) | Tenant thử A/B/C; **không** có dữ liệu khách thật | Coding Agent, sau khi người dùng duyệt theo từng loại hành động (§25.1 quy tắc 4) | Nơi chạy mọi gate tới G5 và các diễn tập của Phase 6 |
| production | **Chưa tồn tại** — host có IP công khai theo Path C hoặc multi-host (ADR-24), chốt ở D-14, dựng ở P7-T11 sau G6 | Zone hoặc domain riêng cho production; không dùng chung bản ghi với staging | Mọi secret (KEK, khóa backup, token DNS, khóa ký manifest) **sinh mới** tại production; không sao chép từ staging | Dữ liệu khách; không di trú tenant thử | Người vận hành, theo runbook đã diễn tập ở staging (P1-T19, P6-T04a) | Cùng digest trong `versions.lock` đã qua G6 ở staging; bằng chứng gate đầy đủ; diễn tập restore trên chính host production (P7-T11) |

### Phase 0 — Research & Architecture

| Thuộc tính | Nội dung |
|---|---|
| Objective | Đóng băng kiến trúc và backlog đã được phê duyệt |
| Scope | Tách plan thành cây `docs/` (Appendix B), ADR, sơ đồ C4, ERD, threat model, backlog; pin phiên bản; khung repo |
| Technical tasks | P0-T01…P0-T07 và P0-T08 |
| Dependencies | Người dùng phê duyệt plan này |
| Files/modules expected | `docs/**`, `README.md`, `Makefile`, `.gitignore`, `.env.example` (không secret), cấu hình pre-commit (secret scan) |
| Configuration requirements | Không |
| Database migrations | Không |
| API changes | Không (khung `api/openapi.yaml` chỉ có danh mục path) |
| Security controls | Secret scanning ở pre-commit/CI; quy ước pin digest + commit SHA |
| Unit tests | Không áp dụng |
| Integration tests | Kiểm link/mermaid của tài liệu |
| E2E tests | Không áp dụng |
| Acceptance criteria | Đủ file theo Appendix B; ADR được duyệt; Appendix A.1 được trả lời hoặc chấp nhận là "chưa biết" có chủ đích (trừ các mục bắt buộc của G0) |
| Definition of Done | Biên bản phê duyệt kiến trúc |
| Risks | Thiếu thông tin môi trường chặn Phase 1; rủi ro pháp lý R-01 chưa được xem xét |
| Rollback strategy | Không áp dụng (chỉ tài liệu) |
| **Go/No-Go G0** | Kiến trúc được duyệt **và** có đủ: (1) domain + DNS provider có API — **bắt buộc**; chưa có ⇒ không qua G0 và không bắt đầu Phase 1 (khi 7 điều kiện còn lại đã đủ, người dùng có thể chấp thuận bằng văn bản cho các task backend không chạm host ở §20 chạy trước trong lúc chờ domain); (2) thông số host LAN và VPS do người dùng khai, xác minh lại ở P1-T01/P1-T15, kèm mức cấu hình tối thiểu tạm tính của host (ASSUMED cho tới khi có số đo P1-T20) và ngưỡng đạt cho P1-T20/P1-T21 (thời gian restart edge, thời gian phục hồi sau reboot); (3) SSH key cho user triển khai trên cả hai máy + cơ chế nâng quyền **không dùng mật khẩu** (sudoers `NOPASSWD` có phạm vi, hoặc người dùng tự chạy script đặc quyền do agent sinh rồi trả output); **mật khẩu root của VPS và của Proxmox đã đổi** (D-10 — cả hai đã lộ trong hội thoại ngày 2026-11-16; **chủ dự án miễn yêu cầu này ngày 2026-11-16** và chấp nhận rủi ro — R-23, T-19); (4) danh sách client thử: ≥ 4 client ngoài host trên ≥ 2 hệ điều hành và ≥ 1 mạng ngoài LAN; (5) Git hosting, CI runner, registry (P0-T07); (6) D-3 sơ bộ: phương án IdP phải cho ≥ 3 issuer tách biệt (platform + 2 tenant), chốt sau P1-T01; (7) số người vận hành cho dual control (D-11); (8) xác nhận đã đọc R-01 |

### Phase 1 — Infrastructure Foundation

| Thuộc tính | Nội dung |
|---|---|
| Objective | Chứng minh nền hạ tầng: 2 tenant thủ công từ template, qua edge chung, với official client thật |
| Scope | Chuẩn bị Ubuntu, Docker/Compose, PostgreSQL, Caddy/TLS, Headscale Tenant A và B, DERP/STUN, persistent storage, health check cơ bản, **VPS Public Gateway** (tunnel, `l4proxy`, `stund`). **Chưa** có SaaS backend |
| Technical tasks | P1-T01…P1-T19 và các task hậu tố (P1-T20, P1-T21, P1-T05a, T10a, T12a…T12e) |
| Dependencies | G0; quyền thao tác host |
| Files/modules expected | `infrastructure/docker/edge/`, `infrastructure/caddy/Caddyfile`, `infrastructure/compose/compose.core.yaml`, `infrastructure/compose/compose.edge.yaml`, `infrastructure/headscale/templates/*` (gồm fixture `test-allow-intra.hujson`), `infrastructure/crowdsec/*`, `infrastructure/gateway/*`, script render template tối giản, `tests/security/edge`, `tests/isolation/derpprobe`, `docs/deployment/*` |
| Configuration requirements | `daemon.json` (address pools, log), DNS wildcard, token DNS provider (secret file), tunnel WireGuard VPS ↔ host LAN, cấu hình `l4proxy`/`stund` trên VPS, bản ghi CAA, quy tắc firewall đề xuất cho cả hai máy |
| Database migrations | Không (PostgreSQL chỉ được dựng và kiểm tra kết nối) |
| API changes | Không |
| Security controls | Allow-list path ở edge; network 2 thành viên; container hardening; secret dạng file; policy deny-all trước khi gắn edge; không publish PostgreSQL/metrics; CrowdSec ở chế độ chỉ-quan-sát cho tới G1; firewall hai đầu tunnel; VPS không giữ khóa TLS |
| Unit tests | Test render template (golden file) |
| Integration tests | `configtest` trên config đã render; kiểm tra path bị chặn; kiểm tra thành viên network |
| E2E tests | Thủ công với client thật: áp fixture allow (P1-T12a) → enrollment bằng pre-auth key (CLI trong container) → TCP cùng tenant (cổng được phép thông, cổng khác bị chặn) → cô lập chéo tenant → ép relay; lặp lại qua VPS gateway từ mạng ngoài (P1-T18) |
| Acceptance criteria | Ở mức thủ công: AC-01 (hai compose project + hai thư mục dữ liệu), AC-02, AC-03, AC-08, AC-09 (bằng `headscale nodes list`), AC-10 (fixture), AC-11 (smoke), AC-13, AC-14 (pre-auth key), AC-16 (qua Caddy), AC-18, AC-20; IT-09 (`derpprobe`) và IT-14 |
| Definition of Done | Kết quả từng PoC được ghi; `ubuntu-server-inventory.md` hoàn tất cho host LAN và VPS; diễn tập dựng lại từ runbook đạt (P1-T19) |
| Risks | DERP qua Caddy không hoạt động (spike P1-T05a phát hiện sớm); chuỗi VPS → tunnel → edge cắt stream dài; image không chạy non-root; thiếu client thử hoặc mạng ngoài LAN |
| Rollback strategy | `docker compose down` từng project; khôi phục bản sao `daemon.json`/firewall; xóa `/opt/meshguard` (giữ backup) |
| **Go/No-Go G1** | (1) control qua Caddy với client thật trên ≥ 2 hệ điều hành; (2) **DERP qua Caddy** truyền được dữ liệu khi ép relay; (3) upstream động theo nhãn + attach network lúc chạy: theo số đo P1-T12d có 0 stream bị đóng khi gắn và 0 truy vấn DNS đi ra ngoài (hoặc đã chọn phương án lùi); (4) qua **VPS gateway**: `tailscale netcheck` đúng với STUN dùng chung (V-02), control + DERP chạy qua chuỗi `l4proxy` → tunnel → edge (V-16), edge thấy đúng IP client (V-17), stream nhàn rỗi không bị cắt (V-18) — nếu VPS chưa sẵn sàng: ghi "pending" và **không** được tuyên bố Internet-facing; (5) allow-list path đạt (kể cả conformance test P1-T10a) và `admin.<domain>` không tới được qua VPS; (6) restart A: số stream của B bị đóng = 0 và client B không mất kết nối control (ba tiêu chí của AC-18); (7) IT-09 (`derpprobe`) và IT-14 đạt; (8) diễn tập dựng lại (P1-T19) đạt; (9) số đo P1-T20 (edge với 100/300 network) và P1-T21 (reboot host, restart `dockerd`) đạt ngưỡng chốt ở G0. Thất bại (2) — phát hiện sớm ở P1-T05a — ⇒ **dừng**, chạy PoC DP-09 (phương án (e) ở §10.3), rồi người dùng quyết định giữa (e) và (c) kèm ngân sách IP/cổng; sửa ADR-11 và §15.5 tương ứng |

### Phase 2 — SaaS Backend

| Thuộc tính | Nội dung |
|---|---|
| Objective | Backend trung tâm quản lý được cả hai tenant qua API, có authn/authz đầy đủ |
| Scope | Go API, authentication, Tenant Registry, role/permission model, Headscale Adapter, migrations, khung job, "adopt" hai instance thủ công vào registry |
| Technical tasks | P2-T01…P2-T16 và các task hậu tố (P2-T01a, T03a, T04a, T05a, T05b, T11a, T13a, T15a) |
| Dependencies | G0 cho các task không chạm host; **G1** cho việc triển khai lên host (P2-T16); phương án IdP cho ≥ 3 issuer tách biệt (platform + 2 tenant) |
| Files/modules expected | `apps/api`, `apps/worker`, `internal/{identity,idp,authz,tenants,platform,headscale,devices,audit,secrets,monitoring,store,jobs,httpapi,config}`, `api/openapi.yaml`, `database/migrations/*`, `database/queries/*`, `database/seeds/*`, `compose.yaml` (stack dev/CI), `tests/{integration,isolation,security}` |
| Configuration requirements | Issuer/client OIDC; DSN PostgreSQL theo role; KEK file; token nội bộ của edge |
| Database migrations | `0001`–`0006` theo bản đồ migration ở §6.3 (registry; identity & RBAC; secrets; audit có partition, security events không partition; device cache; jobs/idempotency); RLS policy cho từng bảng |
| API changes | `auth/*` (callback theo từng IdP), `tenants` (đọc), `platform/tenants` (đọc; adopt bằng CLI), `devices` (đọc, rename, expire, delete, sync), `users` (đọc), `audit`, `platform/audit`, `platform/instances`, `platform/health`, `tenants/{t}/dashboard`, `tenants/{t}/jobs[/{jobId}]`, `platform/jobs[/{id}]` (đọc) |
| Security controls | Session BFF + CSRF; authz 5 lớp; RLS `FORCE`; SecretStore; rate limit; redaction log; `x-permission` lint |
| Unit tests | Lattice role; lint policy quyền; SecretStore (mã hóa/AAD); ánh xạ lỗi adapter; idempotency |
| Integration tests | Adapter contract test với Headscale 0.29.7 thật (testcontainers); RLS; migration up trên DB có dữ liệu; OIDC với IdP thật |
| E2E tests | API-level: Super Admin thấy hai tenant; Tenant Admin A bị `404` ở B |
| Acceptance criteria | AC-04, AC-05a, AC-06, AC-07, AC-12 ở mức API; IT-01 (kèm 01b, 01c), IT-02, IT-03, IT-06, IT-10, IT-12a tự động |
| Definition of Done | OpenAPI khớp code; coverage authz matrix 100% operation; không secret trong log (test canary) |
| Risks | Quirk REST của Headscale (lỗi 500 cho not-found, tham số query); chi phí bcrypt khi polling |
| Rollback strategy | Triển khai lại image trước; migration có bước bù; restore PostgreSQL từ dump lấy trước migration (P2-T03a) |
| **Go/No-Go G2** | Toàn bộ isolation test của phase xanh; contract test xanh; rà soát bảo mật theo checklist OWASP ASVS (xác thực, phiên, kiểm soát truy cập) do người không viết phần code đó thực hiện — kết quả ở `evidence/G2-security-review.md`, 0 mục Cao còn mở; nghi thức khóa (P2-T04a) hoàn tất; có ý kiến pháp lý sơ bộ bằng văn bản về R-01 |

### Phase 3 — Tenant Orchestrator

| Thuộc tính | Nội dung |
|---|---|
| Objective | Tạo/tạm dừng/xóa tenant hoàn toàn tự động, an toàn khi lỗi giữa chừng |
| Scope | Host Agent, compose driver, state machine provisioning, vòng đời tenant, cấp phát endpoint/UID, secrets, health verification, failure recovery, suspend/deprovision, xoay API key, reconcile, backup cơ bản |
| Technical tasks | P3-T01…P3-T14 và các task hậu tố (P3-T16, P3-T03a, P3-T18, T04a, T05a, T05b, P3-T15, T05c, T06a, T08a, T13a, T14a, T14b, P3-T17) |
| Dependencies | G2 |
| Files/modules expected | `apps/agent`, `apps/probe`, `api/agent/v1/agent.proto`, `internal/provisioning/**`, `internal/relay`, `internal/notifications`, `internal/policies` (lõi), `internal/usage` (quota tối thiểu), template hoàn chỉnh trong `infrastructure/headscale/templates/`, `infrastructure/monitoring/` (bộ cảnh báo tối thiểu — P3-T16) |
| Configuration requirements | Socket Agent; allowlist image digest; dải UID và dải subnet tenant (`tenant_net_pool`) theo host; lịch job; SMTP; số người duyệt 2P (D-11) |
| Database migrations | `0009`–`0015` theo bản đồ migration ở §6.3 (approval/invitation/notification; relay; backups; plans/subscriptions; policy_versions + policy_applications; ràng buộc placement của `hosts`/`tenant_instances`; `provisioning_jobs.cancel_requested_at`) và `0020` (quyền thu hồi session của worker — P3-T17) |
| API changes | `POST /platform/tenants`, `/platform/tenants/{id}/suspend`, `/resume`, `DELETE /platform/tenants/{id}`, `platform/instances/{id}/<action>`, `platform/hosts`, `platform/approvals`, `tenants/{t}/approvals`, `platform/jobs/{id}/retry`, `/cancel`, `/rollback`, `tenants/{t}/invitations`, `tenants/{t}/notifications`, `tenants/{t}/relay`, `platform/relay-regions` (chỉ đọc) |
| Security controls | Agent kiểm tra spec; không secret trong job payload/log; policy deny-all trước attach; dual control cho xóa/restore; một lifecycle job/tenant |
| Unit tests | State machine (mọi chuyển trạng thái, compensation); cấp phát UID; validator spec của Agent |
| Integration tests | Provision trên Docker thật; **tiêm lỗi tại từng step** ⇒ không còn tài nguyên mồ côi; retry idempotent; reconcile báo cáo drift |
| E2E tests | Tạo tenant C qua API → enroll bằng helper (P3-T14a) → áp fixture allow → TCP thông → suspend ⇒ TCP bị chặn → resume ⇒ TCP thông lại → deprovision (qua phê duyệt 2P) |
| Acceptance criteria | AC-01…AC-03 tự động cho tenant mới; AC-18; AC-19 (backup/restore cơ bản); lời mời Owner dùng được để đăng nhập tenant mới |
| Definition of Done | Provision lặp lại 20 lần liên tiếp không lỗi; thời gian từng step được ghi nhận |
| Risks | Quyền của Agent ≈ root; lỗi compensation để lại tài nguyên; attach network lúc chạy |
| Rollback strategy | Tắt orchestrator (feature flag) và quay về quy trình thủ công Phase 1; tenant đã tạo vẫn chạy độc lập |
| **Go/No-Go G3** | Tiêm lỗi đạt; suspend/resume/deprovision đạt với lưu lượng thật; dual control đạt (tự duyệt bị từ chối, payload đổi sau khi duyệt bị từ chối); AC-19 đạt; A/B đã được chuẩn hóa qua orchestrator (P3-T14b); reboot host khi orchestrator đang chạy: mọi tenant tự phục hồi (edge supervisor gắn lại), không thao tác tay |

### Phase 4 — Web Management

| Thuộc tính | Nội dung |
|---|---|
| Objective | Portal thống nhất cho Super Admin và Tenant Admin |
| Scope | Platform Console, Tenant Portal, Device Management, Enrollment (web-auth claim + pre-auth key), Policy Management, DNS/Routes, Resource Catalog, Audit UI, i18n vi/en, dark/light, a11y |
| Technical tasks | P4-T01…P4-T14 và P4-T03a, P4-T09a, P4-T10a, P4-T15 |
| Dependencies | G3 (API ổn định) |
| Files/modules expected | `apps/web/**`, `internal/{enrollment,policies,network,members}`, bổ sung `api/openapi.yaml` |
| Configuration requirements | Hai origin; CSP; quy tắc chuyển hướng `/register/*` ở edge |
| Database migrations | `0021`–`0024` theo bản đồ migration ở §6.3 (enrollment_requests; groups + tenant_tags; network_resources/dns_records; support_access_grants + identity_links) |
| API changes | `enrollment/*`, `policies/*`, `groups/*`, `tags/*`, `users` (ghi, gồm `role`, `admin-role`, `ownership-transfer`), `devices/{id}/tags`, `routes/*`, `dns/*`, `resources/*`, `support-grants/*`, `platform/users`, `platform/settings`, `platform/identity-providers`, `platform/plans`, `tenants/{t}/settings` (+ `settings/security`), `tenants/{t}/approvals`, `tenants/{t}/identity-provider`, `request-deletion`, `PATCH /platform/tenants/{id}` |
| Security controls | Guardrail lint policy; 4-eyes tùy chọn; step-up; key hiển thị một lần; claim chỉ khi có yêu cầu đang chờ trong cùng phiên + kiểm node sau đăng ký (§7.4) |
| Unit tests | Render policy tất định; lint L1–L13; component (Vitest) |
| Integration tests | Pipeline policy với Headscale thật (`CheckPolicy` → `SetPolicy` → read-back); DNS records hot-reload; duyệt route |
| E2E tests | Playwright cho hai vai trò, hai ngôn ngữ; axe; luồng enrollment với client thật |
| Acceptance criteria | AC-05b, AC-06, AC-07, AC-10, AC-11 qua UI ở mức functional; mọi màn hình có trạng thái rỗng/lỗi thật, không mock |
| Definition of Done | Không chuỗi hardcode; type client sinh tự động; không secret trong browser storage (test) |
| Risks | Chuyển hướng web-auth ở edge không tương thích client; phạm vi UI phình to |
| Rollback strategy | Feature flag theo module UI; quay lại bản web trước; API giữ tương thích ngược |
| **Go/No-Go G4** | **G4a:** enrollment (kèm gate web-auth V-07 hoặc đã chuyển sang phương án lùi "dán Auth ID"), policy apply, devices, audit chạy end-to-end qua API + UI tối thiểu. **G4b:** toàn bộ E2E xanh (hai vai trò, hai ngôn ngữ, axe); rà soát UX bảo mật theo checklist: key hiển thị một lần; lời nhắc step-up; cách diễn đạt trạng thái hai pha; không secret trong DOM/storage; xác nhận thao tác phá hủy |

### Phase 5 — Zero Trust & Relay

| Thuộc tính | Nội dung |
|---|---|
| Objective | Chứng minh đầy đủ MVP acceptance trên mạng thật |
| Scope | Default-deny, least-privilege template, grants, DERP fallback, thu hồi thiết bị (đo), connectivity diagnostics, security test, ma trận tương thích client, (tùy chọn) OIDC gốc, (tùy chọn) đánh giá peer relays và STUN endpoint thứ hai |
| Technical tasks | P5-T01…P5-T12 và P5-T02a, T05a, T07a |
| Dependencies | G4a để bắt đầu các task lab, G4b trước G5; ≥ 4 thiết bị thật trên ≥ 2 hệ điều hành; ≥ 1 mạng ngoài LAN; mục G1(4) (VPS gateway) đã đóng — nếu chưa: cần quyết định bằng văn bản "MVP LAN-only" với mạng thứ hai là một segment NAT nội bộ, khi đó AC-15/16 ghi "network E2E verified (LAN NAT)" và phần Internet là ngoại lệ được chấp nhận |
| Files/modules expected | `tests/{e2e,isolation,security}/**`, template policy, trang Diagnostics, báo cáo đo |
| Configuration requirements | Môi trường test NAT; biến ép relay trên client test |
| Database migrations | Không bắt buộc (chỉ nếu thêm bảng báo cáo) |
| API changes | `diagnostics/*` |
| Security controls | Các kiểm soát §7 thuộc phạm vi MVP; kiểm thử T-01…T-21 theo phân bổ ở P5-T09 (phần phụ thuộc Phase 6 thuộc P6-T12) |
| Unit tests | Sinh `tests` policy từ inventory |
| Integration tests | Policy deny bằng TCP thật; revoke read-back |
| E2E tests | **AC-08…AC-17 trên thiết bị thật**; ép relay; đo độ trễ thu hồi và lan truyền policy; IT-07/IT-08 với subnet router + exit node; `node.expiry` trên client thật |
| Acceptance criteria | Toàn bộ AC-01…AC-20 có bằng chứng |
| Definition of Done | Báo cáo nghiệm thu MVP; mọi mã V thuộc MVP theo sổ §22.4 (gate đầu tiên ≤ G5) đã có kết quả đo |
| Risks | Không trực tiếp được trong môi trường test; khác biệt giữa các nền tảng client |
| Rollback strategy | Không thay đổi phá hủy; policy rollback theo version |
| **Go/No-Go G5 (MVP)** | 20/20 AC đạt hoặc có ngoại lệ được người dùng chấp nhận bằng văn bản — ngoại lệ chỉ áp dụng cho tiêu chí phụ thuộc môi trường: AC-15, phần Internet của AC-16 và ngưỡng thời gian của AC-17; các tiêu chí cách ly và bảo mật (AC-05…AC-07, AC-12…AC-14, AC-19, AC-20) và mọi IT có gate đầu tiên ≤ G5 (§5.2) **không** được miễn; không còn lỗi isolation; G4b đạt; mục G1(4) "pending" đã đóng hoặc có ngoại lệ bằng văn bản; ngưỡng đạt cho load/chaos test của Phase 6 được chốt theo A.1 #16 |

### Phase 6 — Production Hardening

| Thuộc tính | Nội dung |
|---|---|
| Objective | Đủ điều kiện vận hành cho khách hàng đầu tiên |
| Scope | Monitoring đầy đủ, backup offsite + PITR, diễn tập restore, xoay secret, vulnerability scan/SBOM/ký image, load test, diễn tập upgrade/rollback, incident response, hardening host (egress), pen test |
| Technical tasks | P6-T01…P6-T12 và P6-T02a, T04a, T07a, T07b |
| Dependencies | G5 |
| Files/modules expected | `infrastructure/monitoring/**`, `docs/operations/**`, pipeline CI supply chain, `tests/load/**` |
| Configuration requirements | Kho offsite; kênh cảnh báo; lịch xoay; quy tắc `DOCKER-USER` |
| Database migrations | `0025` usage_records (partition) + bảng tổng hợp |
| API changes | `usage/*` (gồm `tenants/{t}/billing` và `platform/usage`), `platform/backups`, `platform/security-events`, gỡ ban CrowdSec (endpoint chốt ở P6-T07a) |
| Security controls | Hash-chain audit; đẩy audit ra ngoài host; rà soát grant định kỳ; allow-list đích cho `mg-egress` |
| Unit tests | Hash-chain audit; tổng hợp usage; KEK rewrap |
| Integration tests | Backup/restore tự động; xoay KEK và API key; diễn tập upgrade N−1 → N |
| E2E tests | Chaos: kill instance/edge/PostgreSQL; bão hòa tenant A đo tenant B |
| Acceptance criteria | Diễn tập restore, upgrade và mất host đạt; báo cáo load test (10 → 100 tenant) có số liệu thật so với ngưỡng đã chốt ở G5; pen test không còn lỗi Nghiêm trọng/Cao |
| Definition of Done | Runbook đầy đủ; RPO/RTO **đo được** được ghi nhận |
| Risks | Hạ tầng một host không đạt mục tiêu sẵn sàng |
| Rollback strategy | Mỗi thay đổi hardening có đường lùi; bật từng phần |
| **Go/No-Go G6** | Quyết định **đủ điều kiện** go-live production kèm danh sách rủi ro tồn dư được chấp nhận; production **không** chạy trên host LAN staging (D-5, ADR-24) — môi trường production được dựng và go-live ở P7-T11/P7-T12 trên host chốt ở D-14; có ý kiến pháp lý đầy đủ bằng văn bản về R-01 (D-6) |

### Phase 7 — Scaling & Enterprise Features

| Thuộc tính | Nội dung |
|---|---|
| Objective | Mở rộng quy mô và tính năng enterprise theo nhu cầu đã đo |
| Scope | Dựng môi trường production và go-live ngay sau G6 (P7-T11, P7-T12), multi-host, regional placement, shared DERP **research**, tenant enterprise chuyên dụng, tích hợp danh tính nâng cao (onboarding tự phục vụ cho IdP của tenant, đối soát SCIM), Application ZTNA extensions, Usage/Billing, adapter cho Headscale 0.30, PostgreSQL sharding **nếu benchmark yêu cầu** |
| Technical tasks | P7-T01…P7-T10 và P7-T11, P7-T12 |
| Dependencies | G6; số liệu Phase 6 |
| Files/modules expected | Agent mTLS, `infrastructure/derp/`, `infrastructure/kubernetes/` (nếu chọn), module billing |
| Configuration requirements | mTLS giữa control plane và Agent; DERP map theo tenant |
| Database migrations | Theo tính năng (API token, SCIM, hóa đơn) |
| API changes | API token cho tự động hóa; relocation; relay regions ghi được |
| Security controls | Verify aggregator fail-closed; cô lập host cho enterprise; rà soát lại threat model |
| Unit tests | Theo từng tính năng (verify aggregator, placement liên host, billing) |
| Integration tests | Agent mTLS giữa hai host; adapter 0.30 với Headscale thật; aggregator fail-closed |
| E2E tests | Relocation tenant với client thật; scale validation tới 1.000 tenant (mô phỏng) |
| Acceptance criteria | Go/No-Go riêng cho từng tính năng (§10.5 cho shared DERP) |
| Definition of Done | Mỗi tính năng có ADR bổ sung + báo cáo kiểm chứng |
| Risks | Độ phức tạp vận hành; thay đổi API upstream |
| Rollback strategy | Feature flag; relocation ngược |
| **Go/No-Go G7** | Theo từng tính năng; **không** bật pooled DERP khi chưa có xác thực tenant-aware đã kiểm chứng |

### 22.3 Tiêu chí theo milestone

| Milestone | Điều kiện đạt |
|---|---|
| M0 — Architecture approved (G0) | Plan + ADR được duyệt; đủ 8 điều kiện của G0 (§19) |
| M1 — Infrastructure proven (G1) | AC-01…03, 08, 09, 10 (fixture), 11 (smoke), 13, 14, 16, 18, 20 (thủ công) + IT-09, IT-14 (kèm V-30) + số đo V-33 (sơ bộ) + các PoC V-01…V-05, V-16…V-19 và V-32 |
| M2 — Backend proven (G2) | AC-04, AC-05a, AC-06, AC-07, AC-12 (API) + isolation suite v1 + contract test |
| M3 — Orchestrator proven (G3) | Provision/suspend/resume/deprovision tự động với lưu lượng thật; tiêm lỗi; dual control; AC-19 |
| M4 — Portal proven (G4a + G4b) | E2E hai vai trò; enrollment và policy qua UI; AC-05b; AC-10, 11 mức functional |
| **M5 — MVP (G5)** | **AC-01…AC-20** có bằng chứng; AC mạng ở mức "network E2E verified"; mục G1(4) đã đóng hoặc có ngoại lệ bằng văn bản |
| M6 — Production ready (G6) | Diễn tập restore/upgrade/mất host; load test; pen test; runbook; rủi ro tồn dư được chấp nhận |
| M7 — Scale/Enterprise (G7) | Theo từng tính năng |
