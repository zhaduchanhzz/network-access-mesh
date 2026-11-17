# System Design

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §3 (phần mở đầu), §3.1, §3.5, §4. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 3. Architecture Overview

### 3.1 Năm mặt phẳng độc lập

| Mặt phẳng | Thành phần | Trách nhiệm | **Không** làm |
|---|---|---|---|
| **SaaS Management Plane** | Portal (Super Admin + Tenant Admin), SaaS Backend API, Worker, Host Agent, PostgreSQL, IdP | IAM, Tenant Registry, Orchestrator, Headscale Adapter, device/policy/relay/infra management, monitoring, usage, audit | Không chuyển tiếp lưu lượng WireGuard; không giữ private key của node |
| **Headscale Control Plane** | Mỗi tenant một Headscale instance (upstream, không sửa) | Đăng ký node, định danh node, public key, netmap, địa chỉ, DNS config, policy, route, điều phối, phân phối DERP map | Không mang dữ liệu ứng dụng; không biết về tenant khác |
| **Tailscale Data Plane** | Official Tailscale Client trên thiết bị | Mã hóa WireGuard, P2P trực tiếp, NAT traversal, DERP fallback, routing, DNS | Không đi qua Management Plane |
| **Relay Plane** | Embedded DERP theo tenant + STUN dùng chung `stund` (MVP); derper độc lập/vùng (tương lai) | Relay gói đã mã hóa khi không có đường trực tiếp; hỗ trợ NAT discovery | Không giải mã; không định tuyến theo tenant |
| **Security Plane** | OIDC/MFA tại IdP, RBAC platform + tenant, Grants, device identity, key lifecycle, audit, phân đoạn mạng, SecretStore, edge protection | Xuyên suốt bốn mặt phẳng trên | — |

### 3.5 Single points of failure đã biết (Rule XIX.18)

| SPOF | Ảnh hưởng | Xử lý ở MVP | Hướng loại bỏ |
|---|---|---|---|
| Host duy nhất | Toàn bộ control plane, relay, portal | Backup cục bộ đã mã hóa (P2-T03a, P3-T11) + runbook dựng lại (P1-T19); backup offsite chỉ có từ Phase 6 (P6-T03/P6-T04, trước G6) | Multi-host (Phase 7) |
| VPS Public Gateway | Mọi truy cập từ Internet (control, relay, Portal, STUN) | Gateway không có state ⇒ dựng lại nhanh từ repo; giám sát từ ngoài | Gateway thứ hai ở IP khác; hoặc chuyển tenant runtime lên host có IP công khai (Path C) |
| Tunnel VPS ↔ host LAN và đường truyền Internet của LAN | Như trên; ngoài ra toàn bộ lưu lượng control + relay đi qua uplink của LAN | Keepalive + tự nối lại; cảnh báo khi tunnel rớt | Path C / multi-host |
| Edge (Caddy) | Control + relay + portal của mọi tenant | Restart tự động; cấu hình tránh reload gây rớt stream | Nhiều edge + phân tán theo host |
| Headscale của từng tenant | Control + relay của tenant đó | Restart tự động; restore nhanh | Warm standby bằng restore (không active-active) |
| Một relay mỗi tenant | Kết nối phải relay của tenant đó | Chấp nhận (HS-17) | Thêm region (Phase 7) |
| PostgreSQL | Portal/API (không ảnh hưởng client đang chạy) | Backup; PITR ở Phase 6 | Replica + failover |
| IdP | Đăng nhập Portal; enrollment mới | Session đang mở vẫn dùng được tới khi hết hạn | IdP HA hoặc IdP của tenant |
| Một địa chỉ IP công khai | DDoS/chặn IP ảnh hưởng mọi tenant | Giới hạn tốc độ tại API (ở edge từ P6-T07); giám sát | Nhiều IP/vùng |
| Chứng chỉ wildcard + tài khoản ACME + DNS provider/registrar | Hết hạn, bị thu hồi hoặc mất quyền DNS ⇒ client của **mọi** tenant không đăng nhập/relay được (client kiểm chứng chỉ chặt — CL-02) | Theo dõi hạn chứng chỉ; persist + backup volume ACME; token của edge chỉ trên zone ủy quyền ACME (§15.4); khóa registrar | Tài khoản ACME/DNS dự phòng; chứng chỉ theo cụm tenant |
| KEK (keyring file trên host: `kek-app`, `kek-ops`) | Mất ⇒ không giải mã được SecretStore; lộ ⇒ lộ secret của mọi tenant | Hai bản offline + diễn tập nạp lại (P2-T04a) | KMS/OpenBao (Phase 7) |
| Worker / Host Agent (mỗi loại một tiến trình) | Không provision, backup, reconcile, xoay key được; client đang chạy không bị ảnh hưởng | Restart tự động; job idempotent tiếp tục sau khi lên lại; cảnh báo độ trễ hàng đợi | Worker nhân bản; Agent mỗi host |
| Docker daemon | Restart daemon ảnh hưởng mọi container trên host | `live-restore`; nâng cấp trong cửa sổ bảo trì | Multi-host |
| STUN dùng chung (`stund`) | Client không khám phá được endpoint ⇒ kết nối mới rơi về relay | Stateless, restart tự động; giám sát bằng prober | STUN ở IP thứ hai |

## 4. Component Architecture

### 4.1 Thành phần và ranh giới

| Thành phần | Trách nhiệm | State | Phơi ra ngoài | Đặc quyền |
|---|---|---|---|---|
| **edge** (Caddy tự build, pin version) | TLS 443, định tuyến theo hostname, allow-list path cho Headscale, listener admin nội bộ (`/api/v1/*` của instance), listener metrics nội bộ (`/metrics`), `/generate_204`, bouncer CrowdSec | Chứng chỉ ACME (volume) | TCP 80/443 | Thành viên của mọi network tenant; **không** có Docker socket |
| **crowdsec** | Phân tích JSON access log của edge, quyết định ban (đã tinh chỉnh) | DB quyết định + cấu hình (volume) | Không | — |
| **web** | SPA React tĩnh (hai origin `app.` và `admin.`) | Không | Qua edge | — |
| **api** (`meshguard api`) | REST `/api/v1`, session, authz, enqueue job | Không (stateless) | Qua edge | Không Docker, không filesystem tenant |
| **worker** (`meshguard worker`) | Orchestrator, inventory sync, xoay key, lịch backup, reconcile, usage | Không | Không | Gọi Agent; không Docker |
| **agent** (`meshguard agent`) | Thực thi hạ tầng theo spec đã kiểm tra (§11.5) | Không | Không (Unix socket) | **Docker socket + `/opt/meshguard/tenants` + `/opt/meshguard/backups/tenants`** — tương đương root |
| **postgres** | Dữ liệu Management Plane + hàng đợi job | Volume | Không | — |
| **idp** | OIDC issuer platform + issuer theo tenant, MFA | DB riêng | Qua edge | — |
| **monitoring** (Prometheus, Alertmanager, Grafana, log store, collector) | Metrics, log, cảnh báo | Volume | Grafana qua edge (origin admin) | Collector đọc log container |
| **headscale-<tenant>** (upstream, pin digest) | Control plane + embedded DERP của **một** tenant | `data/` của tenant | Chỉ qua edge (443); **không publish cổng nào** | `cap_drop: ALL`, read-only, UID riêng, network `internal` |
| **stund** (tự build từ tag Tailscale đã pin) | STUN responder dùng chung cho mọi tenant (UDP 3478) | Không | UDP 3478 tại điểm vào công khai | Host network; không có secret; HTTP debug chỉ bind loopback |
| **VPS Public Gateway** (`l4proxy` + `stund` + tunnel WireGuard) | Điểm vào từ Internet: chuyển tiếp TCP 80/443 ở tầng 4 về edge trên host LAN (PROXY protocol v2); trả lời STUN | Không (stateless) | TCP 80/443, UDP 3478, UDP tunnel | **Không** có khóa TLS, token DNS, dữ liệu tenant hay Docker socket của nền tảng |

### 4.2 Module của SaaS Backend (Go modular monolith — một codebase, ba chế độ chạy)

| Module (`internal/…`) | Trách nhiệm | Interface chính |
|---|---|---|
| `identity` | OIDC RP đa issuer, session, CSRF, step-up, principal | `Authenticator`, `SessionStore` |
| `authz` | Role → permission, kiểm tra theo tenant, support grant | `Authorizer.Require(ctx, tenantID, perm)` |
| `tenants` | Tenant Registry, settings, vòng đời (yêu cầu), membership (đọc) và lời mời (P3-T05a) | `TenantService` |
| `members` | Quản trị membership của tenant: đổi role, khóa/offboard (expire node và pre-auth key qua adapter, vô hiệu user qua `idp`), mời user qua lời mời của `tenants`; groups (P4-T09) | `MemberService` |
| `platform` | Host, instance, relay region, system settings | `PlatformService` |
| `headscale` | Adapter REST có version, `Registry.ForTenant`, ánh xạ lỗi | §13.4 |
| `provisioning` | State machine, compensation, `InfrastructureDriver`, agent client | §11 |
| `devices` | Inventory sync/cache, rename/tag/expire/delete | `DeviceService` |
| `enrollment` | Web-auth claim, pre-auth key, quota | `EnrollmentService` |
| `policies` | Mô hình, render, lint, vòng đời, drift | `PolicyService` |
| `network` | DNS settings/records, routes, resource catalog | `NetworkService` |
| `relay` | Relay region/assignment, probe | `RelayService` |
| `usage` | Thu thập usage, plan/quota | `UsageService`, `QuotaChecker` |
| `audit` | Ghi/đọc `audit_events`, `security_events` | `AuditLogger` |
| `secrets` | SecretStore (envelope encryption) | §7.6 |
| `monitoring` | Health tổng hợp, truy vấn metrics có ép nhãn tenant | `HealthService` |
| `store` | Repository PostgreSQL, `WithTenantTx`, RLS | `TenantStore` |
| `jobs` | Đăng ký worker, lịch, idempotency | §13.5 |
| `httpapi` | Handler sinh từ OpenAPI, middleware | — |
| `idp` | Driver IdP (`keycloak`, `external`): tạo/vô hiệu issuer, mời/vô hiệu user, kiểm discovery qua HTTP client đã hardening | `IdPDriver` (§8.2) |
| `notifications` | Ghi `notification_outbox` cùng transaction với sự kiện; gửi email/in-portal bằng job `notification.send` | `Notifier` |
| `config` | Nạp cấu hình runtime (file, secret dạng file), đọc/ghi `system_settings`, đọc `tenants.settings` có kiểu (`TenantSettings` — §13.3) | `ConfigProvider` |

Lý do chọn **modular monolith** thay vì microservices: một nhóm nhỏ, một DB, giao dịch nhất quán giữa registry và job (enqueue trong transaction), ranh giới module được ép bằng lint; đặc quyền hạ tầng vẫn được tách tiến trình (Agent). Đánh đổi: scale theo tiến trình chứ chưa theo module — chấp nhận tới mức 1.000 tenant, xem lại sau scale test.

Ngoài ba chế độ chạy chính (`api`, `worker`, `agent`), codebase còn build **prober** (`apps/probe`, §14.4): một tiến trình nhỏ không có secret, không có quyền ghi DB, chỉ thực hiện phép đo từ "phía ngoài" (STUN, HTTPS theo hostname tenant, allow-list của edge) theo yêu cầu của Worker và cho Prometheus. Tên module dùng trong lint kiến trúc (§13.6) là tên ở bảng này. Đối chiếu với danh sách module của đề bài: `usage` hiện thực module *billing* (plan, quota, usage) cho tới khi có hóa đơn ở P7-T08; `config` hiện thực module *configuration*.

### 4.3 Technology stack (ADR-04, ADR-21) — phiên bản pin lại ở Phase 0

| Lớp | Lựa chọn mặc định | Lý do | Phương án thay thế |
|---|---|---|---|
| Ngôn ngữ backend | Go (bản stable hiện hành) | Yêu cầu đề bài; một binary tĩnh | — |
| HTTP + contract | `net/http` ServeMux + `oapi-codegen` strict server | Contract-first, không thêm router | chi; ogen |
| Data access | `pgx` v5 + `sqlc` | SQL tường minh, type-safe, hợp RLS | pgx thuần |
| Migrations | `goose` (SQL nhúng) | Xử lý DDL RLS như SQL thường | golang-migrate |
| Background jobs | River (PostgreSQL) | Enqueue cùng transaction; unique job; backoff | Outbox + `SKIP LOCKED` tự viết (dự phòng vì River còn pre-1.0) |
| OIDC RP / session | `go-oidc` + `x/oauth2`; bảng session riêng trong PostgreSQL | Kiểm soát hash, thu hồi, step-up | `scs` |
| Authorization | Bảng role/permission tự quản + RLS | Đơn giản, kiểm toán được | Casbin; OpenFGA khi cần chia sẻ theo tài nguyên |
| Logging / telemetry | `log/slog` JSON + Prometheus client; OpenTelemetry ở Phase 6 | Ít phụ thuộc ở MVP | — |
| Headscale client | Client REST mỏng tự viết + contract test | API v1 sẽ bị thay ở 0.30; module Headscale quá nặng để import | Sinh từ Swagger |
| Điều khiển Docker | Agent gọi CLI `docker compose -p …`; `moby/moby/client` chỉ để inspect | Minh bạch, ít phụ thuộc | Compose Go SDK |
| Frontend | React + TypeScript + Vite; React Router (data mode, SPA tĩnh); TanStack Query; `openapi-typescript` + `openapi-fetch` | Yêu cầu đề bài; type-safe end-to-end | — |
| UI | Tailwind + shadcn trên Radix (hoặc React Aria) | Accessible, dark/light theme | Ant Design (nếu tái dùng nhiều component của R2) |
| i18n | `react-i18next`, catalog `vi` + `en` | Rủi ro tích hợp thấp | Lingui |
| Topology (Phase 4+) | `@xyflow/react` | MIT | Bảng + SVG |
| Test | Go test + testcontainers; Vitest; Playwright | — | — |
| Edge | Caddy build bằng xcaddy (module DNS provider + CrowdSec bouncer + module rate-limit [ứng viên: `mholt/caddy-ratelimit` — ASSUMED, chưa đọc source; tên và commit chốt ở P0-T03], pin version và review mã nguồn) | Wildcard DNS-01; shared edge; giới hạn tốc độ/kết nối theo hostname (EG-11) | — |
| IdP | Keycloak (realm theo tenant) — xem §8.2 | Issuer theo tenant, Admin API, MFA | Zitadel; IdP của tenant |
| Database | PostgreSQL 18.x | `uuidv7()`, RLS, partition | — |
| Secrets | Envelope encryption + file secret | Không thêm dịch vụ ở MVP | OpenBao (Phase 7) |
| Backup | `VACUUM INTO` + `age` + `restic`; pgBackRest (Phase 6) | An toàn với SQLite đang chạy | `.backup` |
| Observability | Prometheus, Alertmanager, Grafana, Loki, Alloy, cAdvisor, node_exporter, blackbox_exporter + STUN/DERP probe tự viết | — | — |
| Supply chain | Syft, Grype, cosign; pin digest + commit SHA | ST-09 | Trivy (pin chặt) |
| Host | Ubuntu LTS + Docker Engine **rootful** + Compose v5 | Rootless mặc định không giữ IP nguồn ở cổng publish (ST-10); xem lại ở Phase 6 | — |

### 4.4 Source structure (điều chỉnh từ đề xuất của đề bài)

```text
meshguard/
├── apps/
│   ├── api/            # main.go: meshguard api; cùng binary có nhóm lệnh quản trị chỉ chạy trên host: meshguard admin <lệnh> (adopt-instance, bootstrap-super-admin, seed-membership — P2-T11, P2-T11a)
│   ├── worker/         # main.go: meshguard worker
│   ├── agent/          # main.go: meshguard agent   (BỔ SUNG: thành phần duy nhất có Docker socket)
│   ├── probe/          # prober: STUN/HTTPS/allow-list từ phía ngoài (không secret)
│   └── web/            # React SPA (app + admin)
├── internal/           # identity, idp, authz, tenants, members, platform, devices, enrollment, headscale, policies, network,
│                       # provisioning (driver/compose, agentspec — lớp kiểm tra của Agent, reconcile), agentclient, relay, audit, usage, secrets, monitoring,
│                       # notifications, store, jobs, httpapi, config
├── api/
│   ├── openapi.yaml    # contract của SaaS API (nguồn sự thật)
│   └── agent/v1/agent.proto
├── database/
│   ├── migrations/     # SQL đánh số (goose)
│   ├── queries/        # sqlc
│   └── seeds/          # role, permission, plan mặc định
├── infrastructure/
│   ├── docker/         # Dockerfile: api/worker/agent/web/edge
│   ├── compose/        # compose.edge.yaml (project riêng mg-edge), compose.core.yaml, compose.monitoring.yaml, compose.idp.yaml
│   ├── caddy/          # Caddyfile, xcaddy build manifest
│   ├── crowdsec/       # acquis, profiles, allowlists
│   ├── headscale/templates/   # config.yaml.tmpl, compose.tenant.yaml.tmpl, bootstrap-policy.hujson, test-allow-intra.hujson
│   ├── gateway/        # VPS Public Gateway: compose mg-gateway, l4proxy, Dockerfile stund, mẫu tunnel (không khóa)
│   ├── derp/           # (Phase 7) Dockerfile derper từ tag upstream
│   ├── idp/            # realm template
│   ├── monitoring/     # prometheus, alert rules, dashboards, alloy
│   └── kubernetes/     # (tương lai, để trống có README)
├── tests/
│   ├── integration/    # adapter contract test với Headscale thật (testcontainers)
│   ├── isolation/      # IT-01…IT-14 (gồm công cụ derpprobe)
│   ├── e2e/            # Playwright + harness client Tailscale (container cho CI, thiết bị thật trong lab)
│   ├── security/       # authz matrix, secret scan, edge conformance (allow-list, fuzz nhãn host)
│   └── load/
├── docs/               # theo Appendix B
├── compose.yaml        # stack dev/CI (P2-T01a): postgres, IdP, edge, 2 Headscale, client container
├── .env.example        # KHÔNG chứa secret thật
├── Makefile
└── README.md
```

Khác biệt so với đề xuất gốc và lý do: (1) thêm `apps/agent` để tách đặc quyền Docker; (2) thêm `api/` cho contract; (3) unit test Go đặt cạnh mã nguồn (`*_test.go`) theo thông lệ, nên không có `tests/unit`; (4) thêm `tests/isolation` vì cách ly tenant là tiêu chí số một; (5) `internal/` bổ sung `authz`, `enrollment`, `network`, `secrets`, `store`, `jobs`, `httpapi`; (6) sau vòng phản biện thêm `apps/probe`, `internal/idp`, `internal/notifications`, `internal/members`.
