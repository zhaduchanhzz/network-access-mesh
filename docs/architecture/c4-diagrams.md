# C4 Diagrams

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §3.2, §3.3, §3.4. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

### 3.2 C4 Level 1 — System Context

```mermaid
flowchart LR
  SA[Platform Super Admin / Operator / Support]
  TA[Tenant Owner / Admin / Operator]
  EU[End User + thiết bị chạy official Tailscale Client]
  IDP[(Identity Provider: issuer platform + issuer theo tenant)]
  DNS[(DNS provider + ACME CA)]
  RES[(Tài nguyên nội bộ của tenant sau subnet router)]
  subgraph MG[MeshGuard ZTNA Platform]
    MP[SaaS Management Plane]
    CP[Headscale Control Plane - mỗi tenant một instance]
    RP[Relay Plane - DERP theo tenant, STUN dùng chung]
  end
  SA -->|HTTPS admin origin| MP
  TA -->|HTTPS app origin| MP
  EU -->|HTTPS: Portal, enrollment| MP
  MP -->|OIDC| IDP
  MP -->|Headscale REST API, mạng nội bộ| CP
  EU -->|control: TLS 443 + Noise| CP
  EU -->|STUN UDP, DERP qua TLS 443| RP
  EU <-->|WireGuard P2P trực tiếp - KHÔNG qua nền tảng| EU
  EU -->|qua subnet router của tenant| RES
  MP -->|ACME DNS-01, bản ghi DNS| DNS
```

Phụ thuộc bên ngoài lúc chạy: IdP, DNS/ACME. **Không** phụ thuộc relay hay coordination server của Tailscale Inc. lúc chạy (`derp.urls: []`); official client vẫn có thể tự liên lạc một số host của Tailscale Inc. (log lúc khởi động, dò captive portal, DNS fallback — CL-16); chỉ phụ thuộc phần mềm client do Tailscale phát hành (xem rủi ro pháp lý ở §23).

### 3.3 C4 Level 2 — Containers (single-host MVP)

```mermaid
flowchart TB
  Internet((Internet / LAN))
  subgraph HOST[Ubuntu host trong LAN - Docker Engine]
    subgraph EDGEP[Compose project: mg-edge]
      EDGE[edge: Caddy + CrowdSec bouncer<br/>:80 :443 public · listener admin nội bộ · listener metrics nội bộ]
    end
    subgraph CORE[Compose project: mg-core]
      CS[crowdsec: LAPI + agent]
      WEB[web: SPA tĩnh]
      API[api: Go - REST /api/v1]
      WRK[worker: Go - jobs, orchestrator, sync]
      AGT[agent: Go - Docker socket + /opt/meshguard/tenants]
      PG[(postgres)]
      IDPC[idp]
      OBS[prometheus · alertmanager · grafana · log store]
    end
    subgraph TEN_A[Compose project: mg-t-A]
      HSA[headscale A<br/>SQLite A · keys A]
    end
    subgraph TEN_B[Compose project: mg-t-B]
      HSB[headscale B<br/>SQLite B · keys B]
    end
  end
  subgraph VPS[VPS Public Gateway - không giữ khóa TLS và không có dữ liệu tenant]
    L4[l4proxy: chuyển tiếp TCP 80/443 kèm PROXY protocol]
    STUN[stund: STUN dùng chung UDP 3478]
  end
  Internet -->|TCP 80/443| L4
  Internet -->|UDP 3478| STUN
  L4 -->|tunnel WireGuard site-to-site| EDGE
  EDGE --- CS
  EDGE --> WEB
  EDGE --> API
  EDGE --> IDPC
  EDGE -->|network mg-t-A: chỉ edge + headscale A| HSA
  EDGE -->|network mg-t-B: chỉ edge + headscale B| HSB
  API --> PG
  WRK --> PG
  API -->|Headscale REST qua listener admin của edge| EDGE
  WRK -->|Headscale REST qua listener admin của edge| EDGE
  WRK -->|gRPC qua Unix socket| AGT
  AGT -->|Docker API + file| TEN_A
  AGT -->|Docker API + file| TEN_B
  OBS -->|scrape /metrics qua listener metrics của edge| EDGE
```

Ghi chú: sơ đồ trên là chế độ **Internet-facing**. Ở chế độ **Local Development** không có VPS: client trong LAN vào thẳng edge (TCP 80/443) và `stund` chạy trên chính host LAN. Trong cả hai chế độ, container Headscale của tenant **không publish cổng nào**.

### 3.4 C4 Level 3 — Components của SaaS Backend (Go modular monolith)

```mermaid
flowchart LR
  subgraph HTTP[httpapi: router sinh từ OpenAPI + middleware]
    MW[session · CSRF · rate limit · request id · authz theo x-permission]
  end
  MW --> ID[identity]
  MW --> TN[tenants]
  MW --> MB[members: users · groups]
  MW --> PF[platform]
  MW --> DV[devices]
  MW --> EN[enrollment]
  MW --> PL[policies]
  MW --> NW[network: dns · routes · resources]
  MW --> RELAY[relay]
  MW --> US[usage]
  MW --> AU[audit]
  DV --> HA[headscale adapter: Registry.ForTenant]
  EN --> HA
  MB --> HA
  PL --> HA
  NW --> HA
  TN -->|enqueue job vòng đời| JOBS
  PV --> HA
  PV --> AC[agent client]
  HA --> SEC[secrets: SecretStore]
  PV --> SEC
  ID --> ST[(store: WithTenantTx + RLS)]
  TN --> ST
  DV --> ST
  PL --> ST
  AU --> ST
  JOBS[jobs: hàng đợi trên PostgreSQL] --> PV[provisioning: state machine + InfrastructureDriver]
  JOBS --> DV
  JOBS --> PL
```
