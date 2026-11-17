# Dependency Graph

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §21. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 21. Dependency Graph

### 21.1 Phụ thuộc giữa các phase và gate

```mermaid
flowchart LR
  APPROVE([Phê duyệt kiến trúc]) --> P0[Phase 0<br/>Research & Architecture]
  P0 -->|G0| P1[Phase 1<br/>Infrastructure Foundation]
  P0 -. sau G0 — task backend không chạm host .-> P2
  P1 -->|G1: DERP qua Caddy, STUN, allow-list, VPS gateway| P2[Phase 2<br/>SaaS Backend]
  P2 -->|G2: isolation + contract test| P3[Phase 3<br/>Tenant Orchestrator]
  P3 -->|G3: tiêm lỗi, lifecycle, dual control| P4[Phase 4<br/>Web Management]
  P4 -->|G4a: enrollment + policy + devices| P5[Phase 5<br/>Zero Trust & Relay]
  P4 -. G4b — phần UI còn lại .-> P5
  P5 -->|G5 = MVP: 20 AC| P6[Phase 6<br/>Production Hardening]
  P6 -->|G6: đủ điều kiện go-live| P7[Phase 7<br/>Scaling & Enterprise]
  P1 -. spike P1-T05a thất bại .-> ALT[Phương án lùi: PoC SNI passthrough DP-09, rồi derper theo tenant / sửa ADR-11]
  ALT --> P1
```

### 21.2 Chuỗi phụ thuộc chính ở mức task

Sơ đồ chỉ minh họa chuỗi chính; bảng ở §20 là nguồn sự thật (ở Build Mode, `make docs-check` phải báo lỗi nếu sơ đồ có cạnh không tồn tại trong bảng).

```mermaid
flowchart TD
  T01[P1-T01 discovery] --> T02[P1-T02 host prep] --> T03[P1-T03 layout]
  T03 --> T06[P1-T06 core compose]
  T04[P1-T04 image edge + stund] --> T06
  T06 --> T05[P1-T05 DNS + wildcard cert]
  T07[P1-T07 template instance] --> S05[P1-T05a spike DERP qua Caddy]
  T05 --> S05
  T06 --> T11[P1-T11 PoC non-root]
  T07 --> T11
  S05 --> T08[P1-T08 tenant A]
  T11 --> T08 --> T09[P1-T09 tenant B]
  T05 --> T10[P1-T10 edge config]
  T08 --> T10
  T09 --> T12a[P1-T12a policy thử]
  T10 --> T12[P1-T12 client thật]
  T12a --> T12
  T12 --> T13[P1-T13 restart độc lập] --> T19[P1-T19 dựng lại] --> T14[P1-T14 báo cáo G1] --> G1{{G1}}
  T10 --> X1[P1-T10a, P1-T12c] --> T14
  T12 --> X2[P1-T12b, P1-T12d, P1-T12e] --> T14
  T15[P1-T15 VPS hardening] --> T16[P1-T16 tunnel] --> T17[P1-T17 VPS gateway] --> T18[P1-T18 DNS public + test từ ngoài] --> T14
  T02 --> T16
  T10 --> T17
  T12 --> T18
  G0{{G0}} --> B01[P2-T01 Go module + CI] --> B02[P2-T02 OpenAPI]
  B01 --> B03[P2-T03 migrations + RLS] --> B04[P2-T04 SecretStore] --> B09[P2-T09 adapter] --> B10[P2-T10 contract test]
  T10 --> B09
  G0 --> B05[P2-T05 IdP] --> B06[P2-T06 identity]
  B03 --> B06
  B02 --> B07[P2-T07 authz]
  B03 --> B07
  B03 --> B12[P2-T12 jobs]
  B07 --> B11[P2-T11 registry + adopt]
  B09 --> B11 --> B13[P2-T13 devices]
  B12 --> B13
  B06 --> B15[P2-T15 isolation suite]
  B07 --> B15
  B13 --> B15 --> B16[P2-T16 triển khai + rà soát G2] --> G2{{G2}}
  B10 --> B10a[P2-T10a Headscale vá V-26] --> B16
  G1 --> B16
  G2 --> C01[P3-T01 agent] --> C02[P3-T02 compose driver] --> C03[P3-T03 agent ops] --> C05[P3-T05 state machine] --> C07[P3-T07 tiêm lỗi] --> C14[P3-T14 báo cáo G3] --> G3{{G3}}
  G2 --> C06[P3-T06 migrations 0009–0013] --> C05
  C06 --> C04[P3-T04 placement] --> C05
  C06 --> C4a[P3-T04a dual control]
  C06 --> C8a[P3-T08a lõi policy] --> C08[P3-T08 suspend/resume] --> C14
  C05 --> C08
  C05 --> C11[P3-T11 backup/restore]
  C4a --> C11
  C8a --> C11 --> C09[P3-T09 deprovision] --> C14
  C4a --> C09
  G3 --> D01[P4-T01 web shell] --> D04[P4-T04 devices UI]
  G3 --> D05[P4-T05 migrations 0014–0017] --> D06[P4-T06 enrollment] --> D07[P4-T07 web-auth gate]
  D05 --> D09[P4-T09 users/groups] --> D10[P4-T10 policies] --> D11[P4-T11 policy UI]
  D04 --> D10a[P4-T10a báo cáo G4a] --> G4a{{G4a}}
  D07 --> D10a
  D10 --> D10a
  D11 --> D14[P4-T14 E2E] --> G4b{{G4b}}
  G4a --> E02[P5-T02 lab mạng thật] --> E06[P5-T06 P2P + relay] --> E12[P5-T12 báo cáo MVP] --> G5{{G5 MVP}}
  E02 --> E07[P5-T07 đo thu hồi] --> E12
  E02 --> E2a[P5-T02a AC-20 từ Internet] --> E12
  G4b --> E12
```

### 21.3 Phụ thuộc bên ngoài (chặn tiến độ nếu thiếu)

| Phụ thuộc | Chặn | Người cung cấp |
|---|---|---|
| Domain + DNS provider có API | G0 và toàn bộ Phase 1 (không có ⇒ không qua G0; khi các điều kiện khác của G0 đã đủ, người dùng có thể chấp thuận bằng văn bản cho các task backend không chạm host chạy trước) | Người dùng |
| Thông số host + SSH key + cơ chế nâng quyền không dùng mật khẩu | P1-T01, P1-T02 | Người dùng |
| Git hosting, CI runner có Docker, container registry | P0-T07 ⇒ P0-T03, P0-T04, mọi task có "CI xanh" | Người dùng |
| Quyết định IdP (phương án cho ≥ 3 issuer tách biệt; đủ RAM nếu dùng Keycloak) | P2-T05 | Người dùng + kết quả discovery |
| Thiết bị thật (≥ 4, trên ≥ 2 hệ điều hành) + mạng thứ hai ngoài LAN | P1-T05a, P1-T12, P1-T18, P5-T02…T07 | Người dùng |
| VPS làm public gateway (đã có địa chỉ): **mật khẩu root đã đổi**, SSH key cho user triển khai, thông số VPS | P1-T15…P1-T18, phần Internet-facing của G1, AC-16 qua Internet | Người dùng |
| SMTP (thư mời, cảnh báo) | P3-T05b; lời mời Owner ở bước 16 của provisioning | Người dùng |
| Số người vận hành nền tảng (dual control cần ≥ 2; nếu chỉ 1 ⇒ chọn chế độ thay thế ở D-11) | P3-T04a, P3-T09, P3-T11 | Người dùng |
| Tư vấn pháp lý về việc dùng official client (R-01) | Ý kiến sơ bộ bằng văn bản: G2; đầy đủ: G6 (go-live thương mại) | Người dùng |
| Kho backup offsite; máy thứ hai cho diễn tập mất host | P6-T03, P6-T04, P6-T04a | Người dùng |
| Host production có IP công khai (D-14) | P7-T11, P7-T12 (go-live) | Người dùng |
