# Research Evidence Log

> **File viết tay — không sinh từ master** (Appendix B). Đầu ra phần 1 của task **P0-T08**: nhật ký bằng chứng của phiên nghiên cứu chỉ-đọc ngày 2026-11-16, chép nguyên từ kết quả của 16 research agent (mỗi agent một mảng nguồn, pin theo tag/commit). Nhận định và trích dẫn giữ nguyên tiếng Anh như agent đã ghi.
>
> **Cách dùng với master:** các bảng dữ kiện ở §2.1–§2.6 của [implementation-master-plan.md](../planning/implementation-master-plan.md) (HS-, PL-, ID-, DP-, RT-, CL-, EG-, ST-…) được tổng hợp từ các nhận định này. Nhãn **VERIFIED** của agent tương ứng với nhãn **VERIFIED (agent)** trong master: agent đã đọc nguồn đã pin và trích dẫn, nhưng tác giả plan chưa tự đọc lại nguyên văn. Phiên nghiên cứu **không** ghi ánh xạ một-một giữa ID dữ kiện của master và ID nhận định ở đây.
>
> **Phần 2 của P0-T08 (chưa làm):** đọc lại nguyên văn mọi dữ kiện §2.5–§2.6 được tham chiếu ngoài §2 và mọi dữ kiện `[DOC:tailscale.com/docs]` (ít nhất CL-15), ghi file + dòng cho từng ID dữ kiện; dữ kiện không đọc lại được bị hạ nhãn xuống REQUIRES VALIDATION và được thêm mã V ở §22.4.

## Tổng hợp

- Mảng nghiên cứu: **16** · nhận định: **874** (trong đó 409 được agent đánh dấu *critical* cho thiết kế) · nguồn đã đọc (không trùng): **1105**
- Nhãn: VERIFIED: 727 · UNSUPPORTED: 67 · REQUIRES_VALIDATION: 51 · ASSUMED: 29

| Mã | Mảng nghiên cứu | Nhận định | Nguồn đã đọc |
|---|---|---|---|
| [A](research-evidence/a.md) | AREA A - Repository OLife97/headscale-stack-crowdsec @ 1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4 (assessed against Headscale v0.29.7) | 45 | 71 |
| [B1](research-evidence/b1.md) | B1 - fzhzyh/headscale-admin: backend core and security (commit 0a4ca5e92c992bc4dff17d84f8c8c12856f1db69) | 51 | 69 |
| [B2](research-evidence/b2.md) | B2 - fzhzyh/headscale-admin @0a4ca5e: feature routes, ACL engine and Headscale v0.29 API notes, cross-checked against juanfont/headscale v0.29.7 (proto, swagger, generated gateway, source, docs, CHANGELOG) | 55 | 78 |
| [B3](research-evidence/b3.md) | B3 - fzhzyh/headscale-admin: frontend and deployment (MIT, commit 0a4ca5e92c992bc4dff17d84f8c8c12856f1db69) | 50 | 79 |
| [C1](research-evidence/c1.md) | C1 - XavierAlpha/derper image (commit e721396) and upstream Tailscale derper v1.104.7 | 50 | 56 |
| [D](research-evidence/d.md) | D - Repository OwnDing/headscale-saas (Headscale 'clustering' via cluster_id, shared PostgreSQL, binary-only image archive) assessed against upstream Headscale v0.26.1 and v0.29.7 | 41 | 43 |
| [E1](research-evidence/e1.md) | E1 - Headscale v0.29.7: scope, compatibility, requirements, database guidance, upgrade rules, scaling/HA statements, releases | 62 | 70 |
| [E2](research-evidence/e2.md) | E2 - Headscale v0.29.7: complete configuration reference and runtime network surface | 60 | 62 |
| [F](research-evidence/f.md) | F - Headscale v0.29.7: management API (gRPC + REST gateway) and CLI - complete inventory and semantics | 65 | 80 |
| [G1](research-evidence/g1.md) | G1 - Headscale v0.29.7: OIDC, users/identity and node registration behaviour | 50 | 35 |
| [G2](research-evidence/g2.md) | G2 - Headscale v0.29.7: policy engine (ACLs, grants, tests, SSH), tags, routes, exit nodes | 60 | 54 |
| [H2](research-evidence/h2.md) | H2 - Headscale v0.29.7 embedded DERP, DERP map, /verify endpoint, STUN, and several Headscale instances with relays on one host | 55 | 48 |
| [I1](research-evidence/i1.md) | I1 - Official Tailscale clients (v1.104.7) against self-hosted Headscale (v0.29.7): platforms, enrolment, TLS, lifecycle, unsupported features, licensing | 50 | 114 |
| [I2](research-evidence/i2.md) | I2 - Connectivity model and test methodology (control plane vs data plane, NAT traversal, DERP relay, WireGuard, failure/continuity) | 51 | 91 |
| [J1](research-evidence/j1.md) | J1 - Shared edge for many Headscale instances on one host: Caddy, CrowdSec, TLS/ACME, DNS, Docker networking | 56 | 70 |
| [J2](research-evidence/j2.md) | J2 - Technology stack validation for the management plane (versions, licences, maturity, fit) as of 2026-11-16 | 73 | 196 |
