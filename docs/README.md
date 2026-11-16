# MeshGuard ZTNA — Tài liệu thiết kế

Bộ tài liệu kiến trúc và kế hoạch triển khai của MeshGuard ZTNA (multi-tenant Zero Trust Mesh VPN trên Headscale + official Tailscale Client).

> **Trạng thái:** Kiến trúc **đã được chủ dự án phê duyệt** ngày 2026-11-16 (biên bản: `docs/planning/evidence/architecture-approval.md`); dự án đang ở **Phase 1** (Build Mode) — G0 đạt ngày 2026-11-16 (`docs/planning/evidence/G0.md`). Chưa có application code, container MeshGuard, migration hay thay đổi DNS; firewall của host staging đã bật (P1-T02). Theo chỉ đạo của chủ dự án, ngày 2026-11-16 đã: cài SSH key của dự án lên Proxmox và VPS, tạo user triển khai trên VPS, tạo 6 VM trên Proxmox và dừng 3 dự án cũ trên VPS để giải phóng cổng 80/443/3478 (nhật ký và lệnh hoàn tác: `docs/planning/evidence/infrastructure-bootstrap.md`; kết quả discovery: Appendix A.4). Thiết kế **chưa được coi là production-ready** cho tới khi qua kiểm thử và kiểm toán bảo mật (Rule XIX.20).
> **Ngày lập:** 2026-11-16 · **Phiên bản tham chiếu đã xác minh qua GitHub Releases API:** Headscale `v0.29.7` (2026-10-30) · Tailscale client `v1.104.7` (2026-11-12).
> **Bản sửa đổi:** Rev 3 (2026-11-16). *Rev 2* — bổ sung quyết định của người dùng: các endpoint cần public đi qua **VPS Public Gateway** (§15.3, §14.9, ADR-25); chuyển STUN sang responder dùng chung tại điểm vào công khai (§10, ADR-11). *Rev 3* — tích hợp kết quả **phản biện đối kháng** của 8 reviewer độc lập — là 8 agent AI phản biện tự động, mỗi agent một góc nhìn, không thay cho thẩm định của chuyên gia bên ngoài (186 phát hiện: 1 nghiêm trọng, 50 cao, 106 trung bình, 29 thấp); tổng hợp và cách xử lý ở Appendix D, bản ghi nguyên văn ở `docs/planning/review-findings.md`. File này là **bản master**; các file khác trong `docs/` được trích sinh từ đây bằng `tools/split_plan.py` — sửa ở master rồi sinh lại.

## Cách dùng

- **Bản master**: [planning/implementation-master-plan.md](planning/implementation-master-plan.md) — nguồn sự thật duy nhất, gồm đủ 25 mục và phụ lục.
- Các file còn lại được **trích sinh tự động** từ master. Quy trình sửa: sửa master → `python tools/split_plan.py` → commit cả master lẫn file sinh.
- Không ghi mật khẩu, private key hay token vào bất kỳ file nào trong thư mục này.

## Mục lục

| Tài liệu | Nội dung (mục của master) |
|---|---|
| [planning/implementation-master-plan.md](planning/implementation-master-plan.md) | Toàn bộ Implementation Master Plan |
| [architecture/repository-assessment.md](architecture/repository-assessment.md) | Repository Assessment — §2 |
| [architecture/compatibility-matrix.md](architecture/compatibility-matrix.md) | Compatibility Matrix — §2.7 |
| [architecture/system-design.md](architecture/system-design.md) | System Design — §3, §3.1, §3.5, §4 |
| [architecture/c4-diagrams.md](architecture/c4-diagrams.md) | C4 Diagrams — §3.2, §3.3, §3.4 |
| [architecture/multi-tenant-design.md](architecture/multi-tenant-design.md) | Multi-Tenant Design — §5, §5.1, §5.4, §5.5 |
| [architecture/database-design.md](architecture/database-design.md) | Database Design — §6 |
| [architecture/network-topology.md](architecture/network-topology.md) | Network Topology — §14.3, §14.6, §15.3 |
| [architecture/control-data-flows.md](architecture/control-data-flows.md) | Control & Data Flows — §9 |
| [architecture/relay-architecture.md](architecture/relay-architecture.md) | Relay Architecture (DERP/STUN) — §10 |
| [architecture/tenant-orchestrator.md](architecture/tenant-orchestrator.md) | Tenant Orchestrator — §11 |
| [architecture/portal-design.md](architecture/portal-design.md) | Portal Design (Super Admin / Tenant Admin) — §12 |
| [security/zero-trust-design.md](security/zero-trust-design.md) | Zero Trust Design — §7 |
| [security/threat-model.md](security/threat-model.md) | Threat Model — §18 |
| [security/permission-matrix.md](security/permission-matrix.md) | Authentication, Authorization & Permission Matrix — §8 |
| [security/tenant-isolation.md](security/tenant-isolation.md) | Tenant Isolation — §5.2, §5.3 |
| [api/api-contracts.md](api/api-contracts.md) | API Contracts — §13 |
| [deployment/ubuntu-server-inventory.md](deployment/ubuntu-server-inventory.md) | Server Inventory (Ubuntu host + VPS) — §A |
| [deployment/deployment-plan.md](deployment/deployment-plan.md) | Deployment Plan — §14 |
| [deployment/network-port-matrix.md](deployment/network-port-matrix.md) | Network Port Matrix & Connectivity Requirements — §15, §15.1, §15.2, §15.5 |
| [deployment/domain-and-tls-plan.md](deployment/domain-and-tls-plan.md) | Domain & TLS Plan — §15.4 |
| [deployment/rollback-plan.md](deployment/rollback-plan.md) | Rollback Plan — §11.4, §17.6, Rollback của §19 |
| [operations/monitoring-and-operations.md](operations/monitoring-and-operations.md) | Monitoring & Operations — §16 |
| [operations/backup-recovery-ha.md](operations/backup-recovery-ha.md) | Backup, Recovery & High Availability — §17 |
| [planning/milestones.md](planning/milestones.md) | Roadmap & Milestones — §19, §22.3 |
| [planning/task-breakdown.md](planning/task-breakdown.md) | Task Breakdown — §20 |
| [planning/dependency-graph.md](planning/dependency-graph.md) | Dependency Graph — §21 |
| [planning/test-strategy.md](planning/test-strategy.md) | Test Strategy — §22, §22.1, §22.4 |
| [planning/acceptance-criteria.md](planning/acceptance-criteria.md) | MVP Acceptance Criteria — §22.2 |
| [planning/risks-and-technical-debt.md](planning/risks-and-technical-debt.md) | Risks & Technical Debt — §23 |
| [planning/build-mode-instructions.md](planning/build-mode-instructions.md) | Build Mode Execution Instructions — §25 |
| [planning/review-log.md](planning/review-log.md) | Review Log & Dispositions — §D |
| [adr/architecture-decision-records.md](adr/architecture-decision-records.md) | Architecture Decision Records — §24 |
| [planning/review-findings.md](planning/review-findings.md) | Bản ghi nguyên văn các phát hiện của vòng phản biện (không sinh từ master; tổng hợp và cách xử lý ở Appendix D) |
| [architecture/research-evidence.md](architecture/research-evidence.md) | Nhật ký bằng chứng nghiên cứu: 874 nhận định kèm trích dẫn và nguồn đã pin (không sinh từ master; P0-T08) |
| [planning/evidence/](planning/evidence/README.md) | Bằng chứng thực hiện: quy ước, biên bản phê duyệt kiến trúc, task bị chặn, sổ kết quả kiểm chứng, báo cáo gate (không sinh từ master) |

## Quy ước đọc tài liệu

**Nhãn bằng chứng** (bắt buộc cho mọi nhận định kỹ thuật):

| Nhãn | Ý nghĩa |
|---|---|
| **VERIFIED** | Đã đọc trực tiếp trong mã nguồn/tài liệu được trích dẫn (pin theo tag/commit) trong phiên nghiên cứu này. |
| **VERIFIED (agent)** | Biến thể của VERIFIED: nhận định do research agent chỉ-đọc báo cáo từ nguồn đã pin và có trích dẫn trong nhật ký bằng chứng, nhưng tác giả plan **chưa** tự đọc lại nguyên văn. Mọi nhãn VERIFIED ở §2.1–§2.4, §2.6 và §2.8 được hiểu theo nghĩa này, trừ dòng ghi rõ tác giả hoặc reviewer đã tự đối chiếu (§2.5, PL-15, RT-02a, RT-15, GW-01…GW-04, §10.1). Nguồn đọc qua công cụ tóm lược (`[DOC:tailscale.com/docs]` — Appendix C) phải được đọc lại nguyên văn ở P0-T08; không đọc lại được thì hạ xuống REQUIRES VALIDATION. |
| **ASSUMED** | Suy luận kỹ thuật hợp lý, chưa có nguồn khẳng định trực tiếp. |
| **REQUIRES VALIDATION** | Không thể kết luận bằng cách đọc; phải kiểm thử thực tế trong môi trường của ta (ghi rõ phép thử), hoặc là tuyên bố của bên thứ ba chưa đối chiếu được với upstream. |
| **UNSUPPORTED** | Nguồn cho thấy tính năng không tồn tại/không được hỗ trợ, hoặc mâu thuẫn với giả định phổ biến. |

**Ký hiệu nguồn** (URL gốc ở Appendix C): `[HS:<path>]` = `juanfont/headscale@v0.29.7`; `[TS:<path>]` = `tailscale/tailscale@v1.104.7`; `[R1:<path>]` = `OLife97/headscale-stack-crowdsec@1afd96c`; `[R2:<path>]` = `fzhzyh/headscale-admin@0a4ca5e`; `[R3:<path>]` = `XavierAlpha/derper@e721396`; `[R4:<path>]` = `OwnDing/headscale-saas@25778c3`; `[DOC:<site>]` = tài liệu chính thức khác.

**Placeholder tên miền và tham số path.** `<domain>` = domain đã đăng ký của nền tảng (D-1); `<mesh_domain>` = `mesh.<domain>` — hostname control của tenant là `<slug>.<mesh_domain>` (ở §15 và ADR-09 có chỗ viết khai triển `*.mesh.<domain>`, cùng nghĩa); `<tailnet_suffix>` = hậu tố MagicDNS, mặc định `tail.<domain>` — `base_domain` của tenant là `<slug>.<tailnet_suffix>`. Trong path API, `{tenantId}` là tham số tenant của mọi route phạm vi tenant; `{t}` là cách viết tắt của `{tenantId}` trong các bảng, và `{id}` trong `/platform/tenants/{id}` cũng chính là `tenantId`.

**Tham chiếu đề bài.** `Rule XIX.n` (có chỗ viết gọn `Rule XIX`) = quy tắc thứ n ở mục XIX của đề bài — task brief người dùng cung cấp ở Plan Mode; "§2.1 đề bài" = mục 2.1 của chính đề bài đó. Đề bài không nằm trong repo; mọi số `§` không kèm chữ "đề bài" đều chỉ mục của bản master này.

**Thuật ngữ.** *Tenant* = một doanh nghiệp khách hàng. *Instance* = một tiến trình Headscale (một tailnet). *Edge* = Caddy + CrowdSec dùng chung. *Management Plane* = API/Worker/Agent/Portal/PostgreSQL. *Host Agent* = thành phần duy nhất được chạm vào Docker trên một host.
