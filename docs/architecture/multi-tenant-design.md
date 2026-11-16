# Multi-Tenant Design

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §5 (phần mở đầu), §5.1, §5.4, §5.5. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 5. Multi-Tenant Isolation Design

### 5.1 Mô hình mặc định (ADR-01): One Tenant = One Tailnet = One Headscale Instance

| Thành phần của mỗi tenant | Hiện thực | Vì sao không dùng chung |
|---|---|---|
| Headscale instance | 1 container, compose project `mg-t-<slug>`, UID riêng | Headscale chỉ hiện thực một tailnet/instance (HS-01) |
| SQLite | `tenants/<instance_id>/data/db.sqlite` | Node registry, khóa, route, policy là state của **một** tailnet |
| Server keys | `noise_private.key`, `derp_server_private.key` riêng | Định danh control plane và relay của tenant |
| API credentials | 1 API key/instance trong SecretStore | Key của Headscale là toàn quyền, không có scope (RT-16) |
| Policy | Policy riêng (mode `database`), lịch sử ở `policy_versions` | Một policy chi phối cả tailnet |
| DNS | `base_domain`, nameserver, extra records riêng | MagicDNS namespace theo tailnet |
| DERP configuration | Embedded DERP riêng + `verify_clients` (STUN dùng chung — stateless, không mang danh tính tenant) | Relay chỉ nhận node của tenant |
| Mesh network | Netmap riêng; cùng dải `100.64.0.0/10` nhưng không liên thông | Không có peer discovery chéo |

**Không dùng nhiều Headscale user trong một tailnet để thay thế tenant isolation** (Rule XIX.14): user trong cùng instance dùng chung netmap namespace, một policy, một API key toàn quyền, một relay, một DNS base domain — không có ranh giới quản trị hay ranh giới khóa nào giữa họ.

### 5.4 Tenant mapping (Central Tenant Registry)

| Trường yêu cầu | Vị trí trong schema (§6.3) |
|---|---|
| `tenant_id`, `tenant_name`, `tenant_status`, `created_at`, `updated_at` | `tenants.id`, `.name`, `.status`, `.created_at`, `.updated_at` |
| `deployment_region` | `tenants.deployment_region` (mong muốn) · `hosts.region` (thực tế) |
| `headscale_instance_id` | `tenant_instances.id` |
| `headscale_endpoint` | `tenant_instances.server_url` (public) · `.internal_address` (nội bộ) |
| `secret_reference` | `tenant_instances.api_key_secret_ref` |
| `relay_assignment` | `relay_assignments` → `relay_regions` |
| `subscription_plan` | `subscriptions` → `subscription_plans` |

Đường đi của **mọi** lời gọi Headscale API: session → `tenantId` từ path → authz (§8.8) → `Registry.ForTenant(tenantID)` → địa chỉ nội bộ + API key từ registry/SecretStore → REST qua listener nội bộ của edge → instance của đúng tenant. Không có đường nào cho phép client chọn instance.

### 5.5 Các mức tăng trưởng (mức **kiểm thử dự kiến**, không phải hiệu năng đã chứng minh)

| Mức | Hình thái | Việc phải đo/kiểm ở mức này | Thay đổi kiến trúc cần trước khi lên mức kế |
|---|---|---|---|
| **2 tenant — POC** | 1 host, provisioning bán thủ công bằng template | IT-04 (restart), IT-05, IT-09, IT-10 (quyền file/UID), IT-13 (pre-auth key), IT-14 ở mức thủ công theo bảng truy vết §5.2 — các IT còn lại theo phase; hai gate của §10.1; RSS/CPU nhàn rỗi của một instance (P1-T20) | Orchestrator tự động (Phase 3) |
| **10 tenant — MVP** | 1 host, orchestrator đầy đủ | Thời gian provisioning; chi phí polling (mỗi lời gọi API tốn một lần bcrypt ở instance — RT-15); số Docker network và thời gian attach edge; tác động reload edge | Dải subnet tenant đủ lớn (`hosts.tenant_net_pool`); hardening; PITR; offsite backup |
| **100 tenant — Early Production** | 1–3 host; Agent theo host | Mật độ instance/host theo RAM/CPU đo được; cửa sổ backup; khối lượng log; giới hạn ACME; hành vi edge với ~100 network | Multi-host placement; tách PostgreSQL khỏi host tenant |
| **1.000 tenant — Scale Validation** | Nhiều host/vùng | Điều phối upgrade theo đợt; fleet Agent; chiến lược relay vùng; quyết định sharding PostgreSQL **dựa trên benchmark** | Tùy kết quả |

| Hạng mục đánh giá | Trạng thái hiểu biết | Cách đo |
|---|---|---|
| Memory overhead mỗi instance | **REQUIRES VALIDATION** (V-13) — upstream không công bố | `docker stats`/cAdvisor với 0, 10, 100 node |
| CPU / network-map workload | Upstream: mỗi thay đổi tính lại map cho mọi node; "100s of devices" nếu ít biến động (HS-23) | Client tổng hợp + tỉ lệ churn; theo dõi metrics `headscale_mapresponse_*` |
| Control connections | Mỗi node online giữ một long-poll qua edge | Số stream nâng cấp tại edge; giới hạn file descriptor |
| Persistent volume | SQLite + WAL + key; kích thước theo số node | `du` theo instance; tốc độ tăng |
| Provisioning speed | Chưa biết | Thời gian từng step trong `provisioning_job_steps` |
| Relay traffic | Phụ thuộc tỉ lệ kết nối không trực tiếp được | Bộ đếm network theo container + log edge (§10.6) |
| Database capacity (PostgreSQL) | Dữ liệu quản trị nhỏ — **ASSUMED** | Kích thước bảng, p95 truy vấn |
| Tenant placement | `hosts.capacity` + trọng số theo plan; trần instance/host cấu hình được; tenant enterprise có thể host riêng | Mô phỏng placement; diễn tập relocation |

**Không** công bố SLA hay giới hạn số node trước khi có số liệu đo (Rule XIX — không phỏng đoán).
