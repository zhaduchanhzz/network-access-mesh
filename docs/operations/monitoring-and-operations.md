# Monitoring & Operations

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §16. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## 16. Monitoring & Operations

### 16.1 Nguồn dữ liệu (chỉ dữ liệu thật — không mock)

| Nguồn | Cung cấp | Nhãn / cách ly | Cách thu thập |
|---|---|---|---|
| Headscale `/metrics` của từng instance | `headscale_mapresponse_*`, `http_*` (không có metrics relay — §10.6) | `tenant_id`, `instance_id` gắn từ service discovery; job scrape đặt `honor_labels: false`, `metric_relabel_configs` loại mọi nhãn `tenant_id`/`instance_id` do target tự khai, `sample_limit`, `label_limit`, `body_size_limit`, `scrape_timeout`; cảnh báo khi target chạm trần | Prometheus HTTP SD đọc `GET /internal/prometheus/sd` của API → scrape qua listener metrics của edge |
| cAdvisor | CPU, RAM, network, restart theo container | **Không** mount Docker socket ⇒ chỉ có nhãn `id` (đường dẫn cgroup chứa container ID), không có tên/label container; nhãn tenant được ghép bằng join theo container ID với chuỗi `meshguard_instance_info{container_id, tenant_id, instance_id}` do API xuất (container ID do Agent báo trong `InstanceStatus`) — REQUIRES VALIDATION (V-31) | `mg-obs` |
| node_exporter | CPU, RAM, đĩa, mạng của host | — | `mg-obs` |
| Edge | Request theo hostname, mã trạng thái, thời lượng; access log JSON | `host` ⇒ ánh xạ tenant | Metrics Caddy + log → collector |
| API / Worker | Metrics HTTP, job (độ sâu hàng đợi, lỗi, thời lượng), độ trễ inventory sync theo tenant, số ngày còn lại của API key, tuổi bản backup gần nhất, số lần policy drift, drift của reconcile theo kind (`meshguard_reconcile_drift` — P3-T12), số lần giải mã SecretStore theo tenant và thành phần gọi | `tenant_id` | `/metrics` nội bộ |
| PostgreSQL exporter | Kết nối, lock, replication/WAL (Phase 6) | — | `mg-obs` |
| blackbox_exporter (trong service `prober`) | HTTPS `https://<slug>.<mesh_domain>/key?v=<capver>` (kỳ vọng 200 và body có `publicKey`; `<capver>` lấy từ `versions.lock`), hạn chứng chỉ, Portal, IdP | `tenant_id` | Probe định kỳ |
| Probe STUN/DERP trong service `prober` (P3-T03a) | STUN binding tới điểm vào công khai dùng chung (UDP 3478); `GET /derp/probe` theo từng hostname tenant | `tenant_id` (DERP) | blackbox_exporter không có UDP prober (ST-08) |
| VPS Public Gateway | Trạng thái tunnel, health backend của `l4proxy`, `stund`, tài nguyên VPS, lưu lượng so với quota băng thông | — | node_exporter trên VPS scrape qua tunnel + probe từ ngoài tới IP công khai |
| CrowdSec | Quyết định, alert | — | Metrics của engine |
| Bảng `backups`, `provisioning_jobs`, `tenant_instances` | Trạng thái backup, job, health gần nhất | `tenant_id` | Truy vấn qua API/exporter nội bộ |

### 16.2 Health checks

| Thành phần | Liveness | Readiness / kiểm tra sâu |
|---|---|---|
| Headscale instance | Healthcheck container `headscale health` | `GET /api/v1/health` qua adapter (key + DB); probe `/key?v=<capver>` qua listener public; so khớp fingerprint Noise key; probe STUN dùng chung |
| api | `/healthz` | `/readyz`: PostgreSQL, SecretStore (giải mã thử), listener admin của edge |
| worker | Heartbeat job | Độ trễ hàng đợi; kết nối Agent |
| agent | Ping qua Unix socket | Docker daemon phản hồi; quyền thư mục tenant |
| edge | Kiểm tra cấu hình + TCP 443 | Probe từng hostname tenant |
| postgres / idp | Lệnh chuẩn của image | Đăng nhập thử (synthetic) cho IdP |

### 16.3 Alerting (bộ rule khởi đầu)

| Nhóm | Điều kiện | Mức |
|---|---|---|
| Tenant control plane | Instance down / healthcheck fail / probe `/key?v=<capver>` fail > 2 phút / fingerprint Noise key khác giá trị đã ghi nhận | Critical |
| Relay | Probe STUN hoặc `/derp/probe` fail | High |
| Enrollment | Log Headscale của một tenant báo từ chối admission vì cache pending-auth đầy (mẫu log chốt ở P6-T02) | High |
| Public gateway | Tunnel VPS ↔ host LAN rớt; `l4proxy` báo backend down; IP công khai không tới được từ probe ngoài; lưu lượng VPS gần chạm quota | Critical/High |
| Bảo mật | Node đã thu hồi còn online; policy drift; chuỗi `403/404` chéo tenant bất thường; break-glass được dùng; đăng nhập console quản trị IdP, impersonation hay reset credential do actor ngoài tenant ở IdP do nền tảng host, event của realm bị tắt (P3-T15 — `security_events` `idp.*`); ghi audit thất bại; số lần giải mã SecretStore theo tenant/thành phần gọi tăng bất thường (chỉ phát hiện lạm dụng qua đường code của ứng dụng, không phát hiện kẻ đã đọc được file KEK) | Critical/High |
| Credential | API key của instance còn < 14 ngày (`meshguard_instance_api_key_expires_in_seconds < 14*86400` — P3-T10); chứng chỉ còn < 21 ngày | High |
| DNS | Bản ghi `*.mesh.<domain>`, `app.`, `auth.` hoặc CAA của zone sản xuất khác giá trị mong đợi (prober truy vấn resolver công cộng) | Critical |
| Backup | Quá hạn lịch backup của tenant/PostgreSQL; kiểm tra restore định kỳ thất bại | High |
| Orchestrator | Job `failed` hoặc `failed_resumable`; job tự kết thúc ở `rolled_back` do lỗi không phục hồi được (không tính trường hợp operator gọi `/rollback`); job bị `job.reaper` thu hồi (quá `timeout_at`); reconcile phát hiện network tenant ≠ 2 thành viên (`meshguard_reconcile_drift{kind="network_extra_member"}` > 0 — P3-T12) | High |
| Hạ tầng | Đĩa > 80%; `data/` của một instance vượt ngưỡng dung lượng theo plan; RAM host; PostgreSQL down; tỉ lệ 5xx ở edge (lưu ý: site wildcard đổi 502/503/504 thành 404 nên tenant ngừng **không** làm tăng 5xx — do probe `/key?v=<capver>` phát hiện); container restart loop | High/Critical |
| Đồng bộ | Độ trễ inventory sync vượt ngưỡng | Medium |

Bộ tối thiểu chạy từ Phase 3 (P3-T16): instance down / probe `/key?v=<capver>` fail, đĩa > 80%, chứng chỉ còn < 21 ngày, quá hạn backup; các rule còn lại của bảng thuộc P6-T01. Cảnh báo IdP của P3-T15 có trước P3-T16: mỗi đăng nhập console là `security_event` high + email `idp.console_login` (outbox → `notification.send` → SMTP) tới SA/PO + metric `meshguard_idp_console_logins_total` (rule Alertmanager: P3-T16/P6-T01).

Alertmanager có **inhibition cho cửa sổ boot của host** (dựa trên thời điểm boot do node_exporter báo): trong cửa sổ này các cảnh báo "instance down"/probe fail theo tenant được nén thành một cảnh báo "host vừa khởi động lại"; độ dài cửa sổ lấy từ số đo reboot thực tế (P1-T21), hết cửa sổ mà instance chưa lên thì cảnh báo Critical như thường.

### 16.4 Dashboards

**Platform Dashboard** (Grafana ở origin admin + trang Platform Health của Portal)

| Mục | Nguồn |
|---|---|
| Total tenants / theo trạng thái | `tenants` |
| Active Headscale instances, version theo instance | `tenant_instances` + health |
| Host capacity (CPU/RAM/đĩa, số instance/host) và tình trạng VPS gateway (tunnel, băng thông) | node_exporter, cAdvisor, `hosts` |
| Provisioning status (đang chạy, lỗi, thời lượng) | `provisioning_jobs` + metrics job |
| DERP infrastructure (probe theo tenant, lưu lượng xấp xỉ theo container) | Probe + cAdvisor |
| System incidents | Alertmanager + `security_events` |

**Tenant Dashboard** (do backend phục vụ; mọi truy vấn metrics được **ép nhãn tenant ở server**, không nhận PromQL từ client)

| Mục | Nguồn | Độ tin cậy |
|---|---|---|
| Total devices | `device_inventory_cache` | Theo lần sync gần nhất (`synced_at`) |
| Device online/offline | Trường `online`, `last_seen` do Headscale báo | Là góc nhìn của **control plane** tại thời điểm sync, không phải phép đo đường truyền |
| Device inventory | Cache | Như trên |
| Network policies (version đang áp dụng, drift) | `policy_applications` (hàng `applied` hiện hành) + `GetPolicy` | Đã xác minh bằng read-back |
| Route status (quảng bá / đã duyệt) | Cache node | Như trên |
| Relay metrics | Probe + xấp xỉ theo container | **Xấp xỉ**; ghi rõ không phải tổng lưu lượng VPN |
| Security events | `security_events`, `audit_events` | — |

### 16.5 Central logging & audit

- Mọi container log JSON ra stdout; collector gắn `service`, `tenant_id` (từ label container) và đẩy về log store; có bước **redaction** (mẫu `hskey-`, `Authorization`, cookie) trước khi lưu.
- User của tenant **không** truy cập log thô; họ xem `audit_events` của tenant mình qua API.
- `audit_events` là nguồn authoritative cho hành động quản trị; log chỉ phục vụ chẩn đoán. Bản sao audit được đẩy ra ngoài host (Phase 6) để chống xóa dấu vết khi host bị chiếm.

### 16.6 Vận hành

Runbook (Phase 6, `docs/operations/`): onboard/offboard tenant thủ công khi orchestrator lỗi; restart/relocate instance; restore tenant; restore PostgreSQL; xoay KEK/API key/token DNS; gỡ ban CrowdSec; nâng cấp Headscale theo đợt; nâng cấp/recreate edge (§17.6); policy lỗi chặn khởi động; ứng phó sự cố (phân loại, cô lập tenant bằng suspend hoặc quarantine instance nghi bị chiếm (§11.4), bảo toàn chứng cứ, thông báo tenant). Lịch định kỳ: diễn tập restore hằng tháng, rà soát support grant và tagged node hằng quý, cập nhật bản vá Headscale khi có bản phát hành (upstream không có kênh advisory — RT-12).
