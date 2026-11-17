# Tham số theo môi trường

> **File viết tay.** Tham số **không bí mật** để render cấu hình của từng môi trường bằng các tool trong `tools/`
> (domain lấy từ biến môi trường `MG_BASE_DOMAIN` — D-1; secret không bao giờ nằm ở đây — §14.2).

| File | Tool | Ghi chú |
|---|---|---|
| `staging/edge.json` | `tools/render_edge.py` | Edge của host LAN staging (VM 104 `mg-staging`); `acme` = CA đang dùng |
| `staging/tenants/<slug>.json` | `tools/render_instance.py` | Tenant thử của Phase 1 (P1-T08, P1-T09) — dựng tay bằng `infrastructure/host/tenant-deploy.sh` |
| `ci/ci.env`, `ci/edge.json`, `ci/tenants/<slug>.json` | `tests/e2e/harness` (gọi `render_instance`, `render_edge`, `render_idp`) | Môi trường **ci** của stack dev/CI P2-T01a (`compose.yaml`): domain `.test`, subnet riêng của stack; `MG_E2E_EDGE_IPV4`, `MG_E2E_TENANT_*_CIDR`, `MG_E2E_*_IMAGE` do harness suy ra từ `ci.env` và `versions.lock` lúc chạy — render tay các file này cần đặt các biến đó. Kết quả chỉ "functional" |

Từ Phase 3, tham số tenant do Orchestrator cấp từ registry (§11.3); các file `tenants/` chỉ còn là bản ghi của
hai tenant dựng tay (`adopt-instance` — P2-T11).

Ví dụ: `MG_BASE_DOMAIN=<domain> python tools/render_edge.py infrastructure/environments/staging/edge.json <out>`
