# MeshGuard ZTNA

Nền tảng SaaS Zero Trust Mesh VPN tự lưu trữ, đa tenant: mỗi doanh nghiệp có một tailnet riêng do một Headscale instance riêng quản lý, Platform Super Admin quản trị tập trung, và official Tailscale client đảm nhiệm toàn bộ data plane.

> **Trạng thái:** Phase 0 — kiến trúc đã được duyệt (2026-11-16), gate G0 chưa đạt. Chưa có mã ứng dụng. Thiết kế **chưa** production-ready.

## Đọc gì trước

| Tài liệu | Dùng để |
|---|---|
| [ROADMAP.md](ROADMAP.md) | Lộ trình, trạng thái hiện tại, việc cần chủ dự án làm |
| [docs/README.md](docs/README.md) | Mục lục tài liệu kiến trúc, bảo mật, triển khai, kế hoạch |
| [Implementation Master Plan](docs/planning/implementation-master-plan.md) | Nguồn sự thật — mọi file khác trong `docs/` (trừ thư mục `evidence/` và nhật ký nghiên cứu) được sinh từ đây |
| [docs/planning/evidence/](docs/planning/evidence/README.md) | Bằng chứng thực hiện: gate, task bị chặn, sổ kiểm chứng, nhật ký hạ tầng |

## Cấu trúc repo (§4.4 của master)

| Đường dẫn | Nội dung | Có từ |
|---|---|---|
| `docs/` | Tài liệu; phần lớn sinh từ master | Phase 0 |
| `tools/` | `split_plan.py` (sinh `docs/`), `plan_lint.py`, `roadmap_check.py`, `docs_check.py` | Phase 0 |
| `apps/` | `api`, `worker`, `agent` (Go), `web` (React + TypeScript) | P2-T01, P3-T01, P4-T01 |
| `internal/` | Module Go của Management Plane | Phase 2 |
| `api/` | `openapi.yaml` (contract SaaS API), `agent/v1/agent.proto` | P2-T02, P3-T01 |
| `database/` | Migration, truy vấn `sqlc`, seed | P2-T03 |
| `infrastructure/` | Dockerfile, compose, Caddy, CrowdSec, template Headscale, gateway VPS, IdP, monitoring | Phase 1 |
| `tests/` | integration, isolation, e2e, security, load | Phase 1–6 |

## Lệnh

| Lệnh | Việc | Trên Windows không có `make` |
|---|---|---|
| `make docs` | Sinh lại `docs/` từ master | `python tools/split_plan.py` |
| `make docs-check` | Lint master, sinh lại `docs/`, kiểm ROADMAP, sơ đồ phụ thuộc §21.2, nhãn REQUIRES VALIDATION, link | `python tools/docs_check.py` |
| `make secret-scan` | Quét secret bằng gitleaks (rule riêng cho credential Headscale trong `.gitleaks.toml`) | `gitleaks git --config .gitleaks.toml --redact .` |

## Quy tắc bắt buộc (§25.1 của master)

- Không commit secret. Secret luôn ở dạng file nằm ngoài repo; `.env` chỉ chứa giá trị không bí mật (mẫu: `.env.example`).
- Sửa tài liệu kiến trúc ở master rồi chạy `make docs`; không sửa trực tiếp file được sinh ra.
- Image pin theo digest, action CI pin theo commit SHA, phiên bản ghi trong `versions.lock`.
- Không chạy script, compose hay image từ bốn repository tham khảo; không tải `h.tar`.
- Thao tác trên server chỉ qua SSH key; mỗi loại thay đổi trên host cần chủ dự án chấp thuận.
