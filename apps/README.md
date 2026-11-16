# apps

Ứng dụng của Management Plane (§4.2, §4.4 của master): `api`, `worker`, `agent` — một codebase Go, ba chế độ chạy — và `web` (React + TypeScript). Tạo ở P2-T01 (api, worker), P3-T01 (agent), P4-T01 (web). Chỉ `agent` được chạm Docker socket (ADR-05).

`web/` hiện chỉ chứa công cụ sinh type (pin trong `package-lock.json`) và `src/api/schema.d.ts` sinh từ `api/openapi.yaml` bằng `make api-gen` (P2-T02); SPA được dựng ở P4-T01.
