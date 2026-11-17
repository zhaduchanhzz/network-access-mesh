# apps

Ứng dụng của Management Plane (§4.2, §4.4 của master): `api`, `worker`, `agent` — một codebase Go, ba chế độ chạy — và `web` (React + TypeScript). Tạo ở P2-T01 (api, worker), P3-T01 (agent), P4-T01 (web). Chỉ `agent` được chạm Docker socket (ADR-05).

`agent/` (P3-T01): `meshguard-agent` — Host Agent, thành phần duy nhất có Docker socket (ADR-05). Chỉ nghe Unix socket (`/run/meshguard/agent.sock`, không TCP), xác thực mỗi lời gọi bằng `SO_PEERCRED` (UID của worker) **và** token Agent, kiểm mọi tham số qua `internal/provisioning/agentspec` (tập đóng, allowlist digest, kiểm label/meta trước khi đụng tài nguyên) rồi mới tới driver; P3-T01 chưa có driver (mọi thao tác hạ tầng trả `UNIMPLEMENTED` sau khi đã kiểm), compose driver ở P3-T02. Client của worker: `internal/agentclient`. Bằng chứng: [`docs/planning/evidence/P3-T01.md`](../docs/planning/evidence/P3-T01.md).

`backup/` (P2-T03a, P2-T05b): `meshguard-backup` — tiến trình của image `backup` (project compose `mg-backup`: `pg-backup`, `idp-backup`, `edge-backup`), không phải chế độ chạy của Management Plane: lịch riêng, mã hóa tới recovery key bằng `age` trong lúc dump, file trạng thái cho cảnh báo quá hạn. Chỉ dùng thư viện chuẩn + `internal/kit`. Runbook: [`docs/operations/backup-restore.md`](../docs/operations/backup-restore.md).

`web/` hiện chỉ chứa công cụ sinh type (pin trong `package-lock.json`) và `src/api/schema.d.ts` sinh từ `api/openapi.yaml` bằng `make api-gen` (P2-T02); SPA được dựng ở P4-T01.
