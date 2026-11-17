# api

Contract: `openapi.yaml` — SaaS API, contract-first, mỗi operation có `x-permission` (P2-T02, §13); `agent/v1/agent.proto` — giao thức worker ↔ Host Agent (P3-T01, §11).

`openapi.yaml` (OpenAPI 3.1) là nguồn sự thật:

- `make api-lint` — spec-lint `tools/openapi_lint.py`: mỗi operation có đúng một `x-permission` thuộc ma trận §8.5/§8.6 (hoặc `public`/`authenticated`/`internal` của §13.1), `x-task` là ID ở §20 và khớp bảng truy vết §13.2, `x-audit-action`; tenant chỉ lấy từ path `{tenantId}`; hành động là segment con `/…/{id}/<action>`; lỗi là `application/problem+json`.
  Chiều ngược lại (P2-T07): mỗi hàng của §8.5/§8.6 (theo khóa quyền) phải có ít nhất một operation khi mọi task mà bảng truy vết §13.2 gán cho API action của hàng đó đã "đã thực hiện" ở §20; trước đó `--list` báo là độ phủ còn thiếu.
- `make api-gen` — sinh server Go (oapi-codegen strict server → `internal/httpapi/gen`) và type TypeScript (openapi-typescript → `apps/web/src/api/schema.d.ts`). CI sinh lại và fail nếu code đã commit lệch spec.
- `make authz-gen` — sinh `internal/authz/operations_gen.go` (x-permission, x-own-resource, x-dual-control của mỗi operation — bảng mà `authz.RequireOperation` dùng, deny-by-default với operation không có trong spec) và `database/seeds/rbac.sql` (role/permission/grant từ §8.4–§8.6). Spec-lint fail khi hai file đã commit lệch master/spec.
- Trong v1 chỉ thay đổi cộng thêm (§13.1). Nhóm endpoint của phase sau được thêm ở task xây nhóm đó (cột Task của bảng truy vết §13.2).
- Server được lắp ở `internal/httpapi` (P2-T14): chuỗi middleware (request id, log có redaction, recover, rate limit, giới hạn body), lỗi `problem+json` (`internal/httpapi/problem`) và điểm mở rộng `httpapi.Handlers` — mỗi `x-task` một interface handler; operation chưa có handler trả `501 not_implemented`. Cách gắn handler: [bằng chứng P2-T14](../docs/planning/evidence/P2-T14.md).
