# api

Contract: `openapi.yaml` — SaaS API, contract-first, mỗi operation có `x-permission` (P2-T02, §13); `agent/v1/agent.proto` — giao thức worker ↔ Host Agent (P3-T01, §11).

`openapi.yaml` (OpenAPI 3.1) là nguồn sự thật:

- `make api-lint` — spec-lint `tools/openapi_lint.py`: mỗi operation có đúng một `x-permission` thuộc ma trận §8.5/§8.6 (hoặc `public`/`authenticated`/`internal` của §13.1), `x-task` là ID ở §20 và khớp bảng truy vết §13.2, `x-audit-action`; tenant chỉ lấy từ path `{tenantId}`; hành động là segment con `/…/{id}/<action>`; lỗi là `application/problem+json`.
  Chiều ngược lại (P2-T07): mỗi hàng của §8.5/§8.6 (theo khóa quyền) phải có ít nhất một operation khi mọi task mà bảng truy vết §13.2 gán cho API action của hàng đó đã "đã thực hiện" ở §20; trước đó `--list` báo là độ phủ còn thiếu.
- `make api-gen` — sinh server Go (oapi-codegen strict server → `internal/httpapi/gen`) và type TypeScript (openapi-typescript → `apps/web/src/api/schema.d.ts`). CI sinh lại và fail nếu code đã commit lệch spec.
- `make authz-gen` — sinh `internal/authz/operations_gen.go` (x-permission, x-own-resource, x-dual-control của mỗi operation — bảng mà `authz.RequireOperation` dùng, deny-by-default với operation không có trong spec) và `database/seeds/rbac.sql` (role/permission/grant từ §8.4–§8.6). Spec-lint fail khi hai file đã commit lệch master/spec.
- Trong v1 chỉ thay đổi cộng thêm (§13.1). Nhóm endpoint của phase sau được thêm ở task xây nhóm đó (cột Task của bảng truy vết §13.2).
- Server được lắp ở `internal/httpapi` (P2-T14): chuỗi middleware (request id, log có redaction, recover, rate limit, giới hạn body), lỗi `problem+json` (`internal/httpapi/problem`) và điểm mở rộng `httpapi.Handlers` — mỗi `x-task` một interface handler; operation chưa có handler trả `501 not_implemented`. Cách gắn handler: [bằng chứng P2-T14](../docs/planning/evidence/P2-T14.md).
- Lớp bảo mật của chuỗi (`httpapi.Hooks`) lấy từ `internal/httpapi/authzhook`: `Hooks.Session` = `identity.Service.Middleware` (origin, Origin/CSRF, session — P2-T06) + `httpapi.SetIdentity`, `Hooks.Authz` = `authz.RequireOperation` theo tên operation và `{tenantId}` của path (P2-T07; quyết định cho handler qua `authzhook.DecisionFrom`). `TestComposedAPI` lắp cả chuỗi trên PostgreSQL thật với IdP giả (`internal/identity/identitytest`).

`agent/v1/agent.proto` (P3-T01) — giao thức đóng, có kiểu giữa worker và Host Agent (service `meshguard.agent.v1.AgentService`, một RPC cho mỗi phương thức của `InfrastructureDriver` ở §11.5 + `Health`, `GetHostInfo`, `ListInstances`):

- `make agent-gen` (`go generate ./api/agent/v1`) — `buf lint` (bộ STANDARD) rồi sinh `agent.pb.go`, `agent_grpc.pb.go` bằng buf (`go run github.com/bufbuild/buf/cmd/buf@v1.75.0`, không BSR) với plugin cục bộ `protoc-gen-go` (bản protobuf trong `go.mod`) và `protoc-gen-go-grpc@v1.6.2` (`buf.yaml`, `buf.gen.yaml`). CI sinh lại và fail nếu mã đã commit lệch `.proto`.
- Không request nào mang lệnh, đường dẫn, tên image, tên network hay YAML: ý nghĩa của từng trường (UUID chuẩn, digest thuộc allowlist, dải UID/subnet/cổng của host, label sở hữu) do `internal/provisioning/agentspec` kiểm phía agent. Trường hay giá trị enum mà agent không biết ⇒ từ chối. Chỉ thêm trường (không đổi số hiệu, không đổi nghĩa) trong v1.
