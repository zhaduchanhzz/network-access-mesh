# tests

`integration/`, `isolation/` (IT-01…IT-20), `e2e/`, `security/`, `load/` (§22). Unit test Go đặt cạnh mã nguồn (`*_test.go`).

Mã Go trong `security/` dùng fixture phiên kiểm thử `security/sessionfixture` (P2-T15a: session cho từng role của §8.4, không
cần trình duyệt hay IdP) và **chỉ build với tag `mgtestfixture`** — mọi file của fixture và của package import nó bắt đầu bằng
`//go:build mgtestfixture` (`internal/archtest` kiểm, và kiểm binary `api`/`worker` không phụ thuộc fixture). Chạy:
`go test -race -count=1 -tags mgtestfixture ./tests/...` (cần `MG_TEST_PG_ADMIN_URL` như mọi test PostgreSQL; bài đăng nhập
Keycloak thật `security/oidclogin` tự bỏ qua khi thiếu `MG_TEST_KEYCLOAK_URL`).

Isolation suite v1 (P2-T15, `make isolation`; bằng chứng: `docs/planning/evidence/P2-T15.md`):

| Thư mục | Nội dung |
|---|---|
| `security/authzmatrix` (tag) | Ma trận authz **sinh từ OpenAPI** (IT-02): mọi operation của `authz.Operations()` × 9 role + ẩn danh + session ở origin kia + request khác site × tenant của path (của mình, tenant kia, không tồn tại) × object của path (của mình, của thành viên khác, của tenant kia, không tồn tại). Kỳ vọng lấy từ §8.5/§8.6 mã hóa tay trong `master_test.go` (test đối chiếu từng ô với master; operation mới không có kỳ vọng ⇒ fail). Khi mount thêm handler (P2-T11, P2-T13…): chỉ thêm handler set vào `handlerSets` trong `world_test.go` |
| `isolation` (tag) | IT-01 qua API ghép với IdP giả, IT-03 (mọi FK giữa bảng tenant phải ghép `tenant_id`), IT-12a qua `GET …/audit` |
| `isolation/headscale` | IT-06, IT-10 (API key), IT-20 trên **hai Headscale thật**: `bash tests/isolation/headscale/run.sh` (`make isolation-headscale`; không có môi trường của script ⇒ test tự bỏ qua) |
