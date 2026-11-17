# tests

`integration/`, `isolation/` (IT-01…IT-20), `e2e/`, `security/`, `load/` (§22), `backup/` (diễn tập backup → restore của P2-T03a/P2-T05b với khóa dùng một lần: `drill.sh`, chỉ trên máy build/CI). Unit test Go đặt cạnh mã nguồn (`*_test.go`).

Mã Go trong `security/` dùng fixture phiên kiểm thử `security/sessionfixture` (P2-T15a: session cho từng role của §8.4, không
cần trình duyệt hay IdP) và **chỉ build với tag `mgtestfixture`** — mọi file của fixture và của package import nó bắt đầu bằng
`//go:build mgtestfixture` (`internal/archtest` kiểm, và kiểm binary `api`/`worker` không phụ thuộc fixture). Chạy:
`go test -race -count=1 -tags mgtestfixture ./tests/...` (cần `MG_TEST_PG_ADMIN_URL` như mọi test PostgreSQL; bài đăng nhập
Keycloak thật `security/oidclogin` tự bỏ qua khi thiếu `MG_TEST_KEYCLOAK_URL`).
