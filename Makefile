# MeshGuard ZTNA — Makefile (khung P0-T04). Lệnh Go/TypeScript được thêm ở P2-T01, P2-T02 (contract API) và P4-T01.
PYTHON ?= python3

SQLC_VERSION ?= v1.31.1

.PHONY: help docs docs-check render-test lint secret-scan api-lint api-gen authz-gen go-test go-lint go-build sqlc sqlc-diff isolation isolation-headscale

help: ## Liệt kê các target
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

docs: ## Sinh lại docs/ từ bản master
	$(PYTHON) tools/split_plan.py

docs-check: ## Lint master, sinh lại docs/, kiểm ROADMAP, sơ đồ §21.2, nhãn REQUIRES VALIDATION, link
	$(PYTHON) tools/docs_check.py

secret-scan: ## Quét secret trong repo (cần gitleaks; cấu hình .gitleaks.toml)
	@command -v gitleaks >/dev/null || { echo "gitleaks chưa cài — xem README"; exit 1; }
	gitleaks git --config .gitleaks.toml --redact --no-banner .

render-test: ## Test tham số môi trường (mgenv) + golden test của tool render (instance Headscale, edge, IdP)
	$(PYTHON) tools/test_mgenv.py && $(PYTHON) tools/test_render_instance.py && $(PYTHON) tools/test_render_edge.py && $(PYTHON) tools/test_render_idp.py

api-lint: ## Spec-lint api/openapi.yaml (x-permission hai chiều với §8.5/§8.6, x-task, tenant chỉ từ path, action path, problem+json) + seed RBAC/bảng authz đã sinh + test của lint
	$(PYTHON) tools/openapi_lint.py && $(PYTHON) tools/test_openapi_lint.py

authz-gen: ## Sinh lại database/seeds/rbac.sql (từ §8.4–§8.6) và internal/authz/operations_gen.go (từ api/openapi.yaml)
	$(PYTHON) tools/openapi_lint.py --write

api-gen: ## Sinh lại server Go (oapi-codegen qua go tool) và type TypeScript (openapi-typescript) từ api/openapi.yaml
	go generate ./internal/httpapi/gen
	cd apps/web && npm ci --ignore-scripts --no-audit --no-fund && npm run gen:api

lint: docs-check render-test api-lint secret-scan ## Mọi kiểm tra hiện có

go-test: ## go vet + test có race detector; test PostgreSQL của internal/store cần MG_TEST_PG_ADMIN_URL (database/README.md)
	go vet ./... && go test -race -count=1 ./...

# Test của các task khác chứng minh một phần IT-01/01b/01c, IT-03, IT-10 (secret), IT-12a, IT-17 (P2-T15 — bảng ở
# docs/planning/evidence/P2-T15.md); chạy cùng phần mới để `make isolation` là toàn bộ isolation suite v1.
ISOLATION_REUSED = TestTenantIssuerIsolation|TestIdPMixUpRejectedBeforeTokenCall|TestSharedIssuerOrganisationConstraint|TestSessionOriginBinding|TestDBRejectsCrossScopeMemberships|TestDBRejectsCrossScopePlatformUsers|TestDBRejectsCrossScopeGrants|TestDBRejectsIdentityOutsideItsIdP|TestCatalogRLSOnEveryTable|TestRLSUnsetOrEmptyGUC|TestRLSTenantScope|TestRLSTenantPoolCannotBecomePlatform|TestCrossTenantWritesRejected|TestWithTxScopeAndRole|TestPartitionsDirectAccessDenied|TestPartitionMaintain|TestReaderScopes|TestFinishDenials|TestAuditThroughTheAPI|TestWrappedDEKSwapBetweenTenantsRejected|TestTenantPoolClaimingPlatformScope|TestCiphertextSwapRejected|TestAuthorizerTenantRoutes|TestAuthorizerPlatformRoutes

isolation: ## Isolation suite v1 (P2-T15): ma trận authz sinh từ OpenAPI + IT-01/03/12a (tag mgtestfixture) + test IT của P2-T03/04/06/07/08; cần MG_TEST_PG_ADMIN_URL
	go test -race -count=1 -tags mgtestfixture ./tests/security/authzmatrix/ ./tests/isolation/
	go test -race -count=1 -run '^($(ISOLATION_REUSED))$$' ./internal/identity/ ./internal/store/ ./internal/authz/ ./internal/audit/ ./internal/httpapi/auditapi/ ./internal/secrets/

isolation-headscale: ## IT-06, IT-10 (API key), IT-20 trên hai Headscale thật (cần Docker, python3 ≥ 3.11)
	bash tests/isolation/headscale/run.sh

sqlc: ## Sinh lại internal/store/sqlcdb từ database/migrations + database/queries (sqlc pin trong versions.lock; cần CGO)
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate -f database/sqlc.yaml

sqlc-diff: ## Kiểm mã sinh sqlc khớp schema + queries (như CI)
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) diff -f database/sqlc.yaml

go-lint: ## golangci-lint (phiên bản pin trong versions.lock)
	golangci-lint run ./...

go-build: ## Build meshguard api và worker vào bin/
	CGO_ENABLED=0 go build -trimpath -o bin/meshguard-api ./apps/api && CGO_ENABLED=0 go build -trimpath -o bin/meshguard-worker ./apps/worker
