# MeshGuard ZTNA — Makefile (khung P0-T04). Lệnh Go/TypeScript được thêm ở P2-T01, P2-T02 (contract API) và P4-T01.
PYTHON ?= python3

.PHONY: help docs docs-check render-test lint secret-scan api-lint api-gen go-test go-lint go-build

help: ## Liệt kê các target
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

docs: ## Sinh lại docs/ từ bản master
	$(PYTHON) tools/split_plan.py

docs-check: ## Lint master, sinh lại docs/, kiểm ROADMAP, sơ đồ §21.2, nhãn REQUIRES VALIDATION, link
	$(PYTHON) tools/docs_check.py

secret-scan: ## Quét secret trong repo (cần gitleaks; cấu hình .gitleaks.toml)
	@command -v gitleaks >/dev/null || { echo "gitleaks chưa cài — xem README"; exit 1; }
	gitleaks git --config .gitleaks.toml --redact --no-banner .

render-test: ## Test tham số môi trường (mgenv) + golden test của tool render (instance Headscale, edge)
	$(PYTHON) tools/test_mgenv.py && $(PYTHON) tools/test_render_instance.py && $(PYTHON) tools/test_render_edge.py

api-lint: ## Spec-lint api/openapi.yaml (x-permission, x-task, tenant chỉ từ path, action path, problem+json) + test của lint
	$(PYTHON) tools/openapi_lint.py && $(PYTHON) tools/test_openapi_lint.py

api-gen: ## Sinh lại server Go (oapi-codegen qua go tool) và type TypeScript (openapi-typescript) từ api/openapi.yaml
	go generate ./internal/httpapi/gen
	cd apps/web && npm ci --ignore-scripts --no-audit --no-fund && npm run gen:api

lint: docs-check render-test api-lint secret-scan ## Mọi kiểm tra hiện có

go-test: ## go vet + test có race detector (cần Go 1.27.4; CI chạy trong image golang pin theo digest)
	go vet ./... && go test -race -count=1 ./...

go-lint: ## golangci-lint (phiên bản pin trong versions.lock)
	golangci-lint run ./...

go-build: ## Build meshguard api và worker vào bin/
	CGO_ENABLED=0 go build -trimpath -o bin/meshguard-api ./apps/api && CGO_ENABLED=0 go build -trimpath -o bin/meshguard-worker ./apps/worker
