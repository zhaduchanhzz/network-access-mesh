# MeshGuard ZTNA — Makefile (khung P0-T04). Lệnh Go/TypeScript được thêm ở P2-T01 và P4-T01.
PYTHON ?= python3

.PHONY: help docs docs-check render-test lint secret-scan go-test go-lint go-build

help: ## Liệt kê các target
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

docs: ## Sinh lại docs/ từ bản master
	$(PYTHON) tools/split_plan.py

docs-check: ## Lint master, sinh lại docs/, kiểm ROADMAP, sơ đồ §21.2, nhãn REQUIRES VALIDATION, link
	$(PYTHON) tools/docs_check.py

secret-scan: ## Quét secret trong repo (cần gitleaks; cấu hình .gitleaks.toml)
	@command -v gitleaks >/dev/null || { echo "gitleaks chưa cài — xem README"; exit 1; }
	gitleaks git --config .gitleaks.toml --redact --no-banner .

render-test: ## Golden test của tool render (instance Headscale, edge)
	$(PYTHON) tools/test_render_instance.py && $(PYTHON) tools/test_render_edge.py

lint: docs-check render-test secret-scan ## Mọi kiểm tra hiện có

go-test: ## go vet + test có race detector (cần Go 1.27.4; CI chạy trong image golang pin theo digest)
	go vet ./... && go test -race -count=1 ./...

go-lint: ## golangci-lint (phiên bản pin trong versions.lock)
	golangci-lint run ./...

go-build: ## Build meshguard api và worker vào bin/
	CGO_ENABLED=0 go build -trimpath -o bin/meshguard-api ./apps/api && CGO_ENABLED=0 go build -trimpath -o bin/meshguard-worker ./apps/worker
