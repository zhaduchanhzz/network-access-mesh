# MeshGuard ZTNA — Makefile (khung P0-T04). Lệnh Go/TypeScript được thêm ở P2-T01 và P4-T01.
PYTHON ?= python3

.PHONY: help docs docs-check lint secret-scan

help: ## Liệt kê các target
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

docs: ## Sinh lại docs/ từ bản master
	$(PYTHON) tools/split_plan.py

docs-check: ## Lint master, sinh lại docs/, kiểm ROADMAP, sơ đồ §21.2, nhãn REQUIRES VALIDATION, link
	$(PYTHON) tools/docs_check.py

secret-scan: ## Quét secret trong repo (cần gitleaks; cấu hình .gitleaks.toml)
	@command -v gitleaks >/dev/null || { echo "gitleaks chưa cài — xem README"; exit 1; }
	gitleaks git --config .gitleaks.toml --redact --no-banner .

lint: docs-check secret-scan ## Mọi kiểm tra hiện có
