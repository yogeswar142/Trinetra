# Trinetra — Makefile
# Usage: make [target]

PYTHON     := python
PIP        := pip
PYTEST     := pytest
RUFF       := ruff
MYPY       := mypy
VENV_DIR   := .venv
BACKEND    := backend
TESTS      := tests
DASHBOARD_HOST := 0.0.0.0
DASHBOARD_PORT := 8765

.PHONY: help install install-dev lint typecheck test benchmark benchmark-v5 \
        train dashboard dashboard-cli docker-up docker-down clean

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-24s %s\n", $$1, $$2}'

install:  ## Install production dependencies
	$(PIP) install -e ".[dev,benchmark]"

install-dev: install  ## Install dev + benchmark dependencies
	@echo "Dev dependencies installed."

lint:  ## Run ruff linter (check only, no auto-fix)
	$(RUFF) check $(BACKEND) $(TESTS)

lint-fix:  ## Run ruff linter with auto-fix
	$(RUFF) check --fix $(BACKEND) $(TESTS)

typecheck:  ## Run mypy type checker
	$(MYPY) $(BACKEND)/trinetra

test:  ## Run all tests (includes no-transmit safety check)
	$(PYTEST) $(TESTS) -v --tb=short

test-cov:  ## Run tests with coverage report
	$(PYTEST) $(TESTS) --cov=$(BACKEND)/trinetra --cov-report=term-missing --cov-report=html:coverage_html

benchmark:  ## Run full pipeline benchmark v5 (produces JSON report)
	$(PYTHON) scripts/benchmark_v5.py

benchmark-v5: benchmark  ## Alias for benchmark

train:  ## Train and sign all 6 threat-class ML models
	$(PYTHON) scripts/train_and_sign_models.py

generate-pcaps:  ## Generate tool-realistic synthetic PCAPs for all threat classes
	$(PYTHON) scripts/generate_tool_realistic_pcaps.py

dashboard:  ## Start the SOC web dashboard (http://localhost:8765)
	@echo ""
	@echo "  ╔══════════════════════════════════════════╗"
	@echo "  ║  TRINETRA SOC DASHBOARD                  ║"
	@echo "  ║  http://$(DASHBOARD_HOST):$(DASHBOARD_PORT)                  ║"
	@echo "  ╚══════════════════════════════════════════╝"
	@echo ""
	TRINETRA_DASHBOARD_HOST=$(DASHBOARD_HOST) \
	TRINETRA_DASHBOARD_PORT=$(DASHBOARD_PORT) \
	$(PYTHON) -m trinetra.dashboard.api_server

dashboard-next:  ## Start Next.js SOC dashboard (dev mode, http://localhost:3000)
	cd frontend && npm run dev

dashboard-next-build:  ## Build Next.js dashboard for production
	cd frontend && npm run build

dashboard-next-start:  ## Start Next.js production build
	cd frontend && npm run start

dashboard-cli:  ## Start the SOC CLI terminal dashboard
	$(PYTHON) -m trinetra.dashboard.cli_dashboard \
		--ledger-path data/ledger/audit_chain.jsonl \
		--refresh 2.0

docker-up:  ## Start docker-compose development environment
	docker compose up -d

docker-down:  ## Stop docker-compose development environment
	docker compose down

clean:  ## Remove build artifacts and caches
	rm -rf .pytest_cache __pycache__ coverage_html .mypy_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

