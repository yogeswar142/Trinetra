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

.PHONY: help install install-dev lint typecheck test benchmark clean docker-up docker-down

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

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

benchmark:  ## Run Phase 1.5 pipeline benchmark v2 (produces JSON report)
	$(PYTHON) scripts/benchmark_v2.py

docker-up:  ## Start docker-compose development environment
	docker compose up -d

docker-down:  ## Stop docker-compose development environment
	docker compose down

clean:  ## Remove build artifacts and caches
	rm -rf .pytest_cache __pycache__ coverage_html .mypy_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
