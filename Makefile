.PHONY: help install dev run run-prod test test-fuzz lint format typecheck check openapi-validate generate-sdk docker-build docker-up docker-down clean

PYTHON ?= python
PIP ?= pip

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime + dev dependencies
	$(PYTHON) -m pip install -e ".[dev]"

LOOP_FACTORY ?= app.core.eventloop:proactor_event_loop

dev: ## Run the API with uvicorn in development mode (auto-reload)
	uvicorn app.main:app --reload --loop $(LOOP_FACTORY) --host 0.0.0.0 --port 8000

run: ## Run the API with uvicorn (production-ish, single worker)
	uvicorn app.main:app --host 0.0.0.0 --port 8000

run-prod: ## Run with multiple workers and proxy headers
	uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 --loop $(LOOP_FACTORY) --proxy-headers --forwarded-allow-ips "*"

test: ## Run the test suite
	$(PYTHON) -m pytest

test-cov: ## Run tests with coverage report
	$(PYTHON) -m pytest --cov=app --cov-report=term-missing

lint: ## Check code style with ruff
	ruff check .

format: ## Auto-format with ruff
	ruff format .
	ruff check . --fix

typecheck: ## Run static type checking with mypy
	mypy .

check: lint typecheck test ## Run lint, typecheck and tests

docker-build: ## Build the Docker image
	docker build -t awesome-api:latest .

docker-up: ## Start API + Redis via docker-compose
	docker compose up -d --build

docker-down: ## Stop docker-compose services
	docker compose down

clean: ## Remove cache/build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

test-fuzz: ## Run lightweight property/fuzz tests
	$(PYTHON) -m pytest -q tests/test_fuzz.py

openapi-validate: ## Generate and validate the OpenAPI document
	$(PYTHON) -m scripts.generate_sdk --output-dir /tmp/awesome-api-sdk-check

generate-sdk: ## Generate Python and TypeScript SDKs from OpenAPI
	$(PYTHON) -m scripts.generate_sdk --output-dir sdk
