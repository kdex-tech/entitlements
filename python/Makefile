.PHONY: all
all: test

.PHONY: test
test: ## Run Python tests.
	pytest

.PHONY: coverage
coverage: ## Run Python tests with coverage.
	pytest --cov=entitlements --cov-report=term-missing

.PHONY: lint
lint: ## Run Python linter (ruff).
	ruff check .
