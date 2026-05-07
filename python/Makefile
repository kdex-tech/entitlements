VENV = .venv
VENV_BIN = $(VENV)/bin

.PHONY: all
all: test

.PHONY: test
test: $(VENV) ## Run Python tests.
	$(VENV_BIN)/pytest

.PHONY: coverage
coverage: $(VENV) ## Run Python tests with coverage.
	$(VENV_BIN)/pytest --cov=entitlements --cov-report=term-missing

.PHONY: lint
lint: $(VENV) ## Run Python linter (ruff).
	$(VENV_BIN)/ruff check .

$(VENV):
	python3 -m venv $(VENV)
	$(VENV_BIN)/pip install pytest pytest-cov
