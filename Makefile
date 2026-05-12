# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: test

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Go

.PHONY: test-go
test-go: ## Run Go tests.
	$(MAKE) -C go test

.PHONY: coverage-go
coverage-go: ## Generate Go test coverage report.
	$(MAKE) -C go coverage

.PHONY: lint-go
lint-go: ## Run Go linter.
	$(MAKE) -C go lint

##@ Rust

.PHONY: test-rust
test-rust: ## Run Rust tests.
	@if [ -d rust ]; then $(MAKE) -C rust test; else echo "Rust implementation not found"; fi

.PHONY: coverage-rust
coverage-rust: ## Generate Rust test coverage report.
	@if [ -d rust ]; then $(MAKE) -C rust coverage; else echo "Rust implementation not found"; fi

.PHONY: lint-rust
lint-rust: ## Run Rust linter.
	@if [ -d rust ]; then $(MAKE) -C rust lint; else echo "Rust implementation not found"; fi

##@ Python

.PHONY: test-python
test-python: ## Run Python tests.
	@if [ -d python ]; then $(MAKE) -C python test; else echo "Python implementation not found"; fi

.PHONY: coverage-python
coverage-python: ## Generate Python test coverage report.
	@if [ -d python ]; then $(MAKE) -C python coverage; else echo "Python implementation not found"; fi

.PHONY: lint-python
lint-python: ## Run Python linter.
	@if [ -d python ]; then $(MAKE) -C python lint; else echo "Python implementation not found"; fi

##@ TypeScript

.PHONY: test-typescript
test-typescript: ## Run TypeScript tests.
	@if [ -d typescript ]; then $(MAKE) -C typescript test; else echo "TypeScript implementation not found"; fi

.PHONY: coverage-typescript
coverage-typescript: ## Generate TypeScript test coverage report.
	@if [ -d typescript ]; then $(MAKE) -C typescript coverage; else echo "TypeScript implementation not found"; fi

.PHONY: lint-typescript
lint-typescript: ## Run TypeScript linter.
	@if [ -d typescript ]; then $(MAKE) -C typescript lint; else echo "TypeScript implementation not found"; fi

##@ Combined

.PHONY: test
test: test-go test-rust test-python test-typescript ## Run tests for all languages.

.PHONY: coverage
coverage: coverage-go coverage-rust coverage-python coverage-typescript ## Generate coverage reports for all languages.

.PHONY: lint
lint: lint-go lint-rust lint-python lint-typescript ## Run linters for all languages.
