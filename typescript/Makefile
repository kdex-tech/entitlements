SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: test

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

node_modules: package.json
	npm install --no-audit --no-fund
	@touch node_modules

.PHONY: test
test: node_modules ## Run TypeScript tests with coverage.
	npx vitest run

.PHONY: coverage
coverage: node_modules ## Run TypeScript tests with coverage report.
	npx vitest run --coverage

.PHONY: lint
lint: node_modules ## Run TypeScript linter.
	npx eslint src

.PHONY: build
build: node_modules ## Build TypeScript package.
	npx tsc -p tsconfig.build.json

.PHONY: clean
clean: ## Remove build output.
	rm -rf dist node_modules
