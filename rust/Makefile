.PHONY: all
all: test

.PHONY: test
test: ## Run Rust tests.
	cargo test

.PHONY: coverage
coverage: ## Run Rust tests with coverage (requires cargo-tarpaulin or similar).
	@echo "Coverage not yet implemented for Rust"

.PHONY: lint
lint: ## Run Rust linter (clippy).
	cargo clippy -- -D warnings
