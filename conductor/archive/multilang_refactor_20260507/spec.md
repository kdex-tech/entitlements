# Specification: Multi-Language Restructuring

## Overview
Restructure the existing `kdex-entitlements` project into a multi-language monorepo supporting Go, Rust, and Python implementations. The core logic must be 100% compatible across all languages, driven by a centralized specification document derived from the existing Go implementation.

## Functional Requirements
- **Centralized Specification**: Extract the behavioral specification from the existing Go implementation into a single, language-agnostic document (`SPEC.md` or similar) in the project root.
- **Project Structure**: Adopt a root-folder per-language structure (e.g., `go/`, `rust/`, `python/`).
- **Toolchain Isolation**: Ensure each language directory is self-contained with its respective dependency management and configuration files (e.g., `go.mod`, `Cargo.toml`, `pyproject.toml`).
- **Make Targets**: Maintain top-level `Makefile` targets (e.g., `make test`, `make build`) that delegate to language-specific commands.
- **Compatibility**: Ensure the Rust and Python implementations strictly adhere to the central specification and match the Go implementation's behavior exactly.

## Non-Functional Requirements
- Maintain >80% test coverage for all implementations.
- Adhere to the established code style guidelines for each language.

## Acceptance Criteria
- [ ] Root directory contains a clear specification document derived from the Go code.
- [ ] Existing Go code is successfully moved to a dedicated `go/` (or similar) directory and tests pass.
- [ ] Rust project is initialized in `rust/` (or similar) and tests pass.
- [ ] Python project is initialized in `python/` (or similar) and tests pass.
- [ ] Top-level `make test` runs tests for Go, Rust, and Python successfully.
- [ ] Implementations in Go, Rust, and Python pass a compatibility test suite based on the central specification.

## Out of Scope
- Adding new features or modifying the underlying entitlement checking logic beyond what is currently implemented in Go.