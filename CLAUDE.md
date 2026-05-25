# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

`kdex-entitlements` is a **language-agnostic entitlements checking library** shipped as four parallel implementations of the same semantics:

- `go/` — Go module `github.com/kdex-tech/entitlements/go` (the canonical reference; other ports follow its structure and naming)
- `rust/` — crate `kdex-entitlements` (published to crates.io)
- `python/` — package `kdex-entitlements` (published to PyPI, src layout under `src/entitlements/`)
- `typescript/` — `@kdex-tech/entitlements` (published to GitHub Packages, ESM-only)

All four implement the spec in `SPEC.md`. That spec is the contract — when changing behavior, update `SPEC.md` first if the semantics shift, then mirror the change across **all four** implementations and their tests. Drift between ports is a bug.

The Go file `go/entitlements.go` carries the most detailed inline documentation of the pattern semantics; treat it as the reference doc and port docs/behavior from there.

## Build, Test, Lint

The root `Makefile` fans targets out to all four language subdirectories. Subdirectories that don't exist are skipped gracefully.

```bash
make test    # test-go + test-rust + test-python + test-typescript
make lint    # lint-go + lint-rust + lint-python + lint-typescript
make coverage
```

Per-language equivalents: `make test-go`, `make lint-rust`, `make coverage-python`, etc.

### Per-language details

**Go** (`cd go`):
```bash
make test                            # fmt + vet + go test ./... -coverprofile cover.out
make lint                            # downloads golangci-lint v2.10.1 into ./bin on first run
make lint-fix                        # autofix + run modernizer
go test ./... -run TestVerify -v     # single test by name
DEBUG=true make test                 # run under dlv on :2345
TEST_ARGS='-run TestFoo -v' make test
```
The Go module lives at the `/go/` subdirectory (not repo root). Module path is `github.com/kdex-tech/entitlements/go` and CI tags releases as `go/vX.Y.Z` in addition to `vX.Y.Z` — Go's tooling requires the `go/` prefix for subdirectory modules (see https://go.dev/ref/mod#vcs-version). Do not drop the `go/` tag.

**Rust** (`cd rust`):
```bash
make test                            # cargo test
make lint                            # cargo clippy -- -D warnings
cargo test <test_name>               # single test
```

**Python** (`cd python`):
```bash
make test                            # creates .venv on first run, installs pytest + pytest-cov, runs pytest
make lint                            # ruff check .
.venv/bin/pytest tests/test_entitlements.py::test_specific_case -v
```
The Makefile bootstraps `.venv` itself — no need to manage virtualenvs manually for the standard targets.

**TypeScript** (`cd typescript`):
```bash
make test                            # vitest run
make lint                            # eslint src
make build                           # tsc -p tsconfig.build.json
npx vitest run -t "pattern name"     # single test
```
Node ≥20, ESM-only (`"type": "module"`).

## Release Flow

CI (`.github/workflows/ci.yml`) runs all four language test jobs on every push/PR. On a `v*` tag push the `release` job:

1. Creates a GitHub Release with auto-generated notes.
2. Pushes a parallel `go/vX.Y.Z` tag at the same SHA (required for Go subdir module resolution).
3. Publishes the Rust crate (rewriting `Cargo.toml` version inline from the tag).
4. Builds + uploads the Python package via twine (uses `SETUPTOOLS_SCM_PRETEND_VERSION` from the tag, strips the leading `v`).
5. `npm version --no-git-tag-version <ver>` + `npm publish` for TypeScript.

The `VERSION` file at the repo root records the most recently released version. Tag releases as `v<VERSION>` (e.g. `v0.1.24`); the absence of a `v` prefix on `VERSION` itself is intentional.

## Cross-Port Consistency Rules

- **Spec changes propagate to all four ports in the same change.** Don't land a behavior change in one language without the other three.
- **Naming convention:** each port uses its idiomatic case (Go: `VerifyEntitlements`, TS: `verifyEntitlements`, Python: `verify_entitlements`, Rust: `verify_entitlements`) but the method/type names map 1:1.
- **Tests are duplicated by intent, not by literal translation.** Each port's test file exercises the same scenarios from `SPEC.md`; when adding a new behavior, add equivalent test cases in all four.
- **The pattern parser interns/caches parsed patterns** (`maxCacheSize = 10000` in Go). Performance characteristics matter — `SPEC.md` calls out interning + pre-parsing as implementation requirements. Don't regress those without discussion.
- **Concurrency:** `EntitlementsChecker` must be safe for concurrent verification calls in every port (the Go impl uses `sync.RWMutex` around the cache).

## Workspace Context

This repo sits inside the larger `kdex-tech/workspace` multi-repo (see workspace `CLAUDE.md` one level up). Unlike other sub-repos (kdex-crds, kdex-host-manager, kdex-nexus-manager) it is **not** a kubebuilder project, has no CRDs, and is not part of the `updateCrdUsage.sh` propagation chain. It's a standalone polyglot library that other repos consume via their language-native package manager.

## `conductor/` Directory

`conductor/` contains workspace-wide TDD/plan methodology (`workflow.md`, `tracks/`, `product.md`, `tech-stack.md`). It documents a heavyweight `plan.md`-driven, git-notes-per-task flow used for tracked initiatives. **Do not assume every change must follow that flow** — most edits in this repo are ad-hoc library work and only need: failing test → implementation → passing test → commit. Apply the conductor workflow only when the user explicitly invokes a tracked initiative.

## Conventions

- Use `rg` (ripgrep) for searching, not `grep`.
- The Go implementation's inline doc comments are the canonical description of pattern forms (long/medium/short/opaque) and matching rules — read `go/entitlements.go` before relying on `SPEC.md` alone; the code has nuance the spec elides (e.g. the rationale for not URL-encoding resource names inside the library).
- Coverage target is >80% per `SPEC.md`. Each port has a `make coverage` target.
