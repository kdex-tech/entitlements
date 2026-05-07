# Implementation Plan: Multi-Language Restructuring

## Phase 1: Preparation & Specification [checkpoint: 4545e73]
- [x] Task: Create Central Specification Document.
    - [x] Analyze the existing Go implementation (`entitlements.go`, `entitlements_test.go`).
    - [x] Create `SPEC.md` in the project root detailing the behavioral requirements.
- [x] Task: Conductor - User Manual Verification 'Preparation & Specification' (Protocol in workflow.md)

## Phase 2: Project Restructuring
- [ ] Task: Move Go implementation to a dedicated directory.
    - [ ] Create `go/` directory.
    - [ ] Move `entitlements.go`, `entitlements_test.go`, `go.mod`, and `go.sum` into `go/`.
    - [ ] Update `go.mod` if necessary.
- [ ] Task: Update top-level Makefile for Go.
    - [ ] Modify the existing `Makefile` to delegate `test`, `coverage`, and `lint` targets to the `go/` directory.
- [ ] Task: Verify Go Restructuring.
    - [ ] Run `make test` from the root to ensure the Go tests still pass in their new location.
- [ ] Task: Conductor - User Manual Verification 'Project Restructuring' (Protocol in workflow.md)

## Phase 3: Rust Initialization
- [ ] Task: Initialize Rust project.
    - [ ] Create `rust/` directory.
    - [ ] Run `cargo init --lib` within `rust/`.
- [ ] Task: Update top-level Makefile for Rust.
    - [ ] Add/update `test`, `coverage`, and `lint` targets in the top-level `Makefile` to delegate to the `rust/` directory.
- [ ] Task: Conductor - User Manual Verification 'Rust Initialization' (Protocol in workflow.md)

## Phase 4: Python Initialization
- [ ] Task: Initialize Python project.
    - [ ] Create `python/` directory.
    - [ ] Set up Python environment (`pyproject.toml` or similar, `pytest`, etc.).
- [ ] Task: Update top-level Makefile for Python.
    - [ ] Add/update `test`, `coverage`, and `lint` targets in the top-level `Makefile` to delegate to the `python/` directory.
- [ ] Task: Conductor - User Manual Verification 'Python Initialization' (Protocol in workflow.md)