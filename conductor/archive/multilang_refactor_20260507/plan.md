# Implementation Plan: Multi-Language Restructuring

## Phase 1: Preparation & Specification [checkpoint: 4545e73]
- [x] Task: Create Central Specification Document.
    - [x] Analyze the existing Go implementation (`entitlements.go`, `entitlements_test.go`).
    - [x] Create `SPEC.md` in the project root detailing the behavioral requirements.
- [x] Task: Conductor - User Manual Verification 'Preparation & Specification' (Protocol in workflow.md)

## Phase 2: Project Restructuring [checkpoint: 4f5e2d9]
- [x] Task: Move Go implementation to a dedicated directory.
    - [x] Create `go/` directory.
    - [x] Move `entitlements.go`, `entitlements_test.go`, `go.mod`, and `go.sum` into `go/`.
    - [x] Update `go.mod` if necessary.
- [x] Task: Update top-level Makefile for Go.
    - [x] Modify the existing `Makefile` to delegate `test`, `coverage`, and `lint` targets to the `go/` directory.
- [x] Task: Verify Go Restructuring.
    - [x] Run `make test` from the root to ensure the Go tests still pass in their new location.
- [x] Task: Conductor - User Manual Verification 'Project Restructuring' (Protocol in workflow.md)

## Phase 3: Rust Initialization [checkpoint: 8ffa8b2]
- [x] Task: Initialize Rust project.
    - [x] Create `rust/` directory.
    - [x] Run `cargo init --lib` within `rust/`.
- [x] Task: Update top-level Makefile for Rust.
    - [x] Add/update `test`, `coverage`, and `lint` targets in the top-level `Makefile` to delegate to the `rust/` directory.
- [x] Task: Conductor - User Manual Verification 'Rust Initialization' (Protocol in workflow.md)

## Phase 4: Python Initialization [checkpoint: 9a82755]
- [x] Task: Initialize Python project.
    - [x] Create `python/` directory.
    - [x] Set up Python environment (`pyproject.toml` or similar, `pytest`, etc.).
- [x] Task: Update top-level Makefile for Python.
    - [x] Add/update `test`, `coverage`, and `lint` targets in the top-level `Makefile` to delegate to the `python/` directory.
- [x] Task: Conductor - User Manual Verification 'Python Initialization' (Protocol in workflow.md)