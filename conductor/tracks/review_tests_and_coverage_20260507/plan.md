# Implementation Plan: Review tests and coverage

## Phase 1: Analysis and Coverage Check [checkpoint: 46b752d]
- [x] Task: Run existing tests.
    - [x] Run `go test ./...` to ensure all existing tests pass.
- [x] Task: Check current test coverage.
    - [x] Run `go test -coverprofile=coverage.out ./...`
    - [x] Run `go tool cover -func=coverage.out` to view the current coverage percentage.
- [x] Task: Identify coverage gaps.
    - [x] If coverage is below 80%, use `go tool cover -html=coverage.out` (or similar) to identify untested code paths in `entitlements.go`.
- [x] Task: Conductor - User Manual Verification 'Analysis and Coverage Check' (Protocol in workflow.md)

## Phase 2: Implement Additional Tests [checkpoint: faf4bbe]
- [x] Task: Write tests for uncovered code paths (if necessary).
    - [x] Update `entitlements_test.go` or create new test files using `testify` to cover the identified gaps.
- [x] Task: Verify new coverage.
    - [x] Re-run coverage checks to ensure >80% coverage is achieved.
- [x] Task: Conductor - User Manual Verification 'Implement Additional Tests' (Protocol in workflow.md)