# Implementation Plan: Review tests and coverage

## Phase 1: Analysis and Coverage Check
- [ ] Task: Run existing tests.
    - [ ] Run `go test ./...` to ensure all existing tests pass.
- [ ] Task: Check current test coverage.
    - [ ] Run `go test -coverprofile=coverage.out ./...`
    - [ ] Run `go tool cover -func=coverage.out` to view the current coverage percentage.
- [ ] Task: Identify coverage gaps.
    - [ ] If coverage is below 80%, use `go tool cover -html=coverage.out` (or similar) to identify untested code paths in `entitlements.go`.
- [ ] Task: Conductor - User Manual Verification 'Analysis and Coverage Check' (Protocol in workflow.md)

## Phase 2: Implement Additional Tests
- [ ] Task: Write tests for uncovered code paths (if necessary).
    - [ ] Update `entitlements_test.go` or create new test files using `testify` to cover the identified gaps.
- [ ] Task: Verify new coverage.
    - [ ] Re-run coverage checks to ensure >80% coverage is achieved.
- [ ] Task: Conductor - User Manual Verification 'Implement Additional Tests' (Protocol in workflow.md)