# Specification: Implement Rust and Python Libraries

## Overview
Implement the Rust and Python libraries ensuring 100% compatibility with the Go implementation. Both implementations must precisely follow the goals and behaviors outlined in the `SPEC.md` document located in the project root. The existing Go implementation serves as a reference.

## Functional Requirements
- **Rust Implementation**: Develop the entitlements checker library in Rust within the `rust/` directory. Use the standard library as much as possible.
- **Python Implementation**: Develop the entitlements checker library in Python within the `python/` directory. Use the standard library as much as possible.
- **Specification Adherence**: Both libraries must implement the logic defined in `SPEC.md`, including pattern forms (long, medium, short, opaque), wildcards, and verification logic.
- **Compatibility**: Ensure 100% compatibility in behavior across Go, Rust, and Python implementations.

## Non-Functional Requirements
- Maintain >80% test coverage for both new implementations.
- Follow standard Rust and Python conventions.
- Implementations should prioritize performance.

## Acceptance Criteria
- [ ] Rust library is fully implemented and passes all unit tests.
- [ ] Python library is fully implemented and passes all unit tests.
- [ ] Test coverage for both implementations is >80%.
- [ ] Both implementations successfully adhere to all rules in `SPEC.md`.

## Out of Scope
- Modifications to the Go implementation.
- Modifying the central `SPEC.md` document.
