# Design: Disambiguate `anonymous_entitlements` from `base_entitlements`

**Date:** 2026-05-25
**Issue:** [#3 — `EntitlementsChecker`: `anonymous_entitlements` semantic is floor-of-everyone (merges into authenticated bags), not anonymous-only — clarify intent + rename](https://github.com/kdex-tech/entitlements/issues/3)
**Scope:** All four ports (Go, Rust, Python, TypeScript)
**Target version:** `v0.2.0`

## Problem

`EntitlementsChecker` treats `anonymous_entitlements` as "floor-of-everyone": the patterns are merged into every caller's effective entitlement set, including authenticated callers presenting their own claims. The name strongly suggests "applies only to unauthenticated callers", which is what downstream consumers (e.g. `knowdb`) assumed. The mismatch between name and behavior is itself the bug.

The behavior is consistent across all four implementations:

- `rust/src/lib.rs:101-117` — `verify` unconditionally merges into the default scheme.
- `python/src/entitlements/__init__.py:62-67` — same upfront merge.
- `go/entitlements.go:288-306` — `hasParsedEntitlement` consults `anonymousPatterns` whenever the scheme being checked is the default scheme, regardless of caller state.
- `typescript/src/index.ts:242-262` — same shape as Go.

## Resolution

Introduce **two separate concepts** with distinct semantics, both layered on top of caller-supplied entitlements.

| Concept | Source | When applied | Scope |
|---|---|---|---|
| `anonymous_entitlements` | constructor arg (existing) | **Only** when caller's `user_entitlements` map is empty (no schemes, or every scheme's list empty) | Default scheme |
| `base_entitlements` | new builder setter (new) | **Always** (every verify call, regardless of caller) | Default scheme |

The `anonymous_entitlements` constructor argument keeps its name but its **semantic is corrected** to truly-anonymous-only. This is a runtime behavior change for existing operators who relied on the floor behavior; it is intentional and is the resolution to issue #3.

The new "floor-of-everyone" behavior is reachable via the new `base_entitlements` setter.

## Public API

Constructor signatures **stay unchanged** in every port to avoid breaking existing call sites. The new setter is fluent (returns the instance) and parses patterns eagerly at call time into the existing intern cache.

### Go

```go
// New method on EntitlementsChecker. Mirrors the existing WithLogger pattern.
func (ec *EntitlementsChecker) WithBaseEntitlements(patterns []string) *EntitlementsChecker
```

### Rust

```rust
// Consuming builder, idiomatic for Rust.
pub fn with_base_entitlements(mut self, patterns: Vec<String>) -> Self
```

### Python

```python
def with_base_entitlements(self, patterns: list[str]) -> "EntitlementsChecker":
    ...
```

### TypeScript

```typescript
withBaseEntitlements(patterns: string[]): this
```

### Setter semantics (shared across ports)

- **Replaces, does not append.** A subsequent call to the setter overwrites the prior list. Multiple calls are valid (the final call wins); callers needing to extend an existing list compose it themselves before calling.
- **Parses eagerly when the setter runs.** Patterns are pushed through the same parse/intern path as `anonymousPatterns` and stored as a sibling field (`basePatterns` / `base_patterns`). No per-verify-call parsing overhead.
- **Not safe for concurrent mutation with verify calls in flight.** The setter is intended for configuration during checker construction, not runtime reconfiguration while other goroutines/threads are verifying. Rust enforces this at the type level via `mut self`; the other ports document it and do not add locking.

## Matching algorithm (Approach 1)

The change centers on each port's per-pattern check helper (Go/TS: `hasParsedEntitlement`; Rust/Python: equivalent local function). The helper gains one parameter, `is_anonymous_caller`, computed once at the top of the public `verify`/`verifyEntitlements` entry point and threaded through the recursion.

### Helper logic

```
hasParsedEntitlement(entitlementList, scheme, requirement, isAnonymousCaller) -> bool:
    for ep in entitlementList:                       # caller's own
        if ep.matches(requirement): return true

    if scheme == default_scheme:
        for ep in basePatterns:                      # always applied
            if ep.matches(requirement): return true
        if isAnonymousCaller:
            for ep in anonymousPatterns:             # only when caller is anonymous
                if ep.matches(requirement): return true

    return false
```

### `isAnonymousCaller` computation

Computed once at the top of `verifyEntitlements` (and the parsed/resource variants):

```
isAnonymousCaller = parsedEntitlements.patterns has no schemes
                    OR every scheme's pattern list is empty
```

The "presence of scheme" guard in `satisfiesAndRequirements` expands accordingly: a scheme requirement set is reachable when **either** the user has entitlements for that scheme, **or** the scheme is the default scheme and (`basePatterns` is non-empty, **or** `anonymousPatterns` is non-empty and `isAnonymousCaller`).

### Resource identity path

`verifyResourceEntitlements` constructs an identity requirement and checks it via `hasParsedEntitlement` on the default scheme. Under the new semantic:

- An anonymous caller can satisfy the identity via their own entitlements, `basePatterns`, or `anonymousPatterns`.
- An authenticated caller can satisfy the identity via their own entitlements or `basePatterns` only.

`grantReadyByDefault` remains orthogonal: when true, it short-circuits the identity check regardless of caller state.

### Rust and Python structural cleanup

The current Rust and Python implementations merge entitlements upfront in `verify` and rely on the merged structure for matching. To support the new semantic cleanly (and to converge with Go's more efficient pre-parsed shape), both ports refactor to mirror Go's design:

- Parse user entitlements into a map of `scheme -> Vec<Pattern>` / `dict[str, list[Pattern]]` once.
- Run the matching logic against parsed user patterns + the sibling `base_patterns` + `anonymous_patterns` fields, with the per-pattern helper consulting the right lists based on scheme and `is_anonymous_caller`.
- No runtime merge cloning per verify call.

Behavior parity across ports is the test contract; the structural alignment is a maintenance win, not a requirement.

## Tests

Per-port test additions and updates (mirrored across all four ports — same scenarios, idiomatic test style for each):

1. **Anonymous gate — positive:** empty `user_entitlements` + requirement satisfiable only by `anonymousPatterns` → satisfied.
2. **Anonymous gate — negative (regression test for issue #3):** non-empty `user_entitlements` (any scheme, any pattern) + requirement satisfiable only by `anonymousPatterns` → **not** satisfied.
3. **Base — always applies:** authenticated caller with own entitlements + requirement satisfiable only by `basePatterns` → satisfied.
4. **Base — applies to anonymous too:** empty `user_entitlements` + requirement satisfiable only by `basePatterns` → satisfied.
5. **Both bags coexist:** checker configured with both `anonymousPatterns` and `basePatterns`; authenticated caller is satisfied by `basePatterns` but not by `anonymousPatterns`.
6. **Resource identity path:** the new semantic carries through `verifyResourceEntitlements` — anonymous caller can satisfy identity via either bag; authenticated caller via base or own.
7. **Builder replaces:** calling the base-entitlements setter twice leaves only the second list.

Existing test updates:

- `rust/src/lib.rs:240-244` (`test_verify` → "Anonymous match" block with an authenticated caller): assertion flips from positive to negative. This is the visible smoking-gun behavior change.
- Equivalent existing tests in Go/Python/TypeScript test files that codify the floor-of-everyone behavior of `anonymous_entitlements`: updated or moved into the new `basePatterns`-driven scenarios.

## Documentation

- **`SPEC.md`** — "Anonymous Entitlements" section: clarify the activation trigger ("user entitlements map is empty"). Add new "Base Entitlements" section describing the floor concept and the builder setter as the standard way to opt in.
- **Per-port READMEs** (`typescript/README.md`, and add Rust/Python READMEs if missing): show both bags in usage examples, call out that `anonymous_entitlements` only fires for unauthenticated callers.
- **Inline docs** (Go doc comments, rustdoc, Python docstrings, TSDoc): document the new semantic on the constructor argument and on the new setter.

## Versioning and release

- Bump all four packages to `v0.2.0`. Minor bump under pre-1.0 signals the runtime behavior change of `anonymous_entitlements`.
- Single PR landing all four ports together (cross-port consistency rule from repo `CLAUDE.md`).
- Tagging `v0.2.0` triggers the existing CI release flow: GitHub Release, parallel `go/v0.2.0` tag, crates.io publish, PyPI publish, npm publish.
- `VERSION` file at repo root updated to `0.2.0`.
- PR description references and closes issue #3.

## Out of scope

- Changes to constructor signatures.
- Changes to wildcard, short/medium/long, or opaque pattern matching rules.
- Changes to `grantReadyByDefault`.
- Per-scheme base entitlements (default scheme only; YAGNI).
- Deprecation warnings on `anonymous_entitlements` (it stays, with corrected semantic).
- Any change to `SPEC.md` beyond the two clarified sections.
