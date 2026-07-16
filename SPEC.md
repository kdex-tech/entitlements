# Specification: kdex-entitlements

## Core Concept
`kdex-entitlements` is a language-agnostic entitlements checking library. It handles the verification of user entitlements against security requirements using a structured pattern matching system.

## Entitlement Pattern Forms
Entitlements and requirements can be represented in four forms:
- **Long Form**: `<resource>:<resourceName>:<verb>`
  - Matches a specific action on a specific resource instance.
  - Example: `pages:/foo:read`
- **Medium Form**: `<resource>::<verb>`
  - Shorthand for `<resource>:*:<verb>`.
  - Matches a specific action on all instances of a resource type.
  - Example: `pages::read`
- **Short Form**: `<resource>:<verb>`
  - Shorthand for `<resource>:*:<verb>`.
  - Matches a specific action on all instances of a resource type.
  - Example: `pages:read`
- **Opaque Form**: `<string>`
  - A simple string that does not contain colons (or does not follow the pattern structure).
  - Matches only exactly.
  - Example: `admin`, `email`

### Wildcards
- `*` can be used as a `<resourceName>` to represent all instances of a resource.
- `all` can be used as a `<verb>` in an **entitlement** to represent all actions on a resource. A requirement for `read` is satisfied by an entitlement for `all`.

### Requirement Forms

Entitlement forms above describe what a caller **holds**. A **requirement** —
the thing a caller must satisfy — is additionally constrained:

- **Concrete**: `<resource>:<resourceName>:<verb>`. Satisfied by a held wildcard
  or an exact `resourceName` match.
- **Placeholder**: `<resource>:{<key>}:<verb>`. A hole that MUST be bound to a
  concrete value before verification. A `resourceName` is a placeholder iff it
  starts with `{`, ends with `}`, and is longer than two characters — so `{}` is
  a literal, not a placeholder. Binding substitutes the value and then matches
  the concrete result.
- **Opaque**: `<string>` with no colons (or not matching the pattern structure).
  Exact match only, and therefore never satisfied by a wildcard grant. This is
  the correct form for a context-less capability — one with no resource instance
  to name, such as "create a store".

**Wildcards are a held-side concept.** A `resourceName` of `*` or empty is
meaningful in an entitlement (it grants authority over the class) but is
ambiguous in a requirement, where it has historically meant both "substitute the
resource being addressed" and "authority over the class as a whole". Placeholders
now carry the former meaning, so strict mode rejects the latter spelling.

**Strict mode** (`WithStrictRequirements` / `with_strict_requirements` /
`withStrictRequirements`) rejects a requirement whose `resourceName` is `*` or
empty — including the short (`<resource>:<verb>`) and medium
(`<resource>::<verb>`) forms, which are wildcards by definition. It defaults to
**false**; a future major version defaults it to **true**. It never applies to
entitlements, where wildcards remain legal.

Held-side placeholders are meaningless and are treated as literal text.

### Binding

`bindRequirements(requirements, binding)` substitutes each placeholder
`resourceName` with its bound value and returns the rewritten requirements.

- A requirement set containing no placeholder is returned unchanged.
- A placeholder with no entry in `binding` is an **error** from
  `bindRequirements`, never a pass. This is the point of the form: an author who
  declares `{vector_store_id}` on a route whose enforcing layer supplies nothing
  gets a loud configuration error rather than a silent admit.

  **Corollary — only declare placeholders the enforcing layer can resolve.** A
  requirement is a contract with whoever verifies it, and a placeholder is a
  promise that that layer can supply the value. Some identities are resolvable
  only by a *different* layer: an API addressed by `file_id` may be checked
  against the file's owning store, a mapping that lives in the enforcer's data
  rather than in the request. No caller context closes that gap. Naming such an
  identity in a requirement makes `bindRequirements` fail every time, because
  the promise cannot be kept — the error is the contract working, not an
  obstacle to route around. Declare requirements the verifying layer can
  resolve; publish the rest through whatever channel your enforcing layer uses
  to advertise what a caller must hold, where nothing parses them and prose is
  fine.
- A placeholder bound to `""` or `*` is an **error**. Those are the wildcard
  spelling, not a concrete resource name: binding one would silently widen the
  requirement to the whole resource class. A binder that could not resolve a
  value must fail like an unbound placeholder rather than widen the gate.
- A placeholder bound to a value containing `:` is an **error**. Binding
  constructs the resulting pattern directly in Go and TypeScript, but Rust and
  Python have no pre-parsed type and must re-emit it as a string that is then
  re-parsed — a bound value with a `:` would re-split into the wrong shape
  there and silently become opaque, while Go/TypeScript would keep matching.
  Rejecting the colon in every port, rather than only fixing the two that
  re-parse, is what keeps `bindRequirements` producing identical results
  across all four.
- An unbound placeholder that reaches verification **without** passing through
  `bindRequirements` behaves by mode. With strict **off** (the default) it is an
  ordinary literal resource name: it fails to match a specific grant, but a held
  wildcard still matches it — this is the pre-existing behavior the default
  preserves. With strict **on** it matches nothing at all, which is the
  fail-closed backstop for a caller that skipped binding.
- Binding keys that match no placeholder are ignored, so a caller may pass a
  superset without knowing the requirement.
- Multiple distinct placeholders in one requirement set are permitted; each is
  bound by name. An unbound one among them still errors.
- Under strict mode, a wildcard `resourceName` in a requirement is an error here.

Binding operates on whatever each port's verification consumes: the pre-parsed
type in Go and TypeScript, raw `Requirements` in Rust and Python (which parse
inline and have no pre-parsed type).

`wildcardRequirements(requirements)` returns the requirement strings whose
`resourceName` is a wildcard — the spellings strict mode rejects outright.
Results are de-duplicated and in first-seen order.

It is a migration inventory, not a complete strict-mode pre-flight: strict also
rejects an unbound placeholder at verification time, which this query does not
report (a placeholder is the migration's destination, not a target). An empty
result means no requirement still uses a wildcard spelling.

It is a pure function so each consumer may log, count, or fail in its own
idiom. Use it to inventory what remains to migrate before enabling strict mode.

All language ports MUST produce identical results.

### Encoding
The `resourceName` should be URL-encoded (e.g., `url.PathEscape` in Go) if it contains colons `:` to prevent misinterpretation during pattern splitting.

## Data Structures

### Entitlements
A map where keys are security schemes (e.g., "bearer", "oauth2") and values are lists of entitlement strings.
- Example: `{"bearer": ["pages:read", "books:all"], "oauth2": ["email"]}`

### Requirements
A list of maps representing alternative security requirement sets (OR'd). Within each map, all schemes and their associated requirement strings must be satisfied (AND'd).
- Example: `[{"bearer": ["pages:read"]}, {"oauth2": ["email"]}]` means (bearer has pages:read) OR (oauth2 has email).

## Verification Logic

### Pattern Matching Rules
1. **Exact Match**: If the entitlement string exactly matches the requirement string, it is satisfied.
2. **Opaque Match**: If either the entitlement or the requirement is in opaque form, only an exact match satisfies it.
3. **Structured Match**:
   - **Resource**: The resource type in the entitlement must match the resource type in the requirement.
   - **Verb**: The verb in the entitlement must match the verb in the requirement, OR the entitlement verb must be `all`.
   - **Resource Name**:
     - **Under strict mode**, a requirement resource name that is a wildcard
       (`*` or empty) or an unbound placeholder matches **nothing**. This check
       takes precedence over the entitlement-side wildcard rule below — a held
       wildcard does not rescue an illegal or unresolved requirement.
     - If the entitlement resource name is empty or `*`, it matches all resource names in requirements.
     - If the requirement resource name is empty or `*`, it matches all resource names in entitlements.
       **Deprecated**: this direction is what strict mode rejects. See *Requirement Forms*.
     - Otherwise, the resource names must match exactly.

### Verification Flow
1. If requirements are empty, verification succeeds.
2. A requirement set (one map in the list) is satisfied if:
   - For every scheme in the requirement set:
     - The user has entitlements for that scheme.
     - EVERY requirement string for that scheme is satisfied by at least one of the user's entitlement strings for that same scheme.
3. The overall verification succeeds if ANY requirement set is satisfied.

### Attenuation (Dominance)

Attenuation is the inverse-direction check used when **minting a narrowed capability**: it decides whether a **held** entitlement is equal to or **broader than** a **requested** one, so a derived token can only reduce authority, never expand it. Unlike Pattern Matching (where a wildcard `<resourceName>` matches on **either** side), dominance honors a wildcard **only on the held side**.

A held entitlement `H` **dominates** a requested entitlement `R` if and only if:

1. `H` and `R` are the exact same string; or
2. both are in opaque form and are equal; or
3. both are in structured form and ALL of:
   - `resource(H) == resource(R)`, AND
   - `verb(H) == all` OR `verb(H) == verb(R)`, AND
   - `resourceName(H)` is a wildcard (`*` or empty) OR `resourceName(H) == resourceName(R)`.

Mixed opaque/structured forms never dominate. A **specific** held grant does NOT dominate a **wildcard** request (e.g. `vector_stores:X:write` does not dominate `vector_stores:*:write` or `vector_stores::write`) — this is what prevents privilege escalation during minting. A **wildcard** held grant DOES dominate a specific request. A held verb of `all` dominates any requested verb; a requested verb of `all` is dominated only by a held verb of `all`.

`verifyAttenuation(held[], requested[])` returns the first requested entitlement not dominated by any held entitlement (or none / `null` if every requested entitlement is dominated).

All language ports MUST produce identical results: Go `Dominates` / `VerifyAttenuation`, Rust `Pattern::dominates` / `verify_attenuation`, Python `Pattern.dominates` / `verify_attenuation`, TypeScript `dominates` / `verifyAttenuation`.

### Compaction

Compaction prunes an entitlement **array** to the minimal set that grants the
same authority. It is the array-normalization counterpart to attenuation: use it
to shrink a caller's grant list before minting a narrowed token, persisting it,
or embedding it in a claim.

`Compact(entitlements[])` returns the subset with every entry removed that is
**strictly dominated** by another entry (some other entry dominates it and it
does not dominate that entry back), plus exact and equivalent-form duplicates
(e.g. `pages:read`, `pages::read`, and `pages:*:read` collapse to one). It is
defined purely in terms of the dominance relation above — never request-time
matching — so a wider grant (`functions::read`) prunes the narrower ones it
covers (`functions:/api/v1/files:read`) but never the reverse.

Guarantees:
- **Authority-preserving (lossless).** The compacted array authorizes exactly
  the same requests as the input; no wider scope is ever synthesized.
- **Order-preserving.** Survivors appear in first-seen order, with their
  original strings unchanged.
- **Idempotent.** `Compact(Compact(x))` equals `Compact(x)`.

Opaque and malformed scopes collapse only by exact equality, consistent with
dominance.

All language ports MUST produce identical results: Go `Compact`, Rust
`Pattern::compact`, Python `compact`, TypeScript `compact`.

### Anonymous Entitlements
An `EntitlementsChecker` can be configured with a list of "anonymous" patterns. These patterns are automatically granted to callers **only when the caller's `Entitlements` map is empty** (no schemes present, or every scheme's list is empty). They are applied under the `defaultScheme`. An authenticated caller — one who passes any entitlements at all — does **not** receive the anonymous bag.

### Base Entitlements
An `EntitlementsChecker` can additionally be configured with a list of "base" patterns via a builder-style setter (`WithBaseEntitlements` / `with_base_entitlements` / `withBaseEntitlements`). Base patterns are applied under the `defaultScheme` to **every** caller — authenticated or anonymous — and form a floor of grants that every request receives. Calling the setter again replaces the previous list.

Use anonymous entitlements for grants that should only widen the unauthenticated surface. Use base entitlements for grants that should always apply regardless of caller identity.

### Resource-Specific Verification
A specialized verification that automatically adds an "identity requirement" for a specific resource instance:
- Identity Requirement: `<resource>:<encodedResourceName>:<verb>` (default verb is `read`).
- User must satisfy this identity requirement AND the provided additional requirements.

## Implementation Requirements
- **Performance**: Implementations should prioritize performance, potentially using pattern interning/caching and pre-parsing of entitlements and requirements.
- **Coverage**: Maintain >80% test coverage.
- **Concurrency**: The entitlements checker should be thread-safe for concurrent verification calls.
