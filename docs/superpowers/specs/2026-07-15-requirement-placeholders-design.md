# Design: Requirement-side placeholders — bind `{param}`, outlaw wildcards

**Date:** 2026-07-15
**Scope:** All four ports (Go, Rust, Python, TypeScript)
**Target versions:** `v0.4.0` (additive), `v1.0.0` (breaking)
**Issue:** [kdex-tech/entitlements#4](https://github.com/kdex-tech/entitlements/issues/4)

## Problem

At request time the library honors a `resourceName` wildcard **on either side**
(`go/entitlements.go:572`):

```go
// Empty string or "*" in either side means all resources
if ep.resourceName == "" || ep.resourceName == "*" || req.resourceName == "" || req.resourceName == "*" {
    return true
}
```

So a requirement of `vector_stores:*:write` is satisfied by a grant over *any
single* store. There is consequently no way to express *"the caller must hold
authority over the resource class as a whole"* as a request-time requirement.
Reproduced against `v0.3.0`:

| held | required | result |
| --- | --- | --- |
| `vector_stores:vs_alice:all` | `vector_stores:*:write` | **PASS** ← the defect |
| `vector_stores::all` | `vector_stores:*:write` | PASS (correct) |

A principal owning **zero** stores is correctly denied, while one owning a
single store is admitted. "May create" leaks out of "already owns."

`Dominates` (`go/entitlements.go:480`) already implements the strict rule —
*"a wildcard is honored ONLY on the held side"* — so the two predicates give
opposite answers for the same string pair.

### Root cause: `*` is doing double duty

Two incompatible meanings share one glyph on the requirement side:

1. **Placeholder** — *"substitute the identity of the resource being addressed."*
   Used where the enforcing layer cannot interpolate a request parameter, so
   `resource:{id}:verb` is flattened to `resource:*:verb`.
2. **Universal** — *"authority over the class."* Used where there is no identity
   to substitute (create / collection-level operations).

Matching **must** stay permissive for (1), or a holder of `store:id_x:read`
could not pass a `store:*:read` gate to read their own store. That necessary
permissiveness is exactly what makes (2) unenforceable.

## Evidence: what `*` means in the wild

Surveyed across the only two consumers today — `knowdrive-site/k8s/dev` (CRs)
and `multi-modal-store/src` (knowdb). Every requirement set pairs concrete
`functions:<basePath>:<verb>` scopes with **exactly one** glob on a *different*
resource:

```yaml
# function_knowdb_ingest.yaml:204
- bearer: ["functions:/api/v1/ingest:read", "functions:/api/v1/ingest:create", "vector_stores:*:write"]
```

That single glob carries three distinct meanings:

| requirement | actual meaning | can the enforcing layer bind it? |
| --- | --- | --- |
| `vector_stores:*:read` on `/vector_stores/{vector_store_id}/search` | the store in the path | **yes** — `r.PathValue("vector_store_id")` |
| `vector_stores:*:write` on `/ingest` | the store in `X-Vector-Store-Id` | **yes** — a header |
| `vector_stores:*:read` on `/files/{file_id}` | the *file's* store | **no** — a row property |
| `vector_stores:*:own` on `POST /vector_stores` | genuine universal (create) | **n/a** — nothing to bind |
| `users:*:admin` on the backoffice page | genuine universal | **n/a** — nothing to bind |

knowdb already encodes the distinction correctly in its own metadata
(`src/mcp/tools.rs:95`):

> *"A `{placeholder}` denotes the resource resolved at call time; `*` is the
> literal wildcard used for unscoped surfaces."*

Hence `vector_stores:{vector_store_id}:own` (delete) versus `vector_stores:*:own`
(create). **The information exists at the source and is destroyed by flattening
to `*` on the way into a CR.** This design restores it.

## Resolution: the requirement grammar

Give the placeholder its own token. Then `*` collapses to a single meaning, and
the requirement side no longer needs a wildcard at all.

| requirement form | meaning | satisfied by |
| --- | --- | --- |
| `resource:name:verb` | concrete | held wildcard, or exact `name` |
| `resource:{param}:verb` | placeholder — **must** be bound | evaluated against the bound value |
| `capability` (opaque) | context-less capability | exact match only |
| `resource:*:verb`, `resource::verb`, `resource:verb` | — | **illegal as a requirement** (`v1.0.0`) |

**The held side is unchanged.** Wildcards remain valid and meaningful in grants
— that is what a class-wide grant *is*. This makes the asymmetry explicit and
aligns request-time matching with `Dominates`'s existing held-side-only rule:
after `v1.0.0`, the disagreeing input is unrepresentable rather than
reinterpreted.

Context-less requirements move to the **opaque** form, which already matches by
exact string only and is therefore immune to a wildcard grant. That mechanism
needs no library change — it works on `v0.3.0` today — but granting opaque
scopes ergonomically needs a kdex-crds change (see Companion tracks).

### Why not positional clamping

`Verify(held, req, Clamp("vs_abc"))` binds by position, so a set with two globs
(`["vector_stores:*:write", "files:*:read"]`) binds by *list order* — reordering
the scope list in a CR silently changes authorization. Named binding has no such
failure mode, and round-trips with the `{vector_store_id}` metadata knowdb
already publishes.

### Why not opaque alone

Opaque cannot express the contextual cases — ~15 live operations in
`function_knowdb_vector_stores.yaml` name the store in the URL path. Opaque also
severs *legitimate* wildcard authority (a provisioner holding
`vector_stores::own` fails an opaque `vector_stores_create` gate). It is the
right tool precisely where severing blanket authority is the goal.

## Public API

Binding is separated from matching. In Go and TypeScript `ParsedRequirements`
are parsed once per route and cached, while a binding is per-request — so
binding cannot be folded into parsing, and matching stays on the hot path with
an unchanged signature.

```
Bind(requirements, binding) -> requirements'   // per-request; returns an error
Verify(entitlements, requirements')  -> bool   // unchanged
```

Requirement sets containing no placeholder return the receiver unchanged (a
`hasPlaceholder` flag is precomputed where a parsed type exists), so unaffected
routes pay nothing.

**Bind operates on whatever its port's `Verify` consumes.** Only Go and
TypeScript have `ParsedEntitlements` / `ParsedRequirements`; Rust and Python
parse inline inside `verify()` and have no pre-parsed types. Adding them is out
of scope and would buy nothing — a port that re-parses per call pays nothing
extra to bind raw `Requirements`. Method names still map 1:1 per the
cross-port convention; only the argument type follows the port.

| port | binds | returns |
| --- | --- | --- |
| Go | `ParsedRequirements` | `(ParsedRequirements, error)` |
| TypeScript | `ParsedRequirements` | `ParsedRequirements` (throws) |
| Rust | `&Requirements` | `Result<Requirements, BindError>` |
| Python | `Requirements` | `Requirements` (raises) |

### Where strict fires

**Not at parse time.** Go's `ParseRequirements` and TypeScript's
`parseRequirements` return a value with no error channel; giving them one is a
breaking signature change and would defeat `v0.4.0`'s additivity. Strict is
enforced in two places instead:

1. **`BindRequirements` returns `ErrWildcardRequirement`** — it already owns an
   error channel, and it is the per-request call every consumer makes once the
   binding step lands. This is the loud path.
2. **`Verify` treats a wildcard requirement as unsatisfiable** when strict is on
   — a fail-closed backstop for a consumer that skips `Bind` entirely. `Verify`
   keeps its `bool` signature; strict simply makes the requirement match nothing.

With strict off (the `v0.4.0` default) neither fires, so behavior is identical
to `v0.3.0`.

### Go

```go
type Binding map[string]string

// BindRequirements substitutes each {param} resourceName with its bound value.
// Returns ErrUnboundPlaceholder if any placeholder has no entry in b.
// Returns reqs unchanged when reqs contains no placeholder.
func (ec *EntitlementsChecker) BindRequirements(reqs ParsedRequirements, b Binding) (ParsedRequirements, error)

// WithStrictRequirements rejects wildcard resourceNames on the requirement
// side. Default false in v0.4.0, true in v1.0.0.
func (ec *EntitlementsChecker) WithStrictRequirements(strict bool) *EntitlementsChecker

// WildcardRequirements returns the requirement strings whose resourceName is a
// wildcard (`*`, empty, or the short/medium forms) — i.e. exactly what strict
// mode will reject. Empty means strict-clean. Pure; the caller decides whether
// to log, count, or fail.
func (ec *EntitlementsChecker) WildcardRequirements(reqs Requirements) []string

var ErrUnboundPlaceholder = errors.New("entitlements: unbound placeholder in requirement")
var ErrWildcardRequirement = errors.New("entitlements: wildcard resourceName is not allowed in a requirement")
```

### Rust

```rust
pub type Binding = std::collections::HashMap<String, String>;

impl EntitlementsChecker {
    // Rust has no pre-parsed type; binds raw Requirements.
    pub fn bind_requirements(&self, reqs: &Requirements, b: &Binding)
        -> Result<Requirements, BindError>;
    pub fn with_strict_requirements(self, strict: bool) -> Self;
    pub fn wildcard_requirements(&self, reqs: &Requirements) -> Vec<String>;
}

pub enum BindError { UnboundPlaceholder(String), WildcardRequirement(String) }
```

### Python

```python
# Python has no pre-parsed type; binds raw Requirements.
def bind_requirements(self, requirements: Requirements, binding: dict[str, str]) -> Requirements:
    """Raises UnboundPlaceholderError / WildcardRequirementError."""

def with_strict_requirements(self, strict: bool) -> "EntitlementsChecker": ...

def wildcard_requirements(self, requirements: Requirements) -> list[str]: ...
```

### TypeScript

```ts
bindRequirements(reqs: ParsedRequirements, binding: Record<string, string>): ParsedRequirements
withStrictRequirements(strict: boolean): EntitlementsChecker
wildcardRequirements(reqs: Requirements): string[]
// throws UnboundPlaceholderError | WildcardRequirementError
```

## Semantics

**Placeholder recognition.** A requirement's `resourceName` is a placeholder iff
it starts with `{` and ends with `}`. The enclosed name is the binding key.
`{` and `}` are reserved in requirement resourceNames; no other escaping exists.
Verified safe against the corpus: function basePaths match `^/\w+/\w+`, page
paths are URL paths, store ids are `vs_<hex>` — none can contain `{`.

**Held-side placeholders are meaningless** and are treated as literal text. A
grant is never bound; only requirements are.

**Unbound is an error, never a pass.** This is the crux of #4: an author who
writes `{vector_store_id}` on a route whose binder supplies nothing gets a loud
configuration error, not a silent admit and not an anti-enumeration 404.

**Multiple distinct placeholders are permitted.** With named binding there is no
ambiguity, and the map makes N free. Only one is used today; forbidding N would
be code written to prevent something that costs nothing. An unbound one among
them still errors.

**Binding keys with no matching placeholder are ignored**, so a binder may pass
a superset (e.g. every path value it resolved) without knowing the requirement.

**Strict mode** rejects a requirement whose `resourceName` is `*` or empty —
including the short (`resource:verb`) and medium (`resource::verb`) forms, which
are wildcards by definition. It never applies to `parsePattern`, which is shared
with entitlements, where wildcards stay legal. See *Where strict fires* above
for the two enforcement points.

**`Dominates` and `Compact` are untouched.** They operate on mint-time
attenuation, not requirements, and already implement held-side-only wildcards.

## Staging

| version | change | breaks |
| --- | --- | --- |
| `v0.4.0` | `{param}` + `BindRequirements` + `WithStrictRequirements` (default **false**) + `WildcardRequirements` | nothing — no existing string contains `{` |
| `v1.0.0` | `WithStrictRequirements` defaults **true**; setter retained as an escape hatch | requirement-side wildcards |

`v0.4.0` is additive by construction. `WildcardRequirements` gives every cluster
an inventory of exactly what still needs migrating, so `v1.0.0` is a flip
performed once that inventory reaches zero — not an audit-and-hope.

The inventory is a **pure function, not a log line**: only the Go port has a
logger (`ec.log`), so a log-based warning would ship a Go-only migration story
and violate the cross-port parity rule. Returning offenders lets each consumer
log, count, or fail in its own idiom, and makes the migration signal testable.
Consumers call it where requirements are parsed — once per route at mux-build
time, not per request.

**`{param}` is already fail-closed on `v0.3.0`.** A `{vector_store_id}`
resourceName parses today as a *literal*, so it denies per-resource holders and
still admits wildcard holders. The library therefore cannot become *less* safe at
any point in this migration; the only risk is under-permit, which is why the
cross-repo order below matters.

### Cross-repo order (each step independently deployable, none breaking)

1. **entitlements `v0.4.0`** — additive.
2. **host-manager** — supply bindings at check sites. No-op until a CR uses `{param}`.
3. **kdex-crds + host-manager** — opaque grants. Additive.
4. **roles** — grant the opaque capabilities. Additive.
5. **CRs** — migrate `*` → `{param}` or opaque. Both mechanisms live by now.
6. **entitlements `v1.0.0`** — flip strict. Nothing depends on wildcards anymore.

Reversing 2↔5 fails per-store users closed on ingest; reversing 5↔6 errors every
CR at once.

## Tests

Per port, mirroring `SPEC.md` scenarios (tests are duplicated by intent, not
literal translation):

- **Parse:** `{vector_store_id}` recognized as a placeholder; `{` mid-string is
  not; `{}` (empty key) is not a placeholder — it is a literal resourceName;
  held-side `{x}` stays literal.
- **Bind:** substitution yields a concrete requirement; no-placeholder set returns
  the receiver unchanged; superset binding ignored; multi-placeholder binds all.
- **Bind errors:** unbound placeholder errors; strict mode errors on `*`, empty,
  short and medium forms.
- **Inventory:** `WildcardRequirements` returns exactly the strings strict mode
  rejects, and empty for a strict-clean set.
- **The #4 matrix** (the regression that motivates this):

  | held | required | expect |
  | --- | --- | --- |
  | `vector_stores:vs_alice:all` | `{vector_store_id}` bound `vs_alice` | pass |
  | `vector_stores:vs_alice:all` | `{vector_store_id}` bound `vs_bob` | **deny** |
  | `vector_stores::all` | `{vector_store_id}` bound `vs_bob` | pass |
  | `vector_stores:vs_alice:all` | `vector_stores:*:write` (strict) | **error** |
  | `vector_stores::all` | opaque `vector_stores_create` | deny |

- **Unchanged:** every existing test passes on `v0.4.0` with strict off.

## Documentation

- `SPEC.md` — new *Requirement Forms* section defining the grammar; amend
  *Pattern Matching Rules* rule 3 (resourceName) to state that wildcards are
  honored on the held side only and that requirement-side wildcards are rejected
  in strict mode; note that the *Attenuation* section's asymmetry is now the
  universal rule rather than an exception.
- `go/entitlements.go` — the canonical inline docs; port to the other three.
- `README.md` — `{param}` in the forms table.

## Versioning and release

`VERSION` → `0.4.0`, tagged `v0.4.0` + `go/v0.4.0` (both required; Go subdir
module resolution needs the prefixed tag). `v1.0.0` ships separately once the
migration drains. The Go module path is unaffected — `v1` needs no `/v2` suffix.

## Companion tracks (not this repo)

Filed separately; none blocks `v0.4.0`.

- [recoursellm-group/multi-modal-store#360](https://gitlab.com/recoursellm-group/multi-modal-store/-/work_items/360) — knowdb: remove the `system` fallback
- [recoursellm-group/multi-modal-store#361](https://gitlab.com/recoursellm-group/multi-modal-store/-/work_items/361) — knowdb: the `Wildcard` default synthesizes `*`
- [kdex-tech/kdex-crds#15](https://github.com/kdex-tech/kdex-crds/issues/15) — kdex-crds: first-class opaque grants

- **knowdb — remove the `system` fallback.** `resolve_requirement`
  (`src/auth/entitlements.rs:757`) defaults an unresolved store to `system` on 9
  `ROUTE_AUTH` routes, and `Some(SYSTEM_VECTOR_STORE_ID)` does the same for 6 MCP
  write tools. Addressing a store becomes explicit; `system` stays a store, named
  deliberately. Seeding (`seed_from_dir`), the `vector_stores:system:read` grant,
  the `canonical_resource_name` exception (#311), and skill discovery
  (`src/mcp/skills.rs:130` targets `system` explicitly already) are all unaffected.
  **This unblocks `unbound ⇒ error`:** with no default, `/ingest`'s
  `vector_stores:{vector_store_id}:write` is always bindable, so the library rule
  needs no exception, no declared-default syntax, and no policy in the matcher.
- **knowdb — the `Wildcard` default.** The same function synthesizes `"*"` for 39
  routes — knowdb's own instance of #4 (`POST /v1/vector_stores` → `vector_stores:*:own`).
  Needs its own triage: context-less → opaque, row-aware → opaque with downstream
  scoping, path-scoped → `{param}`.
- **kdex-crds — first-class opaque grants.** `PolicyRule` always emits
  `fmt.Sprintf("%s:%s:%s", …)`, so a colon-less opaque grant is unreachable. The
  only current route is a `resourceName` containing a colon (→ 4 parts → opaque),
  which PolicyRule's own doc tells authors to URL-encode away — an author who
  complies silently gets a *structured* grant instead. A dedicated `scopes: []`
  field is the honest fix.

## Out of scope

- Positional or resource-keyed clamping (see *Why not positional clamping*).
- Row-aware requirements (`vector_stores:{file's vector_store_id}:read`). No
  request parameter can name the store; the gate is honestly coarse and the
  backend scopes per row.
- Escaping literal `{`/`}` in a requirement resourceName.
- Any change to `Dominates`, `VerifyAttenuation`, or `Compact`.
- Anonymous/base entitlement semantics.
