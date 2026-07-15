# Requirement-Side Placeholders (v0.4.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `{param}` placeholder binding, an opt-in strict mode, and a wildcard inventory helper to all four ports — additively, changing no existing behavior.

**Architecture:** A requirement's `resourceName` may be a placeholder (`{name}`), bound to a concrete value at check time via a new `BindRequirements` call that sits between parsing and verification. Binding is separated from matching so `Verify` keeps its `bool` signature on the hot path while `Bind` owns the error channel. An opt-in `WithStrictRequirements` flag makes wildcard resourceNames illegal *as requirements* (held-side wildcards are always legal); it defaults **false** in v0.4.0, so this release is behavior-identical to v0.3.0 for every existing caller.

**Tech Stack:** Go 1.x (`go/`, module `github.com/kdex-tech/entitlements/go`), Rust (`rust/`, crate `kdex-entitlements`), Python (`python/`, src layout under `src/entitlements/`), TypeScript (`typescript/`, ESM-only, vitest).

**Spec:** `docs/superpowers/specs/2026-07-15-requirement-placeholders-design.md`
**Issue:** [kdex-tech/entitlements#4](https://github.com/kdex-tech/entitlements/issues/4)

## Global Constraints

- **`SPEC.md` is the contract.** It changes first (Task 1); all four ports implement it. Drift between ports is a bug.
- **All four ports change in this plan.** Never land a behavior change in one language without the other three.
- **Names map 1:1, case is idiomatic:** Go `BindRequirements`, Rust `bind_requirements`, Python `bind_requirements`, TypeScript `bindRequirements`. Same for `WithStrictRequirements` / `with_strict_requirements` / `withStrictRequirements` and `WildcardRequirements` / `wildcard_requirements` / `wildcardRequirements`.
- **v0.4.0 is additive.** No existing signature changes. No existing test changes. `WithStrictRequirements` defaults **false**. If an existing test needs editing, stop — that is a design violation, not a test problem.
- **Placeholder grammar:** a requirement `resourceName` is a placeholder **iff** it starts with `{`, ends with `}`, **and has length > 2**. `{}` is a literal, not a placeholder.
- **A placeholder bound to `""` or `"*"` is an error** — `ErrInvalidBoundValue` (Go) / `BindError::InvalidBoundValue` (Rust) / `InvalidBoundValueError` (Python, TypeScript). Those are the wildcard spelling, not concrete resourceNames: binding one would silently widen the requirement to the whole class, which is the same escalation the placeholder form exists to prevent. A binder that could not resolve a value must fail like an unbound placeholder. *(Added during execution after a Task 2 review finding; approved by the human. Already implemented in Go — Tasks 4-6 must mirror it.)*
- **Wildcard resourceName** means `""` or `"*"`. Note Go/TS parse the short form (`a:b`) to `resourceName: ""` but **Rust/Python parse it to `name: "*"`** — both must be treated as wildcards.
- **Held-side placeholders are literal text.** Only requirements are bound.
- **Strict scans before it binds — two passes, not one.** Every port's bind must sweep *all* requirements for a wildcard resourceName and raise **before** resolving any placeholder. A single interleaved pass makes the reported error depend on list position: `["x:{id}:write", "x:*:read"]` raises unbound-placeholder, and the same list reversed raises wildcard-requirement. Both fail closed, but the *variant* differs — which is cross-port drift, and a caller branching on it breaks. *(Found empirically during Task 4 review: Go and TypeScript two-pass; Rust and Python interleaved. Approved for fixing in all four.)*
- **Never touch** `Dominates`/`dominates`, `VerifyAttenuation`/`verify_attenuation`, or `Compact`/`compact`. They govern mint-time attenuation, not requirements.
- **Do not add `ParsedRequirements` to Rust or Python.** They parse inline; binding raw `Requirements` costs them nothing.
- **Coverage target >80%** per `SPEC.md`; each port has `make coverage`.
- Use `rg` (ripgrep), not `grep`.

---

### Task 1: `SPEC.md` — the contract

**Files:**
- Modify: `SPEC.md`

**Interfaces:**
- Consumes: nothing.
- Produces: the normative text every port implements. Tasks 2–6 cite it.

- [ ] **Step 1: Add a "Requirement Forms" section after "Wildcards"**

Insert after the `### Wildcards` block (currently ends with the `all` verb bullet), before `### Encoding`:

```markdown
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
```

- [ ] **Step 2: Add a "Binding" section immediately after "Requirement Forms"**

```markdown
### Binding

`bindRequirements(requirements, binding)` substitutes each placeholder
`resourceName` with its bound value and returns the rewritten requirements.

- A requirement set containing no placeholder is returned unchanged.
- A placeholder with no entry in `binding` is an **error**, never a pass. This is
  the point of the form: an author who declares `{vector_store_id}` on a route
  whose enforcing layer supplies nothing gets a loud configuration error rather
  than a silent admit.
- Binding keys that match no placeholder are ignored, so a caller may pass a
  superset without knowing the requirement.
- Multiple distinct placeholders in one requirement set are permitted; each is
  bound by name. An unbound one among them still errors.
- Under strict mode, a wildcard `resourceName` in a requirement is an error here.

Binding operates on whatever each port's verification consumes: the pre-parsed
type in Go and TypeScript, raw `Requirements` in Rust and Python (which parse
inline and have no pre-parsed type).

`wildcardRequirements(requirements)` returns the requirement strings whose
`resourceName` is a wildcard — exactly what strict mode rejects. It is a pure
function so each consumer may log, count, or fail in its own idiom; it exists to
inventory what remains to migrate before strict is enabled.

All language ports MUST produce identical results.
```

- [ ] **Step 3: Amend Pattern Matching Rule 3 (Resource Name)**

Replace the three `- If ...` bullets under **Resource Name** with:

```markdown
     - If the entitlement resource name is empty or `*`, it matches all resource names in requirements.
     - If the requirement resource name is empty or `*`, it matches all resource names in entitlements.
       **Deprecated**: this direction is what strict mode rejects. See *Requirement Forms*.
     - A requirement resource name that is an unbound placeholder matches nothing under strict mode.
     - Otherwise, the resource names must match exactly.
```

- [ ] **Step 4: Verify the spec is internally consistent**

Run: `rg -n 'Requirement Forms|### Binding|Deprecated' SPEC.md`
Expected: three sections present; the Attenuation section's held-side-only rule now reads as the general principle rather than an exception.

- [ ] **Step 5: Commit**

```bash
git add SPEC.md
git commit -m "docs(spec): define requirement forms, placeholders and binding

Requirements gain a placeholder form (<resource>:{key}:<verb>) that must be
bound to a concrete value before verification, and an opt-in strict mode that
rejects wildcard resourceNames in requirements. Wildcards become a held-side
concept; opaque is documented as the form for context-less capabilities.

Refs #4"
```

---

### Task 2: Go — placeholder parsing and `BindRequirements`

**Files:**
- Modify: `go/entitlements.go`
- Test: `go/entitlements_test.go`

**Interfaces:**
- Consumes: `SPEC.md` (Task 1).
- Produces:
  - `type Binding map[string]string`
  - `func (ec *EntitlementsChecker) BindRequirements(reqs ParsedRequirements, b Binding) (ParsedRequirements, error)`
  - `var ErrUnboundPlaceholder error`
  - `func placeholderKey(resourceName string) string` (unexported)
  - `func isWildcardName(n string) bool` (unexported)
  - `entitlementPattern.placeholder string` field
  - `ParsedRequirements.hasPlaceholder bool` field

- [ ] **Step 1: Write the failing tests**

Append to `go/entitlements_test.go`:

```go
func TestPlaceholderKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"{vector_store_id}", "vector_store_id"},
		{"{a}", "a"},
		{"{}", ""},           // length 2 -> literal, not a placeholder
		{"vs_alice", ""},
		{"*", ""},
		{"", ""},
		{"{unterminated", ""},
		{"unopened}", ""},
		{"pre{mid}post", ""}, // must start AND end
	}
	for _, c := range cases {
		if got := placeholderKey(c.in); got != c.want {
			t.Errorf("placeholderKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBindRequirements(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false)

	reqs := ec.ParseRequirements(Requirements{{"bearer": {
		"functions:/api/v1/files:read",
		"vector_stores:{vector_store_id}:write",
	}}})

	bound, err := ec.BindRequirements(reqs, Binding{"vector_store_id": "vs_alice"})
	if err != nil {
		t.Fatalf("BindRequirements: %v", err)
	}

	// The store owner passes only for their OWN store.
	held := Entitlements{"bearer": {"functions:/api/v1/files:read", "vector_stores:vs_alice:all"}}
	if !ec.VerifyParsedEntitlements(ec.ParseEntitlements(held), bound) {
		t.Error("vs_alice grant should satisfy the requirement bound to vs_alice")
	}

	boundOther, err := ec.BindRequirements(reqs, Binding{"vector_store_id": "vs_bob"})
	if err != nil {
		t.Fatalf("BindRequirements: %v", err)
	}
	if ec.VerifyParsedEntitlements(ec.ParseEntitlements(held), boundOther) {
		t.Error("vs_alice grant must NOT satisfy the requirement bound to vs_bob")
	}

	// A held wildcard still passes any bound value.
	admin := Entitlements{"bearer": {"functions:/api/v1/files:read", "vector_stores::all"}}
	if !ec.VerifyParsedEntitlements(ec.ParseEntitlements(admin), boundOther) {
		t.Error("held wildcard should satisfy a bound requirement")
	}
}

func TestBindRequirementsUnbound(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false)
	reqs := ec.ParseRequirements(Requirements{{"bearer": {"vector_stores:{vector_store_id}:write"}}})

	if _, err := ec.BindRequirements(reqs, Binding{"wrong_key": "vs_alice"}); !errors.Is(err, ErrUnboundPlaceholder) {
		t.Errorf("expected ErrUnboundPlaceholder, got %v", err)
	}
	if _, err := ec.BindRequirements(reqs, nil); !errors.Is(err, ErrUnboundPlaceholder) {
		t.Errorf("expected ErrUnboundPlaceholder for nil binding, got %v", err)
	}
}

func TestBindRequirementsNoPlaceholderIsNoOp(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false)
	reqs := ec.ParseRequirements(Requirements{{"bearer": {"functions:/api/v1/files:read"}}})

	bound, err := ec.BindRequirements(reqs, nil)
	if err != nil {
		t.Fatalf("BindRequirements: %v", err)
	}
	if bound.hasPlaceholder {
		t.Error("expected hasPlaceholder=false")
	}
	if len(bound.patterns) != len(reqs.patterns) {
		t.Error("no-placeholder bind should return the requirements unchanged")
	}
}

func TestBindRequirementsMultipleAndSuperset(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false)
	reqs := ec.ParseRequirements(Requirements{{"bearer": {
		"vector_stores:{vector_store_id}:write",
		"files:{file_id}:read",
	}}})

	// Superset binding is fine; both placeholders bind by name.
	bound, err := ec.BindRequirements(reqs, Binding{
		"vector_store_id": "vs_alice",
		"file_id":         "file_1",
		"unused":          "ignored",
	})
	if err != nil {
		t.Fatalf("BindRequirements: %v", err)
	}
	held := Entitlements{"bearer": {"vector_stores:vs_alice:all", "files:file_1:read"}}
	if !ec.VerifyParsedEntitlements(ec.ParseEntitlements(held), bound) {
		t.Error("both placeholders should bind by name")
	}

	// One unbound among several still errors.
	if _, err := ec.BindRequirements(reqs, Binding{"vector_store_id": "vs_alice"}); !errors.Is(err, ErrUnboundPlaceholder) {
		t.Errorf("expected ErrUnboundPlaceholder, got %v", err)
	}
}

func TestHeldSidePlaceholderIsLiteral(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false)
	held := Entitlements{"bearer": {"vector_stores:{vector_store_id}:all"}}
	reqs := ec.ParseRequirements(Requirements{{"bearer": {"vector_stores:vs_alice:write"}}})
	if ec.VerifyParsedEntitlements(ec.ParseEntitlements(held), reqs) {
		t.Error("a held-side placeholder must be literal text, not a wildcard")
	}
}
```

Add `"errors"` to the test file's import block if absent.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd go && go test ./... -run 'TestPlaceholderKey|TestBind|TestHeldSide' 2>&1 | head -20`
Expected: FAIL — `undefined: placeholderKey`, `undefined: Binding`, `undefined: ErrUnboundPlaceholder`.

- [ ] **Step 3: Add the placeholder field and helpers**

In `go/entitlements.go`, add `"errors"` to imports. Extend the struct (currently ~line 419):

```go
type entitlementPattern struct {
	raw          string
	resource     string
	resourceName string
	verb         string
	isPattern    bool
	// placeholder is the binding key when resourceName is "{key}", else "".
	// Meaningful only on the requirement side; held-side placeholders are
	// literal text.
	placeholder string
}
```

Add near the other package-level helpers:

```go
// ErrUnboundPlaceholder is returned by BindRequirements when a requirement
// declares a {placeholder} that the supplied Binding does not resolve. An
// unbound placeholder is an error, never a pass.
var ErrUnboundPlaceholder = errors.New("entitlements: unbound placeholder in requirement")

// placeholderKey returns the binding key when resourceName has the form
// "{key}", else "". "{}" is a literal resourceName, not a placeholder.
func placeholderKey(resourceName string) string {
	if len(resourceName) > 2 &&
		strings.HasPrefix(resourceName, "{") &&
		strings.HasSuffix(resourceName, "}") {
		return resourceName[1 : len(resourceName)-1]
	}
	return ""
}

// isWildcardName reports whether a resourceName is a wildcard. Empty is the
// parsed form of both the short (<resource>:<verb>) and medium
// (<resource>::<verb>) syntaxes.
func isWildcardName(n string) bool {
	return n == "" || n == "*"
}
```

In `parsePattern`, set `placeholder` on the 3-part branch only (a 2-part short form has an empty resourceName, which can never be a placeholder):

```go
		} else if len(parts) == 3 {
			p = entitlementPattern{
				raw:          s,
				resource:     parts[0],
				resourceName: parts[1],
				verb:         parts[2],
				isPattern:    true,
				placeholder:  placeholderKey(parts[1]),
			}
		} else {
```

- [ ] **Step 4: Add `hasPlaceholder` to `ParsedRequirements`**

```go
type ParsedRequirements struct {
	patterns []map[string][]entitlementPattern
	// hasPlaceholder is precomputed so BindRequirements can no-op on the
	// (common) requirement sets that contain no placeholder.
	hasPlaceholder bool
}
```

In `ParseRequirements`, track it and return it:

```go
func (ec *EntitlementsChecker) ParseRequirements(requirements Requirements) ParsedRequirements {
	parsed := make([]map[string][]entitlementPattern, len(requirements))
	hasPlaceholder := false
	for i, req := range requirements {
		newReq := make(map[string][]entitlementPattern, len(req))
		for scheme, list := range req {
			patterns := make([]entitlementPattern, len(list))
			for j, s := range list {
				patterns[j] = ec.parsePattern(s)
				if patterns[j].placeholder != "" {
					hasPlaceholder = true
				}
			}
			newReq[scheme] = patterns
		}
		parsed[i] = newReq
	}
	return ParsedRequirements{patterns: parsed, hasPlaceholder: hasPlaceholder}
}
```

- [ ] **Step 5: Implement `BindRequirements`**

```go
// Binding maps a requirement placeholder key to the concrete resourceName it
// stands for, e.g. {"vector_store_id": "vs_abc"}.
type Binding map[string]string

// BindRequirements substitutes every {placeholder} resourceName in reqs with
// its value from b and returns the rewritten requirements. Requirement sets
// containing no placeholder are returned unchanged.
//
// Returns ErrUnboundPlaceholder if any placeholder has no entry in b — an
// unbound placeholder is a configuration error, never a pass. Keys in b that
// match no placeholder are ignored, so a caller may pass a superset (e.g.
// every path value it resolved) without knowing the requirement.
func (ec *EntitlementsChecker) BindRequirements(reqs ParsedRequirements, b Binding) (ParsedRequirements, error) {
	if !reqs.hasPlaceholder {
		return reqs, nil
	}

	bound := make([]map[string][]entitlementPattern, len(reqs.patterns))
	for i, set := range reqs.patterns {
		newSet := make(map[string][]entitlementPattern, len(set))
		for scheme, list := range set {
			newList := make([]entitlementPattern, len(list))
			for j, p := range list {
				if p.placeholder == "" {
					newList[j] = p
					continue
				}
				v, ok := b[p.placeholder]
				if !ok {
					return ParsedRequirements{}, fmt.Errorf("%w: %q in requirement %q",
						ErrUnboundPlaceholder, p.placeholder, p.raw)
				}
				// Construct directly rather than re-parsing: a bound value
				// containing ':' would otherwise be re-split into the wrong
				// shape. Callers encode such values at their boundary.
				newList[j] = entitlementPattern{
					raw:          p.resource + ":" + v + ":" + p.verb,
					resource:     p.resource,
					resourceName: v,
					verb:         p.verb,
					isPattern:    true,
				}
			}
			newSet[scheme] = newList
		}
		bound[i] = newSet
	}
	return ParsedRequirements{patterns: bound, hasPlaceholder: false}, nil
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd go && go test ./... -run 'TestPlaceholderKey|TestBind|TestHeldSide' -v 2>&1 | tail -20`
Expected: PASS for all six tests.

- [ ] **Step 7: Run the full suite to confirm nothing regressed**

Run: `cd go && make test 2>&1 | tail -5`
Expected: `ok github.com/kdex-tech/entitlements/go`. Every pre-existing test passes **unmodified**.

- [ ] **Step 8: Commit**

```bash
git add go/entitlements.go go/entitlements_test.go
git commit -m "feat(go): add {param} placeholder binding for requirements

A requirement resourceName of the form {key} is a hole bound to a concrete
value by BindRequirements before verification. Unbound is an error, never a
pass. Sets with no placeholder are returned unchanged, so unaffected routes
pay nothing.

Refs #4"
```

---

### Task 3: Go — strict mode and the wildcard inventory

**Files:**
- Modify: `go/entitlements.go`
- Test: `go/entitlements_test.go`

**Interfaces:**
- Consumes: Task 2's `placeholderKey`, `isWildcardName`, `Binding`, `BindRequirements`, `entitlementPattern.placeholder`.
- Produces:
  - `func (ec *EntitlementsChecker) WithStrictRequirements(strict bool) *EntitlementsChecker`
  - `func (ec *EntitlementsChecker) WildcardRequirements(reqs Requirements) []string`
  - `var ErrWildcardRequirement error`
  - `EntitlementsChecker.strictRequirements bool` field

- [ ] **Step 1: Write the failing tests**

Append to `go/entitlements_test.go`:

```go
// The regression that motivates #4: a single-store grant must not satisfy a
// class-wide gate once strict is on.
func TestStrictRejectsWildcardRequirement(t *testing.T) {
	held := Entitlements{"bearer": {"vector_stores:vs_alice:all"}}

	// Default (strict off) preserves v0.3.0 behavior: the escalation still passes.
	lax := NewEntitlementsChecker(nil, "bearer", false)
	if !lax.VerifyEntitlements(held, Requirements{{"bearer": {"vector_stores:*:write"}}}) {
		t.Error("with strict off, v0.3.0 behavior must be preserved")
	}

	// Strict on: the wildcard requirement is unsatisfiable.
	strict := NewEntitlementsChecker(nil, "bearer", false).WithStrictRequirements(true)
	if strict.VerifyEntitlements(held, Requirements{{"bearer": {"vector_stores:*:write"}}}) {
		t.Error("strict: a single-store grant must NOT satisfy a wildcard requirement")
	}
	// A genuine held wildcard is still denied by a wildcard REQUIREMENT under
	// strict, because the requirement spelling itself is illegal.
	if strict.VerifyEntitlements(Entitlements{"bearer": {"vector_stores::all"}},
		Requirements{{"bearer": {"vector_stores:*:write"}}}) {
		t.Error("strict: wildcard requirements are illegal regardless of the grant")
	}
	// Concrete requirements are unaffected by strict.
	if !strict.VerifyEntitlements(held, Requirements{{"bearer": {"vector_stores:vs_alice:write"}}}) {
		t.Error("strict must not affect concrete requirements")
	}
}

func TestStrictBindReturnsWildcardError(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false).WithStrictRequirements(true)
	for _, s := range []string{"vector_stores:*:write", "vector_stores::write", "vector_stores:write"} {
		reqs := ec.ParseRequirements(Requirements{{"bearer": {s}}})
		if _, err := ec.BindRequirements(reqs, nil); !errors.Is(err, ErrWildcardRequirement) {
			t.Errorf("%q: expected ErrWildcardRequirement, got %v", s, err)
		}
	}
	// Opaque and concrete requirements bind cleanly under strict.
	for _, s := range []string{"vector_stores_create", "functions:/api/v1/files:read"} {
		reqs := ec.ParseRequirements(Requirements{{"bearer": {s}}})
		if _, err := ec.BindRequirements(reqs, nil); err != nil {
			t.Errorf("%q: unexpected error %v", s, err)
		}
	}
}

// A consumer that forgets to Bind must fail closed under strict, even for an
// admin holding a wildcard.
func TestStrictUnboundPlaceholderFailsClosedInVerify(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false).WithStrictRequirements(true)
	reqs := ec.ParseRequirements(Requirements{{"bearer": {"vector_stores:{vector_store_id}:write"}}})
	admin := ec.ParseEntitlements(Entitlements{"bearer": {"vector_stores::all"}})
	if ec.VerifyParsedEntitlements(admin, reqs) {
		t.Error("strict: an unbound placeholder must not be satisfied, even by a wildcard grant")
	}
}

func TestWildcardRequirements(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false)

	got := ec.WildcardRequirements(Requirements{
		{"bearer": {"functions:/api/v1/ingest:read", "vector_stores:*:write"}},
		{"bearer": {"vector_stores::read", "apitokens:mint", "vector_stores:*:write"}},
		{"bearer": {"vector_stores:{vector_store_id}:write", "vector_stores_create", "users:me:read"}},
	})

	want := []string{"vector_stores:*:write", "vector_stores::read", "apitokens:mint"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q (got %v)", i, got[i], want[i], got)
		}
	}

	// Strict-clean sets report nothing.
	if n := len(ec.WildcardRequirements(Requirements{
		{"bearer": {"functions:/api/v1/files:read", "vector_stores:{vector_store_id}:write", "users_admin"}},
	})); n != 0 {
		t.Errorf("expected a strict-clean set to report nothing, got %d", n)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd go && go test ./... -run 'TestStrict|TestWildcardRequirements' 2>&1 | head -12`
Expected: FAIL — `undefined: ErrWildcardRequirement`, `WithStrictRequirements`, `WildcardRequirements`.

- [ ] **Step 3: Add the flag, the error, and the builder**

Add the field to `EntitlementsChecker` (alongside `grantReadyByDefault`):

```go
	strictRequirements  bool
```

Add beside `ErrUnboundPlaceholder`:

```go
// ErrWildcardRequirement is returned by BindRequirements under strict mode when
// a requirement's resourceName is a wildcard ("*" or empty, which includes the
// short and medium syntaxes). Wildcards are meaningful only on the held side;
// as a requirement the spelling is ambiguous. Use a {placeholder} for the
// resource being addressed, or an opaque scope for a context-less capability.
var ErrWildcardRequirement = errors.New("entitlements: wildcard resourceName is not allowed in a requirement")
```

Add beside `WithLogger`:

```go
// WithStrictRequirements rejects wildcard resourceNames on the requirement side.
// It never affects entitlements, where wildcards remain meaningful.
//
// When enabled, BindRequirements returns ErrWildcardRequirement for such a
// requirement (the loud path), and verification treats both a wildcard
// requirement and an unbound placeholder as unsatisfiable (a fail-closed
// backstop for callers that skip BindRequirements).
//
// Defaults to false; a future major version will default it to true. Intended
// for use during checker construction; not safe for concurrent mutation with
// verify calls in flight.
func (ec *EntitlementsChecker) WithStrictRequirements(strict bool) *EntitlementsChecker {
	ec.strictRequirements = strict
	return ec
}
```

- [ ] **Step 4: Enforce strict in `BindRequirements` (the loud path)**

Insert at the top of `BindRequirements`, **before** the `hasPlaceholder` early return (a wildcard-only set has no placeholder and must still be rejected):

```go
	if ec.strictRequirements {
		for _, set := range reqs.patterns {
			for _, list := range set {
				for _, p := range list {
					if p.isPattern && p.placeholder == "" && isWildcardName(p.resourceName) {
						return ParsedRequirements{}, fmt.Errorf("%w: %q",
							ErrWildcardRequirement, p.raw)
					}
				}
			}
		}
	}
```

- [ ] **Step 5: Add the fail-closed backstop in verification**

At the top of `hasParsedEntitlement`, before the entitlement loop:

```go
	// Strict backstop for callers that skip BindRequirements: a wildcard
	// requirement is an illegal spelling, and an unbound placeholder was never
	// resolved. Both are unsatisfiable rather than silently admitted — a held
	// wildcard would otherwise match either one.
	if ec.strictRequirements && requirement.isPattern {
		if requirement.placeholder != "" || isWildcardName(requirement.resourceName) {
			return false
		}
	}
```

- [ ] **Step 6: Implement `WildcardRequirements`**

```go
// WildcardRequirements returns the requirement strings whose resourceName is a
// wildcard ("*", empty, or the short/medium syntaxes) — the spellings strict
// mode rejects outright. Results are de-duplicated and in first-seen order.
//
// It is a migration inventory, not a complete strict-mode pre-flight: strict
// also rejects an unbound placeholder at verification time, which this query
// does not report (a placeholder is the migration's destination, not a target).
// An empty result means no requirement still uses a wildcard spelling.
//
// It is a pure query so a caller may log, count, or fail in its own idiom. Use
// it to inventory what remains to migrate before enabling WithStrictRequirements.
func (ec *EntitlementsChecker) WildcardRequirements(reqs Requirements) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, set := range reqs {
		for _, list := range set {
			for _, s := range list {
				p := ec.parsePattern(s)
				if !p.isPattern || p.placeholder != "" || !isWildcardName(p.resourceName) {
					continue
				}
				if _, dup := seen[s]; dup {
					continue
				}
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}
```

> **Note on ordering:** `TestWildcardRequirements` relies on requirement *sets* being ordered (a slice) and each scheme's list being ordered. Go map iteration over schemes is random, so each set in that test uses a single scheme — do not add a second scheme to those fixtures.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd go && go test ./... -run 'TestStrict|TestWildcardRequirements' -v 2>&1 | tail -15`
Expected: PASS for all four tests.

- [ ] **Step 8: Run the full suite and lint**

Run: `cd go && make test && make lint 2>&1 | tail -5`
Expected: tests `ok`, lint clean. All pre-existing tests pass **unmodified**.

- [ ] **Step 9: Commit**

```bash
git add go/entitlements.go go/entitlements_test.go
git commit -m "feat(go): add WithStrictRequirements and WildcardRequirements

Strict mode makes a wildcard resourceName illegal as a requirement: loudly via
ErrWildcardRequirement from BindRequirements, and fail-closed in verification
for callers that skip binding. Defaults false, so v0.3.0 behavior is preserved.

WildcardRequirements is a pure query returning exactly what strict rejects, for
inventorying a migration. It is a function rather than a log line because only
the Go port has a logger.

Refs #4"
```

---

### Task 4: Rust — placeholders, binding, strict, inventory

**Files:**
- Modify: `rust/src/lib.rs`
- Test: `rust/src/lib.rs` (in-file `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `SPEC.md` (Task 1); the Go port (Task 2, 3) as the reference for behavior and docs.
- Produces:
  - `pub type Binding = HashMap<String, String>`
  - `pub enum BindError { UnboundPlaceholder(String), WildcardRequirement(String), InvalidBoundValue(String) }`
  - `impl Pattern { pub fn placeholder(&self) -> Option<&str>; pub fn is_wildcard_name(&self) -> bool }`
  - `EntitlementsChecker::bind_requirements(&self, &Requirements, &Binding) -> Result<Requirements, BindError>`
  - `EntitlementsChecker::with_strict_requirements(self, bool) -> Self`
  - `EntitlementsChecker::wildcard_requirements(&self, &Requirements) -> Vec<String>`

> **Rust-specific:** `Pattern::parse` maps the 2-part form to `name: "*"` (not `""` as in Go), and `Pattern::Structured` has no `raw` field. `bind_requirements` therefore operates on **raw `Requirements`** and returns rewritten strings — Rust has no pre-parsed type and must not gain one.

- [ ] **Step 1: Write the failing tests**

Append inside `rust/src/lib.rs`'s `#[cfg(test)] mod tests`:

```rust
    fn reqs(scheme: &str, list: &[&str]) -> Requirements {
        let mut set = RequirementSet::new();
        set.insert(scheme.to_string(), list.iter().map(|s| s.to_string()).collect());
        vec![set]
    }

    fn ents(scheme: &str, list: &[&str]) -> Entitlements {
        let mut m = Entitlements::new();
        m.insert(scheme.to_string(), list.iter().map(|s| s.to_string()).collect());
        m
    }

    #[test]
    fn placeholder_recognition() {
        assert_eq!(Pattern::parse("vs:{vector_store_id}:read").placeholder(), Some("vector_store_id"));
        assert_eq!(Pattern::parse("vs:{a}:read").placeholder(), Some("a"));
        assert_eq!(Pattern::parse("vs:{}:read").placeholder(), None); // literal
        assert_eq!(Pattern::parse("vs:vs_alice:read").placeholder(), None);
        assert_eq!(Pattern::parse("vs:*:read").placeholder(), None);
        assert_eq!(Pattern::parse("opaque").placeholder(), None);
    }

    #[test]
    fn bind_requirements_substitutes_and_scopes() {
        let ec = EntitlementsChecker::new(vec![], "bearer".to_string());
        let r = reqs("bearer", &["vector_stores:{vector_store_id}:write"]);
        let mut b = Binding::new();
        b.insert("vector_store_id".to_string(), "vs_alice".to_string());

        let bound = ec.bind_requirements(&r, &b).unwrap();
        let held = ents("bearer", &["vector_stores:vs_alice:all"]);
        assert!(ec.verify(&held, &bound));

        let mut b2 = Binding::new();
        b2.insert("vector_store_id".to_string(), "vs_bob".to_string());
        let bound2 = ec.bind_requirements(&r, &b2).unwrap();
        assert!(!ec.verify(&held, &bound2), "vs_alice must not satisfy vs_bob");

        // A held wildcard still passes a bound requirement.
        assert!(ec.verify(&ents("bearer", &["vector_stores::all"]), &bound2));
    }

    #[test]
    fn bind_requirements_unbound_errors() {
        let ec = EntitlementsChecker::new(vec![], "bearer".to_string());
        let r = reqs("bearer", &["vector_stores:{vector_store_id}:write"]);
        assert!(matches!(
            ec.bind_requirements(&r, &Binding::new()),
            Err(BindError::UnboundPlaceholder(_))
        ));
    }

    #[test]
    fn bind_requirements_rejects_wildcard_bound_value() {
        let ec = EntitlementsChecker::new(vec![], "bearer".to_string());
        let r = reqs("bearer", &["vector_stores:{vector_store_id}:write"]);
        // "" and "*" are the wildcard spelling, not a concrete resourceName.
        // Binding one would widen the requirement to every store.
        for v in ["", "*"] {
            let mut b = Binding::new();
            b.insert("vector_store_id".to_string(), v.to_string());
            assert!(
                matches!(ec.bind_requirements(&r, &b), Err(BindError::InvalidBoundValue(_))),
                "binding to {v:?} should be rejected"
            );
        }
        // A legitimate value still binds.
        let mut ok = Binding::new();
        ok.insert("vector_store_id".to_string(), "vs_alice".to_string());
        assert!(ec.bind_requirements(&r, &ok).is_ok());
    }

    #[test]
    fn bind_requirements_no_placeholder_is_unchanged() {
        let ec = EntitlementsChecker::new(vec![], "bearer".to_string());
        let r = reqs("bearer", &["functions:/api/v1/files:read"]);
        assert_eq!(ec.bind_requirements(&r, &Binding::new()).unwrap(), r);
    }

    #[test]
    fn bind_requirements_multiple_and_superset() {
        let ec = EntitlementsChecker::new(vec![], "bearer".to_string());
        let r = reqs("bearer", &["vector_stores:{vector_store_id}:write", "files:{file_id}:read"]);
        let mut b = Binding::new();
        b.insert("vector_store_id".to_string(), "vs_alice".to_string());
        b.insert("file_id".to_string(), "file_1".to_string());
        b.insert("unused".to_string(), "ignored".to_string());

        let bound = ec.bind_requirements(&r, &b).unwrap();
        let held = ents("bearer", &["vector_stores:vs_alice:all", "files:file_1:read"]);
        assert!(ec.verify(&held, &bound));
    }

    #[test]
    fn held_side_placeholder_is_literal() {
        let ec = EntitlementsChecker::new(vec![], "bearer".to_string());
        let held = ents("bearer", &["vector_stores:{vector_store_id}:all"]);
        assert!(
            !ec.verify(&held, &reqs("bearer", &["vector_stores:vs_alice:write"])),
            "a held-side placeholder must be literal text, not a wildcard"
        );
    }

    #[test]
    fn strict_rejects_wildcard_requirements() {
        let held = ents("bearer", &["vector_stores:vs_alice:all"]);

        // Strict off preserves existing behavior.
        let lax = EntitlementsChecker::new(vec![], "bearer".to_string());
        assert!(lax.verify(&held, &reqs("bearer", &["vector_stores:*:write"])));

        let strict = EntitlementsChecker::new(vec![], "bearer".to_string())
            .with_strict_requirements(true);
        assert!(!strict.verify(&held, &reqs("bearer", &["vector_stores:*:write"])));
        assert!(strict.verify(&held, &reqs("bearer", &["vector_stores:vs_alice:write"])));

        for s in ["vector_stores:*:write", "vector_stores::write", "vector_stores:write"] {
            assert!(matches!(
                strict.bind_requirements(&reqs("bearer", &[s]), &Binding::new()),
                Err(BindError::WildcardRequirement(_)),
                "{s} should be rejected"
            ));
        }
    }

    #[test]
    fn strict_unbound_placeholder_fails_closed() {
        let strict = EntitlementsChecker::new(vec![], "bearer".to_string())
            .with_strict_requirements(true);
        let admin = ents("bearer", &["vector_stores::all"]);
        assert!(!strict.verify(&admin, &reqs("bearer", &["vector_stores:{vector_store_id}:write"])));
    }

    #[test]
    fn wildcard_requirements_inventory() {
        let ec = EntitlementsChecker::new(vec![], "bearer".to_string());
        let r = reqs("bearer", &[
            "functions:/api/v1/ingest:read",
            "vector_stores:*:write",
            "apitokens:mint",
            "vector_stores:*:write",
            "vector_stores:{vector_store_id}:write",
            "vector_stores_create",
        ]);
        assert_eq!(
            ec.wildcard_requirements(&r),
            vec!["vector_stores:*:write".to_string(), "apitokens:mint".to_string()]
        );
        assert!(ec.wildcard_requirements(&reqs("bearer", &["users:me:read"])).is_empty());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test 2>&1 | head -15`
Expected: FAIL — `no method named placeholder`, `cannot find type Binding`.

- [ ] **Step 3: Add `Binding`, `BindError`, and the `Pattern` helpers**

At the top of `rust/src/lib.rs`, beside the other type aliases:

```rust
/// Maps a requirement placeholder key to the concrete resourceName it stands
/// for, e.g. {"vector_store_id": "vs_abc"}.
pub type Binding = HashMap<String, String>;

/// Why `bind_requirements` refused a requirement set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// A requirement declared a {placeholder} the Binding does not resolve.
    /// Carries the offending requirement string.
    UnboundPlaceholder(String),
    /// Strict mode: a requirement's resourceName is a wildcard. Carries the
    /// offending requirement string.
    WildcardRequirement(String),
    /// A placeholder was bound to "" or "*" — the wildcard spelling, not a
    /// concrete resourceName. Binding one would silently widen the requirement
    /// to the whole resource class, so a binder that could not resolve a value
    /// fails here rather than widening the gate. Carries the offending
    /// requirement string.
    InvalidBoundValue(String),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnboundPlaceholder(s) => write!(f, "unbound placeholder in requirement {s:?}"),
            Self::WildcardRequirement(s) => {
                write!(f, "wildcard resourceName is not allowed in requirement {s:?}")
            }
            Self::InvalidBoundValue(s) => {
                write!(f, "bound value must not be empty or a wildcard, in requirement {s:?}")
            }
        }
    }
}

impl std::error::Error for BindError {}
```

Add to `impl Pattern`:

```rust
    /// Returns the binding key when this pattern's resourceName has the form
    /// "{key}", else None. "{}" is a literal resourceName, not a placeholder.
    /// Meaningful only on the requirement side; held-side placeholders are
    /// literal text.
    pub fn placeholder(&self) -> Option<&str> {
        match self {
            Self::Structured { name, .. }
                if name.len() > 2 && name.starts_with('{') && name.ends_with('}') =>
            {
                Some(&name[1..name.len() - 1])
            }
            _ => None,
        }
    }

    /// Reports whether this pattern's resourceName is a wildcard. Note `parse`
    /// maps the short form (<resource>:<verb>) to `name: "*"`.
    pub fn is_wildcard_name(&self) -> bool {
        matches!(self, Self::Structured { name, .. } if name.is_empty() || name == "*")
    }
```

- [ ] **Step 4: Add the strict flag and builder**

Extend the struct and `new`:

```rust
pub struct EntitlementsChecker {
    anonymous_entitlements: Vec<Pattern>,
    base_entitlements: Vec<Pattern>,
    default_scheme: String,
    strict_requirements: bool,
}
```

In `new`, add `strict_requirements: false` to the struct literal. Then:

```rust
    /// Rejects wildcard resourceNames on the requirement side. Never affects
    /// entitlements, where wildcards remain meaningful.
    ///
    /// When enabled, `bind_requirements` returns `BindError::WildcardRequirement`
    /// (the loud path) and `verify` treats both a wildcard requirement and an
    /// unbound placeholder as unsatisfiable (a fail-closed backstop for callers
    /// that skip binding).
    ///
    /// Defaults to false; a future major version will default it to true.
    pub fn with_strict_requirements(mut self, strict: bool) -> Self {
        self.strict_requirements = strict;
        self
    }
```

- [ ] **Step 5: Implement `bind_requirements` and `wildcard_requirements`**

```rust
    /// Substitutes every {placeholder} resourceName in `reqs` with its value
    /// from `b`, returning the rewritten requirements. Sets containing no
    /// placeholder are returned unchanged.
    ///
    /// An unbound placeholder is an error, never a pass. Keys in `b` that match
    /// no placeholder are ignored, so a caller may pass a superset.
    pub fn bind_requirements(
        &self,
        reqs: &Requirements,
        b: &Binding,
    ) -> Result<Requirements, BindError> {
        let mut out = Requirements::with_capacity(reqs.len());
        for set in reqs {
            let mut new_set = RequirementSet::new();
            for (scheme, list) in set {
                let mut new_list = Vec::with_capacity(list.len());
                for s in list {
                    let p = Pattern::parse(s);
                    if self.strict_requirements && p.placeholder().is_none() && p.is_wildcard_name()
                    {
                        return Err(BindError::WildcardRequirement(s.clone()));
                    }
                    match p.placeholder() {
                        None => new_list.push(s.clone()),
                        Some(key) => {
                            let v = b
                                .get(key)
                                .ok_or_else(|| BindError::UnboundPlaceholder(s.clone()))?;
                            // "" and "*" are the wildcard spelling, not concrete
                            // names: binding one would widen the requirement to
                            // the whole class. Fail like an unbound placeholder.
                            if v.is_empty() || v == "*" {
                                return Err(BindError::InvalidBoundValue(s.clone()));
                            }
                            match &p {
                                Pattern::Structured { resource, verb, .. } => {
                                    new_list.push(format!("{resource}:{v}:{verb}"))
                                }
                                Pattern::Opaque(_) => unreachable!("placeholder implies Structured"),
                            }
                        }
                    }
                }
                new_set.insert(scheme.clone(), new_list);
            }
            out.push(new_set);
        }
        Ok(out)
    }

    /// Returns the requirement strings whose resourceName is a wildcard —
    /// exactly what strict mode rejects. De-duplicated, first-seen order; empty
    /// means strict-clean. Use it to inventory a migration.
    pub fn wildcard_requirements(&self, reqs: &Requirements) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for set in reqs {
            for list in set.values() {
                for s in list {
                    let p = Pattern::parse(s);
                    if p.placeholder().is_none() && p.is_wildcard_name() && !out.contains(s) {
                        out.push(s.clone());
                    }
                }
            }
        }
        out
    }
```

- [ ] **Step 6: Add the strict backstop to verification**

In `verify_set` (`rust/src/lib.rs:237`), immediately after `let req_p = Pattern::parse(req_str);` and **before** the `satisfied_by_user` / `satisfied_by_base` / `satisfied_by_anon` lets, add:

```rust
                // Strict backstop for callers that skip bind_requirements: a
                // wildcard requirement is an illegal spelling and an unbound
                // placeholder was never resolved. Both are unsatisfiable rather
                // than silently admitted — a held wildcard would match either.
                if self.strict_requirements
                    && (req_p.placeholder().is_some() || req_p.is_wildcard_name())
                {
                    return false;
                }
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd rust && cargo test 2>&1 | tail -12`
Expected: PASS — all eight new tests plus every pre-existing test, unmodified.

- [ ] **Step 8: Lint**

Run: `cd rust && make lint 2>&1 | tail -5`
Expected: `cargo clippy -- -D warnings` clean.

- [ ] **Step 9: Commit**

```bash
git add rust/src/lib.rs
git commit -m "feat(rust): add placeholder binding, strict requirements, inventory

Mirrors the Go port. Rust has no pre-parsed requirement type, so
bind_requirements operates on raw Requirements and returns rewritten strings.

Refs #4"
```

---

### Task 5: Python — placeholders, binding, strict, inventory

**Files:**
- Modify: `python/src/entitlements/__init__.py`
- Test: `python/tests/test_entitlements.py`

**Interfaces:**
- Consumes: `SPEC.md` (Task 1); the Go port as the behavior reference.
- Produces:
  - `class BindError(Exception)`, `class UnboundPlaceholderError(BindError)`, `class WildcardRequirementError(BindError)`, `class InvalidBoundValueError(BindError)`
  - `Pattern.placeholder` (property → `Optional[str]`), `Pattern.is_wildcard_name` (property → `bool`)
  - `EntitlementsChecker.bind_requirements(requirements, binding) -> Requirements`
  - `EntitlementsChecker.with_strict_requirements(strict) -> EntitlementsChecker`
  - `EntitlementsChecker.wildcard_requirements(requirements) -> list[str]`

> **Python-specific:** `Pattern.parse` maps the 2-part form to `name="*"` (like Rust). `Pattern` is a frozen dataclass; add the helpers as `@property`. `verify()` parses inline — do **not** add a pre-parsed type.

- [ ] **Step 1: Write the failing tests**

Append to `python/tests/test_entitlements.py`:

```python
import pytest
from entitlements import (
    EntitlementsChecker,
    InvalidBoundValueError,
    Pattern,
    UnboundPlaceholderError,
    WildcardRequirementError,
)


def test_placeholder_recognition():
    assert Pattern.parse("vs:{vector_store_id}:read").placeholder == "vector_store_id"
    assert Pattern.parse("vs:{a}:read").placeholder == "a"
    assert Pattern.parse("vs:{}:read").placeholder is None  # literal
    assert Pattern.parse("vs:vs_alice:read").placeholder is None
    assert Pattern.parse("vs:*:read").placeholder is None
    assert Pattern.parse("opaque").placeholder is None


def test_bind_requirements_substitutes_and_scopes():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["vector_stores:{vector_store_id}:write"]}]
    held = {"bearer": ["vector_stores:vs_alice:all"]}

    bound = ec.bind_requirements(reqs, {"vector_store_id": "vs_alice"})
    assert ec.verify(held, bound)

    bound_other = ec.bind_requirements(reqs, {"vector_store_id": "vs_bob"})
    assert not ec.verify(held, bound_other), "vs_alice must not satisfy vs_bob"

    # A held wildcard still passes a bound requirement.
    assert ec.verify({"bearer": ["vector_stores::all"]}, bound_other)


def test_bind_requirements_unbound_raises():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["vector_stores:{vector_store_id}:write"]}]
    with pytest.raises(UnboundPlaceholderError):
        ec.bind_requirements(reqs, {"wrong_key": "vs_alice"})
    with pytest.raises(UnboundPlaceholderError):
        ec.bind_requirements(reqs, {})


def test_bind_requirements_rejects_wildcard_bound_value():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["vector_stores:{vector_store_id}:write"]}]
    # "" and "*" are the wildcard spelling, not a concrete resource name.
    # Binding one would widen the requirement to every store.
    for v in ("", "*"):
        with pytest.raises(InvalidBoundValueError):
            ec.bind_requirements(reqs, {"vector_store_id": v})
    # A legitimate value still binds.
    ec.bind_requirements(reqs, {"vector_store_id": "vs_alice"})


def test_bind_requirements_no_placeholder_is_unchanged():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["functions:/api/v1/files:read"]}]
    assert ec.bind_requirements(reqs, {}) == reqs


def test_bind_requirements_multiple_and_superset():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["vector_stores:{vector_store_id}:write", "files:{file_id}:read"]}]
    bound = ec.bind_requirements(
        reqs, {"vector_store_id": "vs_alice", "file_id": "file_1", "unused": "ignored"}
    )
    held = {"bearer": ["vector_stores:vs_alice:all", "files:file_1:read"]}
    assert ec.verify(held, bound)

    with pytest.raises(UnboundPlaceholderError):
        ec.bind_requirements(reqs, {"vector_store_id": "vs_alice"})


def test_held_side_placeholder_is_literal():
    ec = EntitlementsChecker()
    held = {"bearer": ["vector_stores:{vector_store_id}:all"]}
    assert not ec.verify(held, [{"bearer": ["vector_stores:vs_alice:write"]}]), (
        "a held-side placeholder must be literal text, not a wildcard"
    )


def test_strict_rejects_wildcard_requirements():
    held = {"bearer": ["vector_stores:vs_alice:all"]}

    # Strict off preserves existing behavior.
    assert EntitlementsChecker().verify(held, [{"bearer": ["vector_stores:*:write"]}])

    strict = EntitlementsChecker().with_strict_requirements(True)
    assert not strict.verify(held, [{"bearer": ["vector_stores:*:write"]}])
    assert strict.verify(held, [{"bearer": ["vector_stores:vs_alice:write"]}])

    # A wildcard requirement is illegal by SPELLING — a genuine wildcard grant
    # does not rescue it. (Parity with Go's TestStrictRejectsWildcardRequirement.)
    assert not strict.verify(
        {"bearer": ["vector_stores::all"]}, [{"bearer": ["vector_stores:*:write"]}]
    )

    for s in ("vector_stores:*:write", "vector_stores::write", "vector_stores:write"):
        with pytest.raises(WildcardRequirementError):
            strict.bind_requirements([{"bearer": [s]}], {})

    # Opaque and concrete requirements bind cleanly under strict — no false reject.
    for s in ("vector_stores_create", "functions:/api/v1/files:read"):
        strict.bind_requirements([{"bearer": [s]}], {})


def test_strict_wildcard_error_is_order_independent():
    # Strict scans all requirements before resolving placeholders, so the
    # wildcard error wins regardless of position. A single interleaved pass would
    # raise UnboundPlaceholderError for the first ordering and
    # WildcardRequirementError for the second — order-dependent, and drift from
    # the Go reference.
    strict = EntitlementsChecker().with_strict_requirements(True)
    for entries in (
        ["vector_stores:{vector_store_id}:write", "vector_stores:*:read"],
        ["vector_stores:*:read", "vector_stores:{vector_store_id}:write"],
    ):
        with pytest.raises(WildcardRequirementError):
            strict.bind_requirements([{"bearer": entries}], {})


def test_strict_unbound_placeholder_fails_closed():
    strict = EntitlementsChecker().with_strict_requirements(True)
    admin = {"bearer": ["vector_stores::all"]}
    assert not strict.verify(admin, [{"bearer": ["vector_stores:{vector_store_id}:write"]}])


def test_wildcard_requirements_inventory():
    ec = EntitlementsChecker()
    reqs = [
        {
            "bearer": [
                "functions:/api/v1/ingest:read",
                "vector_stores:*:write",
                "apitokens:mint",
                "vector_stores:*:write",
                "vector_stores:{vector_store_id}:write",
                "vector_stores_create",
            ]
        }
    ]
    assert ec.wildcard_requirements(reqs) == ["vector_stores:*:write", "apitokens:mint"]
    assert ec.wildcard_requirements([{"bearer": ["users:me:read"]}]) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd python && make test 2>&1 | tail -10`
Expected: FAIL — `ImportError: cannot import name 'UnboundPlaceholderError'`.

- [ ] **Step 3: Add the exceptions and `Pattern` properties**

In `python/src/entitlements/__init__.py`, add after the type aliases:

```python
class BindError(Exception):
    """Base class for bind_requirements failures."""


class UnboundPlaceholderError(BindError):
    """A requirement declared a {placeholder} the binding does not resolve.
    An unbound placeholder is an error, never a pass."""


class WildcardRequirementError(BindError):
    """Strict mode: a requirement's resourceName is a wildcard. Wildcards are
    meaningful only on the held side; as a requirement the spelling is
    ambiguous. Use a {placeholder} for the resource being addressed, or an
    opaque scope for a context-less capability."""


class InvalidBoundValueError(BindError):
    """A placeholder was bound to "" or "*" — the wildcard spelling, not a
    concrete resource name. Binding one would silently widen the requirement to
    the whole resource class, so a binder that could not resolve a value fails
    here rather than widening the gate."""
```

Add to `Pattern` (a frozen dataclass, so these are computed properties):

```python
    @property
    def placeholder(self) -> Optional[str]:
        """The binding key when this pattern's resourceName has the form
        "{key}", else None. "{}" is a literal, not a placeholder. Meaningful
        only on the requirement side; held-side placeholders are literal text.
        """
        n = self.name
        if n is not None and len(n) > 2 and n.startswith("{") and n.endswith("}"):
            return n[1:-1]
        return None

    @property
    def is_wildcard_name(self) -> bool:
        """Whether this pattern's resourceName is a wildcard. Note `parse` maps
        the short form (<resource>:<verb>) to name="*"."""
        return self.opaque is None and self.name in ("*", "")
```

- [ ] **Step 4: Add the strict flag and builder**

In `EntitlementsChecker.__init__`, add after `self.default_scheme = default_scheme`:

```python
        self._strict_requirements = False
```

Add after `with_base_entitlements`:

```python
    def with_strict_requirements(self, strict: bool) -> "EntitlementsChecker":
        """Rejects wildcard resourceNames on the requirement side. Never affects
        entitlements, where wildcards remain meaningful.

        When enabled, bind_requirements raises WildcardRequirementError (the
        loud path) and verify treats both a wildcard requirement and an unbound
        placeholder as unsatisfiable (a fail-closed backstop for callers that
        skip binding).

        Defaults to False; a future major version will default it to True.
        Returns self for chaining.
        """
        self._strict_requirements = strict
        return self
```

- [ ] **Step 5: Implement `bind_requirements` and `wildcard_requirements`**

```python
    def bind_requirements(self, requirements: Requirements, binding: Dict[str, str]) -> Requirements:
        """Substitutes every {placeholder} resourceName with its value from
        `binding`, returning the rewritten requirements. Sets containing no
        placeholder are returned unchanged.

        Raises UnboundPlaceholderError if a placeholder has no entry in
        `binding` — an unbound placeholder is an error, never a pass. Keys that
        match no placeholder are ignored, so a caller may pass a superset.
        Raises WildcardRequirementError under strict mode for a wildcard
        requirement.
        """
        # Strict scans EVERY requirement before any placeholder is resolved, so a
        # wildcard is reported deterministically no matter where it sits in the
        # list. Mirrors the Go reference. A single interleaved pass would make the
        # raised error depend on item order: ["x:{id}:write", "x:*:read"] would
        # raise UnboundPlaceholderError, and the same list reversed would raise
        # WildcardRequirementError — cross-port drift.
        if self._strict_requirements:
            for req_set in requirements:
                for entries in req_set.values():
                    for s in entries:
                        p = Pattern.parse(s)
                        if p.placeholder is None and p.is_wildcard_name:
                            raise WildcardRequirementError(
                                f"wildcard resourceName is not allowed in requirement {s!r}"
                            )

        out: Requirements = []
        for req_set in requirements:
            new_set: RequirementSet = {}
            for scheme, entries in req_set.items():
                new_entries: List[str] = []
                for s in entries:
                    p = Pattern.parse(s)
                    key = p.placeholder
                    if key is None:
                        new_entries.append(s)
                        continue
                    if key not in binding:
                        raise UnboundPlaceholderError(
                            f"unbound placeholder {key!r} in requirement {s!r}"
                        )
                    v = binding[key]
                    # "" and "*" are the wildcard spelling, not concrete names:
                    # binding one would widen the requirement to the whole
                    # class. Fail like an unbound placeholder.
                    if v in ("", "*"):
                        raise InvalidBoundValueError(
                            f"bound value must not be empty or a wildcard: "
                            f"{key!r} bound to {v!r} in requirement {s!r}"
                        )
                    new_entries.append(f"{p.resource}:{v}:{p.verb}")
                new_set[scheme] = new_entries
            out.append(new_set)
        return out

    def wildcard_requirements(self, requirements: Requirements) -> List[str]:
        """Returns the requirement strings whose resourceName is a wildcard —
        exactly what strict mode rejects. De-duplicated, first-seen order; an
        empty result means the requirements are strict-clean. Use it to
        inventory a migration.
        """
        out: List[str] = []
        for req_set in requirements:
            for entries in req_set.values():
                for s in entries:
                    p = Pattern.parse(s)
                    if p.placeholder is None and p.is_wildcard_name and s not in out:
                        out.append(s)
        return out
```

- [ ] **Step 6: Add the strict backstop to verification**

In `_verify_set`, immediately after `req_p = Pattern.parse(req_str)`:

```python
                # Strict backstop for callers that skip bind_requirements: a
                # wildcard requirement is an illegal spelling and an unbound
                # placeholder was never resolved. Both are unsatisfiable rather
                # than silently admitted — a held wildcard would match either.
                if self._strict_requirements and (
                    req_p.placeholder is not None or req_p.is_wildcard_name
                ):
                    return False
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd python && make test 2>&1 | tail -8`
Expected: PASS — all eight new tests plus every pre-existing test, unmodified.

- [ ] **Step 8: Lint**

Run: `cd python && make lint 2>&1 | tail -5`
Expected: `ruff check .` clean.

- [ ] **Step 9: Commit**

```bash
git add python/src/entitlements/__init__.py python/tests/test_entitlements.py
git commit -m "feat(python): add placeholder binding, strict requirements, inventory

Mirrors the Go port. Python has no pre-parsed requirement type, so
bind_requirements operates on raw Requirements and returns rewritten strings.

Refs #4"
```

---

### Task 6: TypeScript — placeholders, binding, strict, inventory

**Files:**
- Modify: `typescript/src/index.ts`
- Test: `typescript/src/index.test.ts`

**Interfaces:**
- Consumes: `SPEC.md` (Task 1); the Go port as the behavior reference.
- Produces:
  - `export type Binding = Record<string, string>`
  - `export class UnboundPlaceholderError extends Error`, `export class WildcardRequirementError extends Error`, `export class InvalidBoundValueError extends Error`
  - `EntitlementsChecker.bindRequirements(reqs: ParsedRequirements, binding: Binding): ParsedRequirements`
  - `EntitlementsChecker.withStrictRequirements(strict: boolean): EntitlementsChecker`
  - `EntitlementsChecker.wildcardRequirements(reqs: Requirements): string[]`
  - `EntitlementPattern.placeholder: string` (internal), `ParsedRequirements.hasPlaceholder: boolean`

> **TypeScript-specific:** mirrors Go closely — it has `ParsedEntitlements` / `ParsedRequirements` and parses the short form to `resourceName: ""`. `ParsedRequirements.patterns` is `readonly`; construct new objects rather than mutating.
>
> **There are TWO `parsePattern`s.** A module-level `function parsePattern(s)` at `index.ts:86` does the actual parsing (and is used by the free `verifyAttenuation` / `compact` functions), and a caching `private parsePattern(s)` method at `index.ts:417` wraps it via `this.cache`. Set the new `placeholder` field in the **module-level** one — the method delegates to it. Call `this.parsePattern` from checker methods so the intern cache is used.
>
> The constructor is `constructor(anonymousEntitlements: readonly string[] | undefined, defaultScheme: string, grantReadyByDefault: boolean)`, and the per-requirement check is `private hasParsedEntitlement(...)` at `index.ts:393`.

- [ ] **Step 1: Write the failing tests**

Append to `typescript/src/index.test.ts`:

```ts
describe("requirement placeholders", () => {
  it("binds a placeholder and scopes to the bound value", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([
      { bearer: ["functions:/api/v1/files:read", "vector_stores:{vector_store_id}:write"] },
    ]);
    const held = ec.parseEntitlements({
      bearer: ["functions:/api/v1/files:read", "vector_stores:vs_alice:all"],
    });

    const bound = ec.bindRequirements(reqs, { vector_store_id: "vs_alice" });
    expect(ec.verifyParsedEntitlements(held, bound)).toBe(true);

    const boundOther = ec.bindRequirements(reqs, { vector_store_id: "vs_bob" });
    expect(ec.verifyParsedEntitlements(held, boundOther)).toBe(false);

    // A held wildcard still passes a bound requirement.
    const admin = ec.parseEntitlements({
      bearer: ["functions:/api/v1/files:read", "vector_stores::all"],
    });
    expect(ec.verifyParsedEntitlements(admin, boundOther)).toBe(true);
  });

  it("throws on an unbound placeholder", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([{ bearer: ["vector_stores:{vector_store_id}:write"] }]);
    expect(() => ec.bindRequirements(reqs, { wrong_key: "vs_alice" })).toThrow(
      UnboundPlaceholderError,
    );
    expect(() => ec.bindRequirements(reqs, {})).toThrow(UnboundPlaceholderError);
  });

  it("throws on a bound value that is empty or a wildcard", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([{ bearer: ["vector_stores:{vector_store_id}:write"] }]);
    // "" and "*" are the wildcard spelling, not a concrete resourceName.
    // Binding one would widen the requirement to every store.
    for (const v of ["", "*"]) {
      expect(() => ec.bindRequirements(reqs, { vector_store_id: v })).toThrow(
        InvalidBoundValueError,
      );
    }
    // A legitimate value still binds.
    expect(() => ec.bindRequirements(reqs, { vector_store_id: "vs_alice" })).not.toThrow();
  });

  it("returns a no-placeholder set unchanged", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([{ bearer: ["functions:/api/v1/files:read"] }]);
    expect(ec.bindRequirements(reqs, {})).toBe(reqs); // identity
  });

  it("binds multiple placeholders by name and ignores superset keys", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([
      { bearer: ["vector_stores:{vector_store_id}:write", "files:{file_id}:read"] },
    ]);
    const bound = ec.bindRequirements(reqs, {
      vector_store_id: "vs_alice",
      file_id: "file_1",
      unused: "ignored",
    });
    const held = ec.parseEntitlements({
      bearer: ["vector_stores:vs_alice:all", "files:file_1:read"],
    });
    expect(ec.verifyParsedEntitlements(held, bound)).toBe(true);

    expect(() => ec.bindRequirements(reqs, { vector_store_id: "vs_alice" })).toThrow(
      UnboundPlaceholderError,
    );
  });

  it("treats a held-side placeholder as literal text", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const held = ec.parseEntitlements({ bearer: ["vector_stores:{vector_store_id}:all"] });
    const reqs = ec.parseRequirements([{ bearer: ["vector_stores:vs_alice:write"] }]);
    expect(ec.verifyParsedEntitlements(held, reqs)).toBe(false);
  });
});

describe("strict requirements", () => {
  it("preserves existing behavior when off and rejects the escalation when on", () => {
    const held = { bearer: ["vector_stores:vs_alice:all"] };
    const reqs: Requirements = [{ bearer: ["vector_stores:*:write"] }];

    expect(new EntitlementsChecker([], "bearer", false).verifyEntitlements(held, reqs)).toBe(true);

    const strict = new EntitlementsChecker([], "bearer", false).withStrictRequirements(true);
    expect(strict.verifyEntitlements(held, reqs)).toBe(false);
    expect(
      strict.verifyEntitlements(held, [{ bearer: ["vector_stores:vs_alice:write"] }]),
    ).toBe(true);

    // A wildcard requirement is illegal by SPELLING — a genuine wildcard grant
    // does not rescue it. (Parity with Go's TestStrictRejectsWildcardRequirement.)
    expect(
      strict.verifyEntitlements({ bearer: ["vector_stores::all"] }, reqs),
    ).toBe(false);
  });

  it("reports the wildcard error regardless of its position in the list", () => {
    // Strict scans all requirements before resolving placeholders, so the
    // wildcard error wins regardless of order. A single interleaved pass would
    // throw UnboundPlaceholderError for the first ordering and
    // WildcardRequirementError for the second — order-dependent, and drift from
    // the Go reference.
    const strict = new EntitlementsChecker([], "bearer", false).withStrictRequirements(true);
    for (const entries of [
      ["vector_stores:{vector_store_id}:write", "vector_stores:*:read"],
      ["vector_stores:*:read", "vector_stores:{vector_store_id}:write"],
    ]) {
      const reqs = strict.parseRequirements([{ bearer: entries }]);
      expect(() => strict.bindRequirements(reqs, {})).toThrow(WildcardRequirementError);
    }
  });

  it("throws WildcardRequirementError from bind for every wildcard spelling", () => {
    const strict = new EntitlementsChecker([], "bearer", false).withStrictRequirements(true);
    for (const s of ["vector_stores:*:write", "vector_stores::write", "vector_stores:write"]) {
      const reqs = strict.parseRequirements([{ bearer: [s] }]);
      expect(() => strict.bindRequirements(reqs, {})).toThrow(WildcardRequirementError);
    }
    for (const s of ["vector_stores_create", "functions:/api/v1/files:read"]) {
      const reqs = strict.parseRequirements([{ bearer: [s] }]);
      expect(() => strict.bindRequirements(reqs, {})).not.toThrow();
    }
  });

  it("fails closed on an unbound placeholder, even for a wildcard grant", () => {
    const strict = new EntitlementsChecker([], "bearer", false).withStrictRequirements(true);
    const reqs = strict.parseRequirements([{ bearer: ["vector_stores:{vector_store_id}:write"] }]);
    const admin = strict.parseEntitlements({ bearer: ["vector_stores::all"] });
    expect(strict.verifyParsedEntitlements(admin, reqs)).toBe(false);
  });
});

describe("wildcardRequirements", () => {
  it("reports exactly what strict rejects, de-duplicated in first-seen order", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    expect(
      ec.wildcardRequirements([
        {
          bearer: [
            "functions:/api/v1/ingest:read",
            "vector_stores:*:write",
            "apitokens:mint",
            "vector_stores:*:write",
            "vector_stores:{vector_store_id}:write",
            "vector_stores_create",
          ],
        },
      ]),
    ).toEqual(["vector_stores:*:write", "apitokens:mint"]);

    expect(ec.wildcardRequirements([{ bearer: ["users:me:read"] }])).toEqual([]);
  });
});
```

Add `UnboundPlaceholderError`, `WildcardRequirementError`, `InvalidBoundValueError`, and `Requirements` to the test file's import from `./index.js` (match the existing import style).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd typescript && npx vitest run 2>&1 | tail -12`
Expected: FAIL — `UnboundPlaceholderError is not exported`.

- [ ] **Step 3: Add the types, errors, and helpers**

In `typescript/src/index.ts`, after the `Requirements` type:

```ts
/**
 * Maps a requirement placeholder key to the concrete resourceName it stands
 * for, e.g. { vector_store_id: "vs_abc" }.
 */
export type Binding = Record<string, string>;

/**
 * A requirement declared a {placeholder} the binding does not resolve. An
 * unbound placeholder is an error, never a pass.
 */
export class UnboundPlaceholderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnboundPlaceholderError";
  }
}

/**
 * Strict mode: a requirement's resourceName is a wildcard. Wildcards are
 * meaningful only on the held side; as a requirement the spelling is ambiguous.
 * Use a {placeholder} for the resource being addressed, or an opaque scope for
 * a context-less capability.
 */
export class WildcardRequirementError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WildcardRequirementError";
  }
}

/**
 * A placeholder was bound to "" or "*" — the wildcard spelling, not a concrete
 * resourceName. Binding one would silently widen the requirement to the whole
 * resource class, so a binder that could not resolve a value fails here rather
 * than widening the gate.
 */
export class InvalidBoundValueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidBoundValueError";
  }
}

/**
 * The binding key when resourceName has the form "{key}", else "". "{}" is a
 * literal resourceName, not a placeholder.
 */
function placeholderKey(resourceName: string): string {
  if (resourceName.length > 2 && resourceName.startsWith("{") && resourceName.endsWith("}")) {
    return resourceName.slice(1, -1);
  }
  return "";
}

/**
 * Whether a resourceName is a wildcard. Empty is the parsed form of both the
 * short (<resource>:<verb>) and medium (<resource>::<verb>) syntaxes.
 */
function isWildcardName(n: string): boolean {
  return n === "" || n === "*";
}
```

Extend the internal pattern interface:

```ts
interface EntitlementPattern {
  raw: string;
  resource: string;
  resourceName: string;
  verb: string;
  isPattern: boolean;
  /** Binding key when resourceName is "{key}", else "". Requirement-side only. */
  placeholder: string;
}
```

In `parsePattern`, set `placeholder: ""` on the opaque and 2-part branches, and `placeholder: placeholderKey(parts[1])` on the 3-part branch. **Every** object literal returned by `parsePattern` needs the field or TypeScript will not compile.

Extend `ParsedRequirements`:

```ts
export interface ParsedRequirements {
  readonly patterns: Array<Record<string, EntitlementPattern[]>>;
  /** Precomputed so bindRequirements can no-op on sets with no placeholder. */
  readonly hasPlaceholder: boolean;
}
```

Update `parseRequirements` to compute and return `hasPlaceholder` (true iff any parsed pattern has a non-empty `placeholder`).

- [ ] **Step 4: Add the strict flag, builder, and `wildcardRequirements`**

Add a **mutable** private field beside `private basePatterns` — mirror that, not `readonly defaultScheme`, since `withStrictRequirements` reassigns it:

```ts
  private strictRequirements = false;
```

Then:

```ts
  /**
   * Rejects wildcard resourceNames on the requirement side. Never affects
   * entitlements, where wildcards remain meaningful.
   *
   * When enabled, bindRequirements throws WildcardRequirementError (the loud
   * path) and verification treats both a wildcard requirement and an unbound
   * placeholder as unsatisfiable (a fail-closed backstop for callers that skip
   * binding).
   *
   * Defaults to false; a future major version will default it to true.
   */
  withStrictRequirements(strict: boolean): EntitlementsChecker {
    this.strictRequirements = strict;
    return this;
  }

  /**
   * The requirement strings whose resourceName is a wildcard — exactly what
   * strict mode rejects. De-duplicated, first-seen order; empty means
   * strict-clean. Use it to inventory a migration.
   */
  wildcardRequirements(reqs: Requirements): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const set of reqs) {
      for (const list of Object.values(set)) {
        for (const s of list) {
          const p = this.parsePattern(s);
          if (!p.isPattern || p.placeholder !== "" || !isWildcardName(p.resourceName)) continue;
          if (seen.has(s)) continue;
          seen.add(s);
          out.push(s);
        }
      }
    }
    return out;
  }
```

> `this.parsePattern` here is the caching method at `index.ts:417`, not the module-level function at `index.ts:86`. Use the method so the intern cache is exercised.

- [ ] **Step 5: Implement `bindRequirements`**

```ts
  /**
   * Substitutes every {placeholder} resourceName in `reqs` with its value from
   * `binding` and returns the rewritten requirements. Sets containing no
   * placeholder are returned unchanged (identity).
   *
   * @throws {UnboundPlaceholderError} a placeholder has no entry in `binding` —
   *   an unbound placeholder is a configuration error, never a pass. Keys that
   *   match no placeholder are ignored, so a caller may pass a superset.
   * @throws {WildcardRequirementError} strict mode, wildcard requirement.
   */
  bindRequirements(reqs: ParsedRequirements, binding: Binding): ParsedRequirements {
    if (this.strictRequirements) {
      for (const set of reqs.patterns) {
        for (const list of Object.values(set)) {
          for (const p of list) {
            if (p.isPattern && p.placeholder === "" && isWildcardName(p.resourceName)) {
              throw new WildcardRequirementError(
                `wildcard resourceName is not allowed in requirement "${p.raw}"`,
              );
            }
          }
        }
      }
    }

    if (!reqs.hasPlaceholder) {
      return reqs;
    }

    const bound = reqs.patterns.map((set) => {
      const newSet: Record<string, EntitlementPattern[]> = {};
      for (const [scheme, list] of Object.entries(set)) {
        newSet[scheme] = list.map((p) => {
          if (p.placeholder === "") return p;
          const v = binding[p.placeholder];
          if (v === undefined) {
            throw new UnboundPlaceholderError(
              `unbound placeholder "${p.placeholder}" in requirement "${p.raw}"`,
            );
          }
          // "" and "*" are the wildcard spelling, not concrete names: binding
          // one would widen the requirement to the whole class. Fail like an
          // unbound placeholder.
          if (isWildcardName(v)) {
            throw new InvalidBoundValueError(
              `bound value must not be empty or a wildcard: "${p.placeholder}" bound to "${v}" in requirement "${p.raw}"`,
            );
          }
          // Construct directly rather than re-parsing: a bound value containing
          // ':' would otherwise be re-split into the wrong shape.
          return {
            raw: `${p.resource}:${v}:${p.verb}`,
            resource: p.resource,
            resourceName: v,
            verb: p.verb,
            isPattern: true,
            placeholder: "",
          };
        });
      }
      return newSet;
    });

    return { patterns: bound, hasPlaceholder: false };
  }
```

- [ ] **Step 6: Add the strict backstop to verification**

At the top of the internal per-requirement check (the method that mirrors Go's `hasParsedEntitlement` — the one taking a single requirement `EntitlementPattern`), before the entitlement loop:

```ts
    // Strict backstop for callers that skip bindRequirements: a wildcard
    // requirement is an illegal spelling and an unbound placeholder was never
    // resolved. Both are unsatisfiable rather than silently admitted — a held
    // wildcard would match either.
    if (
      this.strictRequirements &&
      requirement.isPattern &&
      (requirement.placeholder !== "" || isWildcardName(requirement.resourceName))
    ) {
      return false;
    }
```

- [ ] **Step 7: Run tests, typecheck, and lint**

Run: `cd typescript && npx vitest run 2>&1 | tail -10`
Expected: PASS — all new tests plus every pre-existing test, unmodified.

Run: `cd typescript && make build && make lint 2>&1 | tail -5`
Expected: `tsc` compiles clean, `eslint src` clean.

- [ ] **Step 8: Commit**

```bash
git add typescript/src/index.ts typescript/src/index.test.ts
git commit -m "feat(typescript): add placeholder binding, strict requirements, inventory

Mirrors the Go port, including the ParsedRequirements hasPlaceholder no-op.

Refs #4"
```

---

### Task 7: Cross-port parity, README, and version

**Files:**
- Modify: `README.md`
- Modify: `VERSION`

**Interfaces:**
- Consumes: Tasks 1–6.
- Produces: a releasable `v0.4.0`.

- [ ] **Step 1: Verify all four ports pass together**

Run from the repo root: `make test 2>&1 | tail -20`
Expected: all four language suites pass. This is the parity gate — if one port passes and another fails on the same scenario, that is drift and a bug.

- [ ] **Step 2: Verify parity of the public API names**

Run: `rg -n 'BindRequirements|bind_requirements|bindRequirements' go/ rust/ python/ typescript/ -g '!*test*' -g '!node_modules' -g '!target' -g '!.venv' | rg -v '^\s*//|^\s*#'`
Expected: one definition per port — four hits (Go, Rust, Python, TypeScript). Same check for `WildcardRequirements` / `wildcard_requirements` / `wildcardRequirements` and `WithStrictRequirements` / `with_strict_requirements` / `withStrictRequirements`.

Then verify the three error conditions exist in all four ports:

```bash
rg -c 'ErrUnboundPlaceholder|UnboundPlaceholder' go/entitlements.go rust/src/lib.rs python/src/entitlements/__init__.py typescript/src/index.ts
rg -c 'ErrWildcardRequirement|WildcardRequirement' go/entitlements.go rust/src/lib.rs python/src/entitlements/__init__.py typescript/src/index.ts
rg -c 'ErrInvalidBoundValue|InvalidBoundValue' go/entitlements.go rust/src/lib.rs python/src/entitlements/__init__.py typescript/src/index.ts
```
Expected: every file reports ≥1 for each of the three. A zero in any port is drift — the ports must agree on the error conditions, not just the method names.

- [ ] **Step 3: Run lint across all ports**

Run from the repo root: `make lint 2>&1 | tail -10`
Expected: clean.

- [ ] **Step 4: Update `README.md`**

Add to the pattern-forms documentation a requirement-forms note:

```markdown
### Requirement forms

A requirement — what a caller must satisfy — may additionally be:

- **Placeholder**: `vector_stores:{vector_store_id}:write` — a hole bound to a
  concrete value at check time via `bindRequirements`. Unbound is an error,
  never a pass. (`{}` is a literal, not a placeholder.)
- **Opaque**: `vector_stores_create` — a context-less capability, matched
  exactly and therefore never satisfied by a wildcard grant.

Wildcards (`*` or empty) are a **held-side** concept. As a requirement the
spelling is ambiguous, and `withStrictRequirements(true)` rejects it. Strict
defaults to **false**; use `wildcardRequirements()` to inventory the wildcard
spellings that still need migrating before enabling it.

Binding a placeholder to `""` or `*` is an error — those are the wildcard
spelling, not a concrete resource name, so binding one would widen the
requirement to the whole class.
```

- [ ] **Step 5: Bump `VERSION`**

```bash
echo "0.4.0" > VERSION
```

(The file records the version with no `v` prefix — that is intentional.)

- [ ] **Step 6: Commit**

```bash
git add README.md VERSION
git commit -m "chore: bump version to 0.4.0 for requirement placeholders

Refs #4"
```

- [ ] **Step 7: Release notes for the human**

Do **not** tag. Report to the user that `v0.4.0` is ready, and that tagging
requires **both** `v0.4.0` and `go/v0.4.0` at the same SHA — Go's tooling
requires the `go/`-prefixed tag for a subdirectory module. CI creates the
parallel tag on a `v*` push; confirm before relying on it.

---

## Notes for the implementer

**This release changes no behavior.** `WithStrictRequirements` defaults to false and `{param}` is a new spelling no existing string uses. If you find yourself editing a pre-existing test to make it pass, stop — that is a design violation, not a test problem.

**The one behavior worth internalizing** is why an unbound placeholder must fail closed *even for an admin*: `{vector_store_id}` parses as a literal resourceName, and a held wildcard (`vector_stores::all`) matches any literal. So without the strict backstop, forgetting to call `Bind` would silently admit every wildcard holder — the exact class of silent over-permit this whole change exists to remove.

**Not in this plan:** flipping strict on by default (a later `v1.0.0` plan), host-manager supplying bindings, CR migration, and the knowdb/kdex-crds companion tracks — see the spec's *Companion tracks*.
