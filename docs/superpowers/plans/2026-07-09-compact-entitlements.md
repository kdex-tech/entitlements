# Compact Entitlement-Array Utility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pure `Compact` utility to all four ports that prunes an entitlement array down to a minimal set granting exactly the same authority.

**Architecture:** `Compact` keeps the *maximal* entitlements under the existing dominance relation: it drops any entry another entry strictly dominates, plus exact/equivalent-form duplicates. It is defined **entirely in terms of each port's existing dominance predicate** (`Dominates` / `Pattern::dominates` / `Pattern.dominates` / `dominates`), mirroring how that port's `verify_attenuation` is already built — so compaction can never drift from attenuation.

**Tech Stack:** Go 1.26 (`github.com/kdex-tech/entitlements/go`, testify), Rust (crate `kdex-entitlements`, cargo test), Python (`src/entitlements`, pytest), TypeScript (`@kdex-tech/entitlements`, vitest). Design spec: [docs/superpowers/specs/2026-07-09-compact-entitlements-design.md](../specs/2026-07-09-compact-entitlements-design.md).

## Global Constraints

- **Prune-only / lossless.** Compaction removes only entries already dominated by another entry (plus exact/equivalent-form duplicates). It never synthesizes a wider scope. `Verify*` on the compacted array must equal `Verify*` on the original for every requirement.
- **Use `Dominates`, never request-time `matches`.** The asymmetry (wildcard honored only on the held side) is the correctness foundation.
- **Order-preserving, first-seen wins.** Survivors keep their original strings and their first appearance order.
- **Cross-port parity.** All four ports land together in one PR with equivalent tests (per repo `CLAUDE.md`). Method names map 1:1 in each port's idiomatic case: Go `Compact`, Rust `Pattern::compact`, Python `compact`, TypeScript `compact`.
- **Coverage** stays >80% per port (`SPEC.md`).
- **Version:** additive minor bump to `0.3.0`; `VERSION` file at repo root becomes `0.3.0`.
- **Search with `rg`, not `grep`.**

## Test Fixture: the canonical real-world array (single source of truth)

Every port's headline test uses this exact input and expected output. **INPUT has 49 entries; EXPECTED has 37** (12 pruned: eleven `functions:/<path>:read` dominated by `functions::read`, plus one duplicate `vector_stores:system:read`). Order below is authoritative — survivors are in first-seen order.

**INPUT (49):**
```
functions:/v1/users:read
functions:/v1/users:create
functions:/v1/users:update
functions:/v1/users:delete
users:me:read
users:me:create
users:me:update
users:me:delete
apitokens::mint
apitokens::revoke
vector_stores:system:read
functions:/api/v1/vector_stores:read
functions:/api/v1/vector_stores:create
functions:/api/v1/vector_stores:update
functions:/api/v1/vector_stores:delete
functions:/api/v1/files:read
functions:/api/v1/files:create
functions:/api/v1/files:update
functions:/api/v1/files:delete
functions:/api/v1/search:read
functions:/api/v1/search:create
functions:/api/v1/search:update
functions:/api/v1/search:delete
functions:/api/v1/uploads:read
functions:/api/v1/uploads:create
functions:/api/v1/uploads:update
functions:/api/v1/uploads:delete
functions:/api/v1/ingest:read
functions:/api/v1/ingest:create
functions:/api/v1/ingest:update
functions:/api/v1/ingest:delete
functions:/api/v1/mcp:read
functions:/api/v1/mcp:create
functions:/api/v1/mcp:update
functions:/api/v1/mcp:delete
functions:/api/v1/events:read
functions:/api/v1/events:create
functions:/api/v1/events:update
functions:/api/v1/events:delete
functions:/tenant/v1:read
functions:/tenant/v1:create
functions:/tenant/v1:update
functions:/tenant/v1:delete
functions:/feedback/v1:read
functions:/feedback/v1:create
pages::read
functions::read
vector_stores:system:read
functions:/v1/chat:read
```

**EXPECTED (37):**
```
functions:/v1/users:create
functions:/v1/users:update
functions:/v1/users:delete
users:me:read
users:me:create
users:me:update
users:me:delete
apitokens::mint
apitokens::revoke
vector_stores:system:read
functions:/api/v1/vector_stores:create
functions:/api/v1/vector_stores:update
functions:/api/v1/vector_stores:delete
functions:/api/v1/files:create
functions:/api/v1/files:update
functions:/api/v1/files:delete
functions:/api/v1/search:create
functions:/api/v1/search:update
functions:/api/v1/search:delete
functions:/api/v1/uploads:create
functions:/api/v1/uploads:update
functions:/api/v1/uploads:delete
functions:/api/v1/ingest:create
functions:/api/v1/ingest:update
functions:/api/v1/ingest:delete
functions:/api/v1/mcp:create
functions:/api/v1/mcp:update
functions:/api/v1/mcp:delete
functions:/api/v1/events:create
functions:/api/v1/events:update
functions:/api/v1/events:delete
functions:/tenant/v1:create
functions:/tenant/v1:update
functions:/tenant/v1:delete
functions:/feedback/v1:create
pages::read
functions::read
```

---

### Task 1: `SPEC.md` — Compaction section

**Files:**
- Modify: `SPEC.md` (insert a new section immediately after the `### Attenuation (Dominance)` section, before `### Anonymous Entitlements`)

**Interfaces:**
- Consumes: nothing.
- Produces: the documented contract that Tasks 2–5 implement. Names introduced: Go `Compact`, Rust `Pattern::compact`, Python `compact`, TypeScript `compact`.

- [ ] **Step 1: Insert the Compaction section**

Add this block after the Attenuation section:

```markdown
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
```

- [ ] **Step 2: Verify the section reads correctly in context**

Run: `rg -n "### Compaction" SPEC.md`
Expected: one match, positioned between the Attenuation and Anonymous Entitlements sections.

- [ ] **Step 3: Commit**

```bash
git add SPEC.md
git commit -m "docs(spec): add Compaction section for the Compact array utility"
```

---

### Task 2: Go `Compact` (reference implementation)

**Files:**
- Modify: `go/entitlements.go` (add `Compact` immediately after `VerifyAttenuation`, ~line 503)
- Test: `go/entitlements_test.go` (add test vars + functions)

**Interfaces:**
- Consumes: existing `func Dominates(held, requested string) bool`; `NewEntitlementsChecker`, `VerifyEntitlements`, types `Entitlements`, `Requirements`.
- Produces: `func Compact(entitlements []string) []string`.

- [ ] **Step 1: Write the failing tests**

Add to `go/entitlements_test.go`:

```go
var compactRealWorldInput = []string{
	"functions:/v1/users:read",
	"functions:/v1/users:create",
	"functions:/v1/users:update",
	"functions:/v1/users:delete",
	"users:me:read",
	"users:me:create",
	"users:me:update",
	"users:me:delete",
	"apitokens::mint",
	"apitokens::revoke",
	"vector_stores:system:read",
	"functions:/api/v1/vector_stores:read",
	"functions:/api/v1/vector_stores:create",
	"functions:/api/v1/vector_stores:update",
	"functions:/api/v1/vector_stores:delete",
	"functions:/api/v1/files:read",
	"functions:/api/v1/files:create",
	"functions:/api/v1/files:update",
	"functions:/api/v1/files:delete",
	"functions:/api/v1/search:read",
	"functions:/api/v1/search:create",
	"functions:/api/v1/search:update",
	"functions:/api/v1/search:delete",
	"functions:/api/v1/uploads:read",
	"functions:/api/v1/uploads:create",
	"functions:/api/v1/uploads:update",
	"functions:/api/v1/uploads:delete",
	"functions:/api/v1/ingest:read",
	"functions:/api/v1/ingest:create",
	"functions:/api/v1/ingest:update",
	"functions:/api/v1/ingest:delete",
	"functions:/api/v1/mcp:read",
	"functions:/api/v1/mcp:create",
	"functions:/api/v1/mcp:update",
	"functions:/api/v1/mcp:delete",
	"functions:/api/v1/events:read",
	"functions:/api/v1/events:create",
	"functions:/api/v1/events:update",
	"functions:/api/v1/events:delete",
	"functions:/tenant/v1:read",
	"functions:/tenant/v1:create",
	"functions:/tenant/v1:update",
	"functions:/tenant/v1:delete",
	"functions:/feedback/v1:read",
	"functions:/feedback/v1:create",
	"pages::read",
	"functions::read",
	"vector_stores:system:read",
	"functions:/v1/chat:read",
}

var compactRealWorldExpected = []string{
	"functions:/v1/users:create",
	"functions:/v1/users:update",
	"functions:/v1/users:delete",
	"users:me:read",
	"users:me:create",
	"users:me:update",
	"users:me:delete",
	"apitokens::mint",
	"apitokens::revoke",
	"vector_stores:system:read",
	"functions:/api/v1/vector_stores:create",
	"functions:/api/v1/vector_stores:update",
	"functions:/api/v1/vector_stores:delete",
	"functions:/api/v1/files:create",
	"functions:/api/v1/files:update",
	"functions:/api/v1/files:delete",
	"functions:/api/v1/search:create",
	"functions:/api/v1/search:update",
	"functions:/api/v1/search:delete",
	"functions:/api/v1/uploads:create",
	"functions:/api/v1/uploads:update",
	"functions:/api/v1/uploads:delete",
	"functions:/api/v1/ingest:create",
	"functions:/api/v1/ingest:update",
	"functions:/api/v1/ingest:delete",
	"functions:/api/v1/mcp:create",
	"functions:/api/v1/mcp:update",
	"functions:/api/v1/mcp:delete",
	"functions:/api/v1/events:create",
	"functions:/api/v1/events:update",
	"functions:/api/v1/events:delete",
	"functions:/tenant/v1:create",
	"functions:/tenant/v1:update",
	"functions:/tenant/v1:delete",
	"functions:/feedback/v1:create",
	"pages::read",
	"functions::read",
}

func TestCompact(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", []string{}, []string{}},
		{"single", []string{"x:/a:read"}, []string{"x:/a:read"}},
		{"wildcard prunes specifics", []string{"x:*:read", "x:/a:read", "x:/b:read"}, []string{"x:*:read"}},
		{"medium form prunes specifics", []string{"x::read", "x:/a:read"}, []string{"x::read"}},
		{"all-verb prunes read", []string{"x:/a:all", "x:/a:read"}, []string{"x:/a:all"}},
		{"equivalent forms collapse first-seen", []string{"pages:read", "pages::read", "pages:*:read"}, []string{"pages:read"}},
		{"exact dup dedup", []string{"x:/a:read", "x:/a:read"}, []string{"x:/a:read"}},
		{"opaque dedup", []string{"admin", "admin", "email"}, []string{"admin", "email"}},
		{"opaque never dominates structured", []string{"functions", "functions::read"}, []string{"functions", "functions::read"}},
		{"cross-resource kept", []string{"functions::read", "vector_stores:system:read"}, []string{"functions::read", "vector_stores:system:read"}},
		{"verb non-interference", []string{"functions::read", "functions:/a:create"}, []string{"functions::read", "functions:/a:create"}},
		{"no redundancy preserves order", []string{"x:/a:read", "x:/b:create"}, []string{"x:/a:read", "x:/b:create"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, entitlements.Compact(tc.in))
		})
	}
}

func TestCompactRealWorldArray(t *testing.T) {
	got := entitlements.Compact(compactRealWorldInput)
	assert.Len(t, got, 37)
	assert.Equal(t, compactRealWorldExpected, got)
	// input must not be mutated
	assert.Len(t, compactRealWorldInput, 49)
}

func TestCompactIdempotent(t *testing.T) {
	once := entitlements.Compact(compactRealWorldInput)
	twice := entitlements.Compact(once)
	assert.Equal(t, once, twice)
}

func TestCompactPreservesAuthority(t *testing.T) {
	ec := entitlements.NewEntitlementsChecker(nil, "bearer", false)
	compacted := entitlements.Compact(compactRealWorldInput)
	probes := []struct {
		name string
		req  string
		want bool
	}{
		{"dominated read still granted", "functions:/api/v1/files:read", true},
		{"surviving delete granted", "functions:/api/v1/files:delete", true},
		{"absent resource denied", "billing::read", false},
	}
	for _, p := range probes {
		reqs := entitlements.Requirements{{"bearer": {p.req}}}
		orig := ec.VerifyEntitlements(entitlements.Entitlements{"bearer": compactRealWorldInput}, reqs)
		comp := ec.VerifyEntitlements(entitlements.Entitlements{"bearer": compacted}, reqs)
		assert.Equal(t, p.want, orig, "original result: "+p.name)
		assert.Equal(t, orig, comp, "authority equivalence: "+p.name)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd go && go test ./... -run 'TestCompact' -v`
Expected: compile error `undefined: entitlements.Compact` (or FAIL). This confirms the tests exercise a not-yet-existing function.

- [ ] **Step 3: Write the implementation**

Add to `go/entitlements.go` immediately after `VerifyAttenuation` (after line 503):

```go
// Compact returns the subset of entitlements with every entry removed that is
// strictly dominated by another entry, or that is an exact / equivalent-form
// duplicate (e.g. "pages:read", "pages::read", "pages:*:read" collapse to the
// first-seen one). The result grants exactly the same authority as the input;
// surviving entries keep their original strings and their first-seen order.
//
// It is defined purely in terms of Dominates, so its notion of "broader than"
// can never drift from attenuation. Opaque and malformed scopes collapse only
// by exact equality. Compaction is intended for preparing an entitlement array
// (e.g. before minting a narrowed token); it does not consult the checker's
// anonymous/base patterns or the intern cache.
func Compact(entitlements []string) []string {
	survivors := make([]string, 0, len(entitlements))
	for i, e := range entitlements {
		// (1) Drop e if some OTHER entry strictly dominates it.
		strictlyDominated := false
		for j, o := range entitlements {
			if i == j {
				continue
			}
			if Dominates(o, e) && !Dominates(e, o) {
				strictlyDominated = true
				break
			}
		}
		if strictlyDominated {
			continue
		}
		// (2) e is maximal; keep it unless an equivalent survivor is already
		// present (exact dup or equal form, i.e. mutual dominance).
		dup := false
		for _, s := range survivors {
			if Dominates(s, e) && Dominates(e, s) {
				dup = true
				break
			}
		}
		if !dup {
			survivors = append(survivors, e)
		}
	}
	return survivors
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd go && go test ./... -run 'TestCompact' -v`
Expected: PASS for `TestCompact`, `TestCompactRealWorldArray`, `TestCompactIdempotent`, `TestCompactPreservesAuthority`.

- [ ] **Step 5: Run full Go suite + lint**

Run: `cd go && make test && make lint`
Expected: all tests pass, no lint errors.

- [ ] **Step 6: Commit**

```bash
git add go/entitlements.go go/entitlements_test.go
git commit -m "feat(go): add Compact to prune dominated entitlements from an array"
```

---

### Task 3: Rust `Pattern::compact`

**Files:**
- Modify: `rust/src/lib.rs` (add `compact` inside `impl Pattern`, immediately after `verify_attenuation`, ~line 144)
- Test: `rust/src/lib.rs` (add tests inside the existing `#[cfg(test)] mod tests` block)

**Interfaces:**
- Consumes: `Pattern::parse`, `Pattern::dominates`, `EntitlementsChecker::new`, `EntitlementsChecker::verify`, types `Entitlements`, `Requirements`.
- Produces: `pub fn compact(entitlements: &[String]) -> Vec<String>` (associated function on `Pattern`, mirroring `Pattern::verify_attenuation`).

- [ ] **Step 1: Write the failing tests**

Add inside `mod tests { ... }` in `rust/src/lib.rs`:

```rust
    fn compact_real_world_input() -> Vec<String> {
        [
            "functions:/v1/users:read",
            "functions:/v1/users:create",
            "functions:/v1/users:update",
            "functions:/v1/users:delete",
            "users:me:read",
            "users:me:create",
            "users:me:update",
            "users:me:delete",
            "apitokens::mint",
            "apitokens::revoke",
            "vector_stores:system:read",
            "functions:/api/v1/vector_stores:read",
            "functions:/api/v1/vector_stores:create",
            "functions:/api/v1/vector_stores:update",
            "functions:/api/v1/vector_stores:delete",
            "functions:/api/v1/files:read",
            "functions:/api/v1/files:create",
            "functions:/api/v1/files:update",
            "functions:/api/v1/files:delete",
            "functions:/api/v1/search:read",
            "functions:/api/v1/search:create",
            "functions:/api/v1/search:update",
            "functions:/api/v1/search:delete",
            "functions:/api/v1/uploads:read",
            "functions:/api/v1/uploads:create",
            "functions:/api/v1/uploads:update",
            "functions:/api/v1/uploads:delete",
            "functions:/api/v1/ingest:read",
            "functions:/api/v1/ingest:create",
            "functions:/api/v1/ingest:update",
            "functions:/api/v1/ingest:delete",
            "functions:/api/v1/mcp:read",
            "functions:/api/v1/mcp:create",
            "functions:/api/v1/mcp:update",
            "functions:/api/v1/mcp:delete",
            "functions:/api/v1/events:read",
            "functions:/api/v1/events:create",
            "functions:/api/v1/events:update",
            "functions:/api/v1/events:delete",
            "functions:/tenant/v1:read",
            "functions:/tenant/v1:create",
            "functions:/tenant/v1:update",
            "functions:/tenant/v1:delete",
            "functions:/feedback/v1:read",
            "functions:/feedback/v1:create",
            "pages::read",
            "functions::read",
            "vector_stores:system:read",
            "functions:/v1/chat:read",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn compact_real_world_expected() -> Vec<String> {
        [
            "functions:/v1/users:create",
            "functions:/v1/users:update",
            "functions:/v1/users:delete",
            "users:me:read",
            "users:me:create",
            "users:me:update",
            "users:me:delete",
            "apitokens::mint",
            "apitokens::revoke",
            "vector_stores:system:read",
            "functions:/api/v1/vector_stores:create",
            "functions:/api/v1/vector_stores:update",
            "functions:/api/v1/vector_stores:delete",
            "functions:/api/v1/files:create",
            "functions:/api/v1/files:update",
            "functions:/api/v1/files:delete",
            "functions:/api/v1/search:create",
            "functions:/api/v1/search:update",
            "functions:/api/v1/search:delete",
            "functions:/api/v1/uploads:create",
            "functions:/api/v1/uploads:update",
            "functions:/api/v1/uploads:delete",
            "functions:/api/v1/ingest:create",
            "functions:/api/v1/ingest:update",
            "functions:/api/v1/ingest:delete",
            "functions:/api/v1/mcp:create",
            "functions:/api/v1/mcp:update",
            "functions:/api/v1/mcp:delete",
            "functions:/api/v1/events:create",
            "functions:/api/v1/events:update",
            "functions:/api/v1/events:delete",
            "functions:/tenant/v1:create",
            "functions:/tenant/v1:update",
            "functions:/tenant/v1:delete",
            "functions:/feedback/v1:create",
            "pages::read",
            "functions::read",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_compact_cases() {
        let cases: Vec<(Vec<String>, Vec<String>)> = vec![
            (strs(&[]), strs(&[])),
            (strs(&["x:/a:read"]), strs(&["x:/a:read"])),
            (strs(&["x:*:read", "x:/a:read", "x:/b:read"]), strs(&["x:*:read"])),
            (strs(&["x::read", "x:/a:read"]), strs(&["x::read"])),
            (strs(&["x:/a:all", "x:/a:read"]), strs(&["x:/a:all"])),
            (strs(&["pages:read", "pages::read", "pages:*:read"]), strs(&["pages:read"])),
            (strs(&["x:/a:read", "x:/a:read"]), strs(&["x:/a:read"])),
            (strs(&["admin", "admin", "email"]), strs(&["admin", "email"])),
            (strs(&["functions", "functions::read"]), strs(&["functions", "functions::read"])),
            (strs(&["functions::read", "vector_stores:system:read"]), strs(&["functions::read", "vector_stores:system:read"])),
            (strs(&["functions::read", "functions:/a:create"]), strs(&["functions::read", "functions:/a:create"])),
            (strs(&["x:/a:read", "x:/b:create"]), strs(&["x:/a:read", "x:/b:create"])),
        ];
        for (input, want) in cases {
            assert_eq!(Pattern::compact(&input), want, "input: {:?}", input);
        }
    }

    #[test]
    fn test_compact_real_world_array() {
        let input = compact_real_world_input();
        let got = Pattern::compact(&input);
        assert_eq!(got.len(), 37);
        assert_eq!(got, compact_real_world_expected());
        assert_eq!(input.len(), 49); // input not mutated
    }

    #[test]
    fn test_compact_idempotent() {
        let once = Pattern::compact(&compact_real_world_input());
        let twice = Pattern::compact(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_compact_preserves_authority() {
        let checker = EntitlementsChecker::new(vec![], "bearer".to_string());
        let input = compact_real_world_input();
        let compacted = Pattern::compact(&input);
        let probes: Vec<(&str, bool)> = vec![
            ("functions:/api/v1/files:read", true),
            ("functions:/api/v1/files:delete", true),
            ("billing::read", false),
        ];
        for (req, want) in probes {
            let reqs: Requirements =
                vec![HashMap::from([("bearer".to_string(), vec![req.to_string()])])];
            let ents_orig: Entitlements =
                HashMap::from([("bearer".to_string(), input.clone())]);
            let ents_comp: Entitlements =
                HashMap::from([("bearer".to_string(), compacted.clone())]);
            let orig = checker.verify(&ents_orig, &reqs);
            let comp = checker.verify(&ents_comp, &reqs);
            assert_eq!(orig, want, "original result for {req}");
            assert_eq!(orig, comp, "authority equivalence for {req}");
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test compact`
Expected: compile error `no function or associated item named 'compact' found for enum 'Pattern'`.

- [ ] **Step 3: Write the implementation**

Add inside `impl Pattern` immediately after `verify_attenuation` (after line 144) in `rust/src/lib.rs`:

```rust
    /// Returns the subset of `entitlements` with every entry removed that is
    /// strictly dominated by another entry, or that is an exact /
    /// equivalent-form duplicate (e.g. "pages:read", "pages::read",
    /// "pages:*:read" collapse to the first-seen one). The result grants
    /// exactly the same authority as the input; survivors keep their original
    /// strings and their first-seen order.
    ///
    /// Built purely on `dominates`, so it can never drift from attenuation.
    /// Opaque and malformed scopes collapse only by exact equality.
    pub fn compact(entitlements: &[String]) -> Vec<String> {
        let patterns: Vec<Pattern> = entitlements.iter().map(|s| Pattern::parse(s)).collect();
        let mut survivors: Vec<String> = Vec::new();
        let mut survivor_patterns: Vec<Pattern> = Vec::new();
        for (i, ep) in patterns.iter().enumerate() {
            // (1) Drop if some OTHER entry strictly dominates it.
            let strictly_dominated = patterns
                .iter()
                .enumerate()
                .any(|(j, op)| i != j && op.dominates(ep) && !ep.dominates(op));
            if strictly_dominated {
                continue;
            }
            // (2) Maximal; keep unless an equivalent survivor already present.
            let dup = survivor_patterns
                .iter()
                .any(|sp| sp.dominates(ep) && ep.dominates(sp));
            if !dup {
                survivors.push(entitlements[i].clone());
                survivor_patterns.push(ep.clone());
            }
        }
        survivors
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test compact`
Expected: PASS for `test_compact_cases`, `test_compact_real_world_array`, `test_compact_idempotent`, `test_compact_preserves_authority`.

- [ ] **Step 5: Run full Rust suite + lint**

Run: `cd rust && make test && make lint`
Expected: all tests pass; `cargo clippy -- -D warnings` clean.

- [ ] **Step 6: Commit**

```bash
git add rust/src/lib.rs
git commit -m "feat(rust): add Pattern::compact to prune dominated entitlements"
```

---

### Task 4: Python `compact`

**Files:**
- Modify: `python/src/entitlements/__init__.py` (add module-level `compact` immediately after `verify_attenuation`, ~line 95)
- Test: `python/tests/test_entitlements.py` (add import + tests)

**Interfaces:**
- Consumes: `Pattern.parse`, `Pattern.dominates`, `EntitlementsChecker`, `EntitlementsChecker.verify`.
- Produces: `def compact(entitlements: List[str]) -> List[str]`.

- [ ] **Step 1: Update the test import and write failing tests**

Change the first line of `python/tests/test_entitlements.py` from:

```python
from entitlements import EntitlementsChecker, Pattern, verify_attenuation
```

to:

```python
from entitlements import EntitlementsChecker, Pattern, verify_attenuation, compact
```

Then append these tests:

```python
COMPACT_REAL_WORLD_INPUT = [
    "functions:/v1/users:read",
    "functions:/v1/users:create",
    "functions:/v1/users:update",
    "functions:/v1/users:delete",
    "users:me:read",
    "users:me:create",
    "users:me:update",
    "users:me:delete",
    "apitokens::mint",
    "apitokens::revoke",
    "vector_stores:system:read",
    "functions:/api/v1/vector_stores:read",
    "functions:/api/v1/vector_stores:create",
    "functions:/api/v1/vector_stores:update",
    "functions:/api/v1/vector_stores:delete",
    "functions:/api/v1/files:read",
    "functions:/api/v1/files:create",
    "functions:/api/v1/files:update",
    "functions:/api/v1/files:delete",
    "functions:/api/v1/search:read",
    "functions:/api/v1/search:create",
    "functions:/api/v1/search:update",
    "functions:/api/v1/search:delete",
    "functions:/api/v1/uploads:read",
    "functions:/api/v1/uploads:create",
    "functions:/api/v1/uploads:update",
    "functions:/api/v1/uploads:delete",
    "functions:/api/v1/ingest:read",
    "functions:/api/v1/ingest:create",
    "functions:/api/v1/ingest:update",
    "functions:/api/v1/ingest:delete",
    "functions:/api/v1/mcp:read",
    "functions:/api/v1/mcp:create",
    "functions:/api/v1/mcp:update",
    "functions:/api/v1/mcp:delete",
    "functions:/api/v1/events:read",
    "functions:/api/v1/events:create",
    "functions:/api/v1/events:update",
    "functions:/api/v1/events:delete",
    "functions:/tenant/v1:read",
    "functions:/tenant/v1:create",
    "functions:/tenant/v1:update",
    "functions:/tenant/v1:delete",
    "functions:/feedback/v1:read",
    "functions:/feedback/v1:create",
    "pages::read",
    "functions::read",
    "vector_stores:system:read",
    "functions:/v1/chat:read",
]

COMPACT_REAL_WORLD_EXPECTED = [
    "functions:/v1/users:create",
    "functions:/v1/users:update",
    "functions:/v1/users:delete",
    "users:me:read",
    "users:me:create",
    "users:me:update",
    "users:me:delete",
    "apitokens::mint",
    "apitokens::revoke",
    "vector_stores:system:read",
    "functions:/api/v1/vector_stores:create",
    "functions:/api/v1/vector_stores:update",
    "functions:/api/v1/vector_stores:delete",
    "functions:/api/v1/files:create",
    "functions:/api/v1/files:update",
    "functions:/api/v1/files:delete",
    "functions:/api/v1/search:create",
    "functions:/api/v1/search:update",
    "functions:/api/v1/search:delete",
    "functions:/api/v1/uploads:create",
    "functions:/api/v1/uploads:update",
    "functions:/api/v1/uploads:delete",
    "functions:/api/v1/ingest:create",
    "functions:/api/v1/ingest:update",
    "functions:/api/v1/ingest:delete",
    "functions:/api/v1/mcp:create",
    "functions:/api/v1/mcp:update",
    "functions:/api/v1/mcp:delete",
    "functions:/api/v1/events:create",
    "functions:/api/v1/events:update",
    "functions:/api/v1/events:delete",
    "functions:/tenant/v1:create",
    "functions:/tenant/v1:update",
    "functions:/tenant/v1:delete",
    "functions:/feedback/v1:create",
    "pages::read",
    "functions::read",
]


def test_compact_cases():
    cases = [
        ([], []),
        (["x:/a:read"], ["x:/a:read"]),
        (["x:*:read", "x:/a:read", "x:/b:read"], ["x:*:read"]),
        (["x::read", "x:/a:read"], ["x::read"]),
        (["x:/a:all", "x:/a:read"], ["x:/a:all"]),
        (["pages:read", "pages::read", "pages:*:read"], ["pages:read"]),
        (["x:/a:read", "x:/a:read"], ["x:/a:read"]),
        (["admin", "admin", "email"], ["admin", "email"]),
        (["functions", "functions::read"], ["functions", "functions::read"]),
        (["functions::read", "vector_stores:system:read"], ["functions::read", "vector_stores:system:read"]),
        (["functions::read", "functions:/a:create"], ["functions::read", "functions:/a:create"]),
        (["x:/a:read", "x:/b:create"], ["x:/a:read", "x:/b:create"]),
    ]
    for given, want in cases:
        assert compact(given) == want, f"input: {given}"


def test_compact_real_world_array():
    got = compact(COMPACT_REAL_WORLD_INPUT)
    assert len(got) == 37
    assert got == COMPACT_REAL_WORLD_EXPECTED
    assert len(COMPACT_REAL_WORLD_INPUT) == 49  # input not mutated


def test_compact_idempotent():
    once = compact(COMPACT_REAL_WORLD_INPUT)
    assert compact(once) == once


def test_compact_preserves_authority():
    checker = EntitlementsChecker([], "bearer")
    compacted = compact(COMPACT_REAL_WORLD_INPUT)
    for req, want in [
        ("functions:/api/v1/files:read", True),
        ("functions:/api/v1/files:delete", True),
        ("billing::read", False),
    ]:
        reqs = [{"bearer": [req]}]
        orig = checker.verify({"bearer": COMPACT_REAL_WORLD_INPUT}, reqs)
        comp = checker.verify({"bearer": compacted}, reqs)
        assert orig == want, f"original result for {req}"
        assert orig == comp, f"authority equivalence for {req}"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd python && .venv/bin/pytest tests/test_entitlements.py -k compact -v`
Expected: `ImportError: cannot import name 'compact'` (or collection error). If `.venv` is missing, run `cd python && make test` once to bootstrap it, then re-run.

- [ ] **Step 3: Write the implementation**

Add to `python/src/entitlements/__init__.py` immediately after `verify_attenuation` (after line 95):

```python
def compact(entitlements: List[str]) -> List[str]:
    """Returns the subset of `entitlements` with every entry removed that is
    strictly dominated by another entry, or that is an exact / equivalent-form
    duplicate (e.g. "pages:read", "pages::read", "pages:*:read" collapse to the
    first-seen one). The result grants exactly the same authority as the input;
    survivors keep their original strings and their first-seen order.

    Built purely on `Pattern.dominates`, so it can never drift from attenuation.
    Opaque and malformed scopes collapse only by exact equality.
    """
    patterns = [Pattern.parse(e) for e in entitlements]
    survivors: List[str] = []
    survivor_patterns: List[Pattern] = []
    for i, ep in enumerate(patterns):
        strictly_dominated = any(
            j != i and op.dominates(ep) and not ep.dominates(op)
            for j, op in enumerate(patterns)
        )
        if strictly_dominated:
            continue
        if any(sp.dominates(ep) and ep.dominates(sp) for sp in survivor_patterns):
            continue
        survivors.append(entitlements[i])
        survivor_patterns.append(ep)
    return survivors
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd python && .venv/bin/pytest tests/test_entitlements.py -k compact -v`
Expected: PASS for `test_compact_cases`, `test_compact_real_world_array`, `test_compact_idempotent`, `test_compact_preserves_authority`.

- [ ] **Step 5: Run full Python suite + lint**

Run: `cd python && make test && make lint`
Expected: all tests pass; `ruff check .` clean.

- [ ] **Step 6: Commit**

```bash
git add python/src/entitlements/__init__.py python/tests/test_entitlements.py
git commit -m "feat(python): add compact to prune dominated entitlements"
```

---

### Task 5: TypeScript `compact`

**Files:**
- Modify: `typescript/src/index.ts` (add exported `compact` immediately after `verifyAttenuation`, ~line 168)
- Test: `typescript/src/index.test.ts` (add import + tests)

**Interfaces:**
- Consumes: internal `parsePattern`, internal `dominates`, `EntitlementPattern`; `EntitlementsChecker`, `verifyEntitlements`.
- Produces: `export function compact(entitlements: string[]): string[]`.

- [ ] **Step 1: Update the test import and write failing tests**

Add `compact` to the existing import from `./index.js` in `typescript/src/index.test.ts`:

```typescript
import {
  EntitlementsChecker,
  verifyAttenuation,
  compact,
  type Entitlements,
  type Requirements,
} from "./index.js";
```

Then append:

```typescript
const compactRealWorldInput = [
  "functions:/v1/users:read",
  "functions:/v1/users:create",
  "functions:/v1/users:update",
  "functions:/v1/users:delete",
  "users:me:read",
  "users:me:create",
  "users:me:update",
  "users:me:delete",
  "apitokens::mint",
  "apitokens::revoke",
  "vector_stores:system:read",
  "functions:/api/v1/vector_stores:read",
  "functions:/api/v1/vector_stores:create",
  "functions:/api/v1/vector_stores:update",
  "functions:/api/v1/vector_stores:delete",
  "functions:/api/v1/files:read",
  "functions:/api/v1/files:create",
  "functions:/api/v1/files:update",
  "functions:/api/v1/files:delete",
  "functions:/api/v1/search:read",
  "functions:/api/v1/search:create",
  "functions:/api/v1/search:update",
  "functions:/api/v1/search:delete",
  "functions:/api/v1/uploads:read",
  "functions:/api/v1/uploads:create",
  "functions:/api/v1/uploads:update",
  "functions:/api/v1/uploads:delete",
  "functions:/api/v1/ingest:read",
  "functions:/api/v1/ingest:create",
  "functions:/api/v1/ingest:update",
  "functions:/api/v1/ingest:delete",
  "functions:/api/v1/mcp:read",
  "functions:/api/v1/mcp:create",
  "functions:/api/v1/mcp:update",
  "functions:/api/v1/mcp:delete",
  "functions:/api/v1/events:read",
  "functions:/api/v1/events:create",
  "functions:/api/v1/events:update",
  "functions:/api/v1/events:delete",
  "functions:/tenant/v1:read",
  "functions:/tenant/v1:create",
  "functions:/tenant/v1:update",
  "functions:/tenant/v1:delete",
  "functions:/feedback/v1:read",
  "functions:/feedback/v1:create",
  "pages::read",
  "functions::read",
  "vector_stores:system:read",
  "functions:/v1/chat:read",
];

const compactRealWorldExpected = [
  "functions:/v1/users:create",
  "functions:/v1/users:update",
  "functions:/v1/users:delete",
  "users:me:read",
  "users:me:create",
  "users:me:update",
  "users:me:delete",
  "apitokens::mint",
  "apitokens::revoke",
  "vector_stores:system:read",
  "functions:/api/v1/vector_stores:create",
  "functions:/api/v1/vector_stores:update",
  "functions:/api/v1/vector_stores:delete",
  "functions:/api/v1/files:create",
  "functions:/api/v1/files:update",
  "functions:/api/v1/files:delete",
  "functions:/api/v1/search:create",
  "functions:/api/v1/search:update",
  "functions:/api/v1/search:delete",
  "functions:/api/v1/uploads:create",
  "functions:/api/v1/uploads:update",
  "functions:/api/v1/uploads:delete",
  "functions:/api/v1/ingest:create",
  "functions:/api/v1/ingest:update",
  "functions:/api/v1/ingest:delete",
  "functions:/api/v1/mcp:create",
  "functions:/api/v1/mcp:update",
  "functions:/api/v1/mcp:delete",
  "functions:/api/v1/events:create",
  "functions:/api/v1/events:update",
  "functions:/api/v1/events:delete",
  "functions:/tenant/v1:create",
  "functions:/tenant/v1:update",
  "functions:/tenant/v1:delete",
  "functions:/feedback/v1:create",
  "pages::read",
  "functions::read",
];

describe("compact", () => {
  const cases: Array<{ name: string; in: string[]; want: string[] }> = [
    { name: "empty", in: [], want: [] },
    { name: "single", in: ["x:/a:read"], want: ["x:/a:read"] },
    { name: "wildcard prunes specifics", in: ["x:*:read", "x:/a:read", "x:/b:read"], want: ["x:*:read"] },
    { name: "medium form prunes specifics", in: ["x::read", "x:/a:read"], want: ["x::read"] },
    { name: "all-verb prunes read", in: ["x:/a:all", "x:/a:read"], want: ["x:/a:all"] },
    { name: "equivalent forms collapse", in: ["pages:read", "pages::read", "pages:*:read"], want: ["pages:read"] },
    { name: "exact dup dedup", in: ["x:/a:read", "x:/a:read"], want: ["x:/a:read"] },
    { name: "opaque dedup", in: ["admin", "admin", "email"], want: ["admin", "email"] },
    { name: "opaque never dominates structured", in: ["functions", "functions::read"], want: ["functions", "functions::read"] },
    { name: "cross-resource kept", in: ["functions::read", "vector_stores:system:read"], want: ["functions::read", "vector_stores:system:read"] },
    { name: "verb non-interference", in: ["functions::read", "functions:/a:create"], want: ["functions::read", "functions:/a:create"] },
    { name: "no redundancy preserves order", in: ["x:/a:read", "x:/b:create"], want: ["x:/a:read", "x:/b:create"] },
  ];
  for (const tc of cases) {
    it(tc.name, () => {
      expect(compact(tc.in)).toEqual(tc.want);
    });
  }

  it("compacts the real-world array 49 -> 37", () => {
    const got = compact(compactRealWorldInput);
    expect(got).toHaveLength(37);
    expect(got).toEqual(compactRealWorldExpected);
    expect(compactRealWorldInput).toHaveLength(49); // input not mutated
  });

  it("is idempotent", () => {
    const once = compact(compactRealWorldInput);
    expect(compact(once)).toEqual(once);
  });

  it("preserves authority", () => {
    const checker = new EntitlementsChecker(undefined, "bearer", false);
    const compacted = compact(compactRealWorldInput);
    const probes: Array<[string, boolean]> = [
      ["functions:/api/v1/files:read", true],
      ["functions:/api/v1/files:delete", true],
      ["billing::read", false],
    ];
    for (const [req, want] of probes) {
      const reqs: Requirements = [{ bearer: [req] }];
      const orig = checker.verifyEntitlements({ bearer: compactRealWorldInput }, reqs);
      const comp = checker.verifyEntitlements({ bearer: compacted }, reqs);
      expect(orig).toBe(want);
      expect(comp).toBe(orig);
    }
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd typescript && npx vitest run -t compact`
Expected: FAIL — `compact` is not exported (`does not provide an export named 'compact'`).

- [ ] **Step 3: Write the implementation**

Add to `typescript/src/index.ts` immediately after `verifyAttenuation` (after line 168):

```typescript
/**
 * Returns the subset of `entitlements` with every entry removed that is
 * strictly dominated by another entry, or that is an exact / equivalent-form
 * duplicate (e.g. "pages:read", "pages::read", "pages:*:read" collapse to the
 * first-seen one). The result grants exactly the same authority as the input;
 * survivors keep their original strings and their first-seen order.
 *
 * Built purely on `dominates`, so it can never drift from attenuation. Opaque
 * and malformed scopes collapse only by exact equality.
 */
export function compact(entitlements: string[]): string[] {
  const patterns = entitlements.map((s) => parsePattern(s));
  const survivors: string[] = [];
  const survivorPatterns: EntitlementPattern[] = [];
  for (let i = 0; i < patterns.length; i++) {
    const ep = patterns[i]!;
    // (1) Drop if some OTHER entry strictly dominates it.
    let strictlyDominated = false;
    for (let j = 0; j < patterns.length; j++) {
      if (i === j) continue;
      const op = patterns[j]!;
      if (dominates(op, ep) && !dominates(ep, op)) {
        strictlyDominated = true;
        break;
      }
    }
    if (strictlyDominated) continue;
    // (2) Maximal; keep unless an equivalent survivor already present.
    const dup = survivorPatterns.some((sp) => dominates(sp, ep) && dominates(ep, sp));
    if (!dup) {
      survivors.push(entitlements[i]!);
      survivorPatterns.push(ep);
    }
  }
  return survivors;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd typescript && npx vitest run -t compact`
Expected: PASS for all `compact` describe-block cases.

- [ ] **Step 5: Run full TypeScript suite + lint + build**

Run: `cd typescript && make test && make lint && make build`
Expected: vitest all pass; `eslint src` clean; `tsc` builds without errors.

- [ ] **Step 6: Commit**

```bash
git add typescript/src/index.ts typescript/src/index.test.ts
git commit -m "feat(typescript): add compact to prune dominated entitlements"
```

---

### Task 6: Version bump + full cross-port verification

**Files:**
- Modify: `VERSION`

**Interfaces:**
- Consumes: all four ports from Tasks 2–5.
- Produces: release-ready `0.3.0` across the repo.

- [ ] **Step 1: Bump VERSION**

Replace the entire contents of `VERSION` with:

```
0.3.0
```

- [ ] **Step 2: Run the whole suite from the workspace root of this repo**

Run: `make test`
Expected: `test-go`, `test-rust`, `test-python`, `test-typescript` all pass.

- [ ] **Step 3: Run all linters**

Run: `make lint`
Expected: `lint-go`, `lint-rust`, `lint-python`, `lint-typescript` all clean.

- [ ] **Step 4: Confirm the four ports agree on the headline array**

Run: `rg -c "functions:/v1/users:create" go/entitlements_test.go rust/src/lib.rs python/tests/test_entitlements.py typescript/src/index.test.ts`
Expected: each file reports the same count (the string appears once in INPUT and once in EXPECTED per file → count 2 each), confirming the fixture was transcribed consistently.

- [ ] **Step 5: Commit**

```bash
git add VERSION
git commit -m "chore: bump version to 0.3.0 for Compact utility"
```

---

## Self-Review

**Spec coverage** (against `docs/superpowers/specs/2026-07-09-compact-entitlements-design.md`):

- Public API (Go `Compact`, Rust `Pattern::compact`, Python `compact`, TS `compact`) → Tasks 2–5. ✓
- Algorithm (strict-dominance prune + equivalent-form dedup, first-seen) → identical structure in all four impls. ✓
- Guarantees: authority-preserving → `test_compact_preserves_authority` (all ports); order-preserving + real strings → headline deep-equal; idempotent → `*_idempotent` tests; deterministic first-seen → equivalent-forms case; opaque/malformed → opaque cases. ✓
- Spec test matrix items 1–12 → covered: headline(1), wildcard(2), all-verb(3), equivalent-forms(4), dedup(5), cross-resource(6), verb non-interference(7), opaque(8), edges empty/single/no-redundancy(9), idempotency(10), authority-equivalence(11), input-not-mutated(12, asserted in headline test). ✓
- Docs: `SPEC.md` Compaction section → Task 1; inline doc comments → in each impl step. ✓
- Versioning: `0.3.0` + `VERSION` → Task 6. ✓
- Out-of-scope items (no map variant, no lossy collapse, no canonicalization, no cache/dominance changes) → respected; `Compact` only consumes `Dominates`. ✓

**Placeholder scan:** none — every step carries full code and exact commands.

**Type consistency:** `Compact([]string) []string` (Go), `Pattern::compact(&[String]) -> Vec<String>` (Rust), `compact(List[str]) -> List[str]` (Python), `compact(string[]) : string[]` (TS) — used consistently in each port's tests and implementation. Checker constructors match verified signatures: Go/TS 3-arg (`anon, scheme, grantReady`), Rust/Python 2-arg (`anon, scheme`). Fixture INPUT (49) / EXPECTED (37) identical across all four ports.
