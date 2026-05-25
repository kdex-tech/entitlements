# Anonymous vs. Base Entitlements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Disambiguate `anonymous_entitlements` (correct to truly anonymous-only) from `base_entitlements` (new floor-of-everyone bag exposed via fluent setter), mirrored identically across all four ports.

**Architecture:** Each port grows a sibling `basePatterns` field, a fluent `with*BaseEntitlements` setter, and threads an `isAnonymousCaller` boolean from the public `verify*` entry points down to the per-pattern check helper. The boolean is true iff the caller's `user_entitlements` map is empty (no schemes, or every scheme's list empty). `basePatterns` always applies under the default scheme; `anonymousPatterns` applies under the default scheme only when `isAnonymousCaller`. Constructor signatures stay unchanged. Rust and Python additionally refactor from upfront-merge to per-pattern overlay so they match Go's pre-parsed shape.

**Tech Stack:** Go 1.26 (testify), Rust 2024 edition (cargo test), Python 3.11 (pytest), TypeScript 5+ (vitest, ESM). Spec lives at `docs/superpowers/specs/2026-05-25-anonymous-vs-base-entitlements-design.md`.

---

## File Map

Files modified per port (no new files except the design/plan docs):

- `go/entitlements.go` — add `basePatterns` field, `WithBaseEntitlements` method, thread `isAnonymousCaller`
- `go/entitlements_test.go` — add new test cases (no existing flips required)
- `rust/src/lib.rs` — add `base_entitlements` field, `with_base_entitlements` consuming builder, refactor `verify` to per-pattern overlay, **flip** existing `test_verify` "Anonymous match" assertion, add new tests
- `python/src/entitlements/__init__.py` — add `base_entitlements` attribute, `with_base_entitlements` method, refactor `verify` to per-pattern overlay
- `python/tests/test_entitlements.py` — **flip** existing `test_verify` "Anonymous match" assertion, add new tests
- `typescript/src/index.ts` — add `basePatterns` field, `withBaseEntitlements` method, thread `isAnonymousCaller`
- `typescript/src/index.test.ts` — add new test cases (no existing flips required)
- `SPEC.md` — clarify "Anonymous Entitlements" section, add "Base Entitlements" section
- `typescript/README.md` — add base-entitlements usage example
- `VERSION` — bump `0.1.24` → `0.2.0`

---

## Task 1: Go — implement anonymous-only correction + base entitlements

**Files:**
- Modify: `go/entitlements.go` (struct + helpers around lines 54-90, 200-306, 362-388)
- Test: `go/entitlements_test.go`

The Go port is the canonical reference. Get this right first; the other three mirror its shape.

- [ ] **Step 1: Add failing tests for the new semantic**

Append the following block to `go/entitlements_test.go` (after the existing `TestEntitlementsChecker_CalculateResourceRequirements` block, before the benchmarks):

```go
// TestEntitlementsChecker_AnonymousVsBase regresses the disambiguation
// resolved in issue #3: anonymousEntitlements must apply only when the
// caller is anonymous (empty user_entitlements); baseEntitlements (set
// via WithBaseEntitlements) applies to every caller.
func TestEntitlementsChecker_AnonymousVsBase(t *testing.T) {
	tests := []struct {
		name              string
		anonEntitlements  []string
		baseEntitlements  []string
		userEntitlements  entitlements.Entitlements
		requirements      entitlements.Requirements
		want              bool
	}{
		{
			name:             "anonymous bag applies when caller is empty",
			anonEntitlements: []string{"public:read"},
			userEntitlements: entitlements.Entitlements{},
			requirements:     entitlements.Requirements{{"bearer": {"public:read"}}},
			want:             true,
		},
		{
			name:             "anonymous bag applies when caller has only empty scheme lists",
			anonEntitlements: []string{"public:read"},
			userEntitlements: entitlements.Entitlements{"bearer": {}},
			requirements:     entitlements.Requirements{{"bearer": {"public:read"}}},
			want:             true,
		},
		{
			name:             "anonymous bag does NOT apply when caller has own entitlements",
			anonEntitlements: []string{"public:read"},
			userEntitlements: entitlements.Entitlements{"bearer": {"pages:foo:read"}},
			requirements:     entitlements.Requirements{{"bearer": {"public:read"}}},
			want:             false,
		},
		{
			name:             "anonymous bag does NOT apply when caller has entitlements in a different scheme",
			anonEntitlements: []string{"public:read"},
			userEntitlements: entitlements.Entitlements{"oauth2": {"scope1"}},
			requirements:     entitlements.Requirements{{"bearer": {"public:read"}}},
			want:             false,
		},
		{
			name:             "base bag applies to authenticated caller",
			baseEntitlements: []string{"public:read"},
			userEntitlements: entitlements.Entitlements{"bearer": {"pages:foo:read"}},
			requirements:     entitlements.Requirements{{"bearer": {"public:read"}}},
			want:             true,
		},
		{
			name:             "base bag applies to anonymous caller",
			baseEntitlements: []string{"public:read"},
			userEntitlements: entitlements.Entitlements{},
			requirements:     entitlements.Requirements{{"bearer": {"public:read"}}},
			want:             true,
		},
		{
			name:             "both bags configured: authed caller gets base but not anonymous",
			anonEntitlements: []string{"anon:read"},
			baseEntitlements: []string{"base:read"},
			userEntitlements: entitlements.Entitlements{"bearer": {"pages:foo:read"}},
			requirements:     entitlements.Requirements{{"bearer": {"base:read"}}},
			want:             true,
		},
		{
			name:             "both bags configured: authed caller does not get anonymous",
			anonEntitlements: []string{"anon:read"},
			baseEntitlements: []string{"base:read"},
			userEntitlements: entitlements.Entitlements{"bearer": {"pages:foo:read"}},
			requirements:     entitlements.Requirements{{"bearer": {"anon:read"}}},
			want:             false,
		},
		{
			name:             "both bags configured: anonymous caller gets both",
			anonEntitlements: []string{"anon:read"},
			baseEntitlements: []string{"base:read"},
			userEntitlements: entitlements.Entitlements{},
			requirements:     entitlements.Requirements{{"bearer": {"anon:read", "base:read"}}},
			want:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec := entitlements.NewEntitlementsChecker(tt.anonEntitlements, "bearer", false)
			if tt.baseEntitlements != nil {
				ec = ec.WithBaseEntitlements(tt.baseEntitlements)
			}
			got := ec.VerifyEntitlements(tt.userEntitlements, tt.requirements)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestEntitlementsChecker_WithBaseEntitlements_Replaces verifies the
// setter replaces rather than appends.
func TestEntitlementsChecker_WithBaseEntitlements_Replaces(t *testing.T) {
	ec := entitlements.NewEntitlementsChecker(nil, "bearer", false).
		WithBaseEntitlements([]string{"first:read"}).
		WithBaseEntitlements([]string{"second:read"})

	// "first:read" no longer in the base bag
	assert.False(t, ec.VerifyEntitlements(
		entitlements.Entitlements{"bearer": {"pages:foo:read"}},
		entitlements.Requirements{{"bearer": {"first:read"}}},
	))

	// "second:read" is still there
	assert.True(t, ec.VerifyEntitlements(
		entitlements.Entitlements{"bearer": {"pages:foo:read"}},
		entitlements.Requirements{{"bearer": {"second:read"}}},
	))
}

// TestEntitlementsChecker_VerifyResourceEntitlements_AnonymousVsBase verifies
// the resource identity path honors the new semantic.
func TestEntitlementsChecker_VerifyResourceEntitlements_AnonymousVsBase(t *testing.T) {
	tests := []struct {
		name             string
		anonEntitlements []string
		baseEntitlements []string
		userEntitlements entitlements.Entitlements
		resourceName     string
		want             bool
	}{
		{
			name:             "anon caller satisfies identity via base",
			baseEntitlements: []string{"pages:/foo:read"},
			userEntitlements: entitlements.Entitlements{},
			resourceName:     "/foo",
			want:             true,
		},
		{
			name:             "authed caller satisfies identity via base",
			baseEntitlements: []string{"pages:/foo:read"},
			userEntitlements: entitlements.Entitlements{"bearer": {"other:read"}},
			resourceName:     "/foo",
			want:             true,
		},
		{
			name:             "authed caller does NOT satisfy identity via anonymous",
			anonEntitlements: []string{"pages:/foo:read"},
			userEntitlements: entitlements.Entitlements{"bearer": {"other:read"}},
			resourceName:     "/foo",
			want:             false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec := entitlements.NewEntitlementsChecker(tt.anonEntitlements, "bearer", false)
			if tt.baseEntitlements != nil {
				ec = ec.WithBaseEntitlements(tt.baseEntitlements)
			}
			got, err := ec.VerifyResourceEntitlements("pages", tt.resourceName, tt.userEntitlements, entitlements.Requirements{})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
```

- [ ] **Step 2: Run new tests to verify they fail**

Run: `cd go && go test ./... -run 'AnonymousVsBase|WithBaseEntitlements_Replaces' -v`

Expected: compilation FAIL — `ec.WithBaseEntitlements undefined`. (This is the "doesn't compile" form of RED for Go. Once the method exists, several assertions will fail because the matching logic still applies anonymous to authed callers.)

- [ ] **Step 3: Add `basePatterns` field and `WithBaseEntitlements` method**

Edit `go/entitlements.go`. In the `EntitlementsChecker` struct (around lines 54-61), add `basePatterns` as a sibling of `anonymousPatterns`:

```go
type EntitlementsChecker struct {
	anonymousPatterns   []entitlementPattern
	basePatterns        []entitlementPattern
	cache               map[string]entitlementPattern
	defaultScheme       string
	grantReadyByDefault bool
	log                 *logr.Logger
	mu                  sync.RWMutex
}
```

Add a new method near `WithLogger` (around lines 281-285):

```go
// WithBaseEntitlements sets the base entitlements: patterns that apply to
// every caller (authenticated or anonymous) under the default scheme.
// Unlike anonymousEntitlements (which apply only when the caller's
// entitlements map is empty), base entitlements form a floor of grants
// that every request receives.
//
// Replaces any previously set base entitlements. Intended for use during
// checker construction; not safe for concurrent mutation with verify
// calls in flight.
func (ec *EntitlementsChecker) WithBaseEntitlements(patterns []string) *EntitlementsChecker {
	parsed := make([]entitlementPattern, len(patterns))
	for i, s := range patterns {
		parsed[i] = ec.parsePattern(s)
	}
	ec.basePatterns = parsed
	return ec
}
```

- [ ] **Step 4: Thread `isAnonymousCaller` and consult `basePatterns`**

Edit `go/entitlements.go`.

Add a private helper near the bottom of the file (after `entitlementPattern.matches`):

```go
// isAnonymousCaller returns true iff the caller provided no entitlements
// at all (empty map, or every scheme has an empty list).
func isAnonymousCaller(entitlements map[string][]entitlementPattern) bool {
	if len(entitlements) == 0 {
		return true
	}
	for _, list := range entitlements {
		if len(list) > 0 {
			return false
		}
	}
	return true
}
```

Replace `VerifyParsedEntitlements` (lines 200-224):

```go
func (ec *EntitlementsChecker) VerifyParsedEntitlements(
	entitlements ParsedEntitlements,
	requirements ParsedRequirements,
) (result bool) {
	defer func() {
		if ec.log != nil {
			ec.log.V(2).Info("Verified parsed entitlements", "result", result)
		}
	}()

	if len(requirements.patterns) == 0 {
		return true
	}

	anon := isAnonymousCaller(entitlements.patterns)
	for _, requirement := range requirements.patterns {
		if ec.satisfiesAndRequirements(entitlements.patterns, requirement, anon) {
			result = true
			return
		}
	}

	result = false
	return
}
```

Replace `VerifyResourceParsedEntitlements` identity check (lines 248-279) — change the `hasParsedEntitlement` call to pass the `isAnonymousCaller` value, and ensure the subsequent `VerifyParsedEntitlements` call doesn't re-compute it incorrectly:

```go
func (ec *EntitlementsChecker) VerifyResourceParsedEntitlements(
	resource string,
	resourceName string,
	parsedEntitlements ParsedEntitlements,
	parsedRequirements ParsedRequirements,
	verbs ...string,
) (bool, error) {
	if resource == "" || resourceName == "" {
		return false, fmt.Errorf("resource and resourceName must not be empty")
	}

	verb := "read"
	if len(verbs) > 0 && verbs[0] != "" {
		verb = verbs[0]
	}

	identity := resource + ":" + resourceName + ":" + verb
	parsedIdentity := ec.parsePattern(identity)

	anon := isAnonymousCaller(parsedEntitlements.patterns)
	hasIdentity := ec.grantReadyByDefault || ec.hasParsedEntitlement(parsedEntitlements.patterns[ec.defaultScheme], ec.defaultScheme, parsedIdentity, anon)
	if !hasIdentity {
		return false, nil
	}

	if len(parsedRequirements.patterns) == 0 {
		return true, nil
	}

	return ec.VerifyParsedEntitlements(parsedEntitlements, parsedRequirements), nil
}
```

Replace `hasParsedEntitlement` (lines 287-306):

```go
func (ec *EntitlementsChecker) hasParsedEntitlement(entitlementList []entitlementPattern, scheme string, requirement entitlementPattern, isAnonymousCaller bool) bool {
	// Caller's own entitlements for this scheme.
	for _, entitlement := range entitlementList {
		if entitlement.matches(requirement) {
			return true
		}
	}

	if scheme == ec.defaultScheme {
		// Base entitlements always apply.
		for _, pattern := range ec.basePatterns {
			if pattern.matches(requirement) {
				return true
			}
		}
		// Anonymous entitlements apply only when caller is anonymous.
		if isAnonymousCaller {
			for _, pattern := range ec.anonymousPatterns {
				if pattern.matches(requirement) {
					return true
				}
			}
		}
	}

	return false
}
```

Replace `satisfiesAndRequirements` and `satisfiesRequirement` (lines 362-388):

```go
func (ec *EntitlementsChecker) satisfiesAndRequirements(entitlements map[string][]entitlementPattern, requirement map[string][]entitlementPattern, isAnonymousCaller bool) bool {
	for scheme, requirementList := range requirement {
		_, ok := entitlements[scheme]
		hasFallback := scheme == ec.defaultScheme &&
			(len(ec.basePatterns) > 0 || (isAnonymousCaller && len(ec.anonymousPatterns) > 0))
		if !ok && !hasFallback {
			return false
		}

		if !ec.satisfiesRequirement(entitlements, scheme, requirementList, isAnonymousCaller) {
			return false
		}
	}

	return true
}

func (ec *EntitlementsChecker) satisfiesRequirement(entitlements map[string][]entitlementPattern, scheme string, requirement []entitlementPattern, isAnonymousCaller bool) bool {
	for _, parsedReq := range requirement {
		if !ec.hasParsedEntitlement(entitlements[scheme], scheme, parsedReq, isAnonymousCaller) {
			return false
		}
	}

	return true
}
```

- [ ] **Step 5: Run all Go tests to verify they pass**

Run: `cd go && make test`

Expected: all tests pass, including the new `AnonymousVsBase`, `WithBaseEntitlements_Replaces`, and `VerifyResourceEntitlements_AnonymousVsBase` cases.

- [ ] **Step 6: Run Go linter**

Run: `cd go && make lint`

Expected: clean (downloads golangci-lint v2.10.1 on first run).

- [ ] **Step 7: Commit**

```bash
git add go/entitlements.go go/entitlements_test.go
git commit -m "$(cat <<'EOF'
feat(go): correct anonymous_entitlements semantic and add base_entitlements

anonymous_entitlements now applies only when the caller's user_entitlements
map is empty (no schemes, or every scheme's list empty). The new fluent
WithBaseEntitlements setter installs a separate "floor" bag that applies
to every caller under the default scheme. Threads isAnonymousCaller from
the public verify entry points down through hasParsedEntitlement.

Resolves part of issue #3.
EOF
)"
```

---

## Task 2: Rust — mirror the Go change

**Files:**
- Modify: `rust/src/lib.rs` (struct, builder, `verify`, `verify_set`, tests at lines 87-198 and 196-282)

- [ ] **Step 1: Flip the existing floor-of-everyone assertion (RED for the regression)**

Edit `rust/src/lib.rs:240-244`. Change the "Anonymous match" assertion to assert the **opposite** — that an authenticated caller does NOT receive anonymous coverage. Also add an explicit anonymous-caller positive case below it:

```rust
        // Authed caller does NOT get the anonymous bag (regression for issue #3)
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["anonymous:*:read".to_string()]);
        let requirements = vec![req_set];
        assert!(!checker.verify(&entitlements, &requirements));

        // Anonymous caller DOES get the anonymous bag
        let empty_entitlements = Entitlements::new();
        let mut req_set = RequirementSet::new();
        req_set.insert("bearer".to_string(), vec!["anonymous:*:read".to_string()]);
        let requirements = vec![req_set];
        assert!(checker.verify(&empty_entitlements, &requirements));
```

- [ ] **Step 2: Add the new dedicated test for base + anonymous interplay**

Append to the `tests` mod in `rust/src/lib.rs` (before the closing `}` of `mod tests`):

```rust
    #[test]
    fn test_anonymous_vs_base() {
        let checker = EntitlementsChecker::new(
            vec!["anon:read".to_string()],
            "bearer".to_string(),
        )
        .with_base_entitlements(vec!["base:read".to_string()]);

        let mut authed = Entitlements::new();
        authed.insert("bearer".to_string(), vec!["pages:foo:read".to_string()]);
        let anonymous = Entitlements::new();

        let need_anon = vec![{
            let mut s = RequirementSet::new();
            s.insert("bearer".to_string(), vec!["anon:read".to_string()]);
            s
        }];
        let need_base = vec![{
            let mut s = RequirementSet::new();
            s.insert("bearer".to_string(), vec!["base:read".to_string()]);
            s
        }];

        // Authed caller: base yes, anon no
        assert!(checker.verify(&authed, &need_base));
        assert!(!checker.verify(&authed, &need_anon));

        // Anonymous caller: both
        assert!(checker.verify(&anonymous, &need_base));
        assert!(checker.verify(&anonymous, &need_anon));

        // Authed caller with only an empty scheme list is still anonymous
        let mut empty_list = Entitlements::new();
        empty_list.insert("bearer".to_string(), vec![]);
        assert!(checker.verify(&empty_list, &need_anon));
    }

    #[test]
    fn test_anonymous_vs_base_via_verify_resource() {
        // Authed caller satisfies identity via base
        let base_checker = EntitlementsChecker::new(vec![], "bearer".to_string())
            .with_base_entitlements(vec!["pages:/foo:read".to_string()]);
        let mut authed = Entitlements::new();
        authed.insert("bearer".to_string(), vec!["other:read".to_string()]);
        assert!(base_checker.verify_resource(&authed, "pages", "/foo", "read", &vec![]));

        // Anonymous caller satisfies identity via base
        let anonymous = Entitlements::new();
        assert!(base_checker.verify_resource(&anonymous, "pages", "/foo", "read", &vec![]));

        // Authed caller does NOT satisfy identity via anonymous bag
        let anon_checker = EntitlementsChecker::new(
            vec!["pages:/foo:read".to_string()],
            "bearer".to_string(),
        );
        assert!(!anon_checker.verify_resource(&authed, "pages", "/foo", "read", &vec![]));

        // Anonymous caller DOES satisfy identity via anonymous bag
        assert!(anon_checker.verify_resource(&anonymous, "pages", "/foo", "read", &vec![]));
    }

    #[test]
    fn test_with_base_entitlements_replaces() {
        let checker = EntitlementsChecker::new(vec![], "bearer".to_string())
            .with_base_entitlements(vec!["first:read".to_string()])
            .with_base_entitlements(vec!["second:read".to_string()]);

        let mut authed = Entitlements::new();
        authed.insert("bearer".to_string(), vec!["pages:foo:read".to_string()]);

        let need_first = vec![{
            let mut s = RequirementSet::new();
            s.insert("bearer".to_string(), vec!["first:read".to_string()]);
            s
        }];
        let need_second = vec![{
            let mut s = RequirementSet::new();
            s.insert("bearer".to_string(), vec!["second:read".to_string()]);
            s
        }];

        assert!(!checker.verify(&authed, &need_first));
        assert!(checker.verify(&authed, &need_second));
    }
```

- [ ] **Step 3: Run tests to verify they fail (RED)**

Run: `cd rust && cargo test`

Expected: compilation FAIL — `with_base_entitlements` is not defined. (After the method exists, the flipped `assert!(!...)` will still pass under the old behavior because nothing has changed yet — that's fine; the new `test_anonymous_vs_base` cases drive the actual semantic change.)

- [ ] **Step 4: Refactor `EntitlementsChecker` — add `base_entitlements`, switch to pre-parsed shape, drop upfront merge**

Replace the `EntitlementsChecker` block (lines 86-194) of `rust/src/lib.rs` with:

```rust
/// The main entitlements checker.
pub struct EntitlementsChecker {
    anonymous_entitlements: Vec<Pattern>,
    base_entitlements: Vec<Pattern>,
    default_scheme: String,
}

impl EntitlementsChecker {
    pub fn new(anonymous_entitlements: Vec<String>, default_scheme: String) -> Self {
        let parsed_anon = anonymous_entitlements.iter().map(|s| Pattern::parse(s)).collect();
        Self {
            anonymous_entitlements: parsed_anon,
            base_entitlements: Vec::new(),
            default_scheme,
        }
    }

    /// Sets the base entitlements: patterns that apply to every caller
    /// (authenticated or anonymous) under the default scheme. Unlike
    /// `anonymous_entitlements` (which apply only when the caller's
    /// entitlements map is empty), base entitlements form a floor of grants
    /// that every request receives.
    ///
    /// Replaces any previously set base entitlements. Consuming-self
    /// builder; intended for use during checker construction.
    pub fn with_base_entitlements(mut self, patterns: Vec<String>) -> Self {
        self.base_entitlements = patterns.iter().map(|s| Pattern::parse(s)).collect();
        self
    }

    /// Verifies if the user's entitlements satisfy any of the requirements.
    pub fn verify(&self, user_entitlements: &Entitlements, requirements: &Requirements) -> bool {
        if requirements.is_empty() {
            return true;
        }

        let parsed: HashMap<String, Vec<Pattern>> = user_entitlements
            .iter()
            .map(|(scheme, list)| (scheme.clone(), list.iter().map(|s| Pattern::parse(s)).collect()))
            .collect();

        let is_anonymous = parsed.is_empty() || parsed.values().all(|v| v.is_empty());

        for req_set in requirements {
            if self.verify_set(&parsed, req_set, is_anonymous) {
                return true;
            }
        }

        false
    }

    fn verify_set(
        &self,
        user_patterns: &HashMap<String, Vec<Pattern>>,
        req_set: &RequirementSet,
        is_anonymous: bool,
    ) -> bool {
        for (scheme, required_patterns) in req_set {
            let user_list_present = user_patterns.contains_key(scheme);
            let has_fallback = scheme == &self.default_scheme
                && (!self.base_entitlements.is_empty()
                    || (is_anonymous && !self.anonymous_entitlements.is_empty()));
            if !user_list_present && !has_fallback {
                return false;
            }

            let empty: Vec<Pattern> = Vec::new();
            let user_list = user_patterns.get(scheme).unwrap_or(&empty);

            for req_str in required_patterns {
                let req_p = Pattern::parse(req_str);
                let satisfied_by_user = user_list.iter().any(|p| p.satisfies(&req_p));
                let satisfied_by_base = scheme == &self.default_scheme
                    && self.base_entitlements.iter().any(|p| p.satisfies(&req_p));
                let satisfied_by_anon = scheme == &self.default_scheme
                    && is_anonymous
                    && self.anonymous_entitlements.iter().any(|p| p.satisfies(&req_p));
                if !satisfied_by_user && !satisfied_by_base && !satisfied_by_anon {
                    return false;
                }
            }
        }
        true
    }

    /// Verifies access for a specific resource instance.
    pub fn verify_resource(
        &self,
        user_entitlements: &Entitlements,
        resource: &str,
        name: &str,
        verb: &str,
        additional_requirements: &Requirements,
    ) -> bool {
        let identity_req = format!("{}:{}:{}", resource, name, verb);

        if additional_requirements.is_empty() {
            let mut set = RequirementSet::new();
            set.insert(self.default_scheme.clone(), vec![identity_req]);
            return self.verify(user_entitlements, &vec![set]);
        }

        let mut combined_requirements = Vec::new();
        for set in additional_requirements {
            let mut new_set = set.clone();
            new_set
                .entry(self.default_scheme.clone())
                .or_default()
                .push(identity_req.clone());
            combined_requirements.push(new_set);
        }

        self.verify(user_entitlements, &combined_requirements)
    }
}
```

- [ ] **Step 5: Run tests to verify they pass (GREEN)**

Run: `cd rust && cargo test`

Expected: all tests pass, including `test_anonymous_vs_base`, `test_with_base_entitlements_replaces`, and the flipped assertions in `test_verify`.

- [ ] **Step 6: Run linter**

Run: `cd rust && cargo clippy -- -D warnings`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add rust/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(rust): correct anonymous_entitlements semantic and add base_entitlements

anonymous_entitlements now applies only when the caller's user_entitlements
map is empty. The new with_base_entitlements consuming builder installs a
"floor" bag applied to every caller under the default scheme. Refactors
verify to a per-pattern overlay (no upfront merge clone), aligning with
the Go port's pre-parsed shape.

Flips the prior "Anonymous match" assertion in test_verify (which codified
the floor-of-everyone behavior) to assert the corrected semantic, plus
adds dedicated test_anonymous_vs_base and test_with_base_entitlements_replaces
cases.

Resolves part of issue #3.
EOF
)"
```

---

## Task 3: Python — mirror the Go change

**Files:**
- Modify: `python/src/entitlements/__init__.py` (class definition at lines 52-115)
- Modify: `python/tests/test_entitlements.py` (existing `test_verify` at lines 26-52)

- [ ] **Step 1: Flip the existing floor-of-everyone assertion and add explicit anonymous case**

Edit `python/tests/test_entitlements.py:39-41`. Replace the "Anonymous match" block with:

```python
    # Authed caller does NOT get the anonymous bag (regression for issue #3)
    requirements = [{"bearer": ["anonymous:*:read"]}]
    assert not checker.verify(user_entitlements, requirements)

    # Anonymous caller DOES get the anonymous bag
    requirements = [{"bearer": ["anonymous:*:read"]}]
    assert checker.verify({}, requirements)
```

- [ ] **Step 2: Add new dedicated tests**

Append to `python/tests/test_entitlements.py`:

```python
def test_anonymous_vs_base():
    checker = EntitlementsChecker(
        anonymous_entitlements=["anon:read"],
        default_scheme="bearer",
    ).with_base_entitlements(["base:read"])

    authed = {"bearer": ["pages:foo:read"]}
    anonymous = {}

    need_anon = [{"bearer": ["anon:read"]}]
    need_base = [{"bearer": ["base:read"]}]

    # Authed caller: base yes, anon no
    assert checker.verify(authed, need_base)
    assert not checker.verify(authed, need_anon)

    # Anonymous caller: both
    assert checker.verify(anonymous, need_base)
    assert checker.verify(anonymous, need_anon)

    # Caller with only an empty scheme list is still anonymous
    assert checker.verify({"bearer": []}, need_anon)


def test_with_base_entitlements_replaces():
    checker = (
        EntitlementsChecker(default_scheme="bearer")
        .with_base_entitlements(["first:read"])
        .with_base_entitlements(["second:read"])
    )
    authed = {"bearer": ["pages:foo:read"]}

    assert not checker.verify(authed, [{"bearer": ["first:read"]}])
    assert checker.verify(authed, [{"bearer": ["second:read"]}])


def test_base_entitlements_via_verify_resource():
    checker = EntitlementsChecker(default_scheme="bearer").with_base_entitlements(
        ["pages:/foo:read"]
    )
    # Anonymous caller satisfies identity via base
    assert checker.verify_resource({}, "pages", "/foo", "read")
    # Authed caller satisfies identity via base (caller has unrelated entitlements)
    assert checker.verify_resource({"bearer": ["other:read"]}, "pages", "/foo", "read")
    # Authed caller does NOT satisfy identity via anonymous
    anon_checker = EntitlementsChecker(
        anonymous_entitlements=["pages:/foo:read"], default_scheme="bearer"
    )
    assert not anon_checker.verify_resource(
        {"bearer": ["other:read"]}, "pages", "/foo", "read"
    )
```

- [ ] **Step 3: Run tests to verify they fail (RED)**

Run: `cd python && make test`

Expected: tests fail. `test_anonymous_vs_base` and `test_with_base_entitlements_replaces` fail at the `.with_base_entitlements(...)` call (`AttributeError`). The flipped assertion in `test_verify` fails because the old floor-of-everyone behavior is still in place.

- [ ] **Step 4: Refactor the class**

Replace the `EntitlementsChecker` class in `python/src/entitlements/__init__.py` (lines 52-115) with:

```python
class EntitlementsChecker:
    def __init__(self, anonymous_entitlements: Optional[List[str]] = None, default_scheme: str = "bearer"):
        self._anonymous_patterns: List[Pattern] = [
            Pattern.parse(s) for s in (anonymous_entitlements or [])
        ]
        self._base_patterns: List[Pattern] = []
        self.default_scheme = default_scheme

    def with_base_entitlements(self, patterns: List[str]) -> "EntitlementsChecker":
        """Sets the base entitlements: patterns that apply to every caller
        (authenticated or anonymous) under the default scheme. Unlike
        anonymous_entitlements (which apply only when the caller's
        entitlements map is empty), base entitlements form a floor of
        grants that every request receives.

        Replaces any previously set base entitlements. Returns self for
        chaining. Intended for use during checker construction; not safe
        for concurrent mutation with verify calls in flight.
        """
        self._base_patterns = [Pattern.parse(s) for s in patterns]
        return self

    def verify(self, user_entitlements: Entitlements, requirements: Requirements) -> bool:
        if not requirements:
            return True

        parsed: Dict[SecurityScheme, List[Pattern]] = {
            scheme: [Pattern.parse(e) for e in entries]
            for scheme, entries in user_entitlements.items()
        }
        is_anonymous = not parsed or all(not v for v in parsed.values())

        for req_set in requirements:
            if self._verify_set(parsed, req_set, is_anonymous):
                return True
        return False

    def _verify_set(
        self,
        user_patterns: Dict[SecurityScheme, List[Pattern]],
        req_set: RequirementSet,
        is_anonymous: bool,
    ) -> bool:
        for scheme, required_patterns in req_set.items():
            user_list_present = scheme in user_patterns
            has_fallback = scheme == self.default_scheme and (
                bool(self._base_patterns)
                or (is_anonymous and bool(self._anonymous_patterns))
            )
            if not user_list_present and not has_fallback:
                return False

            user_list = user_patterns.get(scheme, [])
            for req_str in required_patterns:
                req_p = Pattern.parse(req_str)
                satisfied = (
                    any(p.satisfies(req_p) for p in user_list)
                    or (
                        scheme == self.default_scheme
                        and any(p.satisfies(req_p) for p in self._base_patterns)
                    )
                    or (
                        scheme == self.default_scheme
                        and is_anonymous
                        and any(p.satisfies(req_p) for p in self._anonymous_patterns)
                    )
                )
                if not satisfied:
                    return False
        return True

    def verify_resource(
        self,
        user_entitlements: Entitlements,
        resource: str,
        name: str,
        verb: str,
        additional_requirements: Optional[Requirements] = None
    ) -> bool:
        identity_req = f"{resource}:{name}:{verb}"

        if not additional_requirements:
            return self.verify(user_entitlements, [{self.default_scheme: [identity_req]}])

        combined: Requirements = []
        for req_set in additional_requirements:
            new_set = dict(req_set)
            new_set.setdefault(self.default_scheme, []).append(identity_req)
            combined.append(new_set)

        return self.verify(user_entitlements, combined)
```

(The `anonymous_entitlements` and `Union` imports remain at the top; verify nothing else references the old `self.anonymous_entitlements` list attribute by name.)

- [ ] **Step 5: Run tests to verify they pass (GREEN)**

Run: `cd python && make test`

Expected: all tests pass.

- [ ] **Step 6: Run linter**

Run: `cd python && make lint`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add python/src/entitlements/__init__.py python/tests/test_entitlements.py
git commit -m "$(cat <<'EOF'
feat(python): correct anonymous_entitlements semantic and add base_entitlements

anonymous_entitlements now applies only when the caller's user_entitlements
map is empty. The new with_base_entitlements fluent setter installs a
"floor" bag applied to every caller under the default scheme. Refactors
verify to a per-pattern overlay (no upfront merge), aligning with the
Go port's pre-parsed shape.

Flips the prior "Anonymous match" assertion in test_verify (which
codified floor-of-everyone behavior) to assert the corrected semantic,
plus adds dedicated test_anonymous_vs_base,
test_with_base_entitlements_replaces, and
test_base_entitlements_via_verify_resource cases.

Resolves part of issue #3.
EOF
)"
```

---

## Task 4: TypeScript — mirror the Go change

**Files:**
- Modify: `typescript/src/index.ts` (class at lines 86-337)
- Test: `typescript/src/index.test.ts`

- [ ] **Step 1: Add new test block**

Append to `typescript/src/index.test.ts` (after the `describe("verifyResourceEntitlements with path resourceNames", ...)` block):

```ts
describe("anonymous vs base entitlements", () => {
  it("anonymous bag applies when caller is empty", () => {
    const ec = new EntitlementsChecker(["public:read"], "bearer", false);
    expect(ec.verifyEntitlements({}, [{ bearer: ["public:read"] }])).toBe(true);
  });

  it("anonymous bag applies when caller has only empty scheme lists", () => {
    const ec = new EntitlementsChecker(["public:read"], "bearer", false);
    expect(ec.verifyEntitlements({ bearer: [] }, [{ bearer: ["public:read"] }])).toBe(true);
  });

  it("anonymous bag does NOT apply when caller has own entitlements", () => {
    const ec = new EntitlementsChecker(["public:read"], "bearer", false);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["public:read"] }]),
    ).toBe(false);
  });

  it("anonymous bag does NOT apply when caller has entitlements in a different scheme", () => {
    const ec = new EntitlementsChecker(["public:read"], "bearer", false);
    expect(
      ec.verifyEntitlements({ oauth2: ["scope1"] }, [{ bearer: ["public:read"] }]),
    ).toBe(false);
  });

  it("base bag applies to authenticated caller", () => {
    const ec = new EntitlementsChecker([], "bearer", false).withBaseEntitlements([
      "public:read",
    ]);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["public:read"] }]),
    ).toBe(true);
  });

  it("base bag applies to anonymous caller", () => {
    const ec = new EntitlementsChecker([], "bearer", false).withBaseEntitlements([
      "public:read",
    ]);
    expect(ec.verifyEntitlements({}, [{ bearer: ["public:read"] }])).toBe(true);
  });

  it("both bags: authed caller gets base but not anonymous", () => {
    const ec = new EntitlementsChecker(["anon:read"], "bearer", false).withBaseEntitlements([
      "base:read",
    ]);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["base:read"] }]),
    ).toBe(true);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["anon:read"] }]),
    ).toBe(false);
  });

  it("both bags: anonymous caller gets both", () => {
    const ec = new EntitlementsChecker(["anon:read"], "bearer", false).withBaseEntitlements([
      "base:read",
    ]);
    expect(ec.verifyEntitlements({}, [{ bearer: ["anon:read", "base:read"] }])).toBe(true);
  });

  it("withBaseEntitlements replaces (does not append)", () => {
    const ec = new EntitlementsChecker([], "bearer", false)
      .withBaseEntitlements(["first:read"])
      .withBaseEntitlements(["second:read"]);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["first:read"] }]),
    ).toBe(false);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["second:read"] }]),
    ).toBe(true);
  });

  it("verifyResourceEntitlements: authed caller satisfies identity via base", () => {
    const ec = new EntitlementsChecker([], "bearer", false).withBaseEntitlements([
      "pages:/foo:read",
    ]);
    expect(
      ec.verifyResourceEntitlements("pages", "/foo", { bearer: ["other:read"] }, []),
    ).toBe(true);
  });

  it("verifyResourceEntitlements: authed caller does NOT satisfy identity via anonymous", () => {
    const ec = new EntitlementsChecker(["pages:/foo:read"], "bearer", false);
    expect(
      ec.verifyResourceEntitlements("pages", "/foo", { bearer: ["other:read"] }, []),
    ).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail (RED)**

Run: `cd typescript && make test`

Expected: TypeScript compilation FAIL — `Property 'withBaseEntitlements' does not exist on type 'EntitlementsChecker'`. Once the method is added, several `verifyEntitlements` assertions still fail because the matching logic still applies anonymous unconditionally.

- [ ] **Step 3: Add `basePatterns` field, `withBaseEntitlements` method, and thread `isAnonymousCaller`**

Edit `typescript/src/index.ts`. In the `EntitlementsChecker` class declaration (lines 86-102), add the `basePatterns` field next to `anonymousPatterns`:

```ts
export class EntitlementsChecker {
  readonly defaultScheme: string;
  readonly grantReadyByDefault: boolean;
  private readonly anonymousPatterns: EntitlementPattern[];
  private basePatterns: EntitlementPattern[] = [];
  private readonly cache = new Map<string, EntitlementPattern>();

  constructor(
    anonymousEntitlements: readonly string[] | undefined,
    defaultScheme: string,
    grantReadyByDefault: boolean,
  ) {
    this.defaultScheme = defaultScheme === "" ? "bearer" : defaultScheme;
    this.grantReadyByDefault = grantReadyByDefault;
    this.anonymousPatterns = (anonymousEntitlements ?? []).map((s) =>
      this.parsePattern(s),
    );
  }
```

Add a new method right after the constructor:

```ts
  /**
   * Sets the base entitlements: patterns that apply to every caller
   * (authenticated or anonymous) under the default scheme. Unlike the
   * constructor's `anonymousEntitlements` (which apply only when the
   * caller's entitlements map is empty), base entitlements form a floor
   * of grants that every request receives.
   *
   * Replaces any previously set base entitlements. Returns `this` for
   * chaining. Intended for use during construction; not safe for
   * concurrent mutation with verify calls in flight.
   */
  withBaseEntitlements(patterns: readonly string[]): this {
    this.basePatterns = patterns.map((s) => this.parsePattern(s));
    return this;
  }
```

Add a private helper near the bottom of the class (or as a top-level non-exported function — match the style of `matches`):

```ts
function isAnonymousCallerPatterns(
  patterns: Record<string, EntitlementPattern[]>,
): boolean {
  const schemes = Object.keys(patterns);
  if (schemes.length === 0) return true;
  for (const k of schemes) {
    if ((patterns[k]?.length ?? 0) > 0) return false;
  }
  return true;
}
```

Replace `verifyParsedEntitlements`:

```ts
  verifyParsedEntitlements(
    entitlements: ParsedEntitlements,
    requirements: ParsedRequirements,
  ): boolean {
    if (requirements.patterns.length === 0) {
      return true;
    }
    const isAnonymous = isAnonymousCallerPatterns(entitlements.patterns);
    for (const requirement of requirements.patterns) {
      if (this.satisfiesAndRequirements(entitlements.patterns, requirement, isAnonymous)) {
        return true;
      }
    }
    return false;
  }
```

Replace `verifyResourceParsedEntitlements`:

```ts
  verifyResourceParsedEntitlements(
    resource: string,
    resourceName: string,
    entitlements: ParsedEntitlements,
    requirements: ParsedRequirements,
    verb?: string,
  ): boolean {
    if (resource === "" || resourceName === "") {
      throw new Error("resource and resourceName must not be empty");
    }

    const effectiveVerb = verb && verb !== "" ? verb : "read";
    const identity = `${resource}:${resourceName}:${effectiveVerb}`;
    const parsedIdentity = this.parsePattern(identity);

    const list = entitlements.patterns[this.defaultScheme] ?? [];
    const isAnonymous = isAnonymousCallerPatterns(entitlements.patterns);
    const hasIdentity =
      this.grantReadyByDefault ||
      this.hasParsedEntitlement(list, this.defaultScheme, parsedIdentity, isAnonymous);
    if (!hasIdentity) {
      return false;
    }

    if (requirements.patterns.length === 0) {
      return true;
    }
    return this.verifyParsedEntitlements(entitlements, requirements);
  }
```

Replace `hasParsedEntitlement`:

```ts
  private hasParsedEntitlement(
    entitlementList: EntitlementPattern[],
    scheme: string,
    requirement: EntitlementPattern,
    isAnonymousCaller: boolean,
  ): boolean {
    for (const e of entitlementList) {
      if (matches(e, requirement)) return true;
    }

    if (scheme === this.defaultScheme) {
      for (const e of this.basePatterns) {
        if (matches(e, requirement)) return true;
      }
      if (isAnonymousCaller) {
        for (const e of this.anonymousPatterns) {
          if (matches(e, requirement)) return true;
        }
      }
    }

    return false;
  }
```

Replace `satisfiesAndRequirements` and `satisfiesRequirement`:

```ts
  private satisfiesAndRequirements(
    entitlements: Record<string, EntitlementPattern[]>,
    requirement: Record<string, EntitlementPattern[]>,
    isAnonymousCaller: boolean,
  ): boolean {
    for (const [scheme, requirementList] of Object.entries(requirement)) {
      const userHas = scheme in entitlements;
      const hasFallback =
        scheme === this.defaultScheme &&
        (this.basePatterns.length > 0 ||
          (isAnonymousCaller && this.anonymousPatterns.length > 0));
      if (!userHas && !hasFallback) return false;

      if (!this.satisfiesRequirement(entitlements, scheme, requirementList, isAnonymousCaller)) {
        return false;
      }
    }
    return true;
  }

  private satisfiesRequirement(
    entitlements: Record<string, EntitlementPattern[]>,
    scheme: string,
    requirement: EntitlementPattern[],
    isAnonymousCaller: boolean,
  ): boolean {
    const list = entitlements[scheme] ?? [];
    for (const r of requirement) {
      if (!this.hasParsedEntitlement(list, scheme, r, isAnonymousCaller)) {
        return false;
      }
    }
    return true;
  }
```

- [ ] **Step 4: Run tests to verify they pass (GREEN)**

Run: `cd typescript && make test`

Expected: all tests pass, including the new "anonymous vs base entitlements" describe block.

- [ ] **Step 5: Run linter and build**

Run: `cd typescript && make lint && make build`

Expected: clean lint, successful build.

- [ ] **Step 6: Commit**

```bash
git add typescript/src/index.ts typescript/src/index.test.ts
git commit -m "$(cat <<'EOF'
feat(typescript): correct anonymous_entitlements semantic and add base_entitlements

anonymousEntitlements now applies only when the caller's entitlements
map is empty (no schemes, or every scheme's list empty). The new
withBaseEntitlements fluent setter installs a "floor" bag applied to
every caller under the default scheme. Threads isAnonymousCaller from
the public verify entry points down through hasParsedEntitlement.

Resolves part of issue #3.
EOF
)"
```

---

## Task 5: Update SPEC.md

**Files:**
- Modify: `SPEC.md`

- [ ] **Step 1: Edit `SPEC.md` — clarify "Anonymous Entitlements" and add "Base Entitlements"**

Replace the "Anonymous Entitlements" section (lines 62-64) with:

```markdown
### Anonymous Entitlements
An `EntitlementsChecker` can be configured with a list of "anonymous" patterns. These patterns are automatically granted to callers **only when the caller's `Entitlements` map is empty** (no schemes present, or every scheme's list is empty). They are applied under the `defaultScheme`. An authenticated caller — one who passes any entitlements at all — does **not** receive the anonymous bag.

### Base Entitlements
An `EntitlementsChecker` can additionally be configured with a list of "base" patterns via a builder-style setter (`WithBaseEntitlements` / `with_base_entitlements` / `withBaseEntitlements`). Base patterns are applied under the `defaultScheme` to **every** caller — authenticated or anonymous — and form a floor of grants that every request receives. Calling the setter again replaces the previous list.

Use anonymous entitlements for grants that should only widen the unauthenticated surface. Use base entitlements for grants that should always apply regardless of caller identity.
```

- [ ] **Step 2: Commit**

```bash
git add SPEC.md
git commit -m "docs(spec): document anonymous vs base entitlements semantics"
```

---

## Task 6: Update TypeScript README usage example

**Files:**
- Modify: `typescript/README.md`

- [ ] **Step 1: Add base-entitlements usage to `typescript/README.md`**

Edit `typescript/README.md`. After the existing `verifyEntitlements` example (around line 30), append a new section before "## Build":

````markdown
## Base entitlements (floor for every caller)

`anonymousEntitlements` (the constructor argument) is applied **only** to callers who pass an empty entitlements map. For grants that should apply to every caller — authenticated or anonymous — use the fluent `withBaseEntitlements` setter:

```ts
const ec = new EntitlementsChecker(
  ["public:read"],  // anonymous-only: only fires when caller's bag is empty
  "bearer",
  false,
).withBaseEntitlements(["heartbeat:read"]);  // floor: every caller gets this
```

Calling `withBaseEntitlements` again replaces the previously set list.
````

- [ ] **Step 2: Commit**

```bash
git add typescript/README.md
git commit -m "docs(typescript): document withBaseEntitlements in README"
```

---

## Task 7: Bump VERSION

**Files:**
- Modify: `VERSION`

- [ ] **Step 1: Update `VERSION`**

Replace the contents of `VERSION` with:

```
0.2.0
```

- [ ] **Step 2: Commit**

```bash
git add VERSION
git commit -m "chore: bump VERSION to 0.2.0"
```

---

## Task 8: Final sanity check

- [ ] **Step 1: Run the full test matrix from repo root**

Run: `make test`

Expected: every port's tests pass.

- [ ] **Step 2: Run the full lint matrix from repo root**

Run: `make lint`

Expected: every port's linter is clean.

- [ ] **Step 3: Inspect git log**

Run: `git log --oneline -15`

Expected: a clean linear sequence of per-port `feat(<lang>)` commits, plus the spec/plan docs and the SPEC/README/VERSION bumps. No fixup commits, no out-of-order changes.

- [ ] **Step 4: Confirm issue #3 will be closed**

Verify that the four `feat(<lang>)` commit messages each reference issue #3. The eventual PR description should also link the issue with a `Closes #3` line. This is captured in the PR creation step at integration time — not part of this plan.
