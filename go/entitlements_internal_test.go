package entitlements

// White-box (package entitlements) tests for requirement placeholders and
// BindRequirements. These live in a separate file from entitlements_test.go
// (package entitlements_test) because they exercise unexported symbols
// (placeholderKey) and unexported fields (ParsedRequirements.hasPlaceholder,
// ParsedRequirements.patterns) that an external test package cannot reach.

import (
	"errors"
	"testing"
)

func TestPlaceholderKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"{vector_store_id}", "vector_store_id"},
		{"{a}", "a"},
		{"{}", ""}, // length 2 -> literal, not a placeholder
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

func TestBindRequirementsInvalidBoundValue(t *testing.T) {
	ec := NewEntitlementsChecker(nil, "bearer", false)
	reqs := ec.ParseRequirements(Requirements{{"bearer": {"vector_stores:{vector_store_id}:write"}}})

	// "" and "*" are the wildcard spelling, not a concrete resourceName. Binding
	// one would widen the requirement to every store — fail like an unbound
	// placeholder instead.
	for _, v := range []string{"", "*"} {
		if _, err := ec.BindRequirements(reqs, Binding{"vector_store_id": v}); !errors.Is(err, ErrInvalidBoundValue) {
			t.Errorf("bound to %q: expected ErrInvalidBoundValue, got %v", v, err)
		}
	}

	// A legitimate value still binds.
	if _, err := ec.BindRequirements(reqs, Binding{"vector_store_id": "vs_alice"}); err != nil {
		t.Errorf("unexpected error binding a concrete value: %v", err)
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

func TestStrictWildcardResourceNameIdentityIsDenied(t *testing.T) {
	// VerifyResourceParsedEntitlements builds its identity requirement from the
	// caller-supplied resourceName. Under strict a "*" resourceName makes that
	// identity a wildcard requirement, which is illegal by spelling — so the gate
	// denies regardless of the grant, including a genuine wildcard grant. Callers
	// wanting "holds class-wide authority" must use an opaque capability instead.
	strict := NewEntitlementsChecker(nil, "bearer", false).WithStrictRequirements(true)
	admin := strict.ParseEntitlements(Entitlements{"bearer": {"pages::all"}})
	noReqs := strict.ParseRequirements(nil)

	ok, err := strict.VerifyResourceParsedEntitlements("pages", "*", admin, noReqs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("strict: a wildcard resourceName identity must be denied, even for a wildcard grant")
	}

	// A concrete resourceName still passes for the same caller.
	ok, err = strict.VerifyResourceParsedEntitlements("pages", "/foo", admin, noReqs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("strict: a concrete identity must still pass for a wildcard grant")
	}

	// With strict off (the default), the same wildcard identity is admitted —
	// this is the v0.3.0 behavior the default preserves.
	lax := NewEntitlementsChecker(nil, "bearer", false)
	laxAdmin := lax.ParseEntitlements(Entitlements{"bearer": {"pages::all"}})
	ok, err = lax.VerifyResourceParsedEntitlements("pages", "*", laxAdmin, lax.ParseRequirements(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("strict off: a wildcard resourceName identity must behave as it did in v0.3.0")
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
