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
