package entitlements_test

import (
	"errors"
	"testing"

	"github.com/kdex-tech/entitlements/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateEntitlement_WellFormed(t *testing.T) {
	for _, s := range []string{
		"email",            // opaque
		"admin",            // opaque
		"pages:read",       // short
		"pages::read",      // medium: empty resourceName is legal
		"apitokens::mint",  // medium
		"pages:*:read",     // long, wildcard resourceName
		"pages:/foo:all",   // long, verb all
		"users:{}:read",    // "{}" is a literal, not a placeholder
		"pages:a%3Ab:read", // URL-encoded ':' inside a resourceName
		"pages:é:read",     // non-ASCII is fine
	} {
		assert.NoError(t, entitlements.ValidateEntitlement(s), "%q", s)
	}
}

func TestValidateEntitlement_Malformed(t *testing.T) {
	tests := []struct {
		in   string
		want entitlements.InvalidEntitlementReason
	}{
		{"", entitlements.InvalidEntitlementEmpty},

		{" pages:read", entitlements.InvalidEntitlementCharacter},
		{"pages:read\n", entitlements.InvalidEntitlementCharacter},
		{"pages: read", entitlements.InvalidEntitlementCharacter},
		{"a\tb", entitlements.InvalidEntitlementCharacter},
		{"a\x00b", entitlements.InvalidEntitlementCharacter},
		{"a\x7fb", entitlements.InvalidEntitlementCharacter},
		{"a\u0085b", entitlements.InvalidEntitlementCharacter}, // NEL: Cc and White_Space
		{"pages: :read", entitlements.InvalidEntitlementCharacter},
		{"pages:a　b:read", entitlements.InvalidEntitlementCharacter},
		{"pages:a b:read", entitlements.InvalidEntitlementCharacter},
		{"a\xffb", entitlements.InvalidEntitlementCharacter}, // invalid UTF-8

		{"a:b:c:d", entitlements.InvalidEntitlementTooManySegments},
		{"pages:a:b:read", entitlements.InvalidEntitlementTooManySegments},
		{":::", entitlements.InvalidEntitlementTooManySegments},

		{":read", entitlements.InvalidEntitlementEmptyResource},
		{":x:read", entitlements.InvalidEntitlementEmptyResource},
		{":", entitlements.InvalidEntitlementEmptyResource},
		{"::", entitlements.InvalidEntitlementEmptyResource},

		{"users:", entitlements.InvalidEntitlementEmptyVerb},
		{"users::", entitlements.InvalidEntitlementEmptyVerb},
		{"users:*:", entitlements.InvalidEntitlementEmptyVerb},

		{"users:{id}:read", entitlements.InvalidEntitlementPlaceholder},

		// Order: the first failing check is the one reported.
		{"a b:c:d:e", entitlements.InvalidEntitlementCharacter},
		{":x:y:z", entitlements.InvalidEntitlementTooManySegments},
		{":{id}:", entitlements.InvalidEntitlementEmptyResource},
		{"users:{id}:", entitlements.InvalidEntitlementEmptyVerb},
	}
	for _, tt := range tests {
		err := entitlements.ValidateEntitlement(tt.in)
		require.Error(t, err, "%q", tt.in)

		var ie *entitlements.InvalidEntitlementError
		require.ErrorAs(t, err, &ie, "%q", tt.in)
		assert.Equal(t, tt.want, ie.Reason, "%q", tt.in)
		assert.Equal(t, tt.in, ie.Entitlement, "%q", tt.in)
		assert.ErrorIs(t, err, entitlements.ErrInvalidEntitlement, "%q", tt.in)
	}
}

func TestValidateEntitlement_ReasonCodesAreStable(t *testing.T) {
	// The codes are a cross-port contract (SPEC.md, Validation): callers put
	// them in 400 bodies, so they must never change spelling.
	assert.Equal(t, "empty", string(entitlements.InvalidEntitlementEmpty))
	assert.Equal(t, "invalid_character", string(entitlements.InvalidEntitlementCharacter))
	assert.Equal(t, "too_many_segments", string(entitlements.InvalidEntitlementTooManySegments))
	assert.Equal(t, "empty_resource", string(entitlements.InvalidEntitlementEmptyResource))
	assert.Equal(t, "empty_verb", string(entitlements.InvalidEntitlementEmptyVerb))
	assert.Equal(t, "placeholder", string(entitlements.InvalidEntitlementPlaceholder))
}

func TestValidateEntitlement_TooManySegmentsPointsAtEncoding(t *testing.T) {
	err := entitlements.ValidateEntitlement("pages:a:b:read")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL-encode")
	assert.Contains(t, err.Error(), `"pages:a:b:read"`)
}

func TestValidateEntitlement_NotAnErrorOfOtherKinds(t *testing.T) {
	err := entitlements.ValidateEntitlement("")
	assert.False(t, errors.Is(err, entitlements.ErrInvalidBoundValue))
}
