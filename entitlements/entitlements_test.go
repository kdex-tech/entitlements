package entitlements_test

import (
	"testing"

	"github.com/kdex-tech/entitlements/entitlements"
	"github.com/stretchr/testify/assert"
)

func TestEntitlementsChecker_VerifyEntitlements(t *testing.T) {
	tests := []struct {
		name                  string
		anonymousEntitlements []string
		entitlements          entitlements.Entitlements
		requirements          entitlements.Requirements
		want                  bool
	}{
		{
			name:                  "none",
			anonymousEntitlements: []string{},
			entitlements:          map[string][]string{},
			requirements:          entitlements.Requirements{},
			want:                  true,
		},
		{
			name:                  "opaque - no entitlements",
			anonymousEntitlements: []string{},
			entitlements:          map[string][]string{},
			requirements: entitlements.Requirements{
				{"_": {"pages"}},
			},
			want: false,
		},
		{
			name:                  "opaque - entitlements match requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages"}},
			},
			want: true,
		},
		{
			name:                  "opaque - entitlements does not match requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"books"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages"}},
			},
			want: false,
		},
		{
			name:                  "opaque - does not match wildcard specific verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"books"},
			},
			requirements: entitlements.Requirements{
				{"_": {"books:read"}},
			},
			want: false,
		},
		{
			name:                  "opaque - does not match wildcard all verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"books"},
			},
			requirements: entitlements.Requirements{
				{"_": {"books:all"}},
			},
			want: false,
		},
		{
			name:                  "opaque - does not match explicit wildcard all verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"books"},
			},
			requirements: entitlements.Requirements{
				{"_": {"books:*:all"}},
			},
			want: false,
		},
		{
			name:                  "opaque - wildcard all verb entitlement does not match opaque requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"books:all"},
			},
			requirements: entitlements.Requirements{
				{"_": {"books"}},
			},
			want: false,
		},
		{
			name:                  "short - entitlements match requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:read"}},
			},
			want: true,
		},
		{
			name:                  "short - entitlements do not match requirement with multiple verbs",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:read", "pages:write"}},
			},
			want: false,
		},
		{
			name:                  "short - entitlements do not match requirement with multiple verbs",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:read", "pages:write"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:read", "pages:write"}},
			},
			want: true,
		},
		{
			name:                  "short - entitlement does not match requirement wrong verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:write"}},
			},
			want: false,
		},
		{
			name:                  "short - wildcard entitlement does not match opaque requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:all"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages"}},
			},
			want: false,
		},
		{
			name:                  "short - wildcard entitlement matches wildcard requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:all"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:all"}},
			},
			want: true,
		},
		{
			name:                  "short - wildcard entitlement matches short requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:all"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:read"}},
			},
			want: true,
		},
		{
			name:                  "long - long entitlement matches short requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:read"}},
			},
			want: true,
		},
		{
			name:                  "long - long entitlement matches long requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:/foo:read"}},
			},
			want: true,
		},
		{
			name:                  "long - long entitlement does not match short requirement wrong verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:write"}},
			},
			want: false,
		},
		{
			name:                  "long - long entitlement matches short requirement by verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:read"}},
			},
			want: true,
		},
		{
			name:                  "long - long entitlement does not match long requirement wrong resourceName",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:/bar:read"}},
			},
			want: false,
		},
		{
			name:                  "long - long entitlement does not match long requirement wrong resource",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"books:/foo:read"}},
			},
			want: false,
		},
		{
			name:                  "OR - entitlement does not match by resource",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"books:/foo:read"}},
				{"_": {"pages:/bar:read"}},
			},
			want: false,
		},
		{
			name:                  "OR - entitlement does not match by verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"users:/foo:write"}},
				{"_": {"users:/foo:delete"}},
			},
			want: false,
		},
		{
			name:                  "OR - entitlement does not match by resourceName",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"users:/bar:read"}},
				{"_": {"users:/baz:read"}},
			},
			want: false,
		},
		{
			name:                  "OR - entitlement matches one of the requirements",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"_": {"users:/bar:read"}},
				{"_": {"users:/foo:read"}},
			},
			want: true,
		},
		{
			name:                  "AND - entitlement does not match all of the requirements",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{
					"_":      {"users:/bar:read"},
					"bearer": {"users:/foo:read"},
				},
			},
			want: false,
		},
		{
			name:                  "AND - entitlement matches all of the requirements",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_":      {"users:/bar:read"},
				"bearer": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{
					"_":      {"users:/bar:read"},
					"bearer": {"users:/foo:read"},
				},
			},
			want: true,
		},
		{
			name:                  "AND - entitlement does not match scheme of requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"_": {"users:/bar:read"},
			},
			requirements: entitlements.Requirements{
				{
					"bearer": {"users:/bar:read"},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec := entitlements.NewEntitlementsChecker(tt.anonymousEntitlements)
			got := ec.VerifyEntitlements(tt.entitlements, tt.requirements)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEntitlementsChecker_VerifyResourceEntitlements(t *testing.T) {
	tests := []struct {
		name                  string
		anonymousEntitlements []string
		resource              string
		resourceName          string
		entitlements          entitlements.Entitlements
		requirements          entitlements.Requirements
		want                  bool
	}{
		{
			name:                  "identity entitlements are needed",
			anonymousEntitlements: []string{},
			resource:              "pages",
			resourceName:          "all",
			entitlements:          entitlements.Entitlements{},
			requirements:          entitlements.Requirements{},
			want:                  false,
		},
		{
			name:                  "identity entitlements are added by anonymousEntitlements",
			anonymousEntitlements: []string{"pages:read"},
			resource:              "pages",
			resourceName:          "foo",
			entitlements:          entitlements.Entitlements{},
			requirements:          entitlements.Requirements{},
			want:                  true,
		},
		{
			name:                  "anonymousEntitlements are enough",
			anonymousEntitlements: []string{"pages:read"},
			resource:              "pages",
			resourceName:          "foo",
			entitlements: entitlements.Entitlements{
				"_": {"pages:write"},
			},
			requirements: entitlements.Requirements{},
			want:         true,
		},
		{
			name:                  "requirements are raised above anonymousEntitlements",
			anonymousEntitlements: []string{"pages:read"},
			resource:              "pages",
			resourceName:          "foo",
			entitlements:          entitlements.Entitlements{},
			requirements: entitlements.Requirements{
				{"_": {"pages:write"}},
			},
			want: false,
		},
		{
			name:                  "requirements are raised above anonymousEntitlements and met by entitlements",
			anonymousEntitlements: []string{"pages:read"},
			resource:              "pages",
			resourceName:          "foo",
			entitlements: entitlements.Entitlements{
				"_": {"pages:write"},
			},
			requirements: entitlements.Requirements{
				{"_": {"pages:write"}},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec := entitlements.NewEntitlementsChecker(tt.anonymousEntitlements)
			got := ec.VerifyResourceEntitlements(tt.resource, tt.resourceName, tt.entitlements, tt.requirements)
			assert.Equal(t, tt.want, got)
		})
	}
}
