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
				{"bearer": {"pages"}},
			},
			want: false,
		},
		{
			name:                  "opaque - entitlements match requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages"}},
			},
			want: true,
		},
		{
			name:                  "opaque - entitlements does not match requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"books"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages"}},
			},
			want: false,
		},
		{
			name:                  "opaque - does not match wildcard specific verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"books"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"books:read"}},
			},
			want: false,
		},
		{
			name:                  "opaque - does not match wildcard all verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"books"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"books:all"}},
			},
			want: false,
		},
		{
			name:                  "opaque - does not match explicit wildcard all verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"books"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"books:*:all"}},
			},
			want: false,
		},
		{
			name:                  "opaque - wildcard all verb entitlement does not match opaque requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"books:all"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"books"}},
			},
			want: false,
		},
		{
			name:                  "short - entitlements match requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:read"}},
			},
			want: true,
		},
		{
			name:                  "short - entitlements do not match requirement with multiple verbs",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:read", "pages:write"}},
			},
			want: false,
		},
		{
			name:                  "short - entitlements do not match requirement with multiple verbs",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:read", "pages:write"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:read", "pages:write"}},
			},
			want: true,
		},
		{
			name:                  "short - entitlement does not match requirement wrong verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:write"}},
			},
			want: false,
		},
		{
			name:                  "short - wildcard entitlement does not match opaque requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:all"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages"}},
			},
			want: false,
		},
		{
			name:                  "short - wildcard entitlement matches wildcard requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:all"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:all"}},
			},
			want: true,
		},
		{
			name:                  "short - wildcard entitlement matches short requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:all"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:read"}},
			},
			want: true,
		},
		{
			name:                  "long - long entitlement matches short requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:read"}},
			},
			want: true,
		},
		{
			name:                  "long - long entitlement matches long requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:/foo:read"}},
			},
			want: true,
		},
		{
			name:                  "long - long entitlement does not match short requirement wrong verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:write"}},
			},
			want: false,
		},
		{
			name:                  "long - long entitlement matches short requirement by verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:read"}},
			},
			want: true,
		},
		{
			name:                  "long - long entitlement does not match long requirement wrong resourceName",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:/bar:read"}},
			},
			want: false,
		},
		{
			name:                  "long - long entitlement does not match long requirement wrong resource",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"pages:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"books:/foo:read"}},
			},
			want: false,
		},
		{
			name:                  "OR - entitlement does not match by resource",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"books:/foo:read"}},
				{"bearer": {"pages:/bar:read"}},
			},
			want: false,
		},
		{
			name:                  "OR - entitlement does not match by verb",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"users:/foo:write"}},
				{"bearer": {"users:/foo:delete"}},
			},
			want: false,
		},
		{
			name:                  "OR - entitlement does not match by resourceName",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"users:/bar:read"}},
				{"bearer": {"users:/baz:read"}},
			},
			want: false,
		},
		{
			name:                  "OR - entitlement matches one of the requirements",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"users:/bar:read"}},
				{"bearer": {"users:/foo:read"}},
			},
			want: true,
		},
		{
			name:                  "AND - entitlement does not match all of the requirements",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{
					"bearer": {"users:/bar:read"},
					"other":  {"users:/foo:read"},
				},
			},
			want: false,
		},
		{
			name:                  "AND - entitlement matches all of the requirements",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"users:/bar:read"},
				"other":  {"users:/foo:read"},
			},
			requirements: entitlements.Requirements{
				{
					"bearer": {"users:/bar:read"},
					"other":  {"users:/foo:read"},
				},
			},
			want: true,
		},
		{
			name:                  "AND - entitlement does not match scheme of requirement",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {"users:/bar:read"},
			},
			requirements: entitlements.Requirements{
				{
					"other": {"users:/bar:read"},
				},
			},
			want: false,
		},
		{
			name:                  "AND - match only scheme",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {},
			},
			requirements: entitlements.Requirements{
				{
					"bearer": {},
				},
			},
			want: true,
		},
		{
			name:                  "AND - does not match all schemes",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {},
			},
			requirements: entitlements.Requirements{
				{
					"bearer": {},
					"oauth2": {},
				},
			},
			want: false,
		},
		{
			name:                  "AND - matches all schemes",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {},
				"oauth2": {},
			},
			requirements: entitlements.Requirements{
				{
					"bearer": {},
					"oauth2": {},
				},
			},
			want: true,
		},
		{
			name:                  "OR - matches one of the schemes",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {},
			},
			requirements: entitlements.Requirements{
				{
					"bearer": {},
				},
				{
					"oauth2": {},
				},
			},
			want: true,
		},
		{
			name:                  "OR - matches none of the schemes",
			anonymousEntitlements: []string{},
			entitlements: map[string][]string{
				"bearer": {},
			},
			requirements: entitlements.Requirements{
				{
					"foo": {},
				},
				{
					"oauth2": {},
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
			resourceName:          "foo",
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
				"bearer": {"pages:write"},
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
				{"bearer": {"pages:write"}},
			},
			want: false,
		},
		{
			name:                  "requirements are raised above anonymousEntitlements and met by entitlements",
			anonymousEntitlements: []string{"pages:read"},
			resource:              "pages",
			resourceName:          "foo",
			entitlements: entitlements.Entitlements{
				"bearer": {"pages:write"},
			},
			requirements: entitlements.Requirements{
				{"bearer": {"pages:write"}},
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
