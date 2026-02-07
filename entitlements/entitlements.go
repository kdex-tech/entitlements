package entitlements

import (
	"fmt"
	"slices"
	"strings"
)

// Entitlements support exact match and wildcard patterns.
// Long Form:   <resource>:<resourceName>:<verb>
// Medium Form: <resource>::<verb>                (means <resource>:*:<verb>)
// Short Form:  <resource>:<verb>                 (means <resource>:*:<verb>)
// Opaque Form: <resource>                        (not a wildcard, only matches exactly)
//
// Opaque form is intended to support JWT claims and other forms of requirements
// like HTTP Headers.
//
// Examples:
//   - pages:/foo:read - read access to page "foo" (explicit resource name)
//   - pages:*:read -    read access to all pages (explicit wildcard)
//   - pages::read -     read access to all pages (implicit wildcard)
//   - pages:read -      read access to all pages (short form)
//   - pages:/foo:all -  all access to page "foo" (explicit resource name)
//   - pages:*:all -     all access to all pages (explicit wildcard)
//   - pages::all -      all access to all pages (implicit wildcard)
//   - pages:all -       all access to all pages (short form)
//   - email -           exact match only (opaque form)
type EntitlementsChecker struct {
	anonymousEntitlements []string
	defaultScheme         string
	grantReadyByDefault   bool
}

type Entitlements map[string][]string
type Requirements []map[string][]string

// NewEntitlementsChecker creates a new entitlements checker.
// anonymousEntitlements is an array of entitlements granted in anonymous (not logged in) access scenarios.
// grantReadyByDefault should be true when the system is ready by default, false otherwise.
func NewEntitlementsChecker(
	anonymousEntitlements []string,
	defaultScheme string,
	grantReadyByDefault bool,
) *EntitlementsChecker {
	if defaultScheme == "" {
		defaultScheme = "bearer"
	}
	return &EntitlementsChecker{
		anonymousEntitlements: anonymousEntitlements,
		defaultScheme:         defaultScheme,
		grantReadyByDefault:   grantReadyByDefault,
	}
}

// VerifyResourceEntitlements checks if the user's entitlements satisfy the security requirements for a resource instance.
// Requirements is an array of map[string][]string where each map holds the requirements for a given scheme.
// The outer array is OR'd - user needs to satisfy at least one scheme.
// The inner map is AND'd - user needs to satisfy all entitlements in the scheme.
func (ec *EntitlementsChecker) VerifyResourceEntitlements(
	resource string,
	resourceName string,
	entitlements Entitlements,
	requirements Requirements,
) bool {
	// Make sure never to write back
	requirements = deepCloneRequirements(requirements)

	// In order for pattern matching to work we need to create and add an identity requirement.
	identity := fmt.Sprintf("%s:%s:read", resource, resourceName)

	// The identity requirement is added to all requirements
	if len(requirements) == 0 {
		requirements = append(requirements, map[string][]string{
			ec.defaultScheme: {identity},
		})
	} else {
		for _, req := range requirements {
			req[ec.defaultScheme] = append(req[ec.defaultScheme], identity)
		}
	}

	// Make sure never to write back
	entitlements = deepCloneEntitlements(entitlements)

	// The identity entitlement is added to all entitlements
	if ec.grantReadyByDefault {
		entitlements[ec.defaultScheme] = append(entitlements[ec.defaultScheme], identity)
	}

	return ec.VerifyEntitlements(entitlements, requirements)
}

// VerifyEntitlements checks if the user's entitlements satisfy the security requirements.
// Requirements is an array of map[string][]string where each map is a requirement.
// The outer array is OR'd - user needs to satisfy at least one requirement.
// The inner map is AND'd - user needs to satisfy all entitlements in the requirement.
func (ec *EntitlementsChecker) VerifyEntitlements(
	entitlements Entitlements,
	requirements Requirements,
) bool {
	// If there are no requirements, access is granted
	if len(requirements) == 0 {
		return true
	}

	// The entitlements granted to anonymous are added to the default scheme
	if len(ec.anonymousEntitlements) > 0 {
		// Make sure never to write back
		entitlements = deepCloneEntitlements(entitlements)

		added := false
		for scheme, entitlementList := range entitlements {
			for _, anonEntitlement := range ec.anonymousEntitlements {
				if scheme == ec.defaultScheme && !slices.Contains(entitlementList, anonEntitlement) {
					entitlementList = append(entitlementList, anonEntitlement)
					entitlements[scheme] = entitlementList
					added = true
				}
			}
		}
		// When there are no entitlements, the anonymous entitlements are added
		if !added {
			entitlements[ec.defaultScheme] = append(entitlements[ec.defaultScheme], ec.anonymousEntitlements...)
		}
	}

	// Here requirements are OR'd - user needs to satisfy at least one
	for _, requirement := range requirements {
		if ec.satisfiesAndRequirements(entitlements, requirement) {
			return true
		}
	}

	return false
}

func (ec *EntitlementsChecker) satisfiesAndRequirements(entitlements map[string][]string, requirement map[string][]string) bool {
	// Here requirements are AND'ed - user must have match all
	for re, requirementList := range requirement {
		entitlementList, ok := entitlements[re]
		if !ok {
			return false
		}
		if !ec.satisfiesRequirement(entitlementList, requirementList) {
			return false
		}
	}

	return true
}

// satisfiesRequirement checks if user entitlements satisfy a single security requirement.
// Within a requirement, all entitlements must be present (AND logic).
func (ec *EntitlementsChecker) satisfiesRequirement(entitlements []string, requirement []string) bool {
	for _, curRequirement := range requirement {
		if !ec.hasEntitlement(entitlements, curRequirement) {
			return false
		}
	}

	return true
}

// hasEntitlement checks if the user has a specific entitlement.
func (ec *EntitlementsChecker) hasEntitlement(entitlements []string, requirement string) bool {
	for _, entitlement := range entitlements {
		if ec.entitlementMatches(entitlement, requirement) {
			return true
		}
	}
	return false
}

// entitlementMatches checks if a user entitlement matches a required entitlement.
func (ec *EntitlementsChecker) entitlementMatches(entitlement, requirement string) bool {
	// Exact match
	if entitlement == requirement {
		return true
	}

	// Parse entitlements
	parts := strings.Split(entitlement, ":")

	if len(parts) == 2 {
		// short syntax was used <resource>:<verb> which is equal to <resource>::<verb>, or <resource>:*:<verb>
		parts = []string{parts[0], "", parts[1]}
	}

	requiredParts := strings.Split(requirement, ":")

	if len(requiredParts) == 2 {
		// short syntax was used <resource>:<verb> which is equal to <resource>::<verb>, or <resource>:*:<verb>
		requiredParts = []string{requiredParts[0], "", requiredParts[1]}
	}

	// Must have same structure (resource:resourceName:verb)
	if len(parts) != 3 || len(requiredParts) != 3 {
		return false
	}

	// Resource type must match
	if parts[0] != requiredParts[0] {
		return false
	}

	// Verb must match
	if parts[2] != "all" && parts[2] != requiredParts[2] {
		return false
	}

	// Check resource name with wildcard support
	// Empty string or "*" in entitlement means all resources
	if parts[1] == "" || parts[1] == "*" {
		return true
	}

	// Check resource name with wildcard support
	// Empty string or "*" in required entitlement means all resources
	if requiredParts[1] == "" || requiredParts[1] == "*" {
		return true
	}

	// Specific resource name must match
	return parts[1] == requiredParts[1]
}

func deepCloneEntitlements(entitlements map[string][]string) map[string][]string {
	if entitlements == nil {
		return nil
	}

	// 1. Clone the outer slice
	clone := make(map[string][]string, len(entitlements))

	for key, entitlementList := range entitlements {
		if entitlementList == nil {
			clone[key] = nil
			continue
		}

		// 2. Clone the inner Slice
		newEntitlementList := make([]string, len(entitlementList))
		copy(newEntitlementList, entitlementList)
		clone[key] = newEntitlementList
	}

	return clone
}

func deepCloneRequirements(requirements Requirements) Requirements {
	if requirements == nil {
		return nil
	}

	// 1. Clone the outer slice
	clone := make(Requirements, len(requirements))

	for i, reqMap := range requirements {
		if reqMap == nil {
			continue
		}

		// 2. Clone the Map
		newMap := make(map[string][]string, len(reqMap))
		for key, requirementList := range reqMap {
			if requirementList == nil {
				newMap[key] = nil
				continue
			}

			// 3. Clone the inner Slice
			newRequirementList := make([]string, len(requirementList))
			copy(newRequirementList, requirementList)
			newMap[key] = newRequirementList
		}
		clone[i] = newMap
	}

	return clone
}
