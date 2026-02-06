package entitlements

import (
	"fmt"
	"slices"
	"strings"
)

// Supports exact match and wildcard patterns.
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
}

type Entitlements map[string][]string
type Requirements []map[string][]string

// NewEntitlementsChecker creates a new entitlements checker.
func NewEntitlementsChecker(anonymousEntitlements []string) *EntitlementsChecker {
	return &EntitlementsChecker{
		anonymousEntitlements: anonymousEntitlements,
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
	clonedRequirements := deepCloneRequirements(requirements)

	// The identity entitlement allows for pattern matching
	identity := fmt.Sprintf("%s:%s:read", resource, resourceName)

	// The identity entitlement is added to all requirements
	added := false
	for _, req := range clonedRequirements {
		for i, v := range req {
			if !slices.Contains(v, identity) {
				v = append(v, identity)
				req[i] = v
				added = true
			}
		}
	}
	// When there are no requirements, a fallback scheme with the identity entitlement is added
	if !added {
		clonedRequirements = append(clonedRequirements, map[string][]string{
			"_": {identity},
		})
	}

	return ec.VerifyEntitlements(entitlements, clonedRequirements)
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

	clonedEntitlements := deepCloneEntitlements(entitlements)

	// The entitlements granted to anonymous are added to the entitlements
	added := false
	for _, anonEntitlement := range ec.anonymousEntitlements {
		for k, v := range clonedEntitlements {
			if !slices.Contains(v, anonEntitlement) {
				v = append(v, anonEntitlement)
				clonedEntitlements[k] = v
				added = true
			}
		}
	}
	// When there are no entitlements, the anonymous entitlements are added
	if !added {
		for _, anonEntitlement := range ec.anonymousEntitlements {
			clonedEntitlements["_"] = append(clonedEntitlements["_"], anonEntitlement)
		}
	}

	// We need to align the entitlement schemes with the requirement schemes
	for se, v := range clonedEntitlements {
		for _, requirement := range requirements {
			// Requirements are OR'd - user needs to satisfy at least one
			for re, reqs := range requirement {
				if se == re && ec.satisfiesRequirement(v, reqs) {
					return true
				}
			}
		}
	}

	return false
}

// satisfiesRequirement checks if user entitlements satisfy a single security requirement.
// Within a requirement, all entitlements must be present (AND logic).
func (ac *EntitlementsChecker) satisfiesRequirement(entitlements []string, requirement []string) bool {
	// Requirements are AND'ed - Check if user has all required entitlements
	for _, curRequirement := range requirement {
		if !ac.hasEntitlement(entitlements, curRequirement) {
			return false
		}
	}

	return true
}

// hasEntitlement checks if the user has a specific entitlement.
func (ac *EntitlementsChecker) hasEntitlement(entitlements []string, requirement string) bool {
	for _, entitlement := range entitlements {
		if ac.entitlementMatches(entitlement, requirement) {
			return true
		}
	}
	return false
}

// entitlementMatches checks if a user entitlement matches a required entitlement.
func (ac *EntitlementsChecker) entitlementMatches(entitlement, requirement string) bool {
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
