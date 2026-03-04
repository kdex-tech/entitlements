package entitlements

import (
	"fmt"
	"strings"

	"github.com/go-logr/logr"
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
	log                   *logr.Logger
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

// CalculateResourceRequirements calculates the requirements for a resource instance.
// It returns a copy of the requirements with the identity requirement added.
func (ec *EntitlementsChecker) CalculateResourceRequirements(
	resource string,
	resourceName string,
	requirements Requirements,
) (Requirements, error) {
	if resource == "" || resourceName == "" {
		return nil, fmt.Errorf("resource and resourceName must not be empty")
	}

	// In order for pattern matching to work we need to create and add an identity requirement.
	identity := fmt.Sprintf("%s:%s:read", resource, resourceName)

	// We must return a new structure to avoid modifying the input, but we can do it efficiently.
	newRequirements := make(Requirements, 0, len(requirements)+1)

	if len(requirements) == 0 {
		newRequirements = append(newRequirements, map[string][]string{
			ec.defaultScheme: {identity},
		})
	} else {
		for _, req := range requirements {
			newReq := make(map[string][]string, len(req))
			for k, v := range req {
				newReq[k] = v
			}
			newReq[ec.defaultScheme] = append(newReq[ec.defaultScheme], identity)
			newRequirements = append(newRequirements, newReq)
		}
	}

	return newRequirements, nil
}

// VerifyResourceEntitlements checks if the user's entitlements satisfy the security requirements for a resource instance.
func (ec *EntitlementsChecker) VerifyResourceEntitlements(
	resource string,
	resourceName string,
	entitlements Entitlements,
	requirements Requirements,
) (bool, error) {
	if resource == "" || resourceName == "" {
		return false, fmt.Errorf("resource and resourceName must not be empty")
	}

	// 1. Check if user satisfies the resource identity requirement.
	// This is AND'ed into all requirements, so if this fails, everything fails.
	identity := fmt.Sprintf("%s:%s:read", resource, resourceName)

	// If grantReadyByDefault is true, we implicitly grant the identity entitlement.
	hasIdentity := ec.grantReadyByDefault || ec.hasEntitlement(entitlements, ec.defaultScheme, identity)
	if !hasIdentity {
		return false, nil
	}

	// 2. Verify the rest of the requirements.
	return ec.VerifyEntitlements(entitlements, requirements), nil
}

// VerifyEntitlements checks if the user's entitlements satisfy the security requirements.
func (ec *EntitlementsChecker) VerifyEntitlements(
	entitlements Entitlements,
	requirements Requirements,
) (result bool) {
	// If there are no requirements, access is granted
	if len(requirements) == 0 {
		return true
	}

	defer func() {
		if ec.log != nil {
			ec.log.V(2).Info("Verified entitlements", "entitlements", entitlements, "requirements", requirements, "result", result)
		}
	}()

	// Here requirements are OR'd - user needs to satisfy at least one
	for _, requirement := range requirements {
		if ec.satisfiesAndRequirements(entitlements, requirement) {
			result = true
			return
		}
	}

	result = false
	return
}

func (ec *EntitlementsChecker) WithLogger(log logr.Logger) *EntitlementsChecker {
	ec.log = &log
	return ec
}

func (ec *EntitlementsChecker) satisfiesAndRequirements(entitlements map[string][]string, requirement map[string][]string) bool {
	// Here requirements are AND'ed - user must match all
	for scheme, requirementList := range requirement {
		// A scheme is satisfied if it's present in entitlements OR it's the default scheme and we have anonymous entitlements.
		_, ok := entitlements[scheme]
		if !ok && !(scheme == ec.defaultScheme && len(ec.anonymousEntitlements) > 0) {
			return false
		}

		if !ec.satisfiesRequirement(entitlements, scheme, requirementList) {
			return false
		}
	}

	return true
}

// satisfiesRequirement checks if user entitlements satisfy a single security requirement.
// Within a requirement, all entitlements must be present (AND logic).
func (ec *EntitlementsChecker) satisfiesRequirement(entitlements map[string][]string, scheme string, requirement []string) bool {
	for _, curRequirement := range requirement {
		if !ec.hasEntitlement(entitlements, scheme, curRequirement) {
			return false
		}
	}

	return true
}

// hasEntitlement checks if the user has a specific entitlement.
func (ec *EntitlementsChecker) hasEntitlement(entitlements map[string][]string, scheme string, requirement string) bool {
	// Check user-provided entitlements for this scheme
	if entitlementList, ok := entitlements[scheme]; ok {
		for _, entitlement := range entitlementList {
			if ec.entitlementMatches(entitlement, requirement) {
				return true
			}
		}
	}

	// Check anonymous entitlements if we are checking the default scheme
	if scheme == ec.defaultScheme {
		for _, entitlement := range ec.anonymousEntitlements {
			if ec.entitlementMatches(entitlement, requirement) {
				return true
			}
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

