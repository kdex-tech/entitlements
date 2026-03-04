package entitlements

import (
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/go-logr/logr"
)

const (
	// maxCacheSize prevents the interning cache from growing indefinitely.
	maxCacheSize = 10000
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
	anonymousPatterns   []entitlementPattern
	cache               map[string]entitlementPattern
	defaultScheme       string
	grantReadyByDefault bool
	log                 *logr.Logger
	mu                  sync.RWMutex
}

type entitlementPattern struct {
	raw          string
	resource     string
	resourceName string
	verb         string
	isPattern    bool
}

type Entitlements map[string][]string
type Requirements []map[string][]string

// NewEntitlementsChecker creates a new entitlements checker.
func NewEntitlementsChecker(
	anonymousEntitlements []string,
	defaultScheme string,
	grantReadyByDefault bool,
) *EntitlementsChecker {
	if defaultScheme == "" {
		defaultScheme = "bearer"
	}

	ec := &EntitlementsChecker{
		cache:               make(map[string]entitlementPattern),
		defaultScheme:       defaultScheme,
		grantReadyByDefault: grantReadyByDefault,
	}

	if len(anonymousEntitlements) > 0 {
		ec.anonymousPatterns = make([]entitlementPattern, len(anonymousEntitlements))
		for i, s := range anonymousEntitlements {
			ec.anonymousPatterns[i] = ec.parsePattern(s)
		}
	}

	return ec
}

func (ec *EntitlementsChecker) parsePattern(s string) entitlementPattern {
	// 1. Check the interning cache first
	ec.mu.RLock()
	p, ok := ec.cache[s]
	ec.mu.RUnlock()
	if ok {
		return p
	}

	// 2. Optimization: If no colon is present, it's definitely an opaque form.
	// This avoids the allocation of strings.Split for simple strings.
	if !strings.Contains(s, ":") {
		p = entitlementPattern{
			raw:       s,
			isPattern: false,
		}
	} else {
		parts := strings.Split(s, ":")

		// short syntax was used <resource>:<verb> which is equal to <resource>::<verb>, or <resource>:*:<verb>
		if len(parts) == 2 {
			p = entitlementPattern{
				raw:          s,
				resource:     parts[0],
				resourceName: "",
				verb:         parts[1],
				isPattern:    true,
			}
		} else if len(parts) == 3 {
			p = entitlementPattern{
				raw:          s,
				resource:     parts[0],
				resourceName: parts[1],
				verb:         parts[2],
				isPattern:    true,
			}
		} else {
			// Opaque form or invalid structure (e.g. too many colons)
			p = entitlementPattern{
				raw:       s,
				isPattern: false,
			}
		}
	}

	// 3. Store in cache if there is room
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if len(ec.cache) < maxCacheSize {
		ec.cache[s] = p
	}
	return p
}

func (ep entitlementPattern) matches(req entitlementPattern) bool {
	// Exact match is always the fastest path
	if ep.raw == req.raw {
		return true
	}

	// If either is not a pattern (opaque), only exact match (above) works
	if !ep.isPattern || !req.isPattern {
		return false
	}

	// Resource type must match
	if ep.resource != req.resource {
		return false
	}

	// Verb must match (or entitlement provides "all")
	if ep.verb != "all" && ep.verb != req.verb {
		return false
	}

	// Check resource name with wildcard support
	// Empty string or "*" in either side means all resources
	if ep.resourceName == "" || ep.resourceName == "*" || req.resourceName == "" || req.resourceName == "*" {
		return true
	}

	// Specific resource name must match
	return ep.resourceName == req.resourceName
}

// CalculateResourceRequirements calculates the requirements for a resource instance.
// It returns a copy of the requirements with the identity requirement added.
// The optional verbs parameter allows specifying the verb for the identity requirement (defaults to "read").
func (ec *EntitlementsChecker) CalculateResourceRequirements(
	resource string,
	resourceName string,
	requirements Requirements,
	verbs ...string,
) (Requirements, error) {
	if resource == "" || resourceName == "" {
		return nil, fmt.Errorf("resource and resourceName must not be empty")
	}

	verb := "read"
	if len(verbs) > 0 && verbs[0] != "" {
		verb = verbs[0]
	}

	// In order for pattern matching to work we need to create and add an identity requirement.
	// Manual concatenation is faster than fmt.Sprintf
	identity := resource + ":" + resourceName + ":" + verb

	// We must return a new structure to avoid modifying the input, but we can do it efficiently.
	newRequirements := make(Requirements, 0, len(requirements)+1)

	if len(requirements) == 0 {
		newRequirements = append(newRequirements, map[string][]string{
			ec.defaultScheme: {identity},
		})
	} else {
		for _, req := range requirements {
			newReq := make(map[string][]string, len(req))
			maps.Copy(newReq, req)
			newReq[ec.defaultScheme] = append(newReq[ec.defaultScheme], identity)
			newRequirements = append(newRequirements, newReq)
		}
	}

	return newRequirements, nil
}

// VerifyResourceEntitlements checks if the user's entitlements satisfy the security requirements for a resource instance.
// The optional verbs parameter allows specifying the verb for the identity requirement (defaults to "read").
func (ec *EntitlementsChecker) VerifyResourceEntitlements(
	resource string,
	resourceName string,
	entitlements Entitlements,
	requirements Requirements,
	verbs ...string,
) (bool, error) {
	if resource == "" || resourceName == "" {
		return false, fmt.Errorf("resource and resourceName must not be empty")
	}

	parsedEntitlements := ec.ParseEntitlements(entitlements)
	parsedRequirements := ec.ParseRequirements(requirements)
	
	return ec.VerifyResourceParsedEntitlements(resource, resourceName, parsedEntitlements, parsedRequirements, verbs...)
}

// VerifyResourceParsedEntitlements is a high-performance check that uses pre-parsed entitlements and requirements.
// It is intended for power users who want to avoid parsing overhead in tight loops.
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

	// Check if user satisfies the resource identity requirement.
	identity := resource + ":" + resourceName + ":" + verb
	parsedIdentity := ec.parsePattern(identity)

	hasIdentity := ec.grantReadyByDefault || ec.hasParsedEntitlement(parsedEntitlements.patterns[ec.defaultScheme], ec.defaultScheme, parsedIdentity)
	if !hasIdentity {
		return false, nil
	}

	// Verify the rest of the requirements.
	if len(parsedRequirements.patterns) == 0 {
		return true, nil
	}

	return ec.VerifyParsedEntitlements(parsedEntitlements, parsedRequirements), nil
}

// VerifyEntitlements checks if the user's entitlements satisfy the security requirements.
func (ec *EntitlementsChecker) VerifyEntitlements(
	entitlements Entitlements,
	requirements Requirements,
) (result bool) {
	if len(requirements) == 0 {
		return true
	}

	parsedEntitlements := ec.ParseEntitlements(entitlements)
	parsedRequirements := ec.ParseRequirements(requirements)
	return ec.VerifyParsedEntitlements(parsedEntitlements, parsedRequirements)
}

// VerifyParsedEntitlements is a high-performance check that uses pre-parsed entitlements and requirements.
// It is intended for power users who want to avoid parsing overhead in tight loops.
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

	// Here requirements are OR'd - user needs to satisfy at least one
	for _, requirement := range requirements.patterns {
		if ec.satisfiesAndRequirements(entitlements.patterns, requirement) {
			result = true
			return
		}
	}

	result = false
	return
}

// ParsedRequirements represents a pre-parsed set of requirements.
type ParsedRequirements struct {
	patterns []map[string][]entitlementPattern
}

// ParseRequirements pre-parses requirements for high-performance verification.
func (ec *EntitlementsChecker) ParseRequirements(requirements Requirements) ParsedRequirements {
	parsed := make([]map[string][]entitlementPattern, len(requirements))
	for i, req := range requirements {
		newReq := make(map[string][]entitlementPattern, len(req))
		for scheme, list := range req {
			patterns := make([]entitlementPattern, len(list))
			for j, s := range list {
				patterns[j] = ec.parsePattern(s)
			}
			newReq[scheme] = patterns
		}
		parsed[i] = newReq
	}
	return ParsedRequirements{patterns: parsed}
}

// ParsedEntitlements represents a pre-parsed set of user entitlements.
type ParsedEntitlements struct {
	patterns map[string][]entitlementPattern
}

// ParseEntitlements pre-parses entitlements for high-performance verification.
func (ec *EntitlementsChecker) ParseEntitlements(entitlements Entitlements) ParsedEntitlements {
	parsed := make(map[string][]entitlementPattern, len(entitlements))
	for scheme, list := range entitlements {
		patterns := make([]entitlementPattern, len(list))
		for i, s := range list {
			patterns[i] = ec.parsePattern(s)
		}
		parsed[scheme] = patterns
	}
	return ParsedEntitlements{patterns: parsed}
}

func (ec *EntitlementsChecker) WithLogger(log logr.Logger) *EntitlementsChecker {
	ec.log = &log
	return ec
}

func (ec *EntitlementsChecker) satisfiesAndRequirements(entitlements map[string][]entitlementPattern, requirement map[string][]entitlementPattern) bool {
	// Here requirements are AND'ed - user must match all
	for scheme, requirementList := range requirement {
		// A scheme is satisfied if it's present in entitlements OR it's the default scheme and we have anonymous entitlements.
		_, ok := entitlements[scheme]
		if !ok && (scheme != ec.defaultScheme || len(ec.anonymousPatterns) <= 0) {
			return false
		}

		if !ec.satisfiesRequirement(entitlements, scheme, requirementList) {
			return false
		}
	}

	return true
}

// satisfiesRequirement checks if user entitlements satisfy a single security requirement.
func (ec *EntitlementsChecker) satisfiesRequirement(entitlements map[string][]entitlementPattern, scheme string, requirement []entitlementPattern) bool {
	for _, parsedReq := range requirement {
		if !ec.hasParsedEntitlement(entitlements[scheme], scheme, parsedReq) {
			return false
		}
	}

	return true
}

// hasParsedEntitlement checks if the user has a specific entitlement using pre-parsed patterns.
func (ec *EntitlementsChecker) hasParsedEntitlement(entitlementList []entitlementPattern, scheme string, requirement entitlementPattern) bool {
	// Check user-provided entitlements for this scheme
	for _, entitlement := range entitlementList {
		if entitlement.matches(requirement) {
			return true
		}
	}

	// Check anonymous entitlements if we are checking the default scheme
	if scheme == ec.defaultScheme {
		for _, pattern := range ec.anonymousPatterns {
			if pattern.matches(requirement) {
				return true
			}
		}
	}

	return false
}
