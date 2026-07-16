package entitlements

import (
	"errors"
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

// Entitlements is a map where keys are security schemes (e.g., "bearer", "oauth2")
// and values are slices of entitlement strings. Entitlement strings can be in
// long, medium, short, or opaque forms.
type Entitlements map[string][]string

// EntitlementsChecker handles the verification of user entitlements against security requirements.
// It supports exact matches and wildcard patterns for resource names and verbs.
//
// Pattern Forms:
//   - Long Form:   <resource>:<resourceName>:<verb>
//   - Medium Form: <resource>::<verb>                (means <resource>:*:<verb>)
//   - Short Form:  <resource>:<verb>                 (means <resource>:*:<verb>)
//   - Opaque Form: <resource>                        (not a wildcard, only matches exactly)
//
// Opaque form is intended to support JWT claims and other forms of requirements
// like HTTP Headers.
//
// Encoding:
// resourceName must not contain colons ':' since they would be misinterpreted
// by the pattern splitting logic. The library does not escape resourceNames -
// the same string is used on both sides of every match comparison, so callers
// must use the same form when writing entitlements/requirements as they pass
// to the Verify*ResourceEntitlements / CalculateResourceRequirements helpers.
// If a caller's natural resourceName carries a ':', encode it consistently
// (e.g. url.PathEscape) at the caller's boundary on both the input side and
// the verification side.
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
	basePatterns        []entitlementPattern
	cache               map[string]entitlementPattern
	defaultScheme       string
	grantReadyByDefault bool
	log                 *logr.Logger
	mu                  sync.RWMutex
	strictRequirements  bool
}

// NewEntitlementsChecker creates a new entitlements checker with the specified settings.
// anonymousEntitlements is a list of patterns granted only to callers whose
// entitlements map is empty (no schemes present, or every scheme's list empty).
// Authenticated callers do not receive these patterns; use WithBaseEntitlements
// for patterns that should apply to every caller.
// defaultScheme is the fallback security scheme used when none is specified.
// grantReadyByDefault determines if the identity requirement is automatically satisfied.
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

// ParsedEntitlements represents a set of user entitlements that have been pre-parsed
// into internal patterns for high-performance verification.
type ParsedEntitlements struct {
	patterns map[string][]entitlementPattern
}

// ParsedRequirements represents a set of security requirements that have been
// pre-parsed into internal patterns for high-performance verification.
type ParsedRequirements struct {
	patterns []map[string][]entitlementPattern
	// hasPlaceholder is precomputed so BindRequirements can no-op on the
	// (common) requirement sets that contain no placeholder.
	hasPlaceholder bool
}

// Requirements is a slice of maps representing alternative security requirement sets.
// Each map in the slice represents an alternative set of requirements (OR'd).
// Within each map, all schemes and their associated scopes must be satisfied (AND'd).
type Requirements []map[string][]string

// CalculateResourceRequirements calculates the requirements for a resource instance.
// It returns a copy of the requirements with an identity requirement added for the specific resource.
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

// ParseEntitlements converts a raw Entitlements map into ParsedEntitlements for
// efficient reuse in multiple verification calls.
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

// ParseRequirements converts raw Requirements into ParsedRequirements for
// efficient reuse in multiple verification calls.
func (ec *EntitlementsChecker) ParseRequirements(requirements Requirements) ParsedRequirements {
	parsed := make([]map[string][]entitlementPattern, len(requirements))
	hasPlaceholder := false
	for i, req := range requirements {
		newReq := make(map[string][]entitlementPattern, len(req))
		for scheme, list := range req {
			patterns := make([]entitlementPattern, len(list))
			for j, s := range list {
				patterns[j] = ec.parsePattern(s)
				if patterns[j].placeholder != "" {
					hasPlaceholder = true
				}
			}
			newReq[scheme] = patterns
		}
		parsed[i] = newReq
	}
	return ParsedRequirements{patterns: parsed, hasPlaceholder: hasPlaceholder}
}

// Binding maps a requirement placeholder key to the concrete resourceName it
// stands for, e.g. {"vector_store_id": "vs_abc"}.
type Binding map[string]string

// BindRequirements substitutes every {placeholder} resourceName in reqs with
// its value from b and returns the rewritten requirements. Requirement sets
// containing no placeholder are returned unchanged.
//
// Returns ErrUnboundPlaceholder if any placeholder has no entry in b — an
// unbound placeholder is a configuration error, never a pass. Keys in b that
// match no placeholder are ignored, so a caller may pass a superset (e.g.
// every path value it resolved) without knowing the requirement.
//
// Returns ErrInvalidBoundValue if a placeholder is bound to "", "*", or a
// value containing ':'. "" and "*" are the wildcard spelling of a
// resourceName, not a concrete value: binding one would silently widen the
// requirement to the whole resource class. A ':' is rejected because this
// method constructs the bound pattern directly (see the comment below), but
// Rust and Python have no pre-parsed type and must re-emit the bound pattern
// as a string that verify then re-parses — there, a value containing ':'
// re-splits into the wrong shape and the pattern silently becomes opaque.
// Rejecting the colon here, in every port, is what keeps all four producing
// identical results instead of fixing only the two that happen to rebuild the
// string. A binder that could not resolve a value must fail like an unbound
// placeholder rather than widen the gate or diverge across ports.
//
// Under WithStrictRequirements, also returns ErrWildcardRequirement if any
// requirement in reqs — placeholder or not — has a wildcard resourceName (""
// or "*", including the short/medium syntaxes). This check runs before the
// placeholder no-op above, so a wildcard-only requirement set (no placeholder
// at all) is still rejected rather than passed through unchanged.
func (ec *EntitlementsChecker) BindRequirements(reqs ParsedRequirements, b Binding) (ParsedRequirements, error) {
	if ec.strictRequirements {
		for _, set := range reqs.patterns {
			for _, list := range set {
				for _, p := range list {
					if p.isPattern && p.placeholder == "" && isWildcardName(p.resourceName) {
						return ParsedRequirements{}, fmt.Errorf("%w: %q",
							ErrWildcardRequirement, p.raw)
					}
				}
			}
		}
	}

	if !reqs.hasPlaceholder {
		return reqs, nil
	}

	bound := make([]map[string][]entitlementPattern, len(reqs.patterns))
	for i, set := range reqs.patterns {
		newSet := make(map[string][]entitlementPattern, len(set))
		for scheme, list := range set {
			newList := make([]entitlementPattern, len(list))
			for j, p := range list {
				if p.placeholder == "" {
					newList[j] = p
					continue
				}
				v, ok := b[p.placeholder]
				if !ok {
					return ParsedRequirements{}, fmt.Errorf("%w: %q in requirement %q",
						ErrUnboundPlaceholder, p.placeholder, p.raw)
				}
				if isWildcardName(v) || strings.Contains(v, ":") {
					return ParsedRequirements{}, fmt.Errorf("%w: %q bound to %q in requirement %q",
						ErrInvalidBoundValue, p.placeholder, v, p.raw)
				}
				// Construct directly rather than re-parsing: a bound value
				// containing ':' would otherwise be re-split into the wrong
				// shape. Callers encode such values at their boundary.
				newList[j] = entitlementPattern{
					raw:          p.resource + ":" + v + ":" + p.verb,
					resource:     p.resource,
					resourceName: v,
					verb:         p.verb,
					isPattern:    true,
				}
			}
			newSet[scheme] = newList
		}
		bound[i] = newSet
	}
	return ParsedRequirements{patterns: bound, hasPlaceholder: false}, nil
}

// WildcardRequirements returns the requirement strings whose resourceName is a
// wildcard ("*", empty, or the short/medium syntaxes) — the spellings strict
// mode rejects outright. Results are de-duplicated and in first-seen order.
//
// It is a migration inventory, not a complete strict-mode pre-flight: strict
// also rejects an unbound placeholder at verification time, which this query
// does not report (a placeholder is the migration's destination, not a target).
// An empty result means no requirement still uses a wildcard spelling.
//
// It is a pure query so a caller may log, count, or fail in its own idiom. Use
// it to inventory what remains to migrate before enabling WithStrictRequirements.
func (ec *EntitlementsChecker) WildcardRequirements(reqs Requirements) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, set := range reqs {
		for _, list := range set {
			for _, s := range list {
				p := ec.parsePattern(s)
				if !p.isPattern || p.placeholder != "" || !isWildcardName(p.resourceName) {
					continue
				}
				if _, dup := seen[s]; dup {
					continue
				}
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}

// VerifyEntitlements checks if the user's entitlements satisfy the given security requirements.
// It returns true if any of the alternative requirement sets (OR'd) is fully satisfied.
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

// VerifyParsedEntitlements is a high-performance check that uses pre-parsed entitlements
// and requirements. It is intended for scenarios where the same entitlements or
// requirements are checked repeatedly.
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

// VerifyResourceEntitlements checks if the user's entitlements satisfy the security requirements
// for a specific resource instance. It automatically adds an identity requirement for the resource.
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

// VerifyResourceParsedEntitlements is a high-performance check for a specific resource instance
// using pre-parsed entitlements and requirements.
//
// Under WithStrictRequirements, a resourceName of "*" makes the identity
// requirement this method builds illegal by spelling, so it is denied
// regardless of grants — see WithStrictRequirements for the full explanation.
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

// WithLogger attaches a logger to the EntitlementsChecker for debugging purposes.
func (ec *EntitlementsChecker) WithLogger(log logr.Logger) *EntitlementsChecker {
	ec.log = &log
	return ec
}

// WithStrictRequirements rejects wildcard resourceNames on the requirement side.
// It never affects entitlements, where wildcards remain meaningful.
//
// When enabled, BindRequirements returns ErrWildcardRequirement for such a
// requirement (the loud path), and verification treats both a wildcard
// requirement and an unbound placeholder as unsatisfiable (a fail-closed
// backstop for callers that skip BindRequirements).
//
// Defaults to false; a future major version will default it to true. Intended
// for use during checker construction; not safe for concurrent mutation with
// verify calls in flight.
//
// VerifyResourceEntitlements and VerifyResourceParsedEntitlements build their
// identity requirement from the caller-supplied resourceName (as
// "<resource>:<resourceName>:<verb>"). They already reject an empty
// resourceName outright, but "*" passes that guard; under strict, "*" makes
// the identity a wildcard requirement — illegal by spelling — so the check
// denies unconditionally, regardless of the caller's grants, including a
// genuine wildcard grant like "pages::all". Callers must pass a concrete
// resourceName. There is deliberately no requirement spelling for "holds
// authority over the whole class"; use an opaque capability scope for that.
func (ec *EntitlementsChecker) WithStrictRequirements(strict bool) *EntitlementsChecker {
	ec.strictRequirements = strict
	return ec
}

// hasParsedEntitlement checks if the user has a specific entitlement using pre-parsed patterns.
func (ec *EntitlementsChecker) hasParsedEntitlement(entitlementList []entitlementPattern, scheme string, requirement entitlementPattern, isAnonymousCaller bool) bool {
	// Strict backstop for callers that skip BindRequirements: a wildcard
	// requirement is an illegal spelling, and an unbound placeholder was never
	// resolved. Both are unsatisfiable rather than silently admitted — a held
	// wildcard would otherwise match either one.
	if ec.strictRequirements && requirement.isPattern {
		if requirement.placeholder != "" || isWildcardName(requirement.resourceName) {
			return false
		}
	}

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
				placeholder:  placeholderKey(parts[1]),
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

// satisfiesRequirement checks if user entitlements satisfy a single security requirement.
func (ec *EntitlementsChecker) satisfiesRequirement(entitlements map[string][]entitlementPattern, scheme string, requirement []entitlementPattern, isAnonymousCaller bool) bool {
	for _, parsedReq := range requirement {
		if !ec.hasParsedEntitlement(entitlements[scheme], scheme, parsedReq, isAnonymousCaller) {
			return false
		}
	}

	return true
}

type entitlementPattern struct {
	raw          string
	resource     string
	resourceName string
	verb         string
	isPattern    bool
	// placeholder is the binding key when resourceName is "{key}", else "".
	// Meaningful only on the requirement side; held-side placeholders are
	// literal text.
	placeholder string
}

// ErrUnboundPlaceholder is returned by BindRequirements when a requirement
// declares a {placeholder} that the supplied Binding does not resolve. An
// unbound placeholder is an error, never a pass.
var ErrUnboundPlaceholder = errors.New("entitlements: unbound placeholder in requirement")

// ErrWildcardRequirement is returned by BindRequirements under strict mode when
// a requirement's resourceName is a wildcard ("*" or empty, which includes the
// short and medium syntaxes). Wildcards are meaningful only on the held side;
// as a requirement the spelling is ambiguous. Use a {placeholder} for the
// resource being addressed, or an opaque scope for a context-less capability.
var ErrWildcardRequirement = errors.New("entitlements: wildcard resourceName is not allowed in a requirement")

// ErrInvalidBoundValue is returned by BindRequirements when a Binding maps a
// placeholder to "", "*", or a value containing ':'. "" and "*" are the
// wildcard spelling, not a concrete resourceName: binding one would silently
// widen the requirement to the whole resource class. A ':' would re-split the
// bound pattern into the wrong shape when re-parsed — Rust and Python rebuild
// the pattern as a string and are exposed to that hazard, while Go and
// TypeScript construct it directly and are not; rejecting the colon in all
// four ports is what keeps their results identical. A binder that could not
// resolve a value must fail like an unbound placeholder rather than widen the
// gate or diverge across ports.
var ErrInvalidBoundValue = errors.New("entitlements: bound value must not be empty, a wildcard, or contain ':'")

// placeholderKey returns the binding key when resourceName has the form
// "{key}", else "". "{}" is a literal resourceName, not a placeholder.
func placeholderKey(resourceName string) string {
	if len(resourceName) > 2 &&
		strings.HasPrefix(resourceName, "{") &&
		strings.HasSuffix(resourceName, "}") {
		return resourceName[1 : len(resourceName)-1]
	}
	return ""
}

// isWildcardName reports whether a resourceName is a wildcard. Empty is the
// parsed form of both the short (<resource>:<verb>) and medium
// (<resource>::<verb>) syntaxes.
func isWildcardName(n string) bool {
	return n == "" || n == "*"
}

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

// Dominates reports whether the held entitlement is equal to or BROADER than
// the requested one under the kdex-entitlements grammar. This is the predicate
// for attenuation (minting a token that carries a subset of the caller's
// authority). Unlike request-time matching (entitlementMatches), a wildcard
// resourceName is honored ONLY on the held side: a specific grant cannot
// dominate a wildcard request, so a mint can never broaden authority.
//
// Opaque scopes (no ':') dominate only by exact match.
func Dominates(held, requested string) bool {
	if held == requested {
		return true
	}

	hp := strings.Split(held, ":")
	if len(hp) == 2 { // short form <resource>:<verb> == <resource>:*:<verb>
		hp = []string{hp[0], "", hp[1]}
	}
	rp := strings.Split(requested, ":")
	if len(rp) == 2 {
		rp = []string{rp[0], "", rp[1]}
	}

	// Opaque or malformed: only exact match (handled above) dominates.
	if len(hp) != 3 || len(rp) != 3 {
		return false
	}

	// Resource type must match.
	if hp[0] != rp[0] {
		return false
	}

	// Verb: held "all" dominates any; otherwise verbs must match. A requested
	// "all" is NOT dominated by a specific held verb.
	if hp[2] != "all" && hp[2] != rp[2] {
		return false
	}

	// resourceName: a wildcard is honored ONLY on the held side.
	if hp[1] == "" || hp[1] == "*" {
		return true
	}
	return hp[1] == rp[1]
}

// VerifyAttenuation returns ("", true) when every requested entitlement is
// dominated by at least one held entitlement. Otherwise it returns the first
// requested entitlement that no held entitlement dominates, and false.
func VerifyAttenuation(held, requested []string) (offender string, ok bool) {
	for _, req := range requested {
		dominated := false
		for _, h := range held {
			if Dominates(h, req) {
				dominated = true
				break
			}
		}
		if !dominated {
			return req, false
		}
	}
	return "", true
}

// Compact returns the subset of entitlements with every entry removed that is
// strictly dominated by another entry, or that is an exact / equivalent-form
// duplicate (e.g. "pages:read", "pages::read", "pages:*:read" collapse to the
// first-seen one). The result grants exactly the same authority as the input;
// surviving entries keep their original strings and their first-seen order.
//
// It is defined purely in terms of Dominates, so its notion of "broader than"
// can never drift from attenuation. Opaque and malformed scopes collapse only
// by exact equality. Compaction is intended for preparing an entitlement array
// (e.g. before minting a narrowed token); it does not consult the checker's
// anonymous/base patterns or the intern cache.
func Compact(entitlements []string) []string {
	survivors := make([]string, 0, len(entitlements))
	for i, e := range entitlements {
		// (1) Drop e if some OTHER entry strictly dominates it.
		strictlyDominated := false
		for j, o := range entitlements {
			if i == j {
				continue
			}
			if Dominates(o, e) && !Dominates(e, o) {
				strictlyDominated = true
				break
			}
		}
		if strictlyDominated {
			continue
		}
		// (2) e is maximal; keep it unless an equivalent survivor is already
		// present (exact dup or equal form, i.e. mutual dominance).
		dup := false
		for _, s := range survivors {
			if Dominates(s, e) && Dominates(e, s) {
				dup = true
				break
			}
		}
		if !dup {
			survivors = append(survivors, e)
		}
	}
	return survivors
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
