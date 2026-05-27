# Specification: kdex-entitlements

## Core Concept
`kdex-entitlements` is a language-agnostic entitlements checking library. It handles the verification of user entitlements against security requirements using a structured pattern matching system.

## Entitlement Pattern Forms
Entitlements and requirements can be represented in four forms:
- **Long Form**: `<resource>:<resourceName>:<verb>`
  - Matches a specific action on a specific resource instance.
  - Example: `pages:/foo:read`
- **Medium Form**: `<resource>::<verb>`
  - Shorthand for `<resource>:*:<verb>`.
  - Matches a specific action on all instances of a resource type.
  - Example: `pages::read`
- **Short Form**: `<resource>:<verb>`
  - Shorthand for `<resource>:*:<verb>`.
  - Matches a specific action on all instances of a resource type.
  - Example: `pages:read`
- **Opaque Form**: `<string>`
  - A simple string that does not contain colons (or does not follow the pattern structure).
  - Matches only exactly.
  - Example: `admin`, `email`

### Wildcards
- `*` can be used as a `<resourceName>` to represent all instances of a resource.
- `all` can be used as a `<verb>` in an **entitlement** to represent all actions on a resource. A requirement for `read` is satisfied by an entitlement for `all`.

### Encoding
The `resourceName` should be URL-encoded (e.g., `url.PathEscape` in Go) if it contains colons `:` to prevent misinterpretation during pattern splitting.

## Data Structures

### Entitlements
A map where keys are security schemes (e.g., "bearer", "oauth2") and values are lists of entitlement strings.
- Example: `{"bearer": ["pages:read", "books:all"], "oauth2": ["email"]}`

### Requirements
A list of maps representing alternative security requirement sets (OR'd). Within each map, all schemes and their associated requirement strings must be satisfied (AND'd).
- Example: `[{"bearer": ["pages:read"]}, {"oauth2": ["email"]}]` means (bearer has pages:read) OR (oauth2 has email).

## Verification Logic

### Pattern Matching Rules
1. **Exact Match**: If the entitlement string exactly matches the requirement string, it is satisfied.
2. **Opaque Match**: If either the entitlement or the requirement is in opaque form, only an exact match satisfies it.
3. **Structured Match**:
   - **Resource**: The resource type in the entitlement must match the resource type in the requirement.
   - **Verb**: The verb in the entitlement must match the verb in the requirement, OR the entitlement verb must be `all`.
   - **Resource Name**:
     - If the entitlement resource name is empty or `*`, it matches all resource names in requirements.
     - If the requirement resource name is empty or `*`, it matches all resource names in entitlements.
     - Otherwise, the resource names must match exactly.

### Verification Flow
1. If requirements are empty, verification succeeds.
2. A requirement set (one map in the list) is satisfied if:
   - For every scheme in the requirement set:
     - The user has entitlements for that scheme.
     - EVERY requirement string for that scheme is satisfied by at least one of the user's entitlement strings for that same scheme.
3. The overall verification succeeds if ANY requirement set is satisfied.

### Anonymous Entitlements
An `EntitlementsChecker` can be configured with a list of "anonymous" patterns. These patterns are automatically granted to callers **only when the caller's `Entitlements` map is empty** (no schemes present, or every scheme's list is empty). They are applied under the `defaultScheme`. An authenticated caller — one who passes any entitlements at all — does **not** receive the anonymous bag.

### Base Entitlements
An `EntitlementsChecker` can additionally be configured with a list of "base" patterns via a builder-style setter (`WithBaseEntitlements` / `with_base_entitlements` / `withBaseEntitlements`). Base patterns are applied under the `defaultScheme` to **every** caller — authenticated or anonymous — and form a floor of grants that every request receives. Calling the setter again replaces the previous list.

Use anonymous entitlements for grants that should only widen the unauthenticated surface. Use base entitlements for grants that should always apply regardless of caller identity.

### Resource-Specific Verification
A specialized verification that automatically adds an "identity requirement" for a specific resource instance:
- Identity Requirement: `<resource>:<encodedResourceName>:<verb>` (default verb is `read`).
- User must satisfy this identity requirement AND the provided additional requirements.

## Implementation Requirements
- **Performance**: Implementations should prioritize performance, potentially using pattern interning/caching and pre-parsing of entitlements and requirements.
- **Coverage**: Maintain >80% test coverage.
- **Concurrency**: The entitlements checker should be thread-safe for concurrent verification calls.
