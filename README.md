# entitlements
A simple entitlments checking library

### Requirement forms

A requirement — what a caller must satisfy — may additionally be:

- **Placeholder**: `vector_stores:{vector_store_id}:write` — a hole bound to a
  concrete value at check time via `bindRequirements`, where unbound is an
  error, never a pass. (`{}` is a literal, not a placeholder.) Skip binding
  with strict off, though, and an unbound placeholder reaching verification is
  just a literal resourceName — a held wildcard still matches it.
- **Opaque**: `vector_stores_create` — a context-less capability, matched
  exactly and therefore never satisfied by a wildcard grant.

Wildcards (`*` or empty) are a **held-side** concept. As a requirement the
spelling is ambiguous, and `withStrictRequirements(true)` rejects it. Strict
defaults to **false**; use `wildcardRequirements()` to inventory the wildcard
spellings that still need migrating before enabling it.

Binding a placeholder to `""` or `*` is an error — those are the wildcard
spelling, not a concrete resource name, so binding one would widen the
requirement to the whole class.
