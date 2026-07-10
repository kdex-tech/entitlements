# Design: `Compact` — prune dominated entitlements from an array

**Date:** 2026-07-09
**Scope:** All four ports (Go, Rust, Python, TypeScript)
**Target version:** `v0.3.0`

## Problem

Entitlement arrays assembled in the wild accumulate redundancy. A single wide
grant such as `functions::read` (i.e. `functions:*:read`) makes every
`functions:/<path>:read` entry redundant, yet those narrower entries are often
carried alongside it. Exact duplicates creep in too. A real observed array:

```
["functions:/v1/users:read","functions:/v1/users:create","functions:/v1/users:update","functions:/v1/users:delete","users:me:read","users:me:create","users:me:update","users:me:delete","apitokens::mint","apitokens::revoke","vector_stores:system:read","functions:/api/v1/vector_stores:read","functions:/api/v1/vector_stores:create","functions:/api/v1/vector_stores:update","functions:/api/v1/vector_stores:delete","functions:/api/v1/files:read","functions:/api/v1/files:create","functions:/api/v1/files:update","functions:/api/v1/files:delete","functions:/api/v1/search:read","functions:/api/v1/search:create","functions:/api/v1/search:update","functions:/api/v1/search:delete","functions:/api/v1/uploads:read","functions:/api/v1/uploads:create","functions:/api/v1/uploads:update","functions:/api/v1/uploads:delete","functions:/api/v1/ingest:read","functions:/api/v1/ingest:create","functions:/api/v1/ingest:update","functions:/api/v1/ingest:delete","functions:/api/v1/mcp:read","functions:/api/v1/mcp:create","functions:/api/v1/mcp:update","functions:/api/v1/mcp:delete","functions:/api/v1/events:read","functions:/api/v1/events:create","functions:/api/v1/events:update","functions:/api/v1/events:delete","functions:/tenant/v1:read","functions:/tenant/v1:create","functions:/tenant/v1:update","functions:/tenant/v1:delete","functions:/feedback/v1:read","functions:/feedback/v1:create","pages::read","functions::read","vector_stores:system:read","functions:/v1/chat:read"]
```

49 entries, of which 12 are redundant: eleven `functions:/<path>:read` grants
dominated by `functions::read`, plus one exact-duplicate `vector_stores:system:read`.

Consumers of this library (e.g. token-minting code) want a **utility to
normalize such an array before use** — before minting a narrowed token, before
persisting a grant set, before embedding entitlements in a claim.

## Resolution

Add a pure, stateless free function **`Compact`** to each port that returns a
minimal array granting **exactly** the same authority as the input, with all
dominated and duplicate entries removed.

It is defined **entirely in terms of the existing `Dominates` predicate** (Go
`Dominates`, Rust `Pattern::dominates`, Python `Pattern.dominates`, TS
`dominates`) — the same relation used for attenuation. Reusing that predicate is
what guarantees compaction can never drift from the library's notion of "broader
than", and is what makes it safe.

`Compact` is a sibling of `VerifyAttenuation`: a free function, no
`EntitlementsChecker` state involved. Anonymous/base patterns and the intern
cache play no part — compaction is pure string-dominance over a single array.

### Why `Dominates`, not request-time `matches`

Request-time matching (`entitlementPattern.matches`) honors a wildcard
`resourceName` on **either** side. If compaction used it, `pages:*:read` and
`pages:/foo:read` would appear mutually redundant and the algorithm could drop
the **wider** one — silently losing authority. `Dominates` is asymmetric (a
wildcard is honored only on the held side), so `pages:*:read` **strictly**
dominates `pages:/foo:read` and only the specific entry is pruned. This
asymmetry is the correctness foundation of the feature.

## Public API

One free function per port, named to sit alongside `Dominates` /
`VerifyAttenuation`. Pure input → output; input array is not mutated.

### Go

```go
// Compact returns the subset of entitlements with every entry that is
// dominated by another entry (or is an exact/equivalent duplicate) removed.
// The result grants exactly the same authority as the input. Order of the
// surviving entries follows their first appearance in the input.
func Compact(entitlements []string) []string
```

### Rust

```rust
pub fn compact(entitlements: &[String]) -> Vec<String>
```

### Python

```python
def compact(entitlements: list[str]) -> list[str]:
    ...
```

### TypeScript

```typescript
export function compact(entitlements: string[]): string[]
```

## Algorithm

Keep the **maximal** entitlements under dominance; first-seen wins among
equivalents. Expressed in terms of the existing `Dominates(held, requested)`
predicate:

```
compact(entitlements) -> survivors:
    survivors = []
    for each e at index i in entitlements:
        # (1) strictly dominated by some OTHER entry -> redundant, drop
        if exists o at index j (j != i) such that
                Dominates(o, e) AND NOT Dominates(e, o):
            continue
        # (2) e is maximal; keep it unless an equivalent is already kept
        #     (equivalent = mutually dominating; covers exact duplicates AND
        #      equal forms like pages:read / pages::read / pages:*:read)
        if exists s in survivors such that
                Dominates(s, e) AND Dominates(e, s):
            continue
        survivors.append(e)
    return survivors
```

O(n²) in the array length. These arrays are dozens of entries and compaction
runs at prepare/mint time, not on the hot verify path — the same cost profile as
`VerifyAttenuation`. Pre-parsing into interned patterns is a possible future
optimization but is intentionally **not** done here, to keep the reference
implementation a thin, obviously-correct layer over `Dominates`. (A bucketed
group-by-resource approach was considered and rejected: it would introduce a
second, parallel notion of dominance to keep synchronized across four languages
— YAGNI.)

### Guarantees

- **Authority-preserving (lossless).** Every input entry is dominated by some
  survivor, and every survivor came from the input. For all requirements `R`:
  `VerifyEntitlements({scheme: compact(list)}, R) == VerifyEntitlements({scheme: list}, R)`.
  Compaction never fabricates a wider entitlement.
- **Order-preserving.** Survivors appear in first-seen order.
- **Idempotent.** `Compact(Compact(x)) == Compact(x)`.
- **Deterministic.** Dominance is transitive in this grammar (same resource
  throughout; `held`-side wildcard and `all` verb compose transitively), so
  "strictly dominated by *any* other entry" fully captures redundancy with no
  chain ambiguity; the first-seen rule breaks equivalence-form ties.
- **Opaque / malformed handling.** Opaque scopes (`admin`, `email`) and
  malformed structured strings (`a:b:c:d`) collapse only by exact equality —
  identical to `Dominates`.

### Worked result for the Problem array

49 → 37. Pruned: the eleven `functions:/<path>:read` entries (dominated by
`functions::read`) and the one duplicate `vector_stores:system:read`. Survivors
include every `:create` / `:update` / `:delete` grant (no wider entry covers
those verbs), `vector_stores:system:read` (different resource than `functions`,
so `functions::read` does not reach it), `users:me:read` (no `users:*` grant
present), and the dominators `pages::read` and `functions::read` themselves.

## Tests

Mirrored across all four ports — same scenarios, idiomatic test style for each
(per the repo's cross-port consistency rule):

1. **Real-world array (headline):** the 49-entry Problem array compacts to the
   expected 37-entry survivor set, in first-seen order.
2. **Wildcard dominance:** `["x:*:read","x:/a:read","x:/b:read"]` → `["x:*:read"]`.
3. **`all`-verb dominance:** `["x:/a:all","x:/a:read"]` → `["x:/a:all"]`.
4. **Equivalent forms collapse:** `["pages:read","pages::read","pages:*:read"]`
   → `["pages:read"]` (first-seen survivor).
5. **Exact-duplicate dedup:** repeated identical string collapses to one.
6. **Cross-resource non-interference:** `["functions::read","vector_stores:system:read"]`
   is returned unchanged.
7. **Verb non-interference:** `functions::read` does **not** prune
   `functions:/a:create`.
8. **Opaque handling:** `["admin","admin","email"]` → `["admin","email"]`;
   opaque never dominates a structured scope and vice versa.
9. **Edge cases:** empty array → empty; single element → unchanged; array with no
   redundancy → unchanged (same order).
10. **Idempotency:** `Compact(Compact(x)) == Compact(x)` for the headline array.
11. **Authority equivalence:** for a sampling of requirements, `VerifyEntitlements`
    yields the same result against the original and the compacted array.
12. **Input not mutated:** the caller's input array/slice is left untouched.

## Documentation

- **`SPEC.md`** — new **Compaction** section adjacent to *Attenuation (Dominance)*:
  define `Compact`/`compact` as the authority-preserving prune built on the
  dominance relation, note the four port names, and state the guarantees
  (lossless, order-preserving, idempotent). Reference the `Dominates`-not-`matches`
  rationale.
- **Inline docs** — the Go doc comment on `Compact` is the canonical description
  (per repo convention); rustdoc / Python docstring / TSDoc mirror it.

## Versioning and release

- Additive, backward-compatible: **minor** bump to `v0.3.0` across all four
  packages; `VERSION` file → `0.3.0`.
- Single PR landing all four ports + spec together (cross-port consistency rule).
- Tagging `v0.3.0` triggers the existing CI release flow (GitHub Release,
  parallel `go/v0.3.0` tag, crates.io / PyPI / npm publish).

## Out of scope

- Any map-level `Entitlements` variant — this utility operates on arrays only.
  Callers holding an `Entitlements` map compact each scheme's list themselves.
- Lossy collapsing / synthesizing wider scopes (e.g. folding
  `x:foo:{read,create,update,delete}` into `x:foo:all`). Compaction only prunes;
  it never expands authority.
- Canonicalizing/normalizing survivor strings (e.g. rewriting `pages:read` to
  `pages:*:read`). Original strings are preserved.
- Changes to `EntitlementsChecker`, the intern cache, or any matching/dominance
  rule. `Compact` consumes `Dominates` unchanged.
- Pre-parsing/interning inside `Compact` (possible future optimization).
