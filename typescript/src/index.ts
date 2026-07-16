/**
 * KDex Entitlements — TypeScript port of `kdex-entitlements/go/entitlements.go`.
 *
 * Pattern Forms:
 *   - Long Form:   <resource>:<resourceName>:<verb>
 *   - Medium Form: <resource>::<verb>                (means <resource>:*:<verb>)
 *   - Short Form:  <resource>:<verb>                 (means <resource>:*:<verb>)
 *   - Opaque Form: <resource>                        (not a wildcard, only matches exactly)
 *
 * Opaque form is intended to support JWT claims and HTTP-header-style requirements.
 *
 * Encoding: resourceName must not contain colons ':' since they would be
 * misinterpreted by the pattern splitting logic. The library does not encode
 * resourceNames - the same string is used on both sides of every match
 * comparison, so callers must use the same form when writing
 * entitlements/requirements as they pass to
 * verify{,Parsed}ResourceEntitlements / calculateResourceRequirements. If a
 * caller's natural resourceName carries a ':', encode it consistently
 * (e.g. `encodeURIComponent`) at the caller's boundary on both sides.
 */

/** Map of security scheme name → list of entitlement strings. */
export type Entitlements = Record<string, string[]>;

/**
 * Alternative security requirement sets (OR'd). Within each map, all schemes
 * and their associated scopes must be satisfied (AND'd).
 */
export type Requirements = Array<Record<string, string[]>>;

/**
 * Maps a requirement placeholder key to the concrete resourceName it stands
 * for, e.g. { vector_store_id: "vs_abc" }.
 */
export type Binding = Record<string, string>;

/**
 * A requirement declared a {placeholder} the binding does not resolve. An
 * unbound placeholder is an error, never a pass.
 */
export class UnboundPlaceholderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnboundPlaceholderError";
  }
}

/**
 * Strict mode: a requirement's resourceName is a wildcard. Wildcards are
 * meaningful only on the held side; as a requirement the spelling is ambiguous.
 * Use a {placeholder} for the resource being addressed, or an opaque scope for
 * a context-less capability.
 */
export class WildcardRequirementError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WildcardRequirementError";
  }
}

/**
 * A placeholder was bound to "", "*", or a value containing ':'. "" and "*"
 * are the wildcard spelling, not a concrete resourceName: binding one would
 * silently widen the requirement to the whole resource class. A ':' would
 * re-split the bound pattern into the wrong shape when re-parsed — Rust and
 * Python have no pre-parsed type and must re-emit the bound pattern as a
 * string that gets re-parsed, so they are exposed to that hazard even though
 * this port and Go construct the pattern directly; rejecting the colon here
 * too is what keeps all four ports identical. A binder that could not resolve
 * a value must fail like an unbound placeholder rather than widen the gate or
 * diverge across ports.
 */
export class InvalidBoundValueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidBoundValueError";
  }
}

/**
 * The binding key when resourceName has the form "{key}", else "". "{}" is a
 * literal resourceName, not a placeholder.
 */
function placeholderKey(resourceName: string): string {
  if (resourceName.length > 2 && resourceName.startsWith("{") && resourceName.endsWith("}")) {
    return resourceName.slice(1, -1);
  }
  return "";
}

/**
 * Whether a resourceName is a wildcard. Empty is the parsed form of both the
 * short (<resource>:<verb>) and medium (<resource>::<verb>) syntaxes.
 */
function isWildcardName(n: string): boolean {
  return n === "" || n === "*";
}

interface EntitlementPattern {
  raw: string;
  resource: string;
  resourceName: string;
  verb: string;
  isPattern: boolean;
  /** Binding key when resourceName is "{key}", else "". Requirement-side only. */
  placeholder: string;
}

/** Parsed entitlements held for reuse across multiple verifications. */
export interface ParsedEntitlements {
  readonly patterns: Record<string, EntitlementPattern[]>;
}

/** Parsed requirements held for reuse across multiple verifications. */
export interface ParsedRequirements {
  readonly patterns: Array<Record<string, EntitlementPattern[]>>;
  /** Precomputed so bindRequirements can no-op on sets with no placeholder. */
  readonly hasPlaceholder: boolean;
}

const MAX_CACHE_SIZE = 10_000;

function matches(ep: EntitlementPattern, req: EntitlementPattern): boolean {
  // Exact match is always the fastest path.
  if (ep.raw === req.raw) {
    return true;
  }

  // Opaque on either side only matches exactly (handled above).
  if (!ep.isPattern || !req.isPattern) {
    return false;
  }

  // Resource type must match.
  if (ep.resource !== req.resource) {
    return false;
  }

  // Verb must match (or entitlement provides "all").
  if (ep.verb !== "all" && ep.verb !== req.verb) {
    return false;
  }

  // Wildcard resource name on either side matches.
  if (
    ep.resourceName === "" ||
    ep.resourceName === "*" ||
    req.resourceName === "" ||
    req.resourceName === "*"
  ) {
    return true;
  }

  // Otherwise, resource names must match exactly.
  return ep.resourceName === req.resourceName;
}

function parsePattern(s: string): EntitlementPattern {
  if (!s.includes(":")) {
    return { raw: s, resource: "", resourceName: "", verb: "", isPattern: false, placeholder: "" };
  }

  const parts = s.split(":");
  if (parts.length === 2) {
    // Short syntax <resource>:<verb> == <resource>:*:<verb>.
    return {
      raw: s,
      resource: parts[0]!,
      resourceName: "",
      verb: parts[1]!,
      isPattern: true,
      placeholder: "",
    };
  } else if (parts.length === 3) {
    return {
      raw: s,
      resource: parts[0]!,
      resourceName: parts[1]!,
      verb: parts[2]!,
      isPattern: true,
      placeholder: placeholderKey(parts[1]!),
    };
  }

  // Too many colons → treat as opaque (matches Go behavior).
  return { raw: s, resource: "", resourceName: "", verb: "", isPattern: false, placeholder: "" };
}

/**
 * Reports whether the held entitlement (`ep`) is equal to or BROADER than
 * the requested one (`req`) under the kdex-entitlements grammar. This is the
 * predicate for attenuation (minting a token that carries a subset of the
 * caller's authority). Unlike request-time matching (`matches`), a wildcard
 * resourceName is honored ONLY on the held side: a specific grant cannot
 * dominate a wildcard request, so a mint can never broaden authority.
 *
 * Opaque scopes (no ':') dominate only by exact match.
 */
function dominates(ep: EntitlementPattern, req: EntitlementPattern): boolean {
  if (ep.raw === req.raw) {
    return true;
  }

  // Opaque or malformed: only exact match (handled above) dominates.
  if (!ep.isPattern || !req.isPattern) {
    return false;
  }

  // Resource type must match.
  if (ep.resource !== req.resource) {
    return false;
  }

  // Verb: held "all" dominates any; otherwise verbs must match. A requested
  // "all" is NOT dominated by a specific held verb.
  if (ep.verb !== "all" && ep.verb !== req.verb) {
    return false;
  }

  // resourceName: a wildcard is honored ONLY on the held side.
  if (ep.resourceName === "" || ep.resourceName === "*") {
    return true;
  }
  return ep.resourceName === req.resourceName;
}

/**
 * Returns `null` when every requested entitlement is dominated by at least
 * one held entitlement. Otherwise returns the first requested entitlement
 * that no held entitlement dominates.
 */
export function verifyAttenuation(held: string[], requested: string[]): string | null {
  const heldPatterns = held.map((s) => parsePattern(s));
  for (const req of requested) {
    const reqPattern = parsePattern(req);
    const dominated = heldPatterns.some((h) => dominates(h, reqPattern));
    if (!dominated) {
      return req;
    }
  }
  return null;
}

/**
 * Returns the subset of `entitlements` with every entry removed that is
 * strictly dominated by another entry, or that is an exact / equivalent-form
 * duplicate (e.g. "pages:read", "pages::read", "pages:*:read" collapse to the
 * first-seen one). The result grants exactly the same authority as the input;
 * survivors keep their original strings and their first-seen order.
 *
 * Built purely on `dominates`, so it can never drift from attenuation. Opaque
 * and malformed scopes collapse only by exact equality.
 */
export function compact(entitlements: string[]): string[] {
  const patterns = entitlements.map((s) => parsePattern(s));
  const survivors: string[] = [];
  const survivorPatterns: EntitlementPattern[] = [];
  for (let i = 0; i < patterns.length; i++) {
    const ep = patterns[i]!;
    // (1) Drop if some OTHER entry strictly dominates it.
    let strictlyDominated = false;
    for (let j = 0; j < patterns.length; j++) {
      if (i === j) continue;
      const op = patterns[j]!;
      if (dominates(op, ep) && !dominates(ep, op)) {
        strictlyDominated = true;
        break;
      }
    }
    if (strictlyDominated) continue;
    // (2) Maximal; keep unless an equivalent survivor already present.
    const dup = survivorPatterns.some((sp) => dominates(sp, ep) && dominates(ep, sp));
    if (!dup) {
      survivors.push(entitlements[i]!);
      survivorPatterns.push(ep);
    }
  }
  return survivors;
}

function isAnonymousCallerPatterns(
  patterns: Record<string, EntitlementPattern[]>,
): boolean {
  const schemes = Object.keys(patterns);
  if (schemes.length === 0) return true;
  for (const k of schemes) {
    if ((patterns[k]?.length ?? 0) > 0) return false;
  }
  return true;
}

export class EntitlementsChecker {
  readonly defaultScheme: string;
  readonly grantReadyByDefault: boolean;
  private readonly anonymousPatterns: EntitlementPattern[];
  private basePatterns: EntitlementPattern[] = [];
  private strictRequirements = false;
  private readonly cache = new Map<string, EntitlementPattern>();

  constructor(
    anonymousEntitlements: readonly string[] | undefined,
    defaultScheme: string,
    grantReadyByDefault: boolean,
  ) {
    this.defaultScheme = defaultScheme === "" ? "bearer" : defaultScheme;
    this.grantReadyByDefault = grantReadyByDefault;
    this.anonymousPatterns = (anonymousEntitlements ?? []).map((s) =>
      this.parsePattern(s),
    );
  }

  /**
   * Sets the base entitlements: patterns that apply to every caller
   * (authenticated or anonymous) under the default scheme. Unlike the
   * constructor's `anonymousEntitlements` (which apply only when the
   * caller's entitlements map is empty), base entitlements form a floor
   * of grants that every request receives.
   *
   * Replaces any previously set base entitlements. Returns `this` for
   * chaining. Intended for use during construction; not safe for
   * concurrent mutation with verify calls in flight.
   */
  withBaseEntitlements(patterns: readonly string[]): this {
    this.basePatterns = patterns.map((s) => this.parsePattern(s));
    return this;
  }

  /**
   * Rejects wildcard resourceNames on the requirement side. Never affects
   * entitlements, where wildcards remain meaningful.
   *
   * When enabled, bindRequirements throws WildcardRequirementError (the loud
   * path) and verification treats both a wildcard requirement and an unbound
   * placeholder as unsatisfiable (a fail-closed backstop for callers that skip
   * binding).
   *
   * Defaults to false; a future major version will default it to true.
   */
  withStrictRequirements(strict: boolean): EntitlementsChecker {
    this.strictRequirements = strict;
    return this;
  }

  /**
   * The requirement strings whose resourceName is a wildcard — the spellings
   * strict mode rejects outright. De-duplicated, first-seen order.
   *
   * It is a migration inventory, not a complete strict-mode pre-flight:
   * strict also rejects an unbound placeholder at verification time, which
   * this query does not report (a placeholder is the migration's
   * destination, not a target). An empty result means no requirement still
   * uses a wildcard spelling.
   *
   * It is a pure query so a caller may log, count, or fail in its own idiom.
   * Use it to inventory what remains to migrate before enabling
   * withStrictRequirements.
   */
  wildcardRequirements(reqs: Requirements): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const set of reqs) {
      for (const list of Object.values(set)) {
        for (const s of list) {
          const p = this.parsePattern(s);
          if (!p.isPattern || p.placeholder !== "" || !isWildcardName(p.resourceName)) continue;
          if (seen.has(s)) continue;
          seen.add(s);
          out.push(s);
        }
      }
    }
    return out;
  }

  /**
   * Substitutes every {placeholder} resourceName in `reqs` with its value from
   * `binding` and returns the rewritten requirements. Sets containing no
   * placeholder are returned unchanged (identity).
   *
   * @throws {UnboundPlaceholderError} a placeholder has no entry in `binding` —
   *   an unbound placeholder is a configuration error, never a pass. Keys that
   *   match no placeholder are ignored, so a caller may pass a superset.
   * @throws {WildcardRequirementError} strict mode, wildcard requirement.
   */
  bindRequirements(reqs: ParsedRequirements, binding: Binding): ParsedRequirements {
    if (this.strictRequirements) {
      for (const set of reqs.patterns) {
        for (const list of Object.values(set)) {
          for (const p of list) {
            if (p.isPattern && p.placeholder === "" && isWildcardName(p.resourceName)) {
              throw new WildcardRequirementError(
                `wildcard resourceName is not allowed in requirement "${p.raw}"`,
              );
            }
          }
        }
      }
    }

    if (!reqs.hasPlaceholder) {
      return reqs;
    }

    const bound = reqs.patterns.map((set) => {
      const newSet: Record<string, EntitlementPattern[]> = {};
      for (const [scheme, list] of Object.entries(set)) {
        newSet[scheme] = list.map((p) => {
          if (p.placeholder === "") return p;
          const v = binding[p.placeholder];
          if (v === undefined) {
            throw new UnboundPlaceholderError(
              `unbound placeholder "${p.placeholder}" in requirement "${p.raw}"`,
            );
          }
          // "" and "*" are the wildcard spelling, not concrete names: binding
          // one would widen the requirement to the whole class. A ':' is
          // rejected too: although this port constructs the pattern directly
          // below (see the comment there) rather than re-parsing it, Rust and
          // Python have no pre-parsed type and must re-emit the bound pattern
          // as a string that gets re-parsed — a value containing ':' would
          // re-split into the wrong shape there and become opaque. Rejecting
          // the colon here as well is what keeps all four ports identical
          // instead of only the two that build the pattern directly. Fail
          // like an unbound placeholder in every case.
          if (isWildcardName(v) || v.includes(":")) {
            throw new InvalidBoundValueError(
              `bound value must not be empty, a wildcard, or contain ':': "${p.placeholder}" bound to "${v}" in requirement "${p.raw}"`,
            );
          }
          // Construct directly rather than re-parsing: a bound value containing
          // ':' would otherwise be re-split into the wrong shape.
          return {
            raw: `${p.resource}:${v}:${p.verb}`,
            resource: p.resource,
            resourceName: v,
            verb: p.verb,
            isPattern: true,
            placeholder: "",
          };
        });
      }
      return newSet;
    });

    return { patterns: bound, hasPlaceholder: false };
  }

  /**
   * Calculate the requirements for a specific resource instance.
   * Adds an identity requirement (default verb `read`).
   */
  calculateResourceRequirements(
    resource: string,
    resourceName: string,
    requirements: Requirements,
    verb?: string,
  ): Requirements {
    if (resource === "" || resourceName === "") {
      throw new Error("resource and resourceName must not be empty");
    }

    const effectiveVerb = verb && verb !== "" ? verb : "read";
    const identity = `${resource}:${resourceName}:${effectiveVerb}`;

    if (requirements.length === 0) {
      return [{ [this.defaultScheme]: [identity] }];
    }

    return requirements.map((req) => {
      const next: Record<string, string[]> = {};
      for (const [scheme, list] of Object.entries(req)) {
        next[scheme] = [...list];
      }
      next[this.defaultScheme] = [...(next[this.defaultScheme] ?? []), identity];
      return next;
    });
  }

  /** Pre-parse an `Entitlements` map for reuse. */
  parseEntitlements(entitlements: Entitlements): ParsedEntitlements {
    const patterns: Record<string, EntitlementPattern[]> = {};
    for (const [scheme, list] of Object.entries(entitlements)) {
      patterns[scheme] = list.map((s) => this.parsePattern(s));
    }
    return { patterns };
  }

  /** Pre-parse a `Requirements` array for reuse. */
  parseRequirements(requirements: Requirements): ParsedRequirements {
    let hasPlaceholder = false;
    const patterns = requirements.map((req) => {
      const next: Record<string, EntitlementPattern[]> = {};
      for (const [scheme, list] of Object.entries(req)) {
        next[scheme] = list.map((s) => {
          const p = this.parsePattern(s);
          if (p.placeholder !== "") {
            hasPlaceholder = true;
          }
          return p;
        });
      }
      return next;
    });
    return { patterns, hasPlaceholder };
  }

  /**
   * Returns true iff at least one of the alternative requirement sets
   * (OR'd) is fully satisfied by the user's entitlements.
   */
  verifyEntitlements(
    entitlements: Entitlements,
    requirements: Requirements,
  ): boolean {
    if (requirements.length === 0) {
      return true;
    }
    return this.verifyParsedEntitlements(
      this.parseEntitlements(entitlements),
      this.parseRequirements(requirements),
    );
  }

  /** Verify pre-parsed entitlements + requirements. */
  verifyParsedEntitlements(
    entitlements: ParsedEntitlements,
    requirements: ParsedRequirements,
  ): boolean {
    if (requirements.patterns.length === 0) {
      return true;
    }
    const isAnonymous = isAnonymousCallerPatterns(entitlements.patterns);
    for (const requirement of requirements.patterns) {
      if (this.satisfiesAndRequirements(entitlements.patterns, requirement, isAnonymous)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Verify entitlements for a specific resource instance. Automatically adds
   * an identity requirement (default verb `read`).
   */
  verifyResourceEntitlements(
    resource: string,
    resourceName: string,
    entitlements: Entitlements,
    requirements: Requirements,
    verb?: string,
  ): boolean {
    if (resource === "" || resourceName === "") {
      throw new Error("resource and resourceName must not be empty");
    }
    return this.verifyResourceParsedEntitlements(
      resource,
      resourceName,
      this.parseEntitlements(entitlements),
      this.parseRequirements(requirements),
      verb,
    );
  }

  /** Pre-parsed counterpart of `verifyResourceEntitlements`. */
  verifyResourceParsedEntitlements(
    resource: string,
    resourceName: string,
    entitlements: ParsedEntitlements,
    requirements: ParsedRequirements,
    verb?: string,
  ): boolean {
    if (resource === "" || resourceName === "") {
      throw new Error("resource and resourceName must not be empty");
    }

    const effectiveVerb = verb && verb !== "" ? verb : "read";
    const identity = `${resource}:${resourceName}:${effectiveVerb}`;
    const parsedIdentity = this.parsePattern(identity);

    const list = entitlements.patterns[this.defaultScheme] ?? [];
    const isAnonymous = isAnonymousCallerPatterns(entitlements.patterns);
    const hasIdentity =
      this.grantReadyByDefault ||
      this.hasParsedEntitlement(list, this.defaultScheme, parsedIdentity, isAnonymous);
    if (!hasIdentity) {
      return false;
    }

    if (requirements.patterns.length === 0) {
      return true;
    }
    return this.verifyParsedEntitlements(entitlements, requirements);
  }

  private hasParsedEntitlement(
    entitlementList: EntitlementPattern[],
    scheme: string,
    requirement: EntitlementPattern,
    isAnonymousCaller: boolean,
  ): boolean {
    // Strict backstop for callers that skip bindRequirements: a wildcard
    // requirement is an illegal spelling and an unbound placeholder was never
    // resolved. Both are unsatisfiable rather than silently admitted — a held
    // wildcard would match either.
    if (
      this.strictRequirements &&
      requirement.isPattern &&
      (requirement.placeholder !== "" || isWildcardName(requirement.resourceName))
    ) {
      return false;
    }

    for (const e of entitlementList) {
      if (matches(e, requirement)) return true;
    }

    if (scheme === this.defaultScheme) {
      for (const e of this.basePatterns) {
        if (matches(e, requirement)) return true;
      }
      if (isAnonymousCaller) {
        for (const e of this.anonymousPatterns) {
          if (matches(e, requirement)) return true;
        }
      }
    }

    return false;
  }

  private parsePattern(s: string): EntitlementPattern {
    const cached = this.cache.get(s);
    if (cached !== undefined) {
      return cached;
    }

    const p = parsePattern(s);

    if (this.cache.size < MAX_CACHE_SIZE) {
      this.cache.set(s, p);
    }
    return p;
  }

  private satisfiesAndRequirements(
    entitlements: Record<string, EntitlementPattern[]>,
    requirement: Record<string, EntitlementPattern[]>,
    isAnonymousCaller: boolean,
  ): boolean {
    for (const [scheme, requirementList] of Object.entries(requirement)) {
      const userHas = scheme in entitlements;
      const hasFallback =
        scheme === this.defaultScheme &&
        (this.basePatterns.length > 0 ||
          (isAnonymousCaller && this.anonymousPatterns.length > 0));
      if (!userHas && !hasFallback) return false;

      if (!this.satisfiesRequirement(entitlements, scheme, requirementList, isAnonymousCaller)) {
        return false;
      }
    }
    return true;
  }

  private satisfiesRequirement(
    entitlements: Record<string, EntitlementPattern[]>,
    scheme: string,
    requirement: EntitlementPattern[],
    isAnonymousCaller: boolean,
  ): boolean {
    const list = entitlements[scheme] ?? [];
    for (const r of requirement) {
      if (!this.hasParsedEntitlement(list, scheme, r, isAnonymousCaller)) {
        return false;
      }
    }
    return true;
  }
}
