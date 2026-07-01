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

interface EntitlementPattern {
  raw: string;
  resource: string;
  resourceName: string;
  verb: string;
  isPattern: boolean;
}

/** Parsed entitlements held for reuse across multiple verifications. */
export interface ParsedEntitlements {
  readonly patterns: Record<string, EntitlementPattern[]>;
}

/** Parsed requirements held for reuse across multiple verifications. */
export interface ParsedRequirements {
  readonly patterns: Array<Record<string, EntitlementPattern[]>>;
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
    return { raw: s, resource: "", resourceName: "", verb: "", isPattern: false };
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
    };
  } else if (parts.length === 3) {
    return {
      raw: s,
      resource: parts[0]!,
      resourceName: parts[1]!,
      verb: parts[2]!,
      isPattern: true,
    };
  }

  // Too many colons → treat as opaque (matches Go behavior).
  return { raw: s, resource: "", resourceName: "", verb: "", isPattern: false };
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
    const patterns = requirements.map((req) => {
      const next: Record<string, EntitlementPattern[]> = {};
      for (const [scheme, list] of Object.entries(req)) {
        next[scheme] = list.map((s) => this.parsePattern(s));
      }
      return next;
    });
    return { patterns };
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
