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
 * Encoding: resourceName should be URL-encoded (use `encodeURIComponent`) if it
 * contains colons ':' to prevent pattern-splitting from misinterpreting it.
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

export class EntitlementsChecker {
  readonly defaultScheme: string;
  readonly grantReadyByDefault: boolean;
  private readonly anonymousPatterns: EntitlementPattern[];
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
    const identity = `${resource}:${encodeURIComponent(resourceName)}:${effectiveVerb}`;

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
    for (const requirement of requirements.patterns) {
      if (this.satisfiesAndRequirements(entitlements.patterns, requirement)) {
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
    const identity = `${resource}:${encodeURIComponent(resourceName)}:${effectiveVerb}`;
    const parsedIdentity = this.parsePattern(identity);

    const list = entitlements.patterns[this.defaultScheme] ?? [];
    const hasIdentity =
      this.grantReadyByDefault ||
      this.hasParsedEntitlement(list, this.defaultScheme, parsedIdentity);
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
  ): boolean {
    for (const e of entitlementList) {
      if (matches(e, requirement)) {
        return true;
      }
    }

    if (scheme === this.defaultScheme) {
      for (const e of this.anonymousPatterns) {
        if (matches(e, requirement)) {
          return true;
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

    let p: EntitlementPattern;
    if (!s.includes(":")) {
      p = { raw: s, resource: "", resourceName: "", verb: "", isPattern: false };
    } else {
      const parts = s.split(":");
      if (parts.length === 2) {
        // Short syntax <resource>:<verb> == <resource>:*:<verb>.
        p = {
          raw: s,
          resource: parts[0]!,
          resourceName: "",
          verb: parts[1]!,
          isPattern: true,
        };
      } else if (parts.length === 3) {
        p = {
          raw: s,
          resource: parts[0]!,
          resourceName: parts[1]!,
          verb: parts[2]!,
          isPattern: true,
        };
      } else {
        // Too many colons → treat as opaque (matches Go behavior).
        p = { raw: s, resource: "", resourceName: "", verb: "", isPattern: false };
      }
    }

    if (this.cache.size < MAX_CACHE_SIZE) {
      this.cache.set(s, p);
    }
    return p;
  }

  private satisfiesAndRequirements(
    entitlements: Record<string, EntitlementPattern[]>,
    requirement: Record<string, EntitlementPattern[]>,
  ): boolean {
    for (const [scheme, requirementList] of Object.entries(requirement)) {
      // A scheme is satisfied if it's present in the user's entitlements OR
      // it's the default scheme and we have anonymous entitlements.
      if (
        !(scheme in entitlements) &&
        !(scheme === this.defaultScheme && this.anonymousPatterns.length > 0)
      ) {
        return false;
      }
      if (!this.satisfiesRequirement(entitlements, scheme, requirementList)) {
        return false;
      }
    }
    return true;
  }

  private satisfiesRequirement(
    entitlements: Record<string, EntitlementPattern[]>,
    scheme: string,
    requirement: EntitlementPattern[],
  ): boolean {
    const list = entitlements[scheme] ?? [];
    for (const r of requirement) {
      if (!this.hasParsedEntitlement(list, scheme, r)) {
        return false;
      }
    }
    return true;
  }
}
