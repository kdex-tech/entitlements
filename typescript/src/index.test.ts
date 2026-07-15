import { describe, expect, it } from "vitest";
import {
  EntitlementsChecker,
  verifyAttenuation,
  compact,
  UnboundPlaceholderError,
  WildcardRequirementError,
  InvalidBoundValueError,
  type Entitlements,
  type Requirements,
} from "./index.js";

interface VerifyCase {
  name: string;
  anonymousEntitlements: string[];
  entitlements: Entitlements;
  requirements: Requirements;
  want: boolean;
}

const verifyCases: VerifyCase[] = [
  { name: "none", anonymousEntitlements: [], entitlements: {}, requirements: [], want: true },
  {
    name: "opaque - no entitlements",
    anonymousEntitlements: [],
    entitlements: {},
    requirements: [{ bearer: ["pages"] }],
    want: false,
  },
  {
    name: "opaque - entitlements match requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages"] },
    requirements: [{ bearer: ["pages"] }],
    want: true,
  },
  {
    name: "opaque - entitlements does not match requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["books"] },
    requirements: [{ bearer: ["pages"] }],
    want: false,
  },
  {
    name: "opaque - does not match wildcard specific verb",
    anonymousEntitlements: [],
    entitlements: { bearer: ["books"] },
    requirements: [{ bearer: ["books:read"] }],
    want: false,
  },
  {
    name: "opaque - does not match wildcard all verb",
    anonymousEntitlements: [],
    entitlements: { bearer: ["books"] },
    requirements: [{ bearer: ["books:all"] }],
    want: false,
  },
  {
    name: "opaque - does not match explicit wildcard all verb",
    anonymousEntitlements: [],
    entitlements: { bearer: ["books"] },
    requirements: [{ bearer: ["books:*:all"] }],
    want: false,
  },
  {
    name: "opaque - wildcard all verb entitlement does not match opaque requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["books:all"] },
    requirements: [{ bearer: ["books"] }],
    want: false,
  },
  {
    name: "short - entitlements match requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:read"] },
    requirements: [{ bearer: ["pages:read"] }],
    want: true,
  },
  {
    name: "short - entitlements do not match requirement with multiple verbs",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:read"] },
    requirements: [{ bearer: ["pages:read", "pages:write"] }],
    want: false,
  },
  {
    name: "short - entitlements match requirement with multiple verbs",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:read", "pages:write"] },
    requirements: [{ bearer: ["pages:read", "pages:write"] }],
    want: true,
  },
  {
    name: "short - entitlement does not match requirement wrong verb",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:read"] },
    requirements: [{ bearer: ["pages:write"] }],
    want: false,
  },
  {
    name: "short - wildcard entitlement does not match opaque requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:all"] },
    requirements: [{ bearer: ["pages"] }],
    want: false,
  },
  {
    name: "short - wildcard entitlement matches wildcard requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:all"] },
    requirements: [{ bearer: ["pages:all"] }],
    want: true,
  },
  {
    name: "short - wildcard entitlement matches short requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:all"] },
    requirements: [{ bearer: ["pages:read"] }],
    want: true,
  },
  {
    name: "long - long entitlement matches short requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:/foo:read"] },
    requirements: [{ bearer: ["pages:read"] }],
    want: true,
  },
  {
    name: "long - long entitlement matches long requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:/foo:read"] },
    requirements: [{ bearer: ["pages:/foo:read"] }],
    want: true,
  },
  {
    name: "long - long entitlement does not match short requirement wrong verb",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:/foo:read"] },
    requirements: [{ bearer: ["pages:write"] }],
    want: false,
  },
  {
    name: "long - long entitlement matches short requirement by verb",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:/foo:read"] },
    requirements: [{ bearer: ["pages:read"] }],
    want: true,
  },
  {
    name: "long - long entitlement does not match long requirement wrong resourceName",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:/foo:read"] },
    requirements: [{ bearer: ["pages:/bar:read"] }],
    want: false,
  },
  {
    name: "long - long entitlement does not match long requirement wrong resource",
    anonymousEntitlements: [],
    entitlements: { bearer: ["pages:/foo:read"] },
    requirements: [{ bearer: ["books:/foo:read"] }],
    want: false,
  },
  {
    name: "OR - entitlement does not match by resource",
    anonymousEntitlements: [],
    entitlements: { bearer: ["users:/foo:read"] },
    requirements: [
      { bearer: ["books:/foo:read"] },
      { bearer: ["pages:/bar:read"] },
    ],
    want: false,
  },
  {
    name: "OR - entitlement does not match by verb",
    anonymousEntitlements: [],
    entitlements: { bearer: ["users:/foo:read"] },
    requirements: [
      { bearer: ["users:/foo:write"] },
      { bearer: ["users:/foo:delete"] },
    ],
    want: false,
  },
  {
    name: "OR - entitlement does not match by resourceName",
    anonymousEntitlements: [],
    entitlements: { bearer: ["users:/foo:read"] },
    requirements: [
      { bearer: ["users:/bar:read"] },
      { bearer: ["users:/baz:read"] },
    ],
    want: false,
  },
  {
    name: "OR - entitlement matches one of the requirements",
    anonymousEntitlements: [],
    entitlements: { bearer: ["users:/foo:read"] },
    requirements: [
      { bearer: ["users:/bar:read"] },
      { bearer: ["users:/foo:read"] },
    ],
    want: true,
  },
  {
    name: "AND - entitlement does not match all of the requirements",
    anonymousEntitlements: [],
    entitlements: { bearer: ["users:/foo:read"] },
    requirements: [
      { bearer: ["users:/bar:read"], other: ["users:/foo:read"] },
    ],
    want: false,
  },
  {
    name: "AND - entitlement matches all of the requirements",
    anonymousEntitlements: [],
    entitlements: {
      bearer: ["users:/bar:read"],
      other: ["users:/foo:read"],
    },
    requirements: [
      { bearer: ["users:/bar:read"], other: ["users:/foo:read"] },
    ],
    want: true,
  },
  {
    name: "AND - entitlement does not match scheme of requirement",
    anonymousEntitlements: [],
    entitlements: { bearer: ["users:/bar:read"] },
    requirements: [{ other: ["users:/bar:read"] }],
    want: false,
  },
  {
    name: "AND - match only scheme",
    anonymousEntitlements: [],
    entitlements: { bearer: [] },
    requirements: [{ bearer: [] }],
    want: true,
  },
  {
    name: "AND - does not match all schemes",
    anonymousEntitlements: [],
    entitlements: { bearer: [] },
    requirements: [{ bearer: [], oauth2: [] }],
    want: false,
  },
  {
    name: "AND - matches all schemes",
    anonymousEntitlements: [],
    entitlements: { bearer: [], oauth2: [] },
    requirements: [{ bearer: [], oauth2: [] }],
    want: true,
  },
  {
    name: "OR - matches one of the schemes",
    anonymousEntitlements: [],
    entitlements: { bearer: [] },
    requirements: [{ bearer: [] }, { oauth2: [] }],
    want: true,
  },
  {
    name: "OR - matches none of the schemes",
    anonymousEntitlements: [],
    entitlements: { bearer: [] },
    requirements: [{ foo: [] }, { oauth2: [] }],
    want: false,
  },
];

describe("EntitlementsChecker.verifyEntitlements", () => {
  for (const tc of verifyCases) {
    it(tc.name, () => {
      const ec = new EntitlementsChecker(tc.anonymousEntitlements, "bearer", true);
      expect(ec.verifyEntitlements(tc.entitlements, tc.requirements)).toBe(tc.want);
    });
  }
});

interface ResourceCase {
  name: string;
  anonymousEntitlements: string[];
  resource: string;
  resourceName: string;
  entitlements: Entitlements;
  requirements: Requirements;
  want: boolean;
  verb?: string;
}

const resourceReadByDefaultTrueCases: ResourceCase[] = [
  {
    name: "identity entitlements are enough",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: {},
    requirements: [],
    want: true,
  },
  {
    name: "identity entitlements are enough even with other entitlements",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: { bearer: ["pages:write"] },
    requirements: [],
    want: true,
  },
  {
    name: "requirements are raised above identity entitlements",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: {},
    requirements: [{ bearer: ["pages:write"] }],
    want: false,
  },
  {
    name: "requirements are raised above identity entitlements and met by entitlements",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: { bearer: ["pages:write"] },
    requirements: [{ bearer: ["pages:write"] }],
    want: true,
  },
];

describe("verifyResourceEntitlements with grantReadyByDefault=true", () => {
  for (const tc of resourceReadByDefaultTrueCases) {
    it(tc.name, () => {
      const ec = new EntitlementsChecker(tc.anonymousEntitlements, "bearer", true);
      expect(
        ec.verifyResourceEntitlements(
          tc.resource,
          tc.resourceName,
          tc.entitlements,
          tc.requirements,
          tc.verb,
        ),
      ).toBe(tc.want);
    });
  }
});

const resourceReadByDefaultFalseCases: ResourceCase[] = [
  {
    name: "there is no identity entitlements by default",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: {},
    requirements: [],
    want: false,
  },
  {
    name: "need read entitlements",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: { bearer: ["pages:read"] },
    requirements: [],
    want: true,
  },
  {
    name: "require bearer write but not entitled",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: {},
    requirements: [{ bearer: ["pages:write"] }],
    want: false,
  },
  {
    name: "require bearer write and entitled",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: { bearer: ["pages:write", "pages:read"] },
    requirements: [{ bearer: ["pages:write"] }],
    want: true,
  },
  {
    name: "custom identity verb - write",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: { bearer: ["pages:foo:write"] },
    requirements: [],
    want: true,
    verb: "write",
  },
  {
    name: "custom identity verb - write (fails if only read)",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "foo",
    entitlements: { bearer: ["pages:foo:read"] },
    requirements: [],
    want: false,
    verb: "write",
  },
];

describe("verifyResourceEntitlements with grantReadyByDefault=false", () => {
  for (const tc of resourceReadByDefaultFalseCases) {
    it(tc.name, () => {
      // Pass "" so the constructor defaults to "bearer", matching Go test.
      const ec = new EntitlementsChecker(tc.anonymousEntitlements, "", false);
      expect(
        ec.verifyResourceEntitlements(
          tc.resource,
          tc.resourceName,
          tc.entitlements,
          tc.requirements,
          tc.verb,
        ),
      ).toBe(tc.want);
    });
  }
});

// Regression against a previous asymmetry where verify{,Parsed}ResourceEntitlements
// and calculateResourceRequirements ran the caller-supplied resourceName through
// encodeURIComponent when building the identity, but parsePattern (used for both
// anonymousEntitlements and Requirements) left user-supplied resourceNames
// verbatim. A resourceName like "/" came back as "%2F" on the identity side and
// "/" on the entitlement / requirement side, and the specific-name compare in
// matches() does raw-string equality - so any non-wildcard entitlement naming a
// path with reserved chars could not match the identity check. Mirrors the Go
// regression at kdex-entitlements/go/entitlements_test.go's
// TestEntitlementsChecker_VerifyResourceEntitlements_PathResourceNames.
const pathResourceNameCases: ResourceCase[] = [
  {
    name: "anon path-specific grant matches its exact path",
    anonymousEntitlements: ["pages:/:read"],
    resource: "pages",
    resourceName: "/",
    entitlements: {},
    requirements: [],
    want: true,
  },
  {
    name: "anon path-specific grant does not match sibling path",
    anonymousEntitlements: ["pages:/:read"],
    resource: "pages",
    resourceName: "/admin",
    entitlements: {},
    requirements: [],
    want: false,
  },
  {
    name: "anon wildcard matches any path",
    anonymousEntitlements: ["pages:read"],
    resource: "pages",
    resourceName: "/admin",
    entitlements: {},
    requirements: [],
    want: true,
  },
  {
    name: "path-specific requirement + matching anon grant authorizes target path",
    anonymousEntitlements: ["pages:/:read"],
    resource: "pages",
    resourceName: "/",
    entitlements: {},
    requirements: [{ bearer: ["pages:/:read"] }],
    want: true,
  },
  {
    name: "path-specific requirement + non-matching anon grant denies",
    anonymousEntitlements: ["pages:/:read"],
    resource: "pages",
    resourceName: "/admin",
    entitlements: {},
    requirements: [{ bearer: ["pages:/admin:read"] }],
    want: false,
  },
  {
    name: "path-with-subsegment grant matches its exact path",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "/foo",
    entitlements: { bearer: ["pages:/foo:read"] },
    requirements: [],
    want: true,
  },
  {
    name: "path-with-subsegment grant does not match sibling path",
    anonymousEntitlements: [],
    resource: "pages",
    resourceName: "/bar",
    entitlements: { bearer: ["pages:/foo:read"] },
    requirements: [],
    want: false,
  },
];

describe("verifyResourceEntitlements with path resourceNames", () => {
  for (const tc of pathResourceNameCases) {
    it(tc.name, () => {
      const ec = new EntitlementsChecker(tc.anonymousEntitlements, "", false);
      expect(
        ec.verifyResourceEntitlements(
          tc.resource,
          tc.resourceName,
          tc.entitlements,
          tc.requirements,
        ),
      ).toBe(tc.want);
    });
  }
});

describe("anonymous vs base entitlements", () => {
  it("anonymous bag applies when caller is empty", () => {
    const ec = new EntitlementsChecker(["public:read"], "bearer", false);
    expect(ec.verifyEntitlements({}, [{ bearer: ["public:read"] }])).toBe(true);
  });

  it("anonymous bag applies when caller has only empty scheme lists", () => {
    const ec = new EntitlementsChecker(["public:read"], "bearer", false);
    expect(ec.verifyEntitlements({ bearer: [] }, [{ bearer: ["public:read"] }])).toBe(true);
  });

  it("anonymous bag does NOT apply when caller has own entitlements", () => {
    const ec = new EntitlementsChecker(["public:read"], "bearer", false);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["public:read"] }]),
    ).toBe(false);
  });

  it("anonymous bag does NOT apply when caller has entitlements in a different scheme", () => {
    const ec = new EntitlementsChecker(["public:read"], "bearer", false);
    expect(
      ec.verifyEntitlements({ oauth2: ["scope1"] }, [{ bearer: ["public:read"] }]),
    ).toBe(false);
  });

  it("base bag applies to authenticated caller", () => {
    const ec = new EntitlementsChecker([], "bearer", false).withBaseEntitlements([
      "public:read",
    ]);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["public:read"] }]),
    ).toBe(true);
  });

  it("base bag applies to anonymous caller", () => {
    const ec = new EntitlementsChecker([], "bearer", false).withBaseEntitlements([
      "public:read",
    ]);
    expect(ec.verifyEntitlements({}, [{ bearer: ["public:read"] }])).toBe(true);
  });

  it("both bags: authed caller gets base but not anonymous", () => {
    const ec = new EntitlementsChecker(["anon:read"], "bearer", false).withBaseEntitlements([
      "base:read",
    ]);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["base:read"] }]),
    ).toBe(true);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["anon:read"] }]),
    ).toBe(false);
  });

  it("both bags: anonymous caller gets both", () => {
    const ec = new EntitlementsChecker(["anon:read"], "bearer", false).withBaseEntitlements([
      "base:read",
    ]);
    expect(ec.verifyEntitlements({}, [{ bearer: ["anon:read", "base:read"] }])).toBe(true);
  });

  it("withBaseEntitlements replaces (does not append)", () => {
    const ec = new EntitlementsChecker([], "bearer", false)
      .withBaseEntitlements(["first:read"])
      .withBaseEntitlements(["second:read"]);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["first:read"] }]),
    ).toBe(false);
    expect(
      ec.verifyEntitlements({ bearer: ["pages:foo:read"] }, [{ bearer: ["second:read"] }]),
    ).toBe(true);
  });

  it("verifyResourceEntitlements: authed caller satisfies identity via base", () => {
    const ec = new EntitlementsChecker([], "bearer", false).withBaseEntitlements([
      "pages:/foo:read",
    ]);
    expect(
      ec.verifyResourceEntitlements("pages", "/foo", { bearer: ["other:read"] }, []),
    ).toBe(true);
  });

  it("verifyResourceEntitlements: authed caller does NOT satisfy identity via anonymous", () => {
    const ec = new EntitlementsChecker(["pages:/foo:read"], "bearer", false);
    expect(
      ec.verifyResourceEntitlements("pages", "/foo", { bearer: ["other:read"] }, []),
    ).toBe(false);
  });

  it("verifyResourceEntitlements: anon caller satisfies identity via base", () => {
    const ec = new EntitlementsChecker([], "bearer", false).withBaseEntitlements([
      "pages:/foo:read",
    ]);
    expect(
      ec.verifyResourceEntitlements("pages", "/foo", {}, []),
    ).toBe(true);
  });

  it("verifyResourceEntitlements: anon caller satisfies identity via anonymous bag", () => {
    const ec = new EntitlementsChecker(["pages:/foo:read"], "bearer", false);
    expect(
      ec.verifyResourceEntitlements("pages", "/foo", {}, []),
    ).toBe(true);
  });
});

interface CalcCase {
  name: string;
  defaultScheme: string;
  resource: string;
  resourceName: string;
  requirements: Requirements;
  want?: Requirements;
  wantErr?: string;
}

const calcCases: CalcCase[] = [
  {
    name: "no resource",
    defaultScheme: "bearer",
    resource: "",
    resourceName: "foo",
    requirements: [],
    wantErr: "resource and resourceName must not be empty",
  },
  {
    name: "no resource name",
    defaultScheme: "bearer",
    resource: "pages",
    resourceName: "",
    requirements: [],
    wantErr: "resource and resourceName must not be empty",
  },
  {
    name: "no requirements",
    defaultScheme: "bearer",
    resource: "pages",
    resourceName: "foo",
    requirements: [],
    want: [{ bearer: ["pages:foo:read"] }],
  },
  {
    name: "requirements",
    defaultScheme: "bearer",
    resource: "pages",
    resourceName: "foo",
    requirements: [{ bearer: ["pages:write"] }],
    want: [{ bearer: ["pages:write", "pages:foo:read"] }],
  },
  {
    name: "requirements with different scheme",
    defaultScheme: "bar",
    resource: "pages",
    resourceName: "foo",
    requirements: [{ bar: ["pages:write"] }],
    want: [{ bar: ["pages:write", "pages:foo:read"] }],
  },
  {
    name: "requirements with different schemes",
    defaultScheme: "bar",
    resource: "pages",
    resourceName: "foo",
    requirements: [{ bearer: ["pages:write"] }],
    want: [{ bar: ["pages:foo:read"], bearer: ["pages:write"] }],
  },
];

describe("calculateResourceRequirements", () => {
  for (const tc of calcCases) {
    it(tc.name, () => {
      const ec = new EntitlementsChecker([], tc.defaultScheme, false);
      if (tc.wantErr !== undefined) {
        expect(() =>
          ec.calculateResourceRequirements(tc.resource, tc.resourceName, tc.requirements),
        ).toThrow(tc.wantErr);
        return;
      }
      expect(
        ec.calculateResourceRequirements(tc.resource, tc.resourceName, tc.requirements),
      ).toEqual(tc.want);
    });
  }
});

// dominates() is exercised indirectly through verifyAttenuation, mirroring
// Go's TestDominates: held (single-element `held` list) dominates requested
// iff verifyAttenuation returns null (i.e. no offender).
interface DominatesCase {
  name: string;
  held: string;
  requested: string;
  want: boolean;
}

const dominatesCases: DominatesCase[] = [
  {
    name: "held wildcard (medium form) dominates specific",
    held: "vector_stores::write",
    requested: "vector_stores:X:write",
    want: true,
  },
  {
    name: "explicit * on held side dominates specific",
    held: "vector_stores:*:write",
    requested: "vector_stores:X:write",
    want: true,
  },
  {
    name: "specific CANNOT widen to wildcard requested",
    held: "vector_stores:X:write",
    requested: "vector_stores:*:write",
    want: false,
  },
  {
    name: "specific CANNOT widen to empty(*) requested",
    held: "vector_stores:X:write",
    requested: "vector_stores::write",
    want: false,
  },
  {
    name: "exact match dominates",
    held: "vector_stores:X:write",
    requested: "vector_stores:X:write",
    want: true,
  },
  {
    name: "different resourceName does not dominate",
    held: "vector_stores:X:write",
    requested: "vector_stores:Y:write",
    want: false,
  },
  {
    name: "verb all dominates specific verb",
    held: "functions:/api/v1/files:all",
    requested: "functions:/api/v1/files:write",
    want: true,
  },
  {
    name: "requested all is not dominated by specific held verb",
    held: "functions:/api/v1/files:write",
    requested: "functions:/api/v1/files:all",
    want: false,
  },
  {
    name: "different resource does not dominate",
    held: "functions:/x:write",
    requested: "pages:/x:write",
    want: false,
  },
  {
    name: "different verb does not dominate",
    held: "functions:/api/v1/files:read",
    requested: "functions:/api/v1/files:write",
    want: false,
  },
  {
    name: "opaque exact matches",
    held: "admin",
    requested: "admin",
    want: true,
  },
  {
    name: "opaque mismatch does not dominate",
    held: "admin",
    requested: "billing",
    want: false,
  },
  {
    name: "short held form == resource:*:verb",
    held: "functions:read",
    requested: "functions:/api/v1/files:read",
    want: true,
  },
];

describe("dominates (via verifyAttenuation)", () => {
  for (const tc of dominatesCases) {
    it(tc.name, () => {
      const offender = verifyAttenuation([tc.held], [tc.requested]);
      if (tc.want) {
        expect(offender).toBeNull();
      } else {
        expect(offender).toBe(tc.requested);
      }
    });
  }
});

describe("verifyAttenuation", () => {
  it("allows a wildcard held (medium-form) to dominate a specific request", () => {
    const held = ["functions:/api/v1/files:write", "vector_stores::read"];
    const requested = ["functions:/api/v1/files:write", "vector_stores:X:read"];
    expect(verifyAttenuation(held, requested)).toBeNull();
  });

  it("rejects widening a specific held grant to a wildcard request", () => {
    const held = ["vector_stores:X:read"];
    const requested = ["vector_stores:X:read", "vector_stores:*:read"];
    expect(verifyAttenuation(held, requested)).toBe("vector_stores:*:read");
  });
});

const compactRealWorldInput = [
  "functions:/v1/users:read",
  "functions:/v1/users:create",
  "functions:/v1/users:update",
  "functions:/v1/users:delete",
  "users:me:read",
  "users:me:create",
  "users:me:update",
  "users:me:delete",
  "apitokens::mint",
  "apitokens::revoke",
  "vector_stores:system:read",
  "functions:/api/v1/vector_stores:read",
  "functions:/api/v1/vector_stores:create",
  "functions:/api/v1/vector_stores:update",
  "functions:/api/v1/vector_stores:delete",
  "functions:/api/v1/files:read",
  "functions:/api/v1/files:create",
  "functions:/api/v1/files:update",
  "functions:/api/v1/files:delete",
  "functions:/api/v1/search:read",
  "functions:/api/v1/search:create",
  "functions:/api/v1/search:update",
  "functions:/api/v1/search:delete",
  "functions:/api/v1/uploads:read",
  "functions:/api/v1/uploads:create",
  "functions:/api/v1/uploads:update",
  "functions:/api/v1/uploads:delete",
  "functions:/api/v1/ingest:read",
  "functions:/api/v1/ingest:create",
  "functions:/api/v1/ingest:update",
  "functions:/api/v1/ingest:delete",
  "functions:/api/v1/mcp:read",
  "functions:/api/v1/mcp:create",
  "functions:/api/v1/mcp:update",
  "functions:/api/v1/mcp:delete",
  "functions:/api/v1/events:read",
  "functions:/api/v1/events:create",
  "functions:/api/v1/events:update",
  "functions:/api/v1/events:delete",
  "functions:/tenant/v1:read",
  "functions:/tenant/v1:create",
  "functions:/tenant/v1:update",
  "functions:/tenant/v1:delete",
  "functions:/feedback/v1:read",
  "functions:/feedback/v1:create",
  "pages::read",
  "functions::read",
  "vector_stores:system:read",
  "functions:/v1/chat:read",
];

const compactRealWorldExpected = [
  "functions:/v1/users:create",
  "functions:/v1/users:update",
  "functions:/v1/users:delete",
  "users:me:read",
  "users:me:create",
  "users:me:update",
  "users:me:delete",
  "apitokens::mint",
  "apitokens::revoke",
  "vector_stores:system:read",
  "functions:/api/v1/vector_stores:create",
  "functions:/api/v1/vector_stores:update",
  "functions:/api/v1/vector_stores:delete",
  "functions:/api/v1/files:create",
  "functions:/api/v1/files:update",
  "functions:/api/v1/files:delete",
  "functions:/api/v1/search:create",
  "functions:/api/v1/search:update",
  "functions:/api/v1/search:delete",
  "functions:/api/v1/uploads:create",
  "functions:/api/v1/uploads:update",
  "functions:/api/v1/uploads:delete",
  "functions:/api/v1/ingest:create",
  "functions:/api/v1/ingest:update",
  "functions:/api/v1/ingest:delete",
  "functions:/api/v1/mcp:create",
  "functions:/api/v1/mcp:update",
  "functions:/api/v1/mcp:delete",
  "functions:/api/v1/events:create",
  "functions:/api/v1/events:update",
  "functions:/api/v1/events:delete",
  "functions:/tenant/v1:create",
  "functions:/tenant/v1:update",
  "functions:/tenant/v1:delete",
  "functions:/feedback/v1:create",
  "pages::read",
  "functions::read",
];

describe("compact", () => {
  const cases: Array<{ name: string; in: string[]; want: string[] }> = [
    { name: "empty", in: [], want: [] },
    { name: "single", in: ["x:/a:read"], want: ["x:/a:read"] },
    { name: "wildcard prunes specifics", in: ["x:*:read", "x:/a:read", "x:/b:read"], want: ["x:*:read"] },
    { name: "medium form prunes specifics", in: ["x::read", "x:/a:read"], want: ["x::read"] },
    { name: "all-verb prunes read", in: ["x:/a:all", "x:/a:read"], want: ["x:/a:all"] },
    { name: "equivalent forms collapse", in: ["pages:read", "pages::read", "pages:*:read"], want: ["pages:read"] },
    { name: "exact dup dedup", in: ["x:/a:read", "x:/a:read"], want: ["x:/a:read"] },
    { name: "opaque dedup", in: ["admin", "admin", "email"], want: ["admin", "email"] },
    { name: "opaque never dominates structured", in: ["functions", "functions::read"], want: ["functions", "functions::read"] },
    { name: "cross-resource kept", in: ["functions::read", "vector_stores:system:read"], want: ["functions::read", "vector_stores:system:read"] },
    { name: "verb non-interference", in: ["functions::read", "functions:/a:create"], want: ["functions::read", "functions:/a:create"] },
    { name: "no redundancy preserves order", in: ["x:/a:read", "x:/b:create"], want: ["x:/a:read", "x:/b:create"] },
  ];
  for (const tc of cases) {
    it(tc.name, () => {
      expect(compact(tc.in)).toEqual(tc.want);
    });
  }

  it("compacts the real-world array 49 -> 37", () => {
    const got = compact(compactRealWorldInput);
    expect(got).toHaveLength(37);
    expect(got).toEqual(compactRealWorldExpected);
    expect(compactRealWorldInput).toHaveLength(49); // input not mutated
  });

  it("is idempotent", () => {
    const once = compact(compactRealWorldInput);
    expect(compact(once)).toEqual(once);
  });

  it("preserves authority", () => {
    const checker = new EntitlementsChecker(undefined, "bearer", false);
    const compacted = compact(compactRealWorldInput);
    const probes: Array<[string, boolean]> = [
      ["functions:/api/v1/files:read", true],
      ["functions:/api/v1/files:delete", true],
      ["billing::read", false],
    ];
    for (const [req, want] of probes) {
      const reqs: Requirements = [{ bearer: [req] }];
      const orig = checker.verifyEntitlements({ bearer: compactRealWorldInput }, reqs);
      const comp = checker.verifyEntitlements({ bearer: compacted }, reqs);
      expect(orig).toBe(want);
      expect(comp).toBe(orig);
    }
  });
});

describe("requirement placeholders", () => {
  it("binds a placeholder and scopes to the bound value", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([
      { bearer: ["functions:/api/v1/files:read", "vector_stores:{vector_store_id}:write"] },
    ]);
    const held = ec.parseEntitlements({
      bearer: ["functions:/api/v1/files:read", "vector_stores:vs_alice:all"],
    });

    const bound = ec.bindRequirements(reqs, { vector_store_id: "vs_alice" });
    expect(ec.verifyParsedEntitlements(held, bound)).toBe(true);

    const boundOther = ec.bindRequirements(reqs, { vector_store_id: "vs_bob" });
    expect(ec.verifyParsedEntitlements(held, boundOther)).toBe(false);

    // A held wildcard still passes a bound requirement.
    const admin = ec.parseEntitlements({
      bearer: ["functions:/api/v1/files:read", "vector_stores::all"],
    });
    expect(ec.verifyParsedEntitlements(admin, boundOther)).toBe(true);
  });

  it("throws on an unbound placeholder", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([{ bearer: ["vector_stores:{vector_store_id}:write"] }]);
    expect(() => ec.bindRequirements(reqs, { wrong_key: "vs_alice" })).toThrow(
      UnboundPlaceholderError,
    );
    expect(() => ec.bindRequirements(reqs, {})).toThrow(UnboundPlaceholderError);
  });

  it("throws on a bound value that is empty or a wildcard", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([{ bearer: ["vector_stores:{vector_store_id}:write"] }]);
    // "" and "*" are the wildcard spelling, not a concrete resourceName.
    // Binding one would widen the requirement to every store.
    for (const v of ["", "*"]) {
      expect(() => ec.bindRequirements(reqs, { vector_store_id: v })).toThrow(
        InvalidBoundValueError,
      );
    }
    // A legitimate value still binds.
    expect(() => ec.bindRequirements(reqs, { vector_store_id: "vs_alice" })).not.toThrow();
  });

  it("returns a no-placeholder set unchanged", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([{ bearer: ["functions:/api/v1/files:read"] }]);
    expect(ec.bindRequirements(reqs, {})).toBe(reqs); // identity
  });

  it("binds multiple placeholders by name and ignores superset keys", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const reqs = ec.parseRequirements([
      { bearer: ["vector_stores:{vector_store_id}:write", "files:{file_id}:read"] },
    ]);
    const bound = ec.bindRequirements(reqs, {
      vector_store_id: "vs_alice",
      file_id: "file_1",
      unused: "ignored",
    });
    const held = ec.parseEntitlements({
      bearer: ["vector_stores:vs_alice:all", "files:file_1:read"],
    });
    expect(ec.verifyParsedEntitlements(held, bound)).toBe(true);

    expect(() => ec.bindRequirements(reqs, { vector_store_id: "vs_alice" })).toThrow(
      UnboundPlaceholderError,
    );
  });

  it("treats a held-side placeholder as literal text", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    const held = ec.parseEntitlements({ bearer: ["vector_stores:{vector_store_id}:all"] });
    const reqs = ec.parseRequirements([{ bearer: ["vector_stores:vs_alice:write"] }]);
    expect(ec.verifyParsedEntitlements(held, reqs)).toBe(false);
  });
});

describe("strict requirements", () => {
  it("preserves existing behavior when off and rejects the escalation when on", () => {
    const held = { bearer: ["vector_stores:vs_alice:all"] };
    const reqs: Requirements = [{ bearer: ["vector_stores:*:write"] }];

    expect(new EntitlementsChecker([], "bearer", false).verifyEntitlements(held, reqs)).toBe(true);

    const strict = new EntitlementsChecker([], "bearer", false).withStrictRequirements(true);
    expect(strict.verifyEntitlements(held, reqs)).toBe(false);
    expect(
      strict.verifyEntitlements(held, [{ bearer: ["vector_stores:vs_alice:write"] }]),
    ).toBe(true);

    // A wildcard requirement is illegal by SPELLING — a genuine wildcard grant
    // does not rescue it. (Parity with Go's TestStrictRejectsWildcardRequirement.)
    expect(
      strict.verifyEntitlements({ bearer: ["vector_stores::all"] }, reqs),
    ).toBe(false);
  });

  it("reports the wildcard error regardless of its position in the list", () => {
    // Strict scans all requirements before resolving placeholders, so the
    // wildcard error wins regardless of order. A single interleaved pass would
    // throw UnboundPlaceholderError for the first ordering and
    // WildcardRequirementError for the second — order-dependent, and drift from
    // the Go reference.
    const strict = new EntitlementsChecker([], "bearer", false).withStrictRequirements(true);
    for (const entries of [
      ["vector_stores:{vector_store_id}:write", "vector_stores:*:read"],
      ["vector_stores:*:read", "vector_stores:{vector_store_id}:write"],
    ]) {
      const reqs = strict.parseRequirements([{ bearer: entries }]);
      expect(() => strict.bindRequirements(reqs, {})).toThrow(WildcardRequirementError);
    }
  });

  it("throws WildcardRequirementError from bind for every wildcard spelling", () => {
    const strict = new EntitlementsChecker([], "bearer", false).withStrictRequirements(true);
    for (const s of ["vector_stores:*:write", "vector_stores::write", "vector_stores:write"]) {
      const reqs = strict.parseRequirements([{ bearer: [s] }]);
      expect(() => strict.bindRequirements(reqs, {})).toThrow(WildcardRequirementError);
    }
    for (const s of ["vector_stores_create", "functions:/api/v1/files:read"]) {
      const reqs = strict.parseRequirements([{ bearer: [s] }]);
      expect(() => strict.bindRequirements(reqs, {})).not.toThrow();
    }
  });

  it("fails closed on an unbound placeholder, even for a wildcard grant", () => {
    const strict = new EntitlementsChecker([], "bearer", false).withStrictRequirements(true);
    const reqs = strict.parseRequirements([{ bearer: ["vector_stores:{vector_store_id}:write"] }]);
    const admin = strict.parseEntitlements({ bearer: ["vector_stores::all"] });
    expect(strict.verifyParsedEntitlements(admin, reqs)).toBe(false);
  });
});

describe("wildcardRequirements", () => {
  it("reports exactly what strict rejects, de-duplicated in first-seen order", () => {
    const ec = new EntitlementsChecker([], "bearer", false);
    expect(
      ec.wildcardRequirements([
        {
          bearer: [
            "functions:/api/v1/ingest:read",
            "vector_stores:*:write",
            "apitokens:mint",
            "vector_stores:*:write",
            "vector_stores:{vector_store_id}:write",
            "vector_stores_create",
          ],
        },
      ]),
    ).toEqual(["vector_stores:*:write", "apitokens:mint"]);

    expect(ec.wildcardRequirements([{ bearer: ["users:me:read"] }])).toEqual([]);
  });
});
