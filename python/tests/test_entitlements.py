from entitlements import EntitlementsChecker, Pattern, verify_attenuation, compact

def test_pattern_parse():
    assert Pattern.parse("pages:/foo:read") == Pattern(resource="pages", name="/foo", verb="read")
    assert Pattern.parse("pages:read") == Pattern(resource="pages", name="*", verb="read")
    assert Pattern.parse("admin") == Pattern(opaque="admin")

def test_pattern_satisfies():
    ent = Pattern.parse("pages:*:read")
    req = Pattern.parse("pages:/foo:read")
    assert ent.satisfies(req)

    ent = Pattern.parse("pages:all")
    req = Pattern.parse("pages:/foo:read")
    assert ent.satisfies(req)

    ent = Pattern.parse("pages:/bar:read")
    req = Pattern.parse("pages:/foo:read")
    assert not ent.satisfies(req)

    ent = Pattern.parse("admin")
    req = Pattern.parse("admin")
    assert ent.satisfies(req)

def test_verify():
    checker = EntitlementsChecker(anonymous_entitlements=["anonymous:read"], default_scheme="bearer")
    
    user_entitlements = {"bearer": ["pages:foo:read"]}
    
    # Simple match
    requirements = [{"bearer": ["pages:foo:read"]}]
    assert checker.verify(user_entitlements, requirements)
    
    # Wildcard match
    requirements = [{"bearer": ["pages:*:read"]}]
    assert checker.verify(user_entitlements, requirements)

    # Authed caller does NOT get the anonymous bag (regression for issue #3)
    requirements = [{"bearer": ["anonymous:*:read"]}]
    assert not checker.verify(user_entitlements, requirements)

    # Anonymous caller DOES get the anonymous bag
    requirements = [{"bearer": ["anonymous:*:read"]}]
    assert checker.verify({}, requirements)

    # Failing match
    requirements = [{"bearer": ["pages:foo:write"]}]
    assert not checker.verify(user_entitlements, requirements)

    # OR match
    requirements = [
        {"bearer": ["pages:foo:write"]},
        {"bearer": ["pages:foo:read"]}
    ]
    assert checker.verify(user_entitlements, requirements)

def test_verify_resource():
    checker = EntitlementsChecker(default_scheme="bearer")
    user_entitlements = {"bearer": ["pages:foo:read", "admin"]}

    # Identity check
    assert checker.verify_resource(user_entitlements, "pages", "foo", "read")
    assert not checker.verify_resource(user_entitlements, "pages", "bar", "read")

    # Identity + additional requirements
    additional = [{"bearer": ["admin"]}]
    assert checker.verify_resource(user_entitlements, "pages", "foo", "read", additional)

    additional = [{"bearer": ["superadmin"]}]
    assert not checker.verify_resource(user_entitlements, "pages", "foo", "read", additional)


def test_anonymous_vs_base():
    checker = EntitlementsChecker(
        anonymous_entitlements=["anon:read"],
        default_scheme="bearer",
    ).with_base_entitlements(["base:read"])

    authed = {"bearer": ["pages:foo:read"]}
    anonymous = {}

    need_anon = [{"bearer": ["anon:read"]}]
    need_base = [{"bearer": ["base:read"]}]

    # Authed caller: base yes, anon no
    assert checker.verify(authed, need_base)
    assert not checker.verify(authed, need_anon)

    # Anonymous caller: both
    assert checker.verify(anonymous, need_base)
    assert checker.verify(anonymous, need_anon)

    # Caller with only an empty scheme list is still anonymous
    assert checker.verify({"bearer": []}, need_anon)

    # Caller with entitlements in a different scheme is NOT anonymous
    assert not checker.verify({"oauth2": ["scope1"]}, need_anon)


def test_with_base_entitlements_replaces():
    checker = (
        EntitlementsChecker(default_scheme="bearer")
        .with_base_entitlements(["first:read"])
        .with_base_entitlements(["second:read"])
    )
    authed = {"bearer": ["pages:foo:read"]}

    assert not checker.verify(authed, [{"bearer": ["first:read"]}])
    assert checker.verify(authed, [{"bearer": ["second:read"]}])


def test_base_entitlements_via_verify_resource():
    checker = EntitlementsChecker(default_scheme="bearer").with_base_entitlements(
        ["pages:/foo:read"]
    )
    # Anonymous caller satisfies identity via base
    assert checker.verify_resource({}, "pages", "/foo", "read")
    # Authed caller satisfies identity via base (caller has unrelated entitlements)
    assert checker.verify_resource({"bearer": ["other:read"]}, "pages", "/foo", "read")
    # Authed caller does NOT satisfy identity via anonymous
    anon_checker = EntitlementsChecker(
        anonymous_entitlements=["pages:/foo:read"], default_scheme="bearer"
    )
    assert not anon_checker.verify_resource(
        {"bearer": ["other:read"]}, "pages", "/foo", "read"
    )
    # Anonymous caller DOES satisfy identity via anonymous bag
    assert anon_checker.verify_resource({}, "pages", "/foo", "read")


def test_pattern_dominates():
    cases = [
        ("vector_stores::write", "vector_stores:X:write", True),  # held wildcard dominates specific
        ("vector_stores:*:write", "vector_stores:X:write", True),  # explicit * on held side
        ("vector_stores:X:write", "vector_stores:*:write", False),  # specific CANNOT widen to wildcard
        ("vector_stores:X:write", "vector_stores::write", False),  # specific CANNOT widen to empty(*)
        ("vector_stores:X:write", "vector_stores:X:write", True),  # exact
        ("vector_stores:X:write", "vector_stores:Y:write", False),  # different resourceName
        ("functions:/api/v1/files:all", "functions:/api/v1/files:write", True),  # verb all dominates
        ("functions:/api/v1/files:write", "functions:/api/v1/files:all", False),  # requested all not dominated
        ("functions:/x:write", "pages:/x:write", False),  # different resource
        ("functions:/api/v1/files:read", "functions:/api/v1/files:write", False),  # different verb
        ("admin", "admin", True),  # opaque exact
        ("admin", "billing", False),  # opaque mismatch
        ("functions:read", "functions:/api/v1/files:read", True),  # short held == functions:*:read
    ]
    for held, requested, want in cases:
        hp = Pattern.parse(held)
        rp = Pattern.parse(requested)
        assert hp.dominates(rp) == want, f"dominates({held!r},{requested!r}) want {want}"


def test_verify_attenuation():
    # A SPECIFIC held grant cannot be widened to a wildcard request.
    held = ["vector_stores:X:read"]
    requested = ["vector_stores:X:read", "vector_stores:*:read"]
    assert verify_attenuation(held, requested) == "vector_stores:*:read"

    # Wildcard held (medium-form == vector_stores:*:read) dominates a specific request.
    held2 = ["functions:/api/v1/files:write", "vector_stores::read"]
    requested2 = ["functions:/api/v1/files:write", "vector_stores:X:read"]
    assert verify_attenuation(held2, requested2) is None


COMPACT_REAL_WORLD_INPUT = [
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
]

COMPACT_REAL_WORLD_EXPECTED = [
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
]


def test_compact_cases():
    cases = [
        ([], []),
        (["x:/a:read"], ["x:/a:read"]),
        (["x:*:read", "x:/a:read", "x:/b:read"], ["x:*:read"]),
        (["x::read", "x:/a:read"], ["x::read"]),
        (["x:/a:all", "x:/a:read"], ["x:/a:all"]),
        (["pages:read", "pages::read", "pages:*:read"], ["pages:read"]),
        (["x:/a:read", "x:/a:read"], ["x:/a:read"]),
        (["admin", "admin", "email"], ["admin", "email"]),
        (["functions", "functions::read"], ["functions", "functions::read"]),
        (["functions::read", "vector_stores:system:read"], ["functions::read", "vector_stores:system:read"]),
        (["functions::read", "functions:/a:create"], ["functions::read", "functions:/a:create"]),
        (["x:/a:read", "x:/b:create"], ["x:/a:read", "x:/b:create"]),
    ]
    for given, want in cases:
        assert compact(given) == want, f"input: {given}"


def test_compact_real_world_array():
    got = compact(COMPACT_REAL_WORLD_INPUT)
    assert len(got) == 37
    assert got == COMPACT_REAL_WORLD_EXPECTED
    assert len(COMPACT_REAL_WORLD_INPUT) == 49  # input not mutated


def test_compact_idempotent():
    once = compact(COMPACT_REAL_WORLD_INPUT)
    assert compact(once) == once


def test_compact_preserves_authority():
    checker = EntitlementsChecker([], "bearer")
    compacted = compact(COMPACT_REAL_WORLD_INPUT)
    for req, want in [
        ("functions:/api/v1/files:read", True),
        ("functions:/api/v1/files:delete", True),
        ("billing::read", False),
    ]:
        reqs = [{"bearer": [req]}]
        orig = checker.verify({"bearer": COMPACT_REAL_WORLD_INPUT}, reqs)
        comp = checker.verify({"bearer": compacted}, reqs)
        assert orig == want, f"original result for {req}"
        assert orig == comp, f"authority equivalence for {req}"
