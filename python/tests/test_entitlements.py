import pytest
from entitlements import (
    EntitlementsChecker,
    InvalidBoundValueError,
    Pattern,
    UnboundPlaceholderError,
    WildcardRequirementError,
    compact,
    verify_attenuation,
)

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


def test_placeholder_recognition():
    assert Pattern.parse("vs:{vector_store_id}:read").placeholder == "vector_store_id"
    assert Pattern.parse("vs:{a}:read").placeholder == "a"
    assert Pattern.parse("vs:{}:read").placeholder is None  # literal
    assert Pattern.parse("vs:vs_alice:read").placeholder is None
    assert Pattern.parse("vs:*:read").placeholder is None
    assert Pattern.parse("opaque").placeholder is None


def test_bind_requirements_substitutes_and_scopes():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["vector_stores:{vector_store_id}:write"]}]
    held = {"bearer": ["vector_stores:vs_alice:all"]}

    bound = ec.bind_requirements(reqs, {"vector_store_id": "vs_alice"})
    assert ec.verify(held, bound)

    bound_other = ec.bind_requirements(reqs, {"vector_store_id": "vs_bob"})
    assert not ec.verify(held, bound_other), "vs_alice must not satisfy vs_bob"

    # A held wildcard still passes a bound requirement.
    assert ec.verify({"bearer": ["vector_stores::all"]}, bound_other)


def test_bind_requirements_unbound_raises():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["vector_stores:{vector_store_id}:write"]}]
    with pytest.raises(UnboundPlaceholderError):
        ec.bind_requirements(reqs, {"wrong_key": "vs_alice"})
    with pytest.raises(UnboundPlaceholderError):
        ec.bind_requirements(reqs, {})


def test_bind_requirements_rejects_wildcard_bound_value():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["vector_stores:{vector_store_id}:write"]}]
    # "" and "*" are the wildcard spelling, not a concrete resource name.
    # Binding one would widen the requirement to every store.
    for v in ("", "*"):
        with pytest.raises(InvalidBoundValueError):
            ec.bind_requirements(reqs, {"vector_store_id": v})
    # A legitimate value still binds.
    ec.bind_requirements(reqs, {"vector_store_id": "vs_alice"})


def test_bind_requirements_no_placeholder_is_unchanged():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["functions:/api/v1/files:read"]}]
    assert ec.bind_requirements(reqs, {}) == reqs


def test_bind_requirements_multiple_and_superset():
    ec = EntitlementsChecker()
    reqs = [{"bearer": ["vector_stores:{vector_store_id}:write", "files:{file_id}:read"]}]
    bound = ec.bind_requirements(
        reqs, {"vector_store_id": "vs_alice", "file_id": "file_1", "unused": "ignored"}
    )
    held = {"bearer": ["vector_stores:vs_alice:all", "files:file_1:read"]}
    assert ec.verify(held, bound)

    with pytest.raises(UnboundPlaceholderError):
        ec.bind_requirements(reqs, {"vector_store_id": "vs_alice"})


def test_held_side_placeholder_is_literal():
    ec = EntitlementsChecker()
    held = {"bearer": ["vector_stores:{vector_store_id}:all"]}
    assert not ec.verify(held, [{"bearer": ["vector_stores:vs_alice:write"]}]), (
        "a held-side placeholder must be literal text, not a wildcard"
    )


def test_strict_rejects_wildcard_requirements():
    held = {"bearer": ["vector_stores:vs_alice:all"]}

    # Strict off preserves existing behavior.
    assert EntitlementsChecker().verify(held, [{"bearer": ["vector_stores:*:write"]}])

    strict = EntitlementsChecker().with_strict_requirements(True)
    assert not strict.verify(held, [{"bearer": ["vector_stores:*:write"]}])
    assert strict.verify(held, [{"bearer": ["vector_stores:vs_alice:write"]}])

    # A wildcard requirement is illegal by SPELLING — a genuine wildcard grant
    # does not rescue it. (Parity with Go's TestStrictRejectsWildcardRequirement.)
    assert not strict.verify(
        {"bearer": ["vector_stores::all"]}, [{"bearer": ["vector_stores:*:write"]}]
    )

    for s in ("vector_stores:*:write", "vector_stores::write", "vector_stores:write"):
        with pytest.raises(WildcardRequirementError):
            strict.bind_requirements([{"bearer": [s]}], {})

    # Opaque and concrete requirements bind cleanly under strict — no false reject.
    for s in ("vector_stores_create", "functions:/api/v1/files:read"):
        strict.bind_requirements([{"bearer": [s]}], {})


def test_strict_wildcard_error_is_order_independent():
    # Strict scans all requirements before resolving placeholders, so the
    # wildcard error wins regardless of position. A single interleaved pass would
    # raise UnboundPlaceholderError for the first ordering and
    # WildcardRequirementError for the second — order-dependent, and drift from
    # the Go reference.
    strict = EntitlementsChecker().with_strict_requirements(True)
    for entries in (
        ["vector_stores:{vector_store_id}:write", "vector_stores:*:read"],
        ["vector_stores:*:read", "vector_stores:{vector_store_id}:write"],
    ):
        with pytest.raises(WildcardRequirementError):
            strict.bind_requirements([{"bearer": entries}], {})


def test_strict_unbound_placeholder_fails_closed():
    strict = EntitlementsChecker().with_strict_requirements(True)
    admin = {"bearer": ["vector_stores::all"]}
    assert not strict.verify(admin, [{"bearer": ["vector_stores:{vector_store_id}:write"]}])


def test_wildcard_requirements_inventory():
    ec = EntitlementsChecker()
    reqs = [
        {
            "bearer": [
                "functions:/api/v1/ingest:read",
                "vector_stores:*:write",
                "apitokens:mint",
                "vector_stores:*:write",
                "vector_stores:{vector_store_id}:write",
                "vector_stores_create",
            ]
        }
    ]
    assert ec.wildcard_requirements(reqs) == ["vector_stores:*:write", "apitokens:mint"]
    assert ec.wildcard_requirements([{"bearer": ["users:me:read"]}]) == []
