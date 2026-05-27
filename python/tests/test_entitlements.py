from entitlements import EntitlementsChecker, Pattern

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
