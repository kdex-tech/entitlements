import pytest
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

    # Anonymous match
    requirements = [{"bearer": ["anonymous:*:read"]}]
    assert checker.verify(user_entitlements, requirements)

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
