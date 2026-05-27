from typing import Dict, List, Optional
import dataclasses

# Types
SecurityScheme = str
Entitlements = Dict[SecurityScheme, List[str]]
RequirementSet = Dict[SecurityScheme, List[str]]
Requirements = List[RequirementSet]

@dataclasses.dataclass(frozen=True)
class Pattern:
    """Represents a parsed entitlement or requirement pattern."""
    resource: Optional[str] = None
    name: Optional[str] = None
    verb: Optional[str] = None
    opaque: Optional[str] = None

    @classmethod
    def parse(cls, s: str) -> "Pattern":
        parts = s.split(":")
        if len(parts) == 3:
            return cls(resource=parts[0], name=parts[1], verb=parts[2])
        elif len(parts) == 2:
            return cls(resource=parts[0], name="*", verb=parts[1])
        else:
            return cls(opaque=s)

    def satisfies(self, required: "Pattern") -> bool:
        # Both opaque: must match exactly
        if self.opaque is not None and required.opaque is not None:
            return self.opaque == required.opaque
        
        # Mixed: no match unless strings are identical (unlikely given parse)
        if (self.opaque is not None) != (required.opaque is not None):
            return False

        # Structured:
        # Resource must match
        if self.resource != required.resource:
            return False
        
        # Verb must match exactly or entitlement is "all"
        if self.verb != required.verb and self.verb != "all":
            return False
        
        # Name must match exactly, or either is a wildcard
        if self.name != required.name and self.name not in ("*", "") and required.name not in ("*", ""):
            return False
        
        return True

class EntitlementsChecker:
    def __init__(self, anonymous_entitlements: Optional[List[str]] = None, default_scheme: str = "bearer"):
        self._anonymous_patterns: List[Pattern] = [
            Pattern.parse(s) for s in (anonymous_entitlements or [])
        ]
        self._base_patterns: List[Pattern] = []
        self.default_scheme = default_scheme

    def with_base_entitlements(self, patterns: List[str]) -> "EntitlementsChecker":
        """Sets the base entitlements: patterns that apply to every caller
        (authenticated or anonymous) under the default scheme. Unlike
        anonymous_entitlements (which apply only when the caller's
        entitlements map is empty), base entitlements form a floor of
        grants that every request receives.

        Replaces any previously set base entitlements. Returns self for
        chaining. Intended for use during checker construction; not safe
        for concurrent mutation with verify calls in flight.
        """
        self._base_patterns = [Pattern.parse(s) for s in patterns]
        return self

    def verify(self, user_entitlements: Entitlements, requirements: Requirements) -> bool:
        if not requirements:
            return True

        parsed: Dict[SecurityScheme, List[Pattern]] = {
            scheme: [Pattern.parse(e) for e in entries]
            for scheme, entries in user_entitlements.items()
        }
        is_anonymous = not parsed or all(not v for v in parsed.values())

        for req_set in requirements:
            if self._verify_set(parsed, req_set, is_anonymous):
                return True
        return False

    def _verify_set(
        self,
        user_patterns: Dict[SecurityScheme, List[Pattern]],
        req_set: RequirementSet,
        is_anonymous: bool,
    ) -> bool:
        for scheme, required_patterns in req_set.items():
            user_list_present = scheme in user_patterns
            has_fallback = scheme == self.default_scheme and (
                bool(self._base_patterns)
                or (is_anonymous and bool(self._anonymous_patterns))
            )
            if not user_list_present and not has_fallback:
                return False

            user_list = user_patterns.get(scheme, [])
            for req_str in required_patterns:
                req_p = Pattern.parse(req_str)
                satisfied = (
                    any(p.satisfies(req_p) for p in user_list)
                    or (
                        scheme == self.default_scheme
                        and any(p.satisfies(req_p) for p in self._base_patterns)
                    )
                    or (
                        scheme == self.default_scheme
                        and is_anonymous
                        and any(p.satisfies(req_p) for p in self._anonymous_patterns)
                    )
                )
                if not satisfied:
                    return False
        return True

    def verify_resource(
        self,
        user_entitlements: Entitlements,
        resource: str,
        name: str,
        verb: str,
        additional_requirements: Optional[Requirements] = None
    ) -> bool:
        identity_req = f"{resource}:{name}:{verb}"

        if not additional_requirements:
            return self.verify(user_entitlements, [{self.default_scheme: [identity_req]}])

        combined: Requirements = []
        for req_set in additional_requirements:
            new_set = dict(req_set)
            new_set.setdefault(self.default_scheme, []).append(identity_req)
            combined.append(new_set)

        return self.verify(user_entitlements, combined)
