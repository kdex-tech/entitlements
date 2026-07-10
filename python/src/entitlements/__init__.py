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

    def dominates(self, requested: "Pattern") -> bool:
        """Reports whether this pattern (as a HELD entitlement) is equal to or
        BROADER than `requested`. This is the predicate for attenuation
        (minting a token that carries a subset of the caller's authority).
        Unlike `satisfies` (request-time matching), a wildcard resourceName is
        honored ONLY on the held side: a specific grant cannot dominate a
        wildcard request, so a mint can never broaden authority.

        Opaque scopes dominate only by exact match.
        """
        # Both opaque: must match exactly
        if self.opaque is not None and requested.opaque is not None:
            return self.opaque == requested.opaque

        # Mixed: never dominates
        if (self.opaque is not None) != (requested.opaque is not None):
            return False

        # Resource type must match.
        if self.resource != requested.resource:
            return False

        # Verb: held "all" dominates any; otherwise verbs must match. A
        # requested "all" is NOT dominated by a specific held verb.
        if self.verb != "all" and self.verb != requested.verb:
            return False

        # resourceName: a wildcard is honored ONLY on the held side.
        if self.name in ("*", ""):
            return True
        return self.name == requested.name


def verify_attenuation(held: List[str], requested: List[str]) -> Optional[str]:
    """Returns `None` when every requested entitlement is dominated by at
    least one held entitlement. Otherwise returns the first requested
    entitlement (as its original string) that no held entitlement dominates.
    """
    held_patterns = [Pattern.parse(h) for h in held]
    for req in requested:
        req_pattern = Pattern.parse(req)
        if not any(h.dominates(req_pattern) for h in held_patterns):
            return req
    return None


def compact(entitlements: List[str]) -> List[str]:
    """Returns the subset of `entitlements` with every entry removed that is
    strictly dominated by another entry, or that is an exact / equivalent-form
    duplicate (e.g. "pages:read", "pages::read", "pages:*:read" collapse to the
    first-seen one). The result grants exactly the same authority as the input;
    survivors keep their original strings and their first-seen order.

    Built purely on `Pattern.dominates`, so it can never drift from attenuation.
    Opaque and malformed scopes collapse only by exact equality.
    """
    patterns = [Pattern.parse(e) for e in entitlements]
    survivors: List[str] = []
    survivor_patterns: List[Pattern] = []
    for i, ep in enumerate(patterns):
        strictly_dominated = any(
            j != i and op.dominates(ep) and not ep.dominates(op)
            for j, op in enumerate(patterns)
        )
        if strictly_dominated:
            continue
        if any(sp.dominates(ep) and ep.dominates(sp) for sp in survivor_patterns):
            continue
        survivors.append(entitlements[i])
        survivor_patterns.append(ep)
    return survivors


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
