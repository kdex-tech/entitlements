from typing import Dict, List, Optional, Union
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
        self.anonymous_entitlements = anonymous_entitlements or []
        self.default_scheme = default_scheme

    def verify(self, user_entitlements: Entitlements, requirements: Requirements) -> bool:
        if not requirements:
            return True

        # Merge with anonymous
        merged = {k: list(v) for k, v in user_entitlements.items()}
        if self.anonymous_entitlements:
            scheme_list = merged.setdefault(self.default_scheme, [])
            for anon in self.anonymous_entitlements:
                if anon not in scheme_list:
                    scheme_list.append(anon)

        # Pre-parse entitlements
        parsed_entitlements: Dict[SecurityScheme, List[Pattern]] = {
            scheme: [Pattern.parse(e) for e in entries]
            for scheme, entries in merged.items()
        }

        # OR logic for requirements list
        for req_set in requirements:
            if self._verify_set(parsed_entitlements, req_set):
                return True
        
        return False

    def _verify_set(self, user_patterns: Dict[SecurityScheme, List[Pattern]], req_set: RequirementSet) -> bool:
        # AND logic for a requirement set
        for scheme, required_patterns in req_set.items():
            user_list = user_patterns.get(scheme)
            if user_list is None:
                return False
            
            for req_str in required_patterns:
                req_p = Pattern.parse(req_str)
                if not any(user_p.satisfies(req_p) for user_p in user_list):
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
        
        # Identity AND (additional requirements OR...)
        combined: Requirements = []
        for req_set in additional_requirements:
            new_set = dict(req_set)
            new_set.setdefault(self.default_scheme, []).append(identity_req)
            combined.append(new_set)
        
        return self.verify(user_entitlements, combined)
