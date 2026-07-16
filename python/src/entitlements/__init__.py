from typing import Dict, List, Optional
import dataclasses

# Types
SecurityScheme = str
Entitlements = Dict[SecurityScheme, List[str]]
RequirementSet = Dict[SecurityScheme, List[str]]
Requirements = List[RequirementSet]


class BindError(Exception):
    """Base class for bind_requirements failures."""


class UnboundPlaceholderError(BindError):
    """A requirement declared a {placeholder} the binding does not resolve.
    An unbound placeholder is an error, never a pass."""


class WildcardRequirementError(BindError):
    """Strict mode: a requirement's resourceName is a wildcard. Wildcards are
    meaningful only on the held side; as a requirement the spelling is
    ambiguous. Use a {placeholder} for the resource being addressed, or an
    opaque scope for a context-less capability."""


class InvalidBoundValueError(BindError):
    """A placeholder was bound to "", "*", or a value containing ':'. "" and
    "*" are the wildcard spelling, not a concrete resource name: binding one
    would silently widen the requirement to the whole resource class. A ':' is
    rejected because this port has no pre-parsed type and must re-emit the
    bound pattern as a string that gets re-parsed — a value containing ':'
    would re-split into the wrong shape there, while Go/TypeScript (which
    construct the pattern directly) would not; rejecting it here keeps all
    four ports identical. A binder that could not resolve a value must fail
    like an unbound placeholder rather than widen the gate or diverge across
    ports."""


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

    @property
    def placeholder(self) -> Optional[str]:
        """The binding key when this pattern's resourceName has the form
        "{key}", else None. "{}" is a literal, not a placeholder. Meaningful
        only on the requirement side; held-side placeholders are literal text.
        """
        n = self.name
        if n is not None and len(n) > 2 and n.startswith("{") and n.endswith("}"):
            return n[1:-1]
        return None

    @property
    def is_wildcard_name(self) -> bool:
        """Whether this pattern's resourceName is a wildcard. Note `parse` maps
        the short form (<resource>:<verb>) to name="*"."""
        return self.opaque is None and self.name in ("*", "")

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
        self._strict_requirements = False

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

    def with_strict_requirements(self, strict: bool) -> "EntitlementsChecker":
        """Rejects wildcard resourceNames on the requirement side. Never affects
        entitlements, where wildcards remain meaningful.

        When enabled, bind_requirements raises WildcardRequirementError (the
        loud path) and verify treats both a wildcard requirement and an unbound
        placeholder as unsatisfiable (a fail-closed backstop for callers that
        skip binding).

        Defaults to False; a future major version will default it to True.
        Returns self for chaining.
        """
        self._strict_requirements = strict
        return self

    def bind_requirements(self, requirements: Requirements, binding: Dict[str, str]) -> Requirements:
        """Substitutes every {placeholder} resourceName with its value from
        `binding`, returning the rewritten requirements. Sets containing no
        placeholder are returned unchanged.

        Raises UnboundPlaceholderError if a placeholder has no entry in
        `binding` — an unbound placeholder is an error, never a pass. Keys that
        match no placeholder are ignored, so a caller may pass a superset.
        Raises WildcardRequirementError under strict mode for a wildcard
        requirement.
        """
        # Strict scans EVERY requirement before any placeholder is resolved, so a
        # wildcard is reported deterministically no matter where it sits in the
        # list. Mirrors the Go reference. A single interleaved pass would make the
        # raised error depend on item order: ["x:{id}:write", "x:*:read"] would
        # raise UnboundPlaceholderError, and the same list reversed would raise
        # WildcardRequirementError — cross-port drift.
        if self._strict_requirements:
            for req_set in requirements:
                for entries in req_set.values():
                    for s in entries:
                        p = Pattern.parse(s)
                        if p.placeholder is None and p.is_wildcard_name:
                            raise WildcardRequirementError(
                                f"wildcard resourceName is not allowed in requirement {s!r}"
                            )

        out: Requirements = []
        for req_set in requirements:
            new_set: RequirementSet = {}
            for scheme, entries in req_set.items():
                new_entries: List[str] = []
                for s in entries:
                    p = Pattern.parse(s)
                    key = p.placeholder
                    if key is None:
                        new_entries.append(s)
                        continue
                    if key not in binding:
                        raise UnboundPlaceholderError(
                            f"unbound placeholder {key!r} in requirement {s!r}"
                        )
                    v = binding[key]
                    # "" and "*" are the wildcard spelling, not concrete names:
                    # binding one would widen the requirement to the whole
                    # class. ":" is rejected too: this port has no pre-parsed
                    # type and must re-emit the bound pattern as an f-string
                    # below, which Pattern.parse then re-splits on ":" — a
                    # bound value containing one would re-split into the wrong
                    # shape and the pattern would silently become opaque,
                    # diverging from Go/TypeScript, which construct the
                    # pattern directly and never re-split it. Rejecting the
                    # colon here is what keeps all four ports identical. Fail
                    # like an unbound placeholder in every case.
                    if v in ("", "*") or ":" in v:
                        raise InvalidBoundValueError(
                            f"bound value must not be empty, a wildcard, or "
                            f"contain ':': {key!r} bound to {v!r} in "
                            f"requirement {s!r}"
                        )
                    new_entries.append(f"{p.resource}:{v}:{p.verb}")
                new_set[scheme] = new_entries
            out.append(new_set)
        return out

    def wildcard_requirements(self, requirements: Requirements) -> List[str]:
        """Returns the requirement strings whose resourceName is a wildcard —
        the spellings strict mode rejects outright. De-duplicated, first-seen
        order.

        It is a migration inventory, not a complete strict-mode pre-flight:
        strict also rejects an unbound placeholder at verification time, which
        this query does not report (a placeholder is the migration's
        destination, not a target). An empty result means no requirement still
        uses a wildcard spelling.

        It is a pure query so a caller may log, count, or fail in its own
        idiom. Use it to inventory what remains to migrate before enabling
        with_strict_requirements.
        """
        out: List[str] = []
        for req_set in requirements:
            for entries in req_set.values():
                for s in entries:
                    p = Pattern.parse(s)
                    if p.placeholder is None and p.is_wildcard_name and s not in out:
                        out.append(s)
        return out

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
                # Strict backstop for callers that skip bind_requirements: a
                # wildcard requirement is an illegal spelling and an unbound
                # placeholder was never resolved. Both are unsatisfiable rather
                # than silently admitted — a held wildcard would match either.
                if self._strict_requirements and (
                    req_p.placeholder is not None or req_p.is_wildcard_name
                ):
                    return False
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
